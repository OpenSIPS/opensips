/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * nats_pool.h — Shared NATS Connection Pool
 *
 * Module:  modules-contrib/nats (static library linked into event_nats and cachedb_nats)
 *
 * Provides a single, shared NATS connection per OpenSIPS worker process.
 * Both event_nats and cachedb_nats register during mod_init (pre-fork);
 * after fork, each worker calls nats_pool_get() to obtain a per-process
 * natsConnection handle.  JetStream and KV store handles are similarly
 * cached per-process.
 *
 * Key constants:
 *   NATS_POOL_MAX_KV_BUCKETS — maximum cached KV bucket handles
 *
 * TLS configuration is sourced from the OpenSIPS tls_mgm "nats"
 * client domain at connect time -- see the doc block above
 * nats_pool_set_tls_api() below for the operator-facing pattern.
 *
 * Thread model:
 *   - nats_pool_register() is called from mod_init (single-threaded,
 *     pre-fork).  It is NOT safe to call after forking.
 *   - nats_pool_get(), nats_pool_get_js(), nats_pool_get_kv() are called
 *     from child_init or from OpenSIPS worker context (post-fork).  Each
 *     worker has its own connection — no cross-process sharing.
 *   - nats_pool_is_connected(), nats_pool_get_reconnect_epoch(), and
 *     nats_pool_get_server_info() are safe to call from any OpenSIPS
 *     process context (they read process-local or atomic state).
 *   - nats_pool_destroy() is called from mod_destroy (single worker).
 *   - The nats.c library spawns internal threads for reconnection.
 *     Reconnection callbacks registered with nats.c run on those threads
 *     and must NOT call OpenSIPS APIs (LM_*, pkg_malloc, etc.).
 *     They use only write(STDERR_FILENO) and atomic increments.
 *
 * Epoch-based reconnection detection:
 *   The pool maintains an atomic reconnect epoch counter, incremented by
 *   the nats.c reconnected callback (running on a library thread).
 *   Modules compare their saved epoch against nats_pool_get_reconnect_epoch()
 *   to detect that a reconnection occurred, then refresh stale handles
 *   (KV stores, JetStream contexts) without requiring explicit callbacks.
 *   This pattern avoids calling OpenSIPS APIs from nats.c threads.
 */

#ifndef NATS_POOL_H
#define NATS_POOL_H

#include "nats_epoch.h"   /* epoch idiom + the two liveness accessors */

#include <nats/nats.h>

/*
 * Pull in the libnats function-pointer table.  Every NATS source file
 * that includes nats_pool.h gets nats_dl transitively, so direct calls
 * like natsConnection_Connect(...) are written nats_dl.natsConnection_Connect(...)
 * and dispatched through the dlopen-populated table.  See nats_dl.h for
 * the architectural rationale and lifecycle.
 */
#include "nats_dl.h"

/*
 * TLS configuration source.
 *
 * NATS modules no longer carry their own TLS modparams.  When the
 * operator wants TLS for a NATS connection (URL starts with tls://),
 * modules-contrib/nats looks up the OpenSIPS tls_mgm client domain named "nats"
 * and reads cert / CA / key / verify / cipher settings from there.
 * That domain MUST be defined in opensips.cfg before any NATS module
 * connects, e.g.:
 *
 *   loadmodule "tls_mgm.so"
 *   modparam("tls_mgm", "client_domain", "nats")
 *   modparam("tls_mgm", "certificate", "[nats]/etc/opensips/nats-cert.pem")
 *   modparam("tls_mgm", "private_key", "[nats]/etc/opensips/nats-key.pem")
 *   modparam("tls_mgm", "ca_list",     "[nats]/etc/opensips/nats-ca.pem")
 *   modparam("tls_mgm", "verify_cert", "[nats]1")
 *   loadmodule "tls_openssl.so"   # or tls_wolfssl.so
 *
 *   loadmodule "cachedb_nats.so"
 *   loadmodule "event_nats.so"
 *   loadmodule "nats_consumer.so"
 *
 * Plaintext deployments (URL starts with nats://) don't need tls_mgm
 * loaded at all -- the NATS user modules declare it as DEP_SILENT.
 *
 * The user modules call nats_pool_set_tls_api(&binds) in mod_init
 * after binding tls_mgm via load_tls_mgm_api(); modules-contrib/nats's connect
 * path then uses that API to look up the "nats" domain.
 */

/* Maximum number of KV bucket handles cached per process. */
#define NATS_POOL_MAX_KV_BUCKETS 16

/*
 * Register interest in the NATS connection pool.
 *
 * Must be called from mod_init (pre-fork, single-threaded).  Multiple
 * modules may register; the pool merges configurations by taking the
 * superset of server URLs and warns on conflicting TLS settings.
 *
 * @param url             Comma-separated NATS server URLs
 *                        (e.g., "tls://h1:4222,tls://h2:4223").  TLS
 *                        material comes from tls_mgm via
 *                        nats_pool_set_tls_api(), not a parameter here.
 * @param module          Module name string, used in log messages
 *                        (e.g., "event_nats" or "cachedb_nats").
 * @param reconnect_wait  Milliseconds to wait between reconnect attempts.
 *                        Pass 0 to use the default (2000 ms).
 * @param max_reconnect   Maximum number of reconnect attempts before
 *                        giving up.  Pass 0 to use the default (60).
 * @return                0 on success, -1 on error (logged internally).
 *
 * Thread safety: NOT thread-safe.  Call only from mod_init.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_register(const char *url, const char *module,
                       int reconnect_wait, int max_reconnect);
#endif

/*
 * Register for a module that has no URL configured, with its default @url.
 * The default is used only if no module configures servers, whatever the
 * order the modules register in: registered after configured servers, it
 * adds none; the first configured servers registered after it replace it.
 * Otherwise as nats_pool_register() (the reconnect values merge, the
 * registration counts for nats_pool_unregister()).
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_register_default(const char *url, const char *module,
                               int reconnect_wait, int max_reconnect);
#endif

/*
 * Hand the OpenSIPS tls_mgm bind table to modules-contrib/nats.
 *
 * @binds  pointer to a populated `struct tls_mgm_binds` from
 *         load_tls_mgm_api(); modules-contrib/nats stores this opaquely (void *
 *         in the public header to avoid pulling tls_mgm/api.h into
 *         every source that uses nats_pool.h) and casts back inside
 *         nats_pool.c.  Pass NULL to clear (used by tests).
 *
 * Must be called BEFORE the first nats_pool_register on a TLS URL.
 * Subsequent calls overwrite the stored pointer; first-non-NULL wins
 * in practice since all NATS user modules read the same tls_mgm
 * instance.
 *
 * Idempotent: calling twice with the same pointer is a no-op.  No
 * effect on plaintext (nats://) URLs.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_pool_set_tls_api(void *binds);
#endif

/* One-call tls_mgm attach for a NATS module's mod_init: find_export +
 * load_tls_mgm_api + nats_pool_set_tls_api, with uniform logging.
 * Safe when tls_mgm is absent. */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_pool_bind_tls(const char *modname);
#endif

/*
 * Get the shared NATS connection for this worker process.
 *
 * On the first call (from child_init), creates the connection using the
 * merged configuration from all nats_pool_register() calls.  Subsequent
 * calls return the cached handle.  Internally guards nats_Open()
 * to run only once per process.
 *
 * @return  natsConnection pointer on success, NULL on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 *                Each process has its own connection (no sharing).
 */
#ifndef NATS_POOL_NO_PROTOTYPES
natsConnection *nats_pool_get(void);
#endif

/*
 * Get the shared JetStream context for this worker process.
 *
 * Creates the jsCtx on first call from the shared connection.  Sets up
 * the PublishAsync AckHandler at creation time for asynchronous publish
 * acknowledgment tracking.
 *
 * @return  jsCtx pointer on success, NULL on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
jsCtx *nats_pool_get_js(void);
#endif

/*
 * Get a KV store handle for a named bucket.
 *
 * Creates the bucket on the NATS server if it does not already exist.
 * Caches handles per bucket name (process-local, up to
 * NATS_POOL_MAX_KV_BUCKETS entries).  Cached handles are automatically
 * invalidated and recreated when a reconnection is detected via the
 * epoch mechanism.
 *
 * @param bucket    Bucket name (must be a valid NATS subject token:
 *                  no dots, colons, or spaces).
 * @param replicas  JetStream replication factor (only used when creating
 *                  a new bucket; existing buckets retain their config).
 * @param history   Number of historical revisions to keep per key
 *                  (only used when creating a new bucket).
 * @param ttl_secs  Bucket-wide TTL in seconds.  Pass 0 for no expiration.
 *                  Only used when creating a new bucket.
 * @return          kvStore pointer on success, NULL on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
kvStore *nats_pool_get_kv(const char *bucket, int replicas,
                          int history, int64_t ttl_secs);
#endif

/*
 * Destroy the connection pool and release all resources.
 *
 * Drains the connection (flushes pending publishes), closes it, and
 * frees all cached JetStream / KV handles.  Called from mod_destroy
 * during OpenSIPS shutdown.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_destroy
 *                (single process context).
 */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_pool_destroy(void);
#endif

/*
 * Drop one registration reference (the counterpart to
 * nats_pool_register).  The pool is torn down only on the last unregister,
 * so the shared connection survives while any loaded NATS module still
 * uses it.  Each module should call this once from its mod_destroy if its
 * nats_pool_register() succeeded.  Prefer this over calling
 * nats_pool_destroy() directly.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_destroy.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_pool_unregister(void);
#endif

/*
 * Check whether the pool's NATS connection is currently active.
 *
 * @return  1 if connected, 0 if disconnected or not yet initialized.
 *
 * Thread safety: Safe to call from any OpenSIPS process context.
 *                Reads volatile/atomic state.
 *
 * Declared in nats_epoch.h (included below) so SHM-struct headers can
 * embed the epoch tag without the full pool surface.
 */

/*
 * Read the bound bucket's backing-stream MaxAge (ns) into *out_ns.
 * Used at child_init to detect a PRE-EXISTING bucket that already carries a
 * non-zero MaxAge (which would silently expire permanent contacts).  Returns
 * 0 on success (*out_ns set), -1 if the stream info is unavailable.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_bucket_maxage_ns(const char *bucket, int64_t *out_ns);
#endif

/*
 *: read the bound bucket's backing-stream MaxMsgsPerSubject
 * (the KV history depth) into *out_mmps, for startup surfacing of a
 * PRE-EXISTING history-keeping bucket.  0 on success, -1 if unavailable.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_bucket_mmps(const char *bucket, int64_t *out_mmps);
#endif

/*
 * Returns non-zero once any module has registered the pool
 * (nats_pool_register).  Lets a module choose to contribute a default URL
 * only when nothing else has registered, instead of injecting a spurious
 * server into another module's pool.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_is_registered(void);
#endif

/*
 * Returns non-zero if the pool has at least one usable server URL.  Lets a
 * module tell "no usable server configured" (a nats_pool_get() failure it
 * can start degraded on) from a connection that could not be set up with
 * the configured servers (a configuration error).
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_has_servers(void);
#endif

/*
 * Get a human-readable list of discovered NATS server URLs.
 *
 * Intended for MI status reporting.  Returns a comma-separated string
 * of server URLs that the nats.c library has discovered (including
 * cluster peers found via INFO gossip).
 *
 * @return  Pointer to a process-local string.  Do not free.
 *          Returns "not connected" if the connection is not active.
 *
 * Thread safety: Safe to call from any OpenSIPS process context.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
const char *nats_pool_get_server_info(void);
#endif

/*
 * Get the current reconnect epoch.
 *
 * The epoch is an atomic counter incremented each time the nats.c
 * library reports a successful reconnection (from its internal thread).
 * Modules save the epoch value when they obtain a handle (KV store,
 * JetStream context) and later compare against this function's return
 * to detect that a reconnect occurred and the handle may be stale.
 *
 * See also: nats_con_refresh_kv() in cachedb_nats.h, which uses this
 * epoch to transparently refresh KV handles.
 *
 * @return  Current epoch counter value (starts at 0, never wraps in
 *          practice).
 *
 * Thread safety: Safe to call from any thread (atomic read).
 *
 * Declared in nats_epoch.h (included below).
 */

/*
 * Return 1 if the calling OpenSIPS process should initialize NATS,
 * 0 otherwise.
 *
 * NATS is initialized in:
 *   - SIP workers (UDP and TCP workers, rank >= 1)
 *   - HTTPD/MI process (rank == PROC_MODULE, -2)
 *   - Timer (rank == PROC_TIMER, -1) — the timer process raises a large
 *     class of subscribable events in-process (usrloc/dialog EXPIRY, tm/
 *     dialog timeouts); event_nats' raise runs in the raising process, so
 *     the timer must be able to publish to NATS
 *
 * NATS is NOT initialized in:
 *   - Attendant (rank == PROC_MAIN, 0)
 *   - TCP-main (rank == PROC_TCP_MAIN, -4) — holds TLS/OpenSSL state
 *     in a single process, and does not handle SIP routing
 *   - Module-exported processes (negative rank, self-initialize)
 *
 * TCP workers hold no OpenSSL state
 * (TLS runs only in TCP-main), so they are safe to co-host nats.c.
 *
 * This helper is the single source of truth for the admission rule;
 * both event_nats and cachedb_nats must call it rather than open-coding
 * the check.
 *
 * Callable from any OpenSIPS process context.  Pure function — no
 * locking, no globals.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_should_init(int rank);
#endif

/*
 * Drain timeout for the shutdown drain in nats_pool_destroy(), in
 * milliseconds.
 *
 * Each module loaded against modules-contrib/nats may override this from its own
 * mod_init (e.g. via a modparam) to tune how long shutdown waits for
 * outstanding NATS publishes — including JetStream async-pub acks —
 * to flush before destroying the connection.  The default of 5000 ms
 * is appropriate for low-latency local brokers; deployments hitting
 * a remote broker over higher-latency links may want to raise this
 * to avoid silent drops on shutdown.
 *
 * Read from any thread; write only from mod_init (pre-fork, single-
 * threaded), so no synchronization is required.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
extern int nats_pool_drain_timeout_ms;
#endif

/* Merge decision for the shared drain timeout, pure and
 * header-inline so the contract is unit-testable (tests/
 * test_drain_merge.c).  The FIRST explicit modparam value replaces
 * the built-in default outright -- an operator's choice out-ranks the
 * default, including BELOW it (the old setter max-merged against the
 * 5000 ms default, silently ignoring e.g. drain_timeout_ms=2000).
 * Across MULTIPLE explicit registrants the max wins: the longest
 * configured shutdown grace, order-independent. */
static inline int nats_pool_drain_timeout_decide(int current_ms,
	int have_explicit, int proposed_ms)
{
	if (!have_explicit)
		return proposed_ms;
	return proposed_ms > current_ms ? proposed_ms : current_ms;
}

/* Shared modparam setter for the drain timeout: event_nats and
 * cachedb_nats both register it (INT_PARAM|USE_FUNC_PARAM) under the
 * canonical name `drain_timeout_ms` (old per-module spellings kept as
 * aliases), so the ONE pool value is merged via the decide helper
 * above instead of last-writer-wins.  `type` is modparam_t
 * (== unsigned int); spelled out here so this header stays free of the heavy
 * sr_module.h include that the standalone lib unit-tests cannot satisfy. */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_drain_timeout_setter(unsigned int type, void *val);
#endif

/*
 * Server order for the shared connection.  0 (the default): libnats
 * shuffles the configured server list, so the worker processes spread
 * over the servers.  1: every process tries the servers in the order they
 * are configured (primary / backup).  Set pre-fork by the `no_randomize`
 * modparam of the NATS modules, read at connect time.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
extern int nats_pool_no_randomize;
#endif

/* Merge decision for no_randomize, pure and header-inline so the contract
 * is unit-testable: the modules share one connection, so any module that
 * asks for the configured order gets it; a 0 never turns it back off. */
static inline int nats_pool_no_randomize_decide(int current, int proposed)
{
	return (current || proposed) ? 1 : 0;
}

/* Shared modparam setter for `no_randomize` (INT_PARAM|USE_FUNC_PARAM in
 * event_nats, cachedb_nats and nats_consumer).  Accepts 0 or 1.  `type`
 * is modparam_t, spelled out as for nats_pool_drain_timeout_setter(). */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_no_randomize_setter(unsigned int type, void *val);
#endif

/*
 * Credentials of the shared connection (nats_auth.h), set pre-fork by the
 * user, password, token, creds_file, nkey and nkey_seed_file modparams of
 * the NATS modules.  Each setter accepts a non-empty string; a second
 * module setting another value refuses startup.  The first
 * nats_pool_register() checks the set (one method, complete pairs,
 * readable files) and every registration refuses a server URL that also
 * carries user information.  `type` is modparam_t, spelled out as for
 * nats_pool_drain_timeout_setter().
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_user_setter(unsigned int type, void *val);
#endif
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_password_setter(unsigned int type, void *val);
#endif
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_token_setter(unsigned int type, void *val);
#endif
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_creds_file_setter(unsigned int type, void *val);
#endif
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_nkey_setter(unsigned int type, void *val);
#endif
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_nkey_seed_file_setter(unsigned int type, void *val);
#endif

/* Non-zero when credentials are configured as modparams. */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_auth_configured(void);
#endif

/*
 * DNS SRV discovery (nats_srv.h).  A nats+srv:// or tls+srv:// server URL
 * is resolved by the nats module in each process when it connects: the SRV
 * records of _nats._tcp.<domain> become plain URLs in RFC 2782 order, so
 * libnats needs no SRV support.  When the lookups leave no server, the
 * process continues without NATS (nats_pool_has_servers() returns 0) and
 * looks up again at most every nats_pool_srv_retry_s seconds.
 * nats_pool_set_srv_resolver() replaces the resolver (the OpenSIPS core
 * one by default); the unit tests pass a fake.
 */
#include "nats_srv.h"
extern int nats_pool_srv_retry_s;
void nats_pool_set_srv_resolver(nats_srv_resolve_f fn, void *ctx);

/*
 * Module-tunable per-operation timeout (ms) for JetStream / KV requests,
 * plumbed into jsOptions.Wait.  0 keeps cnats's 5 s default; set a smaller
 * value (e.g. cachedb_nats "kv_op_timeout_ms") on hot paths.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
extern int nats_pool_kv_op_timeout_ms;
#endif

/*
 * Size, in bytes, of the libnats buffer that keeps what is published
 * while the connection is reconnecting (natsOptions_SetReconnectBufSize);
 * it is sent once the connection is back.  When it is full, a publish
 * fails with NATS_INSUFFICIENT_BUFFER (the module counts it).  libnats
 * checks the bound before appending a message, so the buffer may exceed
 * it by one message.  Set pre-fork by the `reconnect_buf_size` modparam
 * of the NATS modules, read at connect time.
 */
#define NATS_POOL_RECONNECT_BUF_SIZE_DEFAULT  (8 * 1024 * 1024)
#ifndef NATS_POOL_NO_PROTOTYPES
extern int nats_pool_reconnect_buf_size;
#endif

/* Merge decision for reconnect_buf_size, pure and header-inline so the
 * contract is unit-testable: the first explicit value replaces the
 * default, including below it; across several modules the largest wins
 * (the one connection must hold what any of them publishes). */
static inline int nats_pool_reconnect_buf_size_decide(int current,
	int have_explicit, int proposed)
{
	if (!have_explicit)
		return proposed;
	return proposed > current ? proposed : current;
}

/* Shared modparam setter for `reconnect_buf_size` (INT_PARAM|USE_FUNC_PARAM
 * in event_nats, cachedb_nats and nats_consumer).  Accepts 1 or more.
 * `type` is modparam_t, spelled out as for nats_pool_drain_timeout_setter(). */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_reconnect_buf_size_setter(unsigned int type, void *val);
#endif

/*
 * JetStream async publish acknowledgements (see nats_js_retry.h).  Each
 * async publish waits nats_pool_js_ack_timeout_ms for its ack
 * (jsPubOptions.MaxWait); the ack handler resends a message whose ack
 * failed with a retryable error at most nats_pool_js_publish_retries
 * times.  Set pre-fork by event_nats (js_ack_timeout_ms,
 * js_publish_retries); read by the ack handler on the libnats thread.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
extern int nats_pool_js_ack_timeout_ms;
#endif
#ifndef NATS_POOL_NO_PROTOTYPES
extern int nats_pool_js_publish_retries;
#endif

/*
 * Register a callback for JetStream publish-ack outcomes.
 *
 * The cnats library invokes the AckHandler from a library-internal
 * I/O thread.  Modules that want to observe per-ack outcomes
 * (e.g. to bump nats_stats counters) register a callback here.
 * The callback runs on the cnats thread and MUST NOT call any
 * OpenSIPS APIs (LM_*, pkg_malloc, etc.); it may only do atomic
 * memory operations and async-signal-safe I/O.
 *
 * @param cb  Function called as cb(outcome) for every ack, with an
 *            nats_pub_ack_outcome value (nats_js_retry.h): NATS_PUB_ACK_OK
 *            (1) and NATS_PUB_ACK_FAILED (0) as before, plus DUPLICATE,
 *            RETRIED, FAILED_BUFFER_FULL and FAILED_PENDING_FULL.  A
 *            message reports one RETRIED per resend and exactly one of
 *            the other outcomes at the end.  Pass NULL to clear any
 *            previously-registered callback.
 *
 * Thread safety: Set once during mod_init, before fork.  The
 * callback pointer is read on the cnats thread without locking.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
void nats_pool_set_pub_ack_cb(void (*cb)(int outcome));
#endif

#ifdef UNIT_TESTS
/*
 * Unit-test seam: put the pool back as it is at startup -- nothing
 * registered, no connection, every modparam at its default, no merge
 * history -- closing whatever is open through the libnats table in place.
 */
void nats_pool_test_reset(void);
#endif

#endif /* NATS_POOL_H */
