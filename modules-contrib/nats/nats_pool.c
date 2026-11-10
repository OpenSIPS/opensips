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
 */

/**
 * @file nats_pool.c
 * @brief Shared NATS connection pool for OpenSIPS modules.
 *
 * This module (nats.so) provides a single shared NATS connection per
 * OpenSIPS worker process, used by event_nats.so, cachedb_nats.so,
 * cachedb_nats_fts.so and nats_consumer.so, which bind its API with
 * load_nats_api() (nats_api.h, nats_bind.h).  nats.so is loaded once per
 * process, so all of them share the state below.
 *
 * ## Thread model
 *
 * OpenSIPS is a multi-process server.  All public API functions in this file
 * (nats_pool_register, nats_pool_get, nats_pool_get_js, nats_pool_get_kv,
 * nats_pool_destroy, etc.) are called from OpenSIPS process context — either
 * the main attendant (pre-fork, during mod_init) or a worker/timer process
 * (post-fork, during child_init or normal request processing).
 *
 * However, the nats.c library internally creates its own I/O threads for
 * connection management.  The disconnect/reconnect callbacks
 * (pool_disconnected_cb, pool_reconnected_cb) and the JetStream async
 * publish ack handler (pool_js_pub_ack_handler) run on these nats.c-internal
 * threads, NOT on an OpenSIPS process main thread.  LM_* and pkg_malloc
 * are forbidden there (per-process / main-thread-only state); atomic
 * ops, write(), nats.c APIs, and the shm_malloc + ipc_dispatch_rpc
 * handoff are safe — see the callback-doctrine block below.
 *
 * ## Design
 *
 * - **Configuration** (pool_cfg) lives in SHM, set pre-fork by
 *   nats_pool_register().  Multiple modules can register; configs are merged.
 * - **Connection state** (_nc, _js, _kv_cache) is process-local, created
 *   post-fork on first access via nats_pool_get().
 * - **KV lazy invalidation**: On reconnect, the _kv_stale atomic flag is set
 *   by the reconnect callback.  The next call to nats_pool_get_kv() detects
 *   this and clears the KV cache, forcing fresh handle creation.  This avoids
 *   calling any OpenSIPS APIs from the callback thread.
 * - **Connection lifetime**: _nc is never destroyed or replaced after
 *   creation (except in nats_pool_destroy at shutdown).  nats.c handles
 *   reconnection internally; all derived objects (_js, kvStore, kvWatcher)
 *   remain valid across reconnects.
 */

#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>

#include <nats/nats.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../../dprint.h"
#include "../../sr_module.h"   /* find_export() */
#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../globals.h"   /* process_no */
#include "nats_url_scheme.h"
#include "nats_pool.h"
#include "nats_js_opts.h"
#include "nats_js_retry.h"
#include "nats_auth.h"
#include "nats_srv.h"
#include "nats_rl.h"
#include <time.h>
#include "nats_redact.h"
#include "nats_server_info.h"
#include "nats_ca_dir.h"
#include "nats_err.h"
#include "../../modules/tls_mgm/api.h"   /* tls_mgm_binds, tls_domain */

/* Part of the nats module (nats.so); the other NATS modules call these
 * functions through the API (nats.c, load_nats). */

/* ----------------------------------------------------------------
 * Shared pool configuration (shm, set pre-fork in mod_init)
 * ---------------------------------------------------------------- */

#define NATS_POOL_MAX_SERVERS 16
#define NATS_POOL_DEFAULT_RECONNECT_WAIT 2000
#define NATS_POOL_DEFAULT_MAX_RECONNECT  60

/* Async-publish cap / stall policy lives in nats_js_opts.h
 * (nats_pool_js_opts_apply), behaviourally locked by
 * test/test_js_opts_policy.c. */

/* Connection liveness probing so a black-holed broker is declared dead in
 * ~20 s (vs cnats's ~4-minute default) -- shrinks the window where inline
 * publishes block/buffer in SIP workers before the fast-fail trips. */
#define NATS_POOL_PING_INTERVAL_MS  10000
#define NATS_POOL_MAX_PINGS_OUT     2

/**
 * Pool configuration structure, allocated in shared memory.
 * Set during mod_init (pre-fork) and read-only after fork.  (The TLS
 * probe in nats_pool_get() only READS it; the historical tls://
 * -> nats:// URL rewrite is gone — TLS-less libnats now fails hard,
 * never downgrades.)
 */
typedef struct nats_pool_cfg {
	char *servers[NATS_POOL_MAX_SERVERS]; /* shm-allocated URL strings */
	int   server_cnt;
	int   use_tls;                        /* 1 if any URL is TLS (tls://, tls+srv://) */
	int   default_only;                   /* servers[] is a module's default URL */

	int   reconnect_wait;                 /* ms */
	int   max_reconnect;
	int   auth_plain_warned;              /* plain-text credential warning given */
} nats_pool_cfg;

/* Single shared config — allocated on first register */
static nats_pool_cfg *pool_cfg = NULL;

/* ----------------------------------------------------------------
 * Process-local connection state (set post-fork)
 * ---------------------------------------------------------------- */

static int              _lib_initialized = 0;   /* nats_Open called? */
static natsConnection  *_nc = NULL;              /* NATS connection handle */
static jsCtx           *_js = NULL;              /* JetStream context */

/* Registration refcount.  Each module that calls nats_pool_register()
 * increments this; nats_pool_unregister() decrements it and tears the pool
 * down only on the last unregister, so the connection survives while any
 * module still uses it and is always destroyed once the last one is gone.
 * Single-threaded (mod_init / mod_destroy run before fork / at shutdown). */
static int              _register_count = 0;
static atomic_int       _connected = 0;          /* 1 if connected */
static atomic_int       _reconnect_epoch = 0;    /* bumped on each reconnect */

/* pthread_atfork() prepare handler, registered once nats.c is open */
static int              _atfork_registered = 0;
static void pool_prefork_teardown(void);

/* tls_mgm bind table set by user-module mod_init via
 * nats_pool_set_tls_api().  NULL means "tls_mgm not loaded" -- the
 * connect path uses this to error out cleanly when a tls:// URL is
 * configured but no TLS-domain source is available. */
static struct tls_mgm_binds *_tls_api = NULL;

void nats_pool_set_tls_api(void *binds)
{
	_tls_api = (struct tls_mgm_binds *)binds;
}

/* The tls_mgm attach ritual, shared by every NATS module's mod_init
 *: look up load_tls_mgm, bind, hand the table to the pool.
 * Absence of tls_mgm is not an error -- nats:// keeps working; the
 * connect path errors cleanly on tls:// URLs. */
void nats_pool_bind_tls(const char *modname)
{
	static struct tls_mgm_binds _binds;

	if (find_export("load_tls_mgm", 0)) {
		if (load_tls_mgm_api(&_binds) == 0) {
			nats_pool_set_tls_api(&_binds);
			LM_INFO("%s: tls_mgm bound; tls:// URLs will use "
				"the \"nats\" client domain\n", modname);
		} else {
			LM_WARN("%s: tls_mgm exports load_tls_mgm but the "
				"bind failed; tls:// URLs will not work\n",
				modname);
		}
	} else {
		LM_INFO("%s: tls_mgm not loaded; only nats:// URLs will "
			"work (tls:// will error at connect)\n", modname);
	}
}

/* KV handle cache — maps bucket names to kvStore pointers.
 * Process-local; invalidated on reconnection via _kv_stale. */
typedef struct {
	char     bucket[128];
	kvStore *kv;
} kv_cache_entry;

static kv_cache_entry _kv_cache[NATS_POOL_MAX_KV_BUCKETS];
static int            _kv_cache_cnt = 0;

/* See nats_pool.h — module-tunable shutdown drain timeout, ms. */
int nats_pool_drain_timeout_ms = 5000;

/* Drain-timeout modparam setter shared by event_nats and cachedb_nats
 * (modparam `drain_timeout_ms`).
 * Both target this one global; the merge contract lives in
 * nats_pool_drain_timeout_decide() (nats_pool.h): the first explicit
 * value replaces the default -- including below it -- and further
 * registrants max-merge, WARNing when a lower explicit value loses. */
static int _drain_explicit = 0;

int nats_pool_drain_timeout_setter(modparam_t type, void *val)
{
	int v, merged;

	if ((type & PARAM_TYPE_MASK(INT_PARAM)) == 0) {
		LM_ERR("drain_timeout_ms: must be an integer\n");
		return -1;
	}
	v = (int)(long)val;
	if (v < 0) {
		LM_ERR("drain_timeout_ms: %d is negative\n", v);
		return -1;
	}
	merged = nats_pool_drain_timeout_decide(nats_pool_drain_timeout_ms,
		_drain_explicit, v);
	if (_drain_explicit && merged != v)
		LM_WARN("drain_timeout_ms=%d is below another module's %d; "
			"the shared shutdown grace keeps the max (%d)\n",
			v, nats_pool_drain_timeout_ms, merged);
	nats_pool_drain_timeout_ms = merged;
	_drain_explicit = 1;
	return 0;
}

/* See nats_pool.h — server order of the shared connection. */
int nats_pool_no_randomize = 0;

/* no_randomize modparam setter shared by event_nats, cachedb_nats and
 * nats_consumer; the merge contract is nats_pool_no_randomize_decide()
 * (nats_pool.h): any module asking for the configured order gets it. */
static int _no_randomize_explicit_off = 0;

int nats_pool_no_randomize_setter(modparam_t type, void *val)
{
	int v;

	if ((type & PARAM_TYPE_MASK(INT_PARAM)) == 0) {
		LM_ERR("no_randomize: must be an integer\n");
		return -1;
	}
	v = (int)(long)val;
	if (v != 0 && v != 1) {
		LM_ERR("no_randomize: %d is neither 0 nor 1\n", v);
		return -1;
	}
	if ((v == 0 && nats_pool_no_randomize) || (v == 1 && _no_randomize_explicit_off))
		LM_WARN("no_randomize: NATS modules disagree; the shared "
			"connection keeps the configured server order\n");
	if (v == 0)
		_no_randomize_explicit_off = 1;
	nats_pool_no_randomize = nats_pool_no_randomize_decide(
		nats_pool_no_randomize, v);
	return 0;
}

/* See nats_pool.h — the reconnect buffer of the shared connection. */
int nats_pool_reconnect_buf_size = NATS_POOL_RECONNECT_BUF_SIZE_DEFAULT;

/* reconnect_buf_size modparam setter shared by event_nats, cachedb_nats
 * and nats_consumer; the merge contract is
 * nats_pool_reconnect_buf_size_decide() (nats_pool.h). */
static int _reconnect_buf_explicit = 0;

int nats_pool_reconnect_buf_size_setter(modparam_t type, void *val)
{
	int v, merged;

	if ((type & PARAM_TYPE_MASK(INT_PARAM)) == 0) {
		LM_ERR("reconnect_buf_size: must be an integer\n");
		return -1;
	}
	v = (int)(long)val;
	if (v < 1) {
		LM_ERR("reconnect_buf_size: %d is below 1 byte\n", v);
		return -1;
	}
	merged = nats_pool_reconnect_buf_size_decide(nats_pool_reconnect_buf_size,
		_reconnect_buf_explicit, v);
	if (_reconnect_buf_explicit && merged != v)
		LM_WARN("reconnect_buf_size=%d is below another module's %d; the "
			"shared connection keeps the larger buffer\n",
			v, nats_pool_reconnect_buf_size);
	nats_pool_reconnect_buf_size = merged;
	_reconnect_buf_explicit = 1;
	return 0;
}

/* See nats_pool.h / nats_js_retry.h — JetStream async publish ack wait and
 * retries, set by event_nats. */
int nats_pool_js_ack_timeout_ms = NATS_JS_ACK_TIMEOUT_MS_DEFAULT;
int nats_pool_js_publish_retries = NATS_JS_PUBLISH_RETRIES_DEFAULT;
/* See nats_pool.h / nats_auth.h — credentials of the shared connection.
 * Set pre-fork by the modparam setters below, inherited by the children;
 * the strings are the modparam values, which live as long as the
 * process. */
static nats_auth_cfg _auth;

static int auth_set(const char *name, const char **slot, modparam_t type,
	void *val)
{
	const char *v = (const char *)val;

	if ((type & PARAM_TYPE_MASK(STR_PARAM)) == 0) {
		LM_ERR("%s: must be a string\n", name);
		return -1;
	}
	switch (nats_auth_str_decide(*slot, v)) {
	case NATS_AUTH_SET:
		*slot = v;
		return 0;
	case NATS_AUTH_SAME:
		return 0;
	default:
		/* never log the value: it may be a secret */
		if (!v || !*v)
			LM_ERR("%s: empty value\n", name);
		else
			LM_ERR("%s: NATS modules set different values; the shared "
				"connection takes one\n", name);
		return -1;
	}
}

int nats_pool_auth_user_setter(modparam_t type, void *val)
{ return auth_set("user", &_auth.user, type, val); }
int nats_pool_auth_password_setter(modparam_t type, void *val)
{ return auth_set("password", &_auth.password, type, val); }
int nats_pool_auth_token_setter(modparam_t type, void *val)
{ return auth_set("token", &_auth.token, type, val); }
int nats_pool_auth_creds_file_setter(modparam_t type, void *val)
{ return auth_set("creds_file", &_auth.creds_file, type, val); }
int nats_pool_auth_nkey_setter(modparam_t type, void *val)
{ return auth_set("nkey", &_auth.nkey, type, val); }
int nats_pool_auth_nkey_seed_file_setter(modparam_t type, void *val)
{ return auth_set("nkey_seed_file", &_auth.nkey_seed_file, type, val); }

int nats_pool_auth_configured(void)
{
	return nats_auth_method(&_auth) != NATS_AUTH_NONE;
}

/* Startup check of the credential modparams: one complete method, and
 * the files readable now (libnats reads them at each connect). */
static int pool_auth_check(const char *module)
{
	const char *err = NULL;

	if (nats_auth_validate(&_auth, &err) < 0) {
		LM_ERR("[%s] NATS credentials: %s\n", module, err);
		return -1;
	}
	if (_auth.creds_file && access(_auth.creds_file, R_OK) != 0) {
		LM_ERR("[%s] NATS creds_file '%s' cannot be read\n", module,
			_auth.creds_file);
		return -1;
	}
	if (_auth.nkey_seed_file && access(_auth.nkey_seed_file, R_OK) != 0) {
		LM_ERR("[%s] NATS nkey_seed_file '%s' cannot be read\n", module,
			_auth.nkey_seed_file);
		return -1;
	}
	return 0;
}

/* Hand the credentials to libnats (none: nothing to do).  A refusal fails
 * the connection setup: connecting without them would be refused by the
 * server anyway, or reach an account the operator did not mean. */
static int pool_auth_apply(natsOptions *opts)
{
	natsStatus s = NATS_OK;
	const char *what = NULL;

	switch (nats_auth_method(&_auth)) {
	case NATS_AUTH_NONE:
		return 0;
	case NATS_AUTH_USERPASS:
		what = "natsOptions_SetUserInfo";
		s = nats_dl.natsOptions_SetUserInfo(opts, _auth.user, _auth.password);
		break;
	case NATS_AUTH_TOKEN:
		what = "natsOptions_SetToken";
		s = nats_dl.natsOptions_SetToken(opts, _auth.token);
		break;
	case NATS_AUTH_CREDS:
		what = "natsOptions_SetUserCredentialsFromFiles";
		s = nats_dl.natsOptions_SetUserCredentialsFromFiles(opts,
			_auth.creds_file, NULL);
		break;
	case NATS_AUTH_NKEY:
		what = "natsOptions_SetNKeyFromSeed";
		s = nats_dl.natsOptions_SetNKeyFromSeed(opts, _auth.nkey,
			_auth.nkey_seed_file);
		break;
	}
	if (s != NATS_OK) {
		LM_ERR("NATS pool: %s failed: %s\n", what,
			nats_dl.natsStatus_GetText(s));
		return -1;
	}
	return 0;
}

/* See nats_pool.h — module-tunable JetStream/KV op timeout, ms.  0 keeps
 * cnats's default (5 s).  Set a smaller value (500-1000 ms) on hot paths
 * like usrloc so a slow-but-connected broker can't block a SIP worker for
 * the full default. */
/* Non-zero DEFAULT: the usrloc update path is two synchronous
 * KV round-trips per REGISTER; with cnats's library default (5 s) a
 * slow-but-connected broker can hold a SIP worker ~10 s per attempt.
 * 1000 ms bounds the per-REGISTER worst case at ~2 s; operators can
 * still widen it (or set <= 0 for the library default) via the
 * cachedb_nats kv_op_timeout_ms modparam. */
int nats_pool_kv_op_timeout_ms = 1000;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

/* shm_strdup provided by ../../ut.h — no local copy needed */

/**
 * Tokenize a comma-separated URL string and append each unique server (one
 * not already in pool_cfg->servers[]) to the config, trimming surrounding
 * whitespace/commas and detecting TLS (tls://, tls+srv://).  Shared by the initial parse and
 * the subsequent-registration merge so the tokenizer lives in one place.
 *
 * @param url            Comma-separated URL string.
 * @param hard_overflow  If non-zero, exceeding NATS_POOL_MAX_SERVERS is a
 *                       hard error (-1); otherwise the extra URL is
 *                       warn-skipped (merge semantics).
 * @param skipped        If not NULL, incremented for each DNS SRV URL left
 *                       out for lack of a usable domain name.
 * @return  number of servers added, or -1 on OOM / hard overflow.  On -1 the
 *          caller owns any partial additions.
 *
 * Thread safety: Called only during mod_init (single-threaded, pre-fork).
 */
static int pool_append_server_urls(const char *url, int hard_overflow,
	int *skipped)
{
	const char *p = url, *tok;
	char *srv;
	int len, i, added = 0;

	while (*p) {
		/* skip leading whitespace and commas */
		while (*p == ',' || *p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;

		tok = p;
		while (*p && *p != ',')
			p++;

		len = (int)(p - tok);
		/* trim trailing whitespace */
		while (len > 0 && (tok[len - 1] == ' ' || tok[len - 1] == '\t'))
			len--;
		if (len <= 0)
			continue;

		srv = shm_malloc(len + 1);
		if (!srv) {
			LM_ERR("shm_malloc for server URL failed\n");
			return -1;
		}
		if (!nats_url_is_srv(tok)) {
			memcpy(srv, tok, len);
			srv[len] = '\0';
		} else {
			/* libnats rejects an SRV URL with a port or a path, which
			 * would leave the whole connection without servers: drop
			 * them, or skip a URL that has no usable domain. */
			int r = nats_url_srv_correct(tok, len, srv);
			char redacted[256];

			if (r == 0) {
				memcpy(srv, tok, len);
				srv[len] = '\0';
				nats_url_srv_redact(srv, redacted, sizeof(redacted));
				LM_WARN("NATS pool: ignoring DNS SRV server URL '%s': "
					"it has no usable domain name\n", redacted);
				shm_free(srv);
				if (skipped)
					(*skipped)++;
				continue;
			}
			if (r == 2) {
				nats_url_srv_redact(srv, redacted, sizeof(redacted));
				LM_WARN("NATS pool: a DNS SRV server URL takes no port "
					"and no path (the SRV records give the port); "
					"using '%s'\n", redacted);
			}
		}

		/* skip a URL already in the list (a duplicate within this string
		 * or one a previous registration already added) */
		for (i = 0; i < pool_cfg->server_cnt; i++)
			if (strcmp(pool_cfg->servers[i], srv) == 0)
				break;
		if (i < pool_cfg->server_cnt) {
			shm_free(srv);
			continue;
		}

		if (pool_cfg->server_cnt >= NATS_POOL_MAX_SERVERS) {
			shm_free(srv);
			if (hard_overflow) {
				LM_ERR("too many NATS servers (max %d)\n",
					NATS_POOL_MAX_SERVERS);
				return -1;
			}
			LM_WARN("NATS pool: max servers reached, ignoring "
				"additional URL\n");
			continue;
		}

		pool_cfg->servers[pool_cfg->server_cnt] = srv;

		if (nats_url_is_tls(pool_cfg->servers[pool_cfg->server_cnt]))
			pool_cfg->use_tls = 1;

		pool_cfg->server_cnt++;
		added++;
	}
	return added;
}

/*
 * Parse comma-separated URL string into pool_cfg->servers[] (initial
 * registration).  Sets pool_cfg->use_tls if any URL is TLS (tls://, tls+srv://).
 *
 * @param url  Comma-separated URL string (e.g. "nats://h1:4222,nats://h2:4222").
 * @return     0 on success, -1 on error (empty string, too many servers, OOM).
 *
 * Thread safety: Called only during mod_init (single-threaded, pre-fork).
 */
static int parse_urls(const char *url)
{
	int skipped = 0;

	if (!url || !*url) {
		LM_ERR("empty URL string\n");
		return -1;
	}

	if (pool_append_server_urls(url, 1 /* hard overflow */, &skipped) < 0)
		goto err_free_partial;

	if (pool_cfg->server_cnt == 0 && skipped > 0) {
		/* only unusable SRV URLs (warned above): start anyway, without
		 * a NATS server -- nats_pool_get() then fails */
		LM_WARN("NATS pool: no usable NATS server URL; NATS stays "
			"unavailable\n");
		return 0;
	}
	if (pool_cfg->server_cnt == 0) {
		char redacted[256];
		nats_redact_url(url, redacted, sizeof(redacted));
		LM_ERR("no valid NATS server URLs found in '%s'\n", redacted);
		return -1;
	}

	return 0;

err_free_partial:
	{
		int i;
		for (i = 0; i < pool_cfg->server_cnt; i++) {
			shm_free(pool_cfg->servers[i]);
			pool_cfg->servers[i] = NULL;
		}
		pool_cfg->server_cnt = 0;
	}
	return -1;
}

/* ----------------------------------------------------------------
 * nats.c callbacks (run on nats.c internal I/O thread)
 *
 * CRITICAL: These callbacks run on a thread created by nats.c, NOT
 * an OpenSIPS process main thread.
 *
 * Safe operations in these callbacks:
 *   - C11 atomic ops (atomic_store, atomic_exchange, atomic_fetch_add)
 *   - POSIX write() for logging to stderr (see nats_pool_unsafe_log)
 *   - nats.c API calls (natsConnection_GetConnectedUrl, etc.)
 *   - shm_malloc/shm_free + ipc_dispatch_rpc: the shm allocator locks
 *     with a process-shared gen_lock and the IPC pipe write is a
 *     bounded atomic write(2), so copying a payload into SHM and
 *     dispatching it to a worker IS the sanctioned foreign-thread
 *     handoff — event_nats_sub.c's message callback and the watcher's
 *     raise_kv_change_event are the canonical pattern.  Caveat: on
 *     DBG_MALLOC / SHM_EXTRA_STATS builds the shm wrappers touch
 *     process_no-indexed accounting; if such a build is ever the
 *     target, re-verify this path before shipping.
 *
 * Unsafe operations (will crash or corrupt):
 *   - LM_ERR, LM_INFO, LM_DBG, etc. (dprint is not warranted
 *     reentrant against the process main thread's logging)
 *   - pkg_malloc, pkg_free (per-process, lockless — main thread only)
 *   - Any OpenSIPS API that assumes the process main thread
 *
 * For state signals the pattern here is "lazy invalidation":
 * callbacks set atomic flags, and the main process thread checks them
 * on the next API call to perform the actual work (cache clearing,
 * logging, etc.) in a safe context.
 * ---------------------------------------------------------------- */

/**
 * KV stale flag — lazy invalidation for the KV handle cache.
 *
 * This flag implements a producer-consumer pattern across thread boundaries:
 *
 * - Producer (nats.c I/O thread): The disconnect and reconnect callbacks
 *   set this flag to 1 via atomic_store() when the connection state changes.
 *   KV handles may reference stale server-side state (streams, consumers)
 *   after a reconnection, so they must be recreated.
 *
 * - Consumer (OpenSIPS process thread): nats_pool_get_kv() checks this flag
 *   using atomic_exchange(&_kv_stale, 0), which atomically reads the value
 *   and clears it in one operation.  This prevents the Time-Of-Check to
 *   Time-Of-Use (TOCTOU) race that existed with the prior volatile
 *   read-then-write pattern, where a reconnect callback could set the
 *   flag between the read and the clear.
 *
 * Using atomic_int (C11) instead of volatile int because volatile only
 * prevents compiler reordering — it does not guarantee atomicity of
 * read-modify-write sequences or provide memory ordering between threads.
 */
static atomic_int _kv_stale = 0;

/*
 * Callback-thread-safe stderr emit.
 *
 * The nats.c callbacks below run on library-internal threads where OpenSIPS
 * APIs (LM_*, pkg_malloc, …) are not safe to call, so we emit diagnostics
 * with a raw write(2).  glibc decorates write() with warn_unused_result, and
 * GCC's -Wunused-result is not silenced by a (void) cast, so we capture the
 * return into a local and explicitly discard it.  Centralizing the discard
 * here keeps any future callback site from re-introducing -Werror breakage.
 */
static void nats_pool_unsafe_log(const char *buf, size_t len)
{
	ssize_t n = write(STDERR_FILENO, buf, len);
	(void)n;
}

/**
 * Disconnect callback — called by nats.c I/O thread when the connection drops.
 *
 * Sets _connected to 0 and marks KV handles as stale.  Only uses atomic ops
 * and write() — no OpenSIPS APIs are safe here (see callback header comment).
 *
 * @param nc       The NATS connection (provided by nats.c, unused).
 * @param closure  User closure (NULL, unused).
 */
static void pool_disconnected_cb(natsConnection *nc, void *closure)
{
	/* safe: atomic op + raw write() — no OpenSIPS APIs */
	atomic_store(&_connected, 0);
	atomic_store(&_kv_stale, 1);  /* mark KV handles stale immediately on disconnect */
	nats_pool_unsafe_log("NATS pool: disconnected\n", 24);
}

/**
 * Reconnect callback — called by nats.c I/O thread after a successful reconnect.
 *
 * Restores _connected, bumps the reconnect epoch (so modules can detect
 * reconnection), and marks KV handles as stale.  Logs the new server URL
 * via write() to stderr.
 *
 * Only atomic ops, nats.c APIs, and write() are used here — no OpenSIPS APIs.
 * See the callback section header comment for the full rationale.
 *
 * @param nc       The NATS connection (used to query the new server URL).
 * @param closure  User closure (NULL, unused).
 */
static void pool_reconnected_cb(natsConnection *nc, void *closure)
{
	char buf[300];
	char url[256];
	char redacted[256];
	int len;

	/* Init defensively: on a non-OK status GetConnectedUrl may leave
	 * the buffer unterminated, and nats_redact_url() would then read
	 * uninitialised stack. */
	url[0] = '\0';
	nats_dl.natsConnection_GetConnectedUrl(nc, url, sizeof(url));
	nats_redact_url(url, redacted, sizeof(redacted));
	atomic_store(&_connected, 1);
	atomic_fetch_add(&_reconnect_epoch, 1);
	atomic_store(&_kv_stale, 1);

	len = snprintf(buf, sizeof(buf),
		"NATS pool: reconnected to %s\n", redacted);
	/* Clamp the snprintf return to the buffer before logging (see the
	 * matching note in pool_js_pub_ack_handler): a long redacted URL would
	 * otherwise make write() over-read the stack buffer. */
	if (len >= (int)sizeof(buf))
		len = (int)sizeof(buf) - 1;
	if (len > 0)
		nats_pool_unsafe_log(buf, (size_t)len);
}

/**
 * JetStream async publish ack handler — runs on nats.c internal thread.
 *
 * Called by nats.c when an async JetStream publish completes (success or
 * failure).  Signature must match jsPubAckHandler typedef:
 *   void (*)(jsCtx*, natsMsg*, jsPubAck*, jsPubAckErr*, void*)
 *
 * Memory ownership rules (set by nats.c js.c:_handleAsyncReply):
 * - pa and pae are STACK-ALLOCATED by nats.c — do NOT call nats_dl.jsPubAck_Destroy().
 *   nats.c calls _freePubAck() after this callback returns.
 * - msg (the original published message) IS our responsibility to destroy.
 *   nats.c sets pmsg=NULL after calling us (js.c:719).  A resend with
 *   js_PublishMsgAsync() hands it back to libnats and clears our pointer
 *   (the pattern the jsPubAckHandler documentation gives).
 * - an ack that does not arrive within jsPubOptions.MaxWait reaches this
 *   handler as pae->Err == NATS_TIMEOUT (libnats's publish-async timer).
 *
 * @param js       JetStream context (used for a resend).
 * @param msg      Original published message — destroyed here unless resent.
 * @param pa       Publish ack (stack-allocated by nats.c — do NOT destroy).
 * @param pae      Publish ack error, or NULL on success (stack-allocated).
 * @param closure  User closure (NULL, unused).
 */
/* Optional caller-registered hook to report JS ack outcomes
 * (nats_pub_ack_outcome, nats_js_retry.h).  Read on the cnats thread,
 * set once pre-fork via nats_pool_set_pub_ack_cb(). */
static void (*_pub_ack_cb)(int outcome) = NULL;

void nats_pool_set_pub_ack_cb(void (*cb)(int outcome))
{
	_pub_ack_cb = cb;
}

static void pool_js_ack_log_error(const jsPubAckErr *pae)
{
	char buf[256];
	int len = snprintf(buf, sizeof(buf),
		"NATS JetStream async publish error: %s\n",
		pae->ErrText ? pae->ErrText : "unknown");
	/* snprintf returns the length it WOULD have written; a
	 * broker-controlled ErrText longer than buf makes len exceed
	 * sizeof(buf), so the write() below would read past the stack
	 * buffer and leak adjacent stack.  Clamp to the buffer. */
	if (len >= (int)sizeof(buf))
		len = (int)sizeof(buf) - 1;
	if (len > 0)
		nats_pool_unsafe_log(buf, (size_t)len);
}

/*
 * A failed ack: resend the message when the error is transient and the
 * message has retries left (nats_js_retry.h).  The resend is the same
 * natsMsg, so it keeps its Nats-Msg-Id header: if the first copy was
 * stored after all, the server acks the resend as a duplicate instead
 * of storing it twice.  Returns the outcome; on NATS_PUB_ACK_RETRIED
 * libnats owns the message again and *msg is NULL.
 */
static int pool_js_ack_retry(jsCtx *js, natsMsg **msg, const jsPubAckErr *pae)
{
	jsPubOptions po;
	natsStatus s;
	int done;

	if (!nats_js_ack_retryable(pae->Err, (int)pae->ErrCode) ||
	    nats_pool_js_publish_retries <= 0)
		return NATS_PUB_ACK_FAILED;

	done = nats_js_retry_track(*msg);
	if (!nats_js_ack_should_retry(pae->Err, (int)pae->ErrCode, done,
	    nats_pool_js_publish_retries))
		return NATS_PUB_ACK_FAILED;

	/* no MsgId here: the header set by the first publish stays */
	nats_dl.jsPubOptions_Init(&po);
	po.MaxWait = nats_pool_js_ack_timeout_ms;
	s = nats_dl.js_PublishMsgAsync(js, msg, &po);
	if (s == NATS_OK)
		return NATS_PUB_ACK_RETRIED;
	return nats_js_resend_failed_outcome(s);
}

static void pool_js_pub_ack_handler(jsCtx *js, natsMsg *msg, jsPubAck *pa,
                                 jsPubAckErr *pae, void *closure)
{
	int outcome;

	if (pae == NULL || pae->ErrText == NULL) {
		outcome = (pa && pa->Duplicate) ? NATS_PUB_ACK_DUPLICATE :
			NATS_PUB_ACK_OK;
	} else {
		pool_js_ack_log_error(pae);
		outcome = msg ? pool_js_ack_retry(js, &msg, pae) :
			NATS_PUB_ACK_FAILED;
	}
	/* the last outcome of this message: drop its retry count before the
	 * natsMsg is freed (the pointer may be reused by the next message) */
	if (outcome != NATS_PUB_ACK_RETRIED && msg)
		nats_js_retry_forget(msg);
	if (_pub_ack_cb)
		_pub_ack_cb(outcome);
	/* NULL after a resend: libnats owns it again */
	if (msg)
		nats_dl.natsMsg_Destroy(msg);
}

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

/**
 * Register interest in the shared NATS connection pool.
 *
 * Called from mod_init (pre-fork, single-threaded).  Multiple modules
 * (event_nats, cachedb_nats) may call this; configurations are merged:
 * - Server URLs are de-duplicated and added to the pool.
 * - TLS config uses the first registration's values; conflicts are warned.
 * - Reconnect parameters use the largest values across registrations.
 *
 * The first call allocates pool_cfg in shared memory.  Subsequent calls
 * merge additional servers into the existing config.
 *
 * @param url             Comma-separated server URLs
 *                        (e.g., "tls://h1:4222,tls://h2:4223").
 * @param tls             TLS options (NULL for no TLS).
 * @param module          Module name string for log messages.
 * @param reconnect_wait  Reconnect wait in ms (0 = use default 2000ms).
 * @param max_reconnect   Max reconnect attempts (0 = use default 60).
 * @return                0 on success, -1 on error.
 *
 * Thread safety: Must only be called from mod_init (single-threaded).
 */
/* Drop the servers of the config (a module's default URL), before the
 * configured ones replace them. */
static void pool_clear_servers(void)
{
	int i;

	for (i = 0; i < pool_cfg->server_cnt; i++) {
		shm_free(pool_cfg->servers[i]);
		pool_cfg->servers[i] = NULL;
	}
	pool_cfg->server_cnt = 0;
	pool_cfg->use_tls = 0;
}

static int pool_register(const char *url, const char *module,
                         int reconnect_wait, int max_reconnect, int is_default)
{
	int first;

	if (!url || !*url) {
		LM_ERR("[%s] empty NATS URL\n", module ? module : "?");
		return -1;
	}

	/* Lazy-load libnats via dlopen on first registration.  All
	 * subsequent libnats calls in this file (and in the user
	 * modules that link this library) dispatch through nats_dl.X
	 * — see modules-contrib/nats/nats_dl.h for the architectural rationale.
	 * Idempotent: repeated calls are no-ops once libnats is in.
	 *
	 * Operator picks the libnats variant via standard ld.so
	 * mechanisms (LD_LIBRARY_PATH, ldconfig priorities) or via
	 * the $NATS_DL_LIBNATS_PATH env-var override; modules-contrib/nats does
	 * not bake in version numbers or install-prefix conventions. */
	if (nats_dl_load(NULL) < 0) {
		LM_ERR("[%s] nats_dl_load failed; libnats not available\n",
		       module ? module : "?");
		return -1;
	}

	/* nats+srv:// and tls+srv:// are resolved here, in the nats module, at
	 * connect time (pool_expand_servers()): libnats only ever gets plain
	 * URLs, so any libnats works. */

	/* Credentials as modparams and inside a URL: libnats would use the
	 * URL's for that server and the modparams' for the others. */
	if (nats_pool_auth_configured() && nats_url_list_has_userinfo(url)) {
		LM_ERR("[%s] NATS credentials are set both in a server URL and "
		       "as modparams (user, password, token, creds_file, nkey); "
		       "remove them from the URL\n", module ? module : "?");
		return -1;
	}

	/* First registration — allocate the shared config */
	first = !pool_cfg;
	if (first && pool_auth_check(module ? module : "?") < 0)
		return -1;
	if (first) {
		pool_cfg = shm_malloc(sizeof(nats_pool_cfg));
		if (!pool_cfg) {
			LM_ERR("shm_malloc for pool_cfg failed\n");
			return -1;
		}
		memset(pool_cfg, 0, sizeof(nats_pool_cfg));

		/* parse initial URL set */
		if (parse_urls(url) < 0) {
			shm_free(pool_cfg);
			pool_cfg = NULL;
			return -1;
		}
		pool_cfg->default_only = is_default;

		/* TLS configuration (cert/CA/key/verify) is sourced from the
		 * tls_mgm "nats" client domain at connect time -- see
		 * apply_tls_from_mgm() below.  Caller MUST have called
		 * nats_pool_set_tls_api(&binds) first if any URL is tls://. */

		pool_cfg->reconnect_wait = reconnect_wait > 0 ?
			reconnect_wait : NATS_POOL_DEFAULT_RECONNECT_WAIT;
		pool_cfg->max_reconnect = max_reconnect > 0 ?
			max_reconnect : NATS_POOL_DEFAULT_MAX_RECONNECT;

		LM_INFO("NATS pool: registered by '%s' with %d server(s), "
			"TLS=%s, reconnect_wait=%dms, max_reconnect=%d\n",
			module ? module : "?",
			pool_cfg->server_cnt,
			pool_cfg->use_tls ? "yes" : "no",
			pool_cfg->reconnect_wait,
			pool_cfg->max_reconnect);
	} else if (is_default) {
		/* A module with no URL of its own: it uses the servers the pool
		 * already has. */
		LM_INFO("NATS pool: additional registration by '%s' (no URL "
			"of its own)\n", module ? module : "?");
	} else if (pool_cfg->default_only) {
		/* The first servers configured: they replace the default URL
		 * another module registered, instead of joining it. */
		LM_INFO("NATS pool: servers configured by '%s' replace the "
			"default URL\n", module ? module : "?");
		pool_clear_servers();
		if (parse_urls(url) < 0)
			return -1;
		pool_cfg->default_only = 0;
	} else {
		/* Subsequent registration — merge in any new servers (soft
		 * overflow: extra URLs past the cap are warn-skipped). */
		int added;

		LM_INFO("NATS pool: additional registration by '%s'\n",
			module ? module : "?");

		added = pool_append_server_urls(url, 0 /* soft overflow */, NULL);
		if (added < 0)
			return -1;
		if (added > 0)
			LM_INFO("NATS pool: merged %d new server(s) from '%s'\n",
				added, module ? module : "?");
	}

	if (!first) {
		/* TLS config conflicts no longer possible: every NATS
		 * module reads from the same tls_mgm "nats" domain, so
		 * there's nothing to conflict over. */

		/* use the larger reconnect values */
		if (reconnect_wait > 0 &&
		    reconnect_wait > pool_cfg->reconnect_wait)
			pool_cfg->reconnect_wait = reconnect_wait;
		if (max_reconnect > 0 &&
		    max_reconnect > pool_cfg->max_reconnect)
			pool_cfg->max_reconnect = max_reconnect;
	}

	_register_count++;
	return 0;
}

int nats_pool_register(const char *url, const char *module,
                       int reconnect_wait, int max_reconnect)
{
	return pool_register(url, module, reconnect_wait, max_reconnect, 0);
}

int nats_pool_register_default(const char *url, const char *module,
                               int reconnect_wait, int max_reconnect)
{
	return pool_register(url, module, reconnect_wait, max_reconnect, 1);
}

/**
 * Get the shared NATS connection for this worker process.
 *
 * On first call (post-fork), initializes the nats.c library, probes TLS
 * availability, creates connection options, and connects in a retry loop.
 * Subsequent calls return the cached connection handle.
 *
 * The connection is NEVER destroyed or replaced after creation (except
 * at shutdown in nats_pool_destroy).  Multiple components (watcher threads,
 * producers, nats.c I/O threads) cache pointers to _nc and objects derived
 * from it (_js, kvStore, kvWatcher).  Destroying _nc would invalidate all
 * of them.  nats.c's built-in reconnection handles failover transparently.
 *
 * @return  natsConnection pointer on success, NULL on error (no config,
 *          library init failure, or options creation failure).
 *
 * Thread safety: Called from OpenSIPS process context only.  The first-call
 * initialization is not thread-safe, but OpenSIPS processes are forked
 * (not threaded), so each process has its own _nc.
 */
/*
 * nats_load_ca_directory -- read every regular file in @dir whose
 * name ends in ".pem", concatenate the contents in lexicographic
 * order, and hand it to libnats via the in-memory PEM API.  The
 * actual implementation is in modules-contrib/nats/nats_ca_dir.c (libc-only,
 * unit-testable independently).  This file just calls it.
 */

/*
 * apply_tls_from_mgm -- look up the tls_mgm "nats" client domain
 * and pass its cert / CA / key / verify / cipher settings to libnats
 * via nats_dl.natsOptions_*.  Caller must already have called
 * nats_dl.natsOptions_SetSecure(opts, true).
 *
 * Returns 0 on success (opts populated or no TLS settings to apply),
 * -1 if tls_mgm isn't bound or the "nats" domain isn't defined.
 * Either condition means the operator asked for TLS (tls:// URL) but
 * didn't configure tls_mgm to back it -- a hard error.
 */
static int apply_tls_from_mgm(natsOptions *opts)
{
	str dom_name = str_init("nats");
	struct tls_domain *dom;

	if (!_tls_api) {
		LM_ERR("NATS pool: tls:// URL configured but tls_mgm is not "
		       "loaded.  Add `loadmodule \"tls_mgm.so\"` plus a "
		       "client_domain named \"nats\" before any NATS module "
		       "loads, or use a plain nats:// URL.\n");
		return -1;
	}

	dom = _tls_api->find_client_domain_name(&dom_name);
	if (!dom) {
		LM_ERR("NATS pool: tls:// URL configured but tls_mgm has no "
		       "client_domain named \"nats\".  Define one in "
		       "opensips.cfg, e.g.:\n"
		       "  modparam(\"tls_mgm\", \"client_domain\", \"nats\")\n"
		       "  modparam(\"tls_mgm\", \"certificate\", "
		       "\"[nats]/etc/opensips/nats-cert.pem\")\n"
		       "  modparam(\"tls_mgm\", \"private_key\", "
		       "\"[nats]/etc/opensips/nats-key.pem\")\n"
		       "  modparam(\"tls_mgm\", \"ca_list\", "
		       "\"[nats]/etc/opensips/nats-ca.pem\")\n"
		       "  modparam(\"tls_mgm\", \"verify_cert\", \"[nats]1\")\n");
		return -1;
	}

	/* CA: ca_list (single file) preferred; fall back to ca_directory
	 * (concatenate all .pem in the directory).  libnats has no
	 * directory-load API, so nats_ca_dir.c does it OpenSIPS-side. */
	/* Every natsOptions TLS call below is checked: if libnats rejects a
	 * cert/CA/cipher (bad path, malformed PEM, ...) we must fail closed,
	 * not connect with TLS silently downgraded (no CA pinning / no client
	 * cert). */
	natsStatus ts;
	if (dom->ca.len > 0 && dom->ca.s) {
		ts = nats_dl.natsOptions_LoadCATrustedCertificates(opts, dom->ca.s);
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: LoadCATrustedCertificates failed: %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	} else if (dom->ca_directory) {
		char *err = NULL;
		char *concat = nats_load_ca_directory(dom->ca_directory, &err);
		if (!concat) {
			LM_ERR("nats CA-dir load failed for tls_mgm 'nats': %s\n",
			       err ? err : "unknown");
			free(err);
			_tls_api->release_domain(dom);
			return -1;
		}
		free(err);
		ts = nats_dl.natsOptions_SetCATrustedCertificates(opts, concat);
		free(concat);  /* libnats copies internally */
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: SetCATrustedCertificates failed: %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	}

	/* Client cert + key (mutual TLS).  libnats wants both or neither. */
	if (dom->cert.len > 0 && dom->cert.s &&
	    dom->pkey.len > 0 && dom->pkey.s) {
		ts = nats_dl.natsOptions_LoadCertificatesChain(opts,
		                                          dom->cert.s,
		                                          dom->pkey.s);
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: LoadCertificatesChain failed (mTLS): %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	}

	if (dom->ciphers_list) {
		ts = nats_dl.natsOptions_SetCiphers(opts, dom->ciphers_list);
		if (ts != NATS_OK) {
			LM_ERR("nats TLS: SetCiphers failed: %s\n",
			       nats_dl.natsStatus_GetText(ts));
			_tls_api->release_domain(dom);
			return -1;
		}
	}

	/* tls_mgm verify_cert: 1 = verify (default), 0 = skip.
	 * libnats SkipServerVerification is the inverse polarity.  A failure
	 * here leaves verification ON (the secure default), so it is not a
	 * downgrade -- log but do not fail the connection. */
	if (!dom->verify_cert) {
		ts = nats_dl.natsOptions_SkipServerVerification(opts, true);
		if (ts != NATS_OK)
			LM_WARN("nats TLS: SkipServerVerification failed: %s "
			        "(verification stays enabled)\n",
			        nats_dl.natsStatus_GetText(ts));
	}

	_tls_api->release_domain(dom);
	return 0;
}

/* ----------------------------------------------------------------
 * DNS SRV discovery (nats_srv.h)
 * ---------------------------------------------------------------- */

/* The OpenSIPS core resolver (nats_srv_core.c, linked into
 * nats.so).  Weak, so the unit tests that link this file without
 * the core run on their own resolver (nats_pool_set_srv_resolver()). */
int nats_srv_core_resolve(const char *qname, nats_srv_rec *out, int max,
	void *ctx) __attribute__((weak));

static nats_srv_resolve_f _srv_resolve = NULL;
static void *_srv_resolve_ctx = NULL;

void nats_pool_set_srv_resolver(nats_srv_resolve_f fn, void *ctx)
{
	_srv_resolve = fn;
	_srv_resolve_ctx = ctx;
}

/* See nats_pool.h. */
int nats_pool_srv_retry_s = 5;

/* Process-local: the expanded server list handed to libnats, when the
 * lookups left no server (has_servers() then says "none usable", so the
 * modules start degraded), and when they last did. */
static char  *_servers[NATS_POOL_MAX_SERVERS];
static int    _servers_cnt = 0;
static int    _srv_none = 0;
static time_t _srv_failed_at = 0;
/* rate limit of the DNS SRV warnings (nats_rl.h) */
static time_t _srv_rl_fail, _srv_rl_cap, _srv_rl_none;
/* the libnats TLS probe of nats_pool_get() ran in this process */
static int    _tls_probed = 0;

static unsigned int pool_srv_rand(void *ctx)
{
	static pid_t seeded_for = 0;

	(void)ctx;
	if (seeded_for != getpid()) {
		seeded_for = getpid();
		srandom((unsigned)time(NULL) ^ ((unsigned)getpid() << 16));
	}
	return ((unsigned int)random() << 16) ^ (unsigned int)random();
}

/* any nats+srv:// / tls+srv:// URL among the configured servers? */
static int pool_cfg_has_srv(void)
{
	int i;

	for (i = 0; i < pool_cfg->server_cnt; i++)
		if (nats_url_is_srv(pool_cfg->servers[i]))
			return 1;
	return 0;
}

static void pool_free_servers(void)
{
	nats_srv_free_list(_servers, _servers_cnt);
	_servers_cnt = 0;
}

/* Build _servers from pool_cfg->servers: each nats+srv:// / tls+srv://
 * URL becomes the plain URLs of its SRV targets (RFC 2782 order, see
 * nats_srv_order()), the other URLs are copied.  Returns 0, or -1 when no
 * server is left (each failed lookup is warned about, rate-limited). */
static int pool_expand_servers(void)
{
	nats_srv_resolve_f res = _srv_resolve ? _srv_resolve :
		nats_srv_core_resolve;
	void *rctx = _srv_resolve ? _srv_resolve_ctx : NULL;
	time_t now = time(NULL);
	int i, got, capped, failed, total_capped = 0;

	if (_srv_none && now - _srv_failed_at < nats_pool_srv_retry_s) {
		LM_DBG("NATS pool: DNS SRV lookups failed %ds ago; retrying "
			"after %ds\n", (int)(now - _srv_failed_at), nats_pool_srv_retry_s);
		return -1;
	}

	pool_free_servers();
	for (i = 0; i < pool_cfg->server_cnt; i++) {
		got = nats_srv_expand(&pool_cfg->servers[i], 1,
			_servers + _servers_cnt, NATS_POOL_MAX_SERVERS - _servers_cnt,
			nats_pool_no_randomize, res, rctx, pool_srv_rand, NULL,
			&capped, &failed);
		_servers_cnt += got;
		total_capped += capped;
		if (failed && nats_rl_pass(&_srv_rl_fail, now, 30)) {
			char redacted[512];
			nats_url_srv_redact(pool_cfg->servers[i], redacted,
				sizeof(redacted));
			LM_WARN("NATS pool: the DNS SRV lookup of %s gave no server "
				"(no answer, no record, or no service); repeats "
				"suppressed for 30s\n", redacted);
		}
	}
	if (total_capped && nats_rl_pass(&_srv_rl_cap, now, 30))
		LM_WARN("NATS pool: %d server(s) from DNS SRV records left out: "
			"at most %d servers\n", total_capped, NATS_POOL_MAX_SERVERS);

	if (_servers_cnt == 0) {
		_srv_none = 1;
		_srv_failed_at = now;
		if (nats_rl_pass(&_srv_rl_none, now, 30))
			LM_WARN("NATS pool: no NATS server left after the DNS SRV "
				"lookups; continuing without NATS, lookups retried "
				"every %ds\n", nats_pool_srv_retry_s);
		return -1;
	}
	_srv_none = 0;
	return 0;
}

natsConnection *nats_pool_get(void)
{
	natsOptions *opts = NULL;
	natsStatus s;

	/* Return existing connection — let nats.c handle reconnection.
	 *
	 * IMPORTANT: Never destroy or replace _nc after creation.
	 * Multiple threads (watcher, producer, nats.c I/O) cache pointers
	 * to _nc and objects derived from it (_js, kvStore, kvWatcher).
	 * Destroying _nc invalidates all of them → use-after-free.
	 *
	 * nats.c's built-in reconnection handles failover transparently.
	 * Operations during the disconnected window return NATS errors,
	 * which callers handle gracefully. The reconnect callback bumps
	 * _reconnect_epoch so modules know to refresh KV handles. */
	if (_nc)
		return _nc;

	if (!pool_cfg) {
		LM_ERR("NATS pool: not registered (call nats_pool_register first)\n");
		return NULL;
	}

	/* only unusable SRV URLs were configured: parse_urls() warned about
	 * it once, before the processes were forked */
	if (pool_cfg->server_cnt == 0) {
		LM_DBG("NATS pool: no usable NATS server URL configured\n");
		return NULL;
	}

	/* resolve the DNS SRV URLs of this process (after the fork) */
	if (pool_expand_servers() < 0)
		return NULL;

	/* Initialize nats.c library — once per process.
	 * -1 lets nats.c pick default lock spin count. */
	if (!_lib_initialized) {
		s = nats_dl.nats_Open(-1);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: nats_Open failed: %s\n",
				nats_dl.natsStatus_GetText(s));
			return NULL;
		}
		_lib_initialized = 1;

		if (!_atfork_registered) {
			if (pthread_atfork(pool_prefork_teardown, NULL, NULL) == 0)
				_atfork_registered = 1;
			else
				LM_WARN("NATS pool: pthread_atfork failed; a NATS "
					"connection opened before fork would reach the "
					"children unusable\n");
		}
	}

	/* TLS probe: if tls:// URLs were configured, check whether nats.c
	 * was built with TLS support.  nats.c parses the URL scheme —
	 * tls:// triggers TLS internally; a TLS-less build rejects the
	 * URLs (NATS_ILLEGAL_STATE) at SetServers.
	 *
	 * _tls_probed is a PER-PROCESS static: every process that reaches
	 * here runs the probe once on its own first connect.  That is
	 * fine — the probe is read-only (a throwaway natsOptions), cheap,
	 * and idempotent; on a TLS-less libnats every process fails hard
	 * with the same guidance.  No cross-process coordination is
	 * needed or implied. */
	if (pool_cfg->use_tls) {
		if (!_tls_probed) {
			natsOptions *probe = NULL;
			int tls_ok = 0;

			_tls_probed = 1;

			if (nats_dl.natsOptions_Create(&probe) == NATS_OK) {
				if (nats_dl.natsOptions_SetServers(probe,
				    (const char **)_servers, _servers_cnt) == NATS_OK)
					tls_ok = 1;
				nats_dl.natsOptions_Destroy(probe);
			}

			if (!tls_ok) {
				LM_ERR("NATS pool: TLS requested "
					"(tls:// URLs) but the linked "
					"libnats was built without TLS "
					"support.  Install a TLS-built "
					"libnats (or set $NATS_DL_LIBNATS_PATH "
					"to one) and reload.  No silent "
					"plaintext downgrade.\n");
				return NULL;
			}
		}
	}

	/* Create connection options */
	s = nats_dl.natsOptions_Create(&opts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_Create failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return NULL;
	}

	/* Set server list: the configured URLs with the DNS SRV URLs
	 * replaced by their targets (pool_expand_servers()) */
	s = nats_dl.natsOptions_SetServers(opts,
		(const char **)_servers, _servers_cnt);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_SetServers failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		goto error;
	}

	if (pool_auth_apply(opts) < 0)
		goto error;
	/* user/password and token travel in the CONNECT message */
	if (nats_auth_sends_secret(&_auth) && !pool_cfg->use_tls &&
	    !pool_cfg->auth_plain_warned) {
		pool_cfg->auth_plain_warned = 1;
		LM_WARN("NATS pool: the %s is sent in plain text: use tls:// "
			"server URLs\n", nats_auth_method(&_auth) ==
			NATS_AUTH_TOKEN ? "token" : "password");
	}

	/* Configure reconnection behavior and register callbacks */
	/*
	 * Set nats.c internal reconnect to UNLIMITED (-1). nats.c permanently
	 * removes a server from its pool after max_reconnect failures
	 * (natsSrvPool_GetNextServer calls _freeSrv). With a finite limit,
	 * a long partition empties the pool and kills the connection forever.
	 *
	 * pool_cfg->max_reconnect only gates the startup loop below.
	 * Once connected, nats.c reconnect is unlimited so cluster gossip
	 * (INFO connect_urls) keeps working through any partition length.
	 */
	nats_dl.natsOptions_SetMaxReconnect(opts, -1);
	nats_dl.natsOptions_SetReconnectWait(opts, pool_cfg->reconnect_wait);
	/* Spread runtime reconnects: without jitter, all N worker processes
	 * reconnect in lockstep after a broker restart (a thundering herd that
	 * hammers the broker every reconnect_wait).  Jitter up to one full
	 * reconnect_wait window (TLS uses the same). */
	nats_dl.natsOptions_SetReconnectJitter(opts,
		(int64_t)pool_cfg->reconnect_wait, (int64_t)pool_cfg->reconnect_wait);
	/* Server order: by default libnats shuffles the server list, so the
	 * worker processes spread over the servers; no_randomize=1 makes every
	 * process try them in the configured order (primary / backup). */
	/* With a DNS SRV URL in the list the order is already the RFC 2782
	 * one (priority first, a weighted random choice inside a priority,
	 * pool_expand_servers()): a libnats shuffle would lose the priority
	 * order, so libnats keeps the list as given. */
	s = nats_dl.natsOptions_SetNoRandomize(opts,
		(nats_pool_no_randomize || pool_cfg_has_srv()) ? true : false);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_SetNoRandomize failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		goto error;
	}
	/* What is published while the connection is down waits in this
	 * buffer and is sent after the reconnect; once it is full a publish
	 * fails with NATS_INSUFFICIENT_BUFFER, counted by the module. */
	s = nats_dl.natsOptions_SetReconnectBufSize(opts,
		nats_pool_reconnect_buf_size);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: natsOptions_SetReconnectBufSize(%d) failed: %s\n",
			nats_pool_reconnect_buf_size, nats_dl.natsStatus_GetText(s));
		goto error;
	}
	/* Liveness probing.  Publishes run inline in SIP workers; a black-holed
	 * broker (network drop with no RST) leaves the socket writable until
	 * cnats's ping mechanism declares the connection DISCONNECTED.  The
	 * default 2-minute ping interval x 2 missed pings means ~4 minutes of
	 * workers blocking/buffering before fast-fail trips.  Shorten it: a
	 * 10 s ping with 2 missed pings detects the dead link in ~20 s. */
	nats_dl.natsOptions_SetPingInterval(opts, (int64_t)NATS_POOL_PING_INTERVAL_MS);
	nats_dl.natsOptions_SetMaxPingsOut(opts, NATS_POOL_MAX_PINGS_OUT);
	nats_dl.natsOptions_SetDisconnectedCB(opts, pool_disconnected_cb, NULL);
	nats_dl.natsOptions_SetReconnectedCB(opts, pool_reconnected_cb, NULL);

	/* Async first connect: with the broker unreachable at BOOT,
	 * natsConnection_Connect() returns NATS_NOT_YET_CONNECTED
	 * immediately and cnats keeps dialing in the background using the
	 * reconnect settings above, firing the connected callback on first
	 * success.  Without this every OpenSIPS process blocked inside the
	 * synchronous retry loop below for the full max_reconnect budget
	 * (~2 min) during child_init -- core timers stalled and SIP was
	 * unresponsive (caught by test_boot_degraded_e2e.sh).  Reuse
	 * pool_reconnected_cb as the first-connect callback: it sets
	 * _connected, bumps the reconnect epoch and marks KV handles
	 * stale -- exactly the post-connect bookkeeping needed here. */
	nats_dl.natsOptions_SetRetryOnFailedConnect(opts, true,
		pool_reconnected_cb, NULL);

	/* TLS configuration -- sourced from the tls_mgm "nats" client
	 * domain (apply_tls_from_mgm).  Set up only when at least one
	 * configured URL is tls://. */
	if (pool_cfg->use_tls) {
		nats_dl.natsOptions_SetSecure(opts, true);
		if (apply_tls_from_mgm(opts) < 0)
			goto error;
	}

	/* Retry connection with bounded attempts. pool_cfg->max_reconnect
	 * gates startup only; runtime reconnection is unlimited (set above). */
	{
		int attempts = 0;
		for (;;) {
			s = nats_dl.natsConnection_Connect(&_nc, opts);
			if (s == NATS_OK)
				break;

			/* Not connected: the connection object is live and
			 * dialing in the background (SetRetryOnFailedConnect).
			 * Continue DEGRADED instead of blocking this process --
			 * _connected stays 0 (fast-fails everywhere) until the
			 * first-connect callback fires.  libnats answers this way,
			 * with no error detail and no callback, for a refused
			 * password or TLS handshake too: it keeps dialing.  So the
			 * warning cannot say which it is. */
			if (s == NATS_NOT_YET_CONNECTED) {
				LM_WARN("NATS pool: not connected at startup (broker "
					"unreachable, or credentials or TLS refused); "
					"continuing degraded with background "
					"connect retries\n");
				break;
			}

			/* Non-transient failure classes: retrying cannot
			 * succeed until an operator fixes configuration (TLS
			 * material, credentials, malformed options).  Fail the
			 * boot NOW instead of burning max_reconnect x sleep
			 * (~minutes) in every process's child_init.  Only what
			 * libnats returns before it starts dialing lands here; a
			 * refused password or handshake surfaces as
			 * NATS_NOT_YET_CONNECTED above, like a down broker. */
			if (s == NATS_SSL_ERROR ||
			    s == NATS_CONNECTION_AUTH_FAILED ||
			    s == NATS_INVALID_ARG) {
				char stack_buf[1024];
				nats_dl.nats_GetLastErrorStack(stack_buf,
					sizeof(stack_buf));
				LM_ERR("NATS pool: non-transient connect failure "
					"(%s [%s]) -- fix the TLS/auth/URL "
					"configuration; not retrying\n",
					nats_dl.natsStatus_GetText(s),
					stack_buf[0] ? stack_buf : "no detail");
				goto error;
			}

			attempts++;
			{
				char stack_buf[1024];
				nats_dl.nats_GetLastErrorStack(stack_buf, sizeof(stack_buf));
				LM_ERR("NATS pool: connection attempt %d/%d failed: "
					"%s [%s]\n",
					attempts, pool_cfg->max_reconnect,
					nats_dl.natsStatus_GetText(s),
					stack_buf[0] ? stack_buf : "no detail");
			}

			if (attempts >= pool_cfg->max_reconnect) {
				LM_ERR("NATS pool: giving up after %d attempts\n",
					attempts);
				goto error;
			}

			/* Per-process jitter on the retry sleep so N workers that all
			 * start (or recover) against a down broker don't retry in
			 * lockstep.  Derived from the PID so it is stable but spread;
			 * up to half the base wait on top of it. */
			{
				int base = pool_cfg->reconnect_wait;
				int span = base / 2 + 1;
				int jit  = (int)((unsigned)getpid() % (unsigned)span);
				nats_dl.nats_Sleep(base + jit);
			}
		}
	}

	nats_dl.natsOptions_Destroy(opts);

	/* Degraded start: skip the connected bookkeeping -- the
	 * first-connect callback handles it when the broker appears. */
	if (s != NATS_OK)
		return _nc;

	atomic_store(&_connected, 1);

	/* Log connected URL — natsConnection_GetConnectedUrl is documented
	 * to strip credentials, but redact defensively in case any nats.c
	 * version preserves them. */
	{
		char url[256];
		char redacted[256];
		url[0] = '\0';   /* defensive: see pool_reconnected_cb */
		nats_dl.natsConnection_GetConnectedUrl(_nc, url, sizeof(url));
		nats_redact_url(url, redacted, sizeof(redacted));
		LM_INFO("NATS pool: connected to %s (%d server(s) configured)\n",
			redacted, pool_cfg->server_cnt);
	}

	return _nc;

error:
	if (opts)
		nats_dl.natsOptions_Destroy(opts);
	return NULL;
}

/**
 * Get the shared JetStream context for this worker process.
 *
 * Creates the jsCtx on first call using the shared connection.
 * The async publish ack handler (pool_js_pub_ack_handler) is registered
 * at creation time to handle JetStream publish acknowledgments.
 *
 * @return  jsCtx pointer on success, NULL on error (no connection,
 *          or JetStream context creation failure).
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The jsCtx is process-local and never shared across processes.
 */
jsCtx *nats_pool_get_js(void)
{
	natsStatus s;
	jsOptions jsOpts;

	/* Return cached JetStream context */
	if (_js)
		return _js;

	/* Ensure we have a connection first */
	if (!_nc && !nats_pool_get())
		return NULL;

	/* Initialize JetStream options, then apply the shared policy (ack
	 * handler, MaxPending cap, StallWait, per-op Wait timeout) — see
	 * nats_js_opts.h for the rationale on each knob. */
	nats_dl.jsOptions_Init(&jsOpts);
	nats_pool_js_opts_apply(&jsOpts, pool_js_pub_ack_handler,
		nats_pool_kv_op_timeout_ms);

	s = nats_dl.natsConnection_JetStream(&_js, _nc, &jsOpts);
	if (s != NATS_OK) {
		LM_ERR("NATS pool: JetStream context creation failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return NULL;
	}

	LM_INFO("NATS pool: JetStream context created\n");
	return _js;
}

/**
 * Get a KV store handle for a named bucket.
 *
 * Checks a process-local cache first.  If the bucket handle is not cached,
 * attempts to bind to an existing bucket on the server; if that fails,
 * creates a new bucket with the specified parameters.
 *
 * The cache is invalidated on reconnection via the _kv_stale atomic flag.
 * When a reconnect occurs, stale kvStore handles may reference outdated
 * server-side state (streams, consumers), so the cache is cleared and
 * fresh handles are obtained.
 *
 * @param bucket    KV bucket name (must be a valid NATS subject token).
 * @param replicas  Replication factor (used only when creating a new bucket).
 * @param history   History depth (used only when creating a new bucket).
 * @param ttl_secs  Bucket TTL in seconds (0 = no TTL; creation only).
 * @return          kvStore pointer on success, NULL on error.
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The KV cache is process-local.  The _kv_stale flag is set by the
 * reconnect callback (nats.c thread) and consumed here via atomic_exchange.
 */
/* Read the bound bucket's backing-stream MaxAge (ns). */
int nats_pool_bucket_maxage_ns(const char *bucket, int64_t *out_ns)
{
	char stream[160];
	jsStreamInfo *si = NULL;
	jsErrCode jerr = 0;
	natsStatus s;

	if (!_js || !bucket || !out_ns)
		return -1;
	snprintf(stream, sizeof(stream), "KV_%s", bucket);

	s = nats_dl.js_GetStreamInfo(&si, _js, stream, NULL, &jerr);
	if (s != NATS_OK || !si || !si->Config) {
		LM_WARN("NATS pool: GetStreamInfo(%s) failed (%s, jerr=%d); cannot "
			"read bucket MaxAge\n", stream, nats_dl.natsStatus_GetText(s), jerr);
		if (si)
			nats_dl.jsStreamInfo_Destroy(si);
		return -1;
	}
	*out_ns = (int64_t)si->Config->MaxAge;
	nats_dl.jsStreamInfo_Destroy(si);
	return 0;
}

/* read the bound bucket's backing-stream MaxMsgsPerSubject
 * (the KV history depth) for the module's startup surfacing.  Mirrors
 * nats_pool_bucket_maxage_ns.  0 = ok (*out_mmps filled), -1 = unavailable. */
int nats_pool_bucket_mmps(const char *bucket, int64_t *out_mmps)
{
	char stream[160];
	jsStreamInfo *si = NULL;
	jsErrCode jerr = 0;
	natsStatus s;

	if (!_js || !bucket || !out_mmps)
		return -1;
	snprintf(stream, sizeof(stream), "KV_%s", bucket);

	s = nats_dl.js_GetStreamInfo(&si, _js, stream, NULL, &jerr);
	if (s != NATS_OK || !si || !si->Config) {
		LM_WARN("NATS pool: GetStreamInfo(%s) failed (%s, jerr=%d); cannot "
			"read bucket MaxMsgsPerSubject\n", stream,
			nats_dl.natsStatus_GetText(s), jerr);
		if (si)
			nats_dl.jsStreamInfo_Destroy(si);
		return -1;
	}
	*out_mmps = (int64_t)si->Config->MaxMsgsPerSubject;
	nats_dl.jsStreamInfo_Destroy(si);
	return 0;
}

kvStore *nats_pool_get_kv(const char *bucket, int replicas,
                          int history, int64_t ttl_secs)
{
	int i;
	natsStatus s;
	kvStore *kv = NULL;
	kvConfig kvCfg;

	if (!bucket || !*bucket) {
		LM_ERR("NATS pool: empty KV bucket name\n");
		return NULL;
	}
	/* Reject a name that would not fit the cache key buffer rather than
	 * snprintf-truncating it below: two distinct buckets sharing a long
	 * prefix would otherwise collide on the truncated key and the cache
	 * would hand back the wrong kvStore handle. */
	if (strlen(bucket) >= sizeof(_kv_cache[0].bucket)) {
		LM_ERR("NATS pool: KV bucket name too long (max %zu): '%s'\n",
			sizeof(_kv_cache[0].bucket) - 1, bucket);
		return NULL;
	}

	/* Ensure we have a JetStream context */
	if (!_js && !nats_pool_get_js())
		return NULL;

	/* Check if reconnection invalidated KV handles.
	 *
	 * atomic_exchange atomically reads the current value of _kv_stale
	 * and sets it to 0 in a single operation.  This eliminates the
	 * TOCTOU race that would exist with separate read-then-write:
	 * a reconnect callback could set _kv_stale=1 between our read
	 * and our clear, causing us to lose the invalidation signal.
	 *
	 * libnats requires the caller to destroy kvStore handles when
	 * done; see nats/nats.h kvStore_Destroy().  Earlier revisions
	 * relied on refcounting to clean these up on reconnect, but the
	 * public contract puts destruction on us, and skipping it leaks
	 * one handle per bucket per reconnect event. */
	if (atomic_exchange(&_kv_stale, 0)) {
		for (i = 0; i < _kv_cache_cnt; i++) {
			if (_kv_cache[i].kv) {
				nats_dl.kvStore_Destroy(_kv_cache[i].kv);
				_kv_cache[i].kv = NULL;
			}
		}
		_kv_cache_cnt = 0;
		LM_NOTICE("NATS pool: KV cache cleared after reconnect\n");
	}

	/* Check cache for an existing handle for this bucket */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv &&
		    strcmp(_kv_cache[i].bucket, bucket) == 0)
			return _kv_cache[i].kv;
	}

	/* Try to bind to existing bucket on the server first */
	s = nats_dl.js_KeyValue(&kv, _js, bucket);
	if (s != NATS_OK) {
		/* Bucket does not exist on server — create it */
		LM_DBG("NATS pool: KV bucket '%s' not found, creating\n",
			bucket);

		memset(&kvCfg, 0, sizeof(kvCfg));
		kvCfg.Bucket = bucket;
		kvCfg.Replicas = replicas > 0 ? replicas : 1;
		kvCfg.History = history > 0 ? history : 1;
		if (ttl_secs > 0)
			kvCfg.TTL = ttl_secs * 1000000000LL; /* seconds to nanos */

		s = nats_dl.js_CreateKeyValue(&kv, _js, &kvCfg);
		if (s != NATS_OK) {
			LM_ERR("NATS pool: KV bucket '%s' create failed: %s\n",
				bucket, NATS_ERR_TEXT(s));
			return NULL;
		}
		LM_INFO("NATS pool: KV bucket '%s' created "
			"(replicas=%d, history=%d, ttl=%llds)\n",
			bucket, kvCfg.Replicas, kvCfg.History,
			(long long)ttl_secs);
	} else {
		LM_DBG("NATS pool: bound to existing KV bucket '%s'\n", bucket);
	}

	/* Cache the handle for future lookups */
	if (_kv_cache_cnt < NATS_POOL_MAX_KV_BUCKETS) {
		snprintf(_kv_cache[_kv_cache_cnt].bucket,
			sizeof(_kv_cache[_kv_cache_cnt].bucket), "%s", bucket);
		_kv_cache[_kv_cache_cnt].kv = kv;
		_kv_cache_cnt++;
	} else {
		/* Cache full: do NOT hand back an uncached handle.  Callers
		 * treat the result as pool-owned and never kvStore_Destroy()
		 * it, so every subsequent call for this bucket would create
		 * and leak another handle.  Destroy this one and fail loudly
		 * instead -- raise NATS_POOL_MAX_KV_BUCKETS if more buckets
		 * are genuinely needed. */
		LM_ERR("NATS pool: KV bucket cache full (%d buckets); refusing "
			"bucket '%s' to avoid leaking handles.  Raise "
			"NATS_POOL_MAX_KV_BUCKETS if you need more.\n",
			NATS_POOL_MAX_KV_BUCKETS, bucket);
		nats_dl.kvStore_Destroy(kv);
		return NULL;
	}

	return kv;
}

/*
 * fork() safety.  nats.c is not fork-safe: the connection's I/O threads and
 * the library's timer, callback and GC threads exist only in the process
 * that started them.  When a module uses NATS before the processes are
 * forked (b2b_entities restores its state from cachedb in mod_init), the
 * attendant opens the pool; a forked child would inherit the handles
 * without the threads behind them, and every request there times out.
 *
 * Right before the attendant forks, close everything -- KV handles, the
 * JetStream context, the connection and the library itself -- so each
 * child opens its own.  The reconnect epoch is bumped so that a module
 * still holding a KV handle from before fork fetches a new one.  Only the
 * attendant (process_no 0) does this: a worker that forks (e.g. the exec
 * module) keeps its connection.
 */
#define NATS_POOL_PREFORK_CLOSE_MS 2000

static void pool_prefork_teardown(void)
{
	natsStatus s;
	int i;

	if (process_no != 0 || !_lib_initialized)
		return;

	LM_INFO("NATS pool: closing the connection opened before fork; "
		"each process connects on its own\n");
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv) {
			nats_dl.kvStore_Destroy(_kv_cache[i].kv);
			_kv_cache[i].kv = NULL;
		}
	}
	_kv_cache_cnt = 0;
	if (_js) {
		nats_dl.jsCtx_Destroy(_js);
		_js = NULL;
	}
	if (_nc) {
		nats_dl.natsConnection_Destroy(_nc);
		_nc = NULL;
	}
	s = nats_dl.nats_CloseAndWait(NATS_POOL_PREFORK_CLOSE_MS);
	if (s != NATS_OK)
		LM_WARN("NATS pool: closing the library before fork: %s\n",
			nats_dl.natsStatus_GetText(s));
	_lib_initialized = 0;
	atomic_store(&_connected, 0);
	atomic_store(&_kv_stale, 1);
	atomic_fetch_add(&_reconnect_epoch, 1);
}

/**
 * Destroy the connection pool and free all resources.
 *
 * Called from mod_destroy during OpenSIPS shutdown.
 *
 * ## Shutdown ordering
 *
 * The destruction sequence is critical because nats.c's internal I/O
 * threads may still be running when we enter this function:
 *
 * 1. KV handles destroyed first — they depend on _js.
 * 2. JetStream context destroyed — it depends on _nc.
 * 3. Connection drained THEN destroyed — nats_dl.natsConnection_Drain() flushes
 *    pending messages and waits for in-flight operations to complete
 *    before closing.  This ensures the I/O threads finish their work
 *    before we destroy the connection.  Without draining first,
 *    nats_dl.natsConnection_Destroy() would tear down the socket while I/O
 *    threads may still be reading/writing, causing races.
 * 4. Shared config freed last — it's SHM, no thread dependency.
 *
 * Note: Even with this ordering, there is a small window where
 * callbacks could fire between the drain completing and the destroy
 * call.  In practice this is harmless because the callbacks only
 * set atomic flags and call write(), which are idempotent.
 *
 * Thread safety: Must only be called from OpenSIPS process context
 * during shutdown (mod_destroy).
 */
/*
 * Drop one registration reference.  The pool is actually torn down only on
 * the LAST unregister, so the shared connection survives while any loaded
 * NATS module still uses it, and is always destroyed when the last module
 * is unloaded (even when event_nats -- the historical sole caller of
 * nats_pool_destroy -- is not loaded).  Call once per module from
 * mod_destroy, matching the module's successful nats_pool_register().
 */
void nats_pool_unregister(void)
{
	if (_register_count > 0)
		_register_count--;
	if (_register_count > 0) {
		LM_DBG("NATS pool: unregister (%d registration(s) remain)\n",
			_register_count);
		return;
	}
	nats_pool_destroy();
}

void nats_pool_destroy(void)
{
	int i;

	/* Idempotent: tolerate a direct call or a repeated last-unregister. */
	if (!pool_cfg && !_nc && !_js) {
		_register_count = 0;
		return;
	}

	LM_INFO("NATS pool: destroying\n");

	/* Step 1: Destroy KV handles (depend on _js) */
	for (i = 0; i < _kv_cache_cnt; i++) {
		if (_kv_cache[i].kv) {
			nats_dl.kvStore_Destroy(_kv_cache[i].kv);
			_kv_cache[i].kv = NULL;
		}
	}
	_kv_cache_cnt = 0;

	/* Step 2: Destroy JetStream context (depends on _nc).  First wait
	 * (bounded) for outstanding async publishes to be acked, so events
	 * published just before shutdown are not silently abandoned when the
	 * JS context is torn down. */
	if (_js) {
		jsPubOptions po;
		int budget_ms = nats_pool_drain_timeout_ms > 0
			? nats_pool_drain_timeout_ms : 5000;
		nats_dl.jsPubOptions_Init(&po);
		po.MaxWait = budget_ms;
		(void)nats_dl.js_PublishAsyncComplete(_js, &po);
		nats_dl.jsCtx_Destroy(_js);
		_js = NULL;
	}

	/* Step 3: Drain then destroy connection.
	 * Drain flushes pending publishes, waits for acks, then closes.
	 * Use DrainTimeout with an explicit bound (nats_pool_drain_timeout_ms,
	 * default 5 s, modparam-tunable per loaded module) so we don't
	 * hang mod_destroy if the broker is unreachable.  Log non-OK
	 * with the configured budget so an operator investigating
	 * ack-loss has both a fingerprint and a hint at which knob to
	 * raise, then proceed to Destroy regardless -- shutdown must
	 * complete. */
	if (_nc) {
		int budget_ms = nats_pool_drain_timeout_ms > 0
			? nats_pool_drain_timeout_ms : 5000;
		natsStatus ds = nats_dl.natsConnection_DrainTimeout(_nc, budget_ms);
		if (ds != NATS_OK) {
			LM_WARN("NATS pool: connection drain returned %s "
				"after %d ms; in-flight JetStream publishes "
				"may not have acked before destroy.  Raise "
				"drain_timeout_ms (event_nats or "
				"cachedb_nats) if you "
				"are seeing ack loss on shutdown.\n",
				nats_dl.natsStatus_GetText(ds), budget_ms);
		}
		nats_dl.natsConnection_Destroy(_nc);
		_nc = NULL;
	}

	atomic_store(&_connected, 0);

	/* Step 4: Free shared config (SHM) */
	if (pool_cfg) {
		for (i = 0; i < pool_cfg->server_cnt; i++) {
			if (pool_cfg->servers[i])
				shm_free(pool_cfg->servers[i]);
		}
		shm_free(pool_cfg);
		pool_cfg = NULL;
	}

	_register_count = 0;
}

/* See nats_pool.h.  pool_cfg is set pre-fork and read-only after. */
int nats_pool_has_servers(void)
{
	return (pool_cfg && pool_cfg->server_cnt > 0 && !_srv_none) ? 1 : 0;
}

/**
 * Check if the pool is currently connected.
 *
 * @return  1 if connected, 0 if disconnected.
 *
 * Thread safety: Safe to call from any context.  Uses atomic_load
 * on _connected which is set by callbacks on the nats.c I/O thread.
 */
int nats_pool_is_connected(void)
{
	return atomic_load(&_connected) ? 1 : 0;
}

/**
 * Get the currently connected server URL for status reporting.
 *
 * Queries nats_dl.natsConnection_GetConnectedUrl() directly on each call to
 * avoid returning a stale pointer.  The result is written into a
 * process-local static buffer and is valid until the next call.
 *
 * @return  Server URL string (process-local, do not free), or
 *          "not connected" if no active connection.
 *
 * Thread safety: Called from OpenSIPS process context only.
 * The static buffer is process-local (each forked process has its own).
 * We call nats_dl.natsConnection_GetConnectedUrl() which is thread-safe in
 * nats.c (it locks internally), so this is safe even if the reconnect
 * callback fires concurrently — we always get a consistent snapshot.
 */
const char *nats_pool_get_server_info(void)
{
	static char _server_info_buf[512];

	/* Fetch + redact policy lives in nats_server_info.h, behaviourally
	 * locked by test/test_server_info_redact.c. */
	return nats_pool_server_info_build(_nc,
		nats_dl.natsConnection_GetConnectedUrl,
		_server_info_buf, sizeof(_server_info_buf));
}

/**
 * Get the current reconnect epoch counter.
 *
 * Incremented atomically each time nats.c reports a successful
 * reconnection.  Modules can save the value and compare later to
 * detect that a reconnection occurred (e.g., to re-establish
 * watchers or rebuild indexes).
 *
 * @return  Current epoch counter value.
 *
 * Thread safety: Safe to call from any context.  Uses atomic_load.
 */
int nats_pool_get_reconnect_epoch(void)
{
	return atomic_load(&_reconnect_epoch);
}

/* True once any module has called nats_pool_register().  Lets a module
 * decide whether to contribute a default URL (standalone) or inherit a
 * pool another NATS module already registered. */
int nats_pool_is_registered(void)
{
	return pool_cfg != NULL;
}

#ifdef UNIT_TESTS
void nats_pool_test_reset(void)
{
	nats_pool_destroy();
	_register_count = 0;

	/* process-local connection state */
	pool_free_servers();
	_srv_none = 0;
	_srv_failed_at = 0;
	_srv_rl_fail = _srv_rl_cap = _srv_rl_none = 0;
	_tls_probed = 0;
	_lib_initialized = 0;
	atomic_store(&_connected, 0);
	atomic_store(&_reconnect_epoch, 0);
	atomic_store(&_kv_stale, 0);

	/* what the modules and their modparams set */
	_tls_api = NULL;
	_pub_ack_cb = NULL;
	_srv_resolve = NULL;
	_srv_resolve_ctx = NULL;
	memset(&_auth, 0, sizeof(_auth));
	nats_pool_drain_timeout_ms = 5000;
	_drain_explicit = 0;
	nats_pool_no_randomize = 0;
	_no_randomize_explicit_off = 0;
	nats_pool_reconnect_buf_size = NATS_POOL_RECONNECT_BUF_SIZE_DEFAULT;
	_reconnect_buf_explicit = 0;
	nats_pool_js_ack_timeout_ms = NATS_JS_ACK_TIMEOUT_MS_DEFAULT;
	nats_pool_js_publish_retries = NATS_JS_PUBLISH_RETRIES_DEFAULT;
	nats_pool_kv_op_timeout_ms = 1000;
	nats_pool_srv_retry_s = 5;
}
#endif
