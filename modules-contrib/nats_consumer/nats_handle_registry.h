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
 */

/*
 * nats_handle_registry -- SHM-backed hash table of consumer handles.
 *
 * The registry is the single source of truth for bound JetStream consumer
 * configurations.  Handles are added/removed at runtime via the MI bind/
 * unbind commands or script functions.
 *
 * Concurrency:
 *   - Lookups (hot path) take a per-bucket read lock.
 *   - Bind/unbind take the matching bucket write lock; the global rwlock
 *     is taken only for registry-wide iteration and teardown.
 *   - The runtime counters block inside each handle is guarded by a
 *     per-handle rwlock; stats updates do not block lookups.
 *
 * Memory:
 *   - All handle allocations live in SHM.  Callers transfer ownership
 *     to the registry via nats_registry_bind().
 */

#ifndef NATS_HANDLE_REGISTRY_H
#define NATS_HANDLE_REGISTRY_H

#include <stdint.h>
#include <time.h>
#include "../../str.h"

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../rw_locking.h"
#endif

/* Forward declaration; full type defined in nats_ring.h.  The handle
 * keeps a pointer to the SHM-backed per-handle ring; consumers include
 * nats_ring.h directly when they need to operate on it. */
struct nats_ring;

typedef enum {
	NATS_CONSUMER_DURABLE = 0,
	NATS_CONSUMER_EPHEMERAL,
	NATS_CONSUMER_ORDERED,    /* reserved -- not yet implemented */
} nats_consumer_type_e;

typedef enum {
	NATS_DELIVER_ALL = 0,
	NATS_DELIVER_LAST,
	NATS_DELIVER_NEW,
	NATS_DELIVER_LAST_PER_SUBJECT,
	NATS_DELIVER_BY_START_SEQ,
	NATS_DELIVER_BY_START_TIME,
} nats_deliver_policy_e;

typedef enum {
	NATS_ACK_EXPLICIT = 0,
	NATS_ACK_NONE,
	NATS_ACK_ALL,
} nats_ack_policy_e;

typedef enum {
	NATS_REPLAY_INSTANT = 0,
	NATS_REPLAY_ORIGINAL,
} nats_replay_policy_e;

/* Upper bound on simultaneously-bound handles in a single opensips
 * instance.  Used both as a cap (bind past this returns -3) and to size
 * the consumer process's process-local natsMsg* ref table.  16 bits
 * worth is overkill; the limit is about keeping the ref table shallow.
 */
#define NATS_REGISTRY_MAX_HANDLES 256

typedef struct nats_handle {
	str id;                             /* registry key; SHM-owned */
	str stream;                         /* SHM-owned */
	str durable;                        /* SHM-owned, empty for ephemeral */
	nats_consumer_type_e type;

	/* Recyclable per-handle index, allocated from a free-slot pool
	 * (index_used[]) inside nats_registry_bind and returned to the pool
	 * on reap.  Valid range: [0, NATS_REGISTRY_MAX_HANDLES).
	 * Used to pack (handle_idx, slot_idx, generation) into an ack token
	 * so the consumer process can look up the stored natsMsg* without
	 * a hash.  Stable for the lifetime of the handle; reused by a later
	 * bind once this handle has been reaped. */
	uint16_t index;

	/* filters */
	str filter;                         /* single-subject filter */
	str filters_csv;                    /* multi-filter raw CSV */

	/* delivery policy */
	nats_deliver_policy_e deliver_policy;
	uint64_t start_seq;
	int64_t  start_time_unix_ns;
	nats_replay_policy_e replay_policy;

	/* ack */
	nats_ack_policy_e ack_policy;
	int ack_wait_ms;
	int max_deliver;
	str backoff_csv;
	int max_ack_pending;

	/* shaping */
	int headers_only;
	int sample_freq;
	int rate_limit_bps;
	int inactive_threshold_ms;

	/* multi-env */
	str js_domain;
	str api_prefix;

	/* Per-handle ring capacity override.  If non-zero at bind time,
	 * the registry sizes the SHM ring to this value instead of the
	 * module default (NATS_HANDLE_RING_CAPACITY).  Must be a power of
	 * two >= 2; the parser rejects anything else so the registry can
	 * trust the value.  0 = "use default". */
	uint32_t ring_capacity;

	/* Per-handle Fetch tuning overrides for the consumer process.  0 in
	 * either field means "use the module-global default" (the
	 * `fetch_batch` / `fetch_timeout_ms` modparams in nats_consumer.c).
	 * Non-zero values let high-throughput durables widen the batch
	 * without affecting low-rate handles on the same opensips. */
	uint32_t fetch_batch;
	uint32_t fetch_timeout_ms;


	/* runtime (guarded by rlock) */
	rw_lock_t *rlock;
	time_t created_at;
	time_t last_used_at;
	uint64_t pulls_requested;
	uint64_t msgs_delivered;
	uint64_t acks;
	uint64_t naks;
	uint64_t terms;
	uint64_t redeliveries;
	/* Messages auto-Termed by the consumer-side poison cap because their
	 * NumDelivered exceeded poison_max_deliver (a subset of `terms`). */
	uint64_t poisoned;
	/* Back-pressure / error telemetry.  Bumped by the consumer process
	 * (sole producer) with relaxed atomics; read by the attendant's MI
	 * handlers (nats_consumer_list / nats_consumer_stats).  Kept distinct
	 * because they describe different operator-visible conditions:
	 *
	 *   fetch_skips_full   -- the ring was already full so the Fetch was
	 *                         skipped entirely.  NO message was touched;
	 *                         the broker still owns the un-fetched messages
	 *                         and redelivers them cleanly.  Pure flow
	 *                         control, NOT data loss.
	 *   backpressure_drops -- a message WAS fetched but could not be handed
	 *                         to the worker ring (msg-ref table exhausted or
	 *                         ring full on push).  It is not acked, so the
	 *                         broker redelivers after ack_wait.
	 *   fetch_errors       -- a natsSubscription_Fetch returned a hard error
	 *                         (vanished consumer, transient broker error).
	 */
	uint64_t fetch_skips_full;
	uint64_t backpressure_drops;
	uint64_t fetch_errors;
	int last_error_code;
	str last_error_msg;

	/* Worker-tick backoff for ensure_subscription_for_handle().
	 *
	 * Touched only by the consumer process from reconcile_subs_cb(); not
	 * read by SIP workers, so no inter-process synchronisation needed.
	 *
	 * Without backoff, a handle whose broker-side consumer has been
	 * deleted (e.g. operator-side `nats consumer rm`) would retry its
	 * js_AddConsumer / js_PullSubscribe sequence every IDLE_RETRY_MS
	 * (1 s default) indefinitely, flooding logs and starving fresh
	 * handles' setup on a busy registry tick.
	 *
	 * Semantics:
	 *   ensure_failures        = consecutive ensure_subscription_for_handle
	 *                            calls that returned -1.  Reset to 0 on
	 *                            the first success.
	 *   ensure_next_retry_at   = wall-clock-seconds gate (time(NULL))
	 *                            below which the next reconcile tick
	 *                            skips this handle.  0 = retry immediately
	 *                            (clean handles, freshly bound handles).
	 *
	 * Backoff schedule is exponential, capped at 60 s, computed inline
	 * in reconcile_subs_cb so handles needing custom policy can still be
	 * added later without re-walking every call site.
	 *
	 * sub_torn_down=1 forces both back to zero so a rebind starts fresh. */
	unsigned ensure_failures;
	time_t   ensure_next_retry_at;

	/* SHM ring for this handle -- created on bind, destroyed on unbind.
	 * Producer: the dedicated consumer process.
	 * Consumer: SIP workers.
	 * Ownership: the registry owns the ring and tears it down when the
	 * handle is released.  May be NULL under TEST_SHIM where the test
	 * shim does not provide eventfd-compatible allocation. */
	struct nats_ring *ring;

	/* Refcount guarding against unbind-while-in-use.  Incremented by
	 * consumer-process ring push-success and any worker that holds
	 * an ack IPC pending for this handle; decremented when that
	 * operation completes.  Combined with the retire/reap lifecycle
	 * below: unbind returns 0 but the actual free is deferred until
	 * both `retire` is set AND `sub_torn_down` is set AND
	 * `pending_ops` has drained to zero.  Atomic SEQ_CST for
	 * cross-process visibility. */
	int pending_ops;

	/* Retire/reap lifecycle.
	 *
	 * `retire` is set by nats_registry_unbind() the moment the handle
	 *   is unlinked from its bucket (so new lookups fail).  The handle
	 *   object itself is NOT freed yet -- the consumer process may
	 *   still hold a borrowed pointer in its proc_sub_state_t and
	 *   workers may still have in-flight ack-IPC references.
	 *
	 * `sub_torn_down` is set by the consumer process right after it
	 *   destroys the natsSubscription + frees the process-local
	 *   proc_sub_state_t strings for this handle.  A retired handle
	 *   that the consumer process has never seen (bind-then-unbind
	 *   before the reconcile loop ran) still gets this flag raised
	 *   because the consumer process's retire scan runs unconditionally.
	 *
	 * nats_registry_reap() frees the handle when retire == 1 AND
	 * sub_torn_down == 1 AND pending_ops == 0.  All three conditions
	 * are atomic-SEQ_CST so the ordering across processes is well
	 * defined without a heavy barrier. */
	volatile int retire;
	volatile int sub_torn_down;

	/* Active JetStream subscription handle.
	 * Owned by the consumer process (not SHM; process-local).
	 * NULL until the consumer process creates the subscription.
	 *
	 * Not written by SIP workers.  Treated as opaque in shared headers;
	 * the consumer process code casts this to natsSubscription *. */
	void *subscription;

	/* intrusive bucket chain.  After retire=1 the handle is removed
	 * from the bucket and instead lives on the registry's retire list
	 * (see nats_handle_registry.c), walked by nats_registry_reap(). */
	struct nats_handle *next;
} nats_handle_t;

/**
 * Initialize the registry with `bucket_count` buckets.
 *
 * @param bucket_count  Bucket count; <= 0 falls back to 256.
 * @return              0 on success (idempotent: a second call warns
 *                      and returns 0), -1 on SHM exhaustion or lock
 *                      init failure (everything allocated so far is
 *                      rolled back).
 *
 * Allocation: the registry, its bucket array and all rwlocks live in
 * SHM, freed only by nats_registry_destroy().  Locking: none taken.
 *
 * Context: mod_init (main process, PRE-FORK) so every child inherits
 * the same mapping.
 */
int nats_registry_init(int bucket_count);

/**
 * Tear down the registry: free every handle still bound or parked on
 * the retire list (ignoring the retire bookkeeping -- mod_destroy is
 * the last writer), the bucket array, all locks and the registry
 * itself.  NULL-safe when never initialized.
 *
 * @return  nothing.
 *
 * Locking: takes the global, each bucket and the retire WRITE locks to
 * flush in-flight readers, then destroys them.
 *
 * Context: mod_destroy only (no other process may touch the registry
 * any more).
 */
void nats_registry_destroy(void);

/**
 * Transfer ownership of a handle into the registry.
 *
 * @param h  A caller-owned SHM handle (from nats_handle_parse()).
 * @return
 *    0 on success
 *   -1 on duplicate id
 *   -2 on SHM exhaustion / internal error
 *   -3 on handle-count cap reached (NATS_REGISTRY_MAX_HANDLES)
 *
 * Ownership: on success the REGISTRY owns `h` (rlock initialized,
 * created_at set, a recyclable index and an SHM ring assigned); it is
 * eventually freed by the retire/reap lifecycle or registry destroy.
 * On failure the CALLER retains ownership and must free it with
 * nats_handle_free().
 *
 * Locking: takes the target bucket's WRITE lock for the duplicate
 * check + ring create + insert; the index allocator is a lock-free
 * CAS.
 *
 * Context: any process -- real callers are mod_init (pre-fork `bind`
 * modparams), the startup-route script bind (SIP worker) and the MI
 * bind handler.
 */
int nats_registry_bind(nats_handle_t *h);

/**
 * Remove a handle by id (retire; the physical free is deferred).
 *
 * Lifecycle:
 *   1. unbind marks the handle retired and unlinks it from its bucket
 *      chain so subsequent lookups miss, then parks it on the retire
 *      list.
 *   2. The consumer process observes `retire` on its next iteration,
 *      destroys the JetStream subscription + frees the process-local
 *      proc_sub_state_t, and sets `sub_torn_down`.
 *   3. nats_registry_reap() (called periodically by the consumer
 *      process) frees the handle once `pending_ops==0` AND
 *      `sub_torn_down==1`.
 *
 * @param id  Handle id; borrowed.
 * @return    0 on success (handle retired; actual free deferred to
 *            reap), -1 if not found.
 *
 * Allocation: none.  Locking: the bucket WRITE lock, dropped, then the
 * retire WRITE lock (never nested -- see the lock-ordering note in
 * nats_handle_registry.c).
 *
 * Context: any process; the real caller is the MI unbind handler.
 */
int nats_registry_unbind(const str *id);

/**
 * Weak lookup that also returns retired handles.
 *
 * Checks the live bucket first, then falls back to the retire list --
 * the path a finalizer needs after `retire=1`, when the handle is off
 * its bucket chain but the same object must still be observed (e.g. to
 * set `sub_torn_down`).
 *
 * @param id  Handle id; borrowed.
 * @return    Borrowed pointer (never free it), or NULL if not found in
 *            either place.  NO pending_ops reference is taken: the
 *            pointer is only guaranteed until nats_registry_reap()
 *            frees the handle (which requires sub_torn_down==1 AND
 *            pending_ops==0).
 *
 * Locking: the bucket READ lock, then the retire READ lock (both
 * dropped before returning).
 *
 * Context: safe from any process; intended for the consumer process's
 * retire-finalization paths.
 */
nats_handle_t *nats_registry_lookup_weak(const str *id);

/**
 * Reaper for retired handles.
 *
 * Frees (nats_handle_free: SHM strs + rlock + ring + handle, and the
 * recycled index) any handle whose retire=1, sub_torn_down=1 and
 * pending_ops==0.
 *
 * @return  nothing.
 *
 * Locking: the retire WRITE lock for the splice only; the frees run
 * with no lock held so consumer iterations are not serialized.
 *
 * Context: intended for the consumer process's main loop (cheap enough
 * to run every iteration: O(retired-handles) with a short list).  Safe
 * to call from any process, but only the consumer process ever sets
 * sub_torn_down, so calling it elsewhere is a no-op.
 */
void nats_registry_reap(void);

/**
 * Borrowed lookup.
 *
 * @param id  Handle id; borrowed.
 * @return    Borrowed pointer (never free it; the registry owns the
 *            handle), or NULL if not found.  Handle content is stable
 *            until unbind.
 *
 * Locking: the bucket READ lock, dropped before returning.
 *
 * WARNING: because the lock is dropped, the handle can be retired and
 * reaped between the return and the caller's first dereference /
 * nats_handle_pending_inc().  Prefer nats_registry_lookup_ref() on any
 * path that will dereference the handle.
 *
 * Context: any process.
 */
nats_handle_t *nats_registry_lookup(const str *id);

/**
 * Borrowed lookup that atomically takes a pending_ops reference while
 * the bucket read lock is still held.
 *
 * @param id  Handle id; borrowed.
 * @return    Borrowed, PINNED pointer, or NULL if not found.  The
 *            handle is guaranteed not to be freed by the reaper until
 *            the caller releases the pin with
 *            nats_handle_pending_dec() -- which the caller MUST do
 *            exactly once.
 *
 * This closes the TOCTOU in lookup()+pending_inc(): retire() needs the
 * bucket WRITE lock to unlink a handle, so it cannot run while we hold
 * the read lock; once the reference is taken the reaper (which only
 * frees at pending_ops==0) cannot free the handle even after it is
 * later retired.  The caller should still check h->retire and stop
 * issuing new work on it, but every dereference is safe until the
 * matching pending_dec().
 *
 * Locking: the bucket READ lock, dropped before returning.
 *
 * Context: any process; this is the SIP-worker hot-path lookup (fetch
 * / batch-fetch entry points).
 */
nats_handle_t *nats_registry_lookup_ref(const str *id);

/**
 * Snapshot count of live (non-retired) handles.
 *
 * @return  The counter value; 0 when the registry is not initialized.
 *
 * Non-blocking atomic read; no locking.  Context: any process.
 */
int nats_registry_count(void);

/**
 * Iterate every bound handle while HOLDING the global + per-bucket
 * READ locks across each callback.
 *
 * @param cb    Callback; returns 0 to continue, non-zero to stop early
 *              (that value is returned to the caller).  Handles passed
 *              to cb are borrowed and only valid during the call.
 * @param user  Opaque cookie forwarded to cb.
 * @return      0 on a complete walk (or NULL cb / uninitialized
 *              registry), else cb's early-stop value.
 *
 * cb MUST NOT call registry_bind/unbind (same-lock deadlock) and must
 * not block -- the held read locks plus rwlock writer priority would
 * stall every worker lookup.  Use nats_registry_foreach_unlocked() for
 * slow callbacks.
 *
 * Context: any process; the real callers are the MI list/stats
 * handlers.
 */
int nats_registry_foreach(int (*cb)(nats_handle_t *h, void *user),
                          void *user);

/**
 * Iterate WITHOUT holding registry locks during cb: the live
 * handles are snapshotted + pending_ops-pinned under the locks, the
 * locks drop, then cb runs per pinned handle (pin released after each
 * call; on early-stop the remaining pins are still released).
 *
 * @param cb    Callback; 0 to continue, non-zero to stop early (that
 *              value is returned).  Unlike nats_registry_foreach, cb
 *              MAY bind/unbind/reap and MAY block (network I/O) -- this
 *              exists for the consumer's reconcile pass.  A handle
 *              retired after the snapshot is still visited on valid
 *              memory (cb keeps its own h->retire check); handles
 *              bound after the snapshot are picked up on the caller's
 *              next pass.
 * @param user  Opaque cookie forwarded to cb.
 * @return      0 on a complete walk, else cb's early-stop value.
 *
 * Allocation: a transient pkg_malloc'd snapshot array, freed before
 * returning; falls back to the locked nats_registry_foreach() walk on
 * snapshot-alloc failure.  Locking: global + bucket READ locks for
 * the snapshot phase only.
 *
 * Context: any process; the real caller is the consumer process's
 * per-tick reconcile pass.
 */
int nats_registry_foreach_unlocked(int (*cb)(nats_handle_t *h, void *user),
                                   void *user);

/**
 * Iterate the retire list (handles unbound but not yet reaped).
 *
 * @param cb    Callback, called per retired handle (borrowed pointer);
 *              a non-zero return stops the walk and is returned.
 * @param user  Opaque cookie forwarded to cb.
 * @return      0 on a complete walk, else cb's early-stop value.
 *
 * Locking: walks under the retire READ lock, held across every cb --
 * cb must NOT bind/unbind/reap or modify the list; it may only inspect
 * the handle or set atomic fields on it (e.g. sub_torn_down).  No
 * allocation.
 *
 * Context: any process; used by the consumer process to mark handles
 * that were unbound before they ever got a subscription as
 * sub_torn_down, so the reaper can free them (otherwise their ring
 * leaks for the process lifetime).
 */
int nats_registry_foreach_retired(int (*cb)(nats_handle_t *h, void *user),
                                  void *user);

/**
 * Free a CALLER-OWNED handle (one whose bind failed or was never
 * attempted).  Frees all SHM str buffers, the rlock if initialized,
 * the SHM ring if created, then the handle itself.  NULL-safe.
 *
 * @param h  The handle; ownership is consumed.
 * @return   nothing.
 *
 * Never call this on a registry-owned handle (bind rc == 0) -- those
 * are freed by the retire/reap lifecycle or registry destroy.  The
 * consumer-process subscription is NOT touched here (process-local
 * pointer; its cleanup happens in the consumer process).
 *
 * Locking: none.  Context: any process on the parse-then-fail paths
 * (script / MI / modparam bind), plus the registry's own teardown /
 * reap internals.
 */
void nats_handle_free(nats_handle_t *h);

/**
 * pending_ops helpers.  Use these from any path that holds a borrowed
 * nats_handle_t * across a blocking call (e.g. the consumer process's
 * Fetch() on a subscription owned by handle h).  The retire/reap
 * lifecycle uses pending_ops==0 as one of the gating conditions for
 * the actual free.
 *
 * @param h  The handle; NULL is tolerated (no-op / 0).
 * @return   _inc / _dec: nothing; _get: the current pending_ops value.
 *
 * SEQ_CST atomics on the SHM handle -- no locking needed; safe from
 * any process (SIP workers, consumer process, MI).  Every _inc MUST be
 * balanced by exactly one _dec or the handle can never be reaped.
 *
 * These operate on the handle directly (not by id) because callers
 * already have a pointer from a lookup; re-looking-up by id would
 * reintroduce the race these helpers are meant to close.
 */
static inline void nats_handle_pending_inc(struct nats_handle *h)
{
	if (h)
		__atomic_add_fetch(&h->pending_ops, 1, __ATOMIC_SEQ_CST);
}

static inline void nats_handle_pending_dec(struct nats_handle *h)
{
	if (h)
		__atomic_sub_fetch(&h->pending_ops, 1, __ATOMIC_SEQ_CST);
}

static inline int nats_handle_pending_get(const struct nats_handle *h)
{
	if (!h) return 0;
	return __atomic_load_n(&h->pending_ops, __ATOMIC_SEQ_CST);
}

#endif /* NATS_HANDLE_REGISTRY_H */
