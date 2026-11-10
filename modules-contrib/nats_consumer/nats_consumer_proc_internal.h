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
 * nats_consumer_proc_internal.h — private cross-TU declarations for the
 * consumer-process translation units (the proc-TU split of
 * nats_consumer_proc.c into msg-ref / sub-config / proc-loop TUs).
 * Nothing here is module API: code outside the consumer process must
 * use nats_consumer_proc.h.
 */

#ifndef NATS_CONSUMER_PROC_INTERNAL_H
#define NATS_CONSUMER_PROC_INTERNAL_H

#include <stdint.h>
#include <time.h>

#include <nats/nats.h>

#include "../../str.h"
#include "nats_handle_registry.h"

/**
 * Monotonic clock in microseconds.
 *
 * @return  CLOCK_MONOTONIC as microseconds, or 0 on clock_gettime
 *          failure.
 *
 * Pure inline; no allocation, no locking; safe in any process or
 * thread.
 */
static inline long long now_monotonic_us(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
}

/* ── per-subscription process-local state ─────────────────────── */

typedef struct proc_sub_state {
	str                   id;              /* copy of registry handle id
	                                        * (process-local buffer, NOT
	                                        *  shared) */
	uint16_t              handle_idx;      /* stable index from registry */
	natsSubscription     *sub;             /* active pull subscription */
	struct nats_ring     *ring;            /* borrowed ref to handle ring */
	nats_handle_t        *h_ref;           /* borrowed ref to SHM handle
	                                        * (used for pending_ops
	                                        *  accounting). */
	time_t                last_fetch;

	/* Per-handle pull/push/defer/error counters live in the SHM handle
	 * (nats_handle_t: pulls_requested, msgs_delivered, fetch_skips_full,
	 * backpressure_drops, fetch_errors, ...) so the attendant's MI
	 * handlers can read them.  Bumped here via hstat_add(). */

	/* Monotonic-us timestamp of the last oversize-message WARN, so a flood
	 * of oversized messages logs at most once per interval (the per-handle
	 * `terms` counter still increments on every one). */
	long long             last_oversize_warn_us;

	/* Highest stream sequence delivered so far.  Survives a rebuild (the
	 * proc_sub_state_t is kept when the natsSubscription is recreated), so
	 * a vanished+recreated durable can resume just past it instead of
	 * replaying the whole stream under deliver_policy=all. */
	uint64_t              last_stream_seq;

	/* Stream incarnation the watermark above belongs to
	 * (jsStreamInfo.Created, ns since epoch; 0 = unknown).  Stamped on
	 * every successful subscribe.  The rebuild bias is only valid for
	 * the SAME incarnation: a recreated stream restarts its sequences
	 * at 1, and resuming at a stale watermark would silently skip
	 * every new message until the sequence grows past it (bit us via
	 * test_reconnect.sh: broker restart on memory storage). */
	int64_t               stream_created_ns;

	/* Subscription-refresh bookkeeping. */
	int                   dirty;   /* 1 iff the subscription needs
	                                 * rebuild (epoch bump or broker
	                                 * GC'd ephemeral); cleared when
	                                 * ensure_subscription_for_handle
	                                 * successfully creates a fresh
	                                 * natsSubscription. */

	/* String cleanup slots.  These point at the malloc'd C-strings
	 * and arrays we hand to nats.c in ensure_subscription_for_handle();
	 * nats.c holds borrowed pointers for the life of the subscription,
	 * so we stash them here and the retire/reap teardown path frees
	 * them along with the proc_sub_state_t.  NULL entries mean
	 * "no allocation for that slot". */
	char                 *c_durable;
	char                 *c_filter;
	char                 *c_stream;
	char                 *c_domain;
	char                 *c_api_prefix;
	char                 *c_sample_freq;
	int64_t              *backoff_arr;
	const char          **filters_arr;
	int                   filters_arr_len;

	struct proc_sub_state *next;
} proc_sub_state_t;

/* Linked list of all subscription states (consumer process only). */
extern proc_sub_state_t *g_subs;
/* Dense idx -> state table for O(1) lookup from ack tokens. */
extern proc_sub_state_t *g_subs_by_idx[NATS_REGISTRY_MAX_HANDLES];
/* Process JetStream context (NULL until the proc loop connects). */
extern jsCtx *g_js;

/* ── natsMsg ref table (nats_msg_ref.c) ───────────────────────── */

typedef struct msg_ref_slot {
	natsMsg   *msg;
	uint16_t   generation;
	uint16_t   in_use;       /* 1 iff msg != NULL and ack pending */
	uint32_t   _pad;
	long long  claimed_at_us; /* CLOCK_MONOTONIC us at store; for orphan reap */
} msg_ref_slot_t;

typedef struct msg_ref_row {
	uint32_t         capacity;     /* 0 == row not allocated yet */
	msg_ref_slot_t  *slots;        /* [capacity] */
	uint32_t         next_slot;    /* round-robin hint */
	int              ack_wait_ms;  /* handle ack_wait; drives the orphan TTL */
} msg_ref_row_t;

/* How often the main loop scans for orphans (cheap, but no need every tick). */
#define NATS_MSG_REF_REAP_INTERVAL_US (30LL * 1000000LL)

/* Minimum interval between oversize-message WARN lines per subscription, so
 * a flood of oversized messages cannot flood the log. */
#define NATS_OVERSIZE_WARN_INTERVAL_US (5LL * 1000000LL)

extern msg_ref_row_t g_msg_refs[NATS_REGISTRY_MAX_HANDLES];

/**
 * Per-handle stat bump without the rwlock.
 *
 * @param h      The SHM handle owning the counter; NULL is a no-op
 *               (kept as a liveness cue at call sites).
 * @param field  Pointer to one of the handle's uint64_t counters.
 * @param v      Increment to add.
 * @return       nothing.
 *
 * Relaxed atomic add on the SHM counter -- no locking; the MI readers
 * in the attendant see coherent increments.  Context: consumer process
 * only (the sole producer): the fetch path (nats_consumer_proc.c) and
 * the ack hop (nats_ack_ipc.c).
 */
static inline void hstat_add(nats_handle_t *h, uint64_t *field, uint64_t v)
{
	if (!h || !field) return;
	__atomic_fetch_add(field, v, __ATOMIC_RELAXED);
}

/*
 * Shared contract for the msg-ref table functions below: the ref rows
 * (g_msg_refs) are PROCESS-LOCAL, allocated with libc calloc and freed
 * with libc free by purge_msg_ref_row(); all of them run exclusively
 * on the consumer process's single-threaded main loop (the IPC-drain
 * handlers included), so no locking is used anywhere.
 */

/**
 * Size a handle's ref row (first use only -- an already-allocated row
 * is left untouched, whatever its capacity).
 *
 * @param handle_idx  Handle index; out-of-range returns -1.
 * @param capacity    Slot count to calloc; generations are seeded from
 *                    the persisted per-index seed so stale tokens from
 *                    a prior incarnation cannot match.
 * @return            0 on success or already-allocated, -1 on
 *                    out-of-range index or OOM.
 */
int ensure_row(uint16_t handle_idx, uint32_t capacity);
/**
 * Stash a natsMsg under a fresh ack token.
 *
 * @param handle_idx     Owning handle index.
 * @param ring_capacity  Row size used if the row must be created.
 * @param ack_wait_ms    Handle ack_wait; recorded to scale the orphan
 *                       TTL.
 * @param m              The fetched natsMsg.  On success OWNERSHIP
 *                       TRANSFERS to the ref table (released by a
 *                       later release_msg_ref / purge / orphan reap);
 *                       on failure the caller still owns and must
 *                       destroy it.
 * @param ok             Out: 1 on success, 0 on row-init failure or
 *                       table exhaustion.
 * @return               The packed ack token on success; 0 with
 *                       *ok == 0 otherwise.
 */
uint64_t store_msg_ref(uint16_t handle_idx, uint32_t ring_capacity,
	int ack_wait_ms, natsMsg *m, int *ok);
/**
 * Redeem an ack token.
 *
 * @param token  Packed (handle_idx, slot_idx, generation) token.
 * @return       The stored natsMsg* -- ownership transfers to the
 *               caller, which MUST natsMsg_Destroy it after applying
 *               the requested ack action; NULL if the token is stale
 *               (generation mismatch), the slot is unset, or the
 *               indices are out of range.
 */
natsMsg *release_msg_ref(uint64_t token);
/**
 * Reclaim ref slots older than the orphan TTL (worker died after
 * popping, before acking): destroys the leaked natsMsg, frees the
 * slot and bumps its generation so a late ack is rejected.
 *
 * @return  The number of slots reaped.
 */
int reap_orphan_msg_refs(void);
/**
 * Consume (and clear) a handle's ACK_NEXT refill hint.
 *
 * @param handle_idx  Handle index; out-of-range returns 0.
 * @return            1 iff the hint was set (it is cleared).
 *
 * Proc-local bitmap; set by the ack IPC handlers, read by the main
 * loop right after the pump.
 */
int nats_ack_next_take(uint16_t handle_idx);
/**
 * Destroy every outstanding natsMsg for a handle, free() its ref
 * row's slots buffer and zero the row (persisting a generation seed
 * above every generation this incarnation used).
 *
 * @param handle_idx  Handle index; out-of-range / row-less is a no-op.
 * @return            nothing.
 *
 * MUST be called at every subscription-destroy site: a fetched natsMsg
 * holds an unref'd msg->sub, so acking one after its sub is destroyed
 * is a use-after-free.
 */
void purge_msg_ref_row(uint16_t handle_idx);

/**
 * Walk the registry's retire list and mark retired handles that never
 * got a subscription (no g_subs entry) as torn down -- purging any
 * presized ref row -- so the reaper can free them.
 *
 * @return  nothing.
 *
 * Locking: the retire READ lock, via nats_registry_foreach_retired().
 * Context: consumer process main loop, each tick; exported for unit
 * tests.
 */
void mark_orphan_retired_handles(void);

/* ── subscription config / lifecycle (nats_sub_config.c) ──────── */

/*
 * Shared contract for the subscription-lifecycle functions below:
 * proc_sub_state_t objects and every C-string / array stashed on them
 * are libc-heap (malloc/calloc), owned by the consumer process; all
 * four functions run exclusively on the consumer process's
 * single-threaded main loop, so no locking is used (registry locks
 * are taken only inside the registry API they call).
 */

/**
 * Lookup of the owning subscription state by handle index (identity,
 * not id string -- ids are reused on unbind+rebind).
 *
 * @param index  The handle's registry index.
 * @return       Borrowed proc_sub_state_t* (owned by g_subs; never
 *               free), or NULL when this process has no subscription
 *               state for that index.  Linear walk of g_subs (the
 *               g_subs_by_idx table is the O(1) alternative).
 */
proc_sub_state_t *find_sub_by_index(uint16_t index);
/**
 * Free the C-string / array slots nats.c borrowed for the sub's life
 * (libc free), NULLing each; ss itself stays alive -- the caller
 * decides whether to free the struct (full teardown) or reuse it
 * (rebuild).
 *
 * @param ss  The subscription state; NULL-safe.
 * @return    nothing.
 *
 * Only call after the natsSubscription is destroyed: nats.c holds
 * borrowed pointers into these buffers for the subscription lifetime.
 */
void free_proc_sub_strings(proc_sub_state_t *ss);
/**
 * Create or rebuild the JetStream pull subscription for a handle.
 * Idempotent for a clean, already-subscribed handle; a no-op (0) for a
 * ring-less handle or a disconnected pool.
 *
 * @param h  The bound handle (borrowed; pending_ops-pinned by the
 *           caller's foreach_unlocked walk).
 * @return   0 on success / no-op; -1 on allocation or JetStream
 *           subscribe failure (on rebuild failure the state stays on
 *           g_subs with dirty=1 for a retry; on first-bind failure it
 *           is freed).
 *
 * Allocation: creates the proc_sub_state_t on first bind, mallocs the
 * C-strings/arrays nats.c borrows (stashed on ss; freed by the
 * retire / rebuild teardown) and lets libnats own the natsSubscription.
 * BLOCKS on JetStream API round-trips (AddConsumer / PullSubscribe /
 * GetStreamInfo) -- which is why the reconcile walk is lock-free.
 */
int ensure_subscription_for_handle(nats_handle_t *h);
/**
 * Registry-walk callback: reconcile g_subs with the bound handles.
 * Skips retired handles and handles inside their exponential ensure
 * backoff window; otherwise calls ensure_subscription_for_handle()
 * and updates the backoff bookkeeping on the handle.
 *
 * @param h     The visited handle (borrowed, pinned by the walk).
 * @param user  Unused.
 * @return      Always 0 (never stops the walk).
 *
 * Context: consumer process main loop, as the callback of
 * nats_registry_foreach_unlocked() -- it may block (network I/O).
 */
int reconcile_subs_cb(nats_handle_t *h, void *user);

/**
 * 1 iff the rebuild's anti-replay resume bias must be DROPPED because
 * the stream is a different incarnation than the one the delivery
 * watermark came from (recreated / restored: sequences restarted).
 *
 * @param stamped_created_ns  jsStreamInfo.Created stamped on the last
 *                            successful subscribe (0 = unknown).
 * @param current_created_ns  jsStreamInfo.Created of the stream now
 *                            (0 = unknown).
 * @return                    1 when both are known and differ; else 0.
 *                            Either side unknown keeps the historical
 *                            bias behavior -- fail-open to the cheaper
 *                            wrong-direction (a possible replay)
 *                            rather than the silent-skip direction.
 *
 * Pure inline comparison; no allocation, no locking; safe anywhere.
 * Unit-locked in test/test_consumer_config.c; end-to-end in
 * test_reconnect.sh.
 */
static inline int nats_rebuild_bias_stale(int64_t stamped_created_ns,
	int64_t current_created_ns)
{
	return stamped_created_ns != 0 && current_created_ns != 0 &&
		stamped_created_ns != current_created_ns;
}

#ifdef UNIT_TESTS
/* Builds the jsConsumerConfig of handle `h` as the subscribe path does
 * (nats_sub_config.c), hands it to `inspect`, then frees what the build
 * allocated.  Returns the build's result: 0, or -1 when it failed. */
int nc_ut_build_consumer_config(nats_handle_t *h, proc_sub_state_t *ss,
	int is_rebuild, void (*inspect)(const jsConsumerConfig *cc, void *arg),
	void *arg);
/* fetch_budget_ms() and proc_fetch_batch() of nats_consumer_proc.c */
int nc_ut_fetch_budget_ms(int configured, int num_subs);
int nc_ut_proc_fetch_batch(proc_sub_state_t *ss, int budget_ms,
	natsMsgList *list);
/* tear_down_retired_subs() of nats_consumer_proc.c */
void nc_ut_tear_down_retired_subs(void);
/* push_one_msg() of nats_consumer_proc.c: 1 delivered to the ring, 0 not */
int nc_ut_push_one_msg(proc_sub_state_t *ss, natsMsg *m);
/* mark_orphan_retired_handles() of nats_consumer_proc.c */
void nc_ut_mark_orphan_retired_handles(void);

/* Holding the consumer process between loop iterations, so the suite can
 * work on the shared registry, rings and RPC slots alone: the flags are
 * made in mod_init (nc_ut_hold_init()), and nc_ut_hold_consumer(1) returns
 * 0 once the process is holding (-1 if it did not within 3 s);
 * nc_ut_hold_consumer(0) lets it go on. */
extern int *nc_ut_hold;
int nc_ut_hold_consumer(int on);
#endif

#endif /* NATS_CONSUMER_PROC_INTERNAL_H */
