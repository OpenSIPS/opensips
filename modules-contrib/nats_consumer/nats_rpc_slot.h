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
 * nats_rpc_slot.h -- per-call SHM slot table for the
 * consumer-process-routed async nats_request transport.
 *
 * Why SHM
 *   An earlier per-worker subscription transport segfaulted
 *   because libnats's async-callback subscription thread is
 *   incompatible with the SIP UDP worker context.  This design
 *   moves the subscription to the consumer process (the only
 *   context that already runs libnats safely) and hands off
 *   in-flight state between worker and consumer via SHM.
 *
 * Wake mechanism (IPC wake + worker-private guard timerfd)
 *   OpenSIPS's reactor cannot register fork-inherited eventfds
 *   (see commit 8eae39a5b1).  Instead, each async call creates a
 *   fresh worker-private timerfd registered with the reactor, and
 *   the resume function reads the slot's atomic state whenever it
 *   fires.  When the consumer transitions the slot to DELIVERED
 *   (or abandons it) it IPC-signals the claiming worker
 *   (slot->owner_proc) via nats_rpc_wake_send(); the worker-side
 *   handler pokes the call's timerfd to fire immediately, so the
 *   reply resumes at wire latency.  The timer's own coarse tick
 *   (async_rpc_poll_ms, default 100 ms) only bounds how late a
 *   lost wake or a timeout is noticed.
 *
 * State machine
 *
 *     FREE  -- slot is idle, may be claimed by a worker
 *     CLAIMED -- worker has CAS'd the slot, is filling out_*
 *     INFLIGHT -- worker has IPC'd to consumer, awaiting reply
 *     DELIVERING -- consumer has pinned the claim (CAS from
 *                  INFLIGHT) and is writing reply_*; while pinned
 *                  the worker treats the slot as not-ready and
 *                  never abandons/frees it
 *     DELIVERED -- consumer finished writing reply_* and published
 *                  the reply (store from DELIVERING)
 *     ABANDONED -- worker resume timed out; consumer must drop
 *                  any late reply landing on this slot_idx
 *
 *   FREE ->CLAIMED is a CAS by the worker; the consumer's
 *   INFLIGHT -> DELIVERING -> DELIVERED sequence is a claim-pin
 *   (only the consumer transitions out of DELIVERING).  Every other
 *   transition is done with the slot owned exclusively by either
 *   the worker or the consumer.  No mutex is needed because each
 *   role only reads the other's fields after observing the state
 *   transition that publishes them (acquire/release pairing).
 */

#ifndef NATS_RPC_SLOT_H
#define NATS_RPC_SLOT_H

#include <stdint.h>
#include "../nats/nats_bind.h"
#include "../nats/nats_epoch.h"   /* epoch_at_start tag */
#include <stddef.h>
#include <stdatomic.h>

#include "nats_ring.h"   /* NATS_RING_*_MAX caps */

/*
 * Hard ceiling on simultaneous in-flight async nats_request calls
 * across ALL workers in this OpenSIPS instance.  Each slot is pure
 * SHM (no per-slot fd; the wake mechanism is a per-call
 * worker-private timerfd poll).  Default 64.  Raise via the
 * modparam if you need higher async-RPC concurrency.
 */
#ifndef NATS_RPC_SLOT_COUNT
#define NATS_RPC_SLOT_COUNT 64
#endif

/* Runtime slot-pool size, defaulting to NATS_RPC_SLOT_COUNT and tunable
 * via the nats_consumer "async_rpc_slots" modparam (read at slot init). */
extern int nats_rpc_slot_count;

/* Slot states.  Encoded as plain ints + atomic accesses so we can
 * CAS without an external mutex. */
enum {
	NATS_RPC_SLOT_FREE      = 0,
	NATS_RPC_SLOT_CLAIMED   = 1,
	NATS_RPC_SLOT_INFLIGHT  = 2,
	NATS_RPC_SLOT_DELIVERED = 3,
	NATS_RPC_SLOT_ABANDONED = 4,
	/* DELIVERING pins the claim for the duration of a reply write: the
	 * consumer CAS's INFLIGHT -> DELIVERING BEFORE writing reply_* or
	 * re-validating the generation, and only then stores DELIVERED.  While a
	 * slot is DELIVERING the worker resume treats it as not-ready and never
	 * abandons+frees it, so the generation cannot change under the consumer.
	 * This makes "confirm this is still our claim" and "publish the reply"
	 * atomic w.r.t. the worker, closing the slot-reuse reply-misdelivery
	 * window that existed when the generation re-check was a separate step
	 * after the INFLIGHT -> DELIVERED CAS. */
	NATS_RPC_SLOT_DELIVERING = 5,
};

/*
 * Per-slot SHM record.  Sized large enough to carry the outbound
 * publish payload AND the reply payload by value -- no pointer
 * chasing on either side, and no SHM allocation on the hot path.
 *
 * Memory ordering:
 *   * worker writes out_* fields, then transitions CLAIMED -> INFLIGHT
 *     with release ordering on `state`.  Consumer observes INFLIGHT
 *     with acquire and reads out_*.
 *   * consumer CAS's INFLIGHT -> DELIVERING (acq_rel) to pin the
 *     claim, re-validates the generation, writes reply_* fields,
 *     then transitions DELIVERING -> DELIVERED with release.
 *     Worker observes DELIVERED with acquire and reads reply_*;
 *     while DELIVERING it treats the slot as not-ready and never
 *     abandons/frees it (only the consumer leaves DELIVERING).
 *   * timed-out worker transitions INFLIGHT -> ABANDONED with release.
 *     A late reply from consumer that observes ABANDONED drops the
 *     payload without writing it; consumer never transitions
 *     ABANDONED -> DELIVERED.
 */
typedef struct nats_rpc_slot {
	_Atomic int state;          /* NATS_RPC_SLOT_* */

	/* Identifier echoed in the reply subject suffix so the
	 * consumer's libnats callback can look up the slot without
	 * a hash table.  Slot index in g_slots[]. */
	uint32_t slot_idx;

	/* Correlation id (UUIDv7 string, NUL-terminated).  Stashed
	 * here so the consumer process can include it in any logs
	 * without having to read it back from the worker. */
	char     corr_id[40];
	uint32_t corr_id_len;

	/* Outbound publish data (worker -> consumer).  Reused for any
	 * NATS subject -- not just the inbox. */
	char     out_subject[NATS_RING_SUBJECT_MAX];
	uint32_t out_subject_len;
	char     out_data[NATS_RING_PAYLOAD_MAX];
	uint32_t out_data_len;
	char     out_headers[NATS_RING_HEADERS_MAX];
	uint16_t out_headers_len;

	/* Reply data (consumer -> worker).  Written by the consumer
	 * while DELIVERING; safe for the worker to read once state is
	 * DELIVERED. */
	char     reply_subject[NATS_RING_SUBJECT_MAX];
	uint32_t reply_subject_len;
	char     reply_data[NATS_RING_PAYLOAD_MAX];
	uint32_t reply_data_len;
	char     reply_headers[NATS_RING_HEADERS_MAX];
	uint16_t reply_headers_len;
	uint8_t  reply_headers_truncated;
	char     reply_to[NATS_RING_SUBJECT_MAX];
	uint32_t reply_to_len;
	uint8_t  reply_has_reply_to;

	/* Orphan-reaper age tracking.  claimed_at_us is stamped by
	 * claim(); deadline_us is 0 until the worker stores its per-call
	 * deadline just before publish.  Both CLOCK_MONOTONIC (system-wide
	 * on Linux, so the consumer process can compare).  Atomic because
	 * the reaper reads them from the consumer process while the
	 * owning worker writes them. */
	_Atomic long long claimed_at_us;
	_Atomic long long deadline_us;

	/* process_no of the claiming worker: the destination for
	 * the consumer's reply-delivered / abandoned IPC wake
	 * (nats_rpc_wake_send).  Reset to -1 by claim(); stamped by the
	 * worker just before publish, like deadline_us.  Atomic because
	 * the consumer process reads it while a worker may be re-claiming
	 * the slot; a wake sent from a stale read is dropped by the
	 * generation check in the receiving worker's registry. */
	_Atomic int owner_proc;

	/* Snapshot of the pool reconnect-epoch at claim time.  The
	 * worker resume compares against the current value to surface
	 * -2 (connection lost) if a reconnect intervened. */
	nats_epoch_t epoch_at_start;   /* modules-contrib/nats/nats_epoch.h */

	/* Per-claim generation, bumped on every FREE -> CLAIMED
	 * transition.  Echoed in the reply-inbox subject (see
	 * nats_rpc_subject.h) and revalidated by on_inbox_reply: a late
	 * reply whose generation no longer matches the slot's current
	 * claim is dropped instead of being delivered to whatever request
	 * has since re-claimed the slot.  Atomic because the consumer's
	 * libnats reply thread reads it while a worker may be claiming the
	 * slot for a new request. */
	_Atomic uint32_t generation;
} nats_rpc_slot_t;

/**
 * Module-init / module-destroy hooks.  Both are called from
 * nats_consumer.c::mod_init / mod_destroy.
 *
 * init():
 * @return  0 on success (idempotent: a second call warns and returns
 *          0), -1 on SHM allocation failure.
 * Allocates the slot array with shm_malloc (sized from the clamped
 * `async_rpc_slots` modparam) so every child inherits the shared
 * mapping; freed only by destroy().  No locking.  Context: mod_init in
 * the main process, PRE-FORK.
 *
 * destroy():
 * @return  nothing; NULL-safe.
 * shm_free's the slot array.  No locking.  Context: mod_destroy.
 */
int  nats_rpc_slot_init(void);
void nats_rpc_slot_destroy(void);

/**
 * Claim a free slot (lock-free CAS scan from a rotating hint).
 *
 * @return  Pointer into the SHM slot pool on success, NULL if all
 *          slots are in use (the caller surfaces -5 to the script).
 *
 * The returned slot is pool-owned SHM -- never freed by the caller;
 * it is RETURNED to the pool via nats_rpc_slot_free() (or by the
 * orphan reaper if the owner dies).  On success the slot is in state
 * CLAIMED with its generation bumped, out_* and reply_* fields zeroed,
 * claimed_at_us stamped and owner_proc reset to -1; the caller fills
 * out_* and transitions to INFLIGHT via nats_rpc_slot_publish().
 *
 * No locking (atomic CAS on `state`).  Context: SIP worker, from
 * w_nats_request_async after sanity-checking inputs.
 */
nats_rpc_slot_t *nats_rpc_slot_claim(void);

/**
 * Transition CLAIMED -> INFLIGHT (release ordering), publishing the
 * out_* fields to the consumer's view.
 *
 * @param s  The claimed slot; NULL returns -1.
 * @return   0 on success; -1 if the slot was not in CLAIMED state
 *           (programmer error, logged at ERR).
 *
 * No allocation, no locking (single atomic CAS).  Context: SIP worker,
 * on its own claim, BEFORE the worker->consumer IPC send.
 */
int nats_rpc_slot_publish(nats_rpc_slot_t *s);

/**
 * CAS INFLIGHT -> ABANDONED.  Only fires while the slot is still
 * INFLIGHT; a DELIVERING (claim pinned by consumer) or DELIVERED slot
 * is left untouched and its state returned.
 *
 * @param s  The slot; NULL returns -1.
 * @return   The resulting state: NATS_RPC_SLOT_ABANDONED if the CAS
 *           won (or the slot was already ABANDONED -- idempotent),
 *           otherwise the observed live state (e.g. DELIVERED).
 *
 * No allocation, no locking (single atomic CAS).  Context: the
 * claiming SIP worker's resume path (timeout / epoch-lost), AND the
 * consumer process's fail-fast paths (connection lost, deaf inbox,
 * publish failure) via slot_abandon_and_wake.
 */
int nats_rpc_slot_abandon(nats_rpc_slot_t *s);

/**
 * Worker resume / cleanup: transition the CALLER'S claim -> FREE,
 * returning the slot to the pool (the SHM itself is never freed here).
 *
 * @param s    The slot; NULL is a no-op.
 * @param gen  The generation captured at claim time: if it no longer
 *             matches, the claim was orphan-reaped and possibly
 *             recycled to a new caller, so the free is a NO-OP (a
 *             blind store would clobber the new claim).
 * @return     nothing.
 *
 * Must be called exactly once per live claim; the reaper covers claims
 * whose owner died.  No locking (generation check + state CAS).
 * Context: the claiming SIP worker only (resume / error unwind).
 */
void nats_rpc_slot_free(nats_rpc_slot_t *s, uint32_t gen);

/**
 * Lookup by slot_idx.
 *
 * @param slot_idx  Index parsed from a reply-subject suffix or IPC
 *                  entry.
 * @return          Borrowed pointer into the SHM pool, or NULL if the
 *                  index is out of range OR the slot is currently FREE
 *                  (defensive against a late reply arriving after
 *                  free).  Never free it; validity is governed by the
 *                  slot's state + generation, which the caller must
 *                  re-check.
 *
 * No locking (one acquire load).  Context: consumer process -- both
 * its libnats reply callback thread (on_inbox_reply) and its main-loop
 * IPC publish path.
 */
nats_rpc_slot_t *nats_rpc_slot_lookup(uint32_t slot_idx);

/**
 * Is an outbound IPC publish entry tagged with @gen still the current
 * claim of slot @s?
 *
 * @param s    The slot (borrowed); NULL returns 0.
 * @param gen  The generation captured when the IPC entry was enqueued.
 * @return     1 only when the slot is INFLIGHT *and* its generation
 *             matches @gen; else 0.
 *
 * Pure inline read (acquire load of state, relaxed load of
 * generation); no allocation, no locking.  Context: consumer process,
 * on the IPC drain path (publish_slot / nats_rpc_ipc_on_publish).
 *
 * The worker->consumer IPC entry carries (slot_idx, generation).  A
 * generation mismatch means the slot was freed and re-claimed since the
 * entry was enqueued -- e.g. the original worker timed out (abandon +
 * free) and a new request reused the slot.  Such a stale entry must be
 * skipped: publishing it would send the *new* claim's request a second
 * time (the new claim is also INFLIGHT, so a state-only check cannot tell
 * the two apart).  Used by publish_cb on the IPC drain path.
 */
static inline int nats_rpc_slot_entry_is_current(const nats_rpc_slot_t *s,
		uint32_t gen)
{
	if (!s)
		return 0;
	if (atomic_load_explicit(&s->state, memory_order_acquire)
			!= NATS_RPC_SLOT_INFLIGHT)
		return 0;
	if (atomic_load_explicit(&s->generation, memory_order_relaxed) != gen)
		return 0;
	return 1;
}

/**
 * Advisory in-flight count snapshot.
 *
 * @return  The current in-flight counter (relaxed atomic load; may
 *          race with claims/frees -- a hint, not a guarantee).
 *
 * No allocation, no locking.  Callable from any process (MI stats,
 * worker log lines).
 */
uint32_t nats_rpc_slot_inflight_count(void);

#ifndef NATS_RPC_SLOT_REAP_SLACK_US
#define NATS_RPC_SLOT_REAP_SLACK_US      (60LL * 1000000LL)   /* 60 s  */
#endif
#ifndef NATS_RPC_SLOT_REAP_CLAIM_TTL_US
#define NATS_RPC_SLOT_REAP_CLAIM_TTL_US  (120LL * 1000000LL)  /* 120 s */
#endif
/**
 * Orphan reaper.  Reclaims any non-FREE, non-DELIVERING slot
 * whose owner is provably gone: past deadline_us + slack when the
 * worker stamped a deadline, or past the claim TTL for a CLAIMED slot
 * that never published (death between claim and publish).  Bumps the
 * generation BEFORE the state CAS so late replies / stale IPC entries
 * are invalidated first; repairs the inflight count.
 *
 * @param now_us  Current CLOCK_MONOTONIC time in microseconds
 *                (system-wide, comparable across processes).
 * @return        The number of slots reaped (0 when uninitialised).
 *
 * No allocation; lock-free (per-slot atomic CAS -- safe against
 * concurrent workers and the cnats reply thread).  Context: consumer
 * process main loop, on its periodic reap interval.
 */
int nats_rpc_slot_reap_orphans(long long now_us);

/**
 * Lifetime total of orphan-reaped slots (operator telemetry).
 *
 * @return  Relaxed atomic counter value.  No allocation, no locking;
 *          callable from any process (MI stats).
 */
uint64_t nats_rpc_slot_orphans_reaped_total(void);

/**
 * The slot-pool size fixed at nats_rpc_slot_init() (the clamped
 * `async_rpc_slots` value).
 *
 * @return  Total slot count; 0 before init / after destroy.
 *
 * Plain read of a value that is constant between init and destroy; no
 * locking.  Callable from any process (workers size their wake
 * registry from it; MI reports it).
 */
uint32_t nats_rpc_slot_total_count(void);

#endif /* NATS_RPC_SLOT_H */
