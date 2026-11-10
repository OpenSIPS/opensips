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
 * nats_fetch.h -- script-callable fetch functions and per-worker
 * current-message state.
 *
 * The per-worker `nats_cur_msg_t` is module-global (static in
 * nats_fetch.c).  OpenSIPS SIP workers are single-threaded processes,
 * so a plain static gives us thread-local semantics without the
 * __thread keyword.  A fetch populates it; subsequent ack/nak/pvar
 * reads consume it.
 *
 * Single-message fetch exposes two entry points:
 *   - w_nats_fetch          (sync, cmd_export)
 *   - w_nats_fetch_async    (async, acmd_export with async_ctx)
 *
 * Batch fetch (w_nats_fetch_batch / _async) is declared below.
 */

#ifndef NATS_FETCH_H
#define NATS_FETCH_H

#include <stdint.h>

#include "../../str.h"
#include "../../async.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"

#include "nats_ring.h"

/*
 * Per-worker "current message" state.  Populated by a successful fetch
 * and consumed by the ack / nak / pvar exports.  SIP workers are
 * single-threaded so the static has process-local semantics.
 */
typedef struct nats_cur_msg {
	int      has_message;          /* 1 iff the rest is valid */
	uint16_t handle_idx;           /* index of the source handle */
	uint64_t ack_token;             /* opaque token for ack/nak */

	/* A payload slot copy taken from the ring.  We keep the whole
	 * slot so pvar getters can reach the reply-to and broker metadata
	 * without a second pop. */
	nats_ring_slot_t slot;
} nats_cur_msg_t;

/*
 * Batch fetch: cap of NATS_BATCH_MAX drained slots kept in a per-worker
 * buffer.  The script iterates by calling nats_batch_select(i)
 * which points g_cur at slot i before ack/nak/pvar reads.
 *
 * The cap is bounded to keep the per-worker SHM footprint predictable;
 * 32 slots ~= 32 * ~17 KB = ~540 KB per worker, matching the per-ring
 * slot size in nats_ring.h.
 */
#define NATS_BATCH_MAX 32

typedef struct nats_cur_batch {
	int             count;     /* number of valid slots */
	int             selected;  /* -1 = none selected yet */
	uint16_t        handle_idx; /* shared across the batch */
	nats_cur_msg_t  msgs[NATS_BATCH_MAX];
} nats_cur_batch_t;

/**
 * Get / clear the current-message state for this worker.
 *
 * @return  _current() returns a pointer to the per-process static
 *          nats_cur_msg_t -- module-owned, never freed, never NULL;
 *          check .has_message before using the rest.  _clear() zeroes
 *          it and returns nothing.
 *
 * No allocation, no locking (per-worker static; SIP workers are
 * single-threaded).  Context: SIP worker only -- the fetch / ack /
 * reply / pvar paths of the SAME worker (each process sees its own
 * copy).
 */
nats_cur_msg_t *nats_fetch_current(void);
void            nats_fetch_clear(void);

/**
 * Get / clear the per-worker batch buffer (read-mostly for the ack
 * path).
 *
 * @return  _current_batch() returns a pointer to the per-process
 *          static nats_cur_batch_t -- module-owned, never freed, never
 *          NULL.  _clear_batch() zeroes it (selected = -1) and returns
 *          nothing.
 *
 * No allocation, no locking (per-worker static).  Context: SIP worker
 * only, same-process semantics as nats_fetch_current().
 */
nats_cur_batch_t *nats_fetch_current_batch(void);
void              nats_fetch_clear_batch(void);

/**
 * Script-callable: sync-fetch.
 *
 * @param msg         Current SIP message; unused.
 * @param id          Handle id (registry key); borrowed.
 * @param timeout_ms  Optional wait budget: NULL or 0 = non-blocking
 *                    poll; > 0 blocks the worker up to that long on
 *                    the ring's cross-process futex.
 * @return  (no path returns 0 -- a 0 return from a script-callable cmd
 *          terminates the calling route via ACT_FL_EXIT)
 *    1   got a message (populated current-msg state).
 *   -1   no message within the budget; not an error.  Script may
 *        retry or fall through.
 *   -2   NATS connection lost.  Inspect nats_last_error() for
 *        the textual reason (process-local; valid until the next
 *        fetch / ack call).
 *   -3   handle id not found / handle retiring / no ring.
 *   -6   internal error (OOM, missing eventfd, etc.).
 *
 * Allocation: none; the popped slot is copied into the per-worker
 * static current-message state.  Locking: bucket read lock inside
 * nats_registry_lookup_ref() only; a pending_ops reference pins the
 * handle for the duration of the call.
 *
 * Context: SIP worker script context (ALL_ROUTES); with timeout_ms > 0
 * it BLOCKS the worker, so prefer the async form from request_route.
 */
int w_nats_fetch(struct sip_msg *msg, str *id, int *timeout_ms);

/**
 * Return the most recent per-worker error string.
 *
 * @return  Borrowed pointer into a process-local static buffer -- do
 *          not free; valid until the next nats_fetch* / nats_ack* /
 *          nats_request call on the same worker.  "" (never NULL) when
 *          no error is pending.
 *
 * No allocation, no locking (per-worker static).  Context: the same
 * SIP worker that ran the failing fetch; exposed so MI and debug-log
 * callers can read it without a pseudo-var.
 */
const char *nats_last_error(void);

/**
 * Script-callable: async fetch (acmd, `async(nats_fetch(...), rt)`).
 * Short-circuits to success if the ring has data already; otherwise
 * registers a worker-private timerfd with the async reactor and yields
 * the worker, polling the ring on each 1 ms tick until a message
 * arrives or the deadline expires.
 *
 * @param msg         Current SIP message; unused.
 * @param ctx         Async context; receives resume_f / resume_param.
 * @param id          Handle id; borrowed.
 * @param timeout_ms  Wait budget; MUST be > 0 for the async form
 *                    (rejected with -4 otherwise).
 * @return  1 on immediate message or successful yield; the resume
 *          later reports 1 / -1 (timeout) / -2 (connection lost) to
 *          the script.  Start-path failures: -2 pool disconnected,
 *          -3 unknown / retiring / ring-less handle, -4 bad timeout,
 *          -6 timerfd or pkg-OOM failure.
 *
 * Allocation: a pkg_malloc'd resume param, freed by the resume
 * callback; the timerfd is closed by the async core
 * (ASYNC_DONE_CLOSE_FD).  Locking: bucket read lock inside lookup_ref;
 * the pending_ops reference is held across the reactor round-trip and
 * released by the resume.
 *
 * Context: SIP worker with a reactor (async-capable routes) only.
 */
int w_nats_fetch_async(struct sip_msg *msg, async_ctx *ctx,
                       str *id, int *timeout_ms);

/**
 * Script-callable: sync batch fetch.
 *
 * @param msg   Current SIP message; unused.
 * @param id    Handle id; borrowed.
 * @param opts  Optional k=v;k=v string (NULL / empty accepted);
 *              recognized keys (unknown keys are silently ignored for
 *              forward-compat):
 *     count=<n>         -- request up to n messages (cap NATS_BATCH_MAX)
 *     expires=<dur>     -- total wait budget (ms unless suffixed)
 *     max_bytes=<n>     -- byte cap (advisory, passed through)
 *     no_wait=<0|1>     -- if 1, return immediately with whatever is ready
 * @return  (no path returns 0)
 *    N>0  N messages retrieved (1..NATS_BATCH_MAX); populates the
 *         per-worker batch buffer.  Iterate via nats_batch_select(i).
 *   -1   no messages available within the budget; not an error.
 *        Script writers using `$var(n) = nats_fetch_batch(...)`
 *        should branch on `$var(n) > 0` for the iteration case
 *        and treat any value <= 0 as the empty path.
 *        (Also returned for a bad opts string on this sync form.)
 *   -2   connection lost; broker is down.
 *   -3   unknown handle / retiring / no ring.
 *
 * Allocation: none; slots are copied into the per-worker static batch
 * buffer.  Locking: bucket read lock inside lookup_ref; pending_ops
 * reference held for the duration.  Context: SIP worker script
 * context; with expires > 0 it BLOCKS the worker on the ring futex.
 */
int w_nats_fetch_batch(struct sip_msg *msg, str *id, str *opts);

/**
 * Script-callable: async batch fetch (acmd form).  Same option grammar
 * and batch semantics as w_nats_fetch_batch; yields the worker on a
 * worker-private timerfd if no messages are ready and `expires` > 0,
 * resuming with the count as soon as anything arrives.
 *
 * @param msg   Current SIP message; unused.
 * @param ctx   Async context; receives resume_f / resume_param.
 * @param id    Handle id; borrowed.
 * @param opts  As for w_nats_fetch_batch, except a bad opts string
 *              returns -4 here (the sync form folds it into -1).
 * @return  Immediate N>0 / -1 / -2 / -3 / -4 as above without
 *          yielding; -6 on timerfd or pkg-OOM failure; 0 after a
 *          successful yield (the resume later reports N>0 / -1 / -2).
 *
 * Allocation: a pkg_malloc'd resume param freed by the resume; the
 * timerfd is closed by the async core.  Locking: as the sync form; the
 * pending_ops reference is held across the reactor round-trip.
 * Context: SIP worker with a reactor (async-capable routes) only.
 */
int w_nats_fetch_batch_async(struct sip_msg *msg, async_ctx *ctx,
                             str *id, str *opts);

/**
 * Script-callable: select slot i of the current batch.  Copies
 * msgs[i] into the current-message state so subsequent
 * ack/nak/$nats_* reads see that slot's metadata, and records the
 * index so a following ack can invalidate the batch slot.
 *
 * @param msg    Current SIP message; unused.
 * @param index  Slot index into the current batch (0-based).
 * @return       1 on success, -1 if i is out of range or no batch is
 *               current.
 *
 * No allocation, no locking (per-worker statics).  Context: SIP
 * worker script context, between a batch fetch and the per-message
 * ack/nak.
 */
int w_nats_batch_select(struct sip_msg *msg, int *index);

/* ── pseudo-var getters ─────────────────────────────────────────
 * Exposed to the pvar table; all read g_cur.
 *
 * Shared contract:
 *
 * @param msg  Current SIP message (passed through to pv_get_*val).
 * @param p    pvar param; unused by these getters.
 * @param res  Out: the pvar value.  String results BORROW the bytes of
 *             the per-worker current-message slot -- valid until the
 *             next fetch / clear on this worker; copy to outlive that.
 * @return     0 with *res set (NULL-flagged when no current message,
 *             or no reply-to for _reply_to); -1 on NULL res.
 *
 * No allocation ( _token renders into a per-process static buffer),
 * no locking.  Context: SIP worker script context only. */
int pv_get_nats_subject  (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_data     (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_reply_to (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_seq      (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_delivered(struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_pending  (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_token    (struct sip_msg *msg, pv_param_t *p, pv_value_t *res);
int pv_get_nats_consumer_seq(struct sip_msg *msg, pv_param_t *p, pv_value_t *res);

#endif /* NATS_FETCH_H */
