/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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

/*
 * nats_stats.h — NATS Statistics and MI Command Handlers
 *
 * Module:  event_nats
 *
 * Defines the shared-memory statistics structure for tracking NATS
 * connection state and publish metrics, plus MI (Management Interface)
 * command handlers for runtime introspection.
 *
 * Key types:
 *   nats_stats_t  — volatile counters in shared memory, updated by
 *                   all OpenSIPS worker processes
 *
 * MI commands:
 *   nats_status    — connection state and server info
 *   nats_stats     — publish/ack counters
 *   nats_reconnect — informational; confirms nats.c auto-reconnect is active
 */

#ifndef _NATS_STATS_H_
#define _NATS_STATS_H_

#include <stdatomic.h>

#include "../../mi/mi.h"
#include "../../statistics.h"
#include "../../globals.h"  /* process_no */

/*
 * NATS statistics counters, allocated in OpenSIPS shared memory.
 *
 * Counters are C11 _Atomic with relaxed ordering.  Plain `volatile`
 * is not atomic on weakly-ordered architectures (e.g. aarch64) and
 * concurrent increments produce torn writes (we measured a ~6x
 * undercount under N=8 threads).  The two hot counters (published,
 * failed) are cache-line aligned so per-worker increments do not
 * thrash a shared 64-byte line shared with cooler counters.

 */
/* Per-process upper bound for the SHM stats table.
 *
 * Allocated once in mod_init (pre-fork), sized once and forever.
 * 512 slots × 128 bytes each (ten counters, padded to two 64-byte
 * cachelines) = 64 KB total — trivial SHM cost in exchange for keeping
 * every worker's counter increments off the other workers' cachelines.
 *
 * If a deployment ever runs more than 512 OpenSIPS processes,
 * bumps from process_no >= NATS_STATS_MAX_PROCS are silently
 * dropped (guarded in the bump path); the MI sum still iterates
 * the full table.  Bump the cap if that ceiling becomes a real
 * constraint. */
#define NATS_STATS_MAX_PROCS 512

/* Per-process counter slot, indexed by process_no.  Most counters have
 * a single writer (the owning OpenSIPS process), but that is NOT true
 * for the JetStream ack counters (js_ack_ok / js_ack_failed / js_retried /
 * js_duplicate, and the drop counters a refused resend bumps): the
 * cnats AckHandler runs on a libnats internal thread that shares the
 * owning process's process_no, so it writes the SAME slot the OpenSIPS
 * main thread writes published/evi_published into — two concurrent
 * writers per slot.  All counters are therefore `_Atomic` and bumped
 * with atomic_fetch_add (NATS_STATS_BUMP); do NOT downgrade them to
 * plain increments on the assumption of a single writer.  MI reads use
 * relaxed atomic loads to avoid torn reads.
 *
 * A cacheline-aligned slot keeps the bump path off any other
 * worker's hot lines. */
typedef struct _nats_stats {
    _Atomic unsigned long published;
    _Atomic unsigned long failed;
    _Atomic unsigned long evi_published;
    _Atomic unsigned long script_published;
    _Atomic unsigned long js_ack_ok;
    _Atomic unsigned long js_ack_failed;
    _Atomic unsigned long js_retried;            /* resends after a failed ack */
    _Atomic unsigned long js_duplicate;          /* acks flagged duplicate */
    _Atomic unsigned long reconnect_buf_dropped; /* refused: reconnect buffer full */
    _Atomic unsigned long js_pending_dropped;    /* refused: MaxPending acks waiting */
} __attribute__((aligned(64))) nats_stats_t;

/* Pointer to the SHM array of NATS_STATS_MAX_PROCS slots.  Workers
 * index into it via nats_stats_slot() / nats_stats_sum(). */
extern nats_stats_t *nats_stats;

/* Helpers — defined in nats_stats.c.  Kept inline at the bump site
 * via macros below.  Inlined so the hot path is a single store, no
 * function call. */
static inline nats_stats_t *nats_stats_slot(void)
{
    if (!nats_stats) return NULL;
    if (process_no < 0 || process_no >= NATS_STATS_MAX_PROCS)
        return NULL;
    return &nats_stats[process_no];
}

#define NATS_STATS_BUMP(field) do { \
    nats_stats_t *_s = nats_stats_slot(); \
    if (_s) atomic_fetch_add_explicit(&_s->field, 1, \
        memory_order_relaxed); \
} while (0)

/* Sum a counter across all slots.  Used by the MI handler. */
unsigned long nats_stats_sum(size_t field_offset);
#define NATS_STATS_SUM(field) nats_stats_sum(offsetof(nats_stats_t, field))

/*
 * Allocate and zero-initialize the stats structure in shared memory.
 *
 * Must be called from mod_init (pre-fork) so that all worker processes
 * inherit the same shared-memory pointer.
 *
 * @return  0 on success, -1 on shared-memory allocation failure.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_init.
 */
int nats_stats_init(void);

/*
 * Free the shared-memory stats structure.
 *
 * Called from mod_destroy during shutdown.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_destroy.
 */
void nats_stats_destroy(void);

/*
 * MI handler: "nats_status"
 *
 * Returns a JSON object with the server info, connection state (yes/no),
 * and JetStream mode (enabled/disabled).
 *
 * @param params     MI parameters (unused).
 * @param async_hdl  Async handler (unused — this command is synchronous).
 * @return           MI response tree, or NULL on error.
 *
 * Thread safety: Safe to call from the MI process.
 */
mi_response_t *mi_nats_status(const mi_params_t *params,
    struct mi_handler *async_hdl);

/*
 * MI handler: "nats_stats"
 *
 * Returns a JSON object with all publish/ack counters from nats_stats_t.
 *
 * @param params     MI parameters (unused).
 * @param async_hdl  Async handler (unused — this command is synchronous).
 * @return           MI response tree, or NULL on error.
 *
 * Thread safety: Safe to call from the MI process.
 */
mi_response_t *mi_nats_stats(const mi_params_t *params,
    struct mi_handler *async_hdl);

/*
 * MI handler: "nats_reconnect"
 *
 * Informational only: returns a status string confirming that nats.c's
 * built-in auto-reconnect is active.  It performs no drain and no
 * reconnect; a true manual reconnect would require signaling the worker
 * process and is not implemented.
 *
 * @param params     MI parameters (unused).
 * @param async_hdl  Async handler (unused — this command is synchronous).
 * @return           MI response tree, or NULL on error.
 *
 * Thread safety: Safe to call from the MI process.
 */
mi_response_t *mi_nats_reconnect(const mi_params_t *params,
    struct mi_handler *async_hdl);

#endif /* _NATS_STATS_H_ */
