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
 * cachedb_nats_stats.h — counters for the cachedb path.
 *
 * Mirrors the SHM-atomic pattern from event_nats/nats_stats.h:
 *   - struct allocated in mod_init (pre-fork) so all workers inherit it
 *   - C11 _Atomic counters with relaxed ordering
 *   - exposed via the nats_cdb_stats MI command
 *
 * Counters tracked:
 *   cas_retry        — total CAS retries across all cdbf.update / add /
 *                      sub calls. Bumped once per failed kvStore_Update.
 *   cas_exhausted    — total cdbf calls that ran out of nats_cas_retries
 *                      and dropped the write.
 *   create_doc       — total first-insert documents created by
 *                      nats_cache_update (the rev==0 create landing
 *; formerly the standalone seed write).
 *   index_miss_kv    — query/update found a key in the in-memory index
 *                      but the KV store said NOT_FOUND. Flags index
 *                      staleness, typically from a sibling-instance delete.
 *   fastfail_rejected— KV ops rejected up front because the pool was
 *                      disconnected, or the post-reconnect handle refresh
 *                      failed. The op never reached the broker. Previously
 *                      visible only at LM_DBG; this surfaces broker outages.
 *   op_failed        — KV ops that reached the broker and returned a hard
 *                      error (NOT a NOT_FOUND miss). Distinguishes "broker
 *                      said no" from "broker unreachable" (fastfail_rejected).
 *   watcher_restarts — times the search-index watcher tore down and rebuilt
 *                      its KV handle + index after a reconnect/disconnect.
 *                      A climbing value flags a flapping broker connection.
 *   watcher_handle_leaks — kvWatcher handles NOT destroyed at teardown.
 *                      Expected 0: the disconnected-teardown double-free
 *                      suspicion that used to leak one handle per broker
 *                      flap was refuted live (watcher_destroy_spike.c,
 *                      ASan-clean Stop+Destroy on a disconnected conn) and
 *                      the destroy is now unconditional. The counter stays
 *                      exported so existing dashboards/alerts keep working
 *                      and any regression shows up as a non-zero value.
 */

#ifndef _CACHEDB_NATS_STATS_H_
#define _CACHEDB_NATS_STATS_H_

#include <stddef.h>
#include <stdatomic.h>

#include "../../mi/mi.h"
#include "../../globals.h"  /* process_no */

/* Per-process upper bound for the SHM cdb-stats table.  See the
 * mirror constant in event_nats/nats_stats.h for the rationale; the
 * two NATS modules use the same scheme to keep counter bumps off
 * each others' cachelines. */
#define NATS_CDB_STATS_MAX_PROCS 512

typedef struct _nats_cdb_stats {
	_Atomic unsigned long cas_retry;
	_Atomic unsigned long cas_exhausted;
	_Atomic unsigned long create_doc;
	_Atomic unsigned long index_miss_kv;
	_Atomic unsigned long fastfail_rejected;
	_Atomic unsigned long op_failed;
	_Atomic unsigned long watcher_restarts;
	_Atomic unsigned long watcher_handle_leaks;
	/* Contact saves refused because a field
	 * carried an embedded NUL that could not round-trip. */
	_Atomic unsigned long nul_fields_rejected;
	/* Reads that hit a non-empty, non-object
	 * stored value (poison) — surfaced instead of masked as an empty AoR. */
	_Atomic unsigned long poison_values_rejected;
	/* Writes refused because the merged row value
	 * would exceed nats_max_value_size (NATS payload cap) — cleanly, before
	 * the CAS, rather than a silent truncation / broker-side error. */
	_Atomic unsigned long value_oversize_rejected;
	/* Usrloc rows physically reclaimed by the reaper —
	 * a fully-expired row CAS-deleted, or a partial row CAS-rewritten to its
	 * survivors.  The authoritative expiry mechanism; counts actual reclaims,
	 * not scan passes. */
	_Atomic unsigned long rows_reaped;
	/*: expired contacts pruned out of surviving rows by the
	 * reaper's survivor-writes (rows_reaped counts rows; this counts the
	 * individual bindings removed). */
	_Atomic unsigned long contacts_pruned;
	/* last-reap-pass GAUGES (stores, not increments): the
	 * reaper already Gets every key each pass, so recording bucket totals
	 * here gives monitoring a registration time series every
	 * nats_reap_interval seconds at zero extra broker load.  Written only
	 * by the timer process' slot, so the cross-slot SUM used by the MI
	 * emission still yields the plain value.  "active" mirrors the read
	 * filter (expires==0 or expires+grace>now). */
	_Atomic unsigned long reap_last_run;        /* epoch of last pass       */
	_Atomic unsigned long reap_last_ms;         /* pass duration            */
	_Atomic unsigned long reap_last_keys;       /* prefixed keys enumerated */
	_Atomic unsigned long reap_last_aors;       /* usrloc rows seen         */
	_Atomic unsigned long reap_last_contacts;   /* stored contacts          */
	_Atomic unsigned long reap_last_active;     /* would-be-served contacts */
	_Atomic unsigned long reap_last_permanent;  /* permanent contacts       */
	_Atomic unsigned long reap_last_due;        /* rows past their slack    */
	/* passes whose enumeration failed or stopped early: they keep the
	 * reap_last_* gauges of the last complete pass (counter) */
	_Atomic unsigned long reap_enum_failures;
} __attribute__((aligned(64))) nats_cdb_stats_t;

/* Pointer to the SHM array of NATS_CDB_STATS_MAX_PROCS slots. */
extern nats_cdb_stats_t *nats_cdb_stats;

/**
 * This process's slot in the SHM stats table (indexed by process_no).
 *
 * @return pointer into the SHM array (shared memory owned by the
 *         module — allocated in nats_cdb_stats_init(), freed only by
 *         nats_cdb_stats_destroy(); callers never free it), or NULL
 *         when stats are not yet initialized or process_no is out of
 *         range.
 *
 * Locking: none — slot fields are C11 atomics and each process writes
 * only its own cacheline-aligned slot.  Context: any OpenSIPS process
 * whose process_no is valid (i.e. after nats_cdb_stats_init()).
 */
static inline nats_cdb_stats_t *nats_cdb_stats_slot(void)
{
	if (!nats_cdb_stats) return NULL;
	if (process_no < 0 || process_no >= NATS_CDB_STATS_MAX_PROCS)
		return NULL;
	return &nats_cdb_stats[process_no];
}

/**
 * Sum one counter field across every per-process slot (relaxed atomic
 * loads; the result is a point-in-time approximation under concurrent
 * writers, exact for single-writer gauges).
 *
 * @param field_offset  offsetof(nats_cdb_stats_t, <field>) — use the
 *                      NATS_CDB_STATS_SUM() macro below.
 * @return the sum, or 0 when stats are not initialized.
 *
 * Nothing allocated.  Locking: none.  Context: any process; in
 * production the nats_cdb_stats MI handler (MI process).
 */
unsigned long nats_cdb_stats_sum(size_t field_offset);
#define NATS_CDB_STATS_SUM(field) \
	nats_cdb_stats_sum(offsetof(nats_cdb_stats_t, field))

/**
 * Allocate and zero-initialize the per-process stats table in shared
 * memory (shm_malloc, NATS_CDB_STATS_MAX_PROCS cacheline-aligned
 * slots).
 *
 * @return 0 on success, -1 on SHM allocation failure (logged).
 *
 * Ownership: the SHM block is owned by the module and freed ONLY by
 * nats_cdb_stats_destroy().  Locking: none.  Context: mod_init
 * (pre-fork) ONLY — every child must inherit the pointer.
 */
int nats_cdb_stats_init(void);

/**
 * Free the SHM stats block and NULL the global pointer (idempotent).
 *
 * Locking: none — must run when no other process can still bump
 * counters.  Context: mod_destroy (attendant process at shutdown).
 */
void nats_cdb_stats_destroy(void);

/**
 * MI handler: "nats_cdb_stats" — returns a JSON object with every
 * counter/gauge (cross-slot sums).
 *
 * @param params     unused.
 * @param async_hdl  unused (synchronous handler).
 * @return the MI response object — owned and freed by the MI framework
 *         after sending; NULL on allocation failure.
 *
 * Reads SHM counters with relaxed atomics; no broker I/O.  Locking:
 * none.  Context: the MI process handling the command.
 */
mi_response_t *mi_nats_cdb_stats(const mi_params_t *params,
	struct mi_handler *async_hdl);

/* Convenience bump — no-op if stats are not yet initialized.  Each
 * process writes to its own cacheline-sized slot indexed by
 * process_no, eliminating inter-process cacheline ping-pong on
 * publish-rate-bound counters. */
#define NATS_CDB_STATS_INC(field) do { \
	nats_cdb_stats_t *_s = nats_cdb_stats_slot(); \
	if (_s) atomic_fetch_add_explicit(&_s->field, 1, \
		memory_order_relaxed); \
} while (0)

/* add N at once (reaper contact-prune tallies). */
#define NATS_CDB_STATS_ADD(field, n) do { \
	nats_cdb_stats_t *_s = nats_cdb_stats_slot(); \
	if (_s) atomic_fetch_add_explicit(&_s->field, (unsigned long)(n), \
		memory_order_relaxed); \
} while (0)

/* gauge STORE (last-reap-pass observations; one writer --
 * the timer process -- so a plain relaxed store is exact). */
#define NATS_CDB_STATS_SET(field, v) do { \
	nats_cdb_stats_t *_s = nats_cdb_stats_slot(); \
	if (_s) atomic_store_explicit(&_s->field, (unsigned long)(v), \
		memory_order_relaxed); \
} while (0)

/*
 * Bounded jittered exponential backoff for CAS retry loops.
 *
 * Sleeps for a random interval in [0, max_us(attempt)] where
 *   max_us(attempt) = min(BASE * 2^(attempt-1), CAP)
 *   BASE = 50 us, CAP = 5000 us
 *
 * attempt=0 returns immediately. The cap bounds total sleep across
 * the default 10-retry budget at ~50 ms, well under usrloc's
 * REGISTER processing budget.
 */
#define NATS_CAS_BACKOFF_BASE_US   50UL
#define NATS_CAS_BACKOFF_CAP_US    5000UL

/**
 * Upper bound of the backoff window for a retry attempt (see the
 * formula above; the shift count is clamped so huge attempts cannot
 * overflow).
 *
 * @param attempt  1-based retry attempt; <= 0 returns 0.
 * @return the window bound in microseconds (0..NATS_CAS_BACKOFF_CAP_US).
 *
 * Pure: no allocation, no locking; any process context.
 */
unsigned long nats_cas_backoff_max_us(int attempt);

/**
 * Sleep a full-jitter random interval in [0, max_us(attempt)] so
 * concurrent CAS losers do not all retry at the same instant.
 *
 * @param attempt  1-based retry attempt; <= 0 returns immediately.
 *
 * BLOCKS the calling process (usleep, <= 5 ms per call).  Uses libc
 * rand() (non-cryptographic, per-process state).  Nothing allocated;
 * no locking.  Context: SIP worker CAS retry loops
 * (cachedb_nats_dbase.c counters, cachedb_nats_json.c row updates);
 * safe in any process, but never call it from cnats callback threads.
 */
void nats_cas_backoff_sleep(int attempt);

#endif /* _CACHEDB_NATS_STATS_H_ */
