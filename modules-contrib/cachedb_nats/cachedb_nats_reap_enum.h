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
 * cachedb_nats_reap_enum.h -- one value-carrying watch pass over the
 * KV bucket, for the reaper.
 *
 * Why this exists: the reaper tick used to enumerate with
 * kvStore_Keys() (MetaOnly) and then re-fetch EVERY key's value with
 * an individual synchronous kvStore_Get() -- O(bucket) broker round
 * trips per tick.  Measured on the 30k-AoR bench (2026-07-07): the
 * per-key GET storm runs ~7-17 s per pass at ~1.6k req/s alongside
 * live traffic and drives REGISTER p99/max from ~1 ms to 27-88 ms
 * while it lasts.  A single WatchAll pass carries the values with it
 * (entry = key + value + revision), so the whole enumeration is one
 * ordered-consumer drain: no per-key round trips at all.
 */

#ifndef CACHEDB_NATS_KV_ENUM_H
#define CACHEDB_NATS_KV_ENUM_H

#include <stdint.h>
#include <nats/nats.h>

/* Per-entry wait budget the reaper hands to kvWatcher_Next().  Big
 * enough to ride out a flow-control pause, small enough that a dead
 * broker ends the pass promptly (the next tick rescans). */
#define NATS_KV_ENUM_NEXT_TIMEOUT_MS  5000

/* Return codes (all < 0; success returns the visit count >= 0). */
#define NATS_KV_ENUM_EARG    (-1)  /* bad arguments */
#define NATS_KV_ENUM_EWATCH  (-2)  /* WatchAll create failed */
#define NATS_KV_ENUM_ENEXT   (-3)  /* Next failed/timed out mid-pass */
#define NATS_KV_ENUM_EABORT  (-4)  /* callback asked to abort */

/*
 * Per-entry callback.  Runs once for every live key's LATEST revision
 * (deletes/purges are not delivered).  The entry is owned by the
 * enumerator: it is destroyed after the callback returns -- do not
 * destroy it, do not keep pointers into it past the return.
 * Return >= 0 to continue the pass, < 0 to abort it.
 */
typedef int (*nats_kv_enum_cb_f)(kvEntry *entry, void *arg);

/**
 * Drain one full initial watch pass over a bucket's live keys.
 *
 * Shared live-value enumeration: one kvStore_WatchAll pass with
 * IgnoreDeletes and values riding along, replacing the O(bucket)
 * kvStore_Keys() + per-key kvStore_Get() round-trip pattern.  The end
 * of the initial data set is signalled by libnats delivering a NULL
 * entry from kvWatcher_Next(); the enumerator stops there -- live
 * updates are never consumed.  (Named nats_reap_enum_bucket until the
 * MI scan was converted; the file keeps its original name.)
 *
 * @param kv               bucket handle (pool-owned, e.g. from
 *                         nats_pool_get_kv(); borrowed, not released
 *                         here).
 * @param next_timeout_ms  per-entry wait budget handed to
 *                         kvWatcher_Next(); must be > 0.  A broker
 *                         stall longer than this ends the pass with
 *                         NATS_KV_ENUM_ENEXT (the next tick simply
 *                         rescans -- the reaper is idempotent).
 * @param cb               per-entry visitor (see nats_kv_enum_cb_f:
 *                         each entry is enumerator-owned and destroyed
 *                         after the callback returns; < 0 aborts).
 * @param arg              opaque cookie handed to @cb.
 * @return the number of entries visited (>= 0), or one of the
 *         NATS_KV_ENUM_E* codes above (< 0).  On EWATCH/ENEXT/EABORT
 *         whatever @cb already visited stands.
 *
 * Ownership: nothing is handed to the caller; the transient kvWatcher
 * is stopped and destroyed internally on every path.  BLOCKS for the
 * whole drain (O(bucket); up to @next_timeout_ms per entry).  Locking:
 * none -- but the pool-owned @kv handle is process-local and
 * single-threaded, so the caller must be that process's only NATS
 * user.  Context: the dedicated reaper process (reaper pass) and the
 * MI process (nats_reg_summary / nats_reg_list bucket scans); never
 * cnats callback threads.
 */
int nats_kv_enum_live_values(kvStore *kv, int64_t next_timeout_ms,
		nats_kv_enum_cb_f cb, void *arg);

#endif /* CACHEDB_NATS_KV_ENUM_H */
