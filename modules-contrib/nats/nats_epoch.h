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
 * nats_epoch.h -- the epoch-tagged handle idiom, in ONE place.
 *
 * The pool bumps a per-process reconnect epoch from the libnats
 * reconnect callback.  Any handle DERIVED from the connection (KV
 * store, JetStream context, subscription, in-flight RPC) is dead
 * weight after a reconnect; consumers tag the handle with the epoch
 * at acquire time and re-acquire when the tag goes stale.  This
 * header replaces the save/compare/refresh dance that used to be
 * re-implemented at every site.
 *
 * THE TRAP this header exists to encode (it once caused a permanent
 * per-worker outage): on a REFRESH path, snapshot the epoch BEFORE
 * acquiring the new handle and adopt the snapshot only AFTER the
 * acquire succeeds.  Re-reading the epoch at adopt time can pair an
 * OLD-connection handle with a NEW epoch tag -- the staleness check
 * then never fires again until the next reconnect.  Snapshot-first is
 * conservative in the benign direction: a reconnect that lands mid-
 * refresh leaves the tag stale, so the next call refreshes again.
 *
 *   acquire:   nats_epoch_save(&h->epoch);          (with the handle)
 *   fast path: if (nats_epoch_current(&h->epoch) && h->kv) use it;
 *   refresh:   int snap = nats_epoch_snapshot();
 *              h->kv = nats_pool_get_kv(...);
 *              if (h->kv) nats_epoch_adopt(&h->epoch, snap);
 *   liveness:  nats_epoch_lost(&h->epoch)  ==  reconnected OR
 *              currently disconnected (the "did we lose the broker
 *              since this started" test for in-flight work).
 *
 * Self-contained: only the two pool accessors are declared here, so
 * SHM-struct headers (e.g. nats_rpc_slot.h) can embed nats_epoch_t
 * without pulling the whole pool surface.
 */

#ifndef LIB_NATS_NATS_EPOCH_H
#define LIB_NATS_NATS_EPOCH_H

/**
 * Current per-process reconnect epoch (mirror declaration; defined in
 * nats_pool.c, where the canonical contract lives).  Bumped by the
 * libnats reconnected callback on the cnats I/O thread.
 *
 * @return Monotonic per-process epoch counter (0 until the first
 *         reconnect).  Nothing allocated.
 *
 * Locking: none; atomic_load of a process-local _Atomic.
 * Context: any process or thread (SIP worker, cnats callback thread,
 * MI handler, timer proc).
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_get_reconnect_epoch(void);
#endif

/**
 * Whether this process's pool connection is currently up (mirror
 * declaration; defined in nats_pool.c, where the canonical contract
 * lives).
 *
 * @return 1 connected, 0 disconnected.  Nothing allocated.
 *
 * Locking: none; atomic_load of a process-local _Atomic written by the
 * cnats connection callbacks.
 * Context: any process or thread.
 */
#ifndef NATS_POOL_NO_PROTOTYPES
int nats_pool_is_connected(void);
#endif

typedef struct nats_epoch {
	int seen;
} nats_epoch_t;

/**
 * Tag: the handle being tagged was just acquired from the live pool.
 *
 * @param e Epoch tag to stamp; caller-owned, living wherever the caller
 *          embedded it (pkg struct, SHM struct, static).  Plain int
 *          store; nothing allocated.
 *
 * Locking: none; the store is not atomic.  A tag embedded in SHM that
 * multiple processes touch needs the caller's own serialisation (e.g.
 * the owning slot's lock).
 * Context: any process or thread that may read the pool epoch.
 */
static inline void nats_epoch_save(nats_epoch_t *e)
{
	e->seen = nats_pool_get_reconnect_epoch();
}

/**
 * Fast-path check: no reconnect since the tag was taken.
 *
 * @param e Epoch tag stamped by nats_epoch_save()/nats_epoch_adopt();
 *          caller-owned, read-only here.
 *
 * @return 1 = tag still current (handle usable), 0 = a reconnect
 *         happened since the tag (re-acquire the handle).
 *
 * Locking: none; plain int read vs. an atomic pool read (same caveats
 * as nats_epoch_save() for SHM-resident tags).
 * Context: any process or thread.
 */
static inline int nats_epoch_current(const nats_epoch_t *e)
{
	return e->seen == nats_pool_get_reconnect_epoch();
}

/**
 * Refresh protocol, step 1 (see the file comment): snapshot the epoch
 * BEFORE acquiring the new handle; adopt only after success.
 *
 * @return The epoch value to hand to nats_epoch_adopt() once the
 *         acquire succeeds.  Nothing allocated.
 *
 * Locking: none; atomic pool read.
 * Context: any process or thread.
 */
static inline int nats_epoch_snapshot(void)
{
	return nats_pool_get_reconnect_epoch();
}

/**
 * Refresh protocol, step 2: adopt the pre-acquire snapshot into the tag
 * AFTER the new handle was acquired successfully.  Never re-read the
 * live epoch here -- that is the trap the file comment describes.
 *
 * @param e        Epoch tag to stamp; caller-owned (see
 *                 nats_epoch_save() for the SHM caveat).
 * @param snapshot Value returned by nats_epoch_snapshot() taken before
 *                 the acquire.
 *
 * Locking: none; plain int store.
 * Context: any process or thread.
 */
static inline void nats_epoch_adopt(nats_epoch_t *e, int snapshot)
{
	e->seen = snapshot;
}

/**
 * In-flight liveness: the broker was lost (reconnected since the tag,
 * or not connected right now).
 *
 * @param e Epoch tag taken when the in-flight work started; caller-
 *          owned, read-only here.
 *
 * @return 1 = broker lost since the tag (reconnected OR currently
 *         disconnected; abandon/retry the in-flight work), 0 = still
 *         live.
 *
 * Locking: none; atomic pool reads + plain int read (see
 * nats_epoch_save() for the SHM caveat).
 * Context: any process or thread.
 */
static inline int nats_epoch_lost(const nats_epoch_t *e)
{
	return !nats_pool_is_connected() || !nats_epoch_current(e);
}

#endif /* LIB_NATS_NATS_EPOCH_H */
