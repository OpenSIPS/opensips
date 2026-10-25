/*
 * slab allocator with elastic arenas - cache flushes and the reserve floor
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HG_MALLOC

#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>   /* sysconf, for the IO-pool consumer count */

#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_buddy.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_arena_int.h"

/*
 * Give up every cell this thread has cached, for every class. Only the
 * owning thread can: the caches are __thread. hb->lock must be held.
 * Returns the number of cells handed over.
 */
unsigned int hg_cache_flush_locked(struct hg_block *hb,
                                       struct hg_palloc *pl)
{
	unsigned int c, n = 0;

	if (!pl)
		return 0;

	hb->gc_deferred = 1;
	for (c = 0; c < HG_NCLASSES; c++) {
		void *cur = pl->cls[c].free_head;

		while (cur) {
			void *nxt;

			/* not a cell of this class: an overwritten link, its
			 * "next" a wild read. Stop and leak the rest */
			if (!cell_block(hb, c, cur)) {
				LM_CRIT("%s: class %d private chain broken at %p after %u "
					"cells - dropping the rest\n", hb->name, c, cur, n);
				break;
			}
			nxt = cell_next(cur);
			if (hg_gpool_push(hb, c, cur) < 0) {
				/* refused (likely a double free): the copy in
				 * the pool owns this cell's link now - stop */
				LM_CRIT("%s: class %d private chain stops at refused cell "
					"%p after %u cells - dropping the rest\n", hb->name,
					c, cur, n);
				break;
			}
			cur = nxt;
			n++;
		}
		pl->cls[c].free_head = NULL;
		pl->cls[c].nfree = 0;
	}
	hb->gc_deferred = 0;

	/* nothing walks the cells now, so blocks may go - all of them: under
	 * pressure a kept block is memory the carve could use before a grow */
	for (c = 0; c < HG_NCLASSES; c++)
		if (hb->ndrained[c])
			hb->gc_inline_blocks += hg_gc_class(hb, c, 0, UINT_MAX);

	return n;
}

/*
 * Sweep generation, bumped once per sweep. A thread IPC cannot reach - TCP
 * main's IO pool waits on a condition variable, not the reactor - compares
 * it with its own last-seen value at a job boundary and flushes when they
 * differ. A plain counter: a missed generation only delays a flush to the
 * next sweep, the same fire-and-forget contract as the IPC path.
 */
volatile unsigned long hg_sweep_gen;

/*
 * Reserve floor: below hb->reserve_floor free leaves (1/16 of the grid, set
 * in hg_buddy_init), publish a sweep through hg_sweep_gen, which reaches even
 * the TCP IO pool. below_floor is the hysteresis; recovery needs 2x the floor.
 *
 * Called from hg_buddy_alloc/_free, the one point every consumer of grid
 * space passes (the large tier bypasses carve_chunk()), and recovery shows
 * only on a free. Only a crossing the arena cannot grow out of (at the
 * ceiling, or growth blocked) is a WARN, once; a quiet crossing that later
 * gets stuck below the floor is upgraded to it, with one more sweep.
 *
 * hb->lock is held by every caller.
 */
static inline int hg_floor_stuck(struct hg_block *hb)
{
	unsigned long limit = (hb->pol.active && hb->pol.up_bytes) ?
		hb->pol.up_bytes : hb->hcap;

	return hb->committed_bytes >= limit || hb->grow_blocked;
}

void hg_reserve_floor_check(struct hg_block *hb)
{
	if (!hb->buddy_ready || !hb->reserve_floor)
		return;

	if (hb->buddy_free_leaves < hb->reserve_floor) {
		if (!hb->below_floor) {
			hb->below_floor = 1;
			hb->floor_crossings++;
		} else if (hb->floor_warned || !hg_floor_stuck(hb)) {
			return;
		}
		hg_sweep_gen++;
		if (hg_floor_stuck(hb)) {
			hb->floor_warned = 1;
			LM_WARN("%s: free space fell below the reserve floor "
				"(%lu of %lu leaves free, floor %lu) - sweeping every "
				"thread's cache; raise -m/-M if this repeats\n",
				hb->name, hb->buddy_free_leaves,
				hb->npages * hg_leaves_per_page(hb), hb->reserve_floor);
		} else {
			LM_DBG("%s: free space fell below the reserve floor "
				"(%lu of %lu leaves free, floor %lu) - sweeping every "
				"thread's cache; the arena can still grow\n",
				hb->name, hb->buddy_free_leaves,
				hb->npages * hg_leaves_per_page(hb), hb->reserve_floor);
		}
	} else if (hb->below_floor &&
	           hb->buddy_free_leaves > hb->reserve_floor * 2) {
		hb->below_floor = 0;
		if (hb->floor_warned)
			LM_NOTICE("%s: free space recovered above the reserve floor "
				"(%lu leaves free)\n", hb->name, hb->buddy_free_leaves);
		else
			LM_DBG("%s: free space recovered above the reserve floor "
				"(%lu leaves free)\n", hb->name, hb->buddy_free_leaves);
		hb->floor_warned = 0;
		/* the same 2x-floor mark ends a grow-blocked episode: the
		 * demand that needed the grow has gone. One mark for both,
		 * so "blocked" cannot outlive the pressure */
		hg_grow_unblock(hb, "demand fell back below the floor");
	}
}

/*
 * The sweep flush takes hb->lock per HG_FLUSH_BATCH cells: the chain is TLS,
 * only the pushes and the GC need the lock. A class used since the last sweep
 * keeps a residue (hg_flush_residue()), so its next allocation is not a locked
 * refill; an untouched class, or any below the reserve floor, gives all back.
 * Dropping the lock between batches is safe: a block is reclaimed only when
 * all its cells are in the pool, so none holds a cell still on this chain.
 * gc_deferred covers the walk within a batch.
 */
#define HG_FLUSH_BATCH  64   /* cells per lock hold */
#define HG_FLUSH_KEEP   8    /* residue cap per active class */

unsigned int hg_flush_residue(struct hg_block *hb,
                                         struct hg_palloc *pl, int c)
{
	unsigned int keep;

	if (!pl->cls[c].touched || hb->below_floor)
		return 0;
	keep = hb->priv_max[c] / 4;
	return keep > HG_FLUSH_KEEP ? HG_FLUSH_KEEP : keep;
}

/* hand class @c's private chain down to @keep cells; returns cells pushed */
unsigned int hg_cache_flush_class(struct hg_block *hb,
                                      struct hg_palloc *pl, int c,
                                      unsigned int keep)
{
	unsigned int claimed = pl->cls[c].nfree, n = 0;
	int drained = 0;

	while (!drained) {
		unsigned int b = 0;

		hg_lock_enter(hb, HG_LK_FLUSH);
		hb->gc_deferred = 1;
		while (b < HG_FLUSH_BATCH) {
			void *cur = pl->cls[c].free_head;

			if (!cur) {
				/* the chain's end; nfree left non-zero is the
				 * drift cell_push_private() also catches */
				drained = 1;
				break;
			}
			if (keep && pl->cls[c].nfree <= keep) {
				drained = 1;
				break;
			}
			if (!cell_block(hb, c, cur)) {
				/* an overwritten link - stop, leak the rest */
				LM_CRIT("%s: class %d private chain broken at %p - "
					"dropping the rest of the chain\n", hb->name, c, cur);
				pl->cls[c].free_head = NULL;
				pl->cls[c].nfree = 0;
				drained = 1;
				break;
			}
			pl->cls[c].free_head = cell_next(cur);
			if (pl->cls[c].nfree)
				pl->cls[c].nfree--;
			if (hg_gpool_push(hb, c, cur) < 0) {
				LM_CRIT("%s: class %d private chain stops at refused cell "
					"%p - dropping the rest of the chain\n", hb->name, c, cur);
				pl->cls[c].free_head = NULL;
				pl->cls[c].nfree = 0;
				drained = 1;
				break;
			}
			b++;
		}
		hb->gc_deferred = 0;
		/* only class c's blocks can have drained in this batch */
		if (hb->ndrained[c] > hb->gc_keep[c])
			hb->gc_inline_blocks += hg_gc_class(hb, c, hb->gc_keep[c], UINT_MAX);
		hg_lock_leave(hb);
		n += b;
		/* a batch that ended at the chain end or the residue is done:
		 * decide here, not with one more hold */
		if (!pl->cls[c].free_head ||
		    (keep && pl->cls[c].nfree <= keep))
			drained = 1;
	}
	if (!pl->cls[c].free_head && pl->cls[c].nfree) {
		unsigned int left = pl->cls[c].nfree;

		pl->cls[c].nfree = 0;
		LM_CRIT("%s: class %d chain ran dry after %u cells but nfree "
			"claimed %u (%u still claimed at the end) - counter resynced "
			"to 0, pool accounting drifted\n", hb->name, c, n, claimed,
			left);
		hg_corrupt(hb, HG_C_NFREE_UNDERFLOW);
	}
	return n;
}

/* does process @proc hold anything in its shared-arena caches since its
 * last flush? Read without the lock - a stale answer costs one interval. */
int hg_proc_cache_dirty(int proc)
{
	struct hg_block *hb = (struct hg_block *)shm_block;

	if (!hb || proc < 0)
		return 1;
	return hb->pstat[((unsigned int)(proc + 1)) % HG_STAT_SLOTS].dirty != 0;
}

static __thread unsigned long hg_sweep_seen;

void hg_cache_flush_if_due(void)
{
	unsigned long g = hg_sweep_gen;

	if (g == hg_sweep_seen)
		return;
	hg_sweep_seen = g;
	hg_cache_flush_self();
}
#endif /* HG_MALLOC, statistics included */
