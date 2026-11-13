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
#include <unistd.h>

#include "hg_malloc.h"
#include "hg_arena.h"
#include "hg_buddy.h"
#include "hg_large.h"
#include "hg_dbg.h"
#include "../dprint.h"
#include "../globals.h"
#include "hg_arena_int.h"

/* every cell this thread has cached, all classes, to the pool; owning thread
 * only, hb->lock held */
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

/* relaxed atomics: a missed generation only delays a flush to the next sweep */
unsigned long hg_sweep_gen;

/* the arena cannot grow out of the pressure: only then does a crossing WARN */
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
		__atomic_fetch_add(&hg_sweep_gen, 1, __ATOMIC_RELAXED);
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
		/* the same 2x-floor mark ends a grow-blocked episode, so
		 * "blocked" cannot outlive the pressure */
		hg_grow_unblock(hb, "demand fell back below the floor");
	}
}

/* the sweep flush locks per HG_FLUSH_BATCH cells; a block is reclaimed only
 * when all its cells are pooled, so unlocking between batches is safe */
#define HG_FLUSH_BATCH  64
#define HG_FLUSH_KEEP   8    /* residue cap per active class */

/* the residue spares a used class's next allocation a locked refill */
unsigned int hg_flush_residue(struct hg_block *hb,
                                         struct hg_palloc *pl, int c)
{
	unsigned int keep;

	if (!pl->cls[c].touched || hb->below_floor)
		return 0;
	keep = hb->priv_max[c] / 4;
	return keep > HG_FLUSH_KEEP ? HG_FLUSH_KEEP : keep;
}

/* hand class @c's private chain down to @keep cells (0: all) */
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
				/* nfree left over is drift: resynced below */
				drained = 1;
				break;
			}
			if (keep && pl->cls[c].nfree <= keep) {
				drained = 1;
				break;
			}
			if (!cell_block(hb, c, cur)) {
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

/* read without the lock: a stale answer costs one sweep interval */
int hg_proc_cache_dirty(int proc)
{
	struct hg_block *hb = (struct hg_block *)shm_block;

	if (!hb || proc < 0)
		return 1;
	return __atomic_load_n(&hb->pstat[((unsigned int)(proc + 1)) %
		HG_STAT_SLOTS].dirty, __ATOMIC_RELAXED) != 0;
}

static __thread unsigned long hg_sweep_seen;

void hg_cache_flush_if_due(void)
{
	unsigned long g = __atomic_load_n(&hg_sweep_gen, __ATOMIC_RELAXED);

	if (g == hg_sweep_seen)
		return;
	hg_sweep_seen = g;
	hg_cache_flush_self();
}
#endif /* HG_MALLOC, statistics included */
