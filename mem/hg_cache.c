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
#include "../pt.h"
#include "mem.h"
#include "shm_mem.h"
#include "hg_arena_int.h"

/* class @c's unused bump cells (never handed out, FRESH) to the pool;
 * hb->lock held */
unsigned int hg_cache_bump_return(struct hg_block *hb, struct hg_palloc *pl,
                                  int c)
{
	unsigned int n = 0;

	hb->gc_deferred = 1;
	while (pl->cls[c].left) {
		char *cell = pl->cls[c].bump;

		pl->cls[c].bump += cell_sizes[c];
		pl->cls[c].left--;
		if (hg_gpool_push(hb, c, cell) < 0) {
			pl->cls[c].left = 0;
			break;
		}
		n++;
	}
	hb->gc_deferred = 0;
	if (hb->ndrained[c] > hb->gc_keep[c])
		hb->gc_inline_blocks += hg_gc_class(hb, c, hb->gc_keep[c], UINT_MAX);
	return n;
}

/* every cell this thread caches in @hb, but class @skip (-1: none), to the
 * pool in HG_FLUSH_BATCH holds; hb->lock NOT held */
unsigned int hg_cache_flush_all(struct hg_block *hb, struct hg_palloc *pl,
                                int skip)
{
	unsigned int n = 0;
	int c;

	if (!pl)
		return 0;
	for (c = 0; c < HG_NCLASSES; c++) {
		if (c == skip)
			continue;
		if (pl->cls[c].free_head)
			n += hg_cache_flush_class(hb, pl, c, 0);
		if (pl->cls[c].left) {
			hg_lock_enter(hb, HG_LK_FLUSH);
			n += hg_cache_bump_return(hb, pl, c);
			hg_lock_leave(hb);
		}
	}
	return n;
}

/* relaxed atomics: a missed generation only delays a flush to the next sweep */
unsigned long hg_sweep_gen;

/* the arena cannot grow out of the pressure: only then does a crossing WARN */
static inline int hg_floor_stuck(struct hg_block *hb)
{
	return hb->committed_bytes >= hg_grow_limit(hb) || hb->grow_blocked;
}

void hg_reserve_floor_check(struct hg_block *hb)
{
	if (!hb->buddy_ready || !hb->reserve_floor)
		return;

	if (hb->buddy_free_leaves < hb->reserve_floor) {
		if (!hb->below_floor) {
			hb->below_floor = 1;
			hb->floor_crossings++;
		}
		/* growth relieves an arena that can still grow: no flush; one
		 * flush per episode otherwise */
		if (hb->floor_warned || !hg_floor_stuck(hb))
			return;
		__atomic_fetch_add(&hb->sweep_gen, 1, __ATOMIC_RELAXED);
		__atomic_fetch_add(&hg_sweep_gen, 1, __ATOMIC_RELAXED);
		hb->floor_warned = 1;
		LM_WARN("%s: free space fell below the reserve floor (%lu of %lu "
			"leaves free, floor %lu) and the arena cannot grow - every "
			"thread flushes its cache at its next refill; raise -m/-M if "
			"this repeats\n", hb->name, hb->buddy_free_leaves,
			hb->npages * hg_leaves_per_page(hb), hb->reserve_floor);
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

/* read without the lock: a stale answer costs one sweep interval. A thread
 * slot counts for its owner process only; a HG pkg arena makes every process
 * dirty, as its policy ticks at the sweep */
int hg_proc_cache_dirty(int proc)
{
	unsigned int slot = ((unsigned int)(proc + 1)) % HG_STAT_SLOTS, s;
	int i;

	if (proc < 0 || (mem_allocator_shm != MM_HG_MALLOC &&
	                 mem_allocator_shm != MM_HG_MALLOC_DBG))
		return 1;
#ifdef PKG_MALLOC
	if (mem_allocator_pkg == MM_HG_MALLOC ||
	    mem_allocator_pkg == MM_HG_MALLOC_DBG)
		return 1;
#endif
	for (i = 0; i < HG_ARENA_REG_MAX; i++) {
		struct hg_block *hb = hg_arena_reg[i].hb;

		if (!hb || !hb->shared)
			continue;
		if (__atomic_load_n(&hb->pstat[slot].dirty, __ATOMIC_RELAXED))
			return 1;
		for (s = (unsigned int)counted_max_processes + 1;
		     s < HG_STAT_SLOTS; s++)
			if (hb->pstat[s].owner == proc + 1 &&
			    __atomic_load_n(&hb->pstat[s].dirty, __ATOMIC_RELAXED))
				return 1;
	}
	return 0;
}

/* processes without IPC: the dispatcher raises a flag in shm, polled from
 * the owner's allocation and free slow paths */
static unsigned char *hg_sweep_req;
static unsigned int hg_sweep_req_n;

int hg_sweep_req_init(unsigned int nproc)
{
	if (mem_allocator_shm != MM_HG_MALLOC &&
	    mem_allocator_shm != MM_HG_MALLOC_DBG
#ifdef PKG_MALLOC
	    && mem_allocator_pkg != MM_HG_MALLOC &&
	    mem_allocator_pkg != MM_HG_MALLOC_DBG
#endif
	   )
		return 0;
	hg_sweep_req = shm_malloc(nproc ? nproc : 1);
	if (!hg_sweep_req) {
		LM_ERR("no shm for the HG_MALLOC sweep requests\n");
		return -1;
	}
	memset(hg_sweep_req, 0, nproc ? nproc : 1);
	hg_sweep_req_n = nproc;
	return 0;
}

void hg_sweep_request(int proc)
{
	if (hg_sweep_req && proc >= 0 && (unsigned int)proc < hg_sweep_req_n)
		__atomic_store_n(&hg_sweep_req[proc], 1, __ATOMIC_RELAXED);
}

/* no lock held: 1 when this process swept now */
int hg_sweep_poll(void)
{
	if (!hg_sweep_req || process_no < 0 ||
	    (unsigned int)process_no >= hg_sweep_req_n ||
	    !__atomic_load_n(&hg_sweep_req[process_no], __ATOMIC_RELAXED))
		return 0;
	__atomic_store_n(&hg_sweep_req[process_no], 0, __ATOMIC_RELAXED);
	__atomic_fetch_add(&hg_sweep_gen, 1, __ATOMIC_RELAXED);
	hg_cache_flush_self();
	return 1;
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
