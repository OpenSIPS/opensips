/*
 * slab allocator with elastic arenas - shared free pool and drained-block GC
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
#include "hg_xfer.h"

/* everything here runs under hb->lock */

static inline unsigned int grade_of(const struct hg_chunk *ch)
{
	unsigned int g;

	if (ch->in_gpool == 0)
		return HG_GRADE_NONE;
	if (ch->in_gpool >= ch->cells)
		return HG_GRADE_DRAINED;
	g = (ch->in_gpool * HG_GRADES) / ch->cells;
	if (g >= HG_GRADES)
		g = HG_GRADES - 1;
	return g;
}

static inline void list_unlink(struct hg_block *hb, int c, struct hg_chunk *ch)
{
	struct hg_chunk **head;

	if (ch->grade == HG_GRADE_NONE)
		return;
	head = (ch->grade == HG_GRADE_DRAINED) ? &hb->drained[c]
	                                       : &hb->bucket[c][ch->grade];
	if (ch->fprev)
		ch->fprev->fnext = ch->fnext;
	else
		*head = ch->fnext;
	if (ch->fnext)
		ch->fnext->fprev = ch->fprev;
	if (ch->grade == HG_GRADE_DRAINED) {
		if (hb->drained_tail[c] == ch)
			hb->drained_tail[c] = ch->fprev;
		hb->ndrained[c]--;
		ch->flags &= ~HG_CHUNK_DRAINED;
	}
	ch->fnext = ch->fprev = NULL;
	ch->grade = HG_GRADE_NONE;
}

static inline void list_link(struct hg_block *hb, int c, struct hg_chunk *ch,
                             unsigned int g)
{
	struct hg_chunk **head;

	if (g == HG_GRADE_NONE) {
		ch->grade = HG_GRADE_NONE;
		return;
	}
	head = (g == HG_GRADE_DRAINED) ? &hb->drained[c] : &hb->bucket[c][g];
	ch->fprev = NULL;
	ch->fnext = *head;
	if (ch->fnext)
		ch->fnext->fprev = ch;
	*head = ch;
	ch->grade = g;
	if (g == HG_GRADE_DRAINED) {
		if (!ch->fnext)
			hb->drained_tail[c] = ch;          /* was empty */
		hb->ndrained[c]++;
		ch->flags |= HG_CHUNK_DRAINED;
	}
}

static inline void block_regrade(struct hg_block *hb, int c,
                                 struct hg_chunk *ch)
{
	unsigned int g = grade_of(ch);

	if (g == ch->grade)
		return;
	list_unlink(hb, c, ch);
	list_link(hb, c, ch, g);
}

/* -1 if @cell_start is not a cell boundary of @ch */
static inline long cell_index(const struct hg_chunk *ch, const void *cell_start)
{
	unsigned long off = (unsigned long)((const char *)cell_start -
	                                    ((const char *)ch + sizeof(struct hg_chunk)));

	if ((const char *)cell_start < (const char *)ch + sizeof(struct hg_chunk) ||
	    off % ch->cell_size || off / ch->cell_size >= ch->cells)
		return -1;
	return (long)(off / ch->cell_size);
}

static inline void map_set(struct hg_chunk *ch, long i)
{
	ch->gfree[i / HG_CHUNK_MAP_BITS] |= (uint64_t)1 << (i % HG_CHUNK_MAP_BITS);
}

static inline void map_clear(struct hg_chunk *ch, long i)
{
	ch->gfree[i / HG_CHUNK_MAP_BITS] &= ~((uint64_t)1 << (i % HG_CHUNK_MAP_BITS));
}

/* a link the pool follows must be a map-free cell of the same block, else it
 * was overwritten; NULL is a valid end only when the count agrees */
static inline int pool_link_ok(struct hg_block *hb, struct hg_chunk *ch,
                               void *next, unsigned int remaining)
{
	long i;

	if (!next)
		return remaining == 0;
	i = cell_index(ch, next);
	if (i < 0 || !map_test(ch, i)) {
		LM_CRIT("%s: block %p (class %u) free chain points at %p, which is "
			"%s - the link was overwritten after the free; dropping the "
			"rest of the chain (%u cells leak)\n", hb->name, (void *)ch,
			ch->cls, next, i < 0 ? "not one of its cells" :
			"not free by the map", remaining);
		hg_corrupt(hb, HG_C_NFREE_UNDERFLOW);
		return 0;
	}
	return 1;
}

/* drained blocks of class @c back to the buddy, down to @keep and at most
 * @limit per call */
static unsigned int gc_class_run(struct hg_block *hb, int c, unsigned int keep,
                                 unsigned int limit);

unsigned int hg_gc_class(struct hg_block *hb, int c, unsigned int keep,
                             unsigned int limit)
{
	hg_ns_t t0 = hg_now_ns();
	unsigned int n;

	n = gc_class_run(hb, c, keep, limit);
	hg_lkstat_add(&hb->lk_gc, hg_now_ns() - t0);
	return n;
}

static unsigned int gc_class_run(struct hg_block *hb, int c, unsigned int keep,
                                 unsigned int limit)
{
	struct hg_chunk *ch;
	unsigned int freed = 0;

	while (hb->ndrained[c] > keep && freed < limit) {
		unsigned int ord;
		unsigned long sz;

		ch = hb->drained_tail[c];
#ifdef HG_PARANOIA
		{
			struct hg_chunk *w = hb->drained[c];

			while (w && w->fnext)
				w = w->fnext;
			if (w != ch) {
				LM_CRIT("%s: class %d drained tail %p disagrees with "
					"the walked tail %p\n", hb->name, c, (void *)ch,
					(void *)w);
				hg_corrupt(hb, HG_C_INTERNAL);
				ch = w;
			}
		}
#endif
		if (!ch) {
			LM_CRIT("%s: class %d claims %u drained blocks but the list "
				"is empty - resetting the count\n", hb->name, c,
				hb->ndrained[c]);
			hg_corrupt(hb, HG_C_INTERNAL);
			hb->ndrained[c] = 0;
			break;
		}

		list_unlink(hb, c, ch);
		hb->gpool_n[c] -= ch->in_gpool;
		ch->in_gpool = 0;
		ch->free_head = NULL;

		if (ch->prev)
			ch->prev->next = ch->next;
		else
			hb->chunks = ch->next;
		if (ch->next)
			ch->next->prev = ch->prev;
		hb->nchunks--;
		hb->slab_capacity -= (unsigned long)ch->cells * ch->cell_size;

		ord = ch->order;
		sz = HG_LEAF_SIZE << ord;
		hb->real_used -= sz;

		/* every read of ch must precede this: the buddy at once reuses
		 * the block's first bytes for its own links */
		hg_san_release(hb, ch, sz);
		hg_buddy_free(hb, ch, ord);
		freed++;
	}

	if (freed) {
		hb->gc_blocks_returned += freed;
		hb->gc_passes++;
		LM_DBG("%s gc class %d: returned %u blocks, %u drained kept\n",
			hb->name, c, freed, hb->ndrained[c]);
	}
	return freed;
}

int hg_gpool_push(struct hg_block *hb, int c, void *cell_start)
{
	struct hg_chunk *ch = cell_block(hb, c, cell_start);
	long i;

	if (!ch)
		return -1;
	i = cell_index(ch, cell_start);
	if (i < 0) {
		LM_CRIT("%s: %p is inside block %p (class %u) but not on a cell "
			"boundary - refusing to pool it\n", hb->name, cell_start,
			(void *)ch, ch->cls);
		hg_corrupt(hb, HG_C_FOREIGN_PTR);
		return -1;
	}
	if (map_test(ch, i)) {
		/* the block-level test below fires only after the damage */
		LM_CRIT("%s: cell %p (block %p, class %u, index %ld) is already in "
			"the global pool - double free, refusing the second copy\n",
			hb->name, cell_start, (void *)ch, ch->cls, i);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		return -1;
	}
	if (ch->in_gpool >= ch->cells) {
		LM_CRIT("%s: block %p already has all %u cells free, refusing to "
			"add another - this is a double free\n",
			hb->name, (void *)ch, ch->cells);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		return -1;
	}
	map_set(ch, i);
	cell_set_next(cell_start, ch->free_head);
	ch->free_head = cell_start;
	ch->in_gpool++;
	hb->gpool_n[c]++;
	block_regrade(hb, c, ch);

	if (!hb->gc_deferred &&
	    hb->ndrained[c] > hb->gc_keep[c] + HG_GC_EMERGENCY)
		hb->gc_inline_blocks += hg_gc_class(hb, c, hb->gc_keep[c], HG_GC_EMERGENCY);
	return 0;
}

void *hg_gpool_pop(struct hg_block *hb, int c)
{
	struct hg_chunk *ch = NULL;
	void *cell_start;
	unsigned int g;
	long i;

	for (g = 0; g < HG_GRADES; g++)
		if (hb->bucket[c][g]) {
			ch = hb->bucket[c][g];
			break;
		}
	if (!ch)
		ch = hb->drained[c];
	if (!ch)
		return NULL;

	cell_start = ch->free_head;
	if (!cell_start) {
		LM_CRIT("%s: block %p claims %u free cells but its list is empty - "
			"dropping it from the pool\n",
			hb->name, (void *)ch, ch->in_gpool);
		hg_corrupt(hb, HG_C_NFREE_UNDERFLOW);
		hb->gpool_n[c] -= ch->in_gpool;
		ch->in_gpool = 0;
		memset(ch->gfree, 0, sizeof ch->gfree);
		block_regrade(hb, c, ch);
		return NULL;
	}
	/* the head is vetted as well as its link: a first push was never
	 * checked as a link */
	i = cell_index(ch, cell_start);
	if (i < 0 || !map_test(ch, i) ||
	    !pool_link_ok(hb, ch, cell_next(cell_start), ch->in_gpool - 1)) {
		if (i >= 0 && map_test(ch, i)) {
			/* good head, bad link: serve the head and leak the rest
			 * rather than hand a cell out twice */
			map_clear(ch, i);
			hb->gpool_n[c] -= ch->in_gpool;
			ch->in_gpool = 0;
			ch->free_head = NULL;
			memset(ch->gfree, 0, sizeof ch->gfree);
			block_regrade(hb, c, ch);
			return cell_start;
		}
		LM_CRIT("%s: block %p (class %u) free head %p is not a free cell "
			"of the block - dropping the block's chain (%u cells leak)\n",
			hb->name, (void *)ch, ch->cls, cell_start, ch->in_gpool);
		hg_corrupt(hb, HG_C_NFREE_UNDERFLOW);
		hb->gpool_n[c] -= ch->in_gpool;
		ch->in_gpool = 0;
		ch->free_head = NULL;
		memset(ch->gfree, 0, sizeof ch->gfree);
		block_regrade(hb, c, ch);
		return NULL;
	}
	map_clear(ch, i);
	ch->free_head = cell_next(cell_start);
	ch->in_gpool--;
	hb->gpool_n[c]--;
	block_regrade(hb, c, ch);
	return cell_start;
}

void hg_gc_cycle(struct hg_block *hb)
{
	unsigned long budget = hb->size >> HG_GC_KEEP_BUDGET_SHIFT;
	int c;

	hg_xfer_cycle(hb);

	for (c = 0; c < HG_NCLASSES; c++) {
		unsigned int demand = hb->carves_cycle[c], keep = hb->gc_keep[c] / 2;
		unsigned long bsz = chunk_size_for(hb, c);
		unsigned long cap = bsz ? budget / bsz : 0;

		hb->carves_cycle[c] = 0;
		if (demand > keep)
			keep = demand;
		if (cap > HG_GC_KEEP_MAX)
			cap = HG_GC_KEEP_MAX;
		hb->gc_keep[c] = keep > cap ? (unsigned int)cap : keep;
	}
}

/* round-robin, so one class cannot starve the rest of the budget */
unsigned int hg_gc_tick(struct hg_block *hb, unsigned int budget)
{
	unsigned int done = 0, n;
	int i, c;

	for (i = 0; i < HG_NCLASSES && done < budget; i++) {
		c = (hb->gc_next_class + i) % HG_NCLASSES;
		if (hb->ndrained[c] <= hb->gc_keep[c])
			continue;
		n = hg_gc_class(hb, c, hb->gc_keep[c], budget - done);
		done += n;
	}
	hb->gc_next_class = (hb->gc_next_class + 1) % HG_NCLASSES;
	hb->gc_tick_blocks += done;
	return done;
}
#endif /* HG_MALLOC, statistics included */
