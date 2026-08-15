/*
 * hugepage-backed slab allocator - large-object tier
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

#include "hg_malloc.h"
#include "hg_large.h"
#include "hg_arena.h"
#include "hg_buddy.h"
#include "../dprint.h"

#define HG_LARGE_MIN_FRAG    HG_ROUNDTO
#define HG_LARGE_DEFAULT_CHUNK (1UL << 20)  /* 1 MB - amortizes future churn */

struct hg_large_chunk {
	struct hg_large_chunk *next;
	unsigned long size;
	/* the buddy block/run this chunk occupies, INCLUDING this header and
	 * any rounding slack - what the grid actually lost, as opposed to
	 * ->size, which is only the part available to fragments */
	unsigned long backing;
	/* how it was taken, so it can be given back the same way: a buddy
	 * block of this order, or -1 for a run of whole pages */
	int ord;
	struct hg_lfrag *first_frag;
	struct hg_lfrag *last_frag;  /* sentinel: size=0, prev always NULL,
	                               * naturally stops forward coalescing at
	                               * the chunk boundary without a separate
	                               * bounds check */
};

/* size AFTER the hg_lfrag header (tag region + payload for a live frag,
 * or free-list linkage for a free one) - same convention as f_malloc's
 * fm_frag->size, so FRAG_NEXT-style arithmetic matches */
#define HG_LFRAG_NEXT(f) \
	((struct hg_lfrag *)(void *)((char *)(f) + HG_LFRAG_HDR + (f)->size))

static inline void lfrag_insert_free(struct hg_block *hb, struct hg_lfrag *frag)
{
	frag->prev = &hb->large_free;
	frag->nxt_free = hb->large_free;
	if (hb->large_free)
		hb->large_free->prev = &frag->nxt_free;
	hb->large_free = frag;
}

static inline void lfrag_remove_free(struct hg_lfrag *frag)
{
	*(frag->prev) = frag->nxt_free;
	if (frag->nxt_free)
		frag->nxt_free->prev = frag->prev;
	frag->prev = NULL;
}

#ifdef DBG_MALLOC
void *hg_large_alloc(struct hg_block *hb, unsigned long size,
                     const char *file, const char *func, unsigned int line)
#else
void *hg_large_alloc(struct hg_block *hb, unsigned long size)
#endif
{
	unsigned long need, chunk_size, rest, backing = 0;
	int chunk_ord = -1;
	struct hg_lfrag *f, *n;
	struct hg_large_chunk *ch;
	/* base MUST start NULL: the carve below is a grow-and-retry loop whose
	 * condition reads it before the first attempt assigns it. gcc 9 does
	 * not flag the uninitialized read this replaced (caught live: the
	 * garbage "pointer" was &evi_time_str+12, and the lock_init loop it
	 * was handed to overwrote log_level) */
	char *base = NULL, *tag;

	/* round to HG_PAYLOAD_ALIGN, not HG_ROUNDTO: a frag's size is what
	 * places the NEXT frag (HG_LFRAG_NEXT), so rounding to 4 on 32-bit
	 * ARM would walk every subsequent frag - and its payload - off the
	 * 8-byte boundary the first one started on */
	need = (HG_CELL_HDR + size + HG_PAYLOAD_ALIGN - 1)
	       & ~(unsigned long)(HG_PAYLOAD_ALIGN - 1);

	lock_get(&hb->lock);

	/* linear first-fit across ONE shared, unsorted free list (large
	 * allocations are inherently rare and already slow-path - see the
	 * hg_large.h file header for why this doesn't need f_malloc's
	 * size-hashed buckets) */
	f = NULL;
	for (n = hb->large_free; n; n = n->nxt_free) {
		if (n->size >= need) {
			f = n;
			break;
		}
	}

	if (!f) {
		/* grow: carve a new chunk from the SAME hoff arena the
		 * small-object tier uses, sized for this request (plus a
		 * default floor so small large-object churn doesn't force a
		 * fresh chunk carve every time) */
		chunk_size = HG_LFRAG_HDR * 2 + need;
		/* the 1M amortisation floor is only affordable on a big arena;
		 * on a small one it would eat the whole thing (same reasoning
		 * as chunk_size_for() in hg_arena.c) */
		{
			unsigned long floor = HG_LARGE_DEFAULT_CHUNK;
			if (floor > hb->chunk_max)
				floor = hb->chunk_max;
			if (chunk_size < floor)
				chunk_size = floor;
		}
		chunk_size = (chunk_size + 63) & ~63UL;

		/*
		 * Large chunks come from the buddy now, not the bump allocator.
		 * Two shapes, because the tree tops out at one huge page:
		 *
		 *   up to a page  - one buddy block, rounded up to its order. The
		 *                   slack is not lost, it becomes free-list space
		 *                   inside the chunk.
		 *   over a page   - a run of contiguous whole pages. Rare, but it
		 *                   MUST work: a dialog or usrloc hash table is one
		 *                   allocation of several MB, and the bump allocator
		 *                   this replaces had no upper bound at all.
		 */
		{
			unsigned long total = chunk_size + sizeof(struct hg_large_chunk);
			int ord = hg_buddy_order_for(hb, total);
			int attempt;

			/* two passes: a miss on the first is a growth trigger
			 * (v3), and the retry after a successful grow is served
			 * from whole fresh pages by construction. A second miss
			 * means the grow was refused - fall through to the
			 * ordinary exhaustion error. */
			for (attempt = 0; attempt < 2 && !base; attempt++) {
				if (attempt && hg_buddy_grow(hb, total) != 0)
					break;
				if (ord >= 0) {
					base = hg_buddy_alloc(hb, (unsigned int)ord);
					if (base) {
						backing    = HG_LEAF_SIZE << ord;
						chunk_ord  = ord;
						chunk_size = backing - sizeof(struct hg_large_chunk);
					}
				} else {
					unsigned long np = (total + hb->hps - 1) >> hb->hps_shift;

					base = hg_buddy_alloc_run(hb, np);
					if (base) {
						backing    = np << hb->hps_shift;
						chunk_size = backing - sizeof(struct hg_large_chunk);
					}
				}
			}
			chunk_size &= ~63UL;
		}
		if (!base) {
			lock_release(&hb->lock);
			LM_ERR("%s: no more HG_MALLOC arena memory for a %lu byte "
				"large chunk (need %lu bytes for this allocation) - "
				"increase the arena size\n", hb->name, chunk_size, need);
			return NULL;
		}

		ch = (struct hg_large_chunk *)(void *)base;
		ch->size = chunk_size;
		ch->first_frag = (struct hg_lfrag *)(void *)(base + sizeof(*ch));
		ch->last_frag = (struct hg_lfrag *)(void *)
			((char *)ch->first_frag + chunk_size) - 1;

		ch->first_frag->size = chunk_size - HG_LFRAG_HDR - HG_LFRAG_HDR;
		ch->first_frag->pf = NULL;
		ch->first_frag->prev = NULL;
		ch->last_frag->size = 0;
		ch->last_frag->pf = ch->first_frag;
		ch->last_frag->prev = NULL;

		ch->next = hb->large_chunks;
		hb->large_chunks = ch;
		ch->backing = backing;
		ch->ord = chunk_ord;
		hb->large_chunks_carved++;

		/*
		 * Charge the WHOLE buddy block the chunk sits in, the moment it
		 * is taken - exactly what carve_chunk() does for a slab block.
		 * Charging only the live fragments (which is what this used to
		 * do) meant the chunk's slack, and every byte of a chunk whose
		 * fragments had all been freed, stayed invisible: real_used
		 * under-reported the arena's footprint and free_to_carve
		 * over-reported the room left, without bound.
		 */
		hb->large_backing += backing;
		hb->real_used += backing;
		if (hb->real_used > hb->max_real_used)
			hb->max_real_used = hb->real_used;

		lfrag_insert_free(hb, ch->first_frag);
		f = ch->first_frag;
		/* f->size is guaranteed >= need: the chunk was sized for it */
	}

	lfrag_remove_free(f);

	/* split off the remainder if it's big enough to be worth keeping as
	 * its own free frag (mirrors f_malloc's fm_split_frag threshold) */
	rest = f->size - need;
	if (rest > HG_LFRAG_HDR + HG_LARGE_MIN_FRAG) {
		f->size = need;
		n = HG_LFRAG_NEXT(f);
		n->size = rest - HG_LFRAG_HDR;
		n->pf = f;
		HG_LFRAG_NEXT(n)->pf = n;
		n->prev = NULL;
		lfrag_insert_free(hb, n);
	}

	/* charge the frag's actual payload capacity, NOT the requested @size:
	 * hg_large_free() can only ever know the capacity, so charging the
	 * request here would leave a permanent per-allocation drift between
	 * the two */
	{
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used += f->size - HG_CELL_HDR;
		ps->fragments++;
	}
	/* the chunk's backing was charged to real_used when the chunk was
	 * taken from the buddy; this tracks how much of it is handed out, so
	 * hg_large_recycled() can hand the idle remainder back to the live
	 * figure the way hg_slab_recycled() does for the slab tier */
	hb->large_live += HG_LFRAG_HDR + f->size;

	lock_release(&hb->lock);

	tag = (char *)f + HG_LFRAG_HDR;
	*(unsigned char *)tag = HG_LARGE_MARKER;
#ifdef DBG_MALLOC
	{
		const char **hfile = (const char **)(tag + HG_ROUNDTO);
		const char **hfunc = (const char **)(tag + HG_ROUNDTO * 2);
		unsigned long *hline = (unsigned long *)(tag + HG_ROUNDTO * 3);
		*hfile = file;
		*hfunc = func;
		*hline = line;
	}
#endif

	return tag + HG_CELL_HDR;
}

void hg_large_free(struct hg_block *hb, struct hg_lfrag *frag)
{
	struct hg_lfrag *neigh;

	lock_get(&hb->lock);

	{
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used -= frag->size - HG_CELL_HDR;
		ps->fragments--;
	}
	hb->large_live -= HG_LFRAG_HDR + frag->size;

	/* forward coalesce - neigh->prev is NULL both for allocated frags AND
	 * for a chunk's sentinel, so this naturally stops at the boundary */
	neigh = HG_LFRAG_NEXT(frag);
	if (neigh->prev) {
		lfrag_remove_free(neigh);
		frag->size += HG_LFRAG_HDR + neigh->size;
		HG_LFRAG_NEXT(neigh)->pf = frag;
	}

	/* backward coalesce */
	neigh = frag->pf;
	if (neigh && neigh->prev) {
		lfrag_remove_free(neigh);
		neigh->size += HG_LFRAG_HDR + frag->size;
		HG_LFRAG_NEXT(frag)->pf = neigh;
		frag = neigh;
	}

	/*
	 * Chunk empty?  O(1), and it needs no search: only a chunk's first
	 * fragment has a NULL pf (hg_large_alloc sets it once at chunk setup
	 * and every split gives the remainder a non-NULL one), and only the
	 * chunk's sentinel has size 0.  So a fragment that is BOTH first and
	 * followed by the sentinel spans the entire chunk - nothing else in it
	 * is allocated.  The chunk header sits immediately in front of that
	 * first fragment, which is how we get back to it.
	 *
	 * Returning it unconditionally, with no keep-one hysteresis: the slab
	 * tier's equivalent is HG_GC_KEEP 0, and holding a chunk back is
	 * exactly the invisible retention this tier was just fixed for. The
	 * risk it trades against is alloc/free thrash on a workload that
	 * repeatedly empties and refills the tier, which is why both a carve
	 * and a return counter are exported - carved climbing far faster than
	 * returned is what that would look like.
	 */
	if (!frag->pf && HG_LFRAG_NEXT(frag)->size == 0) {
		struct hg_large_chunk *ch = (struct hg_large_chunk *)(void *)
			((char *)frag - sizeof(struct hg_large_chunk));

		if (ch->first_frag == frag) {
			struct hg_large_chunk **pp;
			void *base = ch;
			unsigned long backing = ch->backing;
			int ord = ch->ord;

			for (pp = &hb->large_chunks; *pp; pp = &(*pp)->next)
				if (*pp == ch) {
					*pp = ch->next;
					break;
				}

			hb->large_backing -= backing;
			hb->real_used     -= backing;
			hb->large_chunks_returned++;

			/* nothing below may touch ch or frag: the buddy writes
			 * its free-list linkage over the first bytes of what it
			 * is handed */
			if (ord >= 0)
				hg_buddy_free(hb, base, (unsigned int)ord);
			else
				hg_buddy_free_run(hb, base);

			lock_release(&hb->lock);
			return;
		}
	}

	lfrag_insert_free(hb, frag);

	lock_release(&hb->lock);
}

unsigned long hg_large_frag_size(const struct hg_lfrag *frag)
{
	return HG_LFRAG_HDR + frag->size;
}

/* opaque-pointer wrapper for hg_malloc.h's hg_frag_size() - see the
 * HG_LFRAG_HDR_SIZE comment there for why this indirection exists */
unsigned long hg_large_frag_size_at(const void *frag)
{
	return hg_large_frag_size((const struct hg_lfrag *)frag);
}

/* catches any future drift between this and HG_LFRAG_HDR_SIZE (hg_malloc.h,
 * which can't sizeof() the opaque-there struct hg_lfrag directly) */
/* the alignment guarantee this allocator hands its callers: cells and frags
 * both start 8-aligned only if every step between them is a multiple of 8 */
_Static_assert(HG_CELL_HDR % HG_PAYLOAD_ALIGN == 0,
	"HG_CELL_HDR must be a multiple of HG_PAYLOAD_ALIGN or payloads misalign");
_Static_assert(HG_LFRAG_HDR_SIZE % HG_PAYLOAD_ALIGN == 0,
	"sizeof(struct hg_lfrag) must be a multiple of HG_PAYLOAD_ALIGN");

_Static_assert(sizeof(struct hg_lfrag) == HG_LFRAG_HDR_SIZE,
	"HG_LFRAG_HDR_SIZE in hg_malloc.h must match sizeof(struct hg_lfrag)");

void hg_large_destroy(struct hg_block *hb)
{
	/* Chunks come from the buddy grid (hg_buddy_alloc / _alloc_run), not
	 * from the bump allocator as the original comment here claimed. Either
	 * way the whole reservation goes back in hg_malloc_destroy()'s munmap,
	 * so there is still nothing to release one chunk at a time - only the
	 * bookkeeping to drop. */
	hb->large_chunks = NULL;
	hb->large_free = NULL;
	hb->large_backing = 0;
	hb->large_live = 0;
}

void hg_large_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx)
{
	struct hg_large_chunk *ch;
	struct hg_lfrag *f;

	lock_get(&hb->lock);

	for (ch = hb->large_chunks; ch; ch = ch->next)
		for (f = ch->first_frag; f != ch->last_frag; f = HG_LFRAG_NEXT(f))
			if (!f->prev)   /* live, exact - see hg_large.h */
				cb((char *)f + HG_LFRAG_HDR + HG_CELL_HDR, ctx);

	lock_release(&hb->lock);
}

#ifdef SHM_EXTRA_STATS
static void hg_large_stats_core_init_cb(void *payload, void *ctx)
{
	HG_STATS_IDX(payload) = (unsigned long)*(int *)ctx;
}

void hg_large_stats_core_init(struct hg_block *hb, int core_index)
{
	hg_large_walk_live(hb, hg_large_stats_core_init_cb, &core_index);
}
#endif

#endif /* HG_MALLOC */
