/*
 * slab allocator with elastic arenas - large-object tier
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
#include "hg_dbg.h"
#include "hg_buddy.h"
#include "../dprint.h"

#define HG_LARGE_MIN_FRAG    HG_ROUNDTO
#define HG_LARGE_DEFAULT_CHUNK (1UL << 20)  /* 1 MB - amortizes future churn */
/* on an arena this big a large chunk is at least one whole huge page: with
 * chunk_max (256 KB) sizing a 256 KB request plus headers takes a 512 KB
 * buddy block too short for a second one, half of it dead. Small arenas
 * (pkg, small shm) keep chunk_max sizing. */
#define HG_LARGE_BIG_ARENA     (256UL << 20)

struct hg_large_chunk {
	struct hg_large_chunk *next;
	unsigned long size;
	/* bytes of the buddy block/run, header and slack included (->size is
	 * only the part available to fragments) */
	unsigned long backing;
	/* buddy order it was taken at, or -1 for a run of whole pages; it is
	 * given back the same way */
	int ord;
	struct hg_lfrag *first_frag;
	struct hg_lfrag *last_frag;  /* sentinel: size 0, prev NULL - stops
	                               * forward coalescing at the chunk end */
};

/* a frag's ->size counts the bytes after its hg_lfrag header, as
 * f_malloc's fm_frag->size does */
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
	/* base MUST start NULL: the grow-and-retry loop below tests it before
	 * the first attempt assigns it */
	char *base = NULL, *tag;

	/* round to HG_PAYLOAD_ALIGN, not HG_ROUNDTO: a frag's size places the
	 * next frag, so rounding to 4 (32-bit ARM) would misalign all later
	 * frags and their payloads */
	need = (HG_CELL_HDR + size + (hb->dbg ? HG_DBG_TAIL : 0) +
	        HG_PAYLOAD_ALIGN - 1) & ~(unsigned long)(HG_PAYLOAD_ALIGN - 1);

	hg_lock_enter(hb, HG_LK_LARGE);

	/* first fit on the one unsorted free list - see hg_large.h for why */
	f = NULL;
	for (n = hb->large_free; n; n = n->nxt_free) {
		if (n->size >= need) {
			f = n;
			break;
		}
	}

	if (!f) {
		/* no fit: a new chunk from the arena the slab tier uses, sized
		 * for this request but at least a floor, so churn of smaller
		 * large objects does not carve a chunk each time */
		chunk_size = HG_LFRAG_HDR * 2 + need;
		/* a 1 MB floor would eat a small arena: there it is capped at
		 * chunk_max (as chunk_size_for() in hg_arena.c) */
		{
			unsigned long floor = HG_LARGE_DEFAULT_CHUNK;
			if (hb->size >= HG_LARGE_BIG_ARENA) {
				/* one whole page, header included, so the buddy
				 * hands back one page, not a two-page run */
				floor = hb->hps;
				if (chunk_size + sizeof(struct hg_large_chunk) < floor)
					chunk_size = (floor - sizeof(struct hg_large_chunk))
					             & ~63UL;
			} else {
				if (floor > hb->chunk_max)
					floor = hb->chunk_max;
				if (chunk_size < floor)
					chunk_size = floor;
			}
		}
		chunk_size = (chunk_size + 63) & ~63UL;

		/*
		 * The chunk comes from the buddy, whose blocks top out at one
		 * huge page: up to a page it is one block rounded up to its
		 * order (the slack becomes free space in the chunk); above, a
		 * run of whole pages - rare, but it MUST work: a dialog or
		 * usrloc hash table is one allocation of several MB.
		 */
		{
			unsigned long total = chunk_size + sizeof(struct hg_large_chunk);
			int ord = hg_buddy_order_for(hb, total);
			int attempt;

			/* a miss grows the arena and retries once, from the
			 * fresh pages; a refused grow falls through to the
			 * exhaustion error */
			for (attempt = 0; attempt < 2 && !base; attempt++) {
				if (attempt && hg_buddy_grow_unlocks(hb, total, HG_GROW_EXHAUSTION) != 0)
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
			int first = hg_oom_first(hb, need);

			hg_lock_leave(hb);
			if (first)
				LM_ERR("%s: no more HG_MALLOC arena memory for a %lu byte "
					"large chunk (need %lu bytes for this allocation) - "
					"increase the arena size; further failures are "
					"summarised every 30 s\n", hb->name, chunk_size, need);
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
		 * Charge the whole buddy block when it is taken, as
		 * carve_chunk() does for a slab block: charging only live
		 * fragments would hide the chunk's slack and free space from
		 * real_used and free_to_carve.
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

	/* split off a remainder big enough to be a free frag of its own
	 * (f_malloc's fm_split_frag threshold) */
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

	/* charge the frag's capacity, NOT @size: hg_large_free() knows only
	 * the capacity, and the two must match */
	{
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used += f->size - HG_CELL_HDR;
		ps->fragments++;
	}
	/* the backing is in real_used since the chunk was taken; large_live
	 * is the part handed out, so hg_large_recycled() can take the idle
	 * rest out of the live figure, as hg_slab_recycled() does for slabs */
	hb->large_live += HG_LFRAG_HDR + f->size;

	hg_lock_leave(hb);

	tag = (char *)f + HG_LFRAG_HDR;
	hg_hdr_set(tag, HG_LARGE_MARKER, HG_ST_LIVE);
	if (hb->dbg)
		hg_dbg_tail_set(tag, f->size - HG_CELL_HDR, size);
	hg_san_give(hb, tag, f->size - HG_CELL_HDR, size);
#ifdef DBG_MALLOC
	HG_CELL_AT(tag)->file = file;
	HG_CELL_AT(tag)->func = func;
	HG_CELL_AT(tag)->line = line;
#endif

	return tag + HG_CELL_HDR;
}

void hg_large_free(struct hg_block *hb, struct hg_lfrag *frag)
{
	struct hg_lfrag *neigh;

	hg_lock_enter(hb, HG_LK_LARGE);

	/* re-check the state under the lock: two concurrent frees can both
	 * pass hg_cell_free()'s check, and the second would coalesce the
	 * fragment again. A LIVE frag still on the free list (prev set) is a
	 * damaged tier: refused the same way. */
	if (hg_hdr_state((char *)frag + HG_LFRAG_HDR) != HG_ST_LIVE ||
	    frag->prev) {
		hg_lock_leave(hb);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		LM_CRIT("%s: large fragment %p is already free - refusing to "
			"free it again\n", hb->name, (void *)frag);
		return;
	}
	hg_hdr_set((char *)frag + HG_LFRAG_HDR, HG_LARGE_MARKER, HG_ST_FREE);

	{
		struct hg_pstat *ps = hg_pstat_mine(hb);
		ps->used -= frag->size - HG_CELL_HDR;
		ps->fragments--;
	}
	hb->large_live -= HG_LFRAG_HDR + frag->size;

	/* forward coalesce: prev is NULL for a live frag and for the sentinel,
	 * so this stops at the chunk end */
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
	 * Chunk empty? Only a chunk's first frag has a NULL pf and only its
	 * sentinel has size 0, so a first frag followed by the sentinel spans
	 * the whole chunk, whose header sits right in front of it. Returned
	 * at once, with no keep-one hysteresis: thrash on a tier that keeps
	 * emptying and refilling shows as large_chunks_carved climbing far
	 * faster than large_chunks_returned.
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
			 * its free-list links over them */
			if (ord >= 0)
				hg_buddy_free(hb, base, (unsigned int)ord);
			else
				hg_buddy_free_run(hb, base);

			hg_lock_leave(hb);
			return;
		}
	}

	lfrag_insert_free(hb, frag);

	hg_lock_leave(hb);
}

unsigned long hg_large_frag_size(const struct hg_lfrag *frag)
{
	return HG_LFRAG_HDR + frag->size;
}

/* hg_frag_size()'s opaque-pointer wrapper - see hg_malloc.h for why */
unsigned long hg_large_frag_size_at(const void *frag)
{
	return hg_large_frag_size((const struct hg_lfrag *)frag);
}

/* the tag region follows the frag header directly, so the header's size
 * must keep every payload HG_PAYLOAD_ALIGN-aligned */
_Static_assert(HG_LFRAG_HDR_SIZE % HG_PAYLOAD_ALIGN == 0,
	"struct hg_lfrag must be a multiple of HG_PAYLOAD_ALIGN");

void hg_large_destroy(struct hg_block *hb)
{
	/* the chunks are buddy blocks and the whole reservation goes back in
	 * hg_malloc_destroy()'s munmap: only the bookkeeping to drop */
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

	hg_lock_enter(hb, HG_LK_STATS);

	for (ch = hb->large_chunks; ch; ch = ch->next)
		for (f = ch->first_frag; f != ch->last_frag; f = HG_LFRAG_NEXT(f))
			if (!f->prev)   /* live, exact - see hg_large.h */
				cb((char *)f + HG_LFRAG_HDR + HG_CELL_HDR, ctx);

	hg_lock_leave(hb);
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
