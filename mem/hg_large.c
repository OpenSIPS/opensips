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

#include <stddef.h>

#include "hg_malloc.h"
#include "hg_large.h"
#include "hg_arena.h"
#include "hg_dbg.h"
#include "hg_buddy.h"
#include "../dprint.h"

#define HG_LARGE_MIN_FRAG    HG_ROUNDTO
#define HG_LARGE_DEFAULT_CHUNK (1UL << 20)
/* on an arena this big a large chunk is a whole huge page or more: a 256 KB
 * request plus headers would take a 512 KB block, half of it dead */
#define HG_LARGE_BIG_ARENA     (256UL << 20)
/* ... unless the page is huge (arm64 64 KB base pages: 512 MB) */
#define HG_LARGE_PAGE_FLOOR_MAX (4UL << 20)
/* a grow can publish less than a multi-page run needs: retry a few times */
#define HG_LARGE_GROW_TRIES    4

struct hg_large_chunk {
	/* doubly linked: a chunk returns in O(1) under the lock */
	struct hg_large_chunk *next;
	struct hg_large_chunk *prev;
	unsigned long size;
	/* bytes of the buddy block/run, header and slack included (->size is
	 * only the part available to fragments) */
	unsigned long backing;
	int ord;   /* buddy order, or -1 for a run of whole pages */
	struct hg_lfrag *first_frag;
	struct hg_lfrag *last_frag;  /* sentinel: size 0, prev NULL - stops
	                               * forward coalescing at the chunk end */
} __attribute__ ((aligned (HG_PAYLOAD_ALIGN)));

/* a large-chunk link: a block or run start on the page grid */
static inline int lchunk_ok(struct hg_block *hb, struct hg_large_chunk *x)
{
	return hg_in_pages(hb, x) && !((unsigned long)((char *)x - hb->hbase) &
	       (HG_LEAF_SIZE - 1));
}

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

static inline int lfrag_in_arena(const struct hg_block *hb, const void *p)
{
	unsigned long off = (unsigned long)((const char *)p - hb->hbase);

	return off >= sizeof(struct hg_block) && off < hb->span_end &&
	       !(off & (HG_PAYLOAD_ALIGN - 1)) && hg_backed(hb, p);
}

/* the boundary tag sits outside the checksummed cell header, so a short
 * overflow of the frag before it can rewrite it: check before following it */
static int lfrag_sane(const struct hg_block *hb, const struct hg_lfrag *f)
{
	const struct hg_lfrag *nx;

	if (!lfrag_in_arena(hb, f) || (f->size & (HG_PAYLOAD_ALIGN - 1)) ||
	    f->size >= hb->span_end)
		return 0;
	nx = HG_LFRAG_NEXT(f);
	if (!lfrag_in_arena(hb, nx) || nx->pf != f)
		return 0;
	if (f->pf && (!lfrag_in_arena(hb, f->pf) || HG_LFRAG_NEXT(f->pf) != f))
		return 0;
	return 1;
}

/* a free neighbour: also on the free list where it says it is */
static int lfrag_free_sane(const struct hg_block *hb, const struct hg_lfrag *f)
{
	/* prev is the list head, or the nxt_free field inside the previous free
	 * frag (offset 4 on 32-bit): the frag is what must be in the arena */
	return lfrag_sane(hb, f) &&
	       (f->prev == &hb->large_free ||
	        lfrag_in_arena(hb, (char *)f->prev -
	                       offsetof(struct hg_lfrag, nxt_free))) &&
	       *(f->prev) == f;
}

static char *large_block_try(struct hg_block *hb, unsigned long total,
		unsigned long *backing, int *ord)
{
	int o = hg_buddy_order_for(hb, total);
	char *base;

	/* up to a page, one buddy block of its order; above, a run of pages */
	if (o >= 0) {
		base = hg_buddy_alloc(hb, (unsigned int)o);
		if (base) {
			*backing = HG_LEAF_SIZE << o;
			*ord = o;
		}
	} else {
		unsigned long np = (total + hb->hps - 1) >> hb->hps_shift;

		base = hg_buddy_alloc_run(hb, np);
		if (base) {
			*backing = np << hb->hps_shift;
			*ord = -1;
		}
	}
	return base;
}

/* the floor-sized block, else one sized for the request */
static char *large_block_try2(struct hg_block *hb, unsigned long total,
		unsigned long min_total, unsigned long *backing, int *ord)
{
	char *base = large_block_try(hb, total, backing, ord);

	if (!base && min_total < total)
		base = large_block_try(hb, min_total, backing, ord);
	return base;
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
	/* the retry loop below tests base before its first assignment */
	char *base = NULL, *tag;
	/* the guarded size is 32 bits: a larger request goes unguarded */
	unsigned int guard = hb->guard && size < 0xffffffffUL;

	/* round to HG_PAYLOAD_ALIGN, not HG_ROUNDTO: a frag's size places the
	 * next frag, so rounding to 4 (32-bit ARM) would misalign the rest */
	need = (HG_CELL_HDR + size + (hb->dbg ? HG_DBG_TAIL : guard ? HG_GUARD_ROOM : 0) +
	        HG_PAYLOAD_ALIGN - 1) & ~(unsigned long)(HG_PAYLOAD_ALIGN - 1);

	hg_lock_enter(hb, HG_LK_LARGE);

	f = NULL;
	{
		struct hg_lfrag **pp = &hb->large_free;

		for (n = *pp; n; pp = &n->nxt_free, n = *pp) {
			if (!lfrag_sane(hb, n) || n->prev != pp) {
				/* cut the list here: what follows is unreachable,
				 * leaked rather than followed */
				*pp = NULL;
				LM_CRIT("%s: large free list damaged at %p (a neighbour's "
					"overflow?) - dropping the rest of the list\n",
					hb->name, (void *)n);
				hg_corrupt(hb, HG_C_OVERFLOW);
				break;
			}
			if (n->size >= need) {
				f = n;
				break;
			}
		}
	}

	if (!f) {
		unsigned long min_chunk, total, min_total;
		int attempt;

		/* a new chunk, at least a floor, so smaller large objects do
		 * not carve one each time; the floor only ever raises the size */
		min_chunk = (HG_LFRAG_HDR * 2 + need + 63) & ~63UL;
		chunk_size = min_chunk;
		if (hb->size >= HG_LARGE_BIG_ARENA &&
		    hb->hps <= HG_LARGE_PAGE_FLOOR_MAX) {
			/* one whole page, header included, so the buddy hands
			 * back one page, not a two-page run */
			if (min_chunk + sizeof(struct hg_large_chunk) < hb->hps)
				chunk_size = (hb->hps - sizeof(struct hg_large_chunk))
				             & ~63UL;
		} else {
			/* a 1 MB floor would eat a small arena: there it is
			 * capped at chunk_max */
			unsigned long floor = HG_LARGE_DEFAULT_CHUNK;

			if (floor > hb->chunk_max)
				floor = hb->chunk_max;
			floor &= ~63UL;
			if (chunk_size < floor)
				chunk_size = floor;
		}
		total = chunk_size + sizeof(struct hg_large_chunk);
		min_total = min_chunk + sizeof(struct hg_large_chunk);

		/* a miss reclaims parked and cached cells once, then grows the
		 * arena and retries; a refused grow falls through to the error */
		base = large_block_try2(hb, total, min_total, &backing, &chunk_ord);
		if (!base && hg_arena_reclaim_locked(hb, min_total))
			base = large_block_try2(hb, total, min_total, &backing,
				&chunk_ord);
		for (attempt = 1; attempt < HG_LARGE_GROW_TRIES && !base; attempt++) {
			if (hg_buddy_grow_unlocks(hb, total, HG_GROW_EXHAUSTION) != 0)
				break;
			base = large_block_try2(hb, total, min_total, &backing,
				&chunk_ord);
		}
		if (!base) {
			int first = hg_oom_first(hb, need);

			hg_lock_leave(hb);
			if (first)
				LM_ERR("%s: no more HG_MALLOC arena memory for a %lu byte "
					"large chunk (need %lu bytes for this allocation) - "
					"increase the arena size; further failures are "
					"summarised every 30 s\n", hb->name, min_chunk, need);
			return NULL;
		}
		chunk_size = (backing - sizeof(struct hg_large_chunk)) & ~63UL;

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
		ch->prev = NULL;
		if (ch->next)
			ch->next->prev = ch;
		hb->large_chunks = ch;
		ch->backing = backing;
		ch->ord = chunk_ord;
		hb->large_chunks_carved++;

		/* charge the whole block, or real_used would hide its slack */
		hb->large_backing += backing;
		hb->real_used += backing;
		if (hb->real_used > hb->max_real_used)
			hb->max_real_used = hb->real_used;

		lfrag_insert_free(hb, ch->first_frag);
		f = ch->first_frag;
	}

	if (f->size < need) {
		hg_lock_leave(hb);
		LM_CRIT("%s: large fragment %p holds %lu bytes, %lu needed - "
			"refusing to split it\n", hb->name, (void *)f, f->size, need);
		hg_corrupt(hb, HG_C_INTERNAL);
		return NULL;
	}
	lfrag_remove_free(f);

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
	hg_pstat_add(hg_pstat_mine(hb), (long)(f->size - HG_CELL_HDR), 1, 0);
	hb->large_live += HG_LFRAG_HDR + f->size;

	/* stamped under the lock: a live-frag walk takes any frag off the free
	 * list as live and reads its header */
	tag = (char *)f + HG_LFRAG_HDR;
	if (guard) {
		unsigned short hsum = hg_hdr_base(tag, HG_LARGE_MARKER);

		hg_guard_set(tag, hsum, f->size - HG_CELL_HDR, size);
		hg_hdr_set_base(tag, HG_LARGE_MARKER, HG_ST_LIVE_G, hsum);
	} else {
		hg_hdr_set(tag, HG_LARGE_MARKER, HG_ST_LIVE);
	}
	if (hb->dbg)
		hg_dbg_tail_set(tag, f->size - HG_CELL_HDR, size);
#ifdef DBG_MALLOC
	HG_CELL_AT(tag)->file = file;
	HG_CELL_AT(tag)->func = func;
	HG_CELL_AT(tag)->line = line;
#endif

	hg_lock_leave(hb);

	hg_san_give(hb, tag, f->size - HG_CELL_HDR, size);

	return tag + HG_CELL_HDR;
}

void hg_large_free(struct hg_block *hb, struct hg_lfrag *frag)
{
	struct hg_lfrag *neigh;
	char *cs = (char *)frag + HG_LFRAG_HDR;
	union hg_hdr_w w;
	unsigned short base;
	unsigned long asked;
	int st;

	hg_lock_enter(hb, HG_LK_LARGE);

	/* a racing free may have returned the chunk and a drain released
	 * its page since the unlocked checks */
	if (!hg_backed(hb, frag)) {
		hg_lock_leave(hb);
		LM_CRIT("%s: large fragment %p is in memory the arena gave back - "
			"freed before, not touching it\n", hb->name, (void *)frag);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		return;
	}
	/* re-check under the lock: two concurrent frees can both pass
	 * hg_cell_free()'s check; a LIVE frag still listed is refused too */
	if (!hg_st_live(hg_hdr_state(cs)) ||
	    frag->prev) {
		hg_lock_leave(hb);
		LM_CRIT("%s: large fragment %p is already free - refusing to "
			"free it again\n", hb->name, (void *)frag);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		return;
	}
	if (!lfrag_sane(hb, frag)) {
		hg_lock_leave(hb);
		LM_CRIT("%s: boundary tag of large fragment %p overwritten (a "
			"neighbour's overflow?) - refusing to free it\n", hb->name,
			(void *)frag);
		hg_corrupt(hb, HG_C_OVERFLOW);
		return;
	}
	/* the size is trusted now: the debug tail, guard and sanitizer checks */
	st = hg_hdr_read(cs, &w, &base);
	if (hb->dbg || HG_SAN_PRIVATE(hb) || st == HG_ST_LIVE_G) {
		hg_san_open(hb, cs, frag->size - HG_CELL_HDR);
		if (hb->dbg)
			hg_dbg_tail_check(hb, cs, frag->size - HG_CELL_HDR);
		else if (st == HG_ST_LIVE_G &&
		    !hg_guard_ok(cs, base, frag->size - HG_CELL_HDR, &asked))
			hg_guard_bad(hb, cs, frag->size - HG_CELL_HDR, asked);
	}
	hg_hdr_set(cs, HG_LARGE_MARKER, HG_ST_FREE);

	hg_pstat_add(hg_pstat_mine(hb), -(long)(frag->size - HG_CELL_HDR), -1,
		0);
	hb->large_live -= HG_LFRAG_HDR + frag->size;

	/* forward coalesce; a damaged free neighbour is left alone */
	neigh = HG_LFRAG_NEXT(frag);
	if (neigh->prev && !lfrag_free_sane(hb, neigh)) {
		LM_CRIT("%s: free large fragment %p after %p is damaged - not "
			"merging with it\n", hb->name, (void *)neigh, (void *)frag);
		hg_corrupt(hb, HG_C_OVERFLOW);
	} else if (neigh->prev) {
		lfrag_remove_free(neigh);
		frag->size += HG_LFRAG_HDR + neigh->size;
		HG_LFRAG_NEXT(neigh)->pf = frag;
	}

	/* backward coalesce */
	neigh = frag->pf;
	if (neigh && neigh->prev && !lfrag_free_sane(hb, neigh)) {
		LM_CRIT("%s: free large fragment %p before %p is damaged - not "
			"merging with it\n", hb->name, (void *)neigh, (void *)frag);
		hg_corrupt(hb, HG_C_OVERFLOW);
	} else if (neigh && neigh->prev) {
		lfrag_remove_free(neigh);
		neigh->size += HG_LFRAG_HDR + frag->size;
		HG_LFRAG_NEXT(frag)->pf = neigh;
		frag = neigh;
	}

	/* a first frag (pf NULL) followed by the sentinel spans the chunk */
	if (!frag->pf && HG_LFRAG_NEXT(frag)->size == 0) {
		struct hg_large_chunk *ch = (struct hg_large_chunk *)(void *)
			((char *)frag - sizeof(struct hg_large_chunk));

		if (ch->first_frag == frag) {
			void *base = ch;
			unsigned long backing = ch->backing;
			int ord = ch->ord;

			/* the neighbours must point back: checked before the
			 * unlink writes through them */
			if ((ch->prev ? !lchunk_ok(hb, ch->prev) ||
			     ch->prev->next != ch : hb->large_chunks != ch) ||
			    (ch->next && (!lchunk_ok(hb, ch->next) ||
			     ch->next->prev != ch))) {
				LM_CRIT("%s: large chunk %p has damaged list links - "
					"not returning its backing\n", hb->name,
					(void *)ch);
				hg_corrupt(hb, HG_C_INTERNAL);
				hg_lock_leave(hb);
				return;
			}
			if (ch->prev)
				ch->prev->next = ch->next;
			else
				hb->large_chunks = ch->next;
			if (ch->next)
				ch->next->prev = ch->prev;

			hb->large_backing -= backing;
			hb->real_used     -= backing;
			hb->large_chunks_returned++;

			/* nothing below may touch ch or frag: the buddy writes
			 * its links over them */
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

unsigned long hg_large_frag_size_at(const void *frag)
{
	return hg_large_frag_size((const struct hg_lfrag *)frag);
}

/* the tag region follows the frag header directly, so the header's size
 * must keep every payload HG_PAYLOAD_ALIGN-aligned */
_Static_assert(HG_LFRAG_HDR_SIZE % HG_PAYLOAD_ALIGN == 0,
	"struct hg_lfrag must be a multiple of HG_PAYLOAD_ALIGN");
/* the first frag follows the chunk header (7 words: 28 B on 32-bit) */
_Static_assert(sizeof(struct hg_large_chunk) % HG_PAYLOAD_ALIGN == 0,
	"struct hg_large_chunk must be a multiple of HG_PAYLOAD_ALIGN");

void hg_large_destroy(struct hg_block *hb)
{
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

	/* from a signal handler that interrupted a locked section */
	if (hg_lock_depth)
		return;
	hg_lock_enter(hb, HG_LK_STATS);

	for (ch = hb->large_chunks; ch; ch = ch->next)
		for (f = ch->first_frag; f < ch->last_frag; f = HG_LFRAG_NEXT(f)) {
			if (!lfrag_sane(hb, f)) {
				hg_corrupt(hb, HG_C_OVERFLOW);
				break;
			}
			if (!f->prev)
				cb((char *)f + HG_LFRAG_HDR + HG_CELL_HDR, ctx);
		}

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
