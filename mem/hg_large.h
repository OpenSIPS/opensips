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

/*
 * The small-object tier (hg_arena.c) caps out at HG_CELL_MAX (64K) by
 * design - fixed size classes, no splitting. Real OpenSIPS processes need
 * bigger single allocations than that even at plain startup (confirmed
 * empirically: init_pvar_support() alone needs ~140K), so this tier is a
 * hard prerequisite for HG_MALLOC to be usable, not an optional later
 * optimization.
 *
 * Design: boundary-tag fragments (ported from f_malloc's fm_frag/split/
 * coalesce logic), but with two deliberate simplifications given large
 * allocations are inherently rare and slow-path already:
 *   - ONE unsorted free list per hg_block, linear first-fit search, not
 *     f_malloc's size-hashed buckets. Correctness and coalescing matter
 *     here; O(1) lookup doesn't.
 *   - Frags never coalesce ACROSS chunk boundaries. Growth happens by
 *     bump-carving an additional chunk from the SAME hoff arena the
 *     small-object tier uses (hg_arena.c's hg_chunk_backing()) whenever no
 *     existing chunk has a big-enough free frag; each chunk is internally
 *     a self-contained f_malloc-style heap. This mirrors how the small
 *     tier itself grows (one more chunk, not a bigger single arena).
 *
 * Dispatch: hg_cell_alloc() (hg_arena.c) routes oversized requests here
 * instead of failing; hg_free()/hg_realloc() (hg_malloc_dyn.h) distinguish
 * a large frag from a small cell via the class-or-marker byte at the SAME
 * fixed HG_CELL_HDR offset before every payload pointer (HG_LARGE_MARKER,
 * a value >= HG_NCLASSES that small-cell code already treats as "not a
 * valid class" - repurposed here as "this is a large frag", not
 * corruption; see hg_malloc.h HG_CLASS/HG_HDR).
 */

#ifndef hg_large_h
#define hg_large_h

#include "hg_malloc.h"

struct hg_lfrag {
	unsigned long size;         /* total frag size: hdr + tag + payload */
	struct hg_lfrag *nxt_free;  /* NULL if allocated */
	struct hg_lfrag **prev;     /* NULL if allocated - f_malloc-style
	                              * free-list back-link for O(1) removal */
	struct hg_lfrag *pf;        /* physical previous frag in this chunk,
	                              * NULL if first frag of its chunk */
} __attribute__ ((aligned (ROUNDTO)));

#define HG_LFRAG_HDR (sizeof(struct hg_lfrag))

/*
 * @size is the caller's requested USABLE payload size (HG_CELL_HDR and
 * HG_LFRAG_HDR are added internally). Unlike hg_cell_alloc()/hg_cell_free()
 * (hg_arena.h), these have only ONE signature each, not a DBG_MALLOC-gated
 * pair: hg_large.c is compiled once, always seeing DBG_MALLOC's true global
 * state directly (no hg_malloc.c-style local #undef dance), so there's no
 * ambiguity to guard against here.
 */
#ifdef DBG_MALLOC
void *hg_large_alloc(struct hg_block *hb, unsigned long size,
                     const char *file, const char *func, unsigned int line);
#else
void *hg_large_alloc(struct hg_block *hb, unsigned long size);
#endif

/* @frag is the struct hg_lfrag* at the very start of the block (i.e.
 * HG_HDR(payload) - HG_LFRAG_HDR), not the payload pointer itself */
void hg_large_free(struct hg_block *hb, struct hg_lfrag *frag);

/* total frag size (hdr+tag+payload), for hg_frag_size()/stats */
unsigned long hg_large_frag_size(const struct hg_lfrag *frag);

/* opaque-pointer wrapper - declared in hg_malloc.h (included above), not
 * redeclared here, since that's the one callers who can't see struct
 * hg_lfrag need */

void hg_large_destroy(struct hg_block *hb);

/* invokes @cb(payload_ptr, ctx) for every currently-live large frag. Unlike
 * hg_arena_walk_live() (small cells), this needs no auxiliary free-address
 * set: a large frag's own ->prev field IS the free/live flag (NULL = live),
 * exactly like f_malloc's frag_is_free(), so this is always exact -
 * regardless of pre-/post-fork - not best-effort. */
void hg_large_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx);

#ifdef SHM_EXTRA_STATS
void hg_large_stats_core_init(struct hg_block *hb, int core_index);
#endif

#endif /* hg_large_h */
