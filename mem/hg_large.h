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

/*
 * Large-object tier, for requests above HG_CELL_MAX, which the fixed size
 * classes of hg_arena.c cannot serve. Boundary-tag fragments as in f_malloc,
 * simplified because large allocations are rare and already slow-path: ONE
 * unsorted free list per hg_block, searched first-fit, and no coalescing
 * across chunks - each chunk is a self-contained f_malloc-style heap, and a
 * new one is taken from the buddy when no free frag fits.
 *
 * hg_cell_alloc() routes oversized requests here. hg_free()/hg_realloc()
 * tell a large frag from a cell by the class byte at HG_CELL_HDR before the
 * payload: HG_LARGE_MARKER, a value >= HG_NCLASSES (HG_CLASS/HG_HDR in
 * hg_malloc.h).
 */

#ifndef hg_large_h
#define hg_large_h

#include "hg_malloc.h"

/* struct hg_lfrag is in hg_malloc.h, visible wherever a payload pointer is
 * turned into its frag header */
#define HG_LFRAG_HDR (sizeof(struct hg_lfrag))

/*
 * @size is the usable payload size asked for (HG_CELL_HDR and HG_LFRAG_HDR
 * are added inside). A plain #ifdef DBG_MALLOC is safe here: hg_large.c
 * sees DBG_MALLOC's true state, with no hg_malloc.c-style local #undef.
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

/* its opaque-pointer form, hg_large_frag_size_at(), is declared in
 * hg_malloc.h, for callers that cannot see struct hg_lfrag */

void hg_large_destroy(struct hg_block *hb);

/* @cb(payload, ctx) for every live large frag. Always exact, pre- or
 * post-fork: a frag's ->prev is its free flag (NULL = live), as in
 * f_malloc's frag_is_free() */
void hg_large_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx);

#ifdef SHM_EXTRA_STATS
void hg_large_stats_core_init(struct hg_block *hb, int core_index);
#endif

#endif /* hg_large_h */
