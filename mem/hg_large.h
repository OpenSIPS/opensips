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

/* Large-object tier, above HG_CELL_MAX: f_malloc-style chunks from the
 * buddy, ONE unsorted first-fit list, as large allocations are rare */

#ifndef hg_large_h
#define hg_large_h

#include "hg_malloc.h"

#define HG_LFRAG_HDR (sizeof(struct hg_lfrag))

#ifdef DBG_MALLOC
void *hg_large_alloc(struct hg_block *hb, unsigned long size,
                     const char *file, const char *func, unsigned int line);
#else
void *hg_large_alloc(struct hg_block *hb, unsigned long size);
#endif

void hg_large_free(struct hg_block *hb, struct hg_lfrag *frag);

/* total frag size (hdr+tag+payload) */
unsigned long hg_large_frag_size(const struct hg_lfrag *frag);

void hg_large_destroy(struct hg_block *hb);

/* @cb(payload, ctx) per live large frag, exact; under hb->lock: @cb may not
 * allocate or free in any HG_MALLOC arena */
void hg_large_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx);

#ifdef SHM_EXTRA_STATS
void hg_large_stats_core_init(struct hg_block *hb, int core_index);
#endif

#endif /* hg_large_h */
