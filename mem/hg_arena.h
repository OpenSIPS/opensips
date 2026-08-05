/*
 * hugepage-backed slab allocator - arena internals
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
 * Slab arena, adapted from cachedb_perf's pcache_arena.{c,h} (DESIGN 2.6.1 /
 * 3.3): cells live in fixed-size chunks bump-carved from a huge-page
 * reservation and NEVER returned while the server runs - that is what keeps
 * the fast path lock-free. A chunk is permanently bound to one size class;
 * cells never straddle or move (Phase 1 has no defrag/GC - see the estimate
 * discussion; the only mitigation is idle-chunk return, added in a later
 * pass, not this one).
 *
 * Two structural differences from cachedb_perf, both required because
 * HG_MALLOC is a general-purpose shm/pkg allocator, not a single cache
 * module's private arena:
 *
 *   1. cachedb_perf's cells put the class-id byte at the FRONT of the
 *      pointer it hands to its own (fully-controlled) callers. HG_MALLOC
 *      hands pointers to arbitrary core/module code via shm_malloc(), so the
 *      class tag lives in a hidden header BEFORE the payload instead
 *      (HG_HDR/HG_CLASS in hg_malloc.h) - callers see a normal, aligned
 *      pointer, exactly like FM_FRAG(p) in f_malloc.
 *
 *   2. cachedb_perf has exactly one arena instance system-wide (a static
 *      global). HG_MALLOC can have several live instances in one process at
 *      once (shm, shm_dbg under DBG_MALLOC, and pkg, if pkg also selects
 *      HG_MALLOC) so every function here takes an explicit struct hg_block *
 *      and the per-process private free-stack state is looked up per-block
 *      (hg_get_palloc()), not a single global struct.
 */

#ifndef hg_arena_h
#define hg_arena_h

#include "hg_malloc.h"

/* builds the size -> class lookup table and positions the bump offset past
 * the block header (@hdr_size bytes, already reserved by hg_malloc_init()
 * at the front of hb->hbase) - called once, right after that header is
 * laid out */
int hg_arena_init(struct hg_block *hb, unsigned long hdr_size);

/* bump-carve @size bytes from hb's own hugepage reservation, 64-aligned.
 * NULL if exhausted - no fallback to another allocator (design decision).
 * Exposed for hg_large.c, which grows by carving additional chunks from
 * this SAME underlying arena rather than a separate reservation. */
void *hg_chunk_backing(struct hg_block *hb, unsigned long size);

/* a cell of at least @size usable bytes (header excluded), or NULL if
 * size > HG_CELL_MAX or the arena is exhausted. No fallback to another
 * allocator on exhaustion - fail loud, per the HG_MALLOC design decision
 * (increase -m/-M instead). DBG_MALLOC variant stamps file/func/line into
 * the cell header at EVERY call, since a cell is reused across many
 * allocations over its life (unlike the class id, stamped once at carve
 * time and immutable). */
#ifdef DBG_MALLOC
void *hg_cell_alloc(struct hg_block *hb, unsigned long size,
                    const char *file, const char *func, unsigned int line);
void hg_cell_free(struct hg_block *hb, void *p, const char *file,
                  const char *func, unsigned int line);
#else
void *hg_cell_alloc(struct hg_block *hb, unsigned long size);
void hg_cell_free(struct hg_block *hb, void *p);
#endif

/* a raw, 64-byte-aligned, never-freed region - same backing seam and
 * never-returned guarantee as chunks, but NOT carved into cells and NOT
 * zeroed. Not on the hg_malloc()/hg_free() hot path in Phase 1; kept for
 * future index-structure consumers (mirrors pcache_region_alloc). */
void *hg_region_alloc(struct hg_block *hb, unsigned long size);

/* cross-process free (not used in Phase 1 - no expiry/maintenance worker at
 * the allocator level - kept for API symmetry with the arena this was
 * ported from, and for the shared-pool donate/refill path itself) */
void hg_cell_free_global(struct hg_block *hb, void *cell);

/* re-sync after fork(): see hg_malloc_child_init() in hg_malloc.c */
void hg_arena_child_init(struct hg_block *hb);

void hg_arena_destroy(struct hg_block *hb);

void hg_arena_stats(struct hg_block *hb, unsigned int *nchunks,
		unsigned long *bytes);

/* invokes @cb(payload_ptr, ctx) for every currently-live small cell across
 * every chunk. Exact pre-fork, best-effort post-fork (see the file-header
 * comment in hg_arena.c above this function's definition for why). Used by
 * hg_arena_stats_core_init() and hg_status_dbg(). */
void hg_arena_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx);

#ifdef SHM_EXTRA_STATS
/* tags every currently-live cell/frag (small + large) with @core_index -
 * called once, pre-fork, mirroring hp_init_shm_statistics() */
void hg_arena_stats_core_init(struct hg_block *hb, int core_index);
#endif

#endif /* hg_arena_h */
