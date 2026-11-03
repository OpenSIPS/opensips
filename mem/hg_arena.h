/*
 * slab allocator with elastic arenas - arena internals
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

/* Slab arena: buddy blocks, each bound to one size class while any cell is in
 * use and given back to the buddy once every cell is free */

#ifndef hg_arena_h
#define hg_arena_h

#include "hg_malloc.h"

/* @hdr_size: the block header at hb->hbase, which the bump offset skips */
int hg_arena_init(struct hg_block *hb, unsigned long hdr_size);

/* bump-carve @size bytes, 64-aligned; NULL if exhausted. Init only, for the
 * buddy's own metadata: refused once the buddy owns the arena (buddy_ready) */
void *hg_chunk_backing(struct hg_block *hb, unsigned long size);

/* the calling thread's cached cells, every arena, to the shared pools; on the
 * owning thread only, as the caches are __thread */
void hg_cache_flush_self(void);
void hg_private_caps_retune(struct hg_block *hb);
int hg_proc_cache_dirty(int proc);

/* drained-block GC, hb->lock held: hg_gc_cycle() recomputes each class's
 * keep; hg_gc_tick() frees up to @budget blocks beyond it, returns how many */
#define HG_GC_KEEP_MAX          8
#define HG_GC_KEEP_BUDGET_SHIFT 8     /* 1/256 of the arena per class */
#define HG_GC_EMERGENCY         32    /* drained beyond keep: donate path GCs */
#define HG_GC_TICK_BUDGET       32    /* blocks per maintenance tick */

void hg_gc_cycle(struct hg_block *hb);
unsigned int hg_gc_tick(struct hg_block *hb, unsigned int budget);

/* bumped once per sweep; see hg_cache_flush_if_due() */
extern unsigned long hg_sweep_gen;

/* called by the buddy on every grid allocation and free, the one point
 * every consumer passes; hb->lock held */
void hg_reserve_floor_check(struct hg_block *hb);

/* flush the calling thread's caches if a sweep was published since its last
 * flush; for threads IPC cannot reach (TCP main's IO pool), per job */
void hg_cache_flush_if_due(void);
/* hand back everything the calling thread holds in the shared arenas, the
 * unused rest of its chunks included - for a process leaving for good */
void hg_cache_drain_self(void);
void *hg_backing_aligned(struct hg_block *hb, unsigned long size,
                         unsigned long align);

/* a cell of at least @size usable bytes, or NULL if the arena is exhausted
 * (no fallback: raise -m/-M); above HG_CELL_MAX goes to the large tier */
#ifdef DBG_MALLOC
void *hg_cell_alloc(struct hg_block *hb, unsigned long size,
                    const char *file, const char *func, unsigned int line);
void hg_cell_free(struct hg_block *hb, void *p, const char *file,
                  const char *func, unsigned int line);
#else
void *hg_cell_alloc(struct hg_block *hb, unsigned long size);
void hg_cell_free(struct hg_block *hb, void *p);
#endif

/* free straight to the shared pool, bypassing the private cache: for an
 * arena the caller has no cache for (foreign, or no private slot) */
void hg_cell_free_global(struct hg_block *hb, void *cell);

void hg_arena_child_init(struct hg_block *hb);

/* release every cell the calling thread holds in @hb's quarantine
 * (HG_MALLOC_DBG), checking each; returns how many left it */
unsigned int hg_quarantine_drain(struct hg_block *hb);
void hg_cell_push_private(struct hg_block *hb, struct hg_palloc *pl,
                          unsigned int c, char *cell_start);

void hg_arena_destroy(struct hg_block *hb);

void hg_arena_stats(struct hg_block *hb, unsigned int *nchunks,
		unsigned long *bytes);

/* @cb(payload, ctx) per live small cell, exact pre-fork, best-effort after;
 * under hb->lock: @cb may not allocate or free in any HG_MALLOC arena */
void hg_arena_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx);

#ifdef SHM_EXTRA_STATS
/* tags every live cell and large frag with @core_index; once, pre-fork,
 * like hp_init_shm_statistics() */
void hg_arena_stats_core_init(struct hg_block *hb, int core_index);
#endif

#endif /* hg_arena_h */
