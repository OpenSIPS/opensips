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

/*
 * Slab arena: cells live in fixed-size blocks carved from the buddy
 * allocator. A block is bound to one size class while any of its cells is
 * in use; cells never straddle or move. A block whose cells are all free
 * goes back to the buddy. The class tag sits in a hidden header before the
 * payload (HG_HDR/HG_CLASS in hg_malloc.h), so callers get a normal aligned
 * pointer. One process can hold several arenas (shm, shm_dbg, pkg), so every
 * function takes a struct hg_block * and the calling thread's private
 * free-list state is looked up per arena (hg_get_palloc()).
 */

#ifndef hg_arena_h
#define hg_arena_h

#include "hg_malloc.h"

/* builds the size -> class table and starts the bump offset past the block
 * header (@hdr_size bytes at hb->hbase, laid out by hg_malloc_init());
 * called once, right after that header */
int hg_arena_init(struct hg_block *hb, unsigned long hdr_size);

/* bump-carve @size bytes from hb's reservation, 64-aligned; NULL if
 * exhausted (no fallback allocator). Init only, for the buddy's own
 * metadata: refused once the buddy owns the arena (buddy_ready) */
void *hg_chunk_backing(struct hg_block *hb, unsigned long size);

/* flush the calling thread's cached cells back to the shared pool, in every
 * arena it caches in. MUST run on the owning thread: the caches are
 * __thread, which is why a sweep is dispatched to each thread */
void hg_cache_flush_self(void);
void hg_private_caps_retune(struct hg_block *hb);
int hg_proc_cache_dirty(int proc);

/* the drained-block GC, hb->lock held. hg_gc_cycle() recomputes each
 * class's keep from the cycle just ended; hg_gc_tick() returns up to
 * @budget blocks beyond keep, round-robin over the classes, and returns how
 * many. Run by the maintenance process for shm (tick every second, cycle
 * every policy cycle), by the owner's sweep flush for a private arena. */
#define HG_GC_KEEP_MAX          8
#define HG_GC_KEEP_BUDGET_SHIFT 8     /* 1/256 of the arena per class */
#define HG_GC_EMERGENCY         32    /* drained beyond keep: donate path GCs */
#define HG_GC_TICK_BUDGET       32    /* blocks per maintenance tick */

void hg_gc_cycle(struct hg_block *hb);
unsigned int hg_gc_tick(struct hg_block *hb, unsigned int budget);

/* sweep generation, bumped once per sweep (see hg_cache_flush_if_due()) */
extern volatile unsigned long hg_sweep_gen;

/* evaluate the reserve floor; called from the buddy layer on every grid
 * allocation and free, the one point every consumer passes. hb->lock held */
void hg_reserve_floor_check(struct hg_block *hb);

/* widen the [lo,hi] extent watermarks over a region just handed out; called
 * from the buddy layer so every consumer is covered. hb->lock held */
void hg_extent_note(struct hg_block *hb, void *base, unsigned long size);
/* flush the calling thread's caches if a sweep was published since its last
 * flush (one read of a global). For threads IPC cannot reach - TCP main's IO
 * pool waits on a condvar, not the reactor - at a job boundary */
void hg_cache_flush_if_due(void);
/* hand back everything the calling thread holds in the shared arenas, the
 * unused rest of its chunks included - for a process leaving for good */
void hg_cache_drain_self(void);
void *hg_backing_aligned(struct hg_block *hb, unsigned long size,
                         unsigned long align);

/* a cell of at least @size usable bytes (header excluded), or NULL if the
 * arena is exhausted - no fallback allocator, raise -m/-M instead. Requests
 * above HG_CELL_MAX go to the large tier. The DBG_MALLOC variant stamps
 * file/func/line on every call: a cell is reused across many allocations,
 * while its class id is stamped once, at carve time. */
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

/* re-sync after fork(): see hg_malloc_child_init() in hg_malloc.c */
void hg_arena_child_init(struct hg_block *hb);

/* release every cell the calling thread holds in @hb's quarantine
 * (HG_MALLOC_DBG), checking each; returns how many left it */
unsigned int hg_quarantine_drain(struct hg_block *hb);
/* a FREE cell onto the calling thread's private list of @hb - for hg_dbg.c,
 * whose quarantine hands cells back this way */
void hg_cell_push_private(struct hg_block *hb, struct hg_palloc *pl,
                          unsigned int c, char *cell_start);

void hg_arena_destroy(struct hg_block *hb);

/* hg_slab_recycled() is declared in hg_malloc.h: do not redeclare it */
void hg_arena_stats(struct hg_block *hb, unsigned int *nchunks,
		unsigned long *bytes);

/* @cb(payload, ctx) for every live small cell; exact pre-fork, best-effort
 * post-fork (see hg_arena.c). Used by hg_arena_stats_core_init() and
 * hg_status_dbg() */
void hg_arena_walk_live(struct hg_block *hb,
		void (*cb)(void *payload, void *ctx), void *ctx);

#ifdef SHM_EXTRA_STATS
/* tags every live cell and large frag with @core_index; once, pre-fork,
 * like hp_init_shm_statistics() */
void hg_arena_stats_core_init(struct hg_block *hb, int core_index);
#endif

#endif /* hg_arena_h */
