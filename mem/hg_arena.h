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
 * Slab arena, adapted from the private slab arena of an earlier caching
 * module: cells live in fixed-size blocks carved from the buddy allocator.
 * A block is bound to one size class while any of its cells is in use;
 * cells never straddle or move. When every cell of a block is free again
 * the block goes back to the buddy and can be re-carved for another class.
 *
 * Two structural differences from that arena, both required because
 * HG_MALLOC is a general-purpose shm/pkg allocator, not a single cache
 * module's private arena:
 *
 *   1. The cache's cells put the class-id byte at the FRONT of the
 *      pointer it hands to its own (fully-controlled) callers. HG_MALLOC
 *      hands pointers to arbitrary core/module code via shm_malloc(), so the
 *      class tag lives in a hidden header BEFORE the payload instead
 *      (HG_HDR/HG_CLASS in hg_malloc.h) - callers see a normal, aligned
 *      pointer, exactly like FM_FRAG(p) in f_malloc.
 *
 *   2. The cache has exactly one arena instance system-wide (a static
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

/* Flush this THREAD's cached cells back to the shared pool, in every arena it
 * caches in. Must run on the owning thread - the caches are __thread and are
 * unreachable from anywhere else, which is the whole reason the sweep is
 * dispatched rather than executed centrally. */
void hg_cache_flush_self(void);
int hg_proc_cache_dirty(int proc);

/* the drained-block GC, hb->lock held by the caller. hg_gc_cycle()
 * recomputes every class's keep from the carves of the cycle just ended;
 * hg_gc_tick() returns up to @budget blocks beyond their classes' keep,
 * round-robin over the classes. The maintenance process runs both for shm
 * (tick every second, cycle every policy cycle); a private arena runs both
 * in its owner's sweep flush. Returns blocks handed back. */
#define HG_GC_KEEP_MAX          8
#define HG_GC_KEEP_BUDGET_SHIFT 8     /* 1/256 of the arena per class */
#define HG_GC_EMERGENCY         32    /* drained beyond keep: donate path GCs */
#define HG_GC_TICK_BUDGET       32    /* blocks per maintenance tick */

void hg_gc_cycle(struct hg_block *hb);
unsigned int hg_gc_tick(struct hg_block *hb, unsigned int budget);

/* Flush only if a sweep has been requested since this thread last looked.
 * For threads IPC cannot reach - TCP main's IO pool waits on a condvar, not
 * the reactor - called at a job boundary. Cheap: one read of a global. */
extern volatile unsigned long hg_sweep_gen;

/* Evaluate the reserve floor. Called from the buddy layer on every grid
 * allocation and free, because that is the one point every consumer passes -
 * see the definition in hg_arena.c for what went wrong when it lived in
 * carve_chunk() instead. hb->lock must be held. */
void hg_reserve_floor_check(struct hg_block *hb);

/* Widen the [lo,hi] extent watermarks over a region just handed out. Called
 * from the buddy layer so every consumer of grid space is covered.
 * hb->lock must be held. */
void hg_extent_note(struct hg_block *hb, void *base, unsigned long size);
/* flush the calling thread's caches if a sweep was published since its
 * last flush - for threads IPC cannot reach (TCP main's IO pool) */
void hg_cache_flush_if_due(void);
/* hand back everything the calling thread holds in the shared arenas, the
 * unused rest of its chunks included - for a process leaving for good */
void hg_cache_drain_self(void);
void *hg_backing_aligned(struct hg_block *hb, unsigned long size,
                         unsigned long align);

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

/* free straight to the shared pool, bypassing the private cache: used for
 * a cell freed into an arena the caller has no cache for (a foreign arena,
 * or a process with no private slot) */
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

/* hg_slab_recycled() is declared in hg_malloc.h, which this header
 * already includes - do not redeclare it here */
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
