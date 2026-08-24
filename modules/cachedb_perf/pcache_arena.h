/*
 * cachedb_perf - high-performance local memory cache
 *
 * Copyright (C) 2026 Yury Kirsanov
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _PCACHE_ARENA_H_
#define _PCACHE_ARENA_H_

/*
 * Slab arena (DESIGN 3.3): entries live in fixed-size cells inside chunks
 * taken from shm and NEVER returned while the server runs - that is what
 * makes the lock-free read path (DESIGN 3.2) legal.  A chunk is permanently
 * bound to one size class; cells never straddle or move.
 *
 * The cell contract:
 *   - byte 0 of every cell is the CLASS ID, stamped for the whole chunk at
 *     carve time and never written again.  Callers lay their record out
 *     with byte 0 as a read-only class field.  This is how the copy-out
 *     clamp finds its bound through a stale pointer without aligned chunks:
 *     pcache_cell_bound() range-checks the byte and returns the cell size.
 *   - bytes 8..15 carry the free-list link while a cell is free; a live
 *     cell owns everything from byte 1 up.
 *
 * Allocation state is per-process (pkg, lazy): a bump chunk plus a private
 * free stack per class - zero shm traffic and zero atomics on the fast
 * path.  Owner frees go to the private stack (LIFO reuse); oversized
 * stacks donate half to a per-class global pool, which also serves refills
 * and takes cross-process frees (expiry / maintenance worker).
 */

#include "../../mi/item.h"

#define PCACHE_CELL_MAX   65536   /* largest cell; bigger allocs fail (v1) */
#define PCACHE_NCLASSES   21

/* Memory backing, decided in pcache_arena_init() (mod_init, pre-fork):
 *   PCACHE_BACKING_OWN     - this file's chunked allocator (chunks from
 *                            shm_malloc or the dedicated reservation)
 *   PCACHE_BACKING_CORE    - the core shm allocator is HG_MALLOC: every cell
 *                            is an HG slab cell in the shm arena
 *   PCACHE_BACKING_OWN_HG  - arena_hugepage_mb set on an HG_MALLOC build: the
 *                            arena is an HG arena of its own, fully managed
 *                            by HG (classes, GC, growth/shrink, maintenance)
 * Policy: the "memory_backing" modparam (auto|core|own-hg|own). */
enum pcache_backing { PCACHE_BACKING_OWN = 0, PCACHE_BACKING_CORE,
                      PCACHE_BACKING_OWN_HG };
extern char *pcache_backing_policy;          /* modparam memory_backing */
extern int pcache_arena_hugepage_cap_mb;     /* modparam, 0 = fixed */
extern char *pcache_arena_profile;           /* modparam arena_profile */
extern int pcache_reclaim_keep;              /* drained chunks kept per class */
extern int pcache_reclaim_quiet_s;           /* quiet window before give-back */
extern int pcache_reclaim_cooloff_s;         /* no give-back after a carve */
extern int pcache_reclaim_giveback;          /* 0 = retire/re-cut only */
int pcache_arena_backing(void);
const char *pcache_arena_backing_str(void);
void pcache_arena_backing_notice(void);

int pcache_arena_init(void);
void pcache_arena_destroy(void);

/* reset inherited allocator state after fork: donates any pre-fork bump
 * chunk / private cells to the global pool.  Two processes must never
 * share a bump pointer. */
void pcache_arena_child_init(void);
void pcache_arena_flush_private(void);       /* a done process sends cells home */
void pcache_arena_reclaim_tick(void);        /* the reclaim process, 1/s */
int pcache_arena_mi(mi_item_t *aobj);        /* reclaim view for perf_stats */

/* a cell of at least @size bytes (including the class byte), or NULL if
 * size > PCACHE_CELL_MAX or shm is exhausted */
void *pcache_cell_alloc(unsigned int size);

/* a raw, 64-byte-aligned, never-freed region for index structures (bucket
 * segments, directories).  Same backing seam and never-returned guarantee
 * as chunks; NOT carved into cells and NOT zeroed. */
void *pcache_region_alloc(size_t size);

/* owner free: private stack of the calling process */
void pcache_cell_free(void *cell);

/* cross-process free (expiry sweep, maintenance worker): global pool */
void pcache_cell_free_global(void *cell);

/* clamp bound for a possibly-stale cell pointer: the cell size of the
 * class in byte 0, or 0 if the byte is not a valid class id */
unsigned int pcache_cell_bound(const void *cell);

/* monotone address watermarks over all chunks (DESIGN 3.2 rule 2) */
void pcache_arena_extents(unsigned long *lo, unsigned long *hi);

void pcache_arena_stats(unsigned int *nchunks, unsigned long *bytes);

/* the memory tier the huge-page reservation actually achieved (1 hugetlb ..
 * 4 plain 4K), as opposed to the pcache_mem.tier probe - CP-11 */
int pcache_arena_tier(void);

/* see the implementation comment in pcache_arena.c - @active must be
 * checked before trusting total/used/free */
void pcache_arena_hugepage_capacity(int *active, unsigned long *total,
		unsigned long *used, unsigned long *free);

/* modparam-triggered startup selftest; returns -1 on any mismatch */
int pcache_arena_selftest(void);

#endif /* _PCACHE_ARENA_H_ */
