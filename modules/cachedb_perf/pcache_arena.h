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

#define PCACHE_CELL_MAX   65536   /* largest cell; bigger allocs fail (v1) */
#define PCACHE_NCLASSES   21

int pcache_arena_init(void);
void pcache_arena_destroy(void);

/* reset inherited allocator state after fork: donates any pre-fork bump
 * chunk / private cells to the global pool.  Two processes must never
 * share a bump pointer. */
void pcache_arena_child_init(void);

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

/* modparam-triggered startup selftest; returns -1 on any mismatch */
int pcache_arena_selftest(void);

#endif /* _PCACHE_ARENA_H_ */
