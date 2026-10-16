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

/* Slab arena.  Memory is never unmapped while running, which the lock-free
 * read path relies on.  Byte 0 of every cell is its immutable class id;
 * bytes 8..15 hold the free-list link while free. */

#include "../../mi/item.h"

#define PCACHE_CELL_MAX   65536   /* largest cell; bigger allocs fail (v1) */
#define PCACHE_NCLASSES   21

/* OWN = own slot allocator, CORE = core HG_MALLOC shm, OWN_HG = own HG arena */
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

/* after fork: donate inherited private state to the global pool, so no
 * two processes share a bump pointer */
void pcache_arena_child_init(void);
void pcache_arena_flush_private(void);       /* a done process sends cells home */
void pcache_arena_reclaim_tick(void);        /* the reclaim process, 1/s */
int pcache_arena_mi(mi_item_t *aobj);        /* reclaim view for perf_stats */

/* a cell of at least @size bytes (including the class byte), or NULL if
 * size > PCACHE_CELL_MAX or shm is exhausted */
void *pcache_cell_alloc(unsigned int size);

/* a 64-byte-aligned, never-freed, non-zeroed region for index structures */
void *pcache_region_alloc(size_t size);

/* owner free: private stack of the calling process */
void pcache_cell_free(void *cell);

/* cross-process free: global pool */
void pcache_cell_free_global(void *cell);

/* clamp bound for a possibly-stale cell pointer: the cell size of the
 * class in byte 0, or 0 if the byte is not a valid class id */
unsigned int pcache_cell_bound(const void *cell);

/* monotone address watermarks over all chunks */
void pcache_arena_extents(unsigned long *lo, unsigned long *hi);

void pcache_arena_stats(unsigned int *nchunks, unsigned long *bytes);

/* the tier the reservation actually achieved, not the probe result */
int pcache_arena_tier(void);

/* @active must be checked before trusting total/used/free */
void pcache_arena_hugepage_capacity(int *active, unsigned long *total,
		unsigned long *used, unsigned long *free);

/* modparam-triggered startup selftest; returns -1 on any mismatch */
int pcache_arena_selftest(void);

#endif /* _PCACHE_ARENA_H_ */
