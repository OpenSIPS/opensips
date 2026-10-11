/*
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Module-owned shared arenas.
 *
 * A module asks for an arena - a name, an initial size and a cap - and
 * gets memory fully managed by the allocator: on a build with HG_MALLOC
 * the arena is an HG block of its own (slab classes, per-process caches,
 * block GC and re-typing, elastic growth and shrink within the cap, the
 * maintenance process, hg_stats), created before the fork and inherited by
 * every child; with no HG_MALLOC compiled in shm_arena_create() returns
 * NULL and the module falls back to whatever it did before. The core
 * allocator selected with -a does not matter: the arena is HG either way.
 *
 * Call shm_arena_create() from mod_init() only.
 */
#ifndef mem_arena_h
#define mem_arena_h

#ifdef HG_MALLOC

#include "hg_malloc.h"
#include "shm_mem.h"      /* mem_allocator_shm, shm_block */

typedef struct hg_block mem_arena_t;

static inline mem_arena_t *shm_arena_create(char *name, unsigned long init,
		unsigned long cap)
{
	return hg_arena_create(name, init, cap);
}

static inline int shm_arena_set_profile(mem_arena_t *a, const char *profile)
{
	return hg_arena_set_profile(a, profile);
}

/* is the CORE shm allocator HG_MALLOC? (then shm_malloc() cells are HG cells
 * and a module may simply use shm_block as its arena handle) */
static inline int shm_allocator_is_hg(void)
{
	return mem_allocator_shm == MM_HG_MALLOC ||
	       mem_allocator_shm == MM_HG_MALLOC_DBG;
}
static inline mem_arena_t *shm_arena_core(void)
{
	return shm_allocator_is_hg() ? (mem_arena_t *)shm_block : NULL;
}

/* the reservation's address range: [lo, hi) holds every pointer the arena
 * ever hands out (the whole cap, committed or not) */
static inline void mem_arena_extents(const mem_arena_t *a, unsigned long *lo,
		unsigned long *hi)
{
	*lo = (unsigned long)a->hbase;
	*hi = (unsigned long)a->hbase + a->hcap;
}

/* the page tier init achieved (enum hg_mem_tier) */
static inline int mem_arena_tier(const mem_arena_t *a)
{
	return (int)a->tier;
}

/* committed bytes, the cap, and what is live (handed out) right now */
static inline void mem_arena_usage(mem_arena_t *a, unsigned long *committed,
		unsigned long *cap, unsigned long *live)
{
	*committed = a->committed_bytes;
	*cap = a->hcap;
	*live = hg_get_real_used(a);
}

#ifdef DBG_MALLOC
#define mem_arena_malloc(a, s) \
	hg_malloc((a), (s), __FILE__, __FUNCTION__, __LINE__)
#define mem_arena_free(a, p) \
	hg_free((a), (p), __FILE__, __FUNCTION__, __LINE__)
#define mem_arena_realloc(a, p, s) \
	hg_realloc((a), (p), (s), __FILE__, __FUNCTION__, __LINE__)
#else
#define mem_arena_malloc(a, s)     hg_malloc((a), (s))
#define mem_arena_free(a, p)       hg_free((a), (p))
#define mem_arena_realloc(a, p, s) hg_realloc((a), (p), (s))
#endif

#else /* !HG_MALLOC */

typedef void mem_arena_t;
static inline mem_arena_t *shm_arena_create(char *name, unsigned long init,
		unsigned long cap) { return NULL; }
static inline int shm_arena_set_profile(mem_arena_t *a, const char *profile)
{ return -1; }
static inline int shm_allocator_is_hg(void) { return 0; }
static inline mem_arena_t *shm_arena_core(void) { return NULL; }
static inline void mem_arena_extents(const mem_arena_t *a, unsigned long *lo,
		unsigned long *hi) { *lo = 0; *hi = 0; }
static inline int mem_arena_tier(const mem_arena_t *a) { return 0; }
static inline void mem_arena_usage(mem_arena_t *a, unsigned long *committed,
		unsigned long *cap, unsigned long *live)
{ *committed = 0; *cap = 0; *live = 0; }
#define mem_arena_malloc(a, s)     ((void *)0)
#define mem_arena_free(a, p)       do { } while (0)
#define mem_arena_realloc(a, p, s) ((void *)0)

#endif /* HG_MALLOC */

#endif /* mem_arena_h */
