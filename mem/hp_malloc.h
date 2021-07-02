/**
 * high-performance allocator with fine-grained SHM locking
 *   (note: may perform worse than F_MALLOC at low CPS values!)
 *
 * Copyright (C) 2014-2019 OpenSIPS Solutions
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

#ifndef HP_MALLOC_H
#define HP_MALLOC_H

#include <sys/time.h>

#include "../statistics.h"
#include "../config.h"
#include "../globals.h"
#include "common.h"

#if !defined INLINE_ALLOC && defined HP_MALLOC_FAST_STATS
#warning "multiple allocators detected -- disabling HP_MALLOC_FAST_STATS"
#undef HP_MALLOC_FAST_STATS
#endif

struct hp_frag;
struct hp_frag_lnk;
struct hp_block;

#ifndef HP_MALLOC_FAST_STATS
extern stat_var *shm_used;
extern stat_var *shm_rused;
extern stat_var *shm_frags;
#endif
extern stat_var *rpm_used;
extern stat_var *rpm_rused;
extern stat_var *rpm_frags;

#include "hp_malloc_stats.h"
#include "meminfo.h"

#undef ROUNDTO
#undef UN_HASH

#define ROUNDTO 8UL /* address alignment, in bytes */

#define HP_MALLOC_OPTIMIZE_FACTOR 14UL /*used below */
#define HP_MALLOC_OPTIMIZE  (1UL << HP_MALLOC_OPTIMIZE_FACTOR)
								/* size to optimize for,
									(most allocs <= this size),
									must be 2^k */

#define HP_LINEAR_HASH_SIZE (HP_MALLOC_OPTIMIZE/ROUNDTO)
#define HP_EXPONENTIAL_HASH_SIZE ((sizeof(long)*8-HP_MALLOC_OPTIMIZE_FACTOR)+1)

#define HP_HASH_SIZE       (HP_LINEAR_HASH_SIZE + HP_EXPONENTIAL_HASH_SIZE)
#define HP_EXTRA_HASH_SIZE (HP_LINEAR_HASH_SIZE * SHM_MAX_SECONDARY_HASH_SIZE)

#define HP_TOTAL_HASH_SIZE (HP_HASH_SIZE + HP_EXTRA_HASH_SIZE)

/* get the fragment which corresponds to a pointer */
#define HP_FRAG(p) \
	((struct hp_frag *)((char *)(p) - sizeof(struct hp_frag)))

#define UN_HASH(h)	(((unsigned long)(h) <= (HP_MALLOC_OPTIMIZE/ROUNDTO)) ?\
						(unsigned long)(h)*ROUNDTO: \
						1UL<<((unsigned long)(h)-HP_MALLOC_OPTIMIZE/ROUNDTO+\
							HP_MALLOC_OPTIMIZE_FACTOR - 1)\
					)

/* hash structure:
 * 0 .... HP_MALLOC_OPTIMIZE/ROUNDTO  - small buckets, size increases with
 *                            ROUNDTO from bucket to bucket
 * +1 .... end -  size = 2^k, big buckets
 * (0 0 0 0 0   ...         0) (ROUNDTO ROUNDTO ...) (2*ROUNDTO...) .... (...) - additional array of hashes!
 *  | | | | |               |      |       |              |
 *  | | | | |               |      |       |              |
 *  | | | | |               |      |       |              |
 *  | | | | |               |      |       |              |
 *  v v v v v               v      v       v              v
 *
 * ^-------  sshs  ----------^ ^------ sshs -------^ ^--- sshs ---^      ^---^
 *  
 *  sshs = "shm_secondary_hash_size" script parameter
 */

struct hp_frag {
	unsigned long size;

	struct hp_frag **prev;
	struct hp_frag *nxt_free;

#ifdef DBG_MALLOC
	const char *file;
	const char *func;
	unsigned long line;
#endif

#ifdef SHM_EXTRA_STATS
	unsigned long statistic_index;
#endif
} __attribute__ ((aligned (ROUNDTO)));

#define HP_FRAG_OVERHEAD (sizeof(struct hp_frag))

struct hp_frag_lnk {
	/*
	 * optimized buckets are further split into
	 * "shm_secondary_hash_size" buckets
	 */
	char is_optimized;

	struct hp_frag *first;

#ifdef HP_MALLOC_FAST_STATS
	/*
	 * no: current number of free fragments in this bucket
	 * total_no: (no + allocated) fragments in this bucket
	 */
	long no;
	long total_no;
#endif
};

struct hp_block {
	char *name; /* purpose of this memory block */

	unsigned long size; /* total size */
	unsigned long used; /* alloc'ed size */
	unsigned long real_used; /* used+malloc overhead */
	unsigned long max_real_used;
	unsigned long total_fragments;

	struct timeval last_updated;

	struct hp_frag *first_frag;
	struct hp_frag *last_frag;

	/* 
	 * the extra hash further divides the heavily used buckets
	 * in order to achieve an even finer-grained locking
	 */
	struct hp_frag_lnk free_hash[HP_HASH_SIZE + HP_EXTRA_HASH_SIZE];
} __attribute__ ((aligned (ROUNDTO)));

struct hp_block *hp_pkg_malloc_init(char *addr, unsigned long size, char *name);
struct hp_block *hp_shm_malloc_init(char *addr, unsigned long size, char *name);

int hp_mem_warming(struct hp_block *);
void hp_update_shm_pattern_file(void);

#ifdef DBG_MALLOC
void *hp_shm_malloc(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_shm_malloc_unsafe(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_pkg_malloc(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_malloc(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_malloc_unsafe(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void hp_shm_free(struct hp_block *, void *p,
				const char *file, const char *func, unsigned int line);
void hp_shm_free_unsafe(struct hp_block *, void *p,
						const char *file, const char *func, unsigned int line);
void hp_pkg_free(struct hp_block *, void *p,
				const char *file, const char *func, unsigned int line);
void hp_rpm_free(struct hp_block *, void *p,
				const char *file, const char *func, unsigned int line);
void hp_rpm_free_unsafe(struct hp_block *, void *p,
						const char *file, const char *func, unsigned int line);
void *hp_shm_realloc(struct hp_block *, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_shm_realloc_unsafe(struct hp_block *, void *p, unsigned long size,
						const char *file, const char *func, unsigned int line);
void *hp_pkg_realloc(struct hp_block *, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_realloc(struct hp_block *, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_realloc_unsafe(struct hp_block *, void *p, unsigned long size,
						const char *file, const char *func, unsigned int line);
#ifndef INLINE_ALLOC
void *hp_shm_malloc_dbg(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_shm_malloc_unsafe_dbg(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_pkg_malloc_dbg(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_malloc_dbg(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_malloc_unsafe_dbg(struct hp_block *, unsigned long size,
					const char *file, const char *func, unsigned int line);
void hp_shm_free_dbg(struct hp_block *, void *p,
				const char *file, const char *func, unsigned int line);
void hp_shm_free_unsafe_dbg(struct hp_block *, void *p,
						const char *file, const char *func, unsigned int line);
void hp_pkg_free_dbg(struct hp_block *, void *p,
				const char *file, const char *func, unsigned int line);
void hp_rpm_free_dbg(struct hp_block *, void *p,
				const char *file, const char *func, unsigned int line);
void hp_rpm_free_unsafe_dbg(struct hp_block *, void *p,
						const char *file, const char *func, unsigned int line);
void *hp_shm_realloc_dbg(struct hp_block *, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_shm_realloc_unsafe_dbg(struct hp_block *, void *p, unsigned long size,
						const char *file, const char *func, unsigned int line);
void *hp_pkg_realloc_dbg(struct hp_block *, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_realloc_dbg(struct hp_block *, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
void *hp_rpm_realloc_unsafe_dbg(struct hp_block *, void *p, unsigned long size,
						const char *file, const char *func, unsigned int line);
#endif
#else
void *hp_shm_malloc(struct hp_block *, unsigned long size);
void *hp_shm_malloc_unsafe(struct hp_block *, unsigned long size);
void *hp_pkg_malloc(struct hp_block *, unsigned long size);
void hp_shm_free(struct hp_block *, void *p);
void hp_shm_free_unsafe(struct hp_block *, void *p);
void hp_pkg_free(struct hp_block *, void *p);
void *hp_shm_realloc(struct hp_block *, void *p, unsigned long size);
void *hp_shm_realloc_unsafe(struct hp_block *, void *p, unsigned long size);
void *hp_pkg_realloc(struct hp_block *, void *p, unsigned long size);
void *hp_rpm_malloc(struct hp_block *, unsigned long size);
void *hp_rpm_malloc_unsafe(struct hp_block *, unsigned long size);
void hp_rpm_free(struct hp_block *, void *p);
void hp_rpm_free_unsafe(struct hp_block *, void *p);
void *hp_rpm_realloc(struct hp_block *, void *p, unsigned long size);
void *hp_rpm_realloc_unsafe(struct hp_block *, void *p, unsigned long size);
#endif

#ifdef SHM_EXTRA_STATS
static inline unsigned long hp_frag_size(void *p)
{
	if (!p)
		return 0;

	return HP_FRAG(p)->size;
}

void hp_stats_core_init(struct hp_block *hp, int core_index);
unsigned long hp_stats_get_index(void *ptr);
void hp_stats_set_index(void *ptr, unsigned long idx);

#ifdef DBG_MALLOC
static inline const char *hp_frag_file(void *p) { return HP_FRAG(p)->file; }
static inline const char *hp_frag_func(void *p) { return HP_FRAG(p)->func; }
static inline unsigned long hp_frag_line(void *p) { return HP_FRAG(p)->line; }
#else
static inline const char *hp_frag_file(void *p) { return NULL; }
static inline const char *hp_frag_func(void *p) { return NULL; }
static inline unsigned long hp_frag_line(void *p) { return 0; }
#endif
#endif

void hp_status(struct hp_block *hpb);
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void hp_status_dbg(struct hp_block *hpb);
#endif
void hp_info(struct hp_block *, struct mem_info *);

#endif /* HP_MALLOC_H */
