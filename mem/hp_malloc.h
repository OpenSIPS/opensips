/**
 * the truly parallel memory allocator
 *
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2014-01-19 initial version (liviu)
 */

#if !defined(HP_MALLOC_H) && !defined(VQ_MALLOC) && !defined(QM_MALLOC) && \
	!defined(F_MALLOC)

#define HP_MALLOC_H

#include <sys/time.h>

#include "../statistics.h"
#include "../config.h"
#include "../globals.h"

struct hp_frag;
struct hp_frag_lnk;
struct hp_block;

#ifndef HP_MALLOC_FAST_STATS
extern stat_var *shm_used;
extern stat_var *shm_rused;
extern stat_var *shm_frags;
#endif

#include "hp_malloc_stats.h"
#include "meminfo.h"

#define ROUNDTO 8UL
#define MIN_FRAG_SIZE	ROUNDTO

#define FRAG_NEXT(f) ((struct hp_frag *) \
		((char *)(f) + sizeof(struct hp_frag) + ((struct hp_frag *)(f))->size))

/* get the fragment which corresponds to a pointer */
#define FRAG_OF(p) \
	((struct hp_frag *)((char *)(p) - sizeof(struct hp_frag)))

#define FRAG_OVERHEAD	(sizeof(struct hp_frag))

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

/* used when detaching free fragments */
unsigned int optimized_get_indexes[HP_HASH_SIZE];

/* used when attaching free fragments */
unsigned int optimized_put_indexes[HP_HASH_SIZE];

/* finds the hash value for s, s=ROUNDTO multiple */
#define GET_HASH(s)  (((unsigned long)(s) <= HP_MALLOC_OPTIMIZE) ? \
	(unsigned long)(s) / ROUNDTO : \
	HP_LINEAR_HASH_SIZE + big_hash_idx((s)) - HP_MALLOC_OPTIMIZE_FACTOR + 1)

/* 
 * - for heavily used sizes (which need some optimizing) it returns
 *   a hash entry for the given size in a round-robin manner
 * - for the non-optimized sizes, behaviour is identical to GET_HASH
 */
#define GET_HASH_RR(fmb, s)  (((unsigned long)(s) <= HP_MALLOC_OPTIMIZE) ? \
	({ \
		unsigned int ___hash, ___idx, ___ret; \
		___hash = (unsigned long)(s) / ROUNDTO; \
		!fmb->free_hash[___hash].is_optimized ? \
			___hash : \
			({ \
				___idx = optimized_put_indexes[___hash]; \
				___ret = HP_HASH_SIZE + \
				         ___hash * shm_secondary_hash_size + ___idx; \
				optimized_put_indexes[___hash] = \
					(___idx + 1) % shm_secondary_hash_size; \
				___ret; \
			}); \
	}) : \
	HP_LINEAR_HASH_SIZE + big_hash_idx((s)) - HP_MALLOC_OPTIMIZE_FACTOR + 1)

/*
 * peek at the next round-robin assigned hash
 *
 * unlike GET_HASH_RR, it always returns the same result
 */
#define PEEK_HASH_RR(fmb, s)  (((unsigned long)(s) <= HP_MALLOC_OPTIMIZE) ? \
	({ \
		unsigned int ___hash; \
		___hash = (unsigned long)(s) / ROUNDTO; \
		!fmb->free_hash[___hash].is_optimized ? \
			___hash : \
			HP_HASH_SIZE + ___hash * shm_secondary_hash_size + \
			optimized_put_indexes[___hash]; \
	}) : \
	HP_LINEAR_HASH_SIZE + big_hash_idx((s)) - HP_MALLOC_OPTIMIZE_FACTOR + 1)

#define UN_HASH(h)	(((unsigned long)(h) <= (HP_MALLOC_OPTIMIZE/ROUNDTO)) ?\
						(unsigned long)(h)*ROUNDTO: \
						1UL<<((unsigned long)(h)-HP_MALLOC_OPTIMIZE/ROUNDTO+\
							HP_MALLOC_OPTIMIZE_FACTOR - 1)\
					)

struct hp_frag {
	unsigned long size;
	union {
		struct hp_frag *nxt_free;
		long reserved;
	} u;
	struct hp_frag **prev;
#ifdef DBG_MALLOC
	const char* file;
	const char* func;
	unsigned long line;
#endif

#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	char is_free;
#endif
#ifdef SHM_EXTRA_STATS
	unsigned long statistic_index;
#endif
};

struct hp_frag_lnk {
	/*
	 * optimized buckets are further split into
	 * "shm_secondary_hash_size" buckets
	 */
	char is_optimized;

	struct hp_frag *first;

	/*
	 * no - current number of free fragments in this bucket
	 * total_no - (no + allocated) free fragments in this bucket
	 */
	long no;
	long total_no;
};

struct hp_block {
	char *name; /* purpose of this memory block */

	unsigned long size; /* total size */
	unsigned long large_space;
	unsigned long large_limit;

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
};

unsigned long frag_size(void* p);

struct hp_block *hp_pkg_malloc_init(char *addr, unsigned long size, char *name);
struct hp_block *hp_shm_malloc_init(char *addr, unsigned long size, char *name);

int hp_mem_warming(struct hp_block *);
void hp_update_mem_pattern_file(void);

#ifdef DBG_MALLOC
void *hp_shm_malloc(struct hp_block *, unsigned long size,
						const char* file, const char* func, unsigned int line);
#else
void *hp_shm_malloc(struct hp_block *, unsigned long size);
#endif

#ifdef DBG_MALLOC
void *hp_shm_malloc_unsafe(struct hp_block *, unsigned long size,
							const char* file, const char* func, unsigned int line);
#else
void *hp_shm_malloc_unsafe(struct hp_block *, unsigned long size);
#endif

#ifdef DBG_MALLOC
void *hp_pkg_malloc(struct hp_block *, unsigned long size,
						const char* file, const char* func, unsigned int line);
#else
void *hp_pkg_malloc(struct hp_block *, unsigned long size);
#endif

#ifdef DBG_MALLOC
void hp_shm_free(struct hp_block *, void *p,
							const char* file, const char* func, unsigned int line);
#else
void hp_shm_free(struct hp_block *, void *p);
#endif

#ifdef DBG_MALLOC
void hp_shm_free_unsafe(struct hp_block *, void *p,
							const char* file, const char* func, unsigned int line);
#else
void hp_shm_free_unsafe(struct hp_block *, void *p);
#endif

#ifdef DBG_MALLOC
void hp_pkg_free(struct hp_block *, void *p,
					const char* file, const char* func, unsigned int line);
#else
void hp_pkg_free(struct hp_block *, void *p);
#endif

#ifdef DBG_MALLOC
void *hp_shm_realloc(struct hp_block *, void *p, unsigned long size,
						const char* file, const char* func, unsigned int line);
#else
void *hp_shm_realloc(struct hp_block *, void *p, unsigned long size);
#endif

#ifdef DBG_MALLOC
void *hp_shm_realloc_unsafe(struct hp_block *, void *p, unsigned long size,
								const char* file, const char* func, unsigned int line);
#else
void *hp_shm_realloc_unsafe(struct hp_block *, void *p, unsigned long size);
#endif

#ifdef DBG_MALLOC
void *hp_pkg_realloc(struct hp_block *, void *p, unsigned long size,
						const char* file, const char* func, unsigned int line);
#else
void *hp_pkg_realloc(struct hp_block *, void *p, unsigned long size);
#endif

#ifdef SHM_EXTRA_STATS
void set_stat_index (void *ptr, unsigned long idx);
unsigned long get_stat_index(void *ptr);
void set_indexes(int core_index);
#endif

#ifdef DBG_MALLOC
	#define _FRAG_FILE(_p) ((struct hp_frag*)((char *)_p - sizeof(struct hp_frag)))->file
	#define _FRAG_FUNC(_p) ((struct hp_frag*)((char *)_p - sizeof(struct hp_frag)))->func
	#define _FRAG_LINE(_p) ((struct hp_frag*)((char *)_p - sizeof(struct hp_frag)))->line
#endif

void hp_status(struct hp_block *);
void hp_info(struct hp_block *, struct mem_info *);

#endif /* HP_MALLOC_H */
