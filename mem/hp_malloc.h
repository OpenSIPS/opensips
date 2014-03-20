/* $Id$
 *
 * simple, very fast, malloc library
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2003-05-21  on sparc64 roundto 8 even in debugging mode (so malloc'ed
 *               long longs will be 64 bit aligned) (andrei)
 *  2004-07-19  support for 64 bit (2^64 mem. block) and more info
 *               for the future de-fragmentation support (andrei)
 *  2004-11-10  support for > 4Gb mem., switched to long (andrei)
 */


#if !defined(f_malloc_h) && !defined(VQ_MALLOC) && !defined(hp_malloc_h)
#define hp_malloc_h

#include "meminfo.h"
#include "../statistics.h"
#include "../config.h"
#include "../globals.h"

/* defs*/

#ifdef DBG_F_MALLOC
#if defined(__CPU_sparc64) || defined(__CPU_sparc)
/* tricky, on sun in 32 bits mode long long must be 64 bits aligned
 * but long can be 32 bits aligned => malloc should return long long
 * aligned memory */
	#define ROUNDTO		sizeof(long long)
#else
	#define ROUNDTO		sizeof(void*) /* size we round to, must be = 2^n, and
                      sizeof(fm_frag) must be multiple of ROUNDTO !*/
#endif
#else /* DBG_F_MALLOC */
	#define ROUNDTO 8UL
#endif
#define MIN_FRAG_SIZE	ROUNDTO



#define F_MALLOC_OPTIMIZE_FACTOR 14UL /*used below */
#define F_MALLOC_OPTIMIZE  (1UL<<F_MALLOC_OPTIMIZE_FACTOR)
								/* size to optimize for,
									(most allocs <= this size),
									must be 2^k */

#define LINEAR_HASH_SIZE (F_MALLOC_OPTIMIZE/ROUNDTO)
#define EXPONENTIAL_HASH_SIZE ((sizeof(long)*8-F_MALLOC_OPTIMIZE_FACTOR)+1)

#define F_HASH_SIZE (LINEAR_HASH_SIZE + EXPONENTIAL_HASH_SIZE + \
					 LINEAR_HASH_SIZE * SHM_MAX_SECONDARY_HASH_SIZE)
#define F_EXTRA_HASH_SIZE  (LINEAR_HASH_SIZE * SHM_MAX_SECONDARY_HASH_SIZE)

/* hash structure:
 * 0 .... F_MALLOC_OPTIMIZE/ROUNDTO  - small buckets, size increases with
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
unsigned int optimized_get_indexes[F_HASH_SIZE];

/* used when attaching free fragments */
unsigned int optimized_put_indexes[F_HASH_SIZE];

/* finds the hash value for s, s=ROUNDTO multiple */
#define GET_HASH(s)  (((unsigned long)(s) <= F_MALLOC_OPTIMIZE) ? \
	(unsigned long)(s) / ROUNDTO : \
	LINEAR_HASH_SIZE + big_hash_idx((s)) - F_MALLOC_OPTIMIZE_FACTOR + 1)

/* 
 * - for heavily used sizes (which need some optimizing) it returns
 *   a hash entry for the given size in a round-robin manner
 * - for the non-optimized sizes, behaviour is identical to GET_HASH
 */
#define GET_HASH_RR(fmb, s)  (((unsigned long)(s) <= F_MALLOC_OPTIMIZE) ? \
	({ \
		unsigned int ___hash, ___idx, ___ret; \
		___hash = (unsigned long)(s) / ROUNDTO; \
		!fmb->free_hash[___hash].is_optimized ? \
			___hash : \
			({ \
				___idx = optimized_put_indexes[___hash]; \
				___ret = F_HASH_SIZE + \
				         ___hash * shm_secondary_hash_size + ___idx; \
				optimized_put_indexes[___hash] = \
					(___idx + 1) % shm_secondary_hash_size; \
				___ret; \
			}); \
	}) : \
	LINEAR_HASH_SIZE + big_hash_idx((s)) - F_MALLOC_OPTIMIZE_FACTOR + 1)

/*
 * peek at the next round-robin assigned hash
 *
 * unlike GET_HASH_RR, it always returns the same result
 */
#define PEEK_HASH_RR(fmb, s)  (((unsigned long)(s) <= F_MALLOC_OPTIMIZE) ? \
	({ \
		unsigned int ___hash; \
		___hash = (unsigned long)(s) / ROUNDTO; \
		!fmb->free_hash[___hash].is_optimized ? \
			___hash : \
			F_HASH_SIZE + ___hash * shm_secondary_hash_size + \
			optimized_put_indexes[___hash]; \
	}) : \
	LINEAR_HASH_SIZE + big_hash_idx((s)) - F_MALLOC_OPTIMIZE_FACTOR + 1)

#define UN_HASH(h)	(((unsigned long)(h) <= (F_MALLOC_OPTIMIZE/ROUNDTO)) ?\
						(unsigned long)(h)*ROUNDTO: \
						1UL<<((unsigned long)(h)-F_MALLOC_OPTIMIZE/ROUNDTO+\
							F_MALLOC_OPTIMIZE_FACTOR-1)\
					)

struct fm_frag{
	unsigned long size;
	union{
		struct fm_frag* nxt_free;
		long reserved;
	}u;
        struct fm_frag ** prev;
#ifdef DBG_F_MALLOC
	const char* file;
	const char* func;
	unsigned long line;
	unsigned long check;
#endif
};

struct fm_frag_lnk{
	/* optimized buckets are further split into X buckets */
	char is_optimized;

	struct fm_frag* first;
	unsigned long no;
};

struct fm_block{
	unsigned long size; /* total size */
        unsigned long large_space;
        unsigned long large_limit;

#if defined(DBG_F_MALLOC) || defined(STATISTICS)
	unsigned long used; /* alloc'ed size*/
	unsigned long real_used; /* used+malloc overhead*/
	unsigned long max_real_used;
#endif

	struct fm_frag* first_frag;
	struct fm_frag* last_frag;

	/* 
	 * the extra hash further divides the heavily used buckets
	 * in order to achieve an even finer-grained locking
	 */
	struct fm_frag_lnk free_hash[F_HASH_SIZE + F_EXTRA_HASH_SIZE];
};

struct fm_block* fm_malloc_init(char* address, unsigned long size);
int fm_mem_warming(struct fm_block *fmb);
void fm_update_mem_pattern_file(void);

#ifdef DBG_F_MALLOC
void* fm_malloc(struct fm_block*, unsigned long size,
					const char* file, const char* func, unsigned int line);
#else
void* fm_malloc(struct fm_block*, unsigned long size);
#endif
void* fm_malloc_unsafe(struct fm_block*, unsigned long size);
void* fm_malloc_raw(struct fm_block*, unsigned long size);

#ifdef DBG_F_MALLOC
void  fm_free(struct fm_block*, void* p, const char* file, const char* func, 
				unsigned int line);
#else
void  fm_free(struct fm_block*, void* p);
#endif
void  fm_free_unsafe(struct fm_block *qm, void *p);
void  fm_free_raw(struct fm_block *qm, void *p);

#ifdef DBG_F_MALLOC
void*  fm_realloc(struct fm_block*, void* p, unsigned long size, 
					const char* file, const char* func, unsigned int line);
#else
void *fm_realloc(struct fm_block*, void* p, unsigned long size);
#endif
void *fm_realloc_unsafe(struct fm_block *qm, void *p, unsigned long size);
void *fm_realloc_raw(struct fm_block *qm, void *p, unsigned long size);

void  fm_status(struct fm_block*);
void  fm_info(struct fm_block*, struct mem_info*);


#ifdef STATISTICS
static inline unsigned long fm_get_size(struct fm_block* qm)
{
	return qm->size;
}
static inline unsigned long fm_get_used(struct fm_block* qm)
{
	return qm->used;
}
static inline unsigned long fm_get_free(struct fm_block* qm)
{
	return qm->size-qm->real_used;
}
static inline unsigned long fm_get_real_used(struct fm_block* qm)
{
	return qm->real_used;
}
static inline unsigned long fm_get_max_real_used(struct fm_block* qm)
{
	return qm->max_real_used;
}
static inline unsigned long fm_get_frags(struct fm_block* qm)
{
	unsigned long frags;
	unsigned int r;
	for(r=0,frags=0;r<F_HASH_SIZE; r++){
		frags+=qm->free_hash[r].no;
	}
	return frags;
}
#endif /*STATISTICS*/


#endif
