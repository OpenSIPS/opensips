/*
 * simple & fast malloc library
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-05-21  on sparc64 roundto 8 even in debugging mode (so malloc'ed
 *               long longs will be 64 bit aligned) (andrei)
 *  2004-07-19  support for 64 bit (2^64 mem. block) and more info
 *               for the future de-fragmentation support (andrei)
 *  2004-11-10  support for > 4Gb mem. (switched to long) (andrei)
 */


#if !defined(q_malloc_h) && !defined(VQ_MALLOC) && !defined(F_MALLOC) && \
	!defined(HP_MALLOC)
#define q_malloc_h

#include "meminfo.h"

/* defs*/
#ifdef DBG_MALLOC
#if defined(__CPU_sparc64) || defined(__CPU_sparc)
/* tricky, on sun in 32 bits mode long long must be 64 bits aligned
 * but long can be 32 bits aligned => malloc should return long long
 * aligned memory */
	#define ROUNDTO		sizeof(long long)
#else
	#define ROUNDTO		sizeof(void*) /* minimum possible ROUNDTO ->heavy
										 debugging*/
#endif
#else /* DBG_MALLOC */
	#define ROUNDTO		16UL /* size we round to, must be = 2^n  and also
							 sizeof(qm_frag)+sizeof(qm_frag_end)
							 must be multiple of ROUNDTO!
						   */
#endif
#define MIN_FRAG_SIZE	ROUNDTO



#define QM_MALLOC_OPTIMIZE_FACTOR 14UL /*used below */
#define QM_MALLOC_OPTIMIZE  ((unsigned long)(1UL<<QM_MALLOC_OPTIMIZE_FACTOR))
								/* size to optimize for,
									(most allocs <= this size),
									must be 2^k */

#define QM_HASH_SIZE ((unsigned long)(QM_MALLOC_OPTIMIZE/ROUNDTO + \
		(sizeof(long)*8-QM_MALLOC_OPTIMIZE_FACTOR)+1))

#define FRAG_OVERHEAD	(sizeof(struct qm_frag)+sizeof(struct qm_frag_end))
/* hash structure:
 * 0 .... QM_MALLOC_OPTIMIE/ROUNDTO  - small buckets, size increases with
 *                            ROUNDTO from bucket to bucket
 * +1 .... end -  size = 2^k, big buckets */

struct qm_frag{
	unsigned long size;
	union{
		struct qm_frag* nxt_free;
		long is_free;
	}u;
#ifdef DBG_MALLOC
	const char* file;
	const char* func;
	unsigned long line;
	unsigned long check;
#endif
#ifdef SHM_EXTRA_STATS
	unsigned long statistic_index;
#endif
};

struct qm_frag_end{
#ifdef DBG_MALLOC
	unsigned long check1;
	unsigned long check2;
	unsigned long reserved1;
	unsigned long reserved2;
#endif
	unsigned long size;
	struct qm_frag* prev_free;
};



struct qm_frag_lnk{
	struct qm_frag head;
	struct qm_frag_end tail;
	unsigned long no;
};


struct qm_block{
	char *name; /* purpose of this memory block */

	unsigned long size; /* total size */
	unsigned long used; /* alloc'ed size*/
	unsigned long real_used; /* used+malloc overhead*/
	unsigned long max_real_used;
	unsigned long fragments; /* number of fragments in use */

	struct qm_frag* first_frag;
	struct qm_frag_end* last_frag_end;

	struct qm_frag_lnk free_hash[QM_HASH_SIZE];
	/*struct qm_frag_end free_lst_end;*/
};



struct qm_block* qm_malloc_init(char* address, unsigned long size, char* name);
unsigned long frag_size(void* p);

#ifdef DBG_MALLOC
void* qm_malloc(struct qm_block*, unsigned long size, const char* file,
					const char* func, unsigned int line);
#else
void* qm_malloc(struct qm_block*, unsigned long size);
#endif

#ifdef DBG_MALLOC
void  qm_free(struct qm_block*, void* p, const char* file, const char* func,
				unsigned int line);
#else
void  qm_free(struct qm_block*, void* p);
#endif
#ifdef DBG_MALLOC
void* qm_realloc(struct qm_block*, void* p, unsigned long size,
					const char* file, const char* func, unsigned int line);
#else
void* qm_realloc(struct qm_block*, void* p, unsigned long size);
#endif

void  qm_status(struct qm_block*);
void  qm_info(struct qm_block*, struct mem_info*);

/*
 * On success, returns the currrent number of fragments
 * Internally aborts on failure
 */
int qm_mem_check(struct qm_block *qm);

#ifdef SHM_EXTRA_STATS
void set_stat_index (void *ptr, unsigned long idx);
unsigned long get_stat_index(void *ptr);
void set_indexes(int core_index);
#endif

#ifdef DBG_MALLOC
	#define _FRAG_FILE(_p) ((struct qm_frag*)((char *)_p - sizeof(struct qm_frag)))->file
	#define _FRAG_FUNC(_p) ((struct qm_frag*)((char *)_p - sizeof(struct qm_frag)))->func
	#define _FRAG_LINE(_p) ((struct qm_frag*)((char *)_p - sizeof(struct qm_frag)))->line
#endif

#ifdef STATISTICS
static inline unsigned long qm_get_size(struct qm_block* qm)
{
	return qm->size;
}
static inline unsigned long qm_get_used(struct qm_block* qm)
{
	return qm->used;
}
static inline unsigned long qm_get_free(struct qm_block* qm)
{
	return qm->size-qm->real_used;
}
static inline unsigned long qm_get_real_used(struct qm_block* qm)
{
	return qm->real_used;
}
static inline unsigned long qm_get_max_real_used(struct qm_block* qm)
{
	return qm->max_real_used;
}
static inline unsigned long qm_get_frags(struct qm_block* qm)
{
	return qm->fragments;
}
#endif /* STATISTICS */


#endif
