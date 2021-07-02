/*
 * simple, very fast, malloc library
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2019 OpenSIPS Solutions
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

#ifdef F_MALLOC

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "f_malloc.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#define MIN_FRAG_SIZE	ROUNDTO
#define FRAG_OVERHEAD	(sizeof(struct fm_frag))
#define frag_is_free(_f) ((_f)->prev)

#define FRAG_NEXT(f) \
	((struct fm_frag *)((char *)(f) + sizeof(struct fm_frag) + (f)->size))

#define max(a,b) ( (a)>(b)?(a):(b))

/* ROUNDTO= 2^k so the following works */
#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

/* finds the hash value for s, s=ROUNDTO multiple*/
#define GET_HASH(s)   ( ((unsigned long)(s)<=F_MALLOC_OPTIMIZE)?\
							(unsigned long)(s)/ROUNDTO: \
							F_MALLOC_OPTIMIZE/ROUNDTO+big_hash_idx((s))- \
								F_MALLOC_OPTIMIZE_FACTOR+1 )

#define UN_HASH(h)	( ((unsigned long)(h)<=(F_MALLOC_OPTIMIZE/ROUNDTO))?\
						(unsigned long)(h)*ROUNDTO: \
						1UL<<((unsigned long)(h)-F_MALLOC_OPTIMIZE/ROUNDTO+\
							F_MALLOC_OPTIMIZE_FACTOR-1)\
					)

static inline void free_minus(struct fm_block *fm, unsigned long size)
{

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->real_used+=size;
	fm->used+=size;
	#endif
}


static inline void free_plus(struct fm_block *fm, unsigned long size)
{

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->real_used-=size;
	fm->used-=size;
	#endif
}


/* computes hash number for big buckets*/
inline static unsigned long big_hash_idx(unsigned long s)
{
	unsigned long idx;
	/* s is rounded => s = k*2^n (ROUNDTO=2^n)
	 * index= i such that 2^i > s >= 2^(i-1)
	 *
	 * => index = number of the first non null bit in s*/
	idx=sizeof(long)*8-1;
	for (; !(s&(1UL<<(sizeof(long)*8-1))) ; s<<=1, idx--);
	return idx;
}

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
unsigned long fm_stats_get_index(void *ptr)
{
	if (!ptr)
		return GROUP_IDX_INVALID;

	return FM_FRAG(ptr)->statistic_index;
}

void fm_stats_set_index(void *ptr, unsigned long idx)
{
	if (!ptr)
		return;

	FM_FRAG(ptr)->statistic_index = idx;
}
#endif

static inline void fm_insert_free(struct fm_block *fm, struct fm_frag *frag)
{
	struct fm_frag **f;
	int hash;

	hash=GET_HASH(frag->size);
	f=&(fm->free_hash[hash].first);
	if (frag->size > F_MALLOC_OPTIMIZE){ /* because of '<=' in GET_HASH,
											(different from 0.8.1[24] on
											 purpose --andrei ) */
		for(; *f; f=&((*f)->u.nxt_free)){
			if (frag->size <= (*f)->size) break;
		}
	}

	/*insert it here*/
	frag->prev = f;
	frag->u.nxt_free=*f;
	if( *f )
		(*f)->prev = &(frag->u.nxt_free);

	*f=frag;
	fm->free_hash[hash].no++;

	free_plus(fm, frag->size);
}

static inline void fm_remove_free(struct fm_block *fm, struct fm_frag *n)
{
	struct fm_frag **pf;
	int hash;

	pf = n->prev;
	hash = GET_HASH( n->size );

	/* detach */
	*pf=n->u.nxt_free;

	if( n->u.nxt_free )
		n->u.nxt_free->prev = pf;

	fm->free_hash[hash].no--;

	n->prev = NULL;

	free_minus(fm , n->size);

};





/* init malloc and return a fm_block*/
struct fm_block *fm_malloc_init(char *address, unsigned long size, char *name)

{
	char *start;
	char *end;
	struct fm_block *fm;
	unsigned long init_overhead;

	/* make address and size multiple of 8*/
	start=(char*)ROUNDUP((unsigned long) address);
	LM_DBG("F_OPTIMIZE=%lu, /ROUNDTO=%lu, %lu-bytes aligned\n",
			F_MALLOC_OPTIMIZE, F_MALLOC_OPTIMIZE/ROUNDTO,
			(unsigned long)ROUNDTO);
	LM_DBG("F_HASH_SIZE=%lu, fm_block size=%zu, frag_size=%zu\n",
			F_HASH_SIZE, sizeof(struct fm_block), sizeof(struct fm_frag));
	LM_DBG("params (%p, %lu), start=%p\n", address, size, start);

	if (size<(unsigned long)(start-address)) return 0;
	size-=(start-address);
	if (size <(MIN_FRAG_SIZE+FRAG_OVERHEAD)) return 0;
	size=ROUNDDOWN(size);

	init_overhead=(ROUNDUP(sizeof(struct fm_block))+ 2 * FRAG_OVERHEAD);


	if (size < init_overhead)
	{
		/* not enough mem to create our control structures !!!*/
		return 0;
	}
	end=start+size;
	fm=(struct fm_block *)start;
	memset(fm, 0, sizeof(struct fm_block));
	fm->name = name;
	fm->size=size;

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->used=size-init_overhead;
	fm->real_used=size;
	fm->max_real_used=init_overhead;
	fm->fragments = 0;
	#endif

	fm->first_frag=(struct fm_frag *)(start+ROUNDUP(sizeof(struct fm_block)));
	fm->last_frag=(struct fm_frag *)(end-sizeof(struct fm_frag));
	/* init initial fragment*/
	fm->first_frag->size=size-init_overhead;
	fm->last_frag->size=0;

	fm->last_frag->prev=NULL;
	fm->first_frag->prev=NULL;

	/* link initial fragment into the free list*/

	fm_insert_free(fm, fm->first_frag);

	return fm;
}

#include "f_malloc_dyn.h"

#if !defined INLINE_ALLOC && defined DBG_MALLOC
#undef DBG_MALLOC
#include "f_malloc_dyn.h"
#define DBG_MALLOC
#endif

#ifdef SHM_EXTRA_STATS
void fm_stats_core_init(struct fm_block *fm, int core_index)
{
	struct fm_frag *f;

	for (f=fm->first_frag; (char *)f < (char *)fm->last_frag; f=FRAG_NEXT(f))
		if (!frag_is_free(f))
			f->statistic_index = core_index;
}

#endif




/* fills a malloc info structure with info about the block
 * if a parameter is not supported, it will be filled with 0 */
void fm_info(struct fm_block *fm, struct mem_info *info)
{
	unsigned int r;
	long total_frags;
#if !defined(DBG_MALLOC) && !defined(STATISTICS)
	struct fm_frag *f;
#endif

	memset(info,0, sizeof(*info));
	total_frags=0;
	info->total_size=fm->size;
	info->min_frag=MIN_FRAG_SIZE;
#if defined(DBG_MALLOC) || defined(STATISTICS)
	info->free=fm->size-fm->real_used;
	info->used=fm->used;
	info->real_used=fm->real_used;
	info->max_used=fm->max_real_used;
	for(r=0;r<F_HASH_SIZE; r++){
		total_frags+=fm->free_hash[r].no;
	}
#else
	/* we'll have to compute it all */
	for (r=0; r<=F_MALLOC_OPTIMIZE/ROUNDTO; r++){
		info->free+=fm->free_hash[r].no*UN_HASH(r);
		total_frags+=fm->free_hash[r].no;
	}
	for(;r<F_HASH_SIZE; r++){
		total_frags+=fm->free_hash[r].no;
		for(f=fm->free_hash[r].first;f;f=f->u.nxt_free){
			info->free+=f->size;
		}
	}
	info->real_used=info->total_size-info->free;
	info->used=0; /* we don't really now */
	info->max_used=0; /* we don't really now */
#endif
	info->total_frags=total_frags;
}



#endif
