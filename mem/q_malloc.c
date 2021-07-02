/*
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

#ifdef Q_MALLOC

#include <stdlib.h>
#include <string.h>

#include "q_malloc.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

/*useful macros*/
#define FRAG_END(f)  \
	((struct qm_frag_end*)((char*)(f)+sizeof(struct qm_frag)+ \
	   (f)->size))

#define FRAG_NEXT(f) \
	((struct qm_frag*)((char*)(f)+sizeof(struct qm_frag)+(f)->size+ \
	   sizeof(struct qm_frag_end)))

#define FRAG_PREV(f) \
	( (struct qm_frag*) ( ((char*)(f)-sizeof(struct qm_frag_end))- \
	((struct qm_frag_end*)((char*)(f)-sizeof(struct qm_frag_end)))->size- \
	   sizeof(struct qm_frag) ) )

#define PREV_FRAG_END(f) \
	((struct qm_frag_end*)((char*)(f)-sizeof(struct qm_frag_end)))

#define MIN_FRAG_SIZE	QM_ROUNDTO
#define FRAG_OVERHEAD	(sizeof(struct qm_frag)+sizeof(struct qm_frag_end))

#define ROUNDTO_MASK	(~((unsigned long)QM_ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(QM_ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

/*
#define ROUNDUP(s)		(((s)%QM_ROUNDTO)?((s)+QM_ROUNDTO)/QM_ROUNDTO*QM_ROUNDTO:(s))
#define ROUNDDOWN(s)	(((s)%QM_ROUNDTO)?((s)-QM_ROUNDTO)/QM_ROUNDTO*QM_ROUNDTO:(s))
*/



	/* finds the hash value for s, s=QM_ROUNDTO multiple*/
#define GET_HASH(s)   ( ((unsigned long)(s)<=Q_MALLOC_OPTIMIZE)?\
							(unsigned long)(s)/QM_ROUNDTO: \
							Q_MALLOC_OPTIMIZE/QM_ROUNDTO+big_hash_idx((s))- \
								Q_MALLOC_OPTIMIZE_FACTOR+1 )

#define UN_HASH(h)	( ((unsigned long)(h)<=(Q_MALLOC_OPTIMIZE/QM_ROUNDTO))?\
							(unsigned long)(h)*QM_ROUNDTO: \
							1UL<<((h)-Q_MALLOC_OPTIMIZE/QM_ROUNDTO+\
								Q_MALLOC_OPTIMIZE_FACTOR-1)\
					)

/* mark/test used/unused frags */
#define FRAG_MARK_USED(f)
#define FRAG_CLEAR_USED(f)
#define FRAG_WAS_USED(f)   (1)

/* other frag related defines:
 * MEM_COALESCE_FRAGS
 */

/* computes hash number for big buckets*/
inline static unsigned long big_hash_idx(unsigned long s)
{
	int idx;
	/* s is rounded => s = k*2^n (QM_ROUNDTO=2^n)
	 * index= i such that 2^i > s >= 2^(i-1)
	 *
	 * => index = number of the first non null bit in s*/
	idx=sizeof(long)*8-1;
	for (; !(s&(1UL<<(sizeof(long)*8-1))) ; s<<=1, idx--);
	return idx;
}


#ifdef DBG_MALLOC

#ifdef __CPU_x86_64
#define ST_CHECK_PATTERN   0xf0f0f0f0f0f0f0f0
#define END_CHECK_PATTERN1 0xc0c0c0c0c0c0c0c0
#define END_CHECK_PATTERN2 0xabcdefedabcdefed
#else
#warning "assuming sizeof(long) = 4"
#define ST_CHECK_PATTERN   0xf0f0f0f0
#define END_CHECK_PATTERN1 0xc0c0c0c0
#define END_CHECK_PATTERN2 0xabcdefed
#endif

static  void qm_debug_frag(struct qm_block *qm, struct qm_frag *f)
{
	if (f->check!=ST_CHECK_PATTERN){
		LM_CRIT("qm_*: fragm. %p (address %p) "
				"beginning overwritten(%lx)!\n",
				f, (char*)f+sizeof(struct qm_frag),
				f->check);
		abort();
	};
	if ((FRAG_END(f)->check1!=END_CHECK_PATTERN1)||
		(FRAG_END(f)->check2!=END_CHECK_PATTERN2)){
		LM_CRIT("qm_*: fragm. %p (address %p)"
					" end overwritten(%lx, %lx)!\n",
				f, (char*)f+sizeof(struct qm_frag),
				FRAG_END(f)->check1, FRAG_END(f)->check2);
		abort();
	}
	if ((f>qm->first_frag)&&
			((PREV_FRAG_END(f)->check1!=END_CHECK_PATTERN1) ||
				(PREV_FRAG_END(f)->check2!=END_CHECK_PATTERN2) ) ){
		LM_CRIT(" qm_*: prev. fragm. tail overwritten(%lx, %lx)[%p:%p] (%s, %s:%ld)!\n",
				PREV_FRAG_END(f)->check1, PREV_FRAG_END(f)->check2, f,
				(char*)f+sizeof(struct qm_frag), FRAG_PREV(f)->func,
				FRAG_PREV(f)->file,FRAG_PREV(f)->line);
		abort();
	}
}
#endif

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
unsigned long qm_stats_get_index(void *ptr) {
	return !ptr ? GROUP_IDX_INVALID : QM_FRAG(ptr)->statistic_index;
}

void qm_stats_set_index(void *ptr, unsigned long idx) {
	if (!ptr)
		return;

	QM_FRAG(ptr)->statistic_index = idx;
}
#endif

static inline void qm_insert_free(struct qm_block *qm, struct qm_frag *frag)
{
	struct qm_frag *f;
	struct qm_frag *prev;
	int hash;

	hash=GET_HASH(frag->size);
	for(f=qm->free_hash[hash].head.u.nxt_free; f!=&(qm->free_hash[hash].head);
			f=f->u.nxt_free){
		if (frag->size <= f->size) break;
	}
	/*insert it here*/
	prev=FRAG_END(f)->prev_free;
	prev->u.nxt_free=frag;
	FRAG_END(frag)->prev_free=prev;
	frag->u.nxt_free=f;
	FRAG_END(f)->prev_free=frag;
	qm->free_hash[hash].no++;

	qm->real_used-=frag->size;
#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->used-=frag->size;
#endif
}


/* init malloc and return a qm_block*/
struct qm_block *qm_malloc_init(char *address, unsigned long size, char *name)
{
	char *start;
	char *end;
	struct qm_block *qm;
	unsigned long init_overhead;
	int h;

	/* make address and size multiple of 8*/
	start=(char*)ROUNDUP((unsigned long) address);
	LM_DBG("QM_OPTIMIZE=%lu, /ROUNDTO=%lu, %lu-bytes aligned\n",
			Q_MALLOC_OPTIMIZE, Q_MALLOC_OPTIMIZE/QM_ROUNDTO,
			(unsigned long)QM_ROUNDTO);
	LM_DBG("QM_HASH_SIZE=%lu, qm_block size=%zu, frag_size=%zu\n",
			QM_HASH_SIZE, sizeof(struct qm_block), FRAG_OVERHEAD);
	LM_DBG("params (%p, %lu), start=%p\n", address, size, start);
	if (size<start-address) return 0;
	size-=(start-address);
	if (size <(MIN_FRAG_SIZE+FRAG_OVERHEAD)) return 0;
	size=ROUNDDOWN(size);

	init_overhead=ROUNDUP(sizeof(struct qm_block))+sizeof(struct qm_frag)+
		sizeof(struct qm_frag_end);
	LM_DBG("size= %lu, init_overhead=%lu\n", size, init_overhead);

	if (size < init_overhead)
	{
		/* not enough mem to create our control structures !!!*/
		return 0;
	}
	end=start+size;
	qm=(struct qm_block*)start;
	memset(qm, 0, sizeof(struct qm_block));
	qm->name=name;
	qm->size=size;
	qm->used=size-init_overhead;
	qm->fragments = 0;

	qm->real_used=size;
	qm->max_real_used = 0;
	size-=init_overhead;

	qm->first_frag=(struct qm_frag*)(start+ROUNDUP(sizeof(struct qm_block)));
	qm->last_frag_end=(struct qm_frag_end*)(end-sizeof(struct qm_frag_end));
	/* init initial fragment*/
	qm->first_frag->size=size;
	qm->last_frag_end->size=size;

#ifdef DBG_MALLOC
	qm->first_frag->check=ST_CHECK_PATTERN;
	qm->last_frag_end->check1=END_CHECK_PATTERN1;
	qm->last_frag_end->check2=END_CHECK_PATTERN2;
#endif
	/* init free_hash* */
	for (h=0; h<QM_HASH_SIZE;h++){
		qm->free_hash[h].head.u.nxt_free=&(qm->free_hash[h].head);
		qm->free_hash[h].tail.prev_free=&(qm->free_hash[h].head);
		qm->free_hash[h].head.size=0;
		qm->free_hash[h].tail.size=0;
	}

	/* link initial fragment into the free list*/

	qm_insert_free(qm, qm->first_frag);

	/*qm->first_frag->u.nxt_free=&(qm->free_lst);
	  qm->last_frag_end->prev_free=&(qm->free_lst);
	*/

	return qm;
}



static inline void qm_detach_free(struct qm_block *qm, struct qm_frag *frag)
{
	struct qm_frag *prev;
	struct qm_frag *next;

	prev=FRAG_END(frag)->prev_free;
	next=frag->u.nxt_free;
	prev->u.nxt_free=next;
	FRAG_END(next)->prev_free=prev;

	qm->real_used+=frag->size;
#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->used+=frag->size;
#endif
}



#ifdef DBG_MALLOC
static inline struct qm_frag *qm_find_free(struct qm_block *qm,
											unsigned long size,
											int *h,
											unsigned int *count)
#else
static inline struct qm_frag *qm_find_free(struct qm_block *qm,
											unsigned long size,
											int *h)
#endif
{
	int hash;
	struct qm_frag *f;

	for (hash=GET_HASH(size); hash<QM_HASH_SIZE; hash++){
		for (f=qm->free_hash[hash].head.u.nxt_free;
					f!=&(qm->free_hash[hash].head); f=f->u.nxt_free){
#ifdef DBG_MALLOC
			*count+=1; /* *count++ generates a warning with gcc 2.9* -Wall */
#endif
			if (f->size>=size){ *h=hash; return f; }
		}
	/*try in a bigger bucket*/
	}
	/* not found */
	return 0;
}

#include "q_malloc_dyn.h"

#if !defined INLINE_ALLOC && defined DBG_MALLOC
#undef DBG_MALLOC
#include "q_malloc_dyn.h"
#define DBG_MALLOC
#endif

#ifdef SHM_EXTRA_STATS
void qm_stats_core_init(struct qm_block *qm, int core_index)
{
	struct qm_frag *f;

	for (f=qm->first_frag; (char*)f<(char*)qm->last_frag_end; f=FRAG_NEXT(f))
		if (!f->u.is_free)
			f->statistic_index = core_index;
}
#endif



/* fills a malloc info structure with info about the block
 * if a parameter is not supported, it will be filled with 0 */
void qm_info(struct qm_block *qm, struct mem_info *info)
{
	int r;
	long total_frags;

	total_frags=0;
	memset(info,0, sizeof(*info));
	info->total_size=qm->size;
	info->min_frag=MIN_FRAG_SIZE;
	info->free=qm->size-qm->real_used;
	info->used=qm->used;
	info->real_used=qm->real_used;
	info->max_used=qm->max_real_used;
	for(r=0;r<QM_HASH_SIZE; r++){
		total_frags+=qm->free_hash[r].no;
	}
	info->total_frags=total_frags;
}

#ifdef DBG_MALLOC
int qm_mem_check(struct qm_block *qm)
{
	struct qm_frag *f;
	int i = 0;

	for (f = qm->first_frag; (char *)f < (char *)qm->last_frag_end;
	     f = FRAG_NEXT(f), i++) {

		qm_debug_frag(qm, f);
	}

	LM_DBG("fragments: %d\n", i);

	return i;
}
#endif


#endif
