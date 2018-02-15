/*
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
 *              created by andrei
 *  2003-07-06  added fm_realloc (andrei)
 *  2004-07-19  fragments book keeping code and support for 64 bits
 *               memory blocks (64 bits machine & size >=2^32)
 *              GET_HASH s/</<=/ (avoids waste of 1 hash cell)   (andrei)
 *  2004-11-10  support for > 4Gb mem., switched to long (andrei)
 *  2005-03-02  added fm_info() (andrei)
 *  2005-12-12  fixed realloc shrink real_used accounting (andrei)
 *              fixed initial size (andrei)
 */


#if !(defined VQ_MALLOC) && !defined(QM_MALLOC) && !(defined HP_MALLOC) && \
	(defined F_MALLOC)

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "f_malloc.h"
#include "common.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

/*useful macros*/

#define max(a,b) ( (a)>(b)?(a):(b))

#define FRAG_NEXT(f) \
	((struct fm_frag*)((char*)(f)+sizeof(struct fm_frag)+(f)->size ))




/* ROUNDTO= 2^k so the following works */
#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

/*
 #define ROUNDUP(s)		(((s)%ROUNDTO)?((s)+ROUNDTO)/ROUNDTO*ROUNDTO:(s))
 #define ROUNDDOWN(s)	(((s)%ROUNDTO)?((s)-ROUNDTO)/ROUNDTO*ROUNDTO:(s))
*/



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

#define MEM_FRAG_AVOIDANCE


#define F_MALLOC_LARGE_LIMIT    F_MALLOC_OPTIMIZE
#define F_MALLOC_DEFRAG_LIMIT (F_MALLOC_LARGE_LIMIT * 5)
#define F_MALLOC_DEFRAG_PERCENT 5

unsigned long frag_size(void* p){
	if(!p)
		return 0;
	return (((struct fm_frag*) ((char*)p-sizeof(struct fm_frag)))->size);
}

static inline void free_minus(struct fm_block* qm, unsigned long size )
{

	if( size > F_MALLOC_LARGE_LIMIT )
		qm->large_space -= size;

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->real_used+=size;
	qm->used+=size;
	#endif
}


static inline void free_plus(struct fm_block* qm, unsigned long size )
{

	if( size > F_MALLOC_LARGE_LIMIT )
		qm->large_space += size;

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->real_used-=size;
	qm->used-=size;
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


#ifdef DBG_MALLOC
#define ST_CHECK_PATTERN   0xf0f0f0f0
#define END_CHECK_PATTERN1 0xc0c0c0c0
#define END_CHECK_PATTERN2 0xabcdefed
#endif

#ifdef SHM_EXTRA_STATS
void set_stat_index (void *ptr, unsigned long idx) {
	struct fm_frag *f;
	f = (struct fm_frag *)((char*)ptr - sizeof(struct fm_frag));
	f->statistic_index = idx;
}

unsigned long get_stat_index(void *ptr) {
	struct fm_frag *f;
	f = (struct fm_frag *)((char*)ptr - sizeof(struct fm_frag));
	return f->statistic_index;
}
#endif


static inline void fm_insert_free(struct fm_block* qm, struct fm_frag* frag)
{
	struct fm_frag** f;
	int hash;

	hash=GET_HASH(frag->size);
	f=&(qm->free_hash[hash].first);
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

#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	/* mark fragment as "free" */
	frag->is_free = 1;
#endif

	*f=frag;
	qm->free_hash[hash].no++;

	free_plus(qm, frag->size);
}

static inline void fm_remove_free(struct fm_block* qm, struct fm_frag* n)
{
	struct fm_frag** pf;
	int hash;

	pf = n->prev;
	hash = GET_HASH( n->size );

	/* detach */
	*pf=n->u.nxt_free;

	if( n->u.nxt_free )
		n->u.nxt_free->prev = pf;

	qm->free_hash[hash].no--;

	n->prev = NULL;

	free_minus(qm , n->size);

};


 /* size should be already rounded-up */
static inline
#ifdef DBG_MALLOC
void fm_split_frag(struct fm_block* qm, struct fm_frag* frag,
					unsigned long size,
					const char* file, const char* func, unsigned int line)
#else
void fm_split_frag(struct fm_block* qm, struct fm_frag* frag,
					unsigned long size)
#endif
{
	unsigned long rest;
	struct fm_frag* n;

	rest=frag->size-size;
	#ifdef MEM_FRAG_AVOIDANCE
	if ((rest> (FRAG_OVERHEAD+F_MALLOC_OPTIMIZE))||
		(rest>=(FRAG_OVERHEAD+size))){ /* the residue fragm. is big enough*/
	#else
	if (rest>(FRAG_OVERHEAD+MIN_FRAG_SIZE)){
	#endif
		frag->size=size;
		/*split the fragment*/
		n=FRAG_NEXT(frag);
		n->size=rest-FRAG_OVERHEAD;

		/*
		 * The real used memory does not increase, as the frag memory is not
		 * freed from real_used. On the other hand, the used size should
		 * decrease, because the new fragment is not "useful data" - razvanc

		#if defined(DBG_MALLOC) || defined(STATISTICS)
		qm->real_used+=FRAG_OVERHEAD;
		#endif

		 */
		#if defined(DBG_MALLOC) || defined(STATISTICS)
		qm->used-=FRAG_OVERHEAD;
		#endif

		#ifdef DBG_MALLOC
		/* frag created by malloc, mark it*/
		n->file=file;
		n->func="frag. from fm_malloc";
		n->line=line;
		n->check=ST_CHECK_PATTERN;
		#endif
		/* reinsert n in free list*/
		fm_insert_free(qm, n);
	}else{
		/* we cannot split this fragment any more => alloc all of it*/
	}
}



/* init malloc and return a fm_block*/
struct fm_block* fm_malloc_init(char* address, unsigned long size, char *name)

{
	char* start;
	char* end;
	struct fm_block* qm;
	unsigned long init_overhead;

	/* make address and size multiple of 8*/
	start=(char*)ROUNDUP((unsigned long) address);
	LM_DBG("F_OPTIMIZE=%lu, /ROUNDTO=%lu\n",
			F_MALLOC_OPTIMIZE, F_MALLOC_OPTIMIZE/ROUNDTO);
	LM_DBG("F_HASH_SIZE=%lu, fm_block size=%lu\n",
			F_HASH_SIZE, (long)sizeof(struct fm_block));
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
	qm=(struct fm_block*)start;
	memset(qm, 0, sizeof(struct fm_block));
	qm->name = name;
	qm->size=size;

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->used=size-init_overhead;
	qm->real_used=size;
	qm->max_real_used=init_overhead;
	qm->fragments = 0;
	#endif

	qm->first_frag=(struct fm_frag*)(start+ROUNDUP(sizeof(struct fm_block)));
	qm->last_frag=(struct fm_frag*)(end-sizeof(struct fm_frag));
	/* init initial fragment*/
	qm->first_frag->size=size-init_overhead;
	qm->last_frag->size=0;

	qm->last_frag->prev=NULL;
	qm->first_frag->prev=NULL;

	#ifdef DBG_MALLOC
	qm->first_frag->check=ST_CHECK_PATTERN;
	qm->last_frag->check=END_CHECK_PATTERN1;
	#endif

	/* link initial fragment into the free list*/

	qm->large_space = 0;
	qm->large_limit = qm->size / 100 * F_MALLOC_DEFRAG_PERCENT;

	if( qm->large_limit < F_MALLOC_DEFRAG_LIMIT )
		qm->large_limit = F_MALLOC_DEFRAG_LIMIT;

	fm_insert_free(qm, qm->first_frag);


	return qm;
}



#ifdef DBG_MALLOC
void* fm_malloc(struct fm_block* qm, unsigned long size,
					const char* file, const char* func, unsigned int line)
#else
void* fm_malloc(struct fm_block* qm, unsigned long size)
#endif
{
	struct fm_frag* frag,*n;
	unsigned int hash;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_malloc(%lu), called from %s: %s(%d)\n", qm->name, size, file, func,
			line);
	#endif

	/*size must be a multiple of 8*/
	size=ROUNDUP(size);

	/*search for a suitable free frag*/

	for(hash=GET_HASH(size);hash<F_HASH_SIZE;hash++){
		frag=qm->free_hash[hash].first;
		for( ; frag; frag = frag->u.nxt_free )
			if ( frag->size >= size ) goto found;
		/* try in a bigger bucket */
	}
	/* not found, bad! */

#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_ERR(oom_errorf, qm->name, qm->size - qm->real_used, size,
			qm->name[0] == 'p' ? "M" : "m");
	LM_INFO("attempting defragmentation...\n");
#else
	LM_ERR(oom_nostats_errorf, qm->name, size, qm->name[0] == 'p' ? "M" : "m");
	LM_INFO("attempting defragmentation...\n");
#endif

	for( frag = qm->first_frag; (char*)frag < (char*)qm->last_frag;  )
	{
		n = FRAG_NEXT(frag);

		if ( ((char*)n < (char*)qm->last_frag) &&  n->prev && frag->prev )
		{
			/* detach frag*/
			fm_remove_free(qm, frag);

			do
			{
				fm_remove_free(qm, n);
				frag->size += n->size + FRAG_OVERHEAD;

				#if defined(DBG_MALLOC) || defined(STATISTICS)
				//qm->real_used -= FRAG_OVERHEAD;
				qm->used += FRAG_OVERHEAD;
				#endif

				if( frag->size >size ) {
					#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
					/* mark it as "busy" */
					frag->is_free = 0;
					#endif

					goto solved;
				}

				n = FRAG_NEXT(frag);
			}
			while
			( ((char*)n < (char*)qm->last_frag) &&  n->prev);

			fm_insert_free(qm,frag);

		}

		frag = n;
	}

	LM_INFO("unable to alloc a big enough fragment!\n");
	pkg_threshold_check();
	return 0;


found:
	/* we found it!*/

	fm_remove_free(qm,frag);

	#if (defined DBG_MALLOC) || (defined SHM_EXTRA_STATS)
	/* mark it as "busy" */
	frag->is_free = 0;
	#endif

	/*see if we'll use full frag, or we'll split it in 2*/

	#ifdef DBG_MALLOC
	fm_split_frag(qm, frag, size, file, func, line);

	frag->file=file;
	frag->func=func;
	frag->line=line;
	frag->check=ST_CHECK_PATTERN;
	LM_GEN1(memlog, "%s_malloc(%lu), returns address %p\n", qm->name, size,
		(char*)frag+sizeof(struct fm_frag));
	#else
	fm_split_frag(qm, frag, size);
	#endif

solved:

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	if (qm->max_real_used<qm->real_used)
		qm->max_real_used=qm->real_used;
	qm->fragments += 1;
	#endif

	pkg_threshold_check();
	return (char*)frag+sizeof(struct fm_frag);
}



#ifdef DBG_MALLOC
void fm_free(struct fm_block* qm, void* p, const char* file, const char* func,
				unsigned int line)
#else
void fm_free(struct fm_block* qm, void* p)
#endif
{
	struct fm_frag* f,*n;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_free(%p), called from %s: %s(%d)\n", qm->name, p, file,
	        func, line);
	if (p && (p > (void *)qm->last_frag || p < (void *)qm->first_frag)) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (p==0) {
		LM_GEN1(memlog, "free(0) called\n");
		return;
	}
	f=(struct fm_frag*) ((char*)p-sizeof(struct fm_frag));

#ifndef F_MALLOC_OPTIMIZATIONS
	if (f->prev) {
	#ifdef DBG_MALLOC
		LM_CRIT("freeing already freed pointer (%p), first free: "
		        "%s: %s(%ld) - aborting\n", p, f->file, f->func, f->line);
		abort();
	#else
		LM_CRIT("freeing already freed pointer (%p) - skipping!\n", p);
		return;
	#endif
	}
#endif
	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "freeing block alloc'ed from %s: %s(%ld)\n", f->file, f->func,
			f->line);
	#endif

join:

	if( qm->large_limit < qm->large_space )
		goto no_join;

	n = FRAG_NEXT(f);

	if (((char*)n < (char*)qm->last_frag) &&  n->prev )
	{

		fm_remove_free(qm, n);
		/* join */
		f->size += n->size + FRAG_OVERHEAD;

		#if defined(DBG_MALLOC) || defined(STATISTICS)
		//qm->real_used -= FRAG_OVERHEAD;
		qm->used += FRAG_OVERHEAD;
		#endif

		goto join;
	}

no_join:

	fm_insert_free(qm, f);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->fragments -= 1;
#endif
	pkg_threshold_check();
}


#ifdef DBG_MALLOC
void* fm_realloc(struct fm_block* qm, void* p, unsigned long size,
					const char* file, const char* func, unsigned int line)
#else
void* fm_realloc(struct fm_block* qm, void* p, unsigned long size)
#endif
{
	struct fm_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct fm_frag *n;
	void *ptr;


	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_realloc(%p, %lu->%lu), called from %s: %s(%d)\n", qm->name,
	        p, p ? ((struct fm_frag*)((char *)p - sizeof(struct fm_frag)))->size:0,
	        size, file, func, line);
	if ((p)&&(p>(void*)qm->last_frag || p<(void*)qm->first_frag)){
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (size==0) {
		if (p)
	#ifdef DBG_MALLOC
			fm_free(qm, p, file, func, line);
	#else
			fm_free(qm, p);
	#endif
		pkg_threshold_check();
		return 0;
	}
	if (p==0)
	#ifdef DBG_MALLOC
		return fm_malloc(qm, size, file, func, line);
	#else
		return fm_malloc(qm, size);
	#endif
	f=(struct fm_frag*) ((char*)p-sizeof(struct fm_frag));
	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	#endif
	size=ROUNDUP(size);
	orig_size=f->size;
	if (f->size > size){
		/* shrink */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "shrinking from %lu to %lu\n", f->size, size);
		fm_split_frag(qm, f, size, file, "frag. from fm_realloc", line);
		#else
		fm_split_frag(qm, f, size);
		#endif

	}else if (f->size<size){
		/* grow */

		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "growing from %lu to %lu\n", f->size, size);
		#endif

		diff=size-f->size;
		n=FRAG_NEXT(f);

		if (((char*)n < (char*)qm->last_frag) &&  n->prev &&
		 ((n->size+FRAG_OVERHEAD)>=diff)){

			fm_remove_free(qm,n);
			/* join */
			f->size += n->size + FRAG_OVERHEAD;

			#if defined(DBG_MALLOC) || defined(STATISTICS)
			//qm->real_used -= FRAG_OVERHEAD;
			qm->used += FRAG_OVERHEAD;
			#endif

			/* split it if necessary */
			if (f->size > size){
				#ifdef DBG_MALLOC
				fm_split_frag(qm, f, size, file, "fragm. from fm_realloc",
						line);
				#else
				fm_split_frag(qm, f, size);
				#endif
			}
		}else{
			/* could not join => realloc */
			#ifdef DBG_MALLOC
			ptr=fm_malloc(qm, size, file, func, line);
			#else
			ptr = fm_malloc(qm, size);
			#endif
			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);
				#ifdef DBG_MALLOC
				fm_free(qm, p, file, func, line);
				#else
				fm_free(qm, p);
				#endif
			}
			p = ptr;
		}
	}else{
		/* do nothing */
	#ifdef DBG_MALLOC
		LM_GEN1(memlog, "doing nothing, same size: %lu - %lu\n", f->size, size);
	#endif
	}
	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "returning %p\n", p);
	#endif

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	if (qm->max_real_used<qm->real_used)
		qm->max_real_used=qm->real_used;
	#endif

	pkg_threshold_check();
	return p;
}


#ifdef SHM_EXTRA_STATS
void set_indexes(int core_index) {

	struct fm_frag* f;
	for (f=shm_block->first_frag; (char*)f<(char*)shm_block->last_frag; f=FRAG_NEXT(f))
		if (!f->is_free)
			f->statistic_index = core_index;
}

#endif

void fm_status(struct fm_block* qm)
{
	struct fm_frag* f;
	unsigned int i,j;
	unsigned int h;
	int unused;
	unsigned long size;

#ifdef DBG_MALLOC
	mem_dbg_htable_t allocd;
	struct mem_dbg_entry *it;
#endif

	LM_GEN1(memdump, "fm_status (%p):\n", qm);
	if (!qm) return;

	LM_GEN1(memdump, " heap size= %ld\n", qm->size);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_GEN1(memdump, " used= %lu, used+overhead=%lu, free=%lu\n",
			qm->used, qm->real_used, qm->size-qm->used);
	LM_GEN1(memdump, " max used (+overhead)= %lu\n", qm->max_real_used);
#endif

#if defined(DBG_MALLOC)
	dbg_ht_init(allocd);

	for (f=qm->first_frag; (char*)f<(char*)qm->last_frag; f=FRAG_NEXT(f))
		if (!f->is_free)
			if (dbg_ht_update(allocd, f->file, f->func, f->line, f->size) < 0) {
				LM_ERR("Unable to update alloc'ed. memory summary\n");
				dbg_ht_free(allocd);
				return;
			}

	LM_GEN1(memdump, " dumping summary of all alloc'ed. fragments:\n");
	for(i=0; i < DBG_HASH_SIZE; i++) {
		it = allocd[i];
		while (it) {
			LM_GEN1(memdump, " %10lu : %lu x [%s: %s, line %lu]\n",
				it->size, it->no_fragments, it->file, it->func, it->line);
			it = it->next;
		}
	}

	dbg_ht_free(allocd);
#endif

	LM_GEN1(memdump, "dumping free list:\n");
	for(h=0,i=0,size=0;h<F_HASH_SIZE;h++){
		unused=0;
		for (f=qm->free_hash[h].first,j=0; f;
				size+=f->size,f=f->u.nxt_free,i++,j++){ }
		if (j) LM_GEN1(memdump,"hash = %3d fragments no.: %5d, unused: %5d\n\t\t"
							" bucket size: %9lu - %9lu (first %9lu)\n",
							h, j, unused, UN_HASH(h),
						((h<=F_MALLOC_OPTIMIZE/ROUNDTO)?1:2)* UN_HASH(h),
							qm->free_hash[h].first->size
				);
		if (j!=qm->free_hash[h].no){
			LM_CRIT("different free frag. count: %d!=%ld"
					" for hash %3d\n", j, qm->free_hash[h].no, h);
		}

	}
	LM_GEN1(memdump, "TOTAL: %6d free fragments = %6lu free bytes\n", i, size);
	LM_GEN1(memdump, "TOTAL: %ld large bytes\n", qm->large_space );
	LM_GEN1(memdump, "TOTAL: %u overhead\n", (unsigned int)FRAG_OVERHEAD );
	LM_GEN1(memdump, "-----------------------------\n");
}



/* fills a malloc info structure with info about the block
 * if a parameter is not supported, it will be filled with 0 */
void fm_info(struct fm_block* qm, struct mem_info* info)
{
	unsigned int r;
	long total_frags;
#if !defined(DBG_MALLOC) && !defined(STATISTICS)
	struct fm_frag* f;
#endif

	memset(info,0, sizeof(*info));
	total_frags=0;
	info->total_size=qm->size;
	info->min_frag=MIN_FRAG_SIZE;
#if defined(DBG_MALLOC) || defined(STATISTICS)
	info->free=qm->size-qm->real_used;
	info->used=qm->used;
	info->real_used=qm->real_used;
	info->max_used=qm->max_real_used;
	for(r=0;r<F_HASH_SIZE; r++){
		total_frags+=qm->free_hash[r].no;
	}
#else
	/* we'll have to compute it all */
	for (r=0; r<=F_MALLOC_OPTIMIZE/ROUNDTO; r++){
		info->free+=qm->free_hash[r].no*UN_HASH(r);
		total_frags+=qm->free_hash[r].no;
	}
	for(;r<F_HASH_SIZE; r++){
		total_frags+=qm->free_hash[r].no;
		for(f=qm->free_hash[r].first;f;f=f->u.nxt_free){
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
