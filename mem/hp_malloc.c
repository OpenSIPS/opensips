/**
 * truly parallel memory allocator for high-performance environments
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-01-19 initial version (liviu)
 */

/**
 * Note on coding style:
 *
 * although there is some duplicate code, it is the best way to go!
 * (minimum number of parameters, no additional jmp instructions) --liviu
 */

#if !defined(q_malloc) && !(defined VQ_MALLOC)  && !(defined F_MALLOC) && \
	(defined HP_MALLOC)

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "hp_malloc.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"
#include "../locking.h"

extern unsigned long *mem_hash_usage;

/*useful macros*/

#define max(a,b) ( (a)>(b)?(a):(b))

#define FRAG_NEXT(f) \
	((struct fm_frag*)((char*)(f)+sizeof(struct fm_frag)+(f)->size ))

#define FRAG_OVERHEAD	(sizeof(struct fm_frag))


/* ROUNDTO= 2^k so the following works */
#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

/*
 #define ROUNDUP(s)		(((s)%ROUNDTO)?((s)+ROUNDTO)/ROUNDTO*ROUNDTO:(s))
 #define ROUNDDOWN(s)	(((s)%ROUNDTO)?((s)-ROUNDTO)/ROUNDTO*ROUNDTO:(s))
*/

#define SHM_LOCK(i) lock_get(&mem_lock[i])
#define SHM_UNLOCK(i) lock_release(&mem_lock[i])

#define MEM_FRAG_AVOIDANCE

#define F_MALLOC_LARGE_LIMIT    F_MALLOC_OPTIMIZE
#define F_MALLOC_DEFRAG_LIMIT (F_MALLOC_LARGE_LIMIT * 5)
#define F_MALLOC_DEFRAG_PERCENT 5

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


#ifdef DBG_F_MALLOC
#define ST_CHECK_PATTERN   0xf0f0f0f0
#define END_CHECK_PATTERN1 0xc0c0c0c0
#define END_CHECK_PATTERN2 0xabcdefed
#endif

static inline void fm_insert_free(struct fm_block* qm, struct fm_frag* frag)
{
	struct fm_frag** f;
	unsigned int hash;

	hash=GET_HASH_RR(qm, frag->size);
	f=&(qm->free_hash[hash].first);

	if (frag->size > F_MALLOC_OPTIMIZE){ /* because of '<=' in GET_HASH,
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

	#if defined(DBG_F_MALLOC) || defined(STATISTICS)
	qm->free_hash[hash].no++;
	#endif
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

	n->prev = NULL;

	#if defined(DBG_F_MALLOC) || defined(STATISTICS)
	qm->free_hash[hash].no--;
	#endif
};



void fm_split_frag_unsafe(struct fm_block* qm, struct fm_frag* frag,
                          unsigned long size)
{
	unsigned long rest;
	struct fm_frag* n;

	rest = frag->size - size;

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

		#if defined(DBG_F_MALLOC) || defined(STATISTICS)
		qm->real_used+=FRAG_OVERHEAD;
		#endif

		 */

		#ifdef DBG_F_MALLOC
		/* frag created by malloc, mark it*/
		n->file=file;
		n->func="frag. from fm_malloc";
		n->line=line;
		n->check=ST_CHECK_PATTERN;
		#endif

		fm_insert_free(qm, n);
	}

	/* we cannot split this fragment any more => alloc all of it */
}

 /* size should be already rounded-up */
static inline
#ifdef DBG_F_MALLOC 
void fm_split_frag(struct fm_block* qm, struct fm_frag* frag,
					unsigned long size,
					const char* file, const char* func, unsigned int line)
#else
void fm_split_frag(struct fm_block* qm, struct fm_frag* frag,
					unsigned long size, unsigned int old_hash)
#endif
{
	unsigned long rest, hash;
	struct fm_frag* n;

	rest = frag->size - size;

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

		#if defined(DBG_F_MALLOC) || defined(STATISTICS)
		qm->real_used+=FRAG_OVERHEAD;
		#endif

		 */

		#ifdef DBG_F_MALLOC
		/* frag created by malloc, mark it*/
		n->file=file;
		n->func="frag. from fm_malloc";
		n->line=line;
		n->check=ST_CHECK_PATTERN;
		#endif

		/* insert the newly obtained fm_frag in its free list */
		hash = PEEK_HASH_RR(qm, n->size);

		if (hash != old_hash)
			SHM_LOCK(hash);

		fm_insert_free(qm, n);

		if (hash != old_hash)
			SHM_UNLOCK(hash);
	}

	/* we cannot split this fragment any more => alloc all of it */
}

void fm_update_mem_pattern_file(void)
{
	int i;
	FILE *f;
	unsigned long long sum = 0;
	double verification = 0;

	f = fopen(mem_warming_pattern_file, "w+");
	if (!f) {
		LM_ERR("failed to open pattern file %s for writing: %d - %s\n",
		        mem_warming_pattern_file, errno, strerror(errno));
		return;
	}

	if (fprintf(f, "%lu %lu\n", ROUNDTO, F_HASH_SIZE) < 0)
		goto write_error;

	/* first compute sum of all malloc requests since startup */
	for (i = 0; i < F_MALLOC_OPTIMIZE / ROUNDTO; i++)
		sum += mem_hash_usage[i] * (i * ROUNDTO + FRAG_OVERHEAD);

	LM_DBG("mem warming hash sum: %llu\n", sum);

	/* save the usage rate of each bucket to the memory pattern file */
	for (i = 0; i < F_MALLOC_OPTIMIZE / ROUNDTO; i++) {
		LM_DBG("[%d] %lf %.8lf\n", i, (double)mem_hash_usage[i], (double)mem_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD));
		verification += (double)mem_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD);

		if (fprintf(f, "%.12lf ",
		            (double)mem_hash_usage[i] / sum * (i * ROUNDTO + FRAG_OVERHEAD)) < 0)
			goto write_error;

		if (i % 10 == 9)
			fprintf(f, "\n");
	}

	LM_INFO("verification: %lf\n", verification);

	fclose(f);
	return;

write_error:
	LM_ERR("failed to write to pattern file\n");
	fclose(f);
}

/**
 * TODO: comments
 */
int fm_mem_warming(struct fm_block *qm)
{
	struct size_fraction {
		int hash_index;

		double amount;
		unsigned long fragments;

		struct size_fraction *next;
	};

	struct size_fraction *sf, *it, *sorted_sf = NULL;
	FILE *f;
	size_t rc;
	unsigned long roundto, hash_size;
	long long bucket_mem;
	int i, c = 0;
	unsigned int current_frag_size;
	struct fm_frag *big_frag;
	unsigned int optimized_buckets;

	f = fopen(mem_warming_pattern_file, "r");
	if (!f) {
		LM_ERR("failed to open pattern file %s: %d - %s\n",
		        mem_warming_pattern_file, errno, strerror(errno));
		return -1;
	}

	rc = fscanf(f, "%lu %lu\n", &roundto, &hash_size);
	if (rc != 2) {
		LM_ERR("failed to read from %s: bad file format\n",
		        mem_warming_pattern_file);
		goto out;
	}
	rc = 0;

	if (roundto != ROUNDTO || hash_size != F_HASH_SIZE) {
		LM_ERR("incompatible pattern file data: [F_HASH_SIZE: %lu-%lu] "
		       "[ROUNDTO: %lu-%lu]\n", hash_size, F_HASH_SIZE, roundto, ROUNDTO);
		rc = -1;
		goto out;
	}

	/* read bucket usage percentages and sort them by number of fragments */
	for (i = 0; i < LINEAR_HASH_SIZE; i++) {

		sf = malloc(sizeof *sf);
		if (!sf) {
			LM_INFO("malloc failed, skipping shm warming\n");
			rc = -1;
			goto out_free;
		}

		sf->hash_index = i;
		sf->next = NULL;

		if (fscanf(f, "%lf", &sf->amount) != 1) {
			LM_CRIT("%s appears to be corrupt. Please remove it first\n",
			         mem_warming_pattern_file);
			abort();
		}

		
		if (i == 0)
			sf->fragments = 0;
		else
			sf->fragments = sf->amount * qm->size / (ROUNDTO * i);

		if (!sorted_sf)
			sorted_sf = sf;
		else {
			for (it = sorted_sf;
			     it->next && it->next->fragments > sf->fragments;
				 it = it->next)
				;

			if (it->fragments < sf->fragments) {
				sf->next = sorted_sf;
				sorted_sf = sf;
			} else {
				sf->next = it->next;
				it->next = sf;
			}
		}
	}

	/* only optimize the configured number of buckets */
	optimized_buckets = (float)shm_hash_split_percentage / 100 * LINEAR_HASH_SIZE;

	LM_INFO("Optimizing %u / %lu mem buckets\n", optimized_buckets,
	         LINEAR_HASH_SIZE);

	sf = sorted_sf;
	for (i = 0; i < optimized_buckets; i++) {
		qm->free_hash[sf->hash_index].is_optimized = 1;
		sf = sf->next;
	}

	big_frag = qm->first_frag;

	/* populate each free hash bucket with proper number of fragments */
	for (sf = sorted_sf; sf; sf = sf->next) {
		LM_INFO("[%d] fraction: %.12lf total mem: %llu, %lu\n", sf->hash_index,
		         sf->amount, (unsigned long long) (sf->amount *
				 qm->size * mem_warming_percentage / 100),
				 ROUNDTO * sf->hash_index);

		current_frag_size = ROUNDTO * sf->hash_index;
		bucket_mem = sf->amount * qm->size * mem_warming_percentage / 100;

		/* create free fragments worth of 'bucket_mem' memory */
		while (bucket_mem >= FRAG_OVERHEAD + current_frag_size) {
			fm_remove_free(qm, big_frag);

			/* trim-insert operation on the big free fragment */
			fm_split_frag(qm, big_frag, current_frag_size, -1);

			/*
			 * "big_frag" now points to a smaller, free and detached frag.
			 *
			 * With optimized buckets, inserts will be automagically
			 * balanced within their dedicated hashes */
			fm_insert_free(qm, big_frag);

			big_frag = FRAG_NEXT(big_frag);

			bucket_mem -= FRAG_OVERHEAD + current_frag_size;

			if (c % 1000000 == 0)
				LM_INFO("%d| %lld %p\n", c, bucket_mem, big_frag);

			c++;
		}
	}

out_free:
	while (sorted_sf) {
		sf = sorted_sf;
		sorted_sf = sorted_sf->next;
		free(sf);
	}

out:
	fclose(f);
	return rc;
}

/* init malloc and return a fm_block*/
struct fm_block* fm_malloc_init(char* address, unsigned long size)
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
	qm->size=size;

	#if defined(DBG_F_MALLOC) || defined(STATISTICS)

	qm->used=size-init_overhead;
	qm->real_used=size;
	qm->max_real_used=init_overhead;
	#endif

	qm->first_frag=(struct fm_frag*)(start+ROUNDUP(sizeof(struct fm_block)));
	qm->last_frag=(struct fm_frag*)(end-sizeof(struct fm_frag));
	/* init initial fragment*/
	qm->first_frag->size=size-init_overhead;
	qm->last_frag->size=0;

	qm->last_frag->prev=NULL;
	qm->first_frag->prev=NULL;

	#ifdef DBG_F_MALLOC
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

void* fm_malloc_unsafe(struct fm_block* qm, unsigned long size)
{
	struct fm_frag* frag;
	unsigned int hash;

	#ifdef DBG_F_MALLOC
	LM_DBG("params (%p, %lu), called from %s: %s(%d)\n", qm, size, file, func,
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
	LM_CRIT("not enough memory, please increase the \"-m\" parameter!\n");
	abort();

found:
	/* we found it!*/
	
	fm_remove_free(qm,frag);
	
	/*see if we'll use full frag, or we'll split it in 2*/
	
	#ifdef DBG_F_MALLOC
	fm_split_frag_unsafe(qm, frag, size, file, func, line);

	frag->file=file;
	frag->func=func;
	frag->line=line;
	frag->check=ST_CHECK_PATTERN;
	LM_DBG("params(%p, %lu), returns address %p \n", qm, size,
		(char*)frag+sizeof(struct fm_frag));
	#else
	fm_split_frag_unsafe(qm, frag, size);
	#endif

	pkg_threshold_check();
	return (char*)frag+sizeof(struct fm_frag);
}

#ifdef DBG_F_MALLOC
void* fm_malloc(struct fm_block* qm, unsigned long size,
					const char* file, const char* func, unsigned int line)
#else
void* fm_malloc(struct fm_block* qm, unsigned long size)
#endif
{
	struct fm_frag* frag;
	unsigned int init_hash, hash, sec_hash;
	int i;

	#ifdef DBG_F_MALLOC
	LM_DBG("params (%p, %lu), called from %s: %s(%d)\n", qm, size, file, func,
			line);
	#endif

	/*size must be a multiple of 8*/
	size=ROUNDUP(size);

	/*search for a suitable free frag*/

	for (hash = GET_HASH(size), init_hash = hash; hash < F_HASH_SIZE; hash++) {
		if (!qm->free_hash[hash].is_optimized) {
			SHM_LOCK(hash);
			frag = qm->free_hash[hash].first;

			for (; frag; frag = frag->u.nxt_free)
				if (frag->size >= size)
					goto found;

			SHM_UNLOCK(hash);
		} else {
			/* optimized size. search through its own hash! */
			for (i = 0, sec_hash = F_HASH_SIZE +
			                       hash * shm_secondary_hash_size +
				                   optimized_get_indexes[hash];
				 i < shm_secondary_hash_size;
				 i++, sec_hash = (sec_hash + 1) % shm_secondary_hash_size) {

				SHM_LOCK(sec_hash);
				frag = qm->free_hash[sec_hash].first;
				for (; frag; frag = frag->u.nxt_free)
					if (frag->size >= size) {
						/* free fragments are detached in a simple round-robin manner */
						optimized_get_indexes[hash] =
						    (optimized_get_indexes[hash] + i + 1)
						     % shm_secondary_hash_size;
						hash = sec_hash;
						goto found;
					}

				SHM_UNLOCK(sec_hash);
			}
		}

		/* try in a bigger bucket */
	}

	/* not found, bad! */
	LM_CRIT("not enough memory, please increase the \"-m\" parameter!\n");
	abort();

found:
	/* we found it!*/
	
	fm_remove_free(qm,frag);
	
	/*see if we'll use full frag, or we'll split it in 2*/
	
	fm_split_frag(qm, frag, size, hash);

	SHM_UNLOCK(hash);

	/* ignore concurrency issues, simply obtaining an estimate is enough */
	mem_hash_usage[init_hash]++;

	pkg_threshold_check();
	return (char*)frag+sizeof(struct fm_frag);
}


void fm_free_unsafe(struct fm_block* qm, void* p)
{
	struct fm_frag* f,*n;
	
	#ifdef DBG_F_MALLOC
	LM_DBG("params(%p, %p), called from %s: %s(%d)\n", qm, p, file, func, line);
	if (p>(void*)qm->last_frag || p<(void*)qm->first_frag){
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (p==0) {
		LM_WARN("free(0) called\n");
		return;
	}
	f=(struct fm_frag*) ((char*)p-sizeof(struct fm_frag));
	
	#ifdef DBG_F_MALLOC
	LM_DBG("freeing block alloc'ed from %s: %s(%ld)\n", f->file, f->func,
			f->line);
	f->file=file;
	f->func=func;
	f->line=line;
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

		#if defined(DBG_F_MALLOC) || defined(STATISTICS)
		qm->real_used -= FRAG_OVERHEAD;
		#endif

		goto join;
	}

no_join:

	fm_insert_free(qm, f);
	pkg_threshold_check();
}


#ifdef DBG_F_MALLOC
void fm_free(struct fm_block* qm, void* p, const char* file, const char* func, 
				unsigned int line)
#else
void fm_free(struct fm_block* qm, void* p)
#endif
{
	struct fm_frag* f,*n;
	unsigned int hash;
	
	#ifdef DBG_F_MALLOC
	LM_DBG("params(%p, %p), called from %s: %s(%d)\n", qm, p, file, func, line);
	if (p>(void*)qm->last_frag || p<(void*)qm->first_frag){
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (p==0) {
		LM_WARN("free(0) called\n");
		return;
	}
	f=(struct fm_frag*) ((char*)p-sizeof(struct fm_frag));
	hash = PEEK_HASH_RR(qm, f->size);

	#ifdef DBG_F_MALLOC
	LM_DBG("freeing block alloc'ed from %s: %s(%ld)\n", f->file, f->func,
			f->line);
	f->file=file;
	f->func=func;
	f->line=line;
	#endif

	SHM_LOCK(hash);

join:
	if( qm->large_limit < qm->large_space )
		goto no_join;

	n = FRAG_NEXT(f);
	
	if (((char*)n < (char*)qm->last_frag) &&  n->prev )
	{

		fm_remove_free(qm, n);
		/* join */
		f->size += n->size + FRAG_OVERHEAD;

		#if defined(DBG_F_MALLOC) || defined(STATISTICS)
		qm->real_used -= FRAG_OVERHEAD;
		#endif

		goto join;
	}

no_join:

	fm_insert_free(qm, f);

	SHM_UNLOCK(hash);

	pkg_threshold_check();
}


void* fm_realloc_unsafe(struct fm_block* qm, void* p, unsigned long size)
{
	struct fm_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct fm_frag *n;
	void *ptr;
	
	#ifdef DBG_F_MALLOC
	LM_DBG("params(%p, %p, %lu), called from %s: %s(%d)\n", qm, p, size,
			file, func, line);
	if ((p)&&(p>(void*)qm->last_frag || p<(void*)qm->first_frag)){
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (size==0) {
		if (p)
	#ifdef DBG_F_MALLOC
			fm_free(qm, p, file, func, line);
	#else
			fm_free(qm, p);
	#endif
		pkg_threshold_check();
		return 0;
	}
	if (p==0)
	#ifdef DBG_F_MALLOC
		return fm_malloc(qm, size, file, func, line);
	#else
		return fm_malloc(qm, size);
	#endif
	f=(struct fm_frag*) ((char*)p-sizeof(struct fm_frag));
	#ifdef DBG_F_MALLOC
	LM_DBG("realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	#endif
	size=ROUNDUP(size);
	orig_size=f->size;
	if (f->size > size){
		/* shrink */
		#ifdef DBG_F_MALLOC
		LM_DBG("shrinking from %lu to %lu\n", f->size, size);
		fm_split_frag_unsafe(qm, f, size, file, "frag. from fm_realloc", line);
		#else
		fm_split_frag_unsafe(qm, f, size);
		#endif

	}else if (f->size<size){
		/* grow */
		
		#ifdef DBG_F_MALLOC
		LM_DBG("growing from %lu to %lu\n", f->size, size);
		#endif
		
		diff=size-f->size;
		n=FRAG_NEXT(f);
		
		if (((char*)n < (char*)qm->last_frag) &&  n->prev &&
		 ((n->size+FRAG_OVERHEAD)>=diff)){

			fm_remove_free(qm,n);
			/* join */
			f->size += n->size + FRAG_OVERHEAD;

			#if defined(DBG_F_MALLOC) || defined(STATISTICS)
			qm->real_used -= FRAG_OVERHEAD;
			#endif

			/* split it if necessary */
			if (f->size > size){
				#ifdef DBG_F_MALLOC
				fm_split_frag_unsafe(qm, f, size, file, "fragm. from fm_realloc",
						line);
				#else
				fm_split_frag_unsafe(qm, f, size);
				#endif
			}
		}else{
			/* could not join => realloc */
			#ifdef DBG_F_MALLOC
			ptr=fm_malloc(qm, size, file, func, line);
			#else
			ptr = fm_malloc(qm, size);
			#endif
			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);
				#ifdef DBG_F_MALLOC
				fm_free(qm, p, file, func, line);
				#else
				fm_free(qm, p);
				#endif
			}
			p = ptr;
		}
	}else{
		/* do nothing */
	#ifdef DBG_F_MALLOC
		LM_DBG("doing nothing, same size: %lu - %lu\n", f->size, size);
	#endif
	}
	#ifdef DBG_F_MALLOC
	LM_DBG("returning %p\n", p);
	#endif

	pkg_threshold_check();
	return p;
}

#ifdef DBG_F_MALLOC
void* fm_realloc(struct fm_block* qm, void* p, unsigned long size,
					const char* file, const char* func, unsigned int line)
#else
void* fm_realloc(struct fm_block* qm, void* p, unsigned long size)
#endif
{
	struct fm_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	unsigned int hash_next;
	struct fm_frag *n;
	void *ptr;
	
	#ifdef DBG_F_MALLOC
	LM_DBG("params(%p, %p, %lu), called from %s: %s(%d)\n", qm, p, size,
			file, func, line);
	if ((p)&&(p>(void*)qm->last_frag || p<(void*)qm->first_frag)){
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (size==0) {
		if (p)
	#ifdef DBG_F_MALLOC
			fm_free(qm, p, file, func, line);
	#else
			fm_free(qm, p);
	#endif
		pkg_threshold_check();
		return 0;
	}
	if (p==0)
	#ifdef DBG_F_MALLOC
		return fm_malloc(qm, size, file, func, line);
	#else
		return fm_malloc(qm, size);
	#endif
	f=(struct fm_frag*) ((char*)p-sizeof(struct fm_frag));
	#ifdef DBG_F_MALLOC
	LM_DBG("realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	#endif
	size=ROUNDUP(size);

	SHM_LOCK(0);

	orig_size=f->size;
	if (f->size > size){
		/* shrink */
		#ifdef DBG_F_MALLOC
		LM_DBG("shrinking from %lu to %lu\n", f->size, size);
		fm_split_frag(qm, f, size, file, "frag. from fm_realloc", line);
		#else
		fm_split_frag(qm, f, size, 0);
		#endif

	}else if (f->size<size){
		/* grow */

		#ifdef DBG_F_MALLOC
		LM_DBG("growing from %lu to %lu\n", f->size, size);
		#endif

		diff=size-f->size;
		n=FRAG_NEXT(f);

		hash_next = GET_HASH(n->size);

		if (0 != hash_next)
			SHM_LOCK(hash_next);

		if (((char*)n < (char*)qm->last_frag) &&  n->prev &&
		 ((n->size+FRAG_OVERHEAD)>=diff)){

			fm_remove_free(qm,n);

			if (0 != hash_next)
				SHM_UNLOCK(hash_next);

			/* join */
			f->size += n->size + FRAG_OVERHEAD;

			#if defined(DBG_F_MALLOC) || defined(STATISTICS)
			qm->real_used -= FRAG_OVERHEAD;
			#endif

			/* split it if necessary */
			if (f->size > size){
				#ifdef DBG_F_MALLOC
				fm_split_frag(qm, f, size, file, "fragm. from fm_realloc",
						line);
				#else
				fm_split_frag(qm, f, size, 0);
				#endif
			}
		}else{
			if (0 != hash_next)
				SHM_UNLOCK(hash_next);

			/* could not join => realloc */
			#ifdef DBG_F_MALLOC
			ptr=fm_malloc(qm, size, file, func, line);
			#else
			ptr=fm_malloc(qm, size);
			#endif
			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);
				#ifdef DBG_F_MALLOC
				fm_free_unsafe(qm, p, file, func, line);
				#else
				fm_free_unsafe(qm, p);
				#endif
			}
			p = ptr;
		}
	}else{
		/* do nothing */
	#ifdef DBG_F_MALLOC
		LM_DBG("doing nothing, same size: %lu - %lu\n", f->size, size);
	#endif
	}

	SHM_UNLOCK(0);

	#ifdef DBG_F_MALLOC
	LM_DBG("returning %p\n", p);
	#endif

	pkg_threshold_check();
	return p;
}



void fm_status(struct fm_block* qm)
{
	struct fm_frag* f;
	unsigned int i,j;
	unsigned int h;
	int unused;
	unsigned long size;

	LM_GEN1(memdump, "fm_status (%p):\n", qm);
	if (!qm) return;

	LM_GEN1(memdump, " heap size= %ld\n", qm->size);
#if defined(DBG_F_MALLOC) || defined(STATISTICS)
	LM_GEN1(memdump, " used= %lu, used+overhead=%lu, free=%lu\n",
			qm->used, qm->real_used, qm->size-qm->used);
	LM_GEN1(memdump, " max used (+overhead)= %lu\n", qm->max_real_used);
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
#if !defined(DBG_F_MALLOC) && !defined(STATISTICS)
	struct fm_frag* f;
#endif

	memset(info,0, sizeof(*info));
	total_frags=0;
	info->total_size=qm->size;
	info->min_frag=MIN_FRAG_SIZE;
#if defined(DBG_F_MALLOC) || defined(STATISTICS)
	info->free=qm->size-qm->real_used;
	info->used=qm->used;
	info->real_used=qm->real_used;
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
#endif
	info->total_frags=total_frags;
}



#endif
