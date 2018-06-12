/* $Id$
 *
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * History:
 * --------
 *  ????-??-??  created by andrei
 *  2003-04-14  more debugging added in DBG_QM_MALLOC mode (andrei)
 *  2003-06-29  added qm_realloc (andrei)
 */


#if !defined(q_malloc) && !(defined VQ_MALLOC) && !(defined F_MALLOC)
#define q_malloc

#include <stdlib.h>
#include <string.h>

#include "q_malloc.h"
#include "../dprint.h"
#include "../globals.h"


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


#define FRAG_OVERHEAD	(sizeof(struct qm_frag)+sizeof(struct qm_frag_end))


#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

/*
#define ROUNDUP(s)		(((s)%ROUNDTO)?((s)+ROUNDTO)/ROUNDTO*ROUNDTO:(s))
#define ROUNDDOWN(s)	(((s)%ROUNDTO)?((s)-ROUNDTO)/ROUNDTO*ROUNDTO:(s))
*/



	/* finds the hash value for s, s=ROUNDTO multiple*/
#define GET_HASH(s)   ( ((s)<QM_MALLOC_OPTIMIZE)?(s)/ROUNDTO: \
						QM_MALLOC_OPTIMIZE/ROUNDTO+big_hash_idx((s))- \
							QM_MALLOC_OPTIMIZE_FACTOR+1 )


/* computes hash number for big buckets*/
inline static int big_hash_idx(int s)
{
	int idx;
	/* s is rounded => s = k*2^n (ROUNDTO=2^n) 
	 * index= i such that 2^i > s >= 2^(i-1)
	 *
	 * => index = number of the first non null bit in s*/
	for (idx=31; !(s&0x80000000) ; s<<=1, idx--);
	return idx;
}


#ifdef DBG_QM_MALLOC
#define ST_CHECK_PATTERN   0xf0f0f0f0
#define END_CHECK_PATTERN1 0xc0c0c0c0
#define END_CHECK_PATTERN2 0xabcdefed


static  void qm_debug_frag(struct qm_block* qm, struct qm_frag* f)
{
	if (f->check!=ST_CHECK_PATTERN){
		LOG(L_CRIT, "BUG: qm_*: fragm. %p (address %p) "
				"beginning overwritten(%lx)!\n",
				f, (char*)f+sizeof(struct qm_frag),
				f->check);
		qm_status(qm);
		abort();
	};
	if ((FRAG_END(f)->check1!=END_CHECK_PATTERN1)||
		(FRAG_END(f)->check2!=END_CHECK_PATTERN2)){
		LOG(L_CRIT, "BUG: qm_*: fragm. %p (address %p)"
					" end overwritten(%lx, %lx)!\n",
				f, (char*)f+sizeof(struct qm_frag), 
				FRAG_END(f)->check1, FRAG_END(f)->check2);
		qm_status(qm);
		abort();
	}
	if ((f>qm->first_frag)&&
			((PREV_FRAG_END(f)->check1!=END_CHECK_PATTERN1) ||
				(PREV_FRAG_END(f)->check2!=END_CHECK_PATTERN2) ) ){
		LOG(L_CRIT, "BUG: qm_*: prev. fragm. tail overwritten(%lx, %lx)[%p:%p]!"
					"\n",
				PREV_FRAG_END(f)->check1, PREV_FRAG_END(f)->check2, f,
				(char*)f+sizeof(struct qm_frag));
		qm_status(qm);
		abort();
	}
}
#endif



static inline void qm_insert_free(struct qm_block* qm, struct qm_frag* frag)
{
	struct qm_frag* f;
	struct qm_frag* prev;
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
}



/* init malloc and return a qm_block*/
struct qm_block* qm_malloc_init(char* address, unsigned int size)
{
	char* start;
	char* end;
	struct qm_block* qm;
	unsigned long init_overhead;
	int h;
	
	/* make address and size multiple of 8*/
	start=(char*)ROUNDUP((unsigned long) address);
	DBG("qm_malloc_init: QM_OPTIMIZE=%ld, /ROUNDTO=%ld\n",
			QM_MALLOC_OPTIMIZE, QM_MALLOC_OPTIMIZE/ROUNDTO);
	DBG("qm_malloc_init: QM_HASH_SIZE=%ld, qm_block size=%d\n",
			QM_HASH_SIZE, (int)sizeof(struct qm_block));
	DBG("qm_malloc_init(%p, %d), start=%p\n", address, size, start);
	if (size<start-address) return 0;
	size-=(start-address);
	if (size <(MIN_FRAG_SIZE+FRAG_OVERHEAD)) return 0;
	size=ROUNDDOWN(size);
	
	init_overhead=ROUNDUP(sizeof(struct qm_block))+sizeof(struct qm_frag)+
		sizeof(struct qm_frag_end);
	DBG("qm_malloc_init: size= %d, init_overhead=%ld\n", size, init_overhead);
	
	if (size < init_overhead)
	{
		/* not enough mem to create our control structures !!!*/
		return 0;
	}
	end=start+size;
	qm=(struct qm_block*)start;
	memset(qm, 0, sizeof(struct qm_block));
	size-=init_overhead;
	qm->size=size;
	qm->real_used=init_overhead;
	qm->max_real_used=qm->real_used;
	
	qm->first_frag=(struct qm_frag*)(start+ROUNDUP(sizeof(struct qm_block)));
	qm->last_frag_end=(struct qm_frag_end*)(end-sizeof(struct qm_frag_end));
	/* init initial fragment*/
	qm->first_frag->size=size;
	qm->last_frag_end->size=size;
	
#ifdef DBG_QM_MALLOC
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



static inline void qm_detach_free(struct qm_block* qm, struct qm_frag* frag)
{
	struct qm_frag *prev;
	struct qm_frag *next;
	
	prev=FRAG_END(frag)->prev_free;
	next=frag->u.nxt_free;
	prev->u.nxt_free=next;
	FRAG_END(next)->prev_free=prev;
	
}


#ifdef DBG_QM_MALLOC
static inline struct qm_frag* qm_find_free(struct qm_block* qm, 
											unsigned int size,
											unsigned int *count)
#else
static inline struct qm_frag* qm_find_free(struct qm_block* qm, 
											unsigned int size)
#endif
{
	int hash;
	struct qm_frag* f;

	for (hash=GET_HASH(size); hash<QM_HASH_SIZE; hash++){
		for (f=qm->free_hash[hash].head.u.nxt_free; 
					f!=&(qm->free_hash[hash].head); f=f->u.nxt_free){
#ifdef DBG_QM_MALLOC
			*count+=1; /* *count++ generates a warning with gcc 2.9* -Wall */
#endif
			if (f->size>=size) return f;
		}
	/*try in a bigger bucket*/
	}
	/* not found */
	return 0;
}


/* returns 0 on success, -1 on error;
 * new_size < size & rounded-up already!*/
static inline
#ifdef DBG_QM_MALLOC
int split_frag(struct qm_block* qm, struct qm_frag* f, unsigned int new_size,
				char* file, char* func, unsigned int line)
#else
int split_frag(struct qm_block* qm, struct qm_frag* f, unsigned int new_size)
#endif
{
	unsigned int rest;
	struct qm_frag* n;
	struct qm_frag_end* end;
	
	rest=f->size-new_size;
	if (rest>(FRAG_OVERHEAD+MIN_FRAG_SIZE)){
		f->size=new_size;
		/*split the fragment*/
		end=FRAG_END(f);
		end->size=new_size;
		n=(struct qm_frag*)((char*)end+sizeof(struct qm_frag_end));
		n->size=rest-FRAG_OVERHEAD;
		FRAG_END(n)->size=n->size;
		qm->real_used+=FRAG_OVERHEAD;
#ifdef DBG_QM_MALLOC
		end->check1=END_CHECK_PATTERN1;
		end->check2=END_CHECK_PATTERN2;
		/* frag created by malloc, mark it*/
		n->file=file;
		n->func=func;
		n->line=line;
		n->check=ST_CHECK_PATTERN;
#endif
		/* reinsert n in free list*/
		qm_insert_free(qm, n);
		return 0;
	}else{
			/* we cannot split this fragment any more */
		return -1;
	}
}



#ifdef DBG_QM_MALLOC
void* qm_malloc(struct qm_block* qm, unsigned int size, char* file, char* func,
					unsigned int line)
#else
void* qm_malloc(struct qm_block* qm, unsigned int size)
#endif
{
	struct qm_frag* f;
	
#ifdef DBG_QM_MALLOC
	unsigned int list_cntr;

	list_cntr = 0;
	DBG("qm_malloc(%p, %d) called from %s: %s(%d)\n", qm, size, file, func,
			line);
#endif
	/*size must be a multiple of 8*/
	size=ROUNDUP(size);
	if (size>(qm->size-qm->real_used)) return 0;

	/*search for a suitable free frag*/
#ifdef DBG_QM_MALLOC
	if ((f=qm_find_free(qm, size, &list_cntr))!=0){
#else
	if ((f=qm_find_free(qm, size))!=0){
#endif
		/* we found it!*/
		/*detach it from the free list*/
#ifdef DBG_QM_MALLOC
			qm_debug_frag(qm, f);
#endif
		qm_detach_free(qm, f);
		/*mark it as "busy"*/
		f->u.is_free=0;
		/* we ignore split return */
#ifdef DBG_QM_MALLOC
		split_frag(qm, f, size, file, "fragm. from qm_malloc", line);
#else
		split_frag(qm, f, size);
#endif
		qm->real_used+=f->size;
		qm->used+=f->size;
		if (qm->max_real_used<qm->real_used)
			qm->max_real_used=qm->real_used;
#ifdef DBG_QM_MALLOC
		f->file=file;
		f->func=func;
		f->line=line;
		f->check=ST_CHECK_PATTERN;
		/*  FRAG_END(f)->check1=END_CHECK_PATTERN1;
			FRAG_END(f)->check2=END_CHECK_PATTERN2;*/
		DBG("qm_malloc(%p, %d) returns address %p frag. %p (size=%ld) on %d -th"
				" hit\n",
			 qm, size, (char*)f+sizeof(struct qm_frag), f, f->size, list_cntr );
#endif
		return (char*)f+sizeof(struct qm_frag);
	}
	return 0;
}



#ifdef DBG_QM_MALLOC
void qm_free(struct qm_block* qm, void* p, char* file, char* func, 
				unsigned int line)
#else
void qm_free(struct qm_block* qm, void* p)
#endif
{
	struct qm_frag* f;
	struct qm_frag* prev;
	struct qm_frag* next;
	unsigned long size;

#ifdef DBG_QM_MALLOC
	DBG("qm_free(%p, %p), called from %s: %s(%d)\n", qm, p, file, func, line);
	if (p>(void*)qm->last_frag_end || p<(void*)qm->first_frag){
		LOG(L_CRIT, "BUG: qm_free: bad pointer %p (out of memory block!) - "
				"aborting\n", p);
		abort();
	}
#endif
	if (p==0) {
		LOG(L_WARN, "WARNING:qm_free: free(0) called\n");
		return;
	}
	prev=next=0;
	f=(struct qm_frag*) ((char*)p-sizeof(struct qm_frag));
#ifdef DBG_QM_MALLOC
	qm_debug_frag(qm, f);
	if (f->u.is_free){
		LOG(L_CRIT, "BUG: qm_free: freeing already freed pointer,"
				" first free: %s: %s(%ld) - aborting\n",
				f->file, f->func, f->line);
		abort();
	}
	DBG("qm_free: freeing frag. %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
#endif
	size=f->size;
	qm->used-=size;
	qm->real_used-=size;

#ifdef QM_JOIN_FREE
	/* join packets if possible*/
	next=FRAG_NEXT(f);
	if (((char*)next < (char*)qm->last_frag_end) &&( next->u.is_free)){
		/* join */
		qm_detach_free(qm, next);
		size+=next->size+FRAG_OVERHEAD;
		qm->real_used-=FRAG_OVERHEAD;
	}
	
	if (f > qm->first_frag){
		prev=FRAG_PREV(f);
		/*	(struct qm_frag*)((char*)f - (struct qm_frag_end*)((char*)f-
								sizeof(struct qm_frag_end))->size);*/
#ifdef DBG_QM_MALLOC
		qm_debug_frag(qm, f);
#endif
		if (prev->u.is_free){
			/*join*/
			qm_detach_free(qm, prev);
			size+=prev->size+FRAG_OVERHEAD;
			qm->real_used-=FRAG_OVERHEAD;
			f=prev;
		}
	}
	f->size=size;
	FRAG_END(f)->size=f->size;
#endif /* QM_JOIN_FREE*/
#ifdef DBG_QM_MALLOC
	f->file=file;
	f->func=func;
	f->line=line;
#endif
	qm_insert_free(qm, f);
}



#ifdef DBG_QM_MALLOC
void* qm_realloc(struct qm_block* qm, void* p, unsigned int size,
					char* file, char* func, unsigned int line)
#else
void* qm_realloc(struct qm_block* qm, void* p, unsigned int size)
#endif
{
	struct qm_frag* f;
	unsigned int diff;
	unsigned int orig_size;
	struct qm_frag* n;
	void* ptr;
	
	
#ifdef DBG_QM_MALLOC
	DBG("qm_realloc(%p, %p, %d) called from %s: %s(%d)\n", qm, p, size,
			file, func, line);
	if ((p)&&(p>(void*)qm->last_frag_end || p<(void*)qm->first_frag)){
		LOG(L_CRIT, "BUG: qm_free: bad pointer %p (out of memory block!) - "
				"aborting\n", p);
		abort();
	}
#endif
	
	if (size==0) {
		if (p)
#ifdef DBG_QM_MALLOC
			qm_free(qm, p, file, func, line);
#else
			qm_free(qm, p);
#endif
		return 0;
	}
	if (p==0)
#ifdef DBG_QM_MALLOC
		return qm_malloc(qm, size, file, func, line);
#else
		return qm_malloc(qm, size);
#endif
	f=(struct qm_frag*) ((char*)p-sizeof(struct qm_frag));
#ifdef DBG_QM_MALLOC
	qm_debug_frag(qm, f);
	DBG("qm_realloc: realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	if (f->u.is_free){
		LOG(L_CRIT, "BUG:qm_realloc: trying to realloc an already freed "
				"pointer %p , fragment %p -- aborting\n", p, f);
		abort();
	}
#endif
	/* find first acceptable size */
	size=ROUNDUP(size);
	if (f->size > size){
		/* shrink */
#ifdef DBG_QM_MALLOC
		DBG("qm_realloc: shrinking from %ld to %d\n", f->size, size);
		if(split_frag(qm, f, size, file, "fragm. from qm_realloc", line)!=0){
		DBG("qm_realloc : shrinked succesfull\n");
#else
		if(split_frag(qm, f, size)!=0){
#endif
			/* update used sizes */
			qm->real_used-=(f->size-size);
			qm->used-=(f->size-size);
		}
		
	}else if (f->size < size){
		/* grow */
#ifdef DBG_QM_MALLOC
		DBG("qm_realloc: growing from %ld to %d\n", f->size, size);
#endif
			orig_size=f->size;
			diff=size-f->size;
			n=FRAG_NEXT(f);
			if (((char*)n < (char*)qm->last_frag_end) && 
					(n->u.is_free)&&((n->size+FRAG_OVERHEAD)>=diff)){
				/* join  */
				qm_detach_free(qm, n);
				f->size+=n->size+FRAG_OVERHEAD;
				qm->real_used-=FRAG_OVERHEAD;
				FRAG_END(f)->size=f->size;
				/* end checks should be ok */
				/* split it if necessary */
				if (f->size > size ){
	#ifdef DBG_QM_MALLOC
					split_frag(qm, f, size, file, "fragm. from qm_realloc",
										line);
	#else
					split_frag(qm, f, size);
	#endif
				}
				qm->real_used+=(f->size-orig_size);
				qm->used+=(f->size-orig_size);
			}else{
				/* could not join => realloc */
	#ifdef DBG_QM_MALLOC
				ptr=qm_malloc(qm, size, file, func, line);
	#else
				ptr=qm_malloc(qm, size);
	#endif
				if (ptr)
					/* copy, need by libssl */
					memcpy(ptr, p, orig_size);
	#ifdef DBG_QM_MALLOC
					qm_free(qm, p, file, func, line);
	#else
					qm_free(qm, p);
	#endif
				p=ptr;
			}
	}else{
		/* do nothing */
#ifdef DBG_QM_MALLOC
		DBG("qm_realloc: doing nothing, same size: %ld - %d\n", f->size, size);
#endif
	}
#ifdef DBG_QM_MALLOC
	DBG("qm_realloc: returning %p\n", p);
#endif
	return p;
}




void qm_status(struct qm_block* qm)
{
	struct qm_frag* f;
	int i,j;
	int h;

	LOG(memlog, "qm_status (%p):\n", qm);
	if (!qm) return;

	LOG(memlog, " heap size= %ld\n", qm->size);
	LOG(memlog, " used= %ld, used+overhead=%ld, free=%ld\n",
			qm->used, qm->real_used, qm->size-qm->real_used);
	LOG(memlog, " max used (+overhead)= %ld\n", qm->max_real_used);
	
	LOG(memlog, "dumping all allocked. fragments:\n");
	for (f=qm->first_frag, i=0;(char*)f<(char*)qm->last_frag_end;f=FRAG_NEXT(f)
			,i++){
		if (! f->u.is_free){
			LOG(memlog, "    %3d. %c  address=%p frag=%p size=%ld\n", i, 
				(f->u.is_free)?'a':'N',
				(char*)f+sizeof(struct qm_frag), f, f->size);
#ifdef DBG_QM_MALLOC
			LOG(memlog, "            %s from %s: %s(%ld)\n",
				(f->u.is_free)?"freed":"alloc'd", f->file, f->func, f->line);
			LOG(memlog, "        start check=%lx, end check= %lx, %lx\n",
				f->check, FRAG_END(f)->check1, FRAG_END(f)->check2);
#endif
		}
	}
	LOG(memlog, "dumping free list stats :\n");
	for(h=0,i=0;h<QM_HASH_SIZE;h++){
		
		for (f=qm->free_hash[h].head.u.nxt_free,j=0; 
				f!=&(qm->free_hash[h].head); f=f->u.nxt_free, i++, j++);
			if (j) LOG(memlog, "hash= %3d. fragments no.: %5d\n", h, j);
	}
	LOG(memlog, "-----------------------------\n");
}




#endif
