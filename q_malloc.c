/* $Id$
 *
 */

#define q_malloc
#ifdef q_malloc

#include "q_malloc.h"
#include "dprint.h"


/*usefull macros*/
#define FRAG_END(f)  \
			((struct qm_frag_end*)((char*)f+sizeof(struct qm_frag)+f->size))

#define FRAG_NEXT(f) \
			((struct qm_frag*)((char*)f+sizeof(struct qm_frag)+f->size+ \
							   sizeof(struct qm_frag_end)))
			
#define FRAG_PREV(f) \
		( (struct qm_frag*) ( ((char*)f-sizeof(struct qm_frag_end))- \
		((struct qm_frag_end*)((char*)f-sizeof(struct qm_frag_end)))->size- \
			sizeof(struct qm_frag) ) )





/* init malloc and return a qm_block*/
struct qm_block* qm_malloc_init(char* address, unsigned int size)
{
	char* start;
	char* end;
	struct qm_block* qm;
	unsigned int init_overhead;
	unsigned int init_size;
	
	init_size=size;
	/* make address and size multiple of 8*/
	start=(char*)( ((unsigned int)address%8)?((unsigned int)address+8)/8*8:
			(unsigned int)address);
	if (size<start-address) return 0;
	size-=(start-address);
	if (size <8) return 0;
	size=(size%8)?(size-8)/8*8:size;
	
	init_overhead=sizeof(struct qm_block)+sizeof(struct qm_frag)+
		sizeof(struct qm_frag_end);
	if (size < init_overhead)
	{
		/* not enough mem to create our control structures !!!*/
		return 0;
	}
	end=start+size;
	qm=(struct qm_block*)start;
	memset(qm, 0, sizeof(struct qm_block));
	qm->init_size=init_size;
	qm->size=size-init_overhead;
	qm->real_used=init_overhead;
	
	qm->first_frag=(struct qm_frag*)(start+sizeof(struct qm_block));
	qm->last_frag_end=(struct qm_frag_end*)(end-sizeof(struct qm_frag_end));
	/* init initial fragment*/
	qm->first_frag->size=size;
	qm->first_frag->u.nxt_free=&(qm->free_lst);
	qm->last_frag_end->size=size;
	qm->last_frag_end->prev_free=&(qm->free_lst);
	/* init free_lst* */
	qm->free_lst.u.nxt_free=qm->first_frag;
	qm->free_lst_end.prev_free=qm->first_frag;
	qm->free_lst.size=0;
	qm->free_lst_end.size=0;
	
	
	return qm;
}


static inline void qm_insert_free(struct qm_block* qm, struct qm_frag* frag)
{
	struct qm_frag* f;
	struct qm_frag* prev;

	for(f=qm->free_lst.u.nxt_free; f!=&(qm->free_lst); f=f->u.nxt_free){
		if (frag->size < f->size) break;
	}
	/*insert it here*/
	prev=FRAG_END(f)->prev_free;
	prev->u.nxt_free=frag;
	FRAG_END(frag)->prev_free=prev;
	frag->u.nxt_free=f;
	FRAG_END(f)->prev_free=frag;
}



static inline void qm_detach_free(struct qm_block* qm, struct qm_frag* frag)
{
	struct qm_frag *prev;
	struct qm_frag *next;
	
	struct qm_frag_end *end;

	prev=FRAG_END(frag)->prev_free;
	next=frag->u.nxt_free;
	prev->u.nxt_free=next;
	FRAG_END(next)->prev_free=prev;
	
}



void* qm_malloc(struct qm_block* qm, unsigned int size)
{
	struct qm_frag* f;
	struct qm_frag_end* end;
	struct qm_frag* n;
	unsigned int rest;
	unsigned int overhead;
	
	/*size must be a multiple of 8*/
	size=(size%8)?(size+8)/8*8:size;
	if (size>(qm->size-qm->real_used)) return 0;
	if (qm->free_lst.u.nxt_free==&(qm->free_lst)) return 0;
	/*search for a suitable free frag*/
	for (f=qm->free_lst.u.nxt_free; f!=&(qm->free_lst); f=f->u.nxt_free){
		if (f->size>=size){
			/* we found it!*/
			/*detach it from the free list*/
			qm_detach_free(qm, f);
			/*mark it as "busy"*/
			f->u.is_free=0;
			
			/*see if we'll use full frag, or we'll split it in 2*/
			rest=f->size-size;
			overhead=sizeof(struct qm_frag)+sizeof(struct qm_frag_end);
			if (rest>overhead){
				f->size=size;
				/*split the fragment*/
				end=FRAG_END(f);
				end->size=size;
				n=(struct qm_frag*)((char*)end+sizeof(struct qm_frag_end));
				n->size=rest-overhead;
				FRAG_END(n)->size=n->size;
				qm->real_used+=overhead;
				/* reinsert n in free list*/
				qm_insert_free(qm, n);
			}else{
				/* we cannot split this fragment any more => alloc all of it*/
			}
			qm->real_used+=f->size;
			qm->used+=f->size;
			return (char*)f+sizeof(struct qm_frag);
		}
	}
	return 0;
}



void qm_free(struct qm_block* qm, void* p)
{
	struct qm_frag* f;
	struct qm_frag* prev;
	struct qm_frag* next;
	struct qm_frag_end *end;
	unsigned int overhead;
	unsigned int size;

	if (p==0) {
		DBG("WARNING:qm_free: free(0) called\n");
		return;
	}
	prev=next=0;
	f=(struct qm_frag*) ((char*)p-sizeof(struct qm_frag));
	overhead=sizeof(struct qm_frag)+sizeof(struct qm_frag_end);
	next=FRAG_NEXT(f);
	size=f->size;
	qm->used-=size;
	qm->real_used-=size;
	if (((char*)next < (char*)qm->last_frag_end) &&( next->u.is_free)){
		/* join */
		qm_detach_free(qm, next);
		size+=next->size+overhead;
		qm->real_used-=overhead;
	}
	
	if (f > qm->first_frag){
		prev=FRAG_PREV(f);
		/*	(struct qm_frag*)((char*)f - (struct qm_frag_end*)((char*)f-
								sizeof(struct qm_frag_end))->size);*/
		if (prev->u.is_free){
			/*join*/
			qm_detach_free(qm, prev);
			size+=prev->size+overhead;
			qm->real_used-=overhead;
			f=prev;
		}
	}
	FRAG_END(f)->size=f->size;
	qm_insert_free(qm, f);
}



void qm_status(struct qm_block* qm)
{
	struct qm_frag* f;
	int i;

	DBG("qm_status (%x):\n", qm);
	DBG(" init_size= %d", qm->init_size);
	DBG(" heap size= %d", qm->size);
	DBG(" used= %d, used+overhead=%d, free=%d\n",
			qm->used, qm->real_used, qm->size-qm->real_used);
	
	DBG("dumping all fragments:\n");
	for (f=qm->first_frag, i=0;(char*)f<(char*)qm->last_frag_end;f=FRAG_NEXT(f)
			,i++)
		DBG("    %3d. %c  address=%x  size=%d\n", i, (f->u.is_free)?'a':'N',
				(char*)f+sizeof(struct qm_frag), f->size);
	DBG("dumping free list:\n");
	for (f=qm->free_lst.u.nxt_free; f!=&(qm->free_lst); f=f->u.nxt_free)
		DBG("    %3d. %c  address=%x  size=%d\n", i, (f->u.is_free)?'a':'N',
				(char*)f+sizeof(struct qm_frag), f->size);
	DBG("-----------------------------\n");
}




#endif
