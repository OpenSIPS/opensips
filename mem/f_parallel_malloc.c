#ifdef F_PARALLEL_MALLOC

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "f_parallel_malloc.h"
#include "../dprint.h"
#include "../globals.h"
#include "../statistics.h"

#ifdef DBG_MALLOC
#include "mem_dbg_hash.h"
#endif

#include "../lib/dbg/struct_hist.h"

#define MIN_FRAG_SIZE	ROUNDTO
#define F_PARALLEL_FRAG_OVERHEAD	(sizeof(struct parallel_frag))
#define frag_is_free(_f) ((_f)->prev)

#define F_PARALLEL_FRAG_NEXT(f) \
	((struct parallel_frag *)((char *)(f) + sizeof(struct parallel_frag) + (f)->size))

#define max(a,b) ( (a)>(b)?(a):(b))

/* ROUNDTO= 2^k so the following works */
#define ROUNDTO_MASK	(~((unsigned long)ROUNDTO-1))
#define ROUNDUP(s)		(((s)+(ROUNDTO-1))&ROUNDTO_MASK)
#define ROUNDDOWN(s)	((s)&ROUNDTO_MASK)

/* finds the hash value for s, s=ROUNDTO multiple*/
#define F_PARALLEL_GET_HASH(s)   ( ((unsigned long)(s)<=F_PARALLEL_MALLOC_OPTIMIZE)?\
							(unsigned long)(s)/ROUNDTO: \
							F_PARALLEL_MALLOC_OPTIMIZE/ROUNDTO+big_hash_idx((s))- \
								F_PARALLEL_MALLOC_OPTIMIZE_FACTOR+1 )

#define F_PARALLEL_UN_HASH(h)	( ((unsigned long)(h)<=(F_PARALLEL_MALLOC_OPTIMIZE/ROUNDTO))?\
						(unsigned long)(h)*ROUNDTO: \
						1UL<<((unsigned long)(h)-F_PARALLEL_MALLOC_OPTIMIZE/ROUNDTO+\
							F_PARALLEL_MALLOC_OPTIMIZE_FACTOR-1)\
					)

static inline void parallel_free_minus(struct parallel_block *fm, unsigned long size)
{

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->real_used+=size;
	fm->used+=size;
	#endif
}


static inline void parallel_free_plus(struct parallel_block *fm, unsigned long size)
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
unsigned long parallel_stats_get_index(void *ptr)
{
	if (!ptr)
		return GROUP_IDX_INVALID;

	return F_PARALLEL_FRAG(ptr)->statistic_index;
}

void parallel_stats_set_index(void *ptr, unsigned long idx)
{
	if (!ptr)
		return;

	F_PARALLEL_FRAG(ptr)->statistic_index = idx;
}
#endif

static inline void parallel_insert_free(struct parallel_block *fm, struct parallel_frag *frag)
{
	struct parallel_frag **f;
	int hash;

//	LM_ERR("Inserting free size frag %p in block %p, total size = %lu\n",frag,fm,frag->size);

	hash=F_PARALLEL_GET_HASH(frag->size);
//	LM_ERR("Gos to hash %d\n",hash);
	f=&(fm->free_hash[hash].first);
	if (*f)
		(*f)->block_ptr = fm;
	if (frag->size > F_PARALLEL_MALLOC_OPTIMIZE){ /* because of '<=' in GET_HASH,
											(different from 0.8.1[24] on
											 purpose --andrei ) */
//		LM_ERR("We optimize it, first is %p!! \n",*f);
		for(; *f; f=&((*f)->u.nxt_free)){
			//LM_ERR("Iterating over next free \n");
			(*f)->block_ptr = fm;
			if (frag->size <= (*f)->size) break;
		}
	}

	/*insert it here*/
	if (*f) {
		//LM_ERR("Setting back-pointer \n");
		(*f)->block_ptr = fm;
	}

	frag->prev = f;
	frag->u.nxt_free=*f;
	frag->block_ptr = fm;

	//LM_ERR("Linking %p with %p \n",frag,*f);

	if( *f ) {
		(*f)->block_ptr = fm;
		(*f)->prev = &(frag->u.nxt_free);
		frag->u.nxt_free->block_ptr = fm;
	}

	//LM_ERR("Putting at %p\n",f);
	*f=frag;
	fm->free_hash[hash].no++;
	//LM_ERR("Free hash no = %lu in block %p\n",fm->free_hash[hash].no,fm);
	//LM_ERR("After insert, we are left with %lu \n",frag->size);

	frag->block_ptr = fm;
	parallel_free_plus(fm, frag->size);
}

static inline void parallel_remove_free(struct parallel_block *fm, struct parallel_frag *n)
{
	struct parallel_frag **pf;
	int hash;

	pf = n->prev;
	hash = F_PARALLEL_GET_HASH( n->size );

	/* detach */
	if (*pf)
		(*pf)->block_ptr=fm;

	*pf=n->u.nxt_free;
	if (*pf)
		(*pf)->block_ptr=fm;

	if( n->u.nxt_free )
		n->u.nxt_free->prev = pf;

	fm->free_hash[hash].no--;

	n->prev = NULL;
	n->block_ptr = fm;

	//LM_ERR("Removing free size frag %p in block %p, total size = %lu\n",n,fm,n->size);

	parallel_free_minus(fm , n->size);

};





/* init malloc and return a parallel_block*/
struct parallel_block *parallel_malloc_init(char *address, unsigned long size, char *name, int idx)

{
	char *start;
	char *end;
	struct parallel_block *fm;
	unsigned long init_overhead;

	//LM_ERR("Init parallel block %p of size %lu\n", address,size);

	/* make address and size multiple of 8*/
	start=(char*)ROUNDUP((unsigned long) address);
	LM_DBG("F_OPTIMIZE=%lu, /ROUNDTO=%lu, %lu-bytes aligned\n",
			F_PARALLEL_MALLOC_OPTIMIZE, F_PARALLEL_MALLOC_OPTIMIZE/ROUNDTO,
			(unsigned long)ROUNDTO);
	LM_DBG("F_HASH_SIZE=%lu, parallel_block size=%zu, frag_size=%zu\n",
			F_PARALLEL_HASH_SIZE, sizeof(struct parallel_block), sizeof(struct parallel_frag));
	LM_DBG("params (%p, %lu), start=%p\n", address, size, start);

	if (size<(unsigned long)(start-address)) return 0;
	size-=(start-address);
	if (size <(MIN_FRAG_SIZE+F_PARALLEL_FRAG_OVERHEAD)) return 0;
	size=ROUNDDOWN(size);

	init_overhead=(ROUNDUP(sizeof(struct parallel_block))+ 2 * F_PARALLEL_FRAG_OVERHEAD);


	if (size < init_overhead)
	{
		/* not enough mem to create our control structures !!!*/
		return 0;
	}
	end=start+size;
	fm=(struct parallel_block *)start;
	//LM_ERR("Actual parallel block is %p \n",fm);
	memset(fm, 0, sizeof(struct parallel_block));
	fm->name = name;
	fm->size=size;

	fm->idx = idx;

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->used=size-init_overhead;
	fm->real_used=size;
	fm->max_real_used=init_overhead;
	fm->fragments = 0;
	#endif

	fm->first_frag=(struct parallel_frag *)(start+ROUNDUP(sizeof(struct parallel_block)));
	fm->last_frag=(struct parallel_frag *)(end-sizeof(struct parallel_frag));

	fm->first_frag->block_ptr = fm;
	fm->last_frag->block_ptr = fm;

	/* init initial fragment*/
	fm->first_frag->size=size-init_overhead;
	fm->last_frag->size=0;

	fm->last_frag->prev=NULL;
	fm->first_frag->prev=NULL;

	/* link initial fragment into the free list*/

	parallel_insert_free(fm, fm->first_frag);

	return fm;
}

#include "f_parallel_malloc_dyn.h"

#if !defined INLINE_ALLOC && defined DBG_MALLOC
#undef DBG_MALLOC
#include "f_parallel_malloc_dyn.h"
#define DBG_MALLOC
#endif

#ifdef SHM_EXTRA_STATS
void parallel_stats_core_init(struct parallel_block *fm, int core_index)
{
	struct parallel_frag *f;

	LM_ERR("Extra stats ?? \n");

	for (f=fm->first_frag; (char *)f < (char *)fm->last_frag; f=F_PARALLEL_FRAG_NEXT(f))
		if (!frag_is_free(f))
			f->statistic_index = core_index;
}

#endif




/* fills a malloc info structure with info about the block
 * if a parameter is not supported, it will be filled with 0 */
void parallel_info(struct parallel_block *fm, struct mem_info *info)
{
	memset(info,0, sizeof(*info));
	/* Not implemented, need an array here, no real use for it now */
	return;
}



#endif
