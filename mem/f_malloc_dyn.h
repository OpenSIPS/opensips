/*
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

/*
 * If you have to deal with the ifdef spaghetti, here are its requirements:
 *   - be able to compile an inlined allocator (fm_split_frag short)
 *   - be able to compile an inlined, dbg allocator (fm_split_frag long)
 *   - be able to compile multiple allocators (fm_split_frag short)
 *   - be able to compile multiple, dbg allocators
 *				(fm_split_frag_dbg + fm_split_frag long, requires x2 include)
 *
 * The same idea applies to all below functions.
 */

static inline
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void fm_split_frag_dbg(struct fm_block* qm, struct fm_frag* frag,
                       unsigned long size,
                       const char* file, const char* func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void fm_split_frag(struct fm_block* qm, struct fm_frag* frag,
                   unsigned long size)
#else
void fm_split_frag(struct fm_block* qm, struct fm_frag* frag,
                   unsigned long size,
                   const char* file, const char* func, unsigned int line)
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
		n->func=func;
		n->line=line;
		n->check=ST_CHECK_PATTERN;
		#endif
		/* reinsert n in free list*/
		fm_insert_free(qm, n);
	}else{
		/* we cannot split this fragment any more => alloc all of it*/
	}
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void* fm_malloc_dbg(struct fm_block* qm, unsigned long size,
                    const char* file, const char* func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void* fm_malloc(struct fm_block* qm, unsigned long size)
#else
void* fm_malloc(struct fm_block* qm, unsigned long size,
                const char* file, const char* func, unsigned int line)
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

		if (((char*)n < (char*)qm->last_frag) &&
		    frag_is_free(n) && frag_is_free(frag))
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
			( ((char*)n < (char*)qm->last_frag) && frag_is_free(n));

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

	#if !defined INLINE_ALLOC && defined DBG_MALLOC
	fm_split_frag_dbg(qm, frag, size, file, "fm_malloc frag", line);
	#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
	fm_split_frag(qm, frag, size);
	#else
	fm_split_frag(qm, frag, size, file, "fm_malloc frag", line);
	#endif

	#ifdef DBG_MALLOC
	frag->file=file;
	frag->func=func;
	frag->line=line;
	frag->check=ST_CHECK_PATTERN;
	LM_GEN1(memlog, "%s_malloc(%lu), returns address %p\n", qm->name, size,
		(char*)frag+sizeof(struct fm_frag));
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

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void fm_free_dbg(struct fm_block* qm, void* p, const char* file,
                 const char* func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void fm_free(struct fm_block* qm, void* p)
#else
void fm_free(struct fm_block* qm, void* p, const char* file,
             const char* func, unsigned int line)
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

	f = FM_FRAG(p);

	check_double_free(p, f, qm);

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "freeing block alloc'ed from %s: %s(%ld)\n",
	        f->file, f->func, f->line);
#endif

join:

	if( qm->large_limit < qm->large_space )
		goto no_join;

	n = FRAG_NEXT(f);

	if (((char*)n < (char*)qm->last_frag) &&  frag_is_free(n) )
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

#ifdef DBG_MALLOC
	f->file = file;
	f->func = func;
	f->line = line;
#endif

	fm_insert_free(qm, f);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	qm->fragments -= 1;
#endif
	pkg_threshold_check();
}


#if !defined INLINE_ALLOC && defined DBG_MALLOC
void* fm_realloc_dbg(struct fm_block* qm, void* p, unsigned long size,
                     const char* file, const char* func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void* fm_realloc(struct fm_block* qm, void* p, unsigned long size)
#else
void* fm_realloc(struct fm_block* qm, void* p, unsigned long size,
                 const char* file, const char* func, unsigned int line)
#endif
{
	struct fm_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct fm_frag *n;
	void *ptr;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_realloc(%p, %lu->%lu), called from %s: %s(%d)\n",
	        qm->name, p, p ? FM_FRAG(p)->size : 0, size, file, func, line);
	if (p && (p > (void *)qm->last_frag || p < (void *)qm->first_frag)) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif

	if (size == 0) {
		if (p)
			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			fm_free_dbg(qm, p, file, func, line);
			#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
			fm_free(qm, p);
			#else
			fm_free(qm, p, file, func, line);
			#endif
		pkg_threshold_check();
		return 0;
	}

	if (!p)
		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		return fm_malloc_dbg(qm, size, file, func, line);
		#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
		return fm_malloc(qm, size);
		#else
		return fm_malloc(qm, size, file, func, line);
		#endif

	f = FM_FRAG(p);

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	#endif

	size = ROUNDUP(size);
	orig_size = f->size;

	if (f->size > size) {
		/* shrink */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "shrinking from %lu to %lu\n", f->size, size);
		#endif

		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		fm_split_frag_dbg(qm, f, size, file, "fm_realloc frag", line);
		#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
		fm_split_frag(qm, f, size);
		#else
		fm_split_frag(qm, f, size, file, "fm_realloc frag", line);
		#endif

	} else if (f->size < size) {
		/* grow */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "growing from %lu to %lu\n", f->size, size);
		#endif

		diff = size-f->size;
		n = FRAG_NEXT(f);

		if (((char*)n < (char*)qm->last_frag) && frag_is_free(n) &&
		 ((n->size+FRAG_OVERHEAD)>=diff)) {

			fm_remove_free(qm,n);
			/* join */
			f->size += n->size + FRAG_OVERHEAD;

			#if defined(DBG_MALLOC) || defined(STATISTICS)
			//qm->real_used -= FRAG_OVERHEAD;
			qm->used += FRAG_OVERHEAD;
			#endif

			/* split it if necessary */
			if (f->size > size){
				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				fm_split_frag_dbg(qm, f, size, file, "fm_realloc frag", line);
				#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
				fm_split_frag(qm, f, size);
				#else
				fm_split_frag(qm, f, size, file, "fm_realloc frag", line);
				#endif
			}
		} else {
			/* could not join => realloc */

			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			ptr = fm_malloc_dbg(qm, size, file, func, line);
			#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
			ptr = fm_malloc(qm, size);
			#else
			ptr = fm_malloc(qm, size, file, func, line);
			#endif

			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);

				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				fm_free_dbg(qm, p, file, func, line);
				#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
				fm_free(qm, p);
				#else
				fm_free(qm, p, file, func, line);
				#endif
			}
			p = ptr;
		}
	} else {
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



#define F_MALLOC_DYN
