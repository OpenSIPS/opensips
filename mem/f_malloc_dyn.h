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
 *             (fm_split_frag_dbg + fm_split_frag long,
 *              requires x2 include, hence the "_dynamic" file suffix)
 *
 * The same idea applies to all below functions.
 */

static inline
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void fm_split_frag_dbg(struct fm_block *fm, struct fm_frag *frag,
                       unsigned long size,
                       const char *file, const char *func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void fm_split_frag(struct fm_block *fm, struct fm_frag *frag,
                   unsigned long size)
#else
void fm_split_frag(struct fm_block *fm, struct fm_frag *frag,
                   unsigned long size,
                   const char *file, const char *func, unsigned int line)
#endif
{
	unsigned long rest;
	struct fm_frag *n;

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
		fm->real_used+=FRAG_OVERHEAD;
		#endif

		 */
		#if defined(DBG_MALLOC) || defined(STATISTICS)
		fm->used-=FRAG_OVERHEAD;
		#endif

		#ifdef DBG_MALLOC
		/* frag created by malloc, mark it*/
		n->file=file;
		n->func=func;
		n->line=line;
		#endif
		/* reinsert n in free list*/
		fm_insert_free(fm, n);
	}else{
		/* we cannot split this fragment any more => alloc all of it*/
	}
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *fm_malloc_dbg(struct fm_block *fm, unsigned long size,
                    const char *file, const char *func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void *fm_malloc(struct fm_block *fm, unsigned long size)
#else
void *fm_malloc(struct fm_block *fm, unsigned long size,
                const char *file, const char *func, unsigned int line)
#endif
{
	struct fm_frag *frag, *n;
	unsigned int hash;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_malloc(%lu), called from %s: %s(%d)\n", fm->name, size, file, func,
			line);
	#endif

	/*size must be a multiple of 8*/
	size=ROUNDUP(size);

	/*search for a suitable free frag*/

	for(hash=GET_HASH(size);hash<F_HASH_SIZE;hash++){
		frag=fm->free_hash[hash].first;
		for( ; frag; frag = frag->u.nxt_free )
			if ( frag->size >= size ) goto found;
		/* try in a bigger bucket */
	}
	/* not found, bad! */

#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_WARN("not enough contiguous free %s memory (%ld bytes left, need %lu), attempting " \
			"defragmentation... please increase the \"-%s\" command line parameter!\n",
			fm->name, fm->size - fm->real_used, size, fm->name[0] == 'p' ? "M" : "m");
#else
	LM_WARN("not enough contiguous free %s memory (need %lu), attempting defragmentation... " \
			"please increase the \"-%s\" command line parameter!\n",
			fm->name, fm->size - fm->real_used, size, fm->name[0] == 'p' ? "M" : "m");
#endif

	for( frag = fm->first_frag; (char*)frag < (char*)fm->last_frag;  )
	{
		n = FRAG_NEXT(frag);

		if (((char*)n < (char*)fm->last_frag) &&
		    frag_is_free(n) && frag_is_free(frag))
		{
			/* detach frag*/
			fm_remove_free(fm, frag);

			do
			{
				fm_remove_free(fm, n);
				frag->size += n->size + FRAG_OVERHEAD;

				#if defined(DBG_MALLOC) || defined(STATISTICS)
				//fm->real_used -= FRAG_OVERHEAD;
				fm->used += FRAG_OVERHEAD;
				#endif

				if (frag->size >size)
					goto solved;

				n = FRAG_NEXT(frag);
			}
			while
			( ((char*)n < (char*)fm->last_frag) && frag_is_free(n));

			fm_insert_free(fm,frag);

		}

		frag = n;
	}

#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_ERR(oom_errorf, fm->name, fm->size - fm->real_used, size,
			fm->name[0] == 'p' ? "M" : "m");
#else
	LM_ERR(oom_nostats_errorf, fm->name, size, fm->name[0] == 'p' ? "M" : "m");
#endif
	pkg_threshold_check();
	return 0;


found:
	/* we found it!*/

	fm_remove_free(fm,frag);

	/*see if we'll use full frag, or we'll split it in 2*/

	#if !defined INLINE_ALLOC && defined DBG_MALLOC
	fm_split_frag_dbg(fm, frag, size, file, "fm_malloc frag", line);
	#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
	fm_split_frag(fm, frag, size);
	#else
	fm_split_frag(fm, frag, size, file, "fm_malloc frag", line);
	#endif

	#ifdef DBG_MALLOC
	frag->file=file;
	frag->func=func;
	frag->line=line;
	LM_GEN1(memlog, "%s_malloc(%lu), returns address %p\n", fm->name, size,
		(char*)frag+sizeof(struct fm_frag));
	#endif

solved:

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	if (fm->max_real_used<fm->real_used)
		fm->max_real_used=fm->real_used;
	fm->fragments += 1;
	#endif

	pkg_threshold_check();
	return (char*)frag+sizeof(struct fm_frag);
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void fm_free_dbg(struct fm_block *fm, void *p, const char *file,
                 const char *func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void fm_free(struct fm_block *fm, void *p)
#else
void fm_free(struct fm_block *fm, void *p, const char *file,
             const char *func, unsigned int line)
#endif
{
	struct fm_frag *f, *n;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_free(%p), called from %s: %s(%d)\n", fm->name, p, file,
	        func, line);
	if (p && (p > (void *)fm->last_frag || p < (void *)fm->first_frag)) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif
	if (!p) {
		LM_GEN1(memlog, "free(NULL) called\n");
		return;
	}

	f = FM_FRAG(p);

	check_double_free(p, f, fm);

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "freeing block alloc'ed from %s: %s(%ld)\n",
	        f->file, f->func, f->line);
#endif

	/* attempt to join with a next fragment that also happens to be free */
	n = FRAG_NEXT(f);
	if (((char*)n < (char*)fm->last_frag) &&  frag_is_free(n)) {
		fm_remove_free(fm, n);
		/* join */
		f->size += n->size + FRAG_OVERHEAD;

		#if defined(DBG_MALLOC) || defined(STATISTICS)
		//fm->real_used -= FRAG_OVERHEAD;
		fm->used += FRAG_OVERHEAD;
		#endif
	}

#ifdef DBG_MALLOC
	f->file = file;
	f->func = func;
	f->line = line;
#endif

	fm_insert_free(fm, f);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->fragments -= 1;
#endif
	pkg_threshold_check();
}


#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *fm_realloc_dbg(struct fm_block *fm, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line)
#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
void *fm_realloc(struct fm_block *fm, void *p, unsigned long size)
#else
void *fm_realloc(struct fm_block *fm, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line)
#endif
{
	struct fm_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct fm_frag *n;
	void *ptr;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_realloc(%p, %lu->%lu), called from %s: %s(%d)\n",
	        fm->name, p, p ? FM_FRAG(p)->size : 0, size, file, func, line);
	if (p && (p > (void *)fm->last_frag || p < (void *)fm->first_frag)) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif

	if (size == 0) {
		if (p)
			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			fm_free_dbg(fm, p, file, func, line);
			#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
			fm_free(fm, p);
			#else
			fm_free(fm, p, file, func, line);
			#endif
		pkg_threshold_check();
		return 0;
	}

	if (!p)
		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		return fm_malloc_dbg(fm, size, file, func, line);
		#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
		return fm_malloc(fm, size);
		#else
		return fm_malloc(fm, size, file, func, line);
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
		fm_split_frag_dbg(fm, f, size, file, "fm_realloc frag", line);
		#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
		fm_split_frag(fm, f, size);
		#else
		fm_split_frag(fm, f, size, file, "fm_realloc frag", line);
		#endif

	} else if (f->size < size) {
		/* grow */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "growing from %lu to %lu\n", f->size, size);
		#endif

		diff = size-f->size;
		n = FRAG_NEXT(f);

		if (((char*)n < (char*)fm->last_frag) && frag_is_free(n) &&
		 ((n->size+FRAG_OVERHEAD)>=diff)) {

			fm_remove_free(fm,n);
			/* join */
			f->size += n->size + FRAG_OVERHEAD;

			#if defined(DBG_MALLOC) || defined(STATISTICS)
			//fm->real_used -= FRAG_OVERHEAD;
			fm->used += FRAG_OVERHEAD;
			#endif

			/* split it if necessary */
			if (f->size > size){
				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				fm_split_frag_dbg(fm, f, size, file, "fm_realloc frag", line);
				#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
				fm_split_frag(fm, f, size);
				#else
				fm_split_frag(fm, f, size, file, "fm_realloc frag", line);
				#endif
			}
		} else {
			/* could not join => realloc */

			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			ptr = fm_malloc_dbg(fm, size, file, func, line);
			#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
			ptr = fm_malloc(fm, size);
			#else
			ptr = fm_malloc(fm, size, file, func, line);
			#endif

			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);

				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				fm_free_dbg(fm, p, file, func, line);
				#elif !defined F_MALLOC_DYN && !defined DBG_MALLOC
				fm_free(fm, p);
				#else
				fm_free(fm, p, file, func, line);
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
	if (fm->max_real_used<fm->real_used)
		fm->max_real_used=fm->real_used;
	#endif

	pkg_threshold_check();
	return p;
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void fm_status_dbg(struct fm_block *fm)
#else
void fm_status(struct fm_block *fm)
#endif
{
	struct fm_frag *f;
	unsigned int i,j;
	unsigned int h;
	int unused;
	unsigned long size;

#ifdef DBG_MALLOC
	mem_dbg_htable_t allocd;
	struct mem_dbg_entry *it;
#endif

	LM_GEN1(memdump, "fm_status (%p):\n", fm);
	if (!fm) return;

	LM_GEN1(memdump, " heap size= %ld\n", fm->size);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_GEN1(memdump, " used= %lu, used+overhead=%lu, free=%lu\n",
			fm->used, fm->real_used, fm->size-fm->used);
	LM_GEN1(memdump, " max used (+overhead)= %lu\n", fm->max_real_used);
#endif

#if defined(DBG_MALLOC)
	dbg_ht_init(allocd);

	for (f = fm->first_frag; f >= fm->first_frag && f < fm->last_frag;
	        f = FRAG_NEXT(f)) {
		if (!frag_is_free(f) && f->file)
			if (dbg_ht_update(allocd, f->file, f->func, f->line, f->size) < 0) {
				LM_ERR("Unable to update alloc'ed. memory summary\n");
				dbg_ht_free(allocd);
				return;
			}
	}

	if (f != fm->last_frag)
		LM_GEN1(memdump, "failed to walk through all fragments (%p %p %p)\n",
		        f, fm->first_frag, fm->last_frag);

	LM_GEN1(memdump, " dumping summary of all alloc'ed. fragments:\n");
	LM_GEN1(memdump, "------------+---------------------------------------\n");
	LM_GEN1(memdump, "total_bytes | num_allocations x [file: func, line]\n");
	LM_GEN1(memdump, "------------+---------------------------------------\n");
	for(i=0; i < DBG_HASH_SIZE; i++) {
		it = allocd[i];
		while (it) {
			LM_GEN1(memdump, " %10lu : %lu x [%s: %s, line %lu]\n",
				it->size, it->no_fragments, it->file, it->func, it->line);
			it = it->next;
		}
	}
	LM_GEN1(memdump, "----------------------------------------------------\n");

	dbg_ht_free(allocd);
#endif

	LM_GEN1(memdump, "dumping free list:\n");
	for(h=0,i=0,size=0;h<F_HASH_SIZE;h++){
		unused=0;
		for (f=fm->free_hash[h].first,j=0; f;
				size+=f->size,f=f->u.nxt_free,i++,j++){ }
		if (j) LM_GEN1(memdump,"hash = %3d fragments no.: %5d, unused: %5d\n\t\t"
							" bucket size: %9lu - %9lu (first %9lu)\n",
							h, j, unused, UN_HASH(h),
						((h<=F_MALLOC_OPTIMIZE/ROUNDTO)?1:2)* UN_HASH(h),
							fm->free_hash[h].first->size
				);
		if (j!=fm->free_hash[h].no){
			LM_CRIT("different free frag. count: %d!=%ld"
					" for hash %3d\n", j, fm->free_hash[h].no, h);
		}

	}
	LM_GEN1(memdump, "TOTAL: %6d free fragments = %6lu free bytes\n", i, size);
	LM_GEN1(memdump, "TOTAL: %u overhead\n", (unsigned int)FRAG_OVERHEAD );
	LM_GEN1(memdump, "-----------------------------\n");
}

#define F_MALLOC_DYN
