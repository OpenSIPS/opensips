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
void parallel_split_frag_dbg(struct parallel_block *fm, struct parallel_frag *frag,
                       unsigned long size,
                       const char *file, const char *func, unsigned int line)
#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
void parallel_split_frag(struct parallel_block *fm, struct parallel_frag *frag,
                   unsigned long size)
#else
void parallel_split_frag(struct parallel_block *fm, struct parallel_frag *frag,
                   unsigned long size,
                   const char *file, const char *func, unsigned int line)
#endif
{
	unsigned long rest;
	struct parallel_frag *n;

	//LM_ERR("VLAD - F_PARALLEL split block %p for size %lu of frag %p \n",fm,size,frag);
	frag->block_ptr = fm;

	rest=frag->size-size;
	#ifdef MEM_FRAG_AVOIDANCE
	//LM_ERR("FRAG avoidance \n");
	if ((rest> (F_PARALLEL_FRAG_OVERHEAD+F_PARALLEL_MALLOC_OPTIMIZE))||
		(rest>=(F_PARALLEL_FRAG_OVERHEAD+size))){ /* the residue fragm. is big enough*/
	#else
	if (rest>(F_PARALLEL_FRAG_OVERHEAD+MIN_FRAG_SIZE)){
	#endif
		//LM_ERR("We-re splliting frag %p from block %p\n",frag,fm);
		frag->size=size;
		/*split the fragment*/
		n=F_PARALLEL_FRAG_NEXT(frag);
		n->block_ptr=fm;
		n->size=rest-F_PARALLEL_FRAG_OVERHEAD;


		/*
		 * The real used memory does not increase, as the frag memory is not
		 * freed from real_used. On the other hand, the used size should
		 * decrease, because the new fragment is not "useful data" - razvanc

		#if defined(DBG_MALLOC) || defined(STATISTICS)
		fm->real_used+=F_PARALLEL_FRAG_OVERHEAD;
		#endif

		 */
		#if defined(DBG_MALLOC) || defined(STATISTICS)
		fm->used-=F_PARALLEL_FRAG_OVERHEAD;
		#endif

		#ifdef DBG_MALLOC
		/* frag created by malloc, mark it*/
		n->file=file;
		n->func=func;
		n->line=line;
		#endif
		/* reinsert n in free list*/
		parallel_insert_free(fm, n);
	}else{
		/* we cannot split this fragment any more => alloc all of it*/
	}
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *parallel_malloc_dbg(struct parallel_block *fm, unsigned long size,
                    const char *file, const char *func, unsigned int line)
#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
void *parallel_malloc(struct parallel_block *fm, unsigned long size)
#else
void *parallel_malloc(struct parallel_block *fm, unsigned long size,
                const char *file, const char *func, unsigned int line)
#endif
{
	struct parallel_frag *frag, *n;
	unsigned int hash;

	//LM_ERR("VLAD - F_PARALLEL malloc block %p for size %lu\n",fm,size);

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_malloc(%lu), called from %s: %s(%d)\n", fm->name, size, file, func,
			line);
	#endif

	/*size must be a multiple of 8*/
	size=ROUNDUP(size);

	/*search for a suitable free frag*/

	//LM_ERR("big Hash = %lu , current hash size = %lu\n",F_PARALLEL_HASH_SIZE,F_PARALLEL_GET_HASH(size));

	for(hash=F_PARALLEL_GET_HASH(size);hash<F_PARALLEL_HASH_SIZE;hash++){
		frag=fm->free_hash[hash].first;
		//LM_ERR("Checking in hash %d, first is frag %p\n",hash,frag);
		for( ; frag; frag = frag->u.nxt_free ) {
			//LM_ERR("Vlad searching %lu size, in frag %p size %lu , hash %d\n",size,frag,frag->size,hash);
			if ( frag->size >= size ) goto found;
		/* try in a bigger bucket */
		}
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
		n = F_PARALLEL_FRAG_NEXT(frag);

		if (((char*)n < (char*)fm->last_frag) &&
		    frag_is_free(n) && frag_is_free(frag))
		{
			/* detach frag*/
			parallel_remove_free(fm, frag);

			do
			{
				parallel_remove_free(fm, n);
				frag->size += n->size + F_PARALLEL_FRAG_OVERHEAD;

				#if defined(DBG_MALLOC) || defined(STATISTICS)
				//fm->real_used -= F_PARALLEL_FRAG_OVERHEAD;
				fm->used += F_PARALLEL_FRAG_OVERHEAD;
				#endif

				if (frag->size >size)
					goto solved;

				n = F_PARALLEL_FRAG_NEXT(frag);
			}
			while
			( ((char*)n < (char*)fm->last_frag) && frag_is_free(n));

			parallel_insert_free(fm,frag);

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
	//LM_ERR("We found it !!! \n");

	parallel_remove_free(fm,frag);

	/*see if we'll use full frag, or we'll split it in 2*/

	#if !defined INLINE_ALLOC && defined DBG_MALLOC
	parallel_split_frag_dbg(fm, frag, size, file, "fm_malloc frag", line);
	#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
	parallel_split_frag(fm, frag, size);
	#else
	parallel_split_frag(fm, frag, size, file, "fm_malloc frag", line);
	#endif

	#ifdef DBG_MALLOC
	frag->file=file;
	frag->func=func;
	frag->line=line;
	LM_GEN1(memlog, "%s_malloc(%lu), returns address %p\n", fm->name, size,
		(char*)frag+sizeof(struct parallel_frag));
	#endif

solved:

	#if defined(DBG_MALLOC) || defined(STATISTICS)
	if (fm->max_real_used<fm->real_used)
		fm->max_real_used=fm->real_used;
	fm->fragments += 1;
	#endif

	frag->block_ptr = fm;

	pkg_threshold_check();

	//LM_ERR("Alloc done ok ! - return frag %p with size %lu \n",frag,frag->size);
	return (char*)frag+sizeof(struct parallel_frag);
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void parallel_free_dbg(struct parallel_block *fm, void *p, const char *file,
                 const char *func, unsigned int line)
#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
void parallel_free(struct parallel_block *fm, void *p)
#else
void parallel_free(struct parallel_block *fm, void *p, const char *file,
             const char *func, unsigned int line)
#endif
{
	struct parallel_frag *f, *n;

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

	f = F_PARALLEL_FRAG(p);

	fm = f->block_ptr;

	//LM_ERR("VLAD - F_PARALLEL free in block %p of %p with idx %d \n",fm,p,fm->idx);

	lock_get(hash_locks[fm->idx]);

	check_double_free(p, f, fm);

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "freeing block alloc'ed from %s: %s(%ld)\n",
	        f->file, f->func, f->line);
#endif

	/* attempt to join with a next fragment that also happens to be free */
	n = F_PARALLEL_FRAG_NEXT(f);
	if (((char*)n < (char*)fm->last_frag) &&  frag_is_free(n)) {
		parallel_remove_free(fm, n);
		/* join */
		f->size += n->size + F_PARALLEL_FRAG_OVERHEAD;

		#if defined(DBG_MALLOC) || defined(STATISTICS)
		//fm->real_used -= F_PARALLEL_FRAG_OVERHEAD;
		fm->used += F_PARALLEL_FRAG_OVERHEAD;
		#endif
	}

#ifdef DBG_MALLOC
	f->file = file;
	f->func = func;
	f->line = line;
#endif

	parallel_insert_free(fm, f);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->fragments -= 1;
#endif
	pkg_threshold_check();

	//LM_ERR("Succes in freeing ! \n");

	lock_release(hash_locks[fm->idx]);
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void parallel_free_dbg_unsafe(struct parallel_block *fm, void *p, const char *file,
                 const char *func, unsigned int line)
#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
void parallel_free_unsafe(struct parallel_block *fm, void *p)
#else
void parallel_free_unsafe(struct parallel_block *fm, void *p, const char *file,
             const char *func, unsigned int line)
#endif
{
	struct parallel_frag *f, *n;

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

	f = F_PARALLEL_FRAG(p);

	check_double_free(p, f, fm);

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "freeing block alloc'ed from %s: %s(%ld)\n",
	        f->file, f->func, f->line);
#endif

	/* attempt to join with a next fragment that also happens to be free */
	n = F_PARALLEL_FRAG_NEXT(f);
	if (((char*)n < (char*)fm->last_frag) &&  frag_is_free(n)) {
		parallel_remove_free(fm, n);
		/* join */
		f->size += n->size + F_PARALLEL_FRAG_OVERHEAD;

		#if defined(DBG_MALLOC) || defined(STATISTICS)
		//fm->real_used -= F_PARALLEL_FRAG_OVERHEAD;
		fm->used += F_PARALLEL_FRAG_OVERHEAD;
		#endif
	}

#ifdef DBG_MALLOC
	f->file = file;
	f->func = func;
	f->line = line;
#endif

	parallel_insert_free(fm, f);
#if defined(DBG_MALLOC) || defined(STATISTICS)
	fm->fragments -= 1;
#endif
	pkg_threshold_check();

	//LM_ERR("Succes in freeing ! \n");
}



#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *parallel_realloc_dbg(struct parallel_block *fm, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line)
#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
void *parallel_realloc(struct parallel_block *fm, void *p, unsigned long size)
#else
void *parallel_realloc(struct parallel_block *fm, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line)
#endif
{
	struct parallel_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct parallel_frag *n;
	void *ptr,*input;

	//LM_ERR("VLAD - F_PARALLEL realloc in block %p of %p \n",fm,p);

	input = p;

	if (p) {
		fm = F_PARALLEL_FRAG(p)->block_ptr;

		lock_get(hash_locks[fm->idx]);

		//LM_ERR("Vlad - forcing our way into the same block for realloc %p, idx = %d \n",fm,fm->idx);
	} else {
		//LM_ERR("Vlad - fresh realloc - we were allocated block %p \n",fm);
	}

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_realloc(%p, %lu->%lu), called from %s: %s(%d)\n",
	        fm->name, p, p ? F_PARALLEL_FRAG(p)->size : 0, size, file, func, line);
	if (p && (p > (void *)fm->last_frag || p < (void *)fm->first_frag)) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif

	if (size == 0) {
		if (p) {
			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			parallel_free_dbg(fm, p, file, func, line);
			#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
			parallel_free(fm, p);
			#else
			parallel_free(fm, p, file, func, line);
			#endif

			lock_release(hash_locks[fm->idx]);
		}
		pkg_threshold_check();
		return 0;
	}

	if (!p)
		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		return parallel_malloc_dbg(fm, size, file, func, line);
		#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
		return parallel_malloc(fm, size);
		#else
		return parallel_malloc(fm, size, file, func, line);
		#endif

	f = F_PARALLEL_FRAG(p);

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	#endif

	size = ROUNDUP(size);
	orig_size = f->size;

	if (f->size > size) {
		//LM_ERR("Vlad - shrink realloc \n");
		/* shrink */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "shrinking from %lu to %lu\n", f->size, size);
		#endif

		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		parallel_split_frag_dbg(fm, f, size, file, "fm_realloc frag", line);
		#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
		parallel_split_frag(fm, f, size);
		#else
		parallel_split_frag(fm, f, size, file, "fm_realloc frag", line);
		#endif

	} else if (f->size < size) {
		//LM_ERR("Vlad - grow realloc \n");
		/* grow */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog, "growing from %lu to %lu\n", f->size, size);
		#endif

		diff = size-f->size;
		n = F_PARALLEL_FRAG_NEXT(f);
		n->block_ptr = fm;

		if (((char*)n < (char*)fm->last_frag) && frag_is_free(n) &&
		 ((n->size+F_PARALLEL_FRAG_OVERHEAD)>=diff)) {
			//LM_ERR("Attempting join \n");

			parallel_remove_free(fm,n);
			/* join */
			f->size += n->size + F_PARALLEL_FRAG_OVERHEAD;

			#if defined(DBG_MALLOC) || defined(STATISTICS)
			//fm->real_used -= F_PARALLEL_FRAG_OVERHEAD;
			fm->used += F_PARALLEL_FRAG_OVERHEAD;
			#endif

			/* split it if necessary */
			if (f->size > size){
				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				parallel_split_frag_dbg(fm, f, size, file, "fm_realloc frag", line);
				#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
				parallel_split_frag(fm, f, size);
				#else
				parallel_split_frag(fm, f, size, file, "fm_realloc frag", line);
				#endif
			}
		} else {
			/* could not join => realloc */
			//LM_ERR("Attempting full realloc \n");

			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			ptr = parallel_malloc_dbg(fm, size, file, func, line);
			#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
			ptr = parallel_malloc(fm, size);
			#else
			ptr = parallel_malloc(fm, size, file, func, line);
			#endif

			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);

				//LM_ERR("Free inside of realloc !!! :( \n");

				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				parallel_free_dbg_unsafe(fm, p, file, func, line);
				#elif !defined F_PARALLEL_MALLOC_DYN && !defined DBG_MALLOC
				parallel_free_unsafe(fm, p);
				#else
				parallel_free_unsafe(fm, p, file, func, line);
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

	f->block_ptr = fm;

	if (input)
		lock_release(hash_locks[fm->idx]);

	pkg_threshold_check();
	return p;
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void parallel_status_dbg(struct parallel_block *fm)
#else
void parallel_status(struct parallel_block *fm)
#endif
{
	struct parallel_frag *f;
	unsigned int i,j,bucket;
	unsigned int h;
	int unused;
	unsigned long size;

	//LM_ERR("VLAD - F_PARALLEL status in block %p \n",fm);

#ifdef DBG_MALLOC
	mem_dbg_htable_t allocd;
	struct mem_dbg_entry *it;
#endif

	/* TODO - 128 hardcode */
	for (bucket=0;bucket<128;bucket++) {
		fm = shm_blocks[bucket]; 
		lock_get(hash_locks[fm->idx]);

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
			f = F_PARALLEL_FRAG_NEXT(f)) {
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
		for(h=0,i=0,size=0;h<F_PARALLEL_HASH_SIZE;h++){
			unused=0;
			for (f=fm->free_hash[h].first,j=0; f;
					size+=f->size,f=f->u.nxt_free,i++,j++){ }
			if (j) LM_GEN1(memdump,"hash = %3d fragments no.: %5d, unused: %5d\n\t\t"
								" bucket size: %9lu - %9lu (first %9lu)\n",
								h, j, unused, F_PARALLEL_UN_HASH(h),
							((h<=F_PARALLEL_MALLOC_OPTIMIZE/ROUNDTO)?1:2)* F_PARALLEL_UN_HASH(h),
								fm->free_hash[h].first->size
					);
			if (j!=fm->free_hash[h].no){
				LM_CRIT("different free frag. count: %d!=%ld"
						" for hash %3d\n", j, fm->free_hash[h].no, h);
			}

		}
		LM_GEN1(memdump, "TOTAL: %6d free fragments = %6lu free bytes\n", i, size);
		LM_GEN1(memdump, "TOTAL: %u overhead\n", (unsigned int)F_PARALLEL_FRAG_OVERHEAD );
		LM_GEN1(memdump, "-----------------------------\n");

		lock_release(hash_locks[fm->idx]);
	}
}

#define F_PARALLEL_MALLOC_DYN

