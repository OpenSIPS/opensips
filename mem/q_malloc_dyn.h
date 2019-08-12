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

/* for any questions on the complex ifdef logic, see mem/f_malloc_dyn.h */

/* returns 0 on success, -1 on error;
 * new_size < size & rounded-up already!*/
static inline
#if !defined INLINE_ALLOC && defined DBG_MALLOC
int qm_split_frag_dbg(struct qm_block *qm, struct qm_frag *f,
                      unsigned long new_size, const char *file,
                      const char *func, unsigned int line)
#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
int qm_split_frag(struct qm_block *qm, struct qm_frag *f,
                  unsigned long new_size)
#else
int qm_split_frag(struct qm_block *qm, struct qm_frag *f,
                  unsigned long new_size, const char *file, const char *func,
                  unsigned int line)
#endif
{
	unsigned long rest;
	struct qm_frag *n;
	struct qm_frag_end *end;

	rest=f->size-new_size;
#ifdef MEM_FRAG_AVOIDANCE
	if ((rest> (FRAG_OVERHEAD+Q_MALLOC_OPTIMIZE))||
		(rest>=(FRAG_OVERHEAD+new_size))){/* the residue fragm. is big enough*/
#else
	if (rest>(FRAG_OVERHEAD+MIN_FRAG_SIZE)){
#endif
		f->size=new_size;
		/*split the fragment*/
		end=FRAG_END(f);
		end->size=new_size;
		n=(struct qm_frag*)((char*)end+sizeof(struct qm_frag_end));
		n->size=rest-FRAG_OVERHEAD;
		FRAG_END(n)->size=n->size;
		FRAG_CLEAR_USED(n); /* never used */
#if defined(DBG_MALLOC) || defined(STATISTICS)
		qm->used-=FRAG_OVERHEAD;
#endif
#ifdef DBG_MALLOC
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



#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *qm_malloc_dbg(struct qm_block *qm, unsigned long size,
					const char *file, const char *func, unsigned int line)
#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
void *qm_malloc(struct qm_block *qm, unsigned long size)
#else
void *qm_malloc(struct qm_block *qm, unsigned long size,
					const char *file, const char *func, unsigned int line)
#endif
{
	struct qm_frag *f;
	int hash;

#if defined DBG_MALLOC || defined Q_MALLOC_DYN
	unsigned int list_cntr;
	list_cntr = 0;
#endif

#if defined DBG_MALLOC
	LM_GEN1(memlog, "%s_malloc (%lu), called from %s: %s(%d)\n",
		qm->name, size, file, func, line);
#endif

	/*size must be a multiple of 8*/
	size=ROUNDUP(size);
	if (size>(qm->size-qm->real_used)) {
		LM_ERR(oom_errorf, qm->name, qm->size - qm->real_used, size,
				qm->name[0] == 'p' ? "M" : "m");
		pkg_threshold_check();
		return 0;
	}

	/*search for a suitable free frag*/
#if !defined INLINE_ALLOC && defined DBG_MALLOC
	if ((f=qm_find_free(qm, size, &hash, &list_cntr))!=0){
#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
	if ((f=qm_find_free(qm, size, &hash))!=0){
#else
	if ((f=qm_find_free(qm, size, &hash, &list_cntr))!=0){
#endif
		/* we found it!*/
		/*detach it from the free list*/
#ifdef DBG_MALLOC
		qm_debug_frag(qm, f);
#endif
		qm_detach_free(qm, f);
		/*mark it as "busy"*/
		f->u.is_free=0;
		qm->free_hash[hash].no--;
		/* we ignore split return */

		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		qm_split_frag_dbg(qm, f, size, file, "qm_malloc frag", line);
		#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
		qm_split_frag(qm, f, size);
		#else
		qm_split_frag(qm, f, size, file, "qm_malloc frag", line);
		#endif

		if (qm->max_real_used<qm->real_used)
			qm->max_real_used=qm->real_used;

#ifdef DBG_MALLOC
		f->file=file;
		f->func=func;
		f->line=line;
		f->check=ST_CHECK_PATTERN;
		/*  FRAG_END(f)->check1=END_CHECK_PATTERN1;
			FRAG_END(f)->check2=END_CHECK_PATTERN2;*/
		LM_GEN1(memlog, "%s_malloc(%lu), returns address %p frag. %p "
			"(size=%lu) on %d -th hit\n",
			 qm->name, size, (char*)f+sizeof(struct qm_frag), f, f->size, list_cntr );
#endif

		pkg_threshold_check();
		qm->fragments += 1;
		return (char*)f+sizeof(struct qm_frag);
	}

	LM_ERR(oom_errorf, qm->name, qm->size - qm->real_used, size,
			qm->name[0] == 'p' ? "M" : "m");
	pkg_threshold_check();
	return 0;
}



#if !defined INLINE_ALLOC && defined DBG_MALLOC
void qm_free_dbg(struct qm_block *qm, void *p,
                 const char *file, const char *func, unsigned int line)
#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
void qm_free(struct qm_block *qm, void *p)
#else
void qm_free(struct qm_block *qm, void *p,
             const char *file, const char *func, unsigned int line)
#endif
{
	struct qm_frag *f;
	struct qm_frag *prev;
	struct qm_frag *next;
	unsigned long size;

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_free(%p), called from %s: %s(%d)\n",
	        qm->name, p, file, func, line);
#endif
	if (!p) {
		LM_GEN1(memlog, "free(NULL) called\n");
		return;
	}
#ifdef DBG_MALLOC
	if (p>(void*)qm->last_frag_end || p<(void*)qm->first_frag){
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
#endif
	f=QM_FRAG(p);
#ifdef DBG_MALLOC
	qm_debug_frag(qm, f);
	if (f->u.is_free){
		LM_CRIT("freeing already freed pointer,"
				" first free: %s: %s(%ld) - aborting\n",
				f->file, f->func, f->line);
		abort();
	}
	LM_GEN1( memlog, "freeing frag. %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
#endif

	size=f->size;
	/* join packets if possible*/
	prev=next=0;
	next=FRAG_NEXT(f);
	if (((char*)next < (char*)qm->last_frag_end) &&( next->u.is_free)){
		/* join */
#ifdef DBG_MALLOC
		qm_debug_frag(qm, next);
#endif
		qm_detach_free(qm, next);
		size+=next->size+FRAG_OVERHEAD;
#if defined(DBG_MALLOC) || defined(STATISTICS)
		qm->used+=FRAG_OVERHEAD;
#endif
		qm->free_hash[GET_HASH(next->size)].no--; /* FIXME slow */
	}

	if (f > qm->first_frag){
		prev=FRAG_PREV(f);
		/*	(struct qm_frag*)((char*)f - (struct qm_frag_end*)((char*)f-
								sizeof(struct qm_frag_end))->size);*/
#ifdef DBG_MALLOC
		qm_debug_frag(qm, prev);
#endif
		if (prev->u.is_free){
			/*join*/
			qm_detach_free(qm, prev);
			size+=prev->size+FRAG_OVERHEAD;
#if defined(DBG_MALLOC) || defined(STATISTICS)
			qm->used+=FRAG_OVERHEAD;
#endif
			qm->free_hash[GET_HASH(prev->size)].no--; /* FIXME slow */
			f=prev;
		}
	}
	f->size=size;
	FRAG_END(f)->size=f->size;
#ifdef DBG_MALLOC
	f->file=file;
	f->func=func;
	f->line=line;
#endif
	qm_insert_free(qm, f);
	qm->fragments -= 1;
	pkg_threshold_check();
}



#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *qm_realloc_dbg(struct qm_block *qm, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line)
#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
void *qm_realloc(struct qm_block *qm, void *p, unsigned long size)
#else
void *qm_realloc(struct qm_block *qm, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line)
#endif
{
	struct qm_frag *f;
	unsigned long diff;
	unsigned long orig_size;
	struct qm_frag *n;
	void *ptr;

	#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_realloc(%p, %lu->%lu), called from %s: %s(%d)\n",
			qm->name, p, p ? QM_FRAG(p)->size:0, size, file, func, line);
	if (p && (p > (void *)qm->last_frag_end || p < (void *)qm->first_frag)) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
	#endif

	if (size == 0) {
		if (p)
			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			qm_free_dbg(qm, p, file, func, line);
			#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
			qm_free(qm, p);
			#else
			qm_free(qm, p, file, func, line);
			#endif
		pkg_threshold_check();
		return 0;
	}

	if (!p)
		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		return qm_malloc_dbg(qm, size, file, func, line);
		#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
		return qm_malloc(qm, size);
		#else
		return qm_malloc(qm, size, file, func, line);
		#endif

	f = QM_FRAG(p);

	#ifdef DBG_MALLOC
	qm_debug_frag(qm, f);
	LM_GEN1( memlog, "realloc'ing frag %p alloc'ed from %s: %s(%ld)\n",
			f, f->file, f->func, f->line);
	if (f->u.is_free) {
		LM_CRIT("trying to realloc an already freed "
				"pointer %p , fragment %p -- aborting\n", p, f);
		abort();
	}
	#endif

	/* find first acceptable size */
	size=ROUNDUP(size);
	if (f->size > size) {
		orig_size=f->size;
		/* shrink */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog,"shrinking from %lu to %lu\n", f->size, size);
		#endif

		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		qm_split_frag_dbg(qm, f, size, file, "qm_realloc frag", line);
		#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
		qm_split_frag(qm, f, size);
		#else
		qm_split_frag(qm, f, size, file, "qm_realloc frag", line);
		#endif

	} else if (f->size < size) {
		/* grow */
		#ifdef DBG_MALLOC
		LM_GEN1( memlog, "growing from %lu to %lu\n", f->size, size);
		#endif

		orig_size=f->size;
		diff=size-f->size;
		n=FRAG_NEXT(f);
		if (((char*)n < (char*)qm->last_frag_end) &&
				(n->u.is_free)&&((n->size+FRAG_OVERHEAD)>=diff)){
			/* join  */
			qm_detach_free(qm, n);
			qm->free_hash[GET_HASH(n->size)].no--; /*FIXME: slow*/
			f->size+=n->size+FRAG_OVERHEAD;
			#if defined(DBG_MALLOC) || defined(STATISTICS)
			qm->used+=FRAG_OVERHEAD;
			#endif
			FRAG_END(f)->size=f->size;
			/* end checks should be ok */
			/* split it if necessary */
			if (f->size > size ) {
				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				qm_split_frag_dbg(qm, f, size, file, "qm_realloc frag", line);
				#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
				qm_split_frag(qm, f, size);
				#else
				qm_split_frag(qm, f, size, file, "qm_realloc frag", line);
				#endif
			}
		} else {
			/* could not join => realloc */
			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			ptr = qm_malloc_dbg(qm, size, file, func, line);
			#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
			ptr = qm_malloc(qm, size);
			#else
			ptr = qm_malloc(qm, size, file, func, line);
			#endif

			if (ptr) {
				/* copy, need by libssl */
				memcpy(ptr, p, orig_size);

				#if !defined INLINE_ALLOC && defined DBG_MALLOC
				qm_free_dbg(qm, p, file, func, line);
				#elif !defined Q_MALLOC_DYN && !defined DBG_MALLOC
				qm_free(qm, p);
				#else
				qm_free(qm, p, file, func, line);
				#endif
			}

			p = ptr;
		}
	} else {
		/* do nothing */
		#ifdef DBG_MALLOC
		LM_GEN1(memlog,"doing nothing, same size: %lu - %lu\n", f->size, size);
		#endif
	}

	#ifdef DBG_MALLOC
	LM_GEN1(memlog,"returning %p\n", p);
	#endif

	pkg_threshold_check();
	return p;
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void qm_status_dbg(struct qm_block *qm)
#else
void qm_status(struct qm_block *qm)
#endif
{
	struct qm_frag *f;
	int i,j;
	int h;
	int unused;

#ifdef DBG_MALLOC
	mem_dbg_htable_t allocd;
	struct mem_dbg_entry *it;
#endif

	LM_GEN1(memdump, "qm_status (%p):\n", qm);
	if (!qm) return;

#if defined(DBG_MALLOC) || defined(STATISTICS)
	LM_GEN1(memdump, " heap size= %lu\n", qm->size);
	LM_GEN1(memdump, " used= %lu, used+overhead=%lu, free=%lu\n",
			qm->used, qm->real_used, qm->size-qm->real_used);
	LM_GEN1(memdump, " max used (+overhead)= %lu\n", qm->max_real_used);
#endif

#ifdef DBG_MALLOC
	dbg_ht_init(allocd);

	for (f = qm->first_frag; f >= qm->first_frag &&
	        (void *)f < (void *)qm->last_frag_end; f = FRAG_NEXT(f)) {
		if (!f->u.is_free && f->file)
			if (dbg_ht_update(allocd, f->file, f->func, f->line, f->size) < 0) {
				LM_ERR("Unable to update alloc'ed. memory summary\n");
				dbg_ht_free(allocd);
				return;
			}
	}

	if ((void *)f != (void *)qm->last_frag_end)
		LM_GEN1(memdump, "failed to walk through all fragments (%p %p %p)\n",
		        f, qm->first_frag, qm->last_frag_end);

	LM_GEN1(memdump, " dumping summary of all alloc'ed. fragments:\n");
	LM_GEN1(memdump, "----------------------------------------------------\n");
	LM_GEN1(memdump, "total_bytes | num_allocations x [file: func, line]\n");
	LM_GEN1(memdump, "----------------------------------------------------\n");
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

	LM_GEN1(memdump, " dumping free list stats :\n");
	for(h=0,i=0;h<QM_HASH_SIZE;h++){
		unused=0;
		for (f=qm->free_hash[h].head.u.nxt_free,j=0;
				f!=&(qm->free_hash[h].head); f=f->u.nxt_free, i++, j++){
				if (!FRAG_WAS_USED(f)){
					unused++;
#ifdef DBG_MALLOC
					LM_GEN1(memdump, "unused fragm.: hash = %3d, fragment %p,"
						" address %p size %lu, created from %s: %s(%lu)\n",
					    h, f, (char*)f+sizeof(struct qm_frag), f->size,
						f->file, f->func, f->line);
#endif
				}
		}

		if (j) LM_GEN1(memdump, "hash= %3d. fragments no.: %5d, unused: %5d\n"
					"\t\t bucket size: %9lu - %9ld (first %9lu)\n",
					h, j, unused, UN_HASH(h),
					((h<=Q_MALLOC_OPTIMIZE/QM_ROUNDTO)?1:2)*UN_HASH(h),
					qm->free_hash[h].head.u.nxt_free->size
				);
		if (j!=qm->free_hash[h].no){
			LM_CRIT("different free frag. count: %d!=%lu"
				" for hash %3d\n", j, qm->free_hash[h].no, h);
		}

	}
	LM_GEN1(memdump, "-----------------------------\n");
}

#define Q_MALLOC_DYN
