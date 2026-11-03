/*
 * Copyright (C) 2026 Yury Kirsanov
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

/* Thin public API over hg_cell_alloc()/hg_cell_free() (hg_arena.c), in the
 * other _dyn.h files' ifdef convention (single/multi x dbg/non-dbg) */

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *hg_malloc_dbg(struct hg_block *hb, unsigned long size,
                    const char *file, const char *func, unsigned int line)
#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
void *hg_malloc(struct hg_block *hb, unsigned long size)
#else
void *hg_malloc(struct hg_block *hb, unsigned long size,
                const char *file, const char *func, unsigned int line)
#endif
{
	void *p;

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_malloc(%lu), called from %s: %s(%d)\n", hb->name,
		size, file, func, line);
#endif
#if HG_CELL_TAKES_DBG_ARGS
	p = hg_cell_alloc(hb, size, file, func, line);
#else
	p = hg_cell_alloc(hb, size);
#endif
#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_malloc(%lu), returns address %p\n", hb->name,
		size, p);
#endif
	return p;
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void hg_free_dbg(struct hg_block *hb, void *p, const char *file,
                 const char *func, unsigned int line)
#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
void hg_free(struct hg_block *hb, void *p)
#else
void hg_free(struct hg_block *hb, void *p, const char *file,
             const char *func, unsigned int line)
#endif
{
#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_free(%p), called from %s: %s(%d)\n", hb->name, p,
		file, func, line);
	if (p && !hg_owns_any(HG_HDR(p))) {
		LM_CRIT("bad pointer %p (out of memory block!) - aborting\n", p);
		abort();
	}
#endif
#if HG_CELL_TAKES_DBG_ARGS
	hg_cell_free(hb, p, file, func, line);
#else
	hg_cell_free(hb, p);
#endif
}

#if !defined INLINE_ALLOC && defined DBG_MALLOC
void *hg_realloc_dbg(struct hg_block *hb, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line)
#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
void *hg_realloc(struct hg_block *hb, void *p, unsigned long size)
#else
void *hg_realloc(struct hg_block *hb, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line)
#endif
{
	unsigned char cls;
	unsigned long cur_total = 0, need_total, cur_payload = 0, copy, asked;
	union hg_hdr_w hw;
	unsigned short hsum;
	int st;
	void *ptr;
	struct hg_block *src;

#ifdef DBG_MALLOC
	LM_GEN1(memlog, "%s_realloc(%p, ->%lu), called from %s: %s(%d)\n",
		hb->name, p, size, file, func, line);
#endif

	if (size == 0) {
		if (p)
			#if !defined INLINE_ALLOC && defined DBG_MALLOC
			hg_free_dbg(hb, p, file, func, line);
			#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
			hg_free(hb, p);
			#else
			hg_free(hb, p, file, func, line);
			#endif
		return NULL;
	}

	if (!p)
		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		return hg_malloc_dbg(hb, size, file, func, line);
		#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
		return hg_malloc(hb, size);
		#else
		return hg_malloc(hb, size, file, func, line);
		#endif

	/* refused before the in-place arithmetic below, which would wrap */
	if (size > hb->hcap) {
		hg_lock_enter(hb, HG_LK_REFILL);
		if (hg_oom_first(hb, size))
			LM_ERR("%s: a %lu byte realloc request exceeds the arena's "
				"%lu byte cap - refused, the allocation is unchanged; "
				"further failures are summarised every 30 s\n",
				hb->name, size, hb->hcap);
		hg_lock_leave(hb);
		return NULL;
	}

	src = hg_owner(HG_HDR(p));
	if (!src) {
		LM_CRIT("%s: realloc of %p, which is from no live arena - "
			"refusing it\n", hb->name, p);
		hg_corrupt(hb, HG_C_FOREIGN_PTR);
		return NULL;
	}
	if (!hg_backed(src, HG_HDR(p))) {
		LM_CRIT("%s: realloc of %p, which points into memory the arena "
			"gave back to the kernel - refusing it\n", hb->name, p);
		hg_corrupt(hb, HG_C_DOUBLE_FREE);
		return NULL;
	}

	/* only an intact LIVE header: its class byte gives the size below */
	st = hg_hdr_read(HG_HDR(p), &hw, &hsum);
	if (!hg_st_live(st)) {
		LM_CRIT("%s: realloc of %p, which is %s - refusing it\n",
			hb->name, p, st < 0 ? "damaged or not a cell" : "free");
		hg_corrupt(hb, st < 0 ? HG_C_HEADER : HG_C_DOUBLE_FREE);
		return NULL;
	}
	/* cur_payload is what the caller may read from @p; a small cell whose
	 * class still fits is kept, a large one always moves */
	cls = HG_CLASS(p);
	if (cls == HG_LARGE_MARKER) {
		cur_total = hg_large_frag_size_at(HG_HDR(p) - HG_LFRAG_HDR_SIZE);
		cur_payload = cur_total > HG_LFRAG_HDR_SIZE + HG_CELL_HDR ?
			cur_total - HG_LFRAG_HDR_SIZE - HG_CELL_HDR : 0;
	} else if (cls >= HG_NCLASSES) {
		LM_CRIT("%s: cell %p carries invalid class %u - aborting "
			"realloc\n", hb->name, p, cls);
		hg_corrupt(hb, HG_C_BAD_CLASS);
		return NULL;
	} else {
		cur_total = hg_cell_total_size(cls);
		cur_payload = cur_total > HG_CELL_HDR ? cur_total - HG_CELL_HDR : 0;
		/* a guarded cell stays guarded, an unguarded one unguarded */
		need_total = ((size + (st == HG_ST_LIVE_G ? HG_GUARD_ROOM : 0) +
			HG_ROUNDTO - 1) / HG_ROUNDTO) * HG_ROUNDTO + HG_CELL_HDR;
		if (hb->dbg)
			need_total += HG_DBG_TAIL;
		if (need_total <= cur_total) {
			/* the dbg tail or guard moves to the new size, checked
			 * first so a write past the old size is still seen */
			struct hg_block *own = hb->dbg || HG_SAN_ON ||
				st == HG_ST_LIVE_G ? hg_owner(HG_HDR(p)) : NULL;

			if (own) {
				hg_san_open(own, HG_HDR(p), cur_payload);
				if (own->dbg) {
					hg_dbg_tail_check(own, HG_HDR(p), cur_payload);
					hg_dbg_tail_set(HG_HDR(p), cur_payload, size);
				} else if (st == HG_ST_LIVE_G) {
					if (!hg_guard_ok(HG_HDR(p), hsum, cur_payload, &asked))
						hg_guard_bad(own, HG_HDR(p), cur_payload, asked);
					hg_guard_set(HG_HDR(p), hsum, cur_payload, size);
				}
				hg_san_keep(own, HG_HDR(p), cur_payload, size);
			}
			return p;
		}
	}

	#if !defined INLINE_ALLOC && defined DBG_MALLOC
	ptr = hg_malloc_dbg(hb, size, file, func, line);
	#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
	ptr = hg_malloc(hb, size);
	#else
	ptr = hg_malloc(hb, size, file, func, line);
	#endif

	if (ptr) {
		/* min(old, new): a shrink from the large tier gets here */
		copy = cur_payload < size ? cur_payload : size;
		/* the copy may read past what the caller asked for, so a
		 * sanitizer must see the copied bytes open first (hg_san.h) */
		if (HG_SAN_ON) {
			struct hg_block *own = hg_owner(HG_HDR(p));

			if (own)
				hg_san_open(own, HG_HDR(p), copy);
		}
		memcpy(ptr, p, copy);
		#if !defined INLINE_ALLOC && defined DBG_MALLOC
		hg_free_dbg(hb, p, file, func, line);
		#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
		hg_free(hb, p);
		#else
		hg_free(hb, p, file, func, line);
		#endif
	}

	return ptr;
}

#define HG_MALLOC_DYN
