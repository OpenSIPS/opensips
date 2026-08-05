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

/*
 * Thin public-API layer over hg_cell_alloc()/hg_cell_free() (hg_arena.c).
 * Much simpler than f_malloc_dyn.h/q_malloc_dyn.h's split_frag machinery:
 * fixed size classes mean there is no fragment-splitting concept here at
 * all - "does size X fit in cell class C" is a table lookup, not a runtime
 * decision. Same ifdef-spaghetti convention as the other _dyn.h files
 * though, for the same reasons (single/multi allocator x dbg/non-dbg).
 */

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
	if (p && ((unsigned long)p < hb->lo || (unsigned long)p > hb->hi)) {
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
	unsigned int cur_total = 0, need_total;
	void *ptr;

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

	/* fixed size classes: if the new size still fits the SAME class
	 * (accounting for the hidden header, same rule hg_cell_alloc() uses
	 * to pick a class), the existing cell is already big enough - no
	 * copy, no reallocation, unlike f_malloc's frag split/merge.
	 *
	 * Large objects (hg_large.c) take the simple path: always alloc new +
	 * copy + free old, no in-place grow/shrink via the boundary-tag
	 * frag's neighbors. That optimization is real future work, not
	 * needed for correctness - large reallocs are rarer still than large
	 * allocs to begin with. */
	cls = HG_CLASS(p);
	if (cls == HG_LARGE_MARKER) {
		cur_total = hg_large_frag_size_at(HG_HDR(p) - HG_LFRAG_HDR_SIZE);
	} else if (cls >= HG_NCLASSES) {
		LM_CRIT("%s: cell %p carries invalid class %u - aborting "
			"realloc\n", hb->name, p, cls);
		return NULL;
	} else {
		cur_total = hg_cell_total_size(cls);
		need_total = ((size + HG_ROUNDTO - 1) / HG_ROUNDTO) * HG_ROUNDTO + HG_CELL_HDR;
		if (need_total <= cur_total)
			return p;
	}

	#if !defined INLINE_ALLOC && defined DBG_MALLOC
	ptr = hg_malloc_dbg(hb, size, file, func, line);
	#elif !defined HG_MALLOC_DYN && !defined DBG_MALLOC
	ptr = hg_malloc(hb, size);
	#else
	ptr = hg_malloc(hb, size, file, func, line);
	#endif

	if (ptr) {
		memcpy(ptr, p, cur_total > HG_CELL_HDR ? cur_total - HG_CELL_HDR : 0);
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
