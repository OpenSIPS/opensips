/*
 * simple, very fast, malloc library
 *
 * Copyright (C) 2001-2003 FhG Fokus
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

#ifndef f_malloc_h
#define f_malloc_h

#include <stdio.h>
#include "meminfo.h"
#include "common.h"

#undef ROUNDTO
#undef UN_HASH

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
/* tricky, on sun in 32 bits mode long long must be 64 bits aligned
 * but long can be 32 bits aligned => malloc should return long long
 * aligned memory */
	#define ROUNDTO		sizeof(long long)
#else
	#define ROUNDTO		sizeof(void *) /* address alignment, in bytes (2^n) */
#endif

#define F_MALLOC_OPTIMIZE_FACTOR 14UL /*used below */

/* size to optimize for, (most allocs <= this size), must be 2^k */
#define F_MALLOC_OPTIMIZE  (1UL << F_MALLOC_OPTIMIZE_FACTOR)

#define F_HASH_SIZE (F_MALLOC_OPTIMIZE/ROUNDTO + \
		(sizeof(long)*8-F_MALLOC_OPTIMIZE_FACTOR)+1)

/* get the fragment which corresponds to a pointer */
#define FM_FRAG(p) \
	((struct fm_frag *)((char *)(p) - sizeof(struct fm_frag)))

/* hash structure:
 * 0 .... F_MALLOC_OPTIMIZE/ROUNDTO  - small buckets, size increases with
 *                            ROUNDTO from bucket to bucket
 * +1 .... end -  size = 2^k, big buckets */

struct fm_frag {
	unsigned long size;
	union {
		struct fm_frag *nxt_free;
		long reserved;
	} u;
	struct fm_frag **prev;
#ifdef DBG_MALLOC
	const char *file;
	const char *func;
	unsigned long line;
#endif

#ifdef SHM_EXTRA_STATS
	unsigned long statistic_index;
#endif
} __attribute__ ((aligned (ROUNDTO)));

#define FM_FRAG_OVERHEAD (sizeof(struct fm_frag))

struct fm_frag_lnk {
	struct fm_frag *first;
	unsigned long no;
};

struct fm_block {
	char *name; /* purpose of this memory block */

	unsigned long size; /* total size */
	unsigned long fragments; /* number of fragments in use */
#if defined(DBG_MALLOC) || defined(STATISTICS)
	unsigned long used; /* alloc'ed size */
	unsigned long real_used; /* used + malloc overhead */
	unsigned long max_real_used;
#endif

	struct fm_frag *first_frag;
	struct fm_frag *last_frag;

	struct fm_frag_lnk free_hash[F_HASH_SIZE];
} __attribute__ ((aligned (ROUNDTO)));

struct fm_block *fm_malloc_init(char *address, unsigned long size, char *name);

#ifdef DBG_MALLOC
void *fm_malloc(struct fm_block *fm, unsigned long size,
                const char *file, const char *func, unsigned int line);
void fm_free(struct fm_block *fm, void *p, const char *file,
             const char *func, unsigned int line);
void *fm_realloc(struct fm_block *fm, void *p, unsigned long size,
                 const char *file, const char *func, unsigned int line);
#ifndef INLINE_ALLOC
void *fm_malloc_dbg(struct fm_block *fm, unsigned long size,
                    const char *file, const char *func, unsigned int line);
void fm_free_dbg(struct fm_block *fm, void *p, const char *file,
                 const char *func, unsigned int line);
void *fm_realloc_dbg(struct fm_block *fm, void *p, unsigned long size,
                     const char *file, const char *func, unsigned int line);
#endif
#else
void *fm_malloc(struct fm_block *fm, unsigned long size);
void fm_free(struct fm_block *fm, void *p);
void *fm_realloc(struct fm_block *fm, void *p, unsigned long size);
#endif

void fm_status(struct fm_block *);
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void fm_status_dbg(struct fm_block *);
#endif
void fm_info(struct fm_block *, struct mem_info *);

#ifdef SHM_EXTRA_STATS
static inline unsigned long fm_frag_size(void *p)
{
	if (!p)
		return 0;

	return FM_FRAG(p)->size;
}

void fm_stats_core_init(struct fm_block *fm, int core_index);
unsigned long fm_stats_get_index(void *ptr);
void fm_stats_set_index(void *ptr, unsigned long idx);

#ifdef DBG_MALLOC
static inline const char *fm_frag_file(void *p) { return FM_FRAG(p)->file; }
static inline const char *fm_frag_func(void *p) { return FM_FRAG(p)->func; }
static inline unsigned long fm_frag_line(void *p) { return FM_FRAG(p)->line; }
#else
static inline const char *fm_frag_file(void *p) { return NULL; }
static inline const char *fm_frag_func(void *p) { return NULL; }
static inline unsigned long fm_frag_line(void *p) { return 0; }
#endif
#endif

#ifdef STATISTICS
static inline unsigned long fm_get_size(struct fm_block *fm)
{
	return fm->size;
}
static inline unsigned long fm_get_used(struct fm_block *fm)
{
	return fm->used;
}
static inline unsigned long fm_get_free(struct fm_block *fm)
{
	return fm->size - fm->real_used;
}
static inline unsigned long fm_get_real_used(struct fm_block *fm)
{
	return fm->real_used;
}
static inline unsigned long fm_get_max_real_used(struct fm_block *fm)
{
	return fm->max_real_used;
}
static inline unsigned long fm_get_frags(struct fm_block *fm)
{
	return fm->fragments;
}
#endif /*STATISTICS*/

#endif
