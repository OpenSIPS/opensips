/*
 * simple & fast malloc library
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

#ifndef q_malloc_h
#define q_malloc_h

#include <stdio.h>
#include "meminfo.h"
#include "../dprint.h"
#include "common.h"

#undef UN_HASH

#if defined(__CPU_sparc64) || defined(__CPU_sparc)
/* tricky, on sun in 32 bits mode long long must be 64 bits aligned
 * but long can be 32 bits aligned => malloc should return long long
 * aligned memory */
	#define QM_ROUNDTO		sizeof(long long)
#else
	/* address alignment, in bytes (2^n) */
	#define QM_ROUNDTO		sizeof(void *)
#endif

#define Q_MALLOC_OPTIMIZE_FACTOR 14UL /*used below */
#define Q_MALLOC_OPTIMIZE  ((unsigned long)(1UL<<Q_MALLOC_OPTIMIZE_FACTOR))
								/* size to optimize for,
									(most allocs <= this size),
									must be 2^k */

#define QM_HASH_SIZE ((unsigned long)(Q_MALLOC_OPTIMIZE/QM_ROUNDTO + \
		(sizeof(long)*8 - Q_MALLOC_OPTIMIZE_FACTOR) + 1))

#define QM_FRAG(p) \
	((struct qm_frag *)((char *)(p) - sizeof(struct qm_frag)))

/* hash structure:
 * 0 .... Q_MALLOC_OPTIMIZE/QM_ROUNDTO  - small buckets, size increases with
 *                            QM_ROUNDTO from bucket to bucket
 * +1 .... end -  size = 2^k, big buckets */

struct qm_frag {
	unsigned long size;
	union {
		struct qm_frag *nxt_free;
		long is_free;
	} u;
#ifdef DBG_MALLOC
	const char *file;
	const char *func;
	unsigned long line;
	unsigned long check;
#endif
#ifdef SHM_EXTRA_STATS
	unsigned long statistic_index;
#endif
} __attribute__ ((aligned (QM_ROUNDTO)));

#define QM_FRAG_OVERHEAD (sizeof(struct qm_frag))

struct qm_frag_end {
#ifdef DBG_MALLOC
	unsigned long check1;
	unsigned long check2;
	unsigned long reserved1;
	unsigned long reserved2;
#endif
	unsigned long size;
	struct qm_frag *prev_free;
} __attribute__ ((aligned (QM_ROUNDTO)));

struct qm_frag_lnk {
	struct qm_frag head;
	struct qm_frag_end tail;
	unsigned long no;
};

struct qm_block {
	char *name; /* purpose of this memory block */

	unsigned long size; /* total size */
	unsigned long used; /* alloc'ed size*/
	unsigned long real_used; /* used+malloc overhead*/
	unsigned long max_real_used;
	unsigned long fragments; /* number of fragments in use */

	struct qm_frag *first_frag;
	struct qm_frag_end *last_frag_end;

	struct qm_frag_lnk free_hash[QM_HASH_SIZE];
} __attribute__ ((aligned (QM_ROUNDTO)));

struct qm_block *qm_malloc_init(char *address, unsigned long size, char *name);

#ifdef DBG_MALLOC
void *qm_malloc(struct qm_block*, unsigned long size, const char *file,
                const char *func, unsigned int line);
void  qm_free(struct qm_block*, void *p, const char *file, const char *func,
				unsigned int line);
void *qm_realloc(struct qm_block*, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
#ifndef INLINE_ALLOC
void *qm_malloc_dbg(struct qm_block*, unsigned long size, const char *file,
                    const char *func, unsigned int line);
void qm_free_dbg(struct qm_block*, void *p, const char *file, const char *func,
				unsigned int line);
void *qm_realloc_dbg(struct qm_block*, void *p, unsigned long size,
					const char *file, const char *func, unsigned int line);
#endif
#else
void *qm_malloc(struct qm_block*, unsigned long size);
void  qm_free(struct qm_block*, void *p);
void *qm_realloc(struct qm_block*, void *p, unsigned long size);
#endif

void qm_status(struct qm_block*);
#if !defined INLINE_ALLOC && defined DBG_MALLOC
void qm_status_dbg(struct qm_block*);
#endif
void qm_info(struct qm_block*, struct mem_info*);

/*
 * On success, returns the currrent number of fragments
 * Internally aborts on failure
 */
int qm_mem_check(struct qm_block *qm);

#ifdef SHM_EXTRA_STATS
static inline unsigned long qm_frag_size(void *p)
{
	if (!p)
		return 0;

	return QM_FRAG(p)->size;
}

void qm_stats_core_init(struct qm_block *qm, int core_index);
unsigned long qm_stats_get_index(void *ptr);
void qm_stats_set_index(void *ptr, unsigned long idx);

#ifdef DBG_MALLOC
static inline const char *qm_frag_file(void *p) { return QM_FRAG(p)->file; }
static inline const char *qm_frag_func(void *p) { return QM_FRAG(p)->func; }
static inline unsigned long qm_frag_line(void *p) { return QM_FRAG(p)->line; }
#else
static inline const char *qm_frag_file(void *p) { return NULL; }
static inline const char *qm_frag_func(void *p) { return NULL; }
static inline unsigned long qm_frag_line(void *p) { return 0; }
#endif
#endif

#ifdef STATISTICS
static inline unsigned long qm_get_size(struct qm_block *qm)
{
	return qm->size;
}
static inline unsigned long qm_get_used(struct qm_block *qm)
{
	return qm->used;
}
static inline unsigned long qm_get_free(struct qm_block *qm)
{
	return qm->size - qm->real_used;
}
static inline unsigned long qm_get_real_used(struct qm_block *qm)
{
	return qm->real_used;
}
static inline unsigned long qm_get_max_real_used(struct qm_block *qm)
{
	return qm->max_real_used;
}
static inline unsigned long qm_get_frags(struct qm_block *qm)
{
	return qm->fragments;
}
#endif /* STATISTICS */

#endif
