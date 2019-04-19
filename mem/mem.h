/*
 * memory related stuff (malloc & friends)
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

#ifndef mem_h
#define mem_h

#include <stdlib.h>

#include "../config.h"
#include "../dprint.h"

#include "mem_funcs.h"

int set_pkg_mm(const char *mm_name);

#ifdef PKG_MALLOC
#include "common.h"

extern char *mem_pool;
extern enum osips_mm mem_allocator_pkg;

#ifdef STATISTICS
#define PKG_TOTAL_SIZE_IDX       0
#define PKG_USED_SIZE_IDX        1
#define PKG_REAL_USED_SIZE_IDX   2
#define PKG_MAX_USED_SIZE_IDX    3
#define PKG_FREE_SIZE_IDX        4
#define PKG_FRAGMENTS_SIZE_IDX   5
typedef unsigned long pkg_status_holder[6];
void set_pkg_stats(pkg_status_holder*);
#else
#define set_pkg_stats( _x )
#define init_pkg_stats( _x )  0
#endif

#ifndef INLINE_ALLOC
#ifdef DBG_MALLOC
extern void *(*gen_pkg_malloc)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void (*gen_pkg_free)(void *blk, void *p,
                        const char *file, const char *func, unsigned int line);
#else
extern void *(*gen_pkg_malloc)(void *blk, unsigned long size);
extern void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size);
extern void (*gen_pkg_free)(void *blk, void *p);
#endif
extern void (*gen_pkg_info)(void *blk, struct mem_info *info);
extern void (*gen_pkg_status)(void *blk);
extern unsigned long (*gen_pkg_get_size)(void *blk);
extern unsigned long (*gen_pkg_get_used)(void *blk);
extern unsigned long (*gen_pkg_get_rused)(void *blk);
extern unsigned long (*gen_pkg_get_mused)(void *blk);
extern unsigned long (*gen_pkg_get_free)(void *blk);
extern unsigned long (*gen_pkg_get_frags)(void *blk);
#endif

#ifdef INLINE_ALLOC
#ifdef F_MALLOC
#define PKG_MALLOC_            fm_malloc
#define PKG_REALLOC            fm_realloc
#define PKG_FREE               fm_free
#define PKG_INFO               fm_info
#define PKG_STATUS             fm_status
#define PKG_GET_SIZE()         fm_get_size(mem_block)
#define PKG_GET_USED()         fm_get_used(mem_block)
#define PKG_GET_RUSED()        fm_get_real_used(mem_block)
#define PKG_GET_MUSED()        fm_get_max_real_used(mem_block)
#define PKG_GET_FREE()         fm_get_free(mem_block)
#define PKG_GET_FRAGS()        fm_get_frags(mem_block)
#elif defined Q_MALLOC
#define PKG_MALLOC_            qm_malloc
#define PKG_REALLOC            qm_realloc
#define PKG_FREE               qm_free
#define PKG_INFO               qm_info
#define PKG_STATUS             qm_status
#define PKG_GET_SIZE()         qm_get_size(mem_block)
#define PKG_GET_USED()         qm_get_used(mem_block)
#define PKG_GET_RUSED()        qm_get_real_used(mem_block)
#define PKG_GET_MUSED()        qm_get_max_real_used(mem_block)
#define PKG_GET_FREE()         qm_get_free(mem_block)
#define PKG_GET_FRAGS()        qm_get_frags(mem_block)
#elif defined HP_MALLOC
#define PKG_MALLOC_            hp_pkg_malloc
#define PKG_REALLOC            hp_pkg_realloc
#define PKG_FREE               hp_pkg_free
#define PKG_INFO               hp_info
#define PKG_STATUS             hp_status
#define PKG_GET_SIZE()         hp_pkg_get_size(mem_block)
#define PKG_GET_USED()         hp_pkg_get_used(mem_block)
#define PKG_GET_RUSED()        hp_pkg_get_real_used(mem_block)
#define PKG_GET_MUSED()        hp_pkg_get_max_real_used(mem_block)
#define PKG_GET_FREE()         hp_pkg_get_free(mem_block)
#define PKG_GET_FRAGS()        hp_pkg_get_frags(mem_block)
#endif /* F_MALLOC */
#else
#define PKG_MALLOC_            gen_pkg_malloc
#define PKG_REALLOC            gen_pkg_realloc
#define PKG_FREE               gen_pkg_free
#define PKG_INFO               gen_pkg_info
#define PKG_STATUS             gen_pkg_status
#define PKG_GET_SIZE()         gen_pkg_get_size(mem_block)
#define PKG_GET_USED()         gen_pkg_get_used(mem_block)
#define PKG_GET_RUSED()        gen_pkg_get_rused(mem_block)
#define PKG_GET_MUSED()        gen_pkg_get_mused(mem_block)
#define PKG_GET_FREE()         gen_pkg_get_free(mem_block)
#define PKG_GET_FRAGS()        gen_pkg_get_frags(mem_block)
#endif /* INLINE_ALLOC */

#ifdef DBG_MALLOC
#ifdef __SUNPRO_C
#define __FUNCTION__ ""  /* gcc specific */
#endif
#define pkg_malloc(s)     PKG_MALLOC_(mem_block, (s), \
                                      __FILE__, __FUNCTION__, __LINE__)
#define pkg_free(p)       PKG_FREE(mem_block, (p), \
                                      __FILE__, __FUNCTION__, __LINE__)
#define pkg_realloc(p, s) PKG_REALLOC(mem_block, (p), (s), \
                                      __FILE__, __FUNCTION__, __LINE__)
#define pkg_info(i)       PKG_INFO(mem_block, i)
inline static void *pkg_malloc_func(unsigned long size,
		const char *file, const char *function, unsigned int line)
{
	return PKG_MALLOC_(mem_block, size, file, function, line);
}

inline static void* pkg_realloc_func(void *ptr, unsigned int size,
		const char* file, const char* function, unsigned int line)
{
	return PKG_REALLOC(mem_block, ptr, size, file, function, line);
}

inline static void pkg_free_func(void *ptr,
		const char* file, const char* function, unsigned int line)
{
	return PKG_FREE(mem_block, ptr, file, function, line);
}
#else
#define pkg_malloc(s)     PKG_MALLOC_(mem_block, (s))
#define pkg_realloc(p, s) PKG_REALLOC(mem_block, (p), (s))
#define pkg_free(p)       PKG_FREE(mem_block, (p))
#define pkg_info(i)       PKG_INFO(mem_block, i)
inline static void *pkg_malloc_func(unsigned long size)
{
	return PKG_MALLOC_(mem_block, size);
}

inline static void* pkg_realloc_func(void *ptr, unsigned int size)
{
	return PKG_REALLOC(mem_block, ptr, size);
}

inline static void pkg_free_func(void *ptr)
{
	return PKG_FREE(mem_block, ptr);
}
#endif

#define pkg_status()      PKG_STATUS(mem_block)

#else
#include <stdlib.h>
void *sys_malloc(unsigned long, const char *, const char *, unsigned int);
void *sys_realloc(void *, unsigned long, const char *, const char *, unsigned int);
void sys_free(void *, const char *, const char *, unsigned int);

#define SYSTEM_MALLOC
#define pkg_malloc_func sys_malloc
#define pkg_malloc(s) sys_malloc((s), __FILE__, __FUNCTION__, __LINE__)
#define func_pkg_relloc sys_realloc
#define pkg_realloc(ptr, s) sys_realloc((ptr), (s), __FILE__, __FUNCTION__, __LINE__)
#define pkg_free_func sys_free
#define pkg_free(p) sys_free((p), __FILE__, __FUNCTION__, __LINE__)
#define pkg_status()
#define PKG_GET_SIZE()
#define PKG_GET_USED()
#define PKG_GET_RUSED()
#define PKG_GET_MUSED()
#define PKG_GET_FREE()
#define PKG_GET_FRAGS()
#endif

int init_pkg_mallocs();
int init_shm_mallocs();

#endif
