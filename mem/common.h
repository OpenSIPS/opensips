/*
 * shared code between all memory allocators
 *
 * Copyright (C) 2014-2019 OpenSIPS Solutions
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

#ifndef mem_common_h
#define mem_common_h

extern void *mem_block;
extern void *shm_block;
extern void *rpm_block;

#include "meminfo.h"

#if !defined(F_MALLOC) && !defined(Q_MALLOC) && !defined(HP_MALLOC)
#error "no memory allocator selected"
/* if exactly an allocator was selected, let's inline it! */
#elif ((!defined Q_MALLOC && !defined HP_MALLOC) || \
	 (!defined F_MALLOC && !defined HP_MALLOC) || \
	 (!defined F_MALLOC && !defined Q_MALLOC))
#define INLINE_ALLOC
#endif

#if defined F_MALLOC
#include "f_malloc.h"
#endif

#if defined Q_MALLOC
#include "q_malloc.h"
#endif

#if defined HP_MALLOC
#include "hp_malloc.h"
#endif

extern int mem_warming_enabled;
extern char *mem_warming_pattern_file;
extern int mem_warming_percentage;
extern enum osips_mm mem_allocator;

enum osips_mm {
	MM_NONE,
	MM_F_MALLOC,
	MM_Q_MALLOC,
	MM_HP_MALLOC,
	MM_F_MALLOC_DBG,
	MM_Q_MALLOC_DBG,
	MM_HP_MALLOC_DBG,
};

/* returns -1 if @mm_name is unrecognized */
int set_global_mm(const char *mm_name);

/* returns -1 if @mm_name is unrecognized */
int parse_mm(const char *mm_name, enum osips_mm *mm);

#define mm_str(mm) \
	((mm) == MM_NONE ? "NONE" : \
	 (mm) == MM_F_MALLOC ? "F_MALLOC" : \
	 (mm) == MM_Q_MALLOC ? "Q_MALLOC" : \
	 (mm) == MM_HP_MALLOC ? "HP_MALLOC" : \
	 (mm) == MM_F_MALLOC_DBG ? "F_MALLOC_DBG" : \
	 (mm) == MM_Q_MALLOC_DBG ? "Q_MALLOC_DBG" : \
	 (mm) == MM_HP_MALLOC_DBG ? "HP_MALLOC_DBG" : "unknown")

#ifdef DBG_MALLOC
typedef void *(*osips_block_malloc_f) (void *block, unsigned long size,
                      const char *file, const char *func, unsigned int line);
typedef void *(*osips_block_realloc_f) (void *block, void *ptr, unsigned long size,
                      const char *file, const char *func, unsigned int line);
typedef void (*osips_block_free_f) (void *block, void *ptr,
                      const char *file, const char *func, unsigned int line);
#else
typedef void *(*osips_block_malloc_f) (void *block, unsigned long size);
typedef void *(*osips_block_realloc_f) (void *block, void *ptr, unsigned long size);
typedef void (*osips_block_free_f) (void *block, void *ptr);
#endif

typedef void (*osips_mem_info_f) (void *block, struct mem_info *i);
typedef void (*osips_mem_status_f) (void *block);
typedef unsigned long (*osips_get_mmstat_f) (void *block);
typedef void (*osips_shm_stats_init_f) (void *block, int core_index);

#define oom_errorf \
	"not enough free %s memory (%ld bytes left, need %lu), " \
	"please increase the \"-%s\" command line parameter!\n"

#define oom_nostats_errorf \
	"not enough free %s memory (need %lu), please increase the \"-%s\" " \
	"command line parameter!\n"

#ifdef DBG_MALLOC
#define check_double_free(ptr, frag, block) \
	do { \
		if (frag_is_free(frag)) { \
			LM_CRIT("freeing already freed %s pointer (%p), first free: " \
			        "%s: %s(%ld) - aborting!\n", (block)->name, ptr, \
			        (frag)->file, (frag)->func, (frag)->line); \
			abort(); \
		} \
	} while (0)
#else
#define check_double_free(ptr, frag, block)
#endif

#endif
