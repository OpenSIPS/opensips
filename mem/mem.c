/*
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

#include <stdio.h>
#include <stdlib.h>
#include "../config.h"
#include "../dprint.h"
#include "../globals.h"
#include "mem.h"

#include "shm_mem.h"

enum osips_mm mem_allocator_pkg = MM_NONE;

#ifndef INLINE_ALLOC
#ifdef DBG_MALLOC
void *(*gen_pkg_malloc)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void (*gen_pkg_free)(void *blk, void *p,
                      const char *file, const char *func, unsigned int line);
#else
void *(*gen_pkg_malloc)(void *blk, unsigned long size);
void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size);
void (*gen_pkg_free)(void *blk, void *p);
#endif
void (*gen_pkg_info)(void *blk, struct mem_info *info);
void (*gen_pkg_status)(void *blk);
unsigned long (*gen_pkg_get_size)(void *blk);
unsigned long (*gen_pkg_get_used)(void *blk);
unsigned long (*gen_pkg_get_rused)(void *blk);
unsigned long (*gen_pkg_get_mused)(void *blk);
unsigned long (*gen_pkg_get_free)(void *blk);
unsigned long (*gen_pkg_get_frags)(void *blk);
#endif

#ifdef PKG_MALLOC
	char *mem_pool;
	void *mem_block;
#endif

int set_pkg_mm(const char *mm_name)
{
#ifdef PKG_MALLOC
#ifdef INLINE_ALLOC
	LM_NOTICE("this is an inlined allocator build (see opensips -V), "
	          "cannot set a custom pkg allocator (%s)\n", mm_name);
	return 0;
#endif

	if (parse_mm(mm_name, &mem_allocator_pkg) < 0)
		return -1;

	return 0;
#else
	LM_ERR("cannot change pkg allocator when system malloc is used!\n");
	return -1;
#endif
}

int init_pkg_mallocs(void)
{
#ifdef PKG_MALLOC
	mem_pool = malloc(pkg_mem_size);
	if (!mem_pool) {
		LM_CRIT("could not initialize PKG memory: %ld\n", pkg_mem_size);
		return -1;
	}

#ifdef INLINE_ALLOC
#if defined F_MALLOC
		mem_block = fm_malloc_init(mem_pool, pkg_mem_size, "pkg");
#elif defined Q_MALLOC
		mem_block = qm_malloc_init(mem_pool, pkg_mem_size, "pkg");
#elif defined HP_MALLOC
		mem_block = hp_pkg_malloc_init(mem_pool, pkg_mem_size, "pkg");
#endif
#else
	if (mem_allocator_pkg == MM_NONE)
		mem_allocator_pkg = mem_allocator;

	switch (mem_allocator_pkg) {
#ifdef F_MALLOC
	case MM_F_MALLOC:
		mem_block = fm_malloc_init(mem_pool, pkg_mem_size, "pkg");
		gen_pkg_malloc    = (osips_block_malloc_f)fm_malloc;
		gen_pkg_realloc   = (osips_block_realloc_f)fm_realloc;
		gen_pkg_free      = (osips_block_free_f)fm_free;
		gen_pkg_info      = (osips_mem_info_f)fm_info;
		gen_pkg_status    = (osips_mem_status_f)fm_status;
		gen_pkg_get_size  = (osips_get_mmstat_f)fm_get_size;
		gen_pkg_get_used  = (osips_get_mmstat_f)fm_get_used;
		gen_pkg_get_rused = (osips_get_mmstat_f)fm_get_real_used;
		gen_pkg_get_mused = (osips_get_mmstat_f)fm_get_max_real_used;
		gen_pkg_get_free  = (osips_get_mmstat_f)fm_get_free;
		gen_pkg_get_frags = (osips_get_mmstat_f)fm_get_frags;
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC:
		mem_block = qm_malloc_init(mem_pool, pkg_mem_size, "pkg");
		gen_pkg_malloc    = (osips_block_malloc_f)qm_malloc;
		gen_pkg_realloc   = (osips_block_realloc_f)qm_realloc;
		gen_pkg_free      = (osips_block_free_f)qm_free;
		gen_pkg_info      = (osips_mem_info_f)qm_info;
		gen_pkg_status    = (osips_mem_status_f)qm_status;
		gen_pkg_get_size  = (osips_get_mmstat_f)qm_get_size;
		gen_pkg_get_used  = (osips_get_mmstat_f)qm_get_used;
		gen_pkg_get_rused = (osips_get_mmstat_f)qm_get_real_used;
		gen_pkg_get_mused = (osips_get_mmstat_f)qm_get_max_real_used;
		gen_pkg_get_free  = (osips_get_mmstat_f)qm_get_free;
		gen_pkg_get_frags = (osips_get_mmstat_f)qm_get_frags;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC:
		mem_block = hp_pkg_malloc_init(mem_pool, pkg_mem_size, "pkg");
		gen_pkg_malloc     = (osips_block_malloc_f)hp_pkg_malloc;
		gen_pkg_realloc    = (osips_block_realloc_f)hp_pkg_realloc;
		gen_pkg_free       = (osips_block_free_f)hp_pkg_free;
		gen_pkg_info       = (osips_mem_info_f)hp_info;
		gen_pkg_status     = (osips_mem_status_f)hp_status;
		gen_pkg_get_size   = (osips_get_mmstat_f)hp_pkg_get_size;
		gen_pkg_get_used   = (osips_get_mmstat_f)hp_pkg_get_used;
		gen_pkg_get_rused  = (osips_get_mmstat_f)hp_pkg_get_real_used;
		gen_pkg_get_mused  = (osips_get_mmstat_f)hp_pkg_get_max_real_used;
		gen_pkg_get_free   = (osips_get_mmstat_f)hp_pkg_get_free;
		gen_pkg_get_frags  = (osips_get_mmstat_f)hp_pkg_get_frags;
		break;
#endif
#ifdef DBG_MALLOC
#ifdef F_MALLOC
	case MM_F_MALLOC_DBG:
		mem_block = fm_malloc_init(mem_pool, pkg_mem_size, "pkg");
		gen_pkg_malloc    = (osips_block_malloc_f)fm_malloc_dbg;
		gen_pkg_realloc   = (osips_block_realloc_f)fm_realloc_dbg;
		gen_pkg_free      = (osips_block_free_f)fm_free_dbg;
		gen_pkg_info      = (osips_mem_info_f)fm_info;
		gen_pkg_status    = (osips_mem_status_f)fm_status_dbg;
		gen_pkg_get_size  = (osips_get_mmstat_f)fm_get_size;
		gen_pkg_get_used  = (osips_get_mmstat_f)fm_get_used;
		gen_pkg_get_rused = (osips_get_mmstat_f)fm_get_real_used;
		gen_pkg_get_mused = (osips_get_mmstat_f)fm_get_max_real_used;
		gen_pkg_get_free  = (osips_get_mmstat_f)fm_get_free;
		gen_pkg_get_frags = (osips_get_mmstat_f)fm_get_frags;
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC_DBG:
		mem_block = qm_malloc_init(mem_pool, pkg_mem_size, "pkg");
		gen_pkg_malloc    = (osips_block_malloc_f)qm_malloc_dbg;
		gen_pkg_realloc   = (osips_block_realloc_f)qm_realloc_dbg;
		gen_pkg_free      = (osips_block_free_f)qm_free_dbg;
		gen_pkg_info      = (osips_mem_info_f)qm_info;
		gen_pkg_status    = (osips_mem_status_f)qm_status_dbg;
		gen_pkg_get_size  = (osips_get_mmstat_f)qm_get_size;
		gen_pkg_get_used  = (osips_get_mmstat_f)qm_get_used;
		gen_pkg_get_rused = (osips_get_mmstat_f)qm_get_real_used;
		gen_pkg_get_mused = (osips_get_mmstat_f)qm_get_max_real_used;
		gen_pkg_get_free  = (osips_get_mmstat_f)qm_get_free;
		gen_pkg_get_frags = (osips_get_mmstat_f)qm_get_frags;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC_DBG:
		mem_block = hp_pkg_malloc_init(mem_pool, pkg_mem_size, "pkg");
		gen_pkg_malloc    = (osips_block_malloc_f)hp_pkg_malloc_dbg;
		gen_pkg_realloc   = (osips_block_realloc_f)hp_pkg_realloc_dbg;
		gen_pkg_free      = (osips_block_free_f)hp_pkg_free_dbg;
		gen_pkg_info      = (osips_mem_info_f)hp_info;
		gen_pkg_status    = (osips_mem_status_f)hp_status_dbg;
		gen_pkg_get_size  = (osips_get_mmstat_f)hp_pkg_get_size;
		gen_pkg_get_used  = (osips_get_mmstat_f)hp_pkg_get_used;
		gen_pkg_get_rused = (osips_get_mmstat_f)hp_pkg_get_real_used;
		gen_pkg_get_mused = (osips_get_mmstat_f)hp_pkg_get_max_real_used;
		gen_pkg_get_free  = (osips_get_mmstat_f)hp_pkg_get_free;
		gen_pkg_get_frags = (osips_get_mmstat_f)hp_pkg_get_frags;
		break;
#endif
#endif
	default:
		LM_ERR("current build does not include support for "
		       "selected allocator (%s)\n", mm_str(mem_allocator_pkg));
		return -1;
	}
#endif

	if (!mem_block) {
		LM_CRIT("could not initialize memory pool\n");
		fprintf(stderr, "Given PKG mem size is not enough: %ld\n",
			pkg_mem_size );
		return -1;
	}
#endif

	return 0;
}



#if defined(PKG_MALLOC) && defined(STATISTICS)
void set_pkg_stats(pkg_status_holder *status)
{
	status[0][PKG_TOTAL_SIZE_IDX] = PKG_GET_SIZE();
	status[0][PKG_USED_SIZE_IDX] = PKG_GET_USED();
	status[0][PKG_REAL_USED_SIZE_IDX] = PKG_GET_RUSED();
	status[0][PKG_MAX_USED_SIZE_IDX] = PKG_GET_MUSED();
	status[0][PKG_FREE_SIZE_IDX] = PKG_GET_FREE();
	status[0][PKG_FRAGMENTS_SIZE_IDX] = PKG_GET_FRAGS();
}

/* event interface information */
#include <unistd.h>
#include "../evi/evi_core.h"
#include "../evi/evi_modules.h"

/* events information */
long event_pkg_threshold = 0;

// determines the last percentage triggered
long event_pkg_last = 0;

// determines if there is a pending event
int event_pkg_pending = 0;

static str pkg_usage_str = { "usage", 5 };
static str pkg_threshold_str = { "threshold", 9 };
static str pkg_used_str = { "used", 4 };
static str pkg_size_str = { "size", 4 };
static str pkg_pid_str = { "pid", 3 };


void pkg_event_raise(long used, long size, long perc)
{
	evi_params_p list = 0;
	int pid;

	event_pkg_pending = 1;
	event_pkg_last = perc;

	// event has to be triggered - check for subscribers
	if (!evi_probe_event(EVI_PKG_THRESHOLD_ID)) {
		goto end;
	}

	if (!(list = evi_get_params()))
		goto end;
	if (evi_param_add_int(list, &pkg_usage_str, (int *)&perc)) {
		LM_ERR("unable to add usage parameter\n");
		goto end;
	}
	if (evi_param_add_int(list, &pkg_threshold_str, (int *)&event_pkg_threshold)) {
		LM_ERR("unable to add threshold parameter\n");
		goto end;
	}
	if (evi_param_add_int(list, &pkg_used_str, (int *)&used)) {
		LM_ERR("unable to add used parameter\n");
		goto end;
	}
	if (evi_param_add_int(list, &pkg_size_str, (int *)&size)) {
		LM_ERR("unable to add size parameter\n");
		goto end;
	}
	pid = getpid();
	if (evi_param_add_int(list, &pkg_pid_str, (int *)&pid)) {
		LM_ERR("unable to add size parameter\n");
		goto end;
	}

	if (evi_raise_event(EVI_PKG_THRESHOLD_ID, list)) {
		LM_ERR("unable to send pkg threshold event\n");
	}
	list = 0;
end:
	if (list)
		evi_free_params(list);
	event_pkg_pending = 0;
}

void pkg_threshold_check(void)
{
	long pkg_perc, used, size;

	if (event_pkg_threshold == 0 ||	// threshold not used
			event_pkg_pending ) {	// somebody else is raising the event
		// do not do anything
		return;
	}

	// compute the percentage
	used = PKG_GET_RUSED();
	size = PKG_GET_SIZE();
	pkg_perc = used * 100 / size;

	/* check if the event has to be raised or if it was already notified */
	if ((pkg_perc < event_pkg_threshold && event_pkg_last <= event_pkg_threshold) ||
		(pkg_perc >= event_pkg_threshold && event_pkg_last == pkg_perc))
		return;

	pkg_event_raise(used, size, pkg_perc);
}
#endif



int init_shm_mallocs(void)
{
	if (shm_mem_init() < 0) {
		LM_CRIT("could not initialize shared memory pool, exiting...\n");
		 fprintf(stderr, "Too much shared memory demanded: %ld\n",
			shm_mem_size );
		return -1;
	}

	return 0;
}

#ifdef SYSTEM_MALLOC
void *
sys_malloc(unsigned long s, const char *file, const char *function, unsigned int line)
{
	void *v;

	v = malloc(s);
	LM_DBG("%s:%s:%d: malloc %p size %lu end %p\n", file, function, line,
	    v, (unsigned long)s, (char *)v + s);
	return v;
}

void *
sys_realloc(void *p, unsigned long s, const char *file, const char *function, unsigned int line)
{
	void *v;

	v = realloc(p, s);
	LM_DBG("%s:%s:%d: realloc old %p to %p size %lu end %p\n", file,
	    function, line, p, v, (unsigned long)s, (char *)v + s);
	return v;
}

void
sys_free(void *p, const char *file, const char *function, unsigned int line)
{

	LM_DBG("%s:%s:%d: free %p\n", file, function, line, p);
	free(p);
}
#endif
