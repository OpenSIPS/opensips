/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * --------
 *  2003-04-08  init_mallocs split into init_{pkg,shm}_malloc (andrei)
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include "../config.h"
#include "../dprint.h"
#include "../globals.h"
#include "mem.h"

#ifdef PKG_MALLOC
	#ifdef VQ_MALLOC
		#include "vq_malloc.h"
	#else
		#include "q_malloc.h"
	#endif
#endif

#ifdef SHM_MEM
#include "shm_mem.h"
#endif

#ifdef PKG_MALLOC
	char* mem_pool = NULL;
	#ifdef VQ_MALLOC
		struct vqm_block* mem_block;
	#elif defined F_MALLOC
		struct fm_block* mem_block;
	#elif defined HP_MALLOC
		struct hp_block* mem_block;
	#else
		struct qm_block* mem_block;
	#endif
#endif


int init_pkg_mallocs(void)
{
#ifdef PKG_MALLOC
	/*init mem*/
	mem_pool = malloc(pkg_mem_size);
	if (mem_pool==NULL){
		LM_CRIT("could not initialize PKG memory: %ld\n",
			pkg_mem_size);
		return -1;
	}
	#ifdef VQ_MALLOC
		mem_block=vqm_malloc_init(mem_pool, pkg_mem_size);
	#elif F_MALLOC
		mem_block=fm_malloc_init(mem_pool, pkg_mem_size);
	#elif HP_MALLOC
		mem_block=hp_pkg_malloc_init(mem_pool, pkg_mem_size);
	#else
		mem_block=qm_malloc_init(mem_pool, pkg_mem_size);
	#endif
	if (mem_block==0){
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
	status[0][PKG_TOTAL_SIZE_IDX] = MY_PKG_GET_SIZE();
	status[0][PKG_USED_SIZE_IDX] = MY_PKG_GET_USED();
	status[0][PKG_REAL_USED_SIZE_IDX] = MY_PKG_GET_RUSED();
	status[0][PKG_MAX_USED_SIZE_IDX] = MY_PKG_GET_MUSED();
	status[0][PKG_FREE_SIZE_IDX] = MY_PKG_GET_FREE();
	status[0][PKG_FRAGMENTS_SIZE_IDX] = MY_PKG_GET_FRAGS();
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

inline void pkg_threshold_check(void)
{
	long pkg_perc, used, size;

	if (event_pkg_threshold == 0 ||	// threshold not used
			event_pkg_pending ) {	// somebody else is raising the event
		// do not do anything
		return;
	}

	// compute the percentage
	used = MY_PKG_GET_RUSED();
	size = MY_PKG_GET_SIZE();
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
#ifdef SHM_MEM
	if (shm_mem_init()<0) {
		LM_CRIT("could not initialize shared memory pool, exiting...\n");
		 fprintf(stderr, "Too much shared memory demanded: %ld\n",
			shm_mem_size );
		return -1;
	}
#endif
	return 0;
}

#ifdef SYSTEM_MALLOC
void *
sys_malloc(size_t s, const char *file, const char *function, int line)
{
	void *v;

	v = malloc(s);
	LM_DBG("%s:%s:%d: malloc %p size %lu end %p\n", file, function, line,
	    v, (unsigned long)s, (char *)v + s);
	return v;
}

void *
sys_realloc(void *p, size_t s, const char *file, const char *function, int line)
{
	void *v;

	v = realloc(p, s);
	LM_DBG("%s:%s:%d: realloc old %p to %p size %lu end %p\n", file,
	    function, line, p, v, (unsigned long)s, (char *)v + s);
	return v;
}

void
sys_free(void *p, const char *file, const char *function, int line)
{

	LM_DBG("%s:%s:%d: free %p\n", file, function, line, p);
	free(p);
}
#endif
