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
	char mem_pool[PKG_MEM_POOL_SIZE];
	#ifdef VQ_MALLOC
		struct vqm_block* mem_block;
	#elif defined F_MALLOC
		struct fm_block* mem_block;
	#else
		struct qm_block* mem_block;
	#endif
#endif


int init_pkg_mallocs(void)
{
#ifdef PKG_MALLOC
	/*init mem*/
	#ifdef VQ_MALLOC
		mem_block=vqm_malloc_init(mem_pool, PKG_MEM_POOL_SIZE);
	#elif F_MALLOC
		mem_block=fm_malloc_init(mem_pool, PKG_MEM_POOL_SIZE);
	#else
		mem_block=qm_malloc_init(mem_pool, PKG_MEM_POOL_SIZE);
	#endif
	if (mem_block==0){
		LM_CRIT("could not initialize memory pool\n");
		fprintf(stderr, "Too much pkg memory demanded: %d\n",
			PKG_MEM_POOL_SIZE );
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
