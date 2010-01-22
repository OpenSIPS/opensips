/* $Id$
 *
 * memory related stuff (malloc & friends)
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
 * History:
 * --------
 *  2003-03-10  __FUNCTION__ is a gcc-ism, defined it to "" for sun cc
 *               (andrei)
 *  2003-03-07  split init_malloc into init_pkg_mallocs & init_shm_mallocs 
 *               (andrei)
 */



#ifndef mem_h
#define mem_h
#include "../config.h"
#include "../dprint.h"

/* fix debug defines, DBG_F_MALLOC <=> DBG_QM_MALLOC */
#ifdef F_MALLOC
	#ifdef DBG_F_MALLOC
		#ifndef DBG_QM_MALLOC
			#define DBG_QM_MALLOC
		#endif
	#elif defined(DBG_QM_MALLOC)
		#define DBG_F_MALLOC
	#endif
#endif

#ifdef PKG_MALLOC
#	ifdef VQ_MALLOC
#		include "vq_malloc.h"
		extern struct vqm_block* mem_block;
#	elif defined F_MALLOC
#		include "f_malloc.h"
		extern struct fm_block* mem_block;
#   else
#		include "q_malloc.h"
		extern struct qm_block* mem_block;
#	endif

	extern char mem_pool[PKG_MEM_POOL_SIZE];


#ifdef STATISTICS
#define PKG_TOTAL_SIZE_IDX       0
#define PKG_USED_SIZE_IDX        1
#define PKG_REAL_USED_SIZE_IDX   2
#define PKG_MAX_USED_SIZE_IDX    3
#define PKG_FREE_SIZE_IDX        4
#define PKG_FRAGMENTS_SIZE_IDX   5
typedef unsigned long pkg_status_holder[6];
#endif

void set_pkg_stats(pkg_status_holder*);


#	ifdef DBG_QM_MALLOC
#ifdef __SUNPRO_C
		#define __FUNCTION__ ""  /* gcc specific */
#endif
#		ifdef VQ_MALLOC
#			define pkg_malloc(s) vqm_malloc(mem_block, (s),__FILE__, \
				__FUNCTION__, __LINE__)
#			define pkg_free(p)   vqm_free(mem_block, (p), __FILE__,  \
				__FUNCTION__, __LINE__)
#			warn "no proper realloc implementation, use another mem. alloc"
#		elif defined F_MALLOC
#			define pkg_malloc(s) fm_malloc(mem_block, (s),__FILE__, \
				__FUNCTION__, __LINE__)
#			define pkg_free(p)   fm_free(mem_block, (p), __FILE__,  \
				__FUNCTION__, __LINE__)
#			define pkg_realloc(p, s) fm_realloc(mem_block, (p), (s),__FILE__, \
				__FUNCTION__, __LINE__)
#                       define pkg_info(i) fm_info(mem_block,i)
#		else
#			define pkg_malloc(s) qm_malloc(mem_block, (s),__FILE__, \
				__FUNCTION__, __LINE__)
#			define pkg_realloc(p, s) qm_realloc(mem_block, (p), (s),__FILE__, \
				__FUNCTION__, __LINE__)
#			define pkg_free(p)   qm_free(mem_block, (p), __FILE__,  \
				__FUNCTION__, __LINE__)
#                       define pkg_info(i) qm_info(mem_block,i)
#		endif
#	else
#		ifdef VQ_MALLOC
#			define pkg_malloc(s) vqm_malloc(mem_block, (s))
#			define pkg_free(p)   vqm_free(mem_block, (p))
#		elif defined F_MALLOC
#			define pkg_malloc(s) fm_malloc(mem_block, (s))
#			define pkg_realloc(p, s) fm_realloc(mem_block, (p), (s))
#			define pkg_free(p)   fm_free(mem_block, (p))
#                       define pkg_info(i) fm_info(mem_block,i)
#		else
#			define pkg_malloc(s) qm_malloc(mem_block, (s))
#			define pkg_realloc(p, s) qm_realloc(mem_block, (p), (s))
#			define pkg_free(p)   qm_free(mem_block, (p))
#                       define pkg_info(i) qm_info(mem_block,i)
#		endif
#	endif
#	ifdef VQ_MALLOC
#		define pkg_status()  vqm_status(mem_block)
#	elif defined F_MALLOC
#		define pkg_status()        fm_status(mem_block)
#		define MY_PKG_GET_SIZE()   fm_get_size(mem_block)
#		define MY_PKG_GET_USED()   fm_get_used(mem_block)
#		define MY_PKG_GET_RUSED()  fm_get_real_used(mem_block)
#		define MY_PKG_GET_MUSED()  fm_get_max_real_used(mem_block)
#		define MY_PKG_GET_FREE()   fm_get_free(mem_block)
#		define MY_PKG_GET_FRAGS()  fm_get_frags(mem_block)
#	else
#		define pkg_status()  qm_status(mem_block)
#		define MY_PKG_GET_SIZE()   qm_get_size(mem_block)
#		define MY_PKG_GET_USED()   qm_get_used(mem_block)
#		define MY_PKG_GET_RUSED()  qm_get_real_used(mem_block)
#		define MY_PKG_GET_MUSED()  qm_get_max_real_used(mem_block)
#		define MY_PKG_GET_FREE()   qm_get_free(mem_block)
#		define MY_PKG_GET_FRAGS()  qm_get_frags(mem_block)
#	endif
#elif defined(SHM_MEM) && defined(USE_SHM_MEM)
#	include "shm_mem.h"
#	define pkg_malloc(s) shm_malloc((s))
#	define pkg_free(p)   shm_free((p))
#	define pkg_status()  shm_status()
#	define MY_PKG_GET_SIZE()
#	define MY_PKG_GET_USED()
#	define MY_PKG_GET_RUSED()
#	define MY_PKG_GET_MUSED()
#	define MY_PKG_GET_FREE()
#	define MY_PKG_GET_FRAGS()
#else
#	include <stdlib.h>

void *sys_malloc(size_t, const char *, const char *, int);
void *sys_realloc(void *, size_t, const char *, const char *, int);
void sys_free(void *, const char *, const char *, int);

#	define SYSTEM_MALLOC
#	define pkg_malloc(s) sys_malloc((s), __FILE__, __FUNCTION__, __LINE__)
#	define pkg_realloc(ptr, s) sys_realloc((ptr), (s), __FILE__, __FUNCTION__, __LINE__)
#	define pkg_free(p) sys_free((p), __FILE__, __FUNCTION__, __LINE__)
#	define pkg_status()
#	define MY_PKG_GET_SIZE()
#	define MY_PKG_GET_USED()
#	define MY_PKG_GET_RUSED()
#	define MY_PKG_GET_MUSED()
#	define MY_PKG_GET_FREE()
#	define MY_PKG_GET_FRAGS()
#endif

int init_pkg_mallocs();
int init_shm_mallocs();


#endif
