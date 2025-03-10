/*
 * shared memory debugging
 *
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

#ifndef SHM_MEM_DBG
#define SHM_MEM_DBG

#ifdef DBG_MALLOC
	#include "../lib/dbg/struct_hist.h"
	extern struct struct_hist_list *shm_hist;
	extern int shm_skip_sh_log;
	#define DBG_SHM_ALLOC(verb) \
		do { \
			struct struct_hist *hist; \
			if (!shm_skip_sh_log && p) { \
				shm_skip_sh_log = 1; \
				hist = _sh_push(p, shm_hist, 1, \
					shm_dbg_malloc_func, shm_dbg_free_func); \
				_sh_log(shm_dbg_realloc_func, hist, (verb), "%s:%s:%d, %lu", \
					file, function, line, size); \
				/* on oom, we'd rather crash here */ \
				_sh_unref(hist, shm_dbg_free_func); \
				shm_skip_sh_log = 0; \
			} \
		} while (0)
	#define DBG_SHM_FREE(file, function, line, size) \
		do { \
			struct struct_hist *hist; \
			if (!shm_skip_sh_log && ptr) { \
				shm_skip_sh_log = 1; \
				hist = _sh_push(ptr, shm_hist, 1, \
					shm_dbg_malloc_func, shm_dbg_free_func); \
				_sh_log(shm_dbg_realloc_func, hist, SH_SHM_FREE, \
				       "%s:%s:%d, %d", file, function, line, size); \
				sh_unref(hist); \
				shm_skip_sh_log = 0; \
			} \
		} while (0)
	static inline void shm_mem_enable_dbg(void) { shm_skip_sh_log = 0; }
	static inline void shm_mem_disable_dbg(void) { shm_skip_sh_log = 1; }
#else
	#define DBG_SHM_ALLOC(verb)
	#define DBG_SHM_FREE(verb)
	#define shm_mem_enable_dbg()
	#define shm_mem_disable_dbg()
#endif

#endif /* SHM_MEM_DBG */
