/*
 * Shared memory functions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */


#include <stdlib.h>

#include "shm_mem.h"
#include "../config.h"
#include "../globals.h"

#ifdef  SHM_MMAP

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h> /*open*/
#include <sys/stat.h>
#include <fcntl.h>

#endif

enum osips_mm mem_allocator_shm = MM_NONE;

#ifndef INLINE_ALLOC
#ifdef DBG_MALLOC
void *(*gen_shm_malloc)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_shm_malloc_unsafe)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_shm_realloc)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void *(*gen_shm_realloc_unsafe)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
void (*gen_shm_free)(void *blk, void *p,
                      const char *file, const char *func, unsigned int line);
void (*gen_shm_free_unsafe)(void *blk, void *p,
                      const char *file, const char *func, unsigned int line);
#else
void *(*gen_shm_malloc)(void *blk, unsigned long size);
void *(*gen_shm_malloc_unsafe)(void *blk, unsigned long size);
void *(*gen_shm_realloc)(void *blk, void *p, unsigned long size);
void *(*gen_shm_realloc_unsafe)(void *blk, void *p, unsigned long size);
void (*gen_shm_free)(void *blk, void *p);
void (*gen_shm_free_unsafe)(void *blk, void *p);
#endif
void (*gen_shm_info)(void *blk, struct mem_info *info);
void (*gen_shm_status)(void *blk);
unsigned long (*gen_shm_get_size)(void *blk);
unsigned long (*gen_shm_get_used)(void *blk);
unsigned long (*gen_shm_get_rused)(void *blk);
unsigned long (*gen_shm_get_mused)(void *blk);
unsigned long (*gen_shm_get_free)(void *blk);
unsigned long (*gen_shm_get_frags)(void *blk);
#endif

#ifdef STATISTICS
stat_export_t shm_stats[] = {
	{"total_size" ,     STAT_IS_FUNC,    (stat_var**)shm_get_size  },
	{"max_used_size" ,  STAT_IS_FUNC,    (stat_var**)shm_get_mused },
	{"free_size" ,      STAT_IS_FUNC,    (stat_var**)shm_get_free  },
#if defined HP_MALLOC && defined INLINE_ALLOC && !defined HP_MALLOC_FAST_STATS
	{"used_size" ,     STAT_NO_RESET,               &shm_used      },
	{"real_used_size" ,STAT_NO_RESET,               &shm_rused     },
	{"fragments" ,     STAT_NO_RESET,               &shm_frags     },
#else
	/* for HP_MALLOC, these still need to be edited to stats @ startup */
	{"used_size" ,      STAT_IS_FUNC,    (stat_var**)shm_get_used  },
	{"real_used_size" , STAT_IS_FUNC,    (stat_var**)shm_get_rused },
	{"fragments" ,      STAT_IS_FUNC,    (stat_var**)shm_get_frags },
#endif
	{0,0,0}
};
#endif


#ifndef SHM_MMAP
static int shm_shmid=-1; /*shared memory id*/
#endif

#if defined F_MALLOC || defined Q_MALLOC
gen_lock_t *mem_lock;
#endif

#ifdef HP_MALLOC
gen_lock_t *mem_locks;
#endif

static void* shm_mempool=INVALID_MAP;
void *shm_block;

/*
 * - the memory fragmentation pattern of OpenSIPS
 * - holds the total number of shm_mallocs requested for each
 *   different possible size since daemon startup
 * - allows memory warming (preserving the fragmentation pattern on restarts)
 */
unsigned long long *shm_hash_usage;

#include "../mem/mem.h"
#include "../locking.h"
#ifdef STATISTICS

#include "../evi/evi_core.h"
#include "../evi/evi_modules.h"

/* events information */
long event_shm_threshold = 0;
long *event_shm_last = 0;
int *event_shm_pending = 0;

#ifdef SHM_EXTRA_STATS
int mem_skip_stats = 0;
#ifndef INLINE_ALLOC
void (*shm_stats_core_init)(void *blk, int core_index);
unsigned long (*shm_stats_get_index)(void *ptr);
void (*shm_stats_set_index)(void *ptr, unsigned long idx);
int shm_frag_overhead;
unsigned long (*shm_frag_size)(void *p);
const char *(*shm_frag_file)(void *p);
const char *(*shm_frag_func)(void *p);
unsigned long (*shm_frag_line)(void *p);
#endif
#endif

static str shm_usage_str = { "usage", 5 };
static str shm_threshold_str = { "threshold", 9 };
static str shm_used_str = { "used", 4 };
static str shm_size_str = { "size", 4 };

int set_shm_mm(const char *mm_name)
{
#ifdef INLINE_ALLOC
	LM_NOTICE("this is an inlined allocator build (see opensips -V), "
	          "cannot set a custom shm allocator (%s)\n", mm_name);
	return 0;
#endif

	if (parse_mm(mm_name, &mem_allocator_shm) < 0)
		return -1;

	return 0;
}

void shm_event_raise(long used, long size, long perc)
{
	evi_params_p list = 0;

	*event_shm_pending = 1;
	*event_shm_last = perc;

	// event has to be triggered - check for subscribers
	if (!evi_probe_event(EVI_SHM_THRESHOLD_ID)) {
		goto end;
	}

	if (!(list = evi_get_params()))
		goto end;
	if (evi_param_add_int(list, &shm_usage_str, (int *)&perc)) {
		LM_ERR("unable to add usage parameter\n");
		goto end;
	}
	if (evi_param_add_int(list, &shm_threshold_str, (int *)&event_shm_threshold)) {
		LM_ERR("unable to add threshold parameter\n");
		goto end;
	}
	if (evi_param_add_int(list, &shm_used_str, (int *)&used)) {
		LM_ERR("unable to add used parameter\n");
		goto end;
	}
	if (evi_param_add_int(list, &shm_size_str, (int *)&size)) {
		LM_ERR("unable to add size parameter\n");
		goto end;
	}

	/*
	 * event has to be raised without the lock otherwise a deadlock will be
	 * generated by the transport modules, or by the event_route processing
	 */
	shm_unlock();

	if (evi_raise_event(EVI_SHM_THRESHOLD_ID, list)) {
		LM_ERR("unable to send shm threshold event\n");
	}

	shm_lock();

	list = 0;
end:
	if (list)
		evi_free_params(list);
	*event_shm_pending = 0;
}
#endif

/*
 * Allocates memory using mmap or sysv shmap
 *  - fd: a handler to a file descriptor pointing to a map file
 *  - force_addr: force mapping to a specific address
 *  - size: how large the mmap should be
 */
void *shm_getmem(int fd, void *force_addr, unsigned long size)
{
	void *ret_addr;
	int flags;

#ifndef SHM_MMAP
	struct shmid_ds shm_info;
#endif

#ifdef SHM_MMAP
	flags = MAP_SHARED;
	if (force_addr)
		flags |= MAP_FIXED;
	if (fd == -1)
		flags |= MAP_ANON;
	ret_addr=mmap(force_addr, size, PROT_READ|PROT_WRITE,
					 flags, fd, 0);
#else /* USE_MMAP */
/* TODO: handle persistent storage for SysV */
	#warn "Cannot have persistent storage using SysV"
	if (force_addr || fd == -1)
		return INVALID_MAP;

	shm_shmid=shmget(IPC_PRIVATE, /* SHM_MEM_SIZE */ shm_mem_size, 0700);
	if (shm_shmid==-1){
		LM_CRIT("could not allocate shared memory segment: %s\n",
				strerror(errno));
		return INVALID_MAP;
	}
	shm_mempool=shmat(shm_shmid, 0, 0);
#endif
	return ret_addr;
}


#if !defined INLINE_ALLOC && defined HP_MALLOC
/* startup optimization */
int shm_use_global_lock;
#endif

int shm_mem_init_mallocs(void* mempool, unsigned long pool_size)
{
#ifdef HP_MALLOC
	int i;
#endif

#ifdef INLINE_ALLOC
#if defined F_MALLOC
	shm_block = fm_malloc_init(mempool, pool_size, "shm");
#elif defined Q_MALLOC
	shm_block = qm_malloc_init(mempool, pool_size, "shm");
#elif defined HP_MALLOC
	shm_block = hp_shm_malloc_init(mempool, pool_size, "shm");
#endif
#else
	if (mem_allocator_shm == MM_NONE)
		mem_allocator_shm = mem_allocator;

#ifdef HP_MALLOC
	if (mem_allocator_shm == MM_HP_MALLOC
	        || mem_allocator_shm == MM_HP_MALLOC_DBG) {
		shm_stats[3].flags = STAT_NO_RESET;
		shm_stats[3].stat_pointer = &shm_used;
		shm_stats[4].flags = STAT_NO_RESET;
		shm_stats[4].stat_pointer = &shm_rused;
		shm_stats[5].flags = STAT_NO_RESET;
		shm_stats[5].stat_pointer = &shm_frags;
	} else {
		shm_use_global_lock = 1;
	}
#endif

#ifdef SHM_EXTRA_STATS
	switch (mem_allocator_shm) {
#ifdef F_MALLOC
	case MM_F_MALLOC:
	case MM_F_MALLOC_DBG:
		shm_stats_core_init = (osips_shm_stats_init_f)fm_stats_core_init;
		shm_stats_get_index = fm_stats_get_index;
		shm_stats_set_index = fm_stats_set_index;
		shm_frag_overhead = FM_FRAG_OVERHEAD;
		shm_frag_size = fm_frag_size;
		shm_frag_file = fm_frag_file;
		shm_frag_func = fm_frag_func;
		shm_frag_line = fm_frag_line;
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC:
	case MM_Q_MALLOC_DBG:
		shm_stats_core_init = (osips_shm_stats_init_f)qm_stats_core_init;
		shm_stats_get_index = qm_stats_get_index;
		shm_stats_set_index = qm_stats_set_index;
		shm_frag_overhead = QM_FRAG_OVERHEAD;
		shm_frag_size = qm_frag_size;
		shm_frag_file = qm_frag_file;
		shm_frag_func = qm_frag_func;
		shm_frag_line = qm_frag_line;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC:
	case MM_HP_MALLOC_DBG:
		shm_stats_core_init = (osips_shm_stats_init_f)hp_stats_core_init;
		shm_stats_get_index = hp_stats_get_index;
		shm_stats_set_index = hp_stats_set_index;
		shm_frag_overhead = HP_FRAG_OVERHEAD;
		shm_frag_size = hp_frag_size;
		shm_frag_file = hp_frag_file;
		shm_frag_func = hp_frag_func;
		shm_frag_line = hp_frag_line;
		break;
#endif
	default:
		LM_ERR("current build does not include support for "
		       "selected allocator (%s)\n", mm_str(mem_allocator_shm));
		return -1;
	}
#endif

	switch (mem_allocator_shm) {
#ifdef F_MALLOC
	case MM_F_MALLOC:
		shm_block = fm_malloc_init(mempool, pool_size, "shm");
		gen_shm_malloc         = (osips_block_malloc_f)fm_malloc;
		gen_shm_malloc_unsafe  = (osips_block_malloc_f)fm_malloc;
		gen_shm_realloc        = (osips_block_realloc_f)fm_realloc;
		gen_shm_realloc_unsafe = (osips_block_realloc_f)fm_realloc;
		gen_shm_free           = (osips_block_free_f)fm_free;
		gen_shm_free_unsafe    = (osips_block_free_f)fm_free;
		gen_shm_info           = (osips_mem_info_f)fm_info;
		gen_shm_status         = (osips_mem_status_f)fm_status;
		gen_shm_get_size       = (osips_get_mmstat_f)fm_get_size;
		gen_shm_get_used       = (osips_get_mmstat_f)fm_get_used;
		gen_shm_get_rused      = (osips_get_mmstat_f)fm_get_real_used;
		gen_shm_get_mused      = (osips_get_mmstat_f)fm_get_max_real_used;
		gen_shm_get_free       = (osips_get_mmstat_f)fm_get_free;
		gen_shm_get_frags      = (osips_get_mmstat_f)fm_get_frags;
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC:
		shm_block = qm_malloc_init(mempool, pool_size, "shm");
		gen_shm_malloc         = (osips_block_malloc_f)qm_malloc;
		gen_shm_malloc_unsafe  = (osips_block_malloc_f)qm_malloc;
		gen_shm_realloc        = (osips_block_realloc_f)qm_realloc;
		gen_shm_realloc_unsafe = (osips_block_realloc_f)qm_realloc;
		gen_shm_free           = (osips_block_free_f)qm_free;
		gen_shm_free_unsafe    = (osips_block_free_f)qm_free;
		gen_shm_info           = (osips_mem_info_f)qm_info;
		gen_shm_status         = (osips_mem_status_f)qm_status;
		gen_shm_get_size       = (osips_get_mmstat_f)qm_get_size;
		gen_shm_get_used       = (osips_get_mmstat_f)qm_get_used;
		gen_shm_get_rused      = (osips_get_mmstat_f)qm_get_real_used;
		gen_shm_get_mused      = (osips_get_mmstat_f)qm_get_max_real_used;
		gen_shm_get_free       = (osips_get_mmstat_f)qm_get_free;
		gen_shm_get_frags      = (osips_get_mmstat_f)qm_get_frags;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC:
		shm_block = hp_shm_malloc_init(mempool, pool_size, "shm");
		gen_shm_malloc         = (osips_block_malloc_f)hp_shm_malloc;
		gen_shm_malloc_unsafe  = (osips_block_malloc_f)hp_shm_malloc_unsafe;
		gen_shm_realloc        = (osips_block_realloc_f)hp_shm_realloc;
		gen_shm_realloc_unsafe = (osips_block_realloc_f)hp_shm_realloc_unsafe;
		gen_shm_free           = (osips_block_free_f)hp_shm_free;
		gen_shm_free_unsafe    = (osips_block_free_f)hp_shm_free_unsafe;
		gen_shm_info           = (osips_mem_info_f)hp_info;
		gen_shm_status         = (osips_mem_status_f)hp_status;
		gen_shm_get_size       = (osips_get_mmstat_f)hp_shm_get_size;
		gen_shm_get_used       = (osips_get_mmstat_f)hp_shm_get_used;
		gen_shm_get_rused      = (osips_get_mmstat_f)hp_shm_get_real_used;
		gen_shm_get_mused      = (osips_get_mmstat_f)hp_shm_get_max_real_used;
		gen_shm_get_free       = (osips_get_mmstat_f)hp_shm_get_free;
		gen_shm_get_frags      = (osips_get_mmstat_f)hp_shm_get_frags;
		break;
#endif
#ifdef DBG_MALLOC
#ifdef F_MALLOC
	case MM_F_MALLOC_DBG:
		shm_block = fm_malloc_init(mempool, pool_size, "shm");
		gen_shm_malloc         = (osips_block_malloc_f)fm_malloc_dbg;
		gen_shm_malloc_unsafe  = (osips_block_malloc_f)fm_malloc_dbg;
		gen_shm_realloc        = (osips_block_realloc_f)fm_realloc_dbg;
		gen_shm_realloc_unsafe = (osips_block_realloc_f)fm_realloc_dbg;
		gen_shm_free           = (osips_block_free_f)fm_free_dbg;
		gen_shm_free_unsafe    = (osips_block_free_f)fm_free_dbg;
		gen_shm_info           = (osips_mem_info_f)fm_info;
		gen_shm_status         = (osips_mem_status_f)fm_status_dbg;
		gen_shm_get_size       = (osips_get_mmstat_f)fm_get_size;
		gen_shm_get_used       = (osips_get_mmstat_f)fm_get_used;
		gen_shm_get_rused      = (osips_get_mmstat_f)fm_get_real_used;
		gen_shm_get_mused      = (osips_get_mmstat_f)fm_get_max_real_used;
		gen_shm_get_free       = (osips_get_mmstat_f)fm_get_free;
		gen_shm_get_frags      = (osips_get_mmstat_f)fm_get_frags;
		break;
#endif
#ifdef Q_MALLOC
	case MM_Q_MALLOC_DBG:
		shm_block = qm_malloc_init(mempool, pool_size, "shm");
		gen_shm_malloc         = (osips_block_malloc_f)qm_malloc_dbg;
		gen_shm_malloc_unsafe  = (osips_block_malloc_f)qm_malloc_dbg;
		gen_shm_realloc        = (osips_block_realloc_f)qm_realloc_dbg;
		gen_shm_realloc_unsafe = (osips_block_realloc_f)qm_realloc_dbg;
		gen_shm_free           = (osips_block_free_f)qm_free_dbg;
		gen_shm_free_unsafe    = (osips_block_free_f)qm_free_dbg;
		gen_shm_info           = (osips_mem_info_f)qm_info;
		gen_shm_status         = (osips_mem_status_f)qm_status_dbg;
		gen_shm_get_size       = (osips_get_mmstat_f)qm_get_size;
		gen_shm_get_used       = (osips_get_mmstat_f)qm_get_used;
		gen_shm_get_rused      = (osips_get_mmstat_f)qm_get_real_used;
		gen_shm_get_mused      = (osips_get_mmstat_f)qm_get_max_real_used;
		gen_shm_get_free       = (osips_get_mmstat_f)qm_get_free;
		gen_shm_get_frags      = (osips_get_mmstat_f)qm_get_frags;
		break;
#endif
#ifdef HP_MALLOC
	case MM_HP_MALLOC_DBG:
		shm_block = hp_shm_malloc_init(mempool, pool_size, "shm");
		gen_shm_malloc         = (osips_block_malloc_f)hp_shm_malloc_dbg;
		gen_shm_malloc_unsafe  = (osips_block_malloc_f)hp_shm_malloc_unsafe_dbg;
		gen_shm_realloc        = (osips_block_realloc_f)hp_shm_realloc_dbg;
		gen_shm_realloc_unsafe = (osips_block_realloc_f)hp_shm_realloc_unsafe_dbg;
		gen_shm_free           = (osips_block_free_f)hp_shm_free_dbg;
		gen_shm_free_unsafe    = (osips_block_free_f)hp_shm_free_unsafe_dbg;
		gen_shm_info           = (osips_mem_info_f)hp_info;
		gen_shm_status         = (osips_mem_status_f)hp_status_dbg;
		gen_shm_get_size       = (osips_get_mmstat_f)hp_shm_get_size;
		gen_shm_get_used       = (osips_get_mmstat_f)hp_shm_get_used;
		gen_shm_get_rused      = (osips_get_mmstat_f)hp_shm_get_real_used;
		gen_shm_get_mused      = (osips_get_mmstat_f)hp_shm_get_max_real_used;
		gen_shm_get_free       = (osips_get_mmstat_f)hp_shm_get_free;
		gen_shm_get_frags      = (osips_get_mmstat_f)hp_shm_get_frags;
		break;
#endif
#endif
	default:
		LM_ERR("current build does not include support for "
		       "selected allocator (%s)\n", mm_str(mem_allocator_shm));
		return -1;
	}
#endif

	if (!shm_block){
		LM_CRIT("could not initialize shared malloc\n");
		shm_mem_destroy();
		return -1;
	}

#if defined(SHM_EXTRA_STATS) && defined(SHM_SHOW_DEFAULT_GROUP)
	/* we create the the default group statistic where memory alocated untill groups are defined is indexed */

	#ifndef DBG_MALLOC
	memory_mods_stats = MY_MALLOC_UNSAFE(shm_block, sizeof(struct module_info));
	#else
	memory_mods_stats = MY_MALLOC_UNSAFE(shm_block, sizeof(struct module_info), __FILE__, __FUNCTION__, __LINE__ );
	#endif

	if(!memory_mods_stats){
		LM_CRIT("could not alloc shared memory");
		return -1;
	}
	//initialize the new created groups
	memset((void*)&memory_mods_stats[0], 0, sizeof(struct module_info));
	if (init_new_stat((stat_var*)&memory_mods_stats[0].fragments) < 0)
		return -1;
	
	if (init_new_stat((stat_var*)&memory_mods_stats[0].memory_used) < 0)
		return -1;
	
	if (init_new_stat((stat_var*)&memory_mods_stats[0].real_used) < 0)
		return -1;

	if (init_new_stat((stat_var*)&memory_mods_stats[0].max_real_used) < 0)
		return -1;

	memory_mods_stats[0].lock = shm_malloc_unsafe(sizeof (gen_lock_t));

	if (!memory_mods_stats[0].lock) {
		LM_ERR("Failed to allocate lock \n");
		return -1;
	}

	if (!lock_init(memory_mods_stats[0].lock)) {
		LM_ERR("Failed to init lock \n");
		return -1;
	}

	#ifdef HP_MALLOC
		update_stat((stat_var*)&memory_mods_stats[0].fragments, shm_block->total_fragments);
	#else
		update_stat((stat_var*)&memory_mods_stats[0].fragments, shm_block->fragments);
	#endif

	update_stat((stat_var*)&memory_mods_stats[0].memory_used, shm_block->used);
	update_stat((stat_var*)&memory_mods_stats[0].real_used, shm_block->real_used);
#endif

#ifdef HP_MALLOC
	/* lock_alloc cannot be used yet! */
	mem_locks = shm_malloc_unsafe(HP_TOTAL_HASH_SIZE * sizeof *mem_locks);
	if (!mem_locks) {
		LM_CRIT("could not allocate the shm lock array\n");
		shm_mem_destroy();
		return -1;
	}

	for (i = 0; i < HP_TOTAL_HASH_SIZE; i++)
		if (!lock_init(&mem_locks[i])) {
			LM_CRIT("could not initialize lock\n");
			shm_mem_destroy();
			return -1;
		}

	shm_hash_usage = shm_malloc_unsafe(HP_TOTAL_HASH_SIZE * sizeof *shm_hash_usage);
	if (!shm_hash_usage) {
		LM_ERR("failed to allocate statistics array\n");
		return -1;
	}

	memset(shm_hash_usage, 0, HP_TOTAL_HASH_SIZE * sizeof *shm_hash_usage);
#endif

#if defined F_MALLOC || defined Q_MALLOC
	mem_lock = shm_malloc_unsafe(sizeof *mem_lock);
	if (!mem_lock) {
		LM_CRIT("could not allocate the shm lock\n");
		shm_mem_destroy();
		return -1;
	}

	if (!lock_init(mem_lock)) {
		LM_CRIT("could not initialize lock\n");
		shm_mem_destroy();
		return -1;
	}
#endif

#ifdef STATISTICS
	if (event_shm_threshold) {
		event_shm_last=shm_malloc_unsafe(sizeof(long));
		if (event_shm_last==0){
			LM_CRIT("could not allocate shm last event indicator\n");
			shm_mem_destroy();
			return -1;
		}
		*event_shm_last=0;
		event_shm_pending=shm_malloc_unsafe(sizeof(int));
		if (event_shm_pending==0){
			LM_CRIT("could not allocate shm pending flags\n");
			shm_mem_destroy();
			return -1;
		}
		*event_shm_pending=0;

	}
#endif /* STATISTICS */

	LM_DBG("success\n");

	return 0;
}


int shm_mem_init(void)
{
	int fd = -1;
	LM_INFO("allocating SHM block\n");

#ifdef SHM_MMAP
	if (shm_mempool && (shm_mempool!=(void*)-1)){
#else
	if ((shm_shmid!=-1)||(shm_mempool!=(void*)-1)){
#endif
		LM_CRIT("shm already initialized\n");
		return -1;
	}

#ifndef USE_ANON_MMAP
	fd=open("/dev/zero", O_RDWR);
	if (fd==-1){
		LM_CRIT("could not open /dev/zero: %s\n", strerror(errno));
		return -1;
	}
#endif /* USE_ANON_MMAP */

	shm_mempool = shm_getmem(fd, NULL, shm_mem_size);
#ifndef USE_ANON_MMAP
	close(fd);
#endif /* USE_ANON_MMAP */
	if (shm_mempool == INVALID_MAP) {
		LM_CRIT("could not attach shared memory segment: %s\n",
				strerror(errno));
		/* destroy segment*/
		shm_mem_destroy();
		return -1;
	}

	return shm_mem_init_mallocs(shm_mempool, shm_mem_size);
}

mi_response_t *mi_shm_check(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
#if defined(Q_MALLOC) && defined(DBG_MALLOC)
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int ret;

#ifndef INLINE_ALLOC
	if (mem_allocator_shm == MM_Q_MALLOC_DBG) {
#endif

	shm_lock();
	ret = qm_mem_check(shm_block);
	shm_unlock();

	/* print the number of fragments */
	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	if (add_mi_number(resp, MI_SSTR("total_fragments"), ret) < 0) {
		LM_ERR("failed to add MI item\n");
		free_mi_response(resp);
		return NULL;
	}

	return resp;

#ifndef INLINE_ALLOC
	}
#endif
#endif

	return NULL;
}

void init_shm_post_yyparse(void)
{
#ifdef HP_MALLOC
	if (mem_allocator_shm == MM_HP_MALLOC ||
	    mem_allocator_shm == MM_HP_MALLOC_DBG) {

		if (mem_warming_enabled && hp_mem_warming(shm_block) != 0)
			LM_INFO("skipped memory warming\n");

		hp_init_shm_statistics(shm_block);
	} else if (mem_warming_enabled) {
		LM_WARN("SHM memory warming only makes sense with HP_MALLOC!\n");
	}
#endif

#ifdef SHM_EXTRA_STATS
	struct multi_str *mod_name;
	int i, len;
	char *full_name = NULL;
	stat_var *p __attribute__((unused));

	if(mem_free_idx != 1){

#ifdef SHM_SHOW_DEFAULT_GROUP
		p = (stat_var *)&memory_mods_stats[0].fragments;
		if (register_stat(STAT_PREFIX "default", "fragments", &p, STAT_NO_RESET|STAT_NOT_ALLOCATED)!=0 ) {
			LM_CRIT("can't add stat variable");
			return;
		}
		p = (stat_var *)&memory_mods_stats[0].memory_used;
		if (register_stat(STAT_PREFIX "default", "memory_used", &p, STAT_NO_RESET|STAT_NOT_ALLOCATED)!=0 ) {
			LM_CRIT("can't add stat variable");
			return;
		}

		p = (stat_var *)&memory_mods_stats[0].real_used;
		if (register_stat(STAT_PREFIX "default", "real_used", &p, STAT_NO_RESET|STAT_NOT_ALLOCATED)!=0 ) {
			LM_CRIT("can't add stat variable");
			return;
		}

		p = (stat_var *)&memory_mods_stats[0].max_real_used;
		if (register_stat(STAT_PREFIX "default", "max_real_used", &p, STAT_NOT_ALLOCATED)!=0 ) {
			LM_CRIT("can't add stat variable");
			return;
		}


		i = mem_free_idx - 1;
#else
		i = mem_free_idx - 2;
#endif
		for(mod_name = mod_names; mod_name != NULL; mod_name = mod_name->next){
			len = strlen(mod_name->s);
			full_name = pkg_malloc((len + STAT_PREFIX_LEN + 1) * sizeof(char));

			strcpy(full_name, STAT_PREFIX);
			strcat(full_name, mod_name->s);
			p = (stat_var *)&memory_mods_stats[i].fragments;
			if (register_stat(full_name, "fragments", &p, STAT_NO_RESET|STAT_NOT_ALLOCATED)!=0 ) {
				LM_CRIT("can't add stat variable");
				return;
			}

			p = (stat_var *)&memory_mods_stats[i].memory_used;
			if (register_stat(full_name, "memory_used", &p, STAT_NO_RESET|STAT_NOT_ALLOCATED)!=0 ) {
				LM_CRIT("can't add stat variable");
				return;
			}

			p = (stat_var *) &memory_mods_stats[i].real_used;
			if (register_stat(full_name, "real_used", &p, STAT_NO_RESET|STAT_NOT_ALLOCATED)!=0 ) {
				LM_CRIT("can't add stat variable");
				return;
			}

			p = (stat_var *) &memory_mods_stats[i].max_real_used;
			if (register_stat(full_name, "max_real_used", &p, STAT_NOT_ALLOCATED) != 0) {
				LM_CRIT("can't add stat variable");
				return;
			}
			i--;
		}
	}
#endif

}

void shm_mem_destroy(void)
{
#ifdef SHM_EXTRA_STATS
	int i, core_group;
	int offset;
#endif

#ifndef SHM_MMAP
	struct shmid_ds shm_info;
#endif

#ifdef HP_MALLOC
	int j;

	if (mem_allocator_shm == MM_HP_MALLOC ||
	    mem_allocator_shm == MM_HP_MALLOC_DBG)
		hp_update_shm_pattern_file();
#endif

#ifdef SHM_EXTRA_STATS
	if (memory_mods_stats && (0
#ifdef HP_MALLOC
			|| mem_locks
#endif
#if defined F_MALLOC || defined Q_MALLOC
			|| mem_lock
#endif
			)) {
		core_group = -1;
		offset = 0;
		#ifndef SHM_SHOW_DEFAULT_GROUP
		offset = -1;
		#endif

		if (core_index)
			core_group = core_index + offset;
		else {
			#ifndef SHM_SHOW_DEFAULT_GROUP
			core_group = 0;
			#endif
		}

		mem_skip_stats = 1;

		for (i = 0; i < mem_free_idx + offset; i++)
			if (i != core_group) {
				shm_free(memory_mods_stats[i].fragments.u.val);
				shm_free(memory_mods_stats[i].memory_used.u.val);
				shm_free(memory_mods_stats[i].real_used.u.val);
				shm_free(memory_mods_stats[i].max_real_used.u.val);
				lock_destroy(memory_mods_stats[i].lock);
				lock_dealloc(memory_mods_stats[i].lock);
			}

		if (core_group >= 0) {
			shm_free(memory_mods_stats[core_group].fragments.u.val);
			shm_free(memory_mods_stats[core_group].memory_used.u.val);
			shm_free(memory_mods_stats[core_group].real_used.u.val);
			lock_destroy(memory_mods_stats[core_group].lock);
			lock_dealloc(memory_mods_stats[core_group].lock);
		}

		shm_free((void*)memory_mods_stats);
	}
#endif

	if (0
#if defined F_MALLOC || defined Q_MALLOC
		|| mem_lock
#endif
#ifdef HP_MALLOC
		|| mem_locks
#endif
	) {
	#if defined F_MALLOC || defined Q_MALLOC
		if (mem_lock) {
			LM_DBG("destroying the shared memory lock\n");
			lock_destroy(mem_lock); /* we don't need to dealloc it*/
			mem_lock = NULL;
		}
	#endif

	#if defined HP_MALLOC
		if (mem_locks) {
			for (j = 0; j < HP_TOTAL_HASH_SIZE; j++)
				lock_destroy(&mem_locks[j]);
			mem_locks = NULL;
		}
	#endif

	#ifdef STATISTICS
		if (event_shm_threshold) {
			if (event_shm_last)
				shm_free(event_shm_last);
			if (event_shm_pending)
				shm_free(event_shm_pending);
		}
	#endif
	}
	shm_relmem(shm_mempool, shm_mem_size);
	shm_mempool=INVALID_MAP;

#ifndef SHM_MMAP
	if (shm_shmid!=-1) {
		shmctl(shm_shmid, IPC_RMID, &shm_info);
		shm_shmid=-1;
	}
#endif
}

void shm_relmem(void *mempool, unsigned long size)
{
	if (mempool && (mempool!=INVALID_MAP)) {
#ifdef SHM_MMAP
		munmap(mempool, size);
#else
		shmdt(mempool);
#endif
	}
}

