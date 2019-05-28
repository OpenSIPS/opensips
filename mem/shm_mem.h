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


#include "../statistics.h"
#include "../error.h"

#ifndef shm_mem_h
#define shm_mem_h

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>


#ifndef SHM_MMAP

#include <sys/shm.h>

#endif

#include <sys/sem.h>
#include <string.h>
#include <errno.h>

#include "../dprint.h"
#include "../globals.h"
#include "../lock_ops.h" /* we don't include locking.h on purpose */
#include "mem_funcs.h"
#include "common.h"

#include "../mi/mi.h"

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
#include "mem_stats.h"

#ifdef INLINE_ALLOC
#if defined F_MALLOC
#define shm_stats_core_init fm_stats_core_init
#define shm_stats_get_index fm_stats_get_index
#define shm_stats_set_index fm_stats_set_index
#define shm_frag_overhead FM_FRAG_OVERHEAD
#define shm_frag_size fm_frag_size
#define shm_frag_file fm_frag_file
#define shm_frag_func fm_frag_func
#define shm_frag_line fm_frag_line
#elif defined Q_MALLOC
#define shm_stats_core_init qm_stats_core_init
#define shm_stats_get_index qm_stats_get_index
#define shm_stats_set_index qm_stats_set_index
#define shm_frag_overhead QM_FRAG_OVERHEAD
#define shm_frag_size qm_frag_size
#define shm_frag_file qm_frag_file
#define shm_frag_func qm_frag_func
#define shm_frag_line qm_frag_line
#elif defined HP_MALLOC
#define shm_stats_core_init hp_stats_core_init
#define shm_stats_get_index hp_stats_get_index
#define shm_stats_set_index hp_stats_set_index
#define shm_frag_overhead HP_FRAG_OVERHEAD
#define shm_frag_size hp_frag_size
#define shm_frag_file hp_frag_file
#define shm_frag_func hp_frag_func
#define shm_frag_line hp_frag_line
#endif
#else
extern void (*shm_stats_core_init)(void *blk, int core_index);
extern unsigned long (*shm_stats_get_index)(void *ptr);
extern void (*shm_stats_set_index)(void *ptr, unsigned long idx);
extern int shm_frag_overhead;
extern unsigned long (*shm_frag_size)(void *p);
extern const char *(*shm_frag_file)(void *p);
extern const char *(*shm_frag_func)(void *p);
extern unsigned long (*shm_frag_line)(void *p);
#endif
#endif

int set_shm_mm(const char *mm_name);

#ifndef INLINE_ALLOC
#ifdef DBG_MALLOC
extern void *(*gen_shm_malloc)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_shm_malloc_unsafe)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_shm_realloc)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_shm_realloc_unsafe)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void (*gen_shm_free)(void *blk, void *p,
                        const char *file, const char *func, unsigned int line);
extern void (*gen_shm_free_unsafe)(void *blk, void *p,
                        const char *file, const char *func, unsigned int line);
#else
extern void *(*gen_shm_malloc)(void *blk, unsigned long size);
extern void *(*gen_shm_malloc_unsafe)(void *blk, unsigned long size);
extern void *(*gen_shm_realloc)(void *blk, void *p, unsigned long size);
extern void *(*gen_shm_realloc_unsafe)(void *blk, void *p, unsigned long size);
extern void (*gen_shm_free)(void *blk, void *p);
extern void (*gen_shm_free_unsafe)(void *blk, void *p);
#endif
extern void (*gen_shm_info)(void *blk, struct mem_info *info);
extern void (*gen_shm_status)(void *blk);
extern unsigned long (*gen_shm_get_size)(void *blk);
extern unsigned long (*gen_shm_get_used)(void *blk);
extern unsigned long (*gen_shm_get_rused)(void *blk);
extern unsigned long (*gen_shm_get_mused)(void *blk);
extern unsigned long (*gen_shm_get_free)(void *blk);
extern unsigned long (*gen_shm_get_frags)(void *blk);
#endif

#ifdef INLINE_ALLOC
#ifdef F_MALLOC
#define SHM_MALLOC             fm_malloc
#define SHM_MALLOC_UNSAFE      fm_malloc
#define SHM_REALLOC            fm_realloc
#define SHM_REALLOC_UNSAFE     fm_realloc
#define SHM_FREE               fm_free
#define SHM_FREE_UNSAFE        fm_free
#define SHM_INFO               fm_info
#define SHM_STATUS             fm_status
#define SHM_GET_SIZE           fm_get_size
#define SHM_GET_USED           fm_get_used
#define SHM_GET_RUSED          fm_get_real_used
#define SHM_GET_MUSED          fm_get_max_real_used
#define SHM_GET_FREE           fm_get_free
#define SHM_GET_FRAGS          fm_get_frags
#elif defined Q_MALLOC
#define SHM_MALLOC             qm_malloc
#define SHM_MALLOC_UNSAFE      qm_malloc
#define SHM_REALLOC            qm_realloc
#define SHM_REALLOC_UNSAFE     qm_realloc
#define SHM_FREE               qm_free
#define SHM_FREE_UNSAFE        qm_free
#define SHM_INFO               qm_info
#define SHM_STATUS             qm_status
#define SHM_GET_SIZE           qm_get_size
#define SHM_GET_USED           qm_get_used
#define SHM_GET_RUSED          qm_get_real_used
#define SHM_GET_MUSED          qm_get_max_real_used
#define SHM_GET_FREE           qm_get_free
#define SHM_GET_FRAGS          qm_get_frags
#elif defined HP_MALLOC
#define SHM_MALLOC             hp_shm_malloc
#define SHM_MALLOC_UNSAFE      hp_shm_malloc_unsafe
#define SHM_REALLOC            hp_shm_realloc
#define SHM_REALLOC_UNSAFE     hp_shm_realloc_unsafe
#define SHM_FREE               hp_shm_free
#define SHM_FREE_UNSAFE        hp_shm_free_unsafe
#define SHM_INFO               hp_info
#define SHM_STATUS             hp_status
#define SHM_GET_SIZE           hp_shm_get_size
#define SHM_GET_USED           hp_shm_get_used
#define SHM_GET_RUSED          hp_shm_get_real_used
#define SHM_GET_MUSED          hp_shm_get_max_real_used
#define SHM_GET_FREE           hp_shm_get_free
#define SHM_GET_FRAGS          hp_shm_get_frags
#endif /* F_MALLOC || Q_MALLOC || HP_MALLOC */
#else
#define SHM_MALLOC             gen_shm_malloc
#define SHM_MALLOC_UNSAFE      gen_shm_malloc_unsafe
#define SHM_REALLOC            gen_shm_realloc
#define SHM_REALLOC_UNSAFE     gen_shm_realloc_unsafe
#define SHM_FREE               gen_shm_free
#define SHM_FREE_UNSAFE        gen_shm_free_unsafe
#define SHM_INFO               gen_shm_info
#define SHM_STATUS             gen_shm_status
#define SHM_GET_SIZE           gen_shm_get_size
#define SHM_GET_USED           gen_shm_get_used
#define SHM_GET_RUSED          gen_shm_get_rused
#define SHM_GET_MUSED          gen_shm_get_mused
#define SHM_GET_FREE           gen_shm_get_free
#define SHM_GET_FRAGS          gen_shm_get_frags
#endif /* INLINE_ALLOC */

#if defined F_MALLOC || defined Q_MALLOC
extern gen_lock_t* mem_lock;
extern gen_lock_t* rpmem_lock;
#endif

#ifdef HP_MALLOC
extern gen_lock_t* mem_locks;
extern gen_lock_t* rpmem_locks;
#endif

extern enum osips_mm mem_allocator_shm;


#define INVALID_MAP ((void *)-1)
int shm_mem_init(); /* calls shm_getmem & shm_mem_init_mallocs */

/*
 * must be called after the statistics engine is initialized
 *	- updates the atomic shm statistics with proper values
 *	- performs memory warming with HP_MALLOC
 */
void init_shm_post_yyparse(void);
void *shm_getmem(int, void *, unsigned long);   /* allocates the memory (mmap or sysv shmap) */
void shm_relmem(void *, unsigned long); /* deallocates the memory allocated by shm_getmem() */
void shm_mem_destroy();


#ifdef STATISTICS

// threshold percentage checked
extern long event_shm_threshold;

// determines the last percentage triggered
extern long *event_shm_last;

// determines if there is a pending event
extern int *event_shm_pending;

/* indicates the statistics updates should not be done */
#ifdef SHM_EXTRA_STATS
extern int mem_skip_stats;
#endif

// events are used only if SHM and STATISTICS are used
void shm_event_raise(long used, long size, long perc);

inline static void shm_threshold_check(void)
{
	long shm_perc, used, size;

	if (event_shm_threshold == 0 ||	// threshold not used)
			!shm_block || !event_shm_last || !event_shm_pending || // shm not init
			*event_shm_pending ) {	// somebody else is raising the event
		// do not do anything
		return;
	}

	// compute the percentage here to avoid a function call
	used = SHM_GET_RUSED(shm_block);
	size = SHM_GET_SIZE(shm_block);
	shm_perc = used * 100 / size;

	/* check if the event has to be raised or if it was already notified */
	if ((shm_perc < event_shm_threshold && *event_shm_last <= event_shm_threshold) ||
		(shm_perc >= event_shm_threshold && *event_shm_last == shm_perc))
		return;

	shm_event_raise(used, size, shm_perc);
}
#else
 #define shm_threshold_check()
#endif

#ifdef HP_MALLOC
	#ifdef INLINE_ALLOC
	#define shm_lock()
	#define shm_unlock()
	#else
	extern int shm_use_global_lock;
	#define shm_lock() \
		do { \
			if (shm_use_global_lock) \
				lock_get(mem_lock); \
		} while (0)
	#define shm_unlock() \
		do { \
			if (shm_use_global_lock) \
				lock_release(mem_lock); \
		} while (0)
	#endif
#else
#define shm_lock()    lock_get(mem_lock)
#define shm_unlock()  lock_release(mem_lock)
#endif

#ifdef SHM_EXTRA_STATS
	#define PASTER(_x, _y) _x ## _y
	#define VAR_STAT(_n) PASTER(_n, _mem_stat)
#endif

#ifdef DBG_MALLOC

	#ifdef __SUNPRO_C
			#define __FUNCTION__ ""  /* gcc specific */
	#endif

inline static void* _shm_malloc(unsigned long size,
	const char *file, const char *function, unsigned int line )
{
	void *p;

	shm_lock();

	p = SHM_MALLOC(shm_block, size, file, function, line);
	shm_threshold_check();

	shm_unlock();

	#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = shm_frag_size(p);
		update_module_stats(size_f, size_f + shm_frag_overhead, 1, VAR_STAT(MOD_NAME));
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
	#endif

	return p;
}

inline static void* _shm_malloc_unsafe(unsigned long size,
	const char *file, const char *function, unsigned int line )
{
	void *p;

	p = SHM_MALLOC_UNSAFE(shm_block, size, file, function, line);
	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = shm_frag_size(p);
		update_module_stats(size_f, size_f + shm_frag_overhead, 1, VAR_STAT(MOD_NAME));
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

inline static void* _shm_malloc_bulk(unsigned long size,
	const char *file, const char *function, unsigned int line )
{
	void *p;

	p = SHM_MALLOC(shm_block, size, file, function, line);
	shm_threshold_check();

	#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = shm_frag_size(p);
		update_module_stats(size_f, size_f + shm_frag_overhead, 1, VAR_STAT(MOD_NAME));
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
	#endif

	return p;
}

inline static void* _shm_realloc(void *ptr, unsigned int size, 
		const char* file, const char* function, int line )
{
	void *p;

	#ifdef SHM_EXTRA_STATS
		unsigned long origin = 0;
		if (ptr) {
			origin = shm_stats_get_index(ptr);
			update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
		}
	#endif

	shm_lock();

	p = SHM_REALLOC(shm_block, ptr, size, file, function, line);
	shm_threshold_check();

	shm_unlock();

	#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(shm_frag_size(p), shm_frag_size(p) + shm_frag_overhead,
			1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
				"module index %ld, at %s: %s %ld, reallocated in module index %ld, at %s: %s %d \n", 
				origin, shm_frag_file(p), shm_frag_func(p), shm_frag_line(p), VAR_STAT(MOD_NAME), file, function, line);
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
	#endif

	return p;
}

inline static void* _shm_realloc_unsafe(void *ptr, unsigned int size, 
		const char* file, const char* function, int line )
{
	void *p;

	#ifdef SHM_EXTRA_STATS
		unsigned long origin = 0;
		if (ptr) {
			origin = shm_stats_get_index(ptr);
			update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
		}
	#endif

	p = SHM_REALLOC_UNSAFE(shm_block, ptr, size, file, function, line);
	shm_threshold_check();

	#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(shm_frag_size(p), shm_frag_size(p) +  shm_frag_overhead,
			1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
				"module index %ld, at %s: %s %ld, reallocated in module index %ld, at %s: %s %d \n", 
				origin, shm_frag_file(p), shm_frag_func(p), shm_frag_line(p), VAR_STAT(MOD_NAME), file, function, line);
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
	#endif

	return p;
}

inline static void _shm_free(void *ptr,
		const char* file, const char* function, unsigned int line)
{
	shm_lock();

	#ifdef SHM_EXTRA_STATS
		if (shm_stats_get_index(ptr) !=  VAR_STAT(MOD_NAME)) {
				update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
				LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
					"module with index %ld, freed in module index %ld, at %s: %s %d \n", shm_stats_get_index(ptr), VAR_STAT(MOD_NAME),
					__FILE__, __FUNCTION__, __LINE__);
		} else {
			update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, VAR_STAT(MOD_NAME));
		}
	#endif

	SHM_FREE(shm_block, ptr, file, function, line);
	shm_threshold_check();

	shm_unlock();
}

inline static void _shm_free_unsafe(void *ptr,
		const char* file, const char* function, unsigned int line )
{
#ifdef SHM_EXTRA_STATS
	if (shm_stats_get_index(ptr) !=  VAR_STAT(MOD_NAME)) {
		update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
		LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
			"module index %ld, at %s: %s %ld, freed in module index %ld, at %s: %s %d \n",
			shm_stats_get_index(ptr), shm_frag_file(ptr), shm_frag_func(ptr), shm_frag_line(ptr), VAR_STAT(MOD_NAME),
			file, function, line);
	} else {
		update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, VAR_STAT(MOD_NAME));
	}
#endif

	SHM_FREE_UNSAFE(shm_block, ptr, file, function, line);
	shm_threshold_check();
}

inline static void _shm_free_bulk(void *ptr,
		const char* file, const char* function, unsigned int line)
{
	#ifdef SHM_EXTRA_STATS
		if (shm_stats_get_index(ptr) !=  VAR_STAT(MOD_NAME)) {
				update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
				LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
					"module with index %ld, freed in module index %ld, at %s: %s %d \n", shm_stats_get_index(ptr), VAR_STAT(MOD_NAME),
					__FILE__, __FUNCTION__, __LINE__);
		} else {
			update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, VAR_STAT(MOD_NAME));
		}
	#endif

	SHM_FREE(shm_block, ptr, file, function, line);
	shm_threshold_check();
}


#define shm_malloc_func _shm_malloc
#define shm_malloc( _size ) _shm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_malloc_unsafe_func _shm_malloc_unsafe
#define shm_malloc_unsafe(_size ) _shm_malloc_unsafe((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_malloc_bulk_func  _shm_malloc_bulk
#define shm_malloc_bulk(_size ) _shm_malloc_bulk((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc_func _shm_realloc
#define shm_realloc( _ptr, _size ) _shm_realloc( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc_func_unsafe _shm_realloc_unsafe
#define shm_realloc_unsafe( _ptr, _size ) _shm_realloc_unsafe( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_free_func _shm_free
#define shm_free( _ptr ) _shm_free( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_free_unsafe_func _shm_free_unsafe
#define shm_free_unsafe( _ptr ) _shm_free_unsafe( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_free_bulk_func _shm_free_bulk
#define shm_free_bulk( _ptr ) _shm_free_bulk( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#ifndef	HP_MALLOC
extern unsigned long long *shm_hash_usage;
#endif

#else /*DBG_MALLOC*/

#define shm_malloc_func shm_malloc
inline static void* shm_malloc(unsigned long size)
{
	void *p;

	shm_lock();

	p = SHM_MALLOC(shm_block, size);
	shm_threshold_check();

	shm_unlock();

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = shm_frag_size(p);
		update_module_stats(size_f, size_f + shm_frag_overhead, 1, VAR_STAT(MOD_NAME));
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

#define shm_malloc_func_unsafe shm_malloc_unsafe
inline static void* shm_malloc_unsafe(unsigned int size)
{
	void *p;

	p = SHM_MALLOC_UNSAFE(shm_block, size);

	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = shm_frag_size(p);
		update_module_stats(size_f, size_f + shm_frag_overhead, 1, VAR_STAT(MOD_NAME));
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

#define shm_malloc_bulk_func shm_malloc_bulk
inline static void* shm_malloc_bulk(unsigned long size)
{
	void *p;

	p = SHM_MALLOC(shm_block, size);
	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = shm_frag_size(p);
		update_module_stats(size_f, size_f + shm_frag_overhead, 1, VAR_STAT(MOD_NAME));
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

#define shm_realloc_func shm_realloc
inline static void* shm_realloc(void *ptr, unsigned int size)
{
	void *p;

	shm_lock();

#ifdef SHM_EXTRA_STATS
	unsigned long origin = 0;
	if (ptr) {
		origin = shm_stats_get_index(ptr);
		update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
	}
#endif

	p = SHM_REALLOC(shm_block, ptr, size);
	shm_threshold_check();

	shm_unlock();

#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(shm_frag_size(p), shm_frag_size(p) + shm_frag_overhead,
		                    1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
				"module with index %ld, freed in module with index %ld, at %s: %s %d \n", origin,
				VAR_STAT(MOD_NAME), __FILE__, __FUNCTION__, __LINE__);
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

#define shm_realloc_func_unsafe shm_realloc_unsafe
inline static void* shm_realloc_unsafe(void *ptr, unsigned int size)
{
	void *p;
#ifdef SHM_EXTRA_STATS
	unsigned long origin = 0;
	if (ptr) {
		origin = shm_stats_get_index(ptr);
		update_module_stats(-shm_frag_size(ptr), -(shm_frag_size(ptr) + shm_frag_overhead), -1, shm_stats_get_index(ptr));
	}
#endif

	p = SHM_REALLOC_UNSAFE(shm_block, ptr, size);
	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(shm_frag_size(p), shm_frag_size(p) + shm_frag_overhead,
		                    1, VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
				"module with index %ld, freed in module with index %ld, at %s: %s %d \n", origin,
				VAR_STAT(MOD_NAME), __FILE__, __FUNCTION__, __LINE__);
		shm_stats_set_index(p, VAR_STAT(MOD_NAME));
	}
#endif
	return p;
}

#define shm_free_func shm_free
inline static void shm_free(void *_p)
{
	shm_lock();

	#ifdef SHM_EXTRA_STATS
		if (shm_stats_get_index(_p) !=  VAR_STAT(MOD_NAME)) {
				update_module_stats(-shm_frag_size(_p), -(shm_frag_size(_p) + shm_frag_overhead), -1, shm_stats_get_index(_p));
				LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
					"module with index %ld, freed in module index %ld, at %s: %s %d \n", shm_stats_get_index(_p), VAR_STAT(MOD_NAME),
					__FILE__, __FUNCTION__, __LINE__);
		} else {
			update_module_stats(-shm_frag_size(_p), -(shm_frag_size(_p) + shm_frag_overhead), -1, VAR_STAT(MOD_NAME));
		}
	#endif

	SHM_FREE(shm_block, _p);
	shm_threshold_check();

	shm_unlock();
}

#define shm_free_unsafe_func shm_free_unsafe
inline static void shm_free_unsafe(void *_p)
{
	#ifdef SHM_EXTRA_STATS
	if (shm_stats_get_index(_p) !=  VAR_STAT(MOD_NAME)) {
			update_module_stats(-shm_frag_size(_p), -(shm_frag_size(_p) + shm_frag_overhead), -1, shm_stats_get_index(_p));
			LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
				"module with index %ld, freed in module index %ld, at %s: %s %d \n", shm_stats_get_index(_p), VAR_STAT(MOD_NAME),
				__FILE__, __FUNCTION__, __LINE__);
	} else {
		update_module_stats(-shm_frag_size(_p), -(shm_frag_size(_p) + shm_frag_overhead), -1, VAR_STAT(MOD_NAME));
	}
	#endif
	SHM_FREE_UNSAFE(shm_block, (_p)); \
	shm_threshold_check(); \
}

#define shm_free_bulk_func shm_free_bulk
inline static void shm_free_bulk(void *_p)
{
	#ifdef SHM_EXTRA_STATS
		if (shm_stats_get_index(_p) !=  VAR_STAT(MOD_NAME)) {
				update_module_stats(-shm_frag_size(_p), -(shm_frag_size(_p) + shm_frag_overhead), -1, shm_stats_get_index(_p));
				LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
					"module with index %ld, freed in module index %ld, at %s: %s %d \n", shm_stats_get_index(_p), VAR_STAT(MOD_NAME),
					__FILE__, __FUNCTION__, __LINE__);
		} else {
			update_module_stats(-shm_frag_size(_p), -(shm_frag_size(_p) + shm_frag_overhead), -1, VAR_STAT(MOD_NAME));
		}
	#endif

	SHM_FREE(shm_block, _p);
	shm_threshold_check();
}

#endif

inline static void shm_status(void)
{
	shm_lock();
	SHM_STATUS(shm_block);
	shm_unlock();
}


inline static void shm_info(struct mem_info* mi)
{
	shm_lock();
	SHM_INFO(shm_block, mi);
	shm_unlock();
}

/*
 * performs a full shared memory pool scan for any corruptions or inconsistencies
 */
mi_response_t *mi_shm_check(const mi_params_t *params,
								struct mi_handler *async_hdl);

#ifdef STATISTICS
extern stat_export_t shm_stats[];

inline static unsigned long shm_get_size(unsigned short foo) {
	return SHM_GET_SIZE(shm_block);
}
inline static unsigned long shm_get_used(unsigned short foo) {
	return SHM_GET_USED(shm_block);
}
inline static unsigned long shm_get_rused(unsigned short foo) {
	return SHM_GET_RUSED(shm_block);
}
inline static unsigned long shm_get_mused(unsigned short foo) {
	return SHM_GET_MUSED(shm_block);
}
inline static unsigned long shm_get_free(unsigned short foo) {
	return SHM_GET_FREE(shm_block);
}
inline static unsigned long shm_get_frags(unsigned short foo) {
	return SHM_GET_FRAGS(shm_block);
}
#endif /*STATISTICS*/

#endif

