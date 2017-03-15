/*
 * shared mem stuff
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2003-06-29  added shm_realloc & replaced shm_resize (andrei)
 *  2003-11-19  reverted shm_resize to the old version, using
 *               realloc causes terrible fragmentation  (andrei)
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
#include "common.h"

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
#include "mem_stats.h"
#endif

#ifdef VQ_MALLOC
#	include "vq_malloc.h"
#	define MY_MALLOC vqm_malloc
#	define MY_FREE vqm_free
#	define MY_STATUS vqm_status
#	define  shm_malloc_init vqm_malloc_init
#	warn "no proper vq_realloc implementation, try another memory allocator"
#elif defined F_MALLOC
#	include "f_malloc.h"
#	define MY_MALLOC fm_malloc
#	define MY_FREE fm_free
#	define MY_REALLOC fm_realloc
#	define MY_STATUS fm_status
#	define MY_MEMINFO	fm_info
#	ifdef STATISTICS
#		define MY_SHM_GET_SIZE	fm_get_size
#		define MY_SHM_GET_USED	fm_get_used
#		define MY_SHM_GET_RUSED	fm_get_real_used
#		define MY_SHM_GET_MUSED	fm_get_max_real_used
#		define MY_SHM_GET_FREE	fm_get_free
#		define MY_SHM_GET_FRAGS	fm_get_frags
#	endif
#	define  shm_malloc_init fm_malloc_init
#	define MY_MALLOC_UNSAFE MY_MALLOC
#	define MY_FREE_UNSAFE MY_FREE
#	define MY_REALLOC_UNSAFE MY_REALLOC
#elif defined HP_MALLOC
#	include "hp_malloc.h"
#	define MY_MALLOC hp_shm_malloc
#	define MY_MALLOC_UNSAFE hp_shm_malloc_unsafe
#	define MY_FREE hp_shm_free
#	define MY_FREE_UNSAFE hp_shm_free_unsafe
#	define MY_REALLOC hp_shm_realloc
#	define MY_REALLOC_UNSAFE hp_shm_realloc_unsafe
#	define MY_STATUS hp_status
#	define MY_MEMINFO	hp_info
#	ifdef STATISTICS
#		define MY_SHM_GET_SIZE	hp_shm_get_size
#		define MY_SHM_GET_USED	hp_shm_get_used
#		define MY_SHM_GET_RUSED	hp_shm_get_real_used
#		define MY_SHM_GET_MUSED	hp_shm_get_max_real_used
#		define MY_SHM_GET_FREE	hp_shm_get_free
#		define MY_SHM_GET_FRAGS	hp_shm_get_frags
#	endif
#	define  shm_malloc_init hp_shm_malloc_init
#	define  shm_mem_warming hp_mem_warming
#	define  update_mem_pattern_file hp_update_mem_pattern_file
#elif defined QM_MALLOC
#	include "q_malloc.h"
#	define MY_MALLOC qm_malloc
#	define MY_FREE qm_free
#	define MY_REALLOC qm_realloc
#	define MY_STATUS qm_status
#	define MY_MEMINFO	qm_info
#	define MY_MALLOC_UNSAFE MY_MALLOC
#	define MY_FREE_UNSAFE MY_FREE
#	define MY_REALLOC_UNSAFE MY_REALLOC
#	ifdef STATISTICS
#		define MY_SHM_GET_SIZE	qm_get_size
#		define MY_SHM_GET_USED	qm_get_used
#		define MY_SHM_GET_RUSED	qm_get_real_used
#		define MY_SHM_GET_MUSED	qm_get_max_real_used
#		define MY_SHM_GET_FREE	qm_get_free
#		define MY_SHM_GET_FRAGS	qm_get_frags
#	endif
#	define  shm_malloc_init qm_malloc_init
#else
#	error "no memory allocator selected"
#endif


extern gen_lock_t* mem_lock;


int shm_mem_init(); /* calls shm_getmem & shm_mem_init_mallocs */

/*
 * should be called after the statistics engine is initialized
 * updates the atomic shm statistics with proper values
 */
void init_shm_statistics(void);

int shm_getmem();   /* allocates the memory (mmap or sysv shmap) */
int shm_mem_init_mallocs(void* mempool, unsigned long size); /* initialize
																the mallocs
																& the lock */
void shm_mem_destroy();


#ifdef STATISTICS

// threshold percentage checked
extern long event_shm_threshold;

// determines the last percentage triggered
extern long *event_shm_last;

// determines if there is a pending event
extern int *event_shm_pending;

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
	used = MY_SHM_GET_RUSED(shm_block);
	size = MY_SHM_GET_SIZE(shm_block);
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


#ifndef HP_MALLOC
#define shm_lock()    lock_get(mem_lock)
#define shm_unlock()  lock_release(mem_lock)
#else
#define shm_lock(i)    lock_get(&mem_lock[i])
#define shm_unlock(i)  lock_release(&mem_lock[i])
#endif

#ifdef SHM_EXTRA_STATS
	#define PASTER(_x, _y) _x ## _y
	#define VAR_STAT(_n) PASTER(_n, _mem_stat)
#endif

#ifdef DBG_MALLOC

	#ifdef __SUNPRO_C
			#define __FUNCTION__ ""  /* gcc specific */
	#endif

inline static void* _shm_malloc_unsafe(unsigned int size,
	const char *file, const char *function, int line )
{
	void *p;

	p = MY_MALLOC_UNSAFE(shm_block, size, file, function, line);
	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = frag_size(p);
		update_module_stats(size_f, size_f + FRAG_OVERHEAD, 1, VAR_STAT(MOD_NAME));
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

inline static void* _shm_malloc(unsigned int size, 
	const char *file, const char *function, int line )
{
	void *p;

	#ifndef HP_MALLOC
		shm_lock();
	#endif

	p = MY_MALLOC(shm_block, size, file, function, line);
	shm_threshold_check();

	#ifndef HP_MALLOC
		shm_unlock();
	#endif

	#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = frag_size(p);
		update_module_stats(size_f, size_f + FRAG_OVERHEAD, 1, VAR_STAT(MOD_NAME));
		set_stat_index(p, VAR_STAT(MOD_NAME));
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
			origin = get_stat_index(ptr);
			update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
		}
	#endif

#ifndef HP_MALLOC
	shm_lock();
#endif

	p = MY_REALLOC(shm_block, ptr, size, file, function, line);
	shm_threshold_check();

#ifndef HP_MALLOC
	shm_unlock();
#endif

	#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) + FRAG_OVERHEAD,
			1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from diferent module than it was allocated, allocated in"
				"module index %ld, at %s: %s %ld, reallocated in module index %ld, at %s: %s %d \n", 
				origin, _FRAG_FILE(p), _FRAG_FUNC(p), _FRAG_LINE(p), VAR_STAT(MOD_NAME), file, function, line);
		set_stat_index(p, VAR_STAT(MOD_NAME));
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
			origin = get_stat_index(ptr);
			update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
		}
	#endif

	p = MY_REALLOC_UNSAFE(shm_block, ptr, size, file, function, line);
	shm_threshold_check();

	#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) +  FRAG_OVERHEAD,
			1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from diferent module than it was allocated, allocated in"
				"module index %ld, at %s: %s %ld, reallocated in module index %ld, at %s: %s %d \n", 
				origin, _FRAG_FILE(p), _FRAG_FUNC(p), _FRAG_LINE(p), VAR_STAT(MOD_NAME), file, function, line);
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
	#endif

	return p;
}


#define shm_malloc( _size ) _shm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_malloc_unsafe(_size ) _shm_malloc_unsafe((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc( _ptr, _size ) _shm_realloc( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc_unsafe( _ptr, _size ) _shm_realloc_unsafe( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )


#ifndef SHM_EXTRA_STATS
	#define shm_free_unsafe( _p  ) \
	do {\
		MY_FREE_UNSAFE( shm_block, (_p), __FILE__, __FUNCTION__, __LINE__ ); \
		shm_threshold_check(); \
	} while(0)

	#ifdef HP_MALLOC
	#define shm_free( _p  ) MY_FREE( shm_block, (_p), __FILE__, __FUNCTION__, __LINE__ )
	#endif
#else
	#define shm_free_unsafe( _p  ) \
	do {\
		if (get_stat_index(_p) !=  VAR_STAT(MOD_NAME)) { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, get_stat_index(_p)); \
			LM_GEN1(memlog, "memory freed from diferent module than it was allocated, allocated in" \
				"module index %ld, at %s: %s %ld, freed in module index %ld, at %s: %s %d \n", \
				get_stat_index(_p), _FRAG_FILE(_p), _FRAG_FUNC(_p), _FRAG_LINE(_p), VAR_STAT(MOD_NAME), \
				__FILE__, __FUNCTION__, __LINE__); \
		} else { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME)); \
		} \
		MY_FREE_UNSAFE( shm_block, (_p), __FILE__, __FUNCTION__, __LINE__ ); \
		shm_threshold_check(); \
	} while(0)

	#ifdef HP_MALLOC
	#define shm_free( _p  ) \
	do {\
		if (get_stat_index(_p) !=  VAR_STAT(MOD_NAME)) { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, get_stat_index(_p)); \
			LM_GEN1(memlog, "memory freed from diferent module than it was allocated, allocated in" \
				"module index %ld, at %s: %s %ld, freed in module index %ld, at %s: %s %d \n", \
				get_stat_index(_p), _FRAG_FILE(_p), _FRAG_FUNC(_p), _FRAG_LINE(_p), VAR_STAT(MOD_NAME), \
				__FILE__, __FUNCTION__, __LINE__); \
		} else { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME)); \
		} \
		MY_FREE( shm_block, (_p), __FILE__, __FUNCTION__, __LINE__ ); \
	} while(0)
	#endif
#endif

#ifndef HP_MALLOC
#define shm_free(_p) \
do { \
		shm_lock(); \
		shm_free_unsafe( (_p)); \
		shm_unlock(); \
}while(0)
#endif

#ifndef	HP_MALLOC
extern unsigned long long *mem_hash_usage;
#endif

void* _shm_resize(void* ptr, unsigned int size, const char* f, const char* fn,
					int line);
#define shm_resize(_p, _s ) _shm_resize((_p), (_s), \
		__FILE__, __FUNCTION__, __LINE__ )
/*#define shm_resize(_p, _s ) shm_realloc( (_p), (_s))*/



#else /*DBG_MALLOC*/

inline static void* shm_malloc_unsafe(unsigned int size)
{
	void *p;

	p = MY_MALLOC_UNSAFE(shm_block, size);

	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = frag_size(p);
		update_module_stats(size_f, size_f + FRAG_OVERHEAD, 1, VAR_STAT(MOD_NAME));
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

inline static void* shm_malloc(unsigned long size)
{
	void *p;

#ifndef HP_MALLOC
	shm_lock();
#endif

	p = MY_MALLOC(shm_block, size);
	shm_threshold_check();

#ifndef HP_MALLOC
	shm_unlock();
#endif

#ifdef SHM_EXTRA_STATS
	if (p) {
		unsigned long size_f = frag_size(p);
		update_module_stats(size_f, size_f + FRAG_OVERHEAD, 1, VAR_STAT(MOD_NAME));
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

inline static void* shm_realloc(void *ptr, unsigned int size)
{
	void *p;

#ifndef HP_MALLOC
	shm_lock();
#if (defined F_MALLOC) && !(defined F_MALLOC_OPTIMIZATIONS)
	if (ptr >= (void *)mem_block->first_frag &&
		ptr <= (void *)mem_block->last_frag) {
		LM_BUG("shm_realloc(%u) on pkg ptr %p - aborting!\n", size, ptr);
		abort();
	} else if (ptr && (ptr < (void *)shm_block->first_frag ||
			   ptr > (void *)shm_block->last_frag)) {
		LM_BUG("shm_realloc(%u) on non-shm ptr %p - aborting!\n", size, ptr);
		abort();
	}
#endif
#endif

#ifdef SHM_EXTRA_STATS
	unsigned long origin = 0;
	if (ptr) {
		origin = get_stat_index(ptr);
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
	}
#endif

	p = MY_REALLOC(shm_block, ptr, size);
	shm_threshold_check();

#ifndef HP_MALLOC
	shm_unlock();
#endif

#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) + FRAG_OVERHEAD,
		                    1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from diferent module than it was allocated, allocated in"
				"module with index %ld, freed in module with index %ld, at %s: %s %d \n", origin,
				VAR_STAT(MOD_NAME), __FILE__, __FUNCTION__, __LINE__);
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
#endif

	return p;
}

inline static void* shm_realloc_unsafe(void *ptr, unsigned int size)
{
	void *p;
#ifdef SHM_EXTRA_STATS
	unsigned long origin = 0;
	if (ptr) {
		origin = get_stat_index(ptr);
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
	}
#endif

	p = MY_REALLOC_UNSAFE(shm_block, ptr, size);
	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) + FRAG_OVERHEAD,
		                    1, VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from diferent module than it was allocated, allocated in"
				"module with index %ld, freed in module with index %ld, at %s: %s %d \n", origin,
				VAR_STAT(MOD_NAME), __FILE__, __FUNCTION__, __LINE__);
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
#endif
	return p;
}

#ifndef SHM_EXTRA_STATS
#define shm_free_unsafe( _p ) \
do { \
	MY_FREE_UNSAFE(shm_block, (_p)); \
	shm_threshold_check(); \
} while(0)
#else
#define shm_free_unsafe( _p ) \
do { \
	if (get_stat_index(_p) !=  VAR_STAT(MOD_NAME)) { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, get_stat_index(_p)); \
			LM_GEN1(memlog, "memory freed from diferent module than it was allocated, allocated in" \
				"module with index %ld, freed in module index %ld, at %s: %s %d \n", get_stat_index(_p), VAR_STAT(MOD_NAME), \
				__FILE__, __FUNCTION__, __LINE__); \
		} else { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME)); \
		} \
	MY_FREE_UNSAFE(shm_block, (_p)); \
	shm_threshold_check(); \
} while(0)

#endif

/**
 * FIXME: tmp hacks --liviu
 */
inline static void shm_free(void *_p)
{
#ifndef HP_MALLOC
	shm_lock();
#if defined(F_MALLOC) && !defined(F_MALLOC_OPTIMIZATIONS)
	if (_p >= (void *)mem_block->first_frag &&
		_p <= (void *)mem_block->last_frag) {
		LM_BUG("shm_free() on pkg ptr %p - aborting!\n", _p);
		abort();
	} else if (_p && (_p < (void *)shm_block->first_frag ||
					  _p > (void *)shm_block->last_frag)) {
		LM_BUG("shm_free() on non-shm ptr %p - aborting!\n", _p);
		abort();
	}
#endif
#endif

#ifdef HP_MALLOC
	#ifdef SHM_EXTRA_STATS
	if (get_stat_index(_p) !=  VAR_STAT(MOD_NAME)) {
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, get_stat_index(_p));
			LM_GEN1(memlog, "memory freed from diferent module than it was allocated, allocated in"
				"module with index %ld, freed in module index %ld, at %s: %s %d \n", get_stat_index(_p), VAR_STAT(MOD_NAME),
				__FILE__, __FUNCTION__, __LINE__);
		} else {
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME));
		}
	#endif
	MY_FREE(shm_block, _p);
#else
	shm_free_unsafe( (_p));
#endif

#ifndef HP_MALLOC
	shm_unlock();
#endif
}


void* _shm_resize(void* ptr, unsigned int size);
#define shm_resize(_p, _s) _shm_resize( (_p), (_s))
/*#define shm_resize(_p, _s) shm_realloc( (_p), (_s))*/


#endif


inline static void shm_status(void)
{
#ifndef HP_MALLOC
		shm_lock();
#endif

		MY_STATUS(shm_block);

#ifndef HP_MALLOC
		shm_unlock();
#endif
}


#define shm_info(mi) \
do{\
	shm_lock(); \
	MY_MEMINFO(shm_block, mi); \
	shm_unlock(); \
}while(0)

/*
 * performs a full shared memory pool scan for any corruptions or inconsistencies
 */
struct mi_root *mi_shm_check(struct mi_root *cmd, void *param);

#ifdef STATISTICS
extern stat_export_t shm_stats[];

inline static unsigned long shm_get_size(unsigned short foo) {
	return MY_SHM_GET_SIZE(shm_block);
}
inline static unsigned long shm_get_used(unsigned short foo) {
	return MY_SHM_GET_USED(shm_block);
}
inline static unsigned long shm_get_rused(unsigned short foo) {
	return MY_SHM_GET_RUSED(shm_block);
}
inline static unsigned long shm_get_mused(unsigned short foo) {
	return MY_SHM_GET_MUSED(shm_block);
}
inline static unsigned long shm_get_free(unsigned short foo) {
	return MY_SHM_GET_FREE(shm_block);
}
inline static unsigned long shm_get_frags(unsigned short foo) {
	return MY_SHM_GET_FRAGS(shm_block);
}
#endif /*STATISTICS*/

#endif

