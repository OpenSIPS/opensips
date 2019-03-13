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

#include "../mi/mi.h"

#ifdef SHM_EXTRA_STATS
#include "module_info.h"
#include "mem_stats.h"
#endif

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
#elif defined QM_MALLOC
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
#endif /* F_MALLOC || QM_MALLOC || HP_MALLOC */
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

extern gen_lock_t* mem_lock;
extern enum osips_mm mem_allocator_shm;


int shm_mem_init(); /* calls shm_getmem & shm_mem_init_mallocs */

/*
 * must be called after the statistics engine is initialized
 *	- updates the atomic shm statistics with proper values
 *	- performs memory warming with HP_MALLOC
 */
void init_shm_post_yyparse(void);

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

	p = SHM_MALLOC_UNSAFE(shm_block, size, file, function, line);
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

	p = SHM_MALLOC(shm_block, size, file, function, line);
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

	p = SHM_REALLOC(shm_block, ptr, size, file, function, line);
	shm_threshold_check();

#ifndef HP_MALLOC
	shm_unlock();
#endif

	#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) + FRAG_OVERHEAD,
			1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
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

	p = SHM_REALLOC_UNSAFE(shm_block, ptr, size, file, function, line);
	shm_threshold_check();

	#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) +  FRAG_OVERHEAD,
			1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
				"module index %ld, at %s: %s %ld, reallocated in module index %ld, at %s: %s %d \n", 
				origin, _FRAG_FILE(p), _FRAG_FUNC(p), _FRAG_LINE(p), VAR_STAT(MOD_NAME), file, function, line);
		set_stat_index(p, VAR_STAT(MOD_NAME));
	}
	#endif

	return p;
}

inline static void _shm_free_unsafe(void *ptr,
		const char* file, const char* function, int line )
{
#ifdef SHM_EXTRA_STATS
	if (get_stat_index(ptr) !=  VAR_STAT(MOD_NAME)) {
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
		LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
			"module index %ld, at %s: %s %ld, freed in module index %ld, at %s: %s %d \n",
			get_stat_index(ptr), _FRAG_FILE(ptr), _FRAG_FUNC(ptr), _FRAG_LINE(ptr), VAR_STAT(MOD_NAME),
			file, function, line);
	} else {
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME));
	}
#endif /* SHM_EXTRA_STATS */
	SHM_FREE_UNSAFE(shm_block, ptr, file, function, line);
	shm_threshold_check();
}

inline static void _shm_free(void *ptr,
		const char* file, const char* function, int line)
{
#ifdef HP_MALLOC
#ifdef SHM_EXTRA_STATS
	if (get_stat_index(ptr) !=  VAR_STAT(MOD_NAME)) {
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
		LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
			"module index %ld, at %s: %s %ld, freed in module index %ld, at %s: %s %d \n",
			get_stat_index(ptr), _FRAG_FILE(ptr), _FRAG_FUNC(ptr), _FRAG_LINE(ptr), VAR_STAT(MOD_NAME),
			__FILE__, __FUNCTION__, __LINE__);
	} else {
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME));
	}
#endif /* SHM_EXTRA_STATS */
	SHM_FREE( shm_block, ptr, file, function, line);
	shm_threshold_check();
#else /* HP_MALLOC */
	shm_lock();
	_shm_free_unsafe(ptr, file, function, line);
	shm_unlock();
#endif /* HP_MALLOC */
}

#define shm_malloc( _size ) _shm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_malloc_unsafe(_size ) _shm_malloc_unsafe((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc( _ptr, _size ) _shm_realloc( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc_unsafe( _ptr, _size ) _shm_realloc_unsafe( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_free( _ptr ) _shm_free( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_free_unsafe( _ptr ) _shm_free_unsafe( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

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

	p = SHM_MALLOC_UNSAFE(shm_block, size);

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

	p = SHM_MALLOC(shm_block, size);
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
#endif

#ifdef SHM_EXTRA_STATS
	unsigned long origin = 0;
	if (ptr) {
		origin = get_stat_index(ptr);
		update_module_stats(-frag_size(ptr), -(frag_size(ptr) + FRAG_OVERHEAD), -1, get_stat_index(ptr));
	}
#endif

	p = SHM_REALLOC(shm_block, ptr, size);
	shm_threshold_check();

#ifndef HP_MALLOC
	shm_unlock();
#endif

#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) + FRAG_OVERHEAD,
		                    1 , VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
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

	p = SHM_REALLOC_UNSAFE(shm_block, ptr, size);
	shm_threshold_check();

#ifdef SHM_EXTRA_STATS
	if (p) {
		update_module_stats(frag_size(p), frag_size(p) + FRAG_OVERHEAD,
		                    1, VAR_STAT(MOD_NAME));
		if (ptr && origin !=  VAR_STAT(MOD_NAME))
			LM_GEN1(memlog, "memory reallocated from different module than it was allocated, allocated in"
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
	SHM_FREE_UNSAFE(shm_block, (_p)); \
	shm_threshold_check(); \
} while(0)
#else
#define shm_free_unsafe( _p ) \
do { \
	if (get_stat_index(_p) !=  VAR_STAT(MOD_NAME)) { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, get_stat_index(_p)); \
			LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in" \
				"module with index %ld, freed in module index %ld, at %s: %s %d \n", get_stat_index(_p), VAR_STAT(MOD_NAME), \
				__FILE__, __FUNCTION__, __LINE__); \
		} else { \
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME)); \
		} \
	SHM_FREE_UNSAFE(shm_block, (_p)); \
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
#endif

#ifdef HP_MALLOC
	#ifdef SHM_EXTRA_STATS
	if (get_stat_index(_p) !=  VAR_STAT(MOD_NAME)) {
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, get_stat_index(_p));
			LM_GEN1(memlog, "memory freed from different module than it was allocated, allocated in"
				"module with index %ld, freed in module index %ld, at %s: %s %d \n", get_stat_index(_p), VAR_STAT(MOD_NAME),
				__FILE__, __FUNCTION__, __LINE__);
		} else {
			update_module_stats(-frag_size(_p), -(frag_size(_p) + FRAG_OVERHEAD), -1, VAR_STAT(MOD_NAME));
		}
	#endif
	SHM_FREE(shm_block, _p);
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

		SHM_STATUS(shm_block);

#ifndef HP_MALLOC
		shm_unlock();
#endif
}


inline static void shm_info(struct mem_info* mi)
{
#ifndef HP_MALLOC
	shm_lock();
#endif
	SHM_INFO(shm_block, mi);
#ifndef HP_MALLOC
	shm_unlock();
#endif
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

