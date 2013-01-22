/* $Id$*
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2003-06-29  added shm_realloc & replaced shm_resize (andrei)
 *  2003-11-19  reverted shm_resize to the old version, using
 *               realloc causes terrible fragmentation  (andrei)
 */


#ifdef SHM_MEM

#include "../statistics.h"

#ifndef shm_mem_h
#define shm_mem_h

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

/* fix DBG MALLOC stuff */

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


#include "../dprint.h"
#include "../lock_ops.h" /* we don't include locking.h on purpose */

#ifdef VQ_MALLOC
#	include "vq_malloc.h"
	extern struct vqm_block* shm_block;
#	define MY_MALLOC vqm_malloc
#	define MY_FREE vqm_free
#	define MY_STATUS vqm_status
#	define  shm_malloc_init vqm_malloc_init
#	warn "no proper vq_realloc implementation, try another memory allocator"
#elif defined F_MALLOC
#	include "f_malloc.h"
	extern struct fm_block* shm_block;
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
#else
#	include "q_malloc.h"
	extern struct qm_block* shm_block;
#	define MY_MALLOC qm_malloc
#	define MY_FREE qm_free
#	define MY_REALLOC qm_realloc
#	define MY_STATUS qm_status
#	define MY_MEMINFO	qm_info
#	ifdef STATISTICS
#		define MY_SHM_GET_SIZE	qm_get_size
#		define MY_SHM_GET_USED	qm_get_used
#		define MY_SHM_GET_RUSED	qm_get_real_used
#		define MY_SHM_GET_MUSED	qm_get_max_real_used
#		define MY_SHM_GET_FREE	qm_get_free
#		define MY_SHM_GET_FRAGS	qm_get_frags
#	endif
#	define  shm_malloc_init qm_malloc_init
#endif

	
	extern gen_lock_t* mem_lock;


int shm_mem_init(); /* calls shm_getmem & shm_mem_init_mallocs */
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


#define shm_lock()    lock_get(mem_lock)
#define shm_unlock()  lock_release(mem_lock)


#ifdef DBG_QM_MALLOC

#ifdef __SUNPRO_C
		#define __FUNCTION__ ""  /* gcc specific */
#endif


#define shm_malloc_unsafe(_size ) \
	MY_MALLOC(shm_block, (_size), __FILE__, __FUNCTION__, __LINE__ )

inline static void* shm_malloc_unsafe(unsigned int size, 
	const char *file, const char *function, int line )
{
	void *p = MY_MALLOC(shm_block, size, file, function, line);
	shm_threshold_check();
	return p;
}


inline static void* _shm_malloc(unsigned int size, 
	const char *file, const char *function, int line )
{
	void *p;
	
	shm_lock();
	p=shm_malloc_unsafe(size, file, function, line );
	shm_unlock();
	return p; 
}


inline static void* _shm_realloc(void *ptr, unsigned int size, 
		const char* file, const char* function, int line )
{
	void *p;
	shm_lock();
	p=MY_REALLOC(shm_block, ptr, size, file, function, line);
	shm_threshold_check();
	shm_unlock();
	return p;
}

#define shm_malloc( _size ) _shm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc( _ptr, _size ) _shm_realloc( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )



#define shm_free_unsafe( _p  ) \
do {\
	MY_FREE( shm_block, (_p), __FILE__, __FUNCTION__, __LINE__ ); \
	shm_threshold_check(); \
} while(0)

#define shm_free(_p) \
do { \
		shm_lock(); \
		shm_free_unsafe( (_p)); \
		shm_unlock(); \
}while(0)



void* _shm_resize(void* ptr, unsigned int size, const char* f, const char* fn,
					int line);
#define shm_resize(_p, _s ) _shm_resize((_p), (_s), \
		__FILE__, __FUNCTION__, __LINE__ )
/*#define shm_resize(_p, _s ) shm_realloc( (_p), (_s))*/



#else /*DBQ_QM_MALLOC*/


inline static void *shm_malloc_unsafe(unsigned int size)
{
	void *p = MY_MALLOC(shm_block, size);
	shm_threshold_check();
	return p;
}

inline static void* shm_malloc(unsigned int size)
{
	void *p;
	
	shm_lock();
	p=shm_malloc_unsafe(size);
	shm_unlock();
	return p; 
}


inline static void* shm_realloc(void *ptr, unsigned int size)
{
	void *p;
	shm_lock();
	p=MY_REALLOC(shm_block, ptr, size);
	shm_threshold_check();
	shm_unlock();
	return p;
}



#define shm_free_unsafe( _p ) \
do { \
	MY_FREE(shm_block, (_p)); \
	shm_threshold_check(); \
} while(0)

#define shm_free(_p) \
do { \
		shm_lock(); \
		shm_free_unsafe(_p); \
		shm_unlock(); \
}while(0)



void* _shm_resize(void* ptr, unsigned int size);
#define shm_resize(_p, _s) _shm_resize( (_p), (_s))
/*#define shm_resize(_p, _s) shm_realloc( (_p), (_s))*/


#endif


#define shm_status() \
do { \
		shm_lock(); \
		MY_STATUS(shm_block); \
		shm_unlock(); \
}while(0)


#define shm_info(mi) \
do{\
	shm_lock(); \
	MY_MEMINFO(shm_block, mi); \
	shm_unlock(); \
}while(0)


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

#endif

