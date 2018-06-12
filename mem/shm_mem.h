/* $Id$*
 *
 * shared mem stuff
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * History:
 * --------
 *  2003-06-29  added shm_realloc & replaced shm_resize (andrei)
 *  2003-11-19  reverted shm_resize to the old version, using
 *               realloc causes terrible fragmentation  (andrei)
 */


#ifdef SHM_MEM

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



#include "../dprint.h"
#include "../lock_ops.h" /* we don't include locking.h on purpose */

#ifdef VQ_MALLOC
#	include "vq_malloc.h"
	extern struct vqm_block* shm_block;
#	define MY_MALLOC vqm_malloc
#	define MY_FREE vqm_free
#	define MY_STATUS vqm_status
#	define  shm_malloc_init vqm_malloc_init
#	warn "no proper vq_realloc implementantion, try another memory allocator"
#elif defined F_MALLOC
#	include "f_malloc.h"
	extern struct fm_block* shm_block;
#	define MY_MALLOC fm_malloc
#	define MY_FREE fm_free
#	define MY_REALLOC fm_realloc
#	define MY_STATUS fm_status
#	define  shm_malloc_init fm_malloc_init
#else
#	include "q_malloc.h"
	extern struct qm_block* shm_block;
#	define MY_MALLOC qm_malloc
#	define MY_FREE qm_free
#	define MY_REALLOC qm_realloc
#	define MY_STATUS qm_status
#	define  shm_malloc_init qm_malloc_init
#endif

	
	extern gen_lock_t* mem_lock;


int shm_mem_init(); /* calls shm_getmem & shm_mem_init_mallocs */
int shm_getmem();   /* allocates the memory (mmap or sysv shmap) */
int shm_mem_init_mallocs(void* mempool, int size); /* initialized the mallocs
													  & the lock */
void shm_mem_destroy();



#define shm_lock()    lock_get(mem_lock)
#define shm_unlock()  lock_release(mem_lock)

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


#ifdef DBG_QM_MALLOC

#ifdef __SUNPRO_C
		#define __FUNCTION__ ""  /* gcc specific */
#endif


#define shm_malloc_unsafe(_size ) \
	MY_MALLOC(shm_block, (_size), __FILE__, __FUNCTION__, __LINE__ )


inline static void* _shm_malloc(unsigned int size, 
	char *file, char *function, int line )
{
	void *p;
	
	shm_lock();
	p=MY_MALLOC(shm_block, size, file, function, line );
	shm_unlock();
	return p; 
}


inline static void* _shm_realloc(void *ptr, unsigned int size, 
		char* file, char* function, int line )
{
	void *p;
	shm_lock();
	p=MY_REALLOC(shm_block, ptr, size, file, function, line);
	shm_unlock();
	return p;
}

#define shm_malloc( _size ) _shm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define shm_realloc( _ptr, _size ) _shm_realloc( (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )



#define shm_free_unsafe( _p  ) \
	MY_FREE( shm_block, (_p), __FILE__, __FUNCTION__, __LINE__ )

#define shm_free(_p) \
do { \
		shm_lock(); \
		shm_free_unsafe( (_p)); \
		shm_unlock(); \
}while(0)



void* _shm_resize(void* ptr, unsigned int size, char* f, char* fn, int line);
#define shm_resize(_p, _s ) _shm_resize((_p), (_s), \
		__FILE__, __FUNCTION__, __LINE__ )
/*#define shm_resize(_p, _s ) shm_realloc( (_p), (_s))*/



#else /*DBQ_QM_MALLOC*/


#define shm_malloc_unsafe(_size) MY_MALLOC(shm_block, (_size))

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
	shm_unlock();
	return p;
}



#define shm_free_unsafe( _p ) MY_FREE(shm_block, (_p))

#define shm_free(_p) \
do { \
		shm_lock(); \
		shm_free_unsafe( _p ); \
		shm_unlock(); \
}while(0)



void* _shm_resize(void* ptr, unsigned int size);
#define shm_resize(_p, _s) _shm_resize( (_p), (_s))
/*#define shm_resize(_p, _s) shm_realloc( (_p), (_s))*/


#endif


#define shm_status() \
do { \
		/*shm_lock();*/ \
		MY_STATUS(shm_block); \
		/*shm_unlock();*/ \
}while(0)




#endif

#endif

