/*
 * restart persistency shared mem stuff
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


#include "../error.h"

#ifndef rpm_mem_h
#define rpm_mem_h

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>

#include <sys/sem.h>
#include <string.h>
#include <errno.h>

#include "../dprint.h"
#include "../globals.h"
#include "../lock_ops.h" /* we don't include locking.h on purpose */
#include "common.h"

#include "../mi/mi.h"

/* address where we should first try to map the file */
/* on 64 bits architecture, we "afford" a large memory */
#if (defined __CPU_x86_64) || (defined __CPU_sparc64) || \
	(defined __CPU_ppc64) || (defined __CPU_mips64)
#define RPM_MAP_ADDRESS			((void *)0x550532000000)
#else
#define RPM_MAP_ADDRESS			((void *)0xea000000)
#endif

/* number of retries if a map fails */
#define RPM_MAP_RETRIES			5
/* 0RpM - OpenSIPS Restart Persistency Memory */
#define RPM_MAGIC_CODE			0x0052704Du
#define RPM_MAX_ZONE_NAME		16
#define RPM_MAX_ZONES_NO		16

/* returns a pointer towars a restart persistency zone
 * if NULL is returned, this means that the restart persistency zone is not
 * available
 * if the zone itself contains a NULL pointer, it indicates that the zone has
 * just been allocated - there was no data inside - either a new mapping, or
 * first time usage of restart persistency in this file */
void **get_rpm_zone(char *key);

extern enum osips_mm mem_allocator_rpm;
int set_rpm_mm(const char *mm_name);
extern unsigned long rpm_mem_size;
extern char *rpm_mem_file;


#ifndef INLINE_ALLOC
#ifdef DBG_MALLOC
extern void *(*gen_rpm_malloc)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_rpm_malloc_unsafe)(void *blk, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_rpm_realloc)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void *(*gen_rpm_realloc_unsafe)(void *blk, void *p, unsigned long size,
                        const char *file, const char *func, unsigned int line);
extern void (*gen_rpm_free)(void *blk, void *p,
                        const char *file, const char *func, unsigned int line);
extern void (*gen_rpm_free_unsafe)(void *blk, void *p,
                        const char *file, const char *func, unsigned int line);
#else
extern void *(*gen_rpm_malloc)(void *blk, unsigned long size);
extern void *(*gen_rpm_malloc_unsafe)(void *blk, unsigned long size);
extern void *(*gen_rpm_realloc)(void *blk, void *p, unsigned long size);
extern void *(*gen_rpm_realloc_unsafe)(void *blk, void *p, unsigned long size);
extern void (*gen_rpm_free)(void *blk, void *p);
extern void (*gen_rpm_free_unsafe)(void *blk, void *p);
#endif
#endif

#ifdef INLINE_ALLOC
#ifdef F_MALLOC
#define RPM_MALLOC             fm_malloc
#define RPM_MALLOC_UNSAFE      fm_malloc
#define RPM_REALLOC            fm_realloc
#define RPM_REALLOC_UNSAFE     fm_realloc
#define RPM_FREE               fm_free
#define RPM_FREE_UNSAFE        fm_free
#elif defined Q_MALLOC
#define RPM_MALLOC             qm_malloc
#define RPM_MALLOC_UNSAFE      qm_malloc
#define RPM_REALLOC            qm_realloc
#define RPM_REALLOC_UNSAFE     qm_realloc
#define RPM_FREE               qm_free
#define RPM_FREE_UNSAFE        qm_free
#elif defined HP_MALLOC
#define RPM_MALLOC             hp_shm_malloc
#define RPM_MALLOC_UNSAFE      hp_shm_malloc_unsafe
#define RPM_REALLOC            hp_shm_realloc
#define RPM_REALLOC_UNSAFE     hp_shm_realloc_unsafe
#define RPM_FREE               hp_shm_free
#define RPM_FREE_UNSAFE        hp_shm_free_unsafe
#endif /* F_MALLOC || Q_MALLOC || HP_MALLOC */
#else
#define RPM_MALLOC             gen_rpm_malloc
#define RPM_MALLOC_UNSAFE      gen_rpm_malloc_unsafe
#define RPM_REALLOC            gen_rpm_realloc
#define RPM_REALLOC_UNSAFE     gen_rpm_realloc_unsafe
#define RPM_FREE               gen_rpm_free
#define RPM_FREE_UNSAFE        gen_rpm_free_unsafe
#endif /* INLINE_ALLOC */

#if defined F_MALLOC || defined Q_MALLOC
extern gen_lock_t* rpmem_lock;
#endif

#ifdef HP_MALLOC
extern gen_lock_t* rpmem_locks;
#endif

#ifdef HP_MALLOC
	#ifdef INLINE_ALLOC
	#define rpm_lock()
	#define rpm_unlock()
	#else
	extern int rpm_use_global_lock;
	#define rpm_lock() \
		do { \
			if (rpm_use_global_lock) \
				lock_get(rpmem_lock); \
		} while (0)
	#define rpm_unlock() \
		do { \
			if (rpm_use_global_lock) \
				lock_release(rpmem_lock); \
		} while (0)
	#endif
#else
#define rpm_lock()    lock_get(rpmem_lock)
#define rpm_unlock()  lock_release(rpmem_lock)
#endif

#ifdef DBG_MALLOC

	#ifdef __SUNPRO_C
			#define __FUNCTION__ ""  /* gcc specific */
	#endif

inline static void* _rpm_malloc(unsigned int size,
	const char *file, const char *function, int line )
{
	void *p;

	rpm_lock();
	p = RPM_MALLOC(rpm_block, size, file, function, line);
	rpm_unlock();

	return p;
}


inline static void* _rpm_realloc(void *ptr, unsigned int size,
		const char* file, const char* function, int line )
{
	void *p;

	rpm_lock();
	p = RPM_REALLOC(rpm_block, ptr, size, file, function, line);
	rpm_unlock();

	return p;
}

inline static void _rpm_free(void *ptr,
		const char* file, const char* function, int line)
{
#ifdef HP_MALLOC
	RPM_FREE(rpm_block, ptr, file, function, line);
#else /* HP_MALLOC */
	rpm_lock();
	RPM_FREE(rpm_block, ptr, file, function, line);
	shm_unlock();
#endif /* HP_MALLOC */
}

#define rpm_malloc( _size) _rpm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_malloc_unsafe(_size) RPM_MALLOC(rpm_block, (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_realloc(_ptr, _size) _rpm_realloc((_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_realloc_unsafe(_ptr, _size) RPM_REALLOC_UNSAFE(rpm_block, (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_free( _ptr ) _rpm_free( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_free_unsafe( _ptr ) RPM_FREE_UNSAFE(rpm_block, (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#else /*DBG_MALLOC*/

#define rpm_malloc_unsafe(_size) RPM_MALLOC_UNSAFE(rpm_block, (_size))
#define rpm_realloc_unsafe(_ptr, _size) RPM_REALLOC_UNSAFE(rpm_block, (_ptr), (_size))
#define rpm_free_unsafe( _ptr ) RPM_FREE_UNSAFE(rpm_block, (_ptr))


inline static void* rpm_malloc(unsigned long size)
{
	void *p;

	rpm_lock();
	p = RPM_MALLOC(rpm_block, size);
	rpm_unlock();

	return p;
}

inline static void* rpm_realloc(void *ptr, unsigned int size)
{
	void *p;

	rpm_lock();
	p = RPM_REALLOC(rpm_block, ptr, size);
	rpm_unlock();

	return p;
}

inline static void rpm_free(void *_p)
{
	rpm_lock();

#ifdef HP_MALLOC
	RPM_FREE(rpm_block, _p);
#else
	rpm_free_unsafe( (_p));
#endif

	rpm_unlock();
}

#endif

#endif
