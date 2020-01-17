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
#include "mem_funcs.h"
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

/* returns a pointer to a restart persistency zone, identified by the key */
void *rpm_key_get(char *key);
/* sets the value of a certain key to the specified value
 * IMPORTANT: the value has to be within the restart persistency zone! */
int rpm_key_set(char *key, void *val);
/* deletes a key from the persistent zone */
int rpm_key_del(char *key);
/* initializes the restart persistency memory */
int rpm_init_mem(void);

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
extern void (*gen_rpm_info)(void *blk, struct mem_info *info);
extern void (*gen_rpm_status)(void *blk);
extern unsigned long (*gen_rpm_get_size)(void *blk);
extern unsigned long (*gen_rpm_get_used)(void *blk);
extern unsigned long (*gen_rpm_get_rused)(void *blk);
extern unsigned long (*gen_rpm_get_mused)(void *blk);
extern unsigned long (*gen_rpm_get_free)(void *blk);
extern unsigned long (*gen_rpm_get_frags)(void *blk);
#endif

#ifdef INLINE_ALLOC
#ifdef F_MALLOC
#define RPM_MALLOC             fm_malloc
#define RPM_MALLOC_UNSAFE      fm_malloc
#define RPM_REALLOC            fm_realloc
#define RPM_REALLOC_UNSAFE     fm_realloc
#define RPM_FREE               fm_free
#define RPM_FREE_UNSAFE        fm_free
#define RPM_INFO               fm_info
#define RPM_STATUS             fm_status
#define RPM_GET_SIZE           fm_get_size
#define RPM_GET_USED           fm_get_used
#define RPM_GET_RUSED          fm_get_real_used
#define RPM_GET_MUSED          fm_get_max_real_used
#define RPM_GET_FREE           fm_get_free
#define RPM_GET_FRAGS          fm_get_frags
#elif defined Q_MALLOC
#define RPM_MALLOC             qm_malloc
#define RPM_MALLOC_UNSAFE      qm_malloc
#define RPM_REALLOC            qm_realloc
#define RPM_REALLOC_UNSAFE     qm_realloc
#define RPM_FREE               qm_free
#define RPM_FREE_UNSAFE        qm_free
#define RPM_INFO               qm_info
#define RPM_STATUS             qm_status
#define RPM_GET_SIZE           qm_get_size
#define RPM_GET_USED           qm_get_used
#define RPM_GET_RUSED          qm_get_real_used
#define RPM_GET_MUSED          qm_get_max_real_used
#define RPM_GET_FREE           qm_get_free
#define RPM_GET_FRAGS          qm_get_frags
#elif defined HP_MALLOC
#define RPM_MALLOC             hp_rpm_malloc
#define RPM_MALLOC_UNSAFE      hp_rpm_malloc_unsafe
#define RPM_REALLOC            hp_rpm_realloc
#define RPM_REALLOC_UNSAFE     hp_rpm_realloc_unsafe
#define RPM_FREE               hp_rpm_free
#define RPM_FREE_UNSAFE        hp_rpm_free_unsafe
#define RPM_INFO               hp_info
#define RPM_STATUS             hp_status
#define RPM_GET_SIZE           hp_rpm_get_size
#define RPM_GET_USED           hp_rpm_get_used
#define RPM_GET_RUSED          hp_rpm_get_real_used
#define RPM_GET_MUSED          hp_rpm_get_max_real_used
#define RPM_GET_FREE           hp_rpm_get_free
#define RPM_GET_FRAGS          hp_rpm_get_frags
#endif /* F_MALLOC || Q_MALLOC || HP_MALLOC */
#else
#define RPM_MALLOC             gen_rpm_malloc
#define RPM_MALLOC_UNSAFE      gen_rpm_malloc_unsafe
#define RPM_REALLOC            gen_rpm_realloc
#define RPM_REALLOC_UNSAFE     gen_rpm_realloc_unsafe
#define RPM_FREE               gen_rpm_free
#define RPM_FREE_UNSAFE        gen_rpm_free_unsafe
#define RPM_INFO               gen_rpm_info
#define RPM_STATUS             gen_rpm_status
#define RPM_GET_SIZE           gen_rpm_get_size
#define RPM_GET_USED           gen_rpm_get_used
#define RPM_GET_RUSED          gen_rpm_get_rused
#define RPM_GET_MUSED          gen_rpm_get_mused
#define RPM_GET_FREE           gen_rpm_get_free
#define RPM_GET_FRAGS          gen_rpm_get_frags
#endif /* INLINE_ALLOC */

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

inline static void* _rpm_malloc(unsigned long size,
	const char *file, const char *function, unsigned int line )
{
	void *p;

	rpm_lock();
	p = RPM_MALLOC(rpm_block, size, file, function, line);
	rpm_unlock();

	return p;
}


inline static void* _rpm_realloc(void *ptr, unsigned int size,
		const char* file, const char* function, unsigned int line )
{
	void *p;

	rpm_lock();
	p = RPM_REALLOC(rpm_block, ptr, size, file, function, line);
	rpm_unlock();

	return p;
}

inline static void _rpm_free(void *ptr,
		const char* file, const char* function, unsigned int line)
{
	rpm_lock();
	RPM_FREE(rpm_block, ptr, file, function, line);
	rpm_unlock();
}

#define rpm_malloc_func _rpm_malloc
#define rpm_malloc( _size) _rpm_malloc((_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_malloc_func_unsafe _rpm_malloc_unsafe
#define rpm_malloc_unsafe(_size) RPM_MALLOC(rpm_block, (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_realloc_func _rpm_realloc
#define rpm_realloc(_ptr, _size) _rpm_realloc((_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_realloc_func_unsafe _rpm_realloc_unsafe
#define rpm_realloc_unsafe(_ptr, _size) RPM_REALLOC_UNSAFE(rpm_block, (_ptr), (_size), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_free_func _rpm_free
#define rpm_free( _ptr ) _rpm_free( (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#define rpm_free_func_unsafe _rpm_free_unsafe
#define rpm_free_unsafe( _ptr ) RPM_FREE_UNSAFE(rpm_block, (_ptr), \
	__FILE__, __FUNCTION__, __LINE__ )

#else /*DBG_MALLOC*/

#define rpm_malloc_func_unsafe	RPM_MALLOC_UNSAFE
#define rpm_malloc_unsafe(_size) RPM_MALLOC_UNSAFE(rpm_block, (_size))
#define rpm_realloc_func_unsafe	RPM_REALLOC_UNSAFE
#define rpm_realloc_unsafe(_ptr, _size) RPM_REALLOC_UNSAFE(rpm_block, (_ptr), (_size))
#define rpm_free_func_unsafe RPM_FREE_UNSAFE
#define rpm_free_unsafe( _ptr ) RPM_FREE_UNSAFE(rpm_block, (_ptr))


#define rpm_malloc_func			rpm_malloc
inline static void* rpm_malloc(unsigned long size)
{
	void *p;

	rpm_lock();
	p = RPM_MALLOC(rpm_block, size);
	rpm_unlock();

	return p;
}

#define rpm_realloc_func		rpm_realloc
inline static void* rpm_realloc(void *ptr, unsigned int size)
{
	void *p;

	rpm_lock();
	p = RPM_REALLOC(rpm_block, ptr, size);
	rpm_unlock();

	return p;
}

#define rpm_free_func			rpm_free
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

inline static void rpm_status(void)
{
	if (!rpm_block
#ifndef INLINE_ALLOC
		|| !gen_rpm_status
#endif
			)
		return;

	rpm_lock();
	RPM_STATUS(rpm_block);
	rpm_unlock();
}


inline static void rpm_info(struct mem_info* mi)
{
	rpm_lock();
	RPM_INFO(rpm_block, mi);
	rpm_unlock();
}


#ifdef STATISTICS
struct hp_block;
void hp_init_rpm_statistics(struct hp_block *hpb);

extern stat_export_t rpm_stats[];

inline static unsigned long rpm_get_size(unsigned short foo) {
	if (!rpm_block)
		return 0;
	return RPM_GET_SIZE(rpm_block);
}
inline static unsigned long rpm_get_used(unsigned short foo) {
	if (!rpm_block)
		return 0;
	return RPM_GET_USED(rpm_block);
}
inline static unsigned long rpm_get_rused(unsigned short foo) {
	if (!rpm_block)
		return 0;
	return RPM_GET_RUSED(rpm_block);
}
inline static unsigned long rpm_get_mused(unsigned short foo) {
	if (!rpm_block)
		return 0;
	return RPM_GET_MUSED(rpm_block);
}
inline static unsigned long rpm_get_free(unsigned short foo) {
	if (!rpm_block)
		return 0;
	return RPM_GET_FREE(rpm_block);
}
inline static unsigned long rpm_get_frags(unsigned short foo) {
	if (!rpm_block)
		return 0;
	return RPM_GET_FRAGS(rpm_block);
}
#endif /*STATISTICS*/

#endif
