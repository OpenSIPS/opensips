/*
 * Copyright (C) 2016 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef _rw_locking_h
#define _rw_locking_h

#include <unistd.h>
#include "locking.h"

#define LOCK_WAIT 10

typedef struct rw_lock_t {
	gen_lock_t *lock;
	int w_flag;
	int sw_flag;
	int r_count;
} rw_lock_t;

inline static rw_lock_t * lock_init_rw(void)
{
	rw_lock_t * new_lock;
	new_lock = (rw_lock_t*)shm_malloc(sizeof(rw_lock_t));

	if (!new_lock)
		goto error;
	memset(new_lock, 0, sizeof(rw_lock_t));
	new_lock->lock = lock_alloc();

	if (!new_lock->lock)
		goto error;
	if (!lock_init(new_lock->lock))
		goto error;

	return new_lock;
error:
	if (new_lock!=NULL && new_lock->lock)
		lock_dealloc(new_lock->lock);
	if (new_lock)
		shm_free(new_lock);
	return NULL;
}

inline static void lock_destroy_rw(rw_lock_t *_lock)
{
	if (!_lock)
		return;

	if (_lock->lock) {
		lock_destroy(_lock->lock);
		lock_dealloc(_lock->lock);
	}
	shm_free(_lock);
}

#define lock_start_write(_lock) \
	do { \
		__label__ again; \
		again: \
			lock_get((_lock)->lock); \
			/* wait for the other writers */ \
			if ((_lock)->w_flag) { \
				lock_release((_lock)->lock); \
				usleep(LOCK_WAIT); \
				goto again; \
			} \
			(_lock)->w_flag = 1; \
			lock_release((_lock)->lock); \
			/* wait for readers */ \
			while ((_lock)->r_count) \
				usleep(LOCK_WAIT); \
	} while (0)

#define lock_stop_write(_lock) \
	do { \
		(_lock)->w_flag = 0; \
	} while(0)

#define lock_start_read(_lock) \
	do { \
		__label__ again; \
		again: \
			lock_get((_lock)->lock); \
			if ((_lock)->w_flag) { \
				lock_release((_lock)->lock); \
				usleep(LOCK_WAIT); \
				goto again; \
			} \
			(_lock)->r_count++; \
			lock_release((_lock)->lock); \
	} while (0)

#define lock_stop_read(_lock) \
	do { \
		lock_get((_lock)->lock); \
		(_lock)->r_count--; \
		lock_release((_lock)->lock); \
	} while (0)

#define lock_start_sw_read(_lock) \
	do { \
		__label__ again; \
		again: \
			lock_get((_lock)->lock); \
			if ((_lock)->w_flag || (_lock)->sw_flag) { \
				lock_release((_lock)->lock); \
				usleep(LOCK_WAIT); \
				goto again; \
			} \
			(_lock)->r_count++; \
			(_lock)->sw_flag = 1; \
			lock_release((_lock)->lock); \
	} while (0)

#define lock_stop_sw_read(_lock) \
	do { \
		lock_get((_lock)->lock); \
		(_lock)->r_count--; \
		lock_release((_lock)->lock); \
		(_lock)->sw_flag = 0; \
	} while (0)

/* switch to writing access with lock previously acquired for switchable reading
 * note: switching back to reading is required before releasing the lock
 */
#define lock_switch_write(_lock, __old) \
	do { \
		lock_get((_lock)->lock); \
		__old = (_lock)->w_flag; \
		(_lock)->w_flag = 1; \
		lock_release((_lock)->lock); \
		while ((_lock)->r_count > 1) \
			usleep(LOCK_WAIT); \
	} while (0)

/* switch back to reading access if previously switched to writing */
#define lock_switch_read(_lock, __old) \
	do { \
		lock_get((_lock)->lock); \
		(_lock)->w_flag = __old; \
		lock_release((_lock)->lock); \
	} while (0)

#endif
