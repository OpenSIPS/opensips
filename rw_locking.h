#ifndef _rw_locking_h
#define _rw_locking_h

#include <unistd.h>
#include "locking.h"

#define LOCK_WAIT 10

typedef struct rw_lock_t {
	gen_lock_t *lock;
	int w_flag;
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
	if (new_lock->lock)
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

#endif
