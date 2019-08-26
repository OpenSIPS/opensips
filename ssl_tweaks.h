
#include <openssl/opensslv.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>

int pthread_mutex_init (pthread_mutex_t *__mutex,
		const pthread_mutexattr_t *__mutexattr)
{
	int ret;
	pthread_mutexattr_t *attr;
	pthread_mutexattr_t local_attr;
	int (*real_pthread_mutex_init)(pthread_mutex_t *,
			const pthread_mutexattr_t *);

	real_pthread_mutex_init = dlsym(RTLD_NEXT, "pthread_mutex_init");
	if (!real_pthread_mutex_init)
		return -1;

	if (__mutexattr)
		attr = (pthread_mutexattr_t *)__mutexattr;
	else {
		ret = pthread_mutexattr_init(&local_attr);
		if (ret != 0)
			return ret;

		attr = &local_attr;
	}
	ret = pthread_mutexattr_setpshared(attr, PTHREAD_PROCESS_SHARED);
	if (ret != 0)
		goto destroy;
	ret = real_pthread_mutex_init(__mutex, attr);
destroy:
	if (attr != __mutexattr)
		pthread_mutexattr_destroy(attr);
	return ret;
}

int pthread_rwlock_init (pthread_rwlock_t *__restrict __rwlock,
		                const pthread_rwlockattr_t *__restrict __attr)
{
	int ret;
	pthread_rwlockattr_t *attr;
	pthread_rwlockattr_t local_attr;
	int (*real_pthread_rwlock_init)(pthread_rwlock_t *,
			const pthread_rwlockattr_t *);

	real_pthread_rwlock_init = dlsym(RTLD_NEXT, "pthread_rwlock_init");
	if (!real_pthread_rwlock_init)
		return -1;

	if (__attr)
		attr = (pthread_rwlockattr_t *)__attr;
	else {
		ret = pthread_rwlockattr_init(&local_attr);
		if (ret != 0)
			return ret;

		attr = &local_attr;
	}
	ret = pthread_rwlockattr_setpshared(attr, PTHREAD_PROCESS_SHARED);
	if (ret != 0)
		goto destroy;
	ret = real_pthread_rwlock_init(__rwlock, attr);
destroy:
	if (attr != __attr)
		pthread_rwlockattr_destroy(attr);
	return ret;
}

#endif
