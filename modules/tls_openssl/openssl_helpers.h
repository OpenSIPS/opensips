/*
 * Copyright (C) 2015 OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
 *
 */

#ifndef _OPENSSL_HELPERS_H_
#define _OPENSSL_HELPERS_H_

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <pthread.h>
#include <stdlib.h>

#include "../tls_mgm/tls_helper.h"

#if OPENSSL_VERSION_NUMBER < 0x00908000L
        #error "using an unsupported version of OpenSSL (< 0.9.8)"
#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L
	#warning ""
	#warning "=============================================================="
	#warning "Your version of OpenSSL is < 1.0.1."
	#warning " Upgrade for better compatibility, features and security fixes!"
	#warning "============================================================="
	#warning ""
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
int ssl_versions[TLS_USE_TLSv1_3 + 1];
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
int ssl_versions[TLS_USE_TLSv1_2 + 1];
#else
SSL_METHOD     *ssl_methods[TLS_USE_TLSv1_2 + 1];
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L && defined __OS_linux
#include <sys/types.h>
#if (__GLIBC__ < 2) || (__GLIBC_MINOR__ < 30)
#include <sys/syscall.h>
#endif
#endif



/* Wrappers around process-private OpenSIPS pkg memory operations. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_malloc(size_t size, const char *file, int line)
#else
static void* os_malloc(size_t size)
#endif
{
	(void)file;
	(void)line;
	return thread_malloc(size);
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_realloc(void *ptr, size_t size, const char *file, int line)
#else
static void* os_realloc(void *ptr, size_t size)
#endif
{
	(void)file;
	(void)line;
	return thread_realloc(ptr, size);
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void os_free(void *ptr, const char *file, int line)
#else
static void os_free(void *ptr)
#endif
{
	(void)file;
	(void)line;
	thread_free(ptr);
}




inline static unsigned long tls_get_id(void)
{
#if defined __OS_linux
#if (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 30)
	return gettid();
#else
	return syscall(SYS_gettid);
#endif
#else /* __OS_linux */
	return my_pid(); /* TODO: fix on non linux systems, where we have to
						1. include a thread id alongside with the PID
						2. alocate a new structure that indicates PID + thread id */
#endif /* __OS_linux */
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
void tls_get_thread_id(CRYPTO_THREADID *tid)
{
	CRYPTO_THREADID_set_numeric(tid, tls_get_id());
}
#endif /* OPENSSL_VERSION_NUMBER */

static int tls_mutex_init(pthread_mutex_t *mtx, int recursive)
{
	pthread_mutexattr_t attr;
	int rc;

	if (pthread_mutexattr_init(&attr) != 0)
		return -1;

	if (recursive) {
#ifdef PTHREAD_MUTEX_RECURSIVE
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#elif defined(PTHREAD_MUTEX_RECURSIVE_NP)
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
	}

	rc = pthread_mutex_init(mtx, &attr);
	pthread_mutexattr_destroy(&attr);
	return (rc == 0) ? 0 : -1;
}

/* these locks can not be used in 1.1.0, because the interface has changed */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
struct CRYPTO_dynlock_value {
	pthread_mutex_t lock;
};

static struct CRYPTO_dynlock_value* tls_dyn_lock_create(const char* file,
																	int line)
{
	struct CRYPTO_dynlock_value* new_lock;

	new_lock = malloc(sizeof(*new_lock));
	if (new_lock==0){
		LM_ERR("Failed to allocated new dynamic lock\n");
		return 0;
	}
	if (tls_mutex_init(&new_lock->lock, 0) < 0) {
		LM_ERR("Failed to init new dynamic lock\n");
		free(new_lock);
		return 0;
	}

	return new_lock;
}


static void tls_dyn_lock_ops(int mode, struct CRYPTO_dynlock_value* dyn_lock,
												const char* file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&dyn_lock->lock);
	} else {
		pthread_mutex_unlock(&dyn_lock->lock);
	}
}


static void tls_dyn_lock_destroy(struct CRYPTO_dynlock_value *dyn_lock,
													const char* file, int line)
{
	pthread_mutex_destroy(&dyn_lock->lock);
	free(dyn_lock);
}

static int tls_static_locks_no=0;
static pthread_mutex_t *tls_static_locks = NULL;

static void tls_static_locks_ops(int mode, int n, const char* file, int line)
{
	if (n<0 || n>=tls_static_locks_no) {
		LM_ERR("BUG - SSL Lib attempting to acquire bogus lock\n");
		abort();
	}

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&tls_static_locks[n]);
	} else {
		pthread_mutex_unlock(&tls_static_locks[n]);
	}
}



static int tls_init_multithread(void)
{
	int i;

	/* init static locks support */
	tls_static_locks_no = CRYPTO_num_locks();

	if (tls_static_locks_no>0) {
		tls_static_locks = malloc(sizeof(*tls_static_locks) * tls_static_locks_no);
		if (!tls_static_locks) {
			LM_ERR("Failed to alloc static locks\n");
			return -1;
		}

		for (i = 0; i < tls_static_locks_no; i++) {
			if (tls_mutex_init(&tls_static_locks[i], 0) < 0) {
				while (--i >= 0)
					pthread_mutex_destroy(&tls_static_locks[i]);
				free(tls_static_locks);
				tls_static_locks = NULL;
				LM_ERR("Failed to init static locks\n");
				return -1;
			}
		}

		CRYPTO_set_locking_callback(tls_static_locks_ops);
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	CRYPTO_set_id_callback(tls_get_id);
#else /* between 1.0.0 and 1.1.0 */
	CRYPTO_THREADID_set_callback(tls_get_thread_id);
#endif /* OPENSSL_VERSION_NUMBER */

	/* dynamic locks support*/
	CRYPTO_set_dynlock_create_callback(tls_dyn_lock_create);
	CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_ops);
	CRYPTO_set_dynlock_destroy_callback(tls_dyn_lock_destroy);

	return 0;
}
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
static pthread_mutex_t ssl_lock;
static pthread_once_t ssl_lock_once = PTHREAD_ONCE_INIT;
static int ssl_lock_ready = 0;
static const RAND_METHOD *os_ssl_method;

static void ssl_lock_init_once(void)
{
	if (tls_mutex_init(&ssl_lock, 1) == 0)
		ssl_lock_ready = 1;
	else
		LM_ERR("failed to initialize SSL recursive mutex\n");
}

#define SSL_LOCK_REENTRANT(_cmd) \
	do { \
		if (!ssl_lock_ready) \
			pthread_once(&ssl_lock_once, ssl_lock_init_once); \
		if (ssl_lock_ready) \
			pthread_mutex_lock(&ssl_lock); \
		_cmd; \
		if (ssl_lock_ready) \
			pthread_mutex_unlock(&ssl_lock); \
	} while (0)

static int os_ssl_seed(const void *buf, int num)
{
	int ret;
	if (!os_ssl_method || !os_ssl_method->seed)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->seed(buf, num));
	return ret;
}

static int os_ssl_bytes(unsigned char *buf, int num)
{
	int ret;
	if (!os_ssl_method || !os_ssl_method->bytes)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->bytes(buf, num));
	return ret;
}

static void os_ssl_cleanup(void)
{
	if (!os_ssl_method || !os_ssl_method->cleanup)
		return;
	SSL_LOCK_REENTRANT(os_ssl_method->cleanup());
}

static int os_ssl_add(const void *buf, int num, double entropy)
{
	int ret;
	if (!os_ssl_method || !os_ssl_method->add)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->add(buf, num, entropy));
	return ret;
}

static int os_ssl_pseudorand(unsigned char *buf, int num)
{
	int ret;
	if (!os_ssl_method || !os_ssl_method->pseudorand)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->pseudorand(buf, num));
	return ret;
}

static int os_ssl_status(void)
{
	int ret;
	if (!os_ssl_method || !os_ssl_method->status)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->status());
	return ret;
}

static RAND_METHOD opensips_ssl_method = {
	os_ssl_seed,
	os_ssl_bytes,
	os_ssl_cleanup,
	os_ssl_add,
	os_ssl_pseudorand,
	os_ssl_status
};
#endif

#endif /* _OPENSSL_HELPERS_H_ */
