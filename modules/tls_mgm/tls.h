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

#ifndef _PROTO_TLS_H_
#define _PROTO_TLS_H_

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include "tls_helper.h"
#include "../../locking.h"

#define OS_SSL_SESS_ID (NAME "-" VERSION)
#define OS_SSL_SESS_ID_LEN (sizeof(OS_SSL_SESS_ID)-1)

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
static int ssl_versions[TLS_USE_TLSv1_3 + 1];
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
static int ssl_versions[TLS_USE_TLSv1_2 + 1];
#else
static SSL_METHOD     *ssl_methods[TLS_USE_TLSv1_2 + 1];
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L && defined __OS_linux
#include <sys/types.h>
#if (__GLIBC__ < 2) || (__GLIBC_MINOR__ < 30)
#include <sys/syscall.h>
#endif
#endif

#define VERIFY_DEPTH_S 3


/*
 * Wrappers around OpenSIPS shared memory functions
 * (which can be macros)
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_malloc(size_t size, const char *file, int line)
#else
static void* os_malloc(size_t size)
#endif
{
#if (defined DBG_MALLOC  && OPENSSL_VERSION_NUMBER >= 0x10100000L)
	return _shm_malloc(size, file, __FUNCTION__, line);
#else
	return shm_malloc(size);
#endif
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void* os_realloc(void *ptr, size_t size, const char *file, int line)
#else
static void* os_realloc(void *ptr, size_t size)
#endif
{
#if (defined DBG_MALLOC  && OPENSSL_VERSION_NUMBER >= 0x10100000L)
	return _shm_realloc(ptr, size, file, __FUNCTION__, line);
#else
	return shm_realloc(ptr, size);
#endif
}


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static void os_free(void *ptr, const char *file, int line)
#else
static void os_free(void *ptr)
#endif
{
	/* TODO: also handle free file and line */
	if (ptr)
#if (defined DBG_MALLOC  && OPENSSL_VERSION_NUMBER >= 0x10100000L)
		_shm_free(ptr, file, __FUNCTION__, line);
#else
		shm_free(ptr);
#endif
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

/* these locks can not be used in 1.1.0, because the interface has changed */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
struct CRYPTO_dynlock_value {
	gen_lock_t lock;
};

static struct CRYPTO_dynlock_value* tls_dyn_lock_create(const char* file,
																	int line)
{
	struct CRYPTO_dynlock_value* new_lock;

	new_lock=shm_malloc(sizeof(struct CRYPTO_dynlock_value));
	if (new_lock==0){
		LM_ERR("Failed to allocated new dynamic lock\n");
		return 0;
	}
	if (lock_init(&new_lock->lock)==0) {
		LM_ERR("Failed to init new dynamic lock\n");
		shm_free(new_lock);
		return 0;
	}

	return new_lock;
}


static void tls_dyn_lock_ops(int mode, struct CRYPTO_dynlock_value* dyn_lock,
												const char* file, int line)
{
	if (mode & CRYPTO_LOCK) {
		lock_get(&dyn_lock->lock);
	} else {
		lock_release(&dyn_lock->lock);
	}
}


static void tls_dyn_lock_destroy(struct CRYPTO_dynlock_value *dyn_lock,
													const char* file, int line)
{
	lock_destroy(&dyn_lock->lock);
	shm_free(dyn_lock);
}
#endif

#endif /* _PROTO_TLS_H_ */
