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
 * History:
 * -------
 *  2015-02-12  first version (bogdan)
 */

#ifndef _PROTO_TLS_H_
#define _PROTO_TLS_H_

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#define OS_SSL_SESS_ID ((unsigned char*)NAME "-" VERSION)
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

static int tls_static_locks_no=0;
static gen_lock_set_t* tls_static_locks=NULL;

static SSL_METHOD     *ssl_methods[TLS_USE_TLSv1_2 + 1];

#define VERIFY_DEPTH_S 3


struct CRYPTO_dynlock_value {
	gen_lock_t lock;
};

static unsigned long tls_get_id(void)
{
	return my_pid();
}

/*
 * Wrappers around OpenSIPS shared memory functions
 * (which can be macros)
 */
static void* os_malloc(size_t size)
{
	return shm_malloc(size);
}


static void* os_realloc(void *ptr, size_t size)
{
	return shm_realloc(ptr, size);
}


static void os_free(void *ptr)
{
	if (ptr)
		shm_free(ptr);
}

static int check_for_krb(void)
{
	SSL_CTX *xx;
	int j;

	xx = SSL_CTX_new(ssl_methods[tls_method - 1]);
	if (xx==NULL)
		return -1;

	for( j=0 ; j<sk_SSL_CIPHER_num(xx->cipher_list) ; j++) {
		SSL_CIPHER *yy = sk_SSL_CIPHER_value(xx->cipher_list,j);
		if ( yy->id>=SSL3_CK_KRB5_DES_64_CBC_SHA &&
		 yy->id<=SSL3_CK_KRB5_RC4_40_MD5 ) {
			LM_INFO("KRB5 cipher %s found\n", yy->name);
			SSL_CTX_free(xx);
			return 1;
		}
	}

	SSL_CTX_free(xx);
	return 0;
}



static void tls_static_locks_ops(int mode, int n, const char* file, int line)
{
	if (n<0 || n>tls_static_locks_no) {
		LM_ERR("BUG - SSL Lib attempting to acquire bogus lock\n");
		abort();
	}

	if (mode & CRYPTO_LOCK) {
		lock_set_get(tls_static_locks,n);
	} else {
		lock_set_release(tls_static_locks,n);
	}
}


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


static int tls_init_multithread(void)
{
	/* init static locks support */
	tls_static_locks_no = CRYPTO_num_locks();

	if (tls_static_locks_no>0) {
		/* init a lock set & pass locking function to SSL */
		tls_static_locks = lock_set_alloc(tls_static_locks_no);
		if (tls_static_locks == NULL) {
			LM_ERR("Failed to alloc static locks\n");
			return -1;
		}
		if (lock_set_init(tls_static_locks)==0) {
				LM_ERR("Failed to init static locks\n");
				lock_set_dealloc(tls_static_locks);
				return -1;
		}
		CRYPTO_set_locking_callback(tls_static_locks_ops);
	}

	CRYPTO_set_id_callback(tls_get_id);

	/* dynamic locks support*/
	CRYPTO_set_dynlock_create_callback(tls_dyn_lock_create);
	CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_ops);
	CRYPTO_set_dynlock_destroy_callback(tls_dyn_lock_destroy);

	return 0;
}

/*
 * initialize ssl methods
 */
static void
init_ssl_methods(void)
{
	LM_DBG("entered\n");

	ssl_methods[TLS_USE_TLSv1_cli-1] = (SSL_METHOD*)TLSv1_client_method();
	ssl_methods[TLS_USE_TLSv1_srv-1] = (SSL_METHOD*)TLSv1_server_method();
	ssl_methods[TLS_USE_TLSv1-1] = (SSL_METHOD*)TLSv1_method();

	ssl_methods[TLS_USE_SSLv23_cli-1] = (SSL_METHOD*)SSLv23_client_method();
	ssl_methods[TLS_USE_SSLv23_srv-1] = (SSL_METHOD*)SSLv23_server_method();
	ssl_methods[TLS_USE_SSLv23-1] = (SSL_METHOD*)SSLv23_method();

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	ssl_methods[TLS_USE_TLSv1_2_cli-1] = (SSL_METHOD*)TLSv1_2_client_method();
	ssl_methods[TLS_USE_TLSv1_2_srv-1] = (SSL_METHOD*)TLSv1_2_server_method();
	ssl_methods[TLS_USE_TLSv1_2-1] = (SSL_METHOD*)TLSv1_2_method();
#endif
}



static inline int tls_mod_init(void)
{
	int n;

	/*
	* this has to be called before any function calling CRYPTO_malloc,
	* CRYPTO_malloc will set allow_customize in openssl to 0
	*/
	if (!CRYPTO_set_mem_functions(os_malloc, os_realloc, os_free)) {
		LM_ERR("unable to set the memory allocation functions\n");
		return -1;
	}

#if !defined(OPENSSL_NO_COMP)
	STACK_OF(SSL_COMP)* comp_methods;
	/* disabling compression */
	LM_WARN("disabling compression due ZLIB problems\n");
	comp_methods = SSL_COMP_get_compression_methods();
	if (comp_methods==0) {
		LM_INFO("openssl compression already disabled\n");
	} else {
		sk_SSL_COMP_zero(comp_methods);
	}
#endif

	if (tls_init_multithread() < 0) {
		LM_ERR("failed to init multi-threading support\n");
		return -1;
	}

	SSL_library_init();
	SSL_load_error_strings();
	init_ssl_methods();

	n = check_for_krb();
	if (n==-1) {
		LM_ERR("kerberos check failed\n");
		return -1;
	}

	if ( ( n ^
#ifndef OPENSSL_NO_KRB5
	1
#else
	0
#endif
	)!=0 ) {
		LM_ERR("compiled agaist an openssl with %s"
			"kerberos, but run with one with %skerberos\n",
			(n==1)?"":"no ",(n!=1)?"no ":"");
		return -1;
	}

	return 0;
}

#endif /* _PROTO_TLS_H_ */
