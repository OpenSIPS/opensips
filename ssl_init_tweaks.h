/*
 * Copyright (C) 2020 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <openssl/ssl.h>
#include <dlfcn.h>

#include "sr_module.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
	int (*real_OPENSSL_init_ssl)(uint64_t, const OPENSSL_INIT_SETTINGS *);
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return 1;
	} else {
		real_OPENSSL_init_ssl = dlsym(RTLD_NEXT, "OPENSSL_init_ssl");
		if (!real_OPENSSL_init_ssl)
			return 0;

		return real_OPENSSL_init_ssl(opts, settings);
	}
}

int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
	int (*real_OPENSSL_init_crypto)(uint64_t, const OPENSSL_INIT_SETTINGS *);
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return 1;
	} else {
		real_OPENSSL_init_crypto = dlsym(RTLD_NEXT, "OPENSSL_init_crypto");
		if (!real_OPENSSL_init_crypto)
			return 0;

		return real_OPENSSL_init_crypto(opts, settings);
	}
}

int ERR_load_BIO_strings(void)
{
	int (*real_ERR_load_BIO_strings)(void);
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return 1;
	} else {
		real_ERR_load_BIO_strings = dlsym(RTLD_NEXT, "ERR_load_BIO_strings");
		if (!real_ERR_load_BIO_strings)
			return 0;

		return real_ERR_load_BIO_strings();
	}
}

#else

int SSL_library_init(void)
{
	int (*real_SSL_library_init)(void);
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return 1;
	} else {
		real_SSL_library_init = dlsym(RTLD_NEXT, "SSL_library_init");
		if (!real_SSL_library_init)
			return 0;

		return real_SSL_library_init();
	}
}

void ERR_load_BIO_strings(void)
{
	int (*real_ERR_load_BIO_strings)(void);
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return;
	} else {
		real_ERR_load_BIO_strings = dlsym(RTLD_NEXT, "ERR_load_BIO_strings");
		if (!real_ERR_load_BIO_strings)
			return;

		real_ERR_load_BIO_strings();
	}
}

void CRYPTO_set_locking_callback(void (*func)(int mode, int type,
                                               const char *file, int line))
{
	int (*real_CRYPTO_set_locking_callback)(void (*)(int, int,
		const char *, int));
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return;
	} else {
		real_CRYPTO_set_locking_callback = dlsym(RTLD_NEXT,
			"CRYPTO_set_locking_callback");
		if (!real_CRYPTO_set_locking_callback)
			return;

		real_CRYPTO_set_locking_callback(func);
	}
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
void CRYPTO_set_id_callback(unsigned long (*func) (void))
{
	int (*real_CRYPTO_set_id_callback)(unsigned long (*)(void));
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return;
	} else {
		real_CRYPTO_set_id_callback = dlsym(RTLD_NEXT, "CRYPTO_set_id_callback");
		if (!real_CRYPTO_set_id_callback)
			return;

		real_CRYPTO_set_id_callback(func);
	}
}

#else /* between 1.0.0 and 1.1.0 */
int CRYPTO_THREADID_set_callback(void (*threadid_func) (CRYPTO_THREADID *))
{
	int (*real_CRYPTO_THREADID_set_callback)(void (*)(CRYPTO_THREADID *));
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm) {
		return 0;
	} else {
		real_CRYPTO_THREADID_set_callback = dlsym(RTLD_NEXT,
			"CRYPTO_THREADID_set_callback");
		if (!real_CRYPTO_THREADID_set_callback)
			return 0;

		return real_CRYPTO_THREADID_set_callback(threadid_func);
	}
}
#endif

#endif
