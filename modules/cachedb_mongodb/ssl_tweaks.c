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

#define _GNU_SOURCE

#include <openssl/ssl.h>
#include <dlfcn.h>

#include "../../sr_module.h"

/* mongoc calls SSL_CTX_new and SSL_CTX_free as a test when
 * initing openssl so we also need to overwrite these functions
 * the first time they are called */

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
{
	SSL_CTX* (*real_SSL_CTX_new)(const SSL_METHOD *);
	static int mongoc_init = 0;
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm && !mongoc_init) {
		mongoc_init = 1;
		/* return a dummy pointer the first time SSL_CTX_new is called
		 * when mongoc tries to init openssl */
		return (SSL_CTX *)1;
	} else {
		/* call the real SSL_CTX_new at only at runtime */
		real_SSL_CTX_new = dlsym(RTLD_NEXT, "SSL_CTX_new");
		if (!real_SSL_CTX_new)
			return NULL;

		return real_SSL_CTX_new(method);
	}
}

void SSL_CTX_free(SSL_CTX *ctx)
{
	SSL_CTX* (*real_SSL_CTX_free)(SSL_CTX *);
	static int mongoc_init = 0;
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm && !mongoc_init) {
		mongoc_init = 1;
		/* do nothing the first time SSL_CTX_free is called when mongoc
		 * tries to init openssl */
		return;
	} else {
		/* call the real SSL_CTX_free at runtime */
		real_SSL_CTX_free = dlsym(RTLD_NEXT, "SSL_CTX_free");
		if (!real_SSL_CTX_free)
			return;

		real_SSL_CTX_free(ctx);
	}
}
