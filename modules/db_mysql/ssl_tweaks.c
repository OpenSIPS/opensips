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

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
	int (*real_SSL_CTX_set_default_verify_paths)(SSL_CTX *ctx);
	static int init = 0;
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm && init) {
		return 1;
	} else {
		real_SSL_CTX_set_default_verify_paths = dlsym(RTLD_NEXT,
			"SSL_CTX_set_default_verify_paths");
		if (!real_SSL_CTX_set_default_verify_paths)
			return 0;

		init = 1;

		return real_SSL_CTX_set_default_verify_paths(ctx);
	}
}
