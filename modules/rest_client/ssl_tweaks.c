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
#include "../../globals.h"

/* don't call the real openssl function (from libssh's destructor) when the
 * pre-daemon processes exit */
void BN_clear_free(BIGNUM *a)
{
	void (*real_BN_clear_free)(BIGNUM *a);
	static int have_tls_mgm = -1;

	if (have_tls_mgm == -1)
		have_tls_mgm = module_loaded("tls_mgm");

	if (have_tls_mgm && !no_daemon_mode && is_pre_daemon) {
		return;
	} else {
		real_BN_clear_free = dlsym(RTLD_NEXT, "BN_clear_free");
		if (!real_BN_clear_free)
			return;

		real_BN_clear_free(a);
	}
}
