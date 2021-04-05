/*
 * uac_auth module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2011-05-13  initial version (Ovidiu Sas)
 */

#ifndef _UAC_AUTH_AUTH_H_
#define _UAC_AUTH_AUTH_H_

#include "../../sr_module.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/msg_parser.h"

#include "../../lib/digest_auth/digest_auth.h"

struct uac_credential {
	struct digest_auth_credential auth_data;
	struct uac_credential *next;
};

struct authenticate_nc_cnonce {
	str_const nc;
	str_const cnonce;
};


int uac_auth( struct sip_msg *msg, int algmask);
int do_uac_auth(str *msg_body, str *method, str *uri, struct uac_credential *crd,
		struct authenticate_body *auth, struct authenticate_nc_cnonce *auth_nc_cnonce,
		struct digest_auth_response *response) __attribute__ ((warn_unused_result));;
str* build_authorization_hdr(int code, str *uri,
		struct uac_credential *crd, struct authenticate_body *auth,
		struct authenticate_nc_cnonce *auth_nc_cnonce,
		const struct digest_auth_response *response);
struct uac_credential* lookup_realm(str *realm);


typedef int (*do_uac_auth_t)(str *msg_body, str *method, str *uri, struct uac_credential *crd,
	struct authenticate_body *auth, struct authenticate_nc_cnonce *auth_nc_cnonce,
	struct digest_auth_response *response) __attribute__ ((warn_unused_result));;
typedef str* (*build_authorization_hdr_t)(int code, str *uri,
	struct uac_credential *crd, struct authenticate_body *auth,
	struct authenticate_nc_cnonce *auth_nc_cnonce, const struct digest_auth_response *response);
typedef struct uac_credential* (*lookup_realm_t)(str *realm);

typedef struct uac_auth_api
{
	do_uac_auth_t			_do_uac_auth;
	build_authorization_hdr_t	_build_authorization_hdr;
	lookup_realm_t			_lookup_realm;
}uac_auth_api_t;

int uac_auth_load_api(uac_auth_api_t *api);
typedef int (*load_uac_auth_f)(uac_auth_api_t *api);

static inline int load_uac_auth_api( uac_auth_api_t *uac_auth_api)
{
	load_uac_auth_f load_uac_auth;

	/* import the uac_auth auto-loading function */
	if ( !(load_uac_auth=(load_uac_auth_f)find_export("load_uac_auth", 0))) {
		return -1;
	}

	/* let the auto-loading function load all uac_auth stuff */
	return load_uac_auth( uac_auth_api );
}

#endif
