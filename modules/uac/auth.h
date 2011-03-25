/*
 * $Id$
 *
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opnser, a free SIP server.
 *
 * UAC SER-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * UAC SER-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2005-01-31  first version (ramona)
 */


#ifndef _UAC_AUTH_H_
#define _UAC_AUTH_H_

#include "../../parser/parse_authenticate.h"
#include "../../parser/msg_parser.h"

#define WWW_AUTH_CODE       401
#define WWW_AUTH_HDR        "WWW-Authenticate"
#define WWW_AUTH_HDR_LEN    (sizeof(WWW_AUTH_HDR)-1)
#define PROXY_AUTH_CODE     407
#define PROXY_AUTH_HDR      "Proxy-Authenticate"
#define PROXY_AUTH_HDR_LEN  (sizeof(PROXY_AUTH_HDR)-1)


#define HASHLEN 16
typedef char HASH[HASHLEN];

#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN+1];

struct uac_credential {
	str realm;
	str user;
	str passwd;
	struct uac_credential *next;
};

struct authenticate_nc_cnonce {
	str *nc;
	str *cnonce;
};


int has_credentials();

int add_credential( unsigned int type, void *val);

void destroy_credentials();

int uac_auth( struct sip_msg *msg);
str* build_authorization_hdr(int code, str *uri,
		struct uac_credential *crd, struct authenticate_body *auth,
		struct authenticate_nc_cnonce *auth_nc_cnonce, char *response);

#endif
