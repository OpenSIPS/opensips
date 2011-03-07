/*
 * $Id$
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * Registrant OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * Registrant OpenSIPS-module is distributed in the hope that it will be useful,
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
 *  2011-02-20  import file from uac (Ovidiu Sas)
 */


#include "string.h"
#include "ctype.h"

#include "../../dprint.h"
#include "../../str.h"
#include "../../mem/mem.h"

#include "../../parser/parse_authenticate.h"

#include "auth_hdr.h"
#include "auth.h"


#define AUTHORIZATION_HDR_START       "Authorization: Digest "
#define AUTHORIZATION_HDR_START_LEN   (sizeof(AUTHORIZATION_HDR_START)-1)

#define PROXY_AUTHORIZATION_HDR_START      "Proxy-Authorization: Digest "
#define PROXY_AUTHORIZATION_HDR_START_LEN  \
	(sizeof(PROXY_AUTHORIZATION_HDR_START)-1)

#define USERNAME_FIELD_S         "username=\""
#define USERNAME_FIELD_LEN       (sizeof(USERNAME_FIELD_S)-1)
#define REALM_FIELD_S            "realm=\""
#define REALM_FIELD_LEN          (sizeof(REALM_FIELD_S)-1)
#define NONCE_FIELD_S            "nonce=\""
#define NONCE_FIELD_LEN          (sizeof(NONCE_FIELD_S)-1)
#define URI_FIELD_S              "uri=\""
#define URI_FIELD_LEN            (sizeof(URI_FIELD_S)-1)
#define OPAQUE_FIELD_S           "opaque=\""
#define OPAQUE_FIELD_LEN         (sizeof(OPAQUE_FIELD_S)-1)
#define RESPONSE_FIELD_S         "response=\""
#define RESPONSE_FIELD_LEN       (sizeof(RESPONSE_FIELD_S)-1)
#define ALGORITHM_FIELD_S        "algorithm=MD5"
#define ALGORITHM_FIELD_LEN       (sizeof(ALGORITHM_FIELD_S)-1)
#define FIELD_SEPARATOR_S        "\", "
#define FIELD_SEPARATOR_LEN      (sizeof(FIELD_SEPARATOR_S)-1)
#define FIELD_SEPARATOR_UQ_S     ", "
#define FIELD_SEPARATOR_UQ_LEN   (sizeof(FIELD_SEPARATOR_UQ_S)-1)

#define QOP_FIELD_S              "qop="
#define QOP_FIELD_LEN            (sizeof(QOP_FIELD_S)-1)
#define NC_FIELD_S               "nc="
#define NC_FIELD_LEN             (sizeof(NC_FIELD_S)-1)
#define CNONCE_FIELD_S           "cnonce=\""
#define CNONCE_FIELD_LEN         (sizeof(CNONCE_FIELD_S)-1)

#define add_string( _p, _s, _l) \
	do {\
		memcpy( _p, _s, _l);\
		_p += _l; \
	}while(0)


str* build_authorization_hdr(int code, str *uri, 
		struct uac_credential *crd, struct authenticate_body *auth,
		struct authenticate_nc_cnonce *auth_nc_cnonce, char *response)
{
	static str hdr;
	char *p;
	int len;
	int response_len;

	response_len = strlen(response);

	/* compile then len */
	len = (code==401?
		AUTHORIZATION_HDR_START_LEN:PROXY_AUTHORIZATION_HDR_START_LEN) +
		USERNAME_FIELD_LEN + crd->user.len + FIELD_SEPARATOR_LEN +
		REALM_FIELD_LEN + crd->realm.len + FIELD_SEPARATOR_LEN +
		NONCE_FIELD_LEN + auth->nonce.len + FIELD_SEPARATOR_LEN +
		URI_FIELD_LEN + uri->len + FIELD_SEPARATOR_LEN +
		(auth->opaque.len?
			(OPAQUE_FIELD_LEN + auth->opaque.len + FIELD_SEPARATOR_LEN):0) +
		RESPONSE_FIELD_LEN + response_len + FIELD_SEPARATOR_LEN +
		ALGORITHM_FIELD_LEN + CRLF_LEN;
	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
		len += QOP_FIELD_LEN + 4 /*auth*/ + FIELD_SEPARATOR_UQ_LEN +
				NC_FIELD_LEN + auth_nc_cnonce->nc->len + FIELD_SEPARATOR_UQ_LEN +
				CNONCE_FIELD_LEN + auth_nc_cnonce->cnonce->len + FIELD_SEPARATOR_LEN;

	hdr.s = (char*)pkg_malloc( len + 1);
	if (hdr.s==0)
	{
		LM_ERR("no more pkg mem\n");
		goto error;
	}

	p = hdr.s;
	/* header start */
	if (code==401)
	{
		add_string( p, AUTHORIZATION_HDR_START USERNAME_FIELD_S,
			AUTHORIZATION_HDR_START_LEN+USERNAME_FIELD_LEN);
	} else {
		add_string( p, PROXY_AUTHORIZATION_HDR_START USERNAME_FIELD_S,
			PROXY_AUTHORIZATION_HDR_START_LEN+USERNAME_FIELD_LEN);
	}
	/* username */
	add_string( p, crd->user.s, crd->user.len);
	/* REALM */
	add_string( p, FIELD_SEPARATOR_S REALM_FIELD_S,
		FIELD_SEPARATOR_LEN+REALM_FIELD_LEN);
	add_string( p, crd->realm.s, crd->realm.len);
	/* NONCE */
	add_string( p, FIELD_SEPARATOR_S NONCE_FIELD_S, 
		FIELD_SEPARATOR_LEN+NONCE_FIELD_LEN);
	add_string( p, auth->nonce.s, auth->nonce.len);
	/* URI */
	add_string( p, FIELD_SEPARATOR_S URI_FIELD_S,
		FIELD_SEPARATOR_LEN+URI_FIELD_LEN);
	add_string( p, uri->s, uri->len);
	/* OPAQUE */
	if (auth->opaque.len )
	{
		add_string( p, FIELD_SEPARATOR_S OPAQUE_FIELD_S, 
			FIELD_SEPARATOR_LEN+OPAQUE_FIELD_LEN);
		add_string( p, auth->opaque.s, auth->opaque.len);
	}
	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		add_string( p, FIELD_SEPARATOR_S QOP_FIELD_S, 
			FIELD_SEPARATOR_LEN+QOP_FIELD_LEN);
		add_string( p, "auth", 4);
		add_string( p, FIELD_SEPARATOR_UQ_S NC_FIELD_S, 
			FIELD_SEPARATOR_UQ_LEN+NC_FIELD_LEN);
		add_string( p, auth_nc_cnonce->nc->s, auth_nc_cnonce->nc->len);
		add_string( p, FIELD_SEPARATOR_UQ_S CNONCE_FIELD_S, 
			FIELD_SEPARATOR_UQ_LEN+CNONCE_FIELD_LEN);
		add_string( p, auth_nc_cnonce->cnonce->s, auth_nc_cnonce->cnonce->len);
	}
	/* RESPONSE */
	add_string( p, FIELD_SEPARATOR_S RESPONSE_FIELD_S,
		FIELD_SEPARATOR_LEN+RESPONSE_FIELD_LEN);
	add_string( p, response, response_len);
	/* ALGORITHM */
	add_string( p, FIELD_SEPARATOR_S ALGORITHM_FIELD_S CRLF,
		FIELD_SEPARATOR_LEN+ALGORITHM_FIELD_LEN+CRLF_LEN);

	hdr.len = p - hdr.s;

	if (hdr.len!=len)
	{
		LM_CRIT("BUG: bad buffer computation "
			"(%d<>%d)\n",len,hdr.len);
		pkg_free( hdr.s );
		goto error;
	}

	LM_DBG("hdr is <%.*s>\n",
		hdr.len,hdr.s);

	return &hdr;
error:
	return 0;
}

