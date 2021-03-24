/*
 * Copyright (C) 2011 VoIP Embedded Inc.
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2011-02-20  import file from uac (Ovidiu Sas)
 */


#include <ctype.h>
#include <string.h>

#include "../../str.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../parser/parse_authenticate.h"
#include "../tm/tm_load.h"
#include "../../lib/dassert.h"

#include "uac_auth.h"
#include "../../lib/digest_auth/dauth_calc.h"

extern int            realm_avp_name;
extern unsigned short realm_avp_type;
extern int            user_avp_name;
extern unsigned short user_avp_type;
extern int            pwd_avp_name;
extern unsigned short pwd_avp_type;


static struct uac_credential *crd_list = NULL;

#define  duplicate_str(_strd, _strs, _error)		\
	do {						\
		_strd.s = (char*)pkg_malloc(_strs.len);	\
		if (_strd.s==NULL) {			\
			LM_ERR("no more pkg memory\n");	\
			goto _error;			\
		}					\
		memcpy( _strd.s, _strs.s, _strs.len);	\
		_strd.len = _strs.len;			\
	}while(0)


int has_credentials(void) {return (crd_list)?1:0;}


void free_credential(struct uac_credential *crd)
{
	if (crd) {
		if (crd->auth_data.realm.s) pkg_free(crd->auth_data.realm.s);
		if (crd->auth_data.user.s) pkg_free(crd->auth_data.user.s);
			if (crd->auth_data.passwd.s) pkg_free(crd->auth_data.passwd.s);
			pkg_free(crd);
	}
}


int add_credential( unsigned int type, void *val)
{
	struct uac_credential *crd;
	char *p;
	str foo;

	p = (char*)val;
	crd = 0;

	if (p==NULL || *p==0)
		goto error;

	crd = (struct uac_credential*)pkg_malloc(sizeof(struct uac_credential));
	if (crd==NULL)
	{
		LM_ERR("no more pkg mem\n");
		goto error;
	}
	memset( crd, 0, sizeof(struct uac_credential));

	/*parse the user */
	while (*p && isspace((int)*p)) p++;
	foo.s = p;
	while (*p && *p!=':' && !isspace((int)*p)) p++;
	if (foo.s==p || *p==0)
		/* missing or empty user */
		goto parse_error;
	foo.len = p - foo.s;
	/* dulicate it */
	duplicate_str( crd->auth_data.user, foo, error);

	/* parse the ':' separator */
	while (*p && isspace((int)*p)) p++;
	if (*p!=':')
		goto parse_error;
	p++;
	while (*p && isspace((int)*p)) p++;
	if (*p==0)
		goto parse_error;

	/*parse the realm */
	while (*p && isspace((int)*p)) p++;
	foo.s = p;
	while (*p && *p!=':' && !isspace((int)*p)) p++;
	if (foo.s==p || *p==0)
		/* missing or empty realm */
		goto parse_error;
	foo.len = p - foo.s;
	/* dulicate it */
	duplicate_str( crd->auth_data.realm, foo, error);

	/* parse the ':' separator */
	while (*p && isspace((int)*p)) p++;
	if (*p!=':')
		goto parse_error;
	p++;
	while (*p && isspace((int)*p)) p++;
	if (*p==0)
		goto parse_error;

	/*parse the passwd */
	while (*p && isspace((int)*p)) p++;
	foo.s = p;
	while (*p && !isspace((int)*p)) p++;
	if (foo.s==p)
		/* missing or empty passwd */
		goto parse_error;
	foo.len = p - foo.s;
	/* dulicate it */
	duplicate_str( crd->auth_data.passwd, foo, error);

	/* end of string */
	while (*p && isspace((int)*p)) p++;
	if (*p!=0)
		goto parse_error;

	/* link the new cred struct */
	crd->next = crd_list;
	crd_list = crd;

	pkg_free(val);
	return 0;
parse_error:
		LM_ERR("parse error in <%s> "
		"around %ld\n", (char*)val, (long)(p-(char*)val));
error:
	if (crd)
		free_credential(crd);
	return -1;
}


void destroy_credentials(void)
{
	struct uac_credential *foo;

	while (crd_list)
	{
		foo = crd_list;
		crd_list = crd_list->next;
		free_credential(foo);
	}
	crd_list = NULL;
}


static inline struct uac_credential *get_avp_credential(str *realm)
{
	static struct uac_credential crd;
	struct usr_avp *avp;
	int_str val;

	avp = search_first_avp( realm_avp_type, realm_avp_name, &val, 0);
	if ( avp==NULL || (avp->flags&AVP_VAL_STR)==0 || val.s.len<=0 )
		return 0;

	crd.auth_data.realm = val.s;
	/* is it the domain we are looking for? */
	if (realm->len!=crd.auth_data.realm.len ||
	strncmp( realm->s, crd.auth_data.realm.s, realm->len)!=0 )
		return 0;

	/* get username and password */
	avp = search_first_avp( user_avp_type, user_avp_name, &val, 0);
	if ( avp==NULL || (avp->flags&AVP_VAL_STR)==0 || val.s.len<=0 )
		return 0;
	crd.auth_data.user = val.s;

	avp = search_first_avp( pwd_avp_type, pwd_avp_name, &val, 0);
	if ( avp==NULL || (avp->flags&AVP_VAL_STR)==0 || val.s.len<=0 )
		return 0;
	crd.auth_data.passwd = val.s;

	return &crd;
}


struct uac_credential *lookup_realm( str *realm)
{
	struct uac_credential *crd;

	/* first look into AVP, if set */
	if ( realm_avp_name && (crd=get_avp_credential(realm))!=NULL )
		return crd;

	/* search in the static list */
	for( crd=crd_list ; crd ; crd=crd->next )
		if (realm->len==crd->auth_data.realm.len &&
		strncmp( realm->s, crd->auth_data.realm.s, realm->len)==0 )
			return crd;
	return 0;
}


int do_uac_auth(str *msg_body, str *method, str *uri, struct uac_credential *crd,
		struct authenticate_body *auth, struct authenticate_nc_cnonce *auth_nc_cnonce,
		struct digest_auth_response *response)
{
	HASHHEX ha1;
	HASHHEX ha2;
	int i, has_ha1;
	const struct digest_auth_calc *digest_calc;
	str_const cnonce;
	str_const nc;

	digest_calc = get_digest_calc(auth->algorithm);
	if (digest_calc == NULL) {
		LM_ERR("digest algorithm (%d) unsupported\n", auth->algorithm);
		return (-1);
	}

	/* before actually doing the authe, we check if the received password is
	   a plain text password or a HA1 value ; we detect a HA1 (in the password
	   field if: (1) starts with "0x"; (2) len is 32 + 2 (prefix) ; (3) the 32
	   chars are HEXA values */
	if (crd->auth_data.passwd.len==(digest_calc->HASHHEXLEN + 2) &&
	    crd->auth_data.passwd.s[0]=='0' && crd->auth_data.passwd.s[1]=='x') {
		/* it may be a HA1 - check the actual content */
		for( has_ha1=1,i=2 ; i<crd->auth_data.passwd.len ; i++ ) {
			if ( !( (crd->auth_data.passwd.s[i]>='0' && crd->auth_data.passwd.s[i]<='9') ||
			(crd->auth_data.passwd.s[i]>='a' && crd->auth_data.passwd.s[i]<='f') )) {
				has_ha1 = 0;
				break;
			} else {
				ha1._start[i-2] = crd->auth_data.passwd.s[i];
			}
		}
		ha1._start[digest_calc->HASHHEXLEN] = 0;
	} else {
		has_ha1 = 0;
	}

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		/* if qop generate nonce-count and cnonce */
		nc = str_const_init("00000001");
		cnonce.s = int2str(core_hash(&auth->nonce, NULL, 0),&cnonce.len);

		/* do authentication */
		if (!has_ha1)
			if (digest_calc->HA1(&crd->auth_data, &ha1) != 0)
				return (-1);
		if (digest_calc->HA1sess != NULL)
			if (digest_calc->HA1sess(str2const(&auth->nonce), &cnonce, &ha1) != 0)
				return (-1);
		if (digest_calc->HA2(str2const(msg_body), str2const(method), str2const(uri),
		    !(auth->flags&QOP_AUTH), &ha2) != 0)
			return (-1);

		if (digest_calc->response(&ha1, &ha2, str2const(&auth->nonce),
		    str2const(&auth->qop), &nc, &cnonce, response) != 0)
			return (-1);
		auth_nc_cnonce->nc = nc;
		auth_nc_cnonce->cnonce = cnonce;
	} else {
		/* do authentication */
		if (!has_ha1)
			if (digest_calc->HA1(&crd->auth_data, &ha1) != 0)
				return (-1);
		if (digest_calc->HA1sess != NULL)
			if (digest_calc->HA1sess(str2const(&auth->nonce), NULL/*cnonce*/, &ha1) != 0)
				return (-1);
		if (digest_calc->HA2(str2const(msg_body), str2const(method), str2const(uri),
		    0, &ha2) != 0)
			return (-1);

		if (digest_calc->response(&ha1, &ha2, str2const(&auth->nonce),
		    NULL/*qop*/, NULL/*nc*/, NULL/*cnonce*/, response) != 0)
			return (-1);
	}
	return (0);
}



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
#define ALGORITHM_FIELD_S        "algorithm="
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

#define add_str(_p, _sp) \
	do {\
		memcpy(_p, (_sp)->s, (_sp)->len);\
		_p += (_sp)->len; \
	}while(0)


str* build_authorization_hdr(int code, str *uri,
		struct uac_credential *crd, struct authenticate_body *auth,
		struct authenticate_nc_cnonce *auth_nc_cnonce,
		const struct digest_auth_response *response)
{
	char *p;
	int len;
	str_const qop_val = STR_NULL_const;
	static str auth_hdr = STR_NULL;
	const struct digest_auth_calc *digest_calc = response->digest_calc;
	int response_len = digest_calc->HASHHEXLEN;

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT)) {
		if (!(auth->flags&QOP_AUTH)) {
			qop_val = str_const_init(QOP_AUTHINT_STR);
		} else {
			qop_val = str_const_init(QOP_AUTH_STR);
		}
	}

	/* compile then len */
	len = (code==WWW_AUTH_CODE?
		AUTHORIZATION_HDR_START_LEN:PROXY_AUTHORIZATION_HDR_START_LEN) +
		USERNAME_FIELD_LEN + crd->auth_data.user.len + FIELD_SEPARATOR_LEN +
		REALM_FIELD_LEN + crd->auth_data.realm.len + FIELD_SEPARATOR_LEN +
		NONCE_FIELD_LEN + auth->nonce.len + FIELD_SEPARATOR_LEN +
		URI_FIELD_LEN + uri->len + FIELD_SEPARATOR_LEN +
		(auth->opaque.len?
			(OPAQUE_FIELD_LEN + auth->opaque.len + FIELD_SEPARATOR_LEN):0) +
		RESPONSE_FIELD_LEN + response_len + FIELD_SEPARATOR_LEN +
		ALGORITHM_FIELD_LEN + digest_calc->algorithm_val.len + CRLF_LEN;
	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
		len += QOP_FIELD_LEN + qop_val.len + FIELD_SEPARATOR_UQ_LEN +
				NC_FIELD_LEN + auth_nc_cnonce->nc.len + FIELD_SEPARATOR_UQ_LEN +
				CNONCE_FIELD_LEN + auth_nc_cnonce->cnonce.len + FIELD_SEPARATOR_LEN;

	if (auth_hdr.s || auth_hdr.len)
		LM_WARN("potential memory leak at addr: %p\n", auth_hdr.s);

	auth_hdr.s = (char*)pkg_malloc( len + 1);
	if (auth_hdr.s==NULL)
	{
		LM_ERR("no more pkg mem\n");
		goto error;
	}

	p = auth_hdr.s;
	/* header start */
	if (code==WWW_AUTH_CODE)
	{
		add_str(p, &str_init(AUTHORIZATION_HDR_START USERNAME_FIELD_S));
	} else {
		add_str(p, &str_init(PROXY_AUTHORIZATION_HDR_START USERNAME_FIELD_S));
	}
	/* username */
	add_str(p, &crd->auth_data.user);
	/* REALM */
	add_str(p, &str_init(FIELD_SEPARATOR_S REALM_FIELD_S));
	add_str(p, &crd->auth_data.realm);
	/* NONCE */
	add_str(p, &str_init(FIELD_SEPARATOR_S NONCE_FIELD_S));
	add_str(p, &auth->nonce);
	/* URI */
	add_str(p, &str_init(FIELD_SEPARATOR_S URI_FIELD_S));
	add_str(p, uri);
	/* OPAQUE */
	if (auth->opaque.len )
	{
		add_str(p, &str_init(FIELD_SEPARATOR_S OPAQUE_FIELD_S));
		add_str(p, &auth->opaque);
	}
	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		add_str(p, &str_init(FIELD_SEPARATOR_S QOP_FIELD_S));
		add_str(p, &qop_val);
		add_str(p, &str_init(FIELD_SEPARATOR_UQ_S NC_FIELD_S));
		add_str(p, &auth_nc_cnonce->nc);
		add_str(p, &str_init(FIELD_SEPARATOR_UQ_S CNONCE_FIELD_S));
		add_str(p, &auth_nc_cnonce->cnonce);
	}
	/* RESPONSE */
	add_str(p, &str_init(FIELD_SEPARATOR_S RESPONSE_FIELD_S));
	digest_calc->response_hash_fill(response, p, len - (p - auth_hdr.s));
	p += response_len;
	/* ALGORITHM */
	add_str(p, &str_init(FIELD_SEPARATOR_S ALGORITHM_FIELD_S));
	add_str(p, &digest_calc->algorithm_val);
	add_str(p, &str_init(CRLF));

	auth_hdr.len = p - auth_hdr.s;

	if (auth_hdr.len!=len)
	{
		LM_CRIT("BUG: bad buffer computation "
			"(%d<>%d)\n",len,auth_hdr.len);
		pkg_free( auth_hdr.s );
		auth_hdr.s = NULL; auth_hdr.len = 0;
		goto error;
	}

	LM_DBG("auth_hdr is <%.*s>\n", auth_hdr.len, auth_hdr.s);

	return &auth_hdr;
error:
	return NULL;
}
