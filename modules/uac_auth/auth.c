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
#include "../../md5global.h"
#include "../../md5.h"
#include "../../parser/parse_authenticate.h"
#include "../tm/tm_load.h"

#include "uac_auth.h"


extern int            realm_avp_name;
extern unsigned short realm_avp_type;
extern int            user_avp_name;
extern unsigned short user_avp_type;
extern int            pwd_avp_name;
extern unsigned short pwd_avp_type;



static str nc = {"00000001", 8};
static str cnonce = {"o", 1};
static str auth_hdr = {NULL, 0};

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
		if (crd->realm.s) pkg_free(crd->realm.s);
		if (crd->user.s) pkg_free(crd->user.s);
			if (crd->passwd.s) pkg_free(crd->passwd.s);
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
	duplicate_str( crd->user, foo, error);

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
	duplicate_str( crd->realm, foo, error);

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
	duplicate_str( crd->passwd, foo, error);

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

	crd.realm = val.s;
	/* is it the domain we are looking for? */
	if (realm->len!=crd.realm.len ||
	strncmp( realm->s, crd.realm.s, realm->len)!=0 )
		return 0;

	/* get username and password */
	avp = search_first_avp( user_avp_type, user_avp_name, &val, 0);
	if ( avp==NULL || (avp->flags&AVP_VAL_STR)==0 || val.s.len<=0 )
		return 0;
	crd.user = val.s;

	avp = search_first_avp( pwd_avp_type, pwd_avp_name, &val, 0);
	if ( avp==NULL || (avp->flags&AVP_VAL_STR)==0 || val.s.len<=0 )
		return 0;
	crd.passwd = val.s;

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
		if (realm->len==crd->realm.len &&
		strncmp( realm->s, crd->realm.s, realm->len)==0 )
			return crd;
	return 0;
}


static inline void cvt_hex(HASH bin, HASHHEX hex)
{
	unsigned short i;
	unsigned char j;

	for (i = 0; i<HASHLEN; i++)
	{
		j = (bin[i] >> 4) & 0xf;
		if (j <= 9)
		{
			hex[i * 2] = (j + '0');
		} else {
			hex[i * 2] = (j + 'a' - 10);
		}

		j = bin[i] & 0xf;

		if (j <= 9)
		{
			hex[i * 2 + 1] = (j + '0');
		} else {
			hex[i * 2 + 1] = (j + 'a' - 10);
		}
	};

	hex[HASHHEXLEN] = '\0';
}



/*
 * calculate H(A1)
 */
void uac_calc_HA1( struct uac_credential *crd,
		struct authenticate_body *auth,
		str* cnonce,
		HASHHEX sess_key)
{
	MD5_CTX Md5Ctx;
	HASH HA1;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, crd->user.s, crd->user.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->realm.s, crd->realm.len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, crd->passwd.s, crd->passwd.len);
	MD5Final(HA1, &Md5Ctx);

	if ( auth->flags& AUTHENTICATE_MD5SESS )
	{
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, HA1, HASHLEN);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, auth->nonce.s, auth->nonce.len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Final(HA1, &Md5Ctx);
	};

	cvt_hex(HA1, sess_key);
}



/*
 * calculate H(A2)
 */
void uac_calc_HA2(str *msg_body, str *method, str *uri,
		int auth_int, HASHHEX HA2Hex)
{
	MD5_CTX Md5Ctx;
	HASH HA2;
	HASH HENTITY;
	HASHHEX HENTITYHex;

	if (auth_int) {
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, msg_body->s, msg_body->len);
		MD5Final(HENTITY, &Md5Ctx);
		cvt_hex(HENTITY, HENTITYHex);
	}

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, method->s, method->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, uri->s, uri->len);

	if (auth_int)
	{
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, HENTITYHex, HASHHEXLEN);
	};

	MD5Final(HA2, &Md5Ctx);
	cvt_hex(HA2, HA2Hex);
}



/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
void uac_calc_response( HASHHEX ha1, HASHHEX ha2,
		struct authenticate_body *auth,
		str* nc, str* cnonce,
		HASHHEX response)
{
	MD5_CTX Md5Ctx;
	HASH RespHash;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, ha1, HASHHEXLEN);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, auth->nonce.s, auth->nonce.len);
	MD5Update(&Md5Ctx, ":", 1);

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		MD5Update(&Md5Ctx, nc->s, nc->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		if (!(auth->flags&QOP_AUTH))
			MD5Update(&Md5Ctx, "auth-int", 8);
		else
			MD5Update(&Md5Ctx, "auth", 4);
		MD5Update(&Md5Ctx, ":", 1);
	};
	MD5Update(&Md5Ctx, ha2, HASHHEXLEN);
	MD5Final(RespHash, &Md5Ctx);
	cvt_hex(RespHash, response);
}


void do_uac_auth(str *msg_body, str *method, str *uri, struct uac_credential *crd,
		struct authenticate_body *auth, struct authenticate_nc_cnonce *auth_nc_cnonce,
		HASHHEX response)
{
	HASHHEX ha1;
	HASHHEX ha2;
	int i, has_ha1;

	/* before actually doing the authe, we check if the received password is
	   a plain text password or a HA1 value ; we detect a HA1 (in the password
	   field if: (1) starts with "0x"; (2) len is 32 + 2 (prefix) ; (3) the 32
	   chars are HEXA values */
	if (crd->passwd.len==34 && crd->passwd.s[0]=='0' && crd->passwd.s[1]=='x') {
		/* it may be a HA1 - check the actual content */
		for( has_ha1=1,i=2 ; i<crd->passwd.len ; i++ ) {
			if ( !( (crd->passwd.s[i]>='0' && crd->passwd.s[i]<='9') ||
			(crd->passwd.s[i]>='a' && crd->passwd.s[i]<='f') )) {
				has_ha1 = 0;
				break;
			} else {
				ha1[i-2] = crd->passwd.s[i];
			}
		}
		ha1[HASHHEXLEN] = 0;
	} else {
		has_ha1 = 0;
	}

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		/* if qop generate nonce-count and cnonce */
		cnonce.s = int2str(core_hash(&auth->nonce, 0, 0),&cnonce.len);

		/* do authentication */
		if (!has_ha1)
			uac_calc_HA1( crd, auth, &cnonce, ha1);
		uac_calc_HA2(msg_body, method, uri, !(auth->flags&QOP_AUTH), ha2);

		uac_calc_response( ha1, ha2, auth, &nc, &cnonce, response);
		auth_nc_cnonce->nc = &nc;
		auth_nc_cnonce->cnonce = &cnonce;
	} else {
		/* do authentication */
		if (!has_ha1)
			uac_calc_HA1( crd, auth, 0/*cnonce*/, ha1);
		uac_calc_HA2(msg_body, method, uri, 0, ha2);

		uac_calc_response( ha1, ha2, auth, 0/*nc*/, 0/*cnonce*/, response);
	}
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
	char *p;
	int len;
	int response_len;
	char *qop_val;
	int qop_val_len = 0;

	response_len = strlen(response);

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT)) {
		if (!(auth->flags&QOP_AUTH)) {
			qop_val = "auth-int";
			qop_val_len = 8;
		} else {
			qop_val = "auth";
			qop_val_len = 4;
		}
	}

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
		len += QOP_FIELD_LEN + qop_val_len + FIELD_SEPARATOR_UQ_LEN +
				NC_FIELD_LEN + auth_nc_cnonce->nc->len + FIELD_SEPARATOR_UQ_LEN +
				CNONCE_FIELD_LEN + auth_nc_cnonce->cnonce->len + FIELD_SEPARATOR_LEN;

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
		add_string( p, qop_val, qop_val_len);
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
	return 0;
}


