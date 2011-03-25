/*
 * $Id$
 *
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * UAC OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * UAC OpenSIPS-module is distributed in the hope that it will be useful,
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
 *  2006-03-02  UAC authentication looks first in AVPs for credential (bogdan)
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


#include "auth.h"


extern struct tm_binds uac_tmb;
extern pv_spec_t auth_username_spec;
extern pv_spec_t auth_realm_spec;
extern pv_spec_t auth_password_spec;


static struct uac_credential *crd_list = 0;


#define  duplicate_str(_strd, _strs, _error) \
	do { \
		_strd.s = (char*)pkg_malloc(_strs.len); \
		if (_strd.s==0) \
		{ \
			LM_ERR("no more pkg memory\n");\
			goto _error; \
		} \
		memcpy( _strd.s, _strs.s, _strs.len); \
		_strd.len = _strs.len; \
	}while(0)


static str nc = {"00000001", 8};
static str cnonce = {"o", 1};

int has_credentials(void)
{
	return (crd_list!=0)?1:0;
}

void free_credential(struct uac_credential *crd)
{
	if (crd)
	{
		if (crd->realm.s)
			pkg_free(crd->realm.s);
		if (crd->user.s)
			pkg_free(crd->user.s);
		if (crd->passwd.s)
			pkg_free(crd->passwd.s);
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

	if (p==0 || *p==0)
		goto error;

	crd = (struct uac_credential*)pkg_malloc(sizeof(struct uac_credential));
	if (crd==0)
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
	crd_list = 0;
}


static inline struct uac_credential *lookup_realm( str *realm)
{
	struct uac_credential *crd;

	for( crd=crd_list ; crd ; crd=crd->next )
		if (realm->len==crd->realm.len &&
		strncmp( realm->s, crd->realm.s, realm->len)==0 )
			return crd;
	return 0;
}


static inline struct uac_credential *get_avp_credential(struct sip_msg *msg,
																str *realm)
{
	static struct uac_credential crd;
	pv_value_t pv_val;

	if(pv_get_spec_value( msg, &auth_realm_spec, &pv_val)!=0
	|| pv_val.flags&PV_VAL_NULL || pv_val.rs.len<=0)
		return 0;
	
	crd.realm = pv_val.rs;
	/* is it the domain we are looking for? */
	if (realm->len!=crd.realm.len ||
	strncmp( realm->s, crd.realm.s, realm->len)!=0 )
		return 0;

	/* get username and password */
	if(pv_get_spec_value( msg, &auth_username_spec, &pv_val)!=0
	|| pv_val.flags&PV_VAL_NULL || pv_val.rs.len<=0)
		return 0;
	crd.user = pv_val.rs;

	if(pv_get_spec_value( msg, &auth_password_spec, &pv_val)!=0
	|| pv_val.flags&PV_VAL_NULL || pv_val.rs.len<=0)
		return 0;
	crd.passwd = pv_val.rs;

	return &crd;
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
void uac_calc_HA2( str *method, str *uri,
		struct authenticate_body *auth,
		HASHHEX hentity,
		HASHHEX HA2Hex )
{
	MD5_CTX Md5Ctx;
	HASH HA2;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, method->s, method->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, uri->s, uri->len);

	if ( auth->flags&QOP_AUTH_INT)
	{
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, hentity, HASHHEXLEN);
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

	if ( auth->qop.len)
	{
		MD5Update(&Md5Ctx, nc->s, nc->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, cnonce->s, cnonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, auth->qop.s, auth->qop.len);
		MD5Update(&Md5Ctx, ":", 1);
	};
	MD5Update(&Md5Ctx, ha2, HASHHEXLEN);
	MD5Final(RespHash, &Md5Ctx);
	cvt_hex(RespHash, response);
}



static inline void do_uac_auth(struct sip_msg *req, str *uri,
		struct uac_credential *crd, struct authenticate_body *auth,
		struct authenticate_nc_cnonce *auth_nc_cnonce,
		HASHHEX response)
{
	HASHHEX ha1;
	HASHHEX ha2;

	if((auth->flags&QOP_AUTH) || (auth->flags&QOP_AUTH_INT))
	{
		/* if qop generate nonce-count and cnonce */
		cnonce.s = int2str(core_hash(&auth->nonce, 0, 0),&cnonce.len);

		/* do authentication */
		uac_calc_HA1( crd, auth, &cnonce, ha1);
		uac_calc_HA2( &req->first_line.u.request.method, uri,
			auth, 0/*hentity*/, ha2 );

		uac_calc_response( ha1, ha2, auth, &nc, &cnonce, response);
		auth_nc_cnonce->nc = &nc;
		auth_nc_cnonce->cnonce = &cnonce;
	} else {
		/* do authentication */
		uac_calc_HA1( crd, auth, 0/*cnonce*/, ha1);
		uac_calc_HA2( &req->first_line.u.request.method, uri,
			auth, 0/*hentity*/, ha2 );

		uac_calc_response( ha1, ha2, auth, 0/*nc*/, 0/*cnonce*/, response);
	}
}


static inline int apply_urihdr_changes( struct sip_msg *req,
													str *uri, str *hdr)
{
	struct lump* anchor;

	/* add the uri - move it to branch directly FIXME (bogdan)*/
	if (req->new_uri.s)
	{
		pkg_free(req->new_uri.s);
		req->new_uri.len=0;
	}
	req->parsed_uri_ok=0;
	req->new_uri.s = (char*)pkg_malloc(uri->len+1);
	if (req->new_uri.s==0)
	{
		LM_ERR("no more pkg\n");
		goto error;
	}
	memcpy( req->new_uri.s, uri->s, uri->len);
	req->new_uri.s[uri->len]=0;
	req->new_uri.len=uri->len;

	/* add the header */
	if (parse_headers(req, HDR_EOH_F, 0) == -1)
	{
		LM_ERR("failed to parse message\n");
		goto error;
	}

	anchor = anchor_lump(req, req->unparsed - req->buf, 0, 0);
	if (anchor==0)
	{
		LM_ERR("failed to get anchor\n");
		goto error;
	}

	if (insert_new_lump_before(anchor, hdr->s, hdr->len, 0) == 0)
	{
		LM_ERR("faield to insert lump\n");
		goto error;
	}

	return 0;
error:
	pkg_free( hdr->s );
	return -1;
}



int uac_auth( struct sip_msg *msg)
{
	struct authenticate_body *auth = NULL;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	struct uac_credential *crd;
	int code, branch;
	struct sip_msg *rpl;
	struct cell *t;
	HASHHEX response;
	str *new_hdr;

	/* get transaction */
	t = uac_tmb.t_gett();
	if (t==T_UNDEFINED || t==T_NULL_CELL)
	{
		LM_CRIT("no current transaction found\n");
		goto error;
	}

	/* get the selected branch */
	branch = uac_tmb.t_get_picked();
	if (branch<0) {
		LM_CRIT("no picked branch (%d)\n",branch);
		goto error;
	}

	rpl = t->uac[branch].reply;
	code = t->uac[branch].last_received;
	LM_DBG("picked reply is %p, code %d\n",rpl,code);

	if (rpl==0)
	{
		LM_CRIT("empty reply on picked branch\n");
		goto error;
	}
	if (rpl==FAKED_REPLY)
	{
		LM_ERR("cannot process a FAKED reply\n");
		goto error;
	}

	if (code==WWW_AUTH_CODE) {
		if (0 == parse_www_authenticate_header(rpl))
			auth = get_www_authenticate(rpl);
	} else if (code==PROXY_AUTH_CODE) {
		if (0 == parse_proxy_authenticate_header(rpl))
			auth = get_proxy_authenticate(rpl);
	}

	if (auth == NULL) {
		LM_ERR("Unable to extract authentication info\n");
		goto error;
	}

	/* can we authenticate this realm? */
	crd = 0;
	/* first look into AVP, if set */
	if ( auth_realm_spec.type==PVT_AVP )
		crd = get_avp_credential( msg, &auth->realm );
	/* if not found, look into predefined credentials */
	if (crd==0)
		crd = lookup_realm( &auth->realm );
	/* found? */
	if (crd==0)
	{
		LM_DBG("no credential for realm \"%.*s\"\n",
			auth->realm.len, auth->realm.s);
		goto error;
	}

	/* do authentication */
	do_uac_auth( msg, &t->uac[branch].uri, crd, auth, &auth_nc_cnonce, response);

	/* build the authorization header */
	new_hdr = build_authorization_hdr( code, &t->uac[branch].uri,
		crd, auth, &auth_nc_cnonce, response);
	if (new_hdr==0)
	{
		LM_ERR("failed to build authorization hdr\n");
		goto error;
	}

	/* so far, so good -> add the header and set the proper RURI */
	if ( apply_urihdr_changes( msg, &t->uac[branch].uri, new_hdr)<0 )
	{
		LM_ERR("failed to apply changes\n");
		goto error;
	}

	/* increas the Cseq nr */


	return 0;
error:
	return -1;
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
		struct authenticate_nc_cnonce *auth_nc_cnonce,
		char *response)
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

