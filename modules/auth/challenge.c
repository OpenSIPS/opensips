/*
 * Challenge related functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * 2003-01-20 snprintf in build_auth_hf replaced with memcpy to avoid
 *            possible issues with too small buffer
 * 2003-01-26 consume_credentials no longer complains about ACK/CANCEL(jiri)
 * 2006-03-01 pseudo variables support for domain name (bogdan)
 */

#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../parser/digest/digest.h"
#include "../../parser/digest/digest_parser.h"
#include "../../pvar.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../lib/csv.h"
#include "../../mod_fix.h"
#include "auth_mod.h"
#include "common.h"
#include "challenge.h"
#include "../../lib/digest_auth/dauth_nonce.h"
#include "index.h"
#include "api.h"
#include "../../lib/dassert.h"
#include "../../lib/digest_auth/digest_auth.h"
#include "../../lib/digest_auth/dauth_calc.h"


/*
 * proxy_challenge function sends this reply
 */
#define MESSAGE_407          "Proxy Authentication Required"


/*
 * www_challenge function send this reply
 */
#define MESSAGE_401        "Unauthorized"

#define QOP_AUTH	  ", qop=\"" QOP_AUTH_STR "\""
#define QOP_AUTH_INT	  ", qop=\"" QOP_AUTHINT_STR "\""
#define QOP_AUTH_BOTH_AAI	  ", qop=\"" QOP_AUTH_STR "," QOP_AUTHINT_STR "\""
#define QOP_AUTH_BOTH_AIA	  ", qop=\"" QOP_AUTHINT_STR "," QOP_AUTH_STR "\""
#define STALE_PARAM	  ", stale=true"
#define DIGEST_REALM	  ": Digest realm=\""
#define DIGEST_NONCE	  "\", nonce=\""
#define DIGEST_ALGORITHM  ", algorithm="
#define DIGEST_OPAQUE  ", opaque=\""


/*
 * Create {WWW,Proxy}-Authenticate header field
 */
char *build_auth_hf(struct nonce_context *ncp, struct nonce_params *calc_np,
	int _stale, const str_const *_realm, int* _len,
    const str_const *alg_val, const str_const* _hf_name, const str_const *opaque)
{
	char *hf, *p;
	str_const alg_param;
	str_const qop_param = STR_NULL_const;
	str_const stale_param = STR_NULL_const;
	const str_const digest_realm = str_const_init(DIGEST_REALM);
	const str_const nonce_param = str_const_init(DIGEST_NONCE);
	str_const opaque_param;

	if (calc_np->qop) {
		switch (calc_np->qop) {
		case QOP_AUTH_D:
			qop_param = str_const_init(QOP_AUTH);
			break;
		case QOP_AUTHINT_D:
			qop_param = str_const_init(QOP_AUTH_INT);
			break;
		case QOP_AUTHINT_AUTH_D:
			qop_param = str_const_init(QOP_AUTH_BOTH_AAI);
			break;
		case QOP_AUTH_AUTHINT_D:
			qop_param = str_const_init(QOP_AUTH_BOTH_AIA);
			break;
		default:
			LM_ERR("Wrong _qop value: %d\n", calc_np->qop);
			abort();
		}
	}
	if (_stale)
		stale_param = str_const_init(STALE_PARAM);

	/* length calculation */
	*_len=_hf_name->len;
	*_len+=digest_realm.len
		+_realm->len
		+nonce_param.len
		+ncp->nonce_len
		+1 /* '"' */
		+stale_param.len
		+qop_param.len
		+CRLF_LEN ;

	if (alg_val != NULL) {
		alg_param = str_const_init(DIGEST_ALGORITHM);
		*_len += alg_param.len + alg_val->len;
	}

	if (opaque != NULL) {
		opaque_param = str_const_init(DIGEST_OPAQUE);
		*_len += opaque_param.len + opaque->len + 1 /* '"' */;
	}

	p=hf=pkg_malloc(*_len+1);
	if (!hf) {
		LM_ERR("no pkg memory left\n");
		goto e1;
	}

	memcpy(p, _hf_name->s, _hf_name->len); p+=_hf_name->len;
	memcpy(p, digest_realm.s, digest_realm.len);p+=digest_realm.len;
	memcpy(p, _realm->s, _realm->len);p+=_realm->len;
	memcpy(p, nonce_param.s, nonce_param.len);p+=nonce_param.len;
	if (calc_nonce(ncp, p, calc_np) != 0) {
		LM_ERR("calc_nonce failed\n");
		goto e2;
	}
	p+=ncp->nonce_len;
	*p='"';p++;
	if (calc_np->qop) {
		memcpy(p, qop_param.s, qop_param.len);
		p+=qop_param.len;
	}
	if (_stale) {
		memcpy(p, stale_param.s, stale_param.len);
		p+=stale_param.len;
	}
	if (alg_val != NULL) {
		memcpy(p, alg_param.s, alg_param.len);
		p += alg_param.len;
		memcpy(p, alg_val->s, alg_val->len);
		p += alg_val->len;
	}
	if (opaque != NULL) {
		memcpy(p, opaque_param.s, opaque_param.len);
		p += opaque_param.len;
		memcpy(p, opaque->s, opaque->len);
		p += opaque->len;
		*p='"';p++;
	}

	memcpy(p, CRLF, CRLF_LEN ); p+=CRLF_LEN;
	*p=0; /* zero terminator, just in case */

	LM_DBG("'%s'\n", hf);
	return hf;
e2:
	pkg_free(hf);
e1:
	*_len=0;
	return NULL;
}

/*
 * Create and send a challenge
 */
static inline int challenge(struct sip_msg* _msg, str *realm, qop_type_t _qop,
    int _code, const str *reason, const str_const *_challenge_msg, int algmask)
{
	struct hdr_field* h = NULL;
	auth_body_t* cred = 0;
	int i, ret, nalgs, index = 0;
	hdr_types_t hftype = 0; /* Makes gcc happy */
	struct sip_uri *uri;
	str auth_hfs[LAST_ALG_SPTD - FIRST_ALG_SPTD + 1];
	const str_const *alg_val;
	const struct digest_auth_calc *digest_calc;
	struct nonce_params calc_np;

	switch(_code) {
	case WWW_AUTH_CODE:
		get_authorized_cred(_msg->authorization, &h);
		hftype = HDR_AUTHORIZATION_T;
		break;
	case PROXY_AUTH_CODE:
		get_authorized_cred(_msg->proxy_auth, &h);
		hftype = HDR_PROXYAUTH_T;
		break;
	}

	if (h) cred = (auth_body_t*)(h->parsed);

	if (realm->len == 0) {
		if (get_realm(_msg, hftype, &uri) < 0) {
			LM_ERR("failed to extract URI\n");
			if (send_resp(_msg, 400, &str_init(MESSAGE_400), NULL, 0) == -1) {
				LM_ERR("failed to send the response\n");
				return -1;
			}
			return 0;
		}

		realm = &uri->host;
		strip_realm(realm);
	}

	nalgs = 0;
	if (algmask >= ALG_MD5SESS && _qop == QOP_UNSPEC_D) {
		/* RFC8760 algos and XYZ-sess mandates QOP */
		_qop = QOP_AUTH_D;
	}
	if(!disable_nonce_check) {
		/* get the nonce index and mark it as used */
		index= reserve_nonce_index();
		if(index == -1)
		{
			LM_ERR("no more nonces can be generated\n");
			return -1;
		}
		LM_DBG("nonce index= %d\n", index);
	}

	if (clock_gettime(CLOCK_REALTIME, &calc_np.expires) != 0) {
		LM_ERR("clock_gettime failed\n");
		return -1;
	}
	calc_np.expires.tv_sec += nonce_expire;
	calc_np.index = index;
	calc_np.qop = _qop;

	for (i = LAST_ALG_SPTD; i >= FIRST_ALG_SPTD; i--) {
		if ((algmask & ALG2ALGFLG(i)) == 0)
			continue;
		digest_calc = get_digest_calc(i);
		if (digest_calc == NULL)
			continue;
		alg_val = (i == ALG_UNSPEC) ? NULL : &digest_calc->algorithm_val;
		calc_np.alg = (i == ALG_UNSPEC) ? ALG_MD5 : i;
		auth_hfs[nalgs].s = build_auth_hf(ncp, &calc_np, (cred ? cred->stale : 0),
		    str2const(realm), &auth_hfs[nalgs].len, alg_val, _challenge_msg, NULL);
		if (!auth_hfs[nalgs].s) {
			LM_ERR("failed to generate nonce\n");
			ret = -1;
			goto failure;
		}
		nalgs += 1;
	}
	DASSERT(nalgs > 0);

	ret = send_resp(_msg, _code, reason, auth_hfs, nalgs);
failure:
	for (i = 0; i < nalgs; i++) {
		if (auth_hfs[i].s) pkg_free(auth_hfs[i].s);
	}
	if (ret == -1) {
		LM_ERR("failed to send the response\n");
		return -1;
	}

	return 0;
}

/*
 * Challenge a user to send credentials using WWW-Authorize header field
 */
int www_challenge(struct sip_msg* _msg, str* _realm, void* _qop,
    intptr_t algmask)
{

	return challenge(_msg, _realm, (qop_type_t)(long)_qop, WWW_AUTH_CODE,
	    &str_init(MESSAGE_401), &str_const_init(WWW_AUTH_HDR),
	    algmask ? algmask : ALGFLG_UNSPEC);
}


/*
 * Challenge a user to send credentials using Proxy-Authorize header field
 */
int proxy_challenge(struct sip_msg* _msg, str* _realm, void* _qop,
    intptr_t algmask)
{

	return challenge(_msg, _realm, (qop_type_t)(long)_qop, PROXY_AUTH_CODE,
	    &str_init(MESSAGE_407), &str_const_init(PROXY_AUTH_HDR),
	    algmask ? algmask : ALGFLG_UNSPEC);
}


/*
 * Remove used credentials from a SIP message header
 */
int consume_credentials(struct sip_msg* _m, char* _s1, char* _s2)
{
	struct hdr_field* h;
	int len;

	get_authorized_cred(_m->authorization, &h);
	if (!h) {
		get_authorized_cred(_m->proxy_auth, &h);
		if (!h) {
			if (_m->REQ_METHOD!=METHOD_ACK
					&& _m->REQ_METHOD!=METHOD_CANCEL) {
				LM_ERR("no authorized credentials found (error in scripts)\n");
			}
			return -1;
		}
	}

	len=h->len;

	if (del_lump(_m, h->name.s - _m->buf, len, 0) == 0) {
		LM_ERR("can't remove credentials\n");
		return -1;
	}

	return 1;
}
