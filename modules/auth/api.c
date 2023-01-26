/*
 * Digest Authentication Module
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
 */

#include <string.h>
#include "../../dprint.h"
#include "../../parser/digest/digest.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "auth_mod.h"
#include "../../lib/digest_auth/dauth_nonce.h"
#include "common.h"
#include "api.h"
#include "challenge.h"
#include "rpid.h"
#include "index.h"
#include "../../lib/digest_auth/dauth_calc.h"
#include "../../lib/dassert.h"


/*
 * if realm determined from request, look if there are some
 * modification rules
 */
void strip_realm(str* _realm)
{
	/* no param defined -- return */
	if (!realm_prefix.len) return;

	/* prefix longer than realm -- return */
	if (realm_prefix.len > _realm->len) return;

	/* match ? -- if so, shorten realm -*/
	if (memcmp(realm_prefix.s, _realm->s, realm_prefix.len) == 0) {
		_realm->s += realm_prefix.len;
		_realm->len -= realm_prefix.len;
	}
	return;
}


/*
 * Find credentials with given realm in a SIP message header
 */
static inline int find_credentials(struct sip_msg* _m, str* _realm,
								hdr_types_t _hftype, struct hdr_field** _h)
{
	struct hdr_field** hook, *ptr, *prev;
	hdr_flags_t hdr_flags;
	int res;
	str* r;

	/*
	 * Determine if we should use WWW-Authorization or
	 * Proxy-Authorization header fields, this parameter
	 * is set in www_authorize and proxy_authorize
	 */
	switch(_hftype) {
	case HDR_AUTHORIZATION_T:
		hook = &(_m->authorization);
		hdr_flags=HDR_AUTHORIZATION_F;
		break;
	case HDR_PROXYAUTH_T:
		hook = &(_m->proxy_auth);
		hdr_flags=HDR_PROXYAUTH_F;
		break;
	default:
		hook = &(_m->authorization);
		hdr_flags=HDR_T2F(_hftype);
		break;
	}

	/*
	 * If the credentials haven't been parsed yet, do it now
	 */
	if (*hook == 0) {
		/* No credentials parsed yet */
		if (parse_headers(_m, hdr_flags, 0) == -1) {
			LM_ERR("failed to parse headers\n");
			return -1;
		}
	}

	ptr = *hook;

	/*
	 * Iterate through the credentials in the message and
	 * find credentials with given realm
	 */
	while(ptr) {
		res = parse_credentials(ptr);
		if (res < 0) {
			LM_ERR("failed to parse credentials\n");
			return (res == -1) ? -2 : -3;
		} else if (res == 0) {
			auth_body_t *abp = (auth_body_t *)(ptr->parsed);
			dig_cred_t *dcp = &(abp->digest);
			r = &(abp->digest.realm);
			if (r->len == _realm->len && get_digest_calc(dcp->alg.alg_parsed) != NULL) {
				if (!strncasecmp(_realm->s, r->s, r->len)) {
					*_h = ptr;
					return 0;
				}
			}
		}

		prev = ptr;
		if (parse_headers(_m, hdr_flags, 1) == -1) {
			LM_ERR("failed to parse headers\n");
			return -4;
		} else {
			if (prev != _m->last_header) {
				if (_m->last_header->type == _hftype) ptr = _m->last_header;
				else break;
			} else break;
		}
	}

	/*
	 * Credentials with given realm not found
	 */

    return 1;
}


/*
 * Purpose of this function is to find credentials with given realm,
 * do sanity check, validate credential correctness and determine if
 * we should really authenticate (there must be no authentication for
 * ACK and CANCEL
 */
auth_result_t pre_auth(struct sip_msg* _m, str* _realm, hdr_types_t _hftype,
													struct hdr_field** _h)
{
	int ret, ecode;
	auth_body_t* c;
	struct sip_uri *uri;
	const str *emsg;

	/* ACK and CANCEL must be always authorized, there is
	 * no way how to challenge ACK and CANCEL cannot be
	 * challenged because it must have the same CSeq as
	 * the request to be canceled
	 */

	if ((_m->REQ_METHOD == METHOD_ACK) ||  (_m->REQ_METHOD == METHOD_CANCEL))
		return AUTHORIZED;

	if (_realm->len == 0) {
		if (get_realm(_m, _hftype, &uri) < 0) {
			LM_ERR("failed to extract realm\n");
			emsg = str_static(MESSAGE_400);
			ecode = 400;
			goto ereply;
		}

		*_realm = uri->host;
		strip_realm(_realm);
	}

	/* Try to find credentials with corresponding realm
	 * in the message, parse them and return pointer to
	 * parsed structure
	 */
	ret = find_credentials(_m, _realm, _hftype, _h);
	if (ret < 0) {
		LM_ERR("failed to find credentials\n");
		if (ret == -2) {
			emsg = str_static(MESSAGE_500);
			ecode = 500;
		} else {
			emsg = str_static(MESSAGE_400);
			ecode = 400;
		}
		goto ereply;
	} else if (ret > 0) {
		LM_DBG("credentials with given realm not found\n");
		return NO_CREDENTIALS;
	}

	/* Pointer to the parsed credentials */
	c = (auth_body_t*)((*_h)->parsed);
	dig_cred_t *dcp = &(c->digest);

	/* Check credentials correctness here */
	if (check_dig_cred(dcp) != E_DIG_OK) {
		LM_DBG("received credentials are not filled properly\n");
		emsg = str_static(MESSAGE_400);
		ecode = 400;
		goto ereply;
	}

	if (mark_authorized_cred(_m, *_h) < 0) {
		LM_ERR("failed to mark parsed credentials\n");
		emsg = str_static(MESSAGE_400);
		ecode = 500;
		goto ereply;
	}

	struct nonce_params np;
	if (decr_nonce(ncp, str2const(&dcp->nonce), &np) != 0) {
		LM_DBG("failed to decrypt nonce (stale/invalid)\n");
		goto stalenonce;
	}
	alg_t ealg = (dcp->alg.alg_parsed == ALG_UNSPEC) ? ALG_MD5 :
	    dcp->alg.alg_parsed;
	if (np.alg != ealg) {
		LM_DBG("nonce does not match algorithm\n");
		goto stalenonce;
	}
	qop_type_t qop = dcp->qop.qop_parsed;
	if (qop == QOP_UNSPEC_D) {
		/*
		 * RFC8760: If the "qop" parameter is not specified, then
		 * the default value is "auth".
		 */
		qop = QOP_AUTH_D;
	}
	if (np.qop != qop) {
		switch (np.qop) {
		case QOP_AUTH_AUTHINT_D:
		case QOP_AUTHINT_AUTH_D:
			if (qop == QOP_AUTH_D || qop == QOP_AUTHINT_D)
				break;
			/* Fall through */
		default:
			LM_DBG("nonce (%d) does not match qop (%d)\n", np.qop, qop);
			goto stalenonce;
		}
	}
	if (is_nonce_stale(&np, nonce_expire)) {
		LM_DBG("stale nonce value received\n");
		goto stalenonce;
	}
	if(!disable_nonce_check) {
		/* Verify if it is the first time this nonce is received */
		LM_DBG("nonce index= %d\n", np.index);

		if(!is_nonce_index_valid(np.index)) {
			LM_DBG("nonce index not valid\n");
			goto stalenonce;
		}
	} else if (np.index != 0) {
		LM_DBG("nonce index not valid\n");
		goto stalenonce;
	}

	return DO_AUTHORIZATION;
ereply:
	if (send_resp(_m, ecode, emsg, 0, 0) == -1) {
		LM_ERR("failed to send %d reply\n", ecode);
	}
	return ERROR;
stalenonce:
	c->stale = 1;
	return STALE_NONCE;
}


/*
 * Purpose of this function is to do post authentication steps like
 * marking authorized credentials and so on.
 */
auth_result_t post_auth(struct sip_msg* _m, struct hdr_field* _h)
{

	return AUTHORIZED;
}

int check_response(const dig_cred_t* _cred, const str* _method,
    const str *_msg_body, const HASHHEX* _ha1)
{
	HASHHEX ha2;
	struct digest_auth_response resp;
	const struct digest_auth_calc *digest_calc;

	digest_calc = get_digest_calc(_cred->alg.alg_parsed);
	if (digest_calc == NULL) {
		LM_ERR("digest algorithm (%d) unsupported\n", _cred->alg.alg_parsed);
		return (-1);
	}

	/*
	 * First, we have to verify that the response received has
	 * the same length as responses created by us
	 */
	if (_cred->response.len != digest_calc->HASHHEXLEN) {
		LM_DBG("receive response len != %d\n", digest_calc->HASHHEXLEN);
		return 1;
	}

	/*
	 * Now, calculate our response from parameters received
	 * from the user agent
	 */
	if (digest_calc->HA2(str2const(_msg_body), str2const(_method),
	    str2const(&(_cred->uri)), _cred->qop.qop_parsed == QOP_AUTHINT_D, &ha2) != 0)
		return (-1);
	if (digest_calc->response(_ha1, &ha2, str2const(&(_cred->nonce)),
	    str2const(&(_cred->qop.qop_str)), str2const(&(_cred->nc)),
	    str2const(&(_cred->cnonce)), &resp) != 0)
		return (-1);

#if !defined(NO_DEBUG)
	do {
		char tmpb[digest_calc->HASHHEXLEN];
		LM_DBG("our result = \'%.*s\'\n", digest_calc->HASHHEXLEN,
		    digest_calc->response_hash_fill(&resp, tmpb, sizeof(tmpb)));
	} while (0);
#endif

	/*
	 * And simply compare the strings, the user is
	 * authorized if they match
	 */
	if (digest_calc->response_hash_bcmp(&resp, str2const(&_cred->response)) == 0) {
		LM_DBG("authorization is OK\n");
		return 0;
	} else {
		LM_DBG("authorization failed\n");
		return 2;
	}
}

static int auth_calc_HA1(const struct calc_HA1_arg *params, HASHHEX *sess_key)
{
	const struct digest_auth_calc *digest_calc;

	digest_calc = get_digest_calc(params->alg);
	if (digest_calc == NULL) {
		LM_ERR("digest algorithm (%d) unsupported\n", params->alg);
		return -1;
	}
	if (!params->use_hashed) {
		if (digest_calc->HA1(params->creds.open, sess_key) != 0)
			return -1;
	} else {
		if (params->creds.ha1->len != digest_calc->HASHHEXLEN) {
			LM_ERR("Incorrect length of pre-hashed credentials "
			    "for the algorithm \"%s\": %d expected, %d provided\n",
			    digest_calc->algorithm_val.s, digest_calc->HASHHEXLEN,
			    params->creds.ha1->len);
			return -1;
		}
		memcpy(sess_key->_start, params->creds.ha1->s,
		    params->creds.ha1->len);
	}
	if (digest_calc->HA1sess != NULL)
		if (digest_calc->HA1sess(str2const(params->nonce),
		    str2const(params->cnonce), sess_key) != 0)
			return -1;
	sess_key->_start[digest_calc->HASHHEXLEN] = '\0';
	return 0;
}

#define AUTH_INFO_HDR_START       "Authentication-Info: "
#define AUTH_INFO_HDR_START_LEN   (sizeof(AUTH_INFO_HDR_START)-1)

#define QOP_FIELD_S              "qop="
#define QOP_FIELD_LEN            (sizeof(QOP_FIELD_S)-1)
#define NC_FIELD_S               "nc="
#define NC_FIELD_LEN             (sizeof(NC_FIELD_S)-1)
#define CNONCE_FIELD_S           "cnonce=\""
#define CNONCE_FIELD_LEN         (sizeof(CNONCE_FIELD_S)-1)
#define RSPAUTH_FIELD_S           "rspauth=\""
#define RSPAUTH_FIELD_LEN         (sizeof(RSPAUTH_FIELD_S)-1)
#define FIELD_SEPARATOR_S        "\", "
#define FIELD_SEPARATOR_LEN      (sizeof(FIELD_SEPARATOR_S)-1)
#define FIELD_SEPARATOR_UQ_S     ", "
#define FIELD_SEPARATOR_UQ_LEN   (sizeof(FIELD_SEPARATOR_UQ_S)-1)

static int calc_response(str *msg_body, str *method,
	struct digest_auth_credential *auth_data, dig_cred_t *cred,
	struct digest_auth_response *response)
{
	HASHHEX ha1;
	HASHHEX ha2;
	int i, has_ha1;
	const struct digest_auth_calc *digest_calc;
	str_const cnonce;
	str_const nc;

	digest_calc = get_digest_calc(cred->alg.alg_parsed);
	if (digest_calc == NULL) {
		LM_ERR("digest algorithm (%d) unsupported\n", cred->alg.alg_parsed);
		return (-1);
	}

	/* before actually doing the authe, we check if the received password is
	   a plain text password or a HA1 value ; we detect a HA1 (in the password
	   field if: (1) starts with "0x"; (2) len is 32 + 2 (prefix) ; (3) the 32
	   chars are HEXA values */
	if (auth_data->passwd.len==(digest_calc->HASHHEXLEN + 2) &&
	    auth_data->passwd.s[0]=='0' && auth_data->passwd.s[1]=='x') {
		/* it may be a HA1 - check the actual content */
		for( has_ha1=1,i=2 ; i<auth_data->passwd.len ; i++ ) {
			if ( !( (auth_data->passwd.s[i]>='0' && auth_data->passwd.s[i]<='9') ||
			(auth_data->passwd.s[i]>='a' && auth_data->passwd.s[i]<='f') )) {
				has_ha1 = 0;
				break;
			} else {
				ha1._start[i-2] = auth_data->passwd.s[i];
			}
		}
		ha1._start[digest_calc->HASHHEXLEN] = 0;
	} else {
		has_ha1 = 0;
	}

	if(cred->qop.qop_parsed >= QOP_AUTH_D && cred->qop.qop_parsed < QOP_OTHER_D)
	{
		/* if qop generate nonce-count and cnonce */
		nc = str_const_init("00000001");
		cnonce.s = int2str(core_hash(&cred->nonce, NULL, 0),&cnonce.len);

		/* calc response */
		if (!has_ha1)
			if (digest_calc->HA1(auth_data, &ha1) != 0)
				return (-1);
		if (digest_calc->HA1sess != NULL)
			if (digest_calc->HA1sess(str2const(&cred->nonce), &cnonce, &ha1) != 0)
				return (-1);
		if (digest_calc->HA2(str2const(msg_body), str2const(method), str2const(&cred->uri),
		    (cred->qop.qop_parsed >= QOP_AUTHINT_D), &ha2) != 0)
			return (-1);

		if (digest_calc->response(&ha1, &ha2, str2const(&cred->nonce),
		    str2const(&cred->qop.qop_str), &nc, &cnonce, response) != 0)
			return (-1);
	} else {
		/* calc response */
		if (!has_ha1)
			if (digest_calc->HA1(auth_data, &ha1) != 0)
				return (-1);
		if (digest_calc->HA1sess != NULL)
			if (digest_calc->HA1sess(str2const(&cred->nonce), NULL/*cnonce*/, &ha1) != 0)
				return (-1);
		if (digest_calc->HA2(str2const(msg_body), str2const(method), str2const(&cred->uri),
		    0, &ha2) != 0)
			return (-1);

		if (digest_calc->response(&ha1, &ha2, str2const(&cred->nonce),
		    NULL/*qop*/, NULL/*nc*/, NULL/*cnonce*/, response) != 0)
			return (-1);
	}
	return (0);
}

static str *build_auth_info_hf(str *msg_body, str *method, dig_cred_t *cred,
	struct digest_auth_credential *auth_data)
{
	static str buf = STR_NULL;
	struct digest_auth_response response;
	int rsp_len;
	char *p;

	if (calc_response(msg_body, method, auth_data, cred, &response) != 0) {
		LM_ERR("Failed to calculate response\n");
		return NULL;
	}

	rsp_len = response.digest_calc->HASHHEXLEN;

	buf.len = AUTH_INFO_HDR_START_LEN + QOP_FIELD_LEN + cred->qop.qop_str.len +
		FIELD_SEPARATOR_UQ_LEN + CNONCE_FIELD_LEN + cred->cnonce.len +
		FIELD_SEPARATOR_LEN + NC_FIELD_LEN + cred->nc.len +
		FIELD_SEPARATOR_UQ_LEN  + RSPAUTH_FIELD_LEN + rsp_len + 1;

	buf.s = pkg_malloc(buf.len);
	if (!buf.s) {
		LM_ERR("no more pgk memory\n");
		return NULL;
	}

	p = buf.s;
	memcpy(p, AUTH_INFO_HDR_START, AUTH_INFO_HDR_START_LEN);
	p += AUTH_INFO_HDR_START_LEN;

	memcpy(p, QOP_FIELD_S, QOP_FIELD_LEN);
	p += QOP_FIELD_LEN;
	memcpy(p, cred->qop.qop_str.s, cred->qop.qop_str.len);
	p += cred->qop.qop_str.len;
	memcpy(p, FIELD_SEPARATOR_UQ_S, FIELD_SEPARATOR_UQ_LEN);
	p += FIELD_SEPARATOR_UQ_LEN;

	memcpy(p, CNONCE_FIELD_S, CNONCE_FIELD_LEN);
	p += CNONCE_FIELD_LEN;
	memcpy(p, cred->cnonce.s, cred->cnonce.len);
	p += cred->cnonce.len;
	memcpy(p, FIELD_SEPARATOR_S, FIELD_SEPARATOR_LEN);
	p += FIELD_SEPARATOR_LEN;

	memcpy(p, NC_FIELD_S, NC_FIELD_LEN);
	p += NC_FIELD_LEN;
	memcpy(p, cred->nc.s, cred->nc.len);
	p += cred->nc.len;
	memcpy(p, FIELD_SEPARATOR_S, FIELD_SEPARATOR_LEN);
	p += FIELD_SEPARATOR_LEN;

	memcpy(p, RSPAUTH_FIELD_S, RSPAUTH_FIELD_LEN);
	p += RSPAUTH_FIELD_LEN;
	response.digest_calc->response_hash_fill(&response,
		p, buf.len - (p - buf.s));
	p += rsp_len;

	if (buf.len != p - buf.s) {
		LM_BUG("computed: %d, but wrote %d\n",buf.len,(int)(p-buf.s));
		pkg_free(buf.s);
		return NULL;
	}

	return &buf;
}

int bind_auth(auth_api_t* api)
{
	if (!api) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	api->pre_auth = pre_auth;
	api->post_auth = post_auth;
	api->calc_HA1 = auth_calc_HA1;
	api->check_response = check_response;
	api->build_auth_hf = build_auth_hf;
	api->build_auth_info_hf = build_auth_info_hf;

	get_rpid_avp( &api->rpid_avp, &api->rpid_avp_type );

	return 0;
}
