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
			emsg = &str_init(MESSAGE_400);
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
			emsg = &str_init(MESSAGE_500);
			ecode = 500;
		} else {
			emsg = &str_init(MESSAGE_400);
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
		emsg = &str_init(MESSAGE_400);
		ecode = 400;
		goto ereply;
	}

	if (mark_authorized_cred(_m, *_h) < 0) {
		LM_ERR("failed to mark parsed credentials\n");
		emsg = &str_init(MESSAGE_400);
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
	if ((np.qop != qop) &&
	    (np.qop != QOP_TYPE_BOTH || (qop != QOP_AUTH_D && qop != QOP_AUTHINT_D))) {
		LM_DBG("nonce does not match qop\n");
		goto stalenonce;
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
			LM_ERR("Incorrect length if pre-hashed credentials "
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

	get_rpid_avp( &api->rpid_avp, &api->rpid_avp_type );

	return 0;
}
