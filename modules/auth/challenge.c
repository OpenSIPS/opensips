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
#include "../../pvar.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../lib/csv.h"
#include "../../mod_fix.h"
#include "auth_mod.h"
#include "common.h"
#include "challenge.h"
#include "nonce.h"
#include "index.h"
#include "api.h"


/*
 * proxy_challenge function sends this reply
 */
#define MESSAGE_407          "Proxy Authentication Required"
#define PROXY_AUTH_CHALLENGE "Proxy-Authenticate"


/*
 * www_challenge function send this reply
 */
#define MESSAGE_401        "Unauthorized"
#define WWW_AUTH_CHALLENGE "WWW-Authenticate"

#define QOP_AUTH	  ", qop=\"auth\""
#define QOP_AUTH_INT	  ", qop=\"auth-int\""
#define QOP_AUTH_BOTH	  ", qop=\"auth,auth-int\""
#define STALE_PARAM	  ", stale=true"
#define DIGEST_REALM	  ": Digest realm=\""
#define DIGEST_NONCE	  "\", nonce=\""


/*
 * Create {WWW,Proxy}-Authenticate header field
 */
static inline char *build_auth_hf(int _retries, int _stale, str* _realm,
    int* _len, int _qop, const str* _hf_name)
{
	char *hf, *p;
	int index = 0;
	str qop_param = STR_NULL;
	str stale_param = STR_NULL;
	const str digest_realm = str_init(DIGEST_REALM);
	const str nonce_param = str_init(DIGEST_NONCE);

	if(!disable_nonce_check) {
		/* get the nonce index and mark it as used */
		index= reserve_nonce_index();
		if(index == -1)
		{
			LM_ERR("no more nonces can be generated\n");
			return 0;
		}
		LM_DBG("nonce index= %d\n", index);
	}

	if (_qop) {
		if (_qop == QOP_TYPE_AUTH) {
			qop_param = str_init(QOP_AUTH);
		} else if (_qop == QOP_TYPE_AUTH_INT) {
			qop_param = str_init(QOP_AUTH_INT);
		} else {
			qop_param = str_init(QOP_AUTH_BOTH);
		}
	}
	if (_stale)
		stale_param = str_init(STALE_PARAM);

	/* length calculation */
	*_len=_hf_name->len;
	*_len+=digest_realm.len
		+_realm->len
		+nonce_param.len
		+((!disable_nonce_check)?NONCE_LEN:NONCE_LEN-8)
		+1 /* '"' */
		+qop_param.len
		+CRLF_LEN ;

	p=hf=pkg_malloc(*_len+1);
	if (!hf) {
		LM_ERR("no pkg memory left\n");
		*_len=0;
		return 0;
	}

	memcpy(p, _hf_name->s, _hf_name->len); p+=_hf_name->len;
	memcpy(p, digest_realm.s, digest_realm.len);p+=digest_realm.len;
	memcpy(p, _realm->s, _realm->len);p+=_realm->len;
	memcpy(p, nonce_param.s, nonce_param.len);p+=nonce_param.len;
	calc_nonce(p, time(0) + nonce_expire, index, &secret);
	p+=((!disable_nonce_check)?NONCE_LEN:NONCE_LEN-8);
	*p='"';p++;
	if (_qop) {
		memcpy(p, qop_param.s, qop_param.len);
		p+=qop_param.len;
	}
	if (_stale) {
		memcpy(p, stale_param.s, stale_param.len);
		p+=stale_param.len;
	}
	memcpy(p, CRLF, CRLF_LEN ); p+=CRLF_LEN;
	*p=0; /* zero terminator, just in case */

	LM_DBG("'%s'\n", hf);
	return hf;
}

/*
 * Create and send a challenge
 */
static inline int challenge(struct sip_msg* _msg, str *realm, int _qop,
    int _code, const str *reason, const str* _challenge_msg)
{
	int auth_hf_len;
	struct hdr_field* h = NULL;
	auth_body_t* cred = 0;
	char *auth_hf;
	int ret;
	hdr_types_t hftype = 0; /* Makes gcc happy */
	struct sip_uri *uri;

	switch(_code) {
	case 401:
		get_authorized_cred(_msg->authorization, &h);
		hftype = HDR_AUTHORIZATION_T;
		break;
	case 407:
		get_authorized_cred(_msg->proxy_auth, &h);
		hftype = HDR_PROXYAUTH_T;
		break;
	}

	if (h) cred = (auth_body_t*)(h->parsed);

	if (realm->len == 0) {
		if (get_realm(_msg, hftype, &uri) < 0) {
			LM_ERR("failed to extract URI\n");
			if (send_resp(_msg, 400, &str_init(MESSAGE_400), 0, 0) == -1) {
				LM_ERR("failed to send the response\n");
				return -1;
			}
			return 0;
		}

		realm = &uri->host;
		strip_realm(realm);
	}

	auth_hf = build_auth_hf(0, (cred ? cred->stale : 0), realm,
			&auth_hf_len, _qop, _challenge_msg);
	if (!auth_hf) {
		LM_ERR("failed to generate nonce\n");
		return -1;
	}

	ret = send_resp(_msg, _code, reason, auth_hf, auth_hf_len);
	if (auth_hf) pkg_free(auth_hf);
	if (ret == -1) {
		LM_ERR("failed to send the response\n");
		return -1;
	}

	return 0;
}

int fixup_qop(void** param)
{
	str *s = (str*)*param;
	int qop_type = 0;
	csv_record *q_csv, *q;

	q_csv = parse_csv_record(s);
	if (!q_csv) {
		LM_ERR("Failed to parse qop types\n");
		return -1;
	}
	for (q = q_csv; q; q = q->next) {
		if (!str_strcmp(&q->s, _str("auth")))  {
			if (qop_type == QOP_TYPE_AUTH_INT)
				qop_type = QOP_TYPE_BOTH;
			else
				qop_type = QOP_TYPE_AUTH;
		} else if (!str_strcmp(&q->s, _str("auth-int"))) {
			if (qop_type == QOP_TYPE_AUTH)
				qop_type = QOP_TYPE_BOTH;
			else
				qop_type = QOP_TYPE_AUTH_INT;
		} else {
			LM_ERR("Bad qop type\n");
			free_csv_record(q_csv);
			return -1;
		}
	}
	free_csv_record(q_csv);

	*param=(void*)(long)qop_type;
	return 0;
}

/*
 * Challenge a user to send credentials using WWW-Authorize header field
 */
int www_challenge(struct sip_msg* _msg, str* _realm, void* _qop)
{
	return challenge(_msg, _realm, (int)(long)_qop, 401,
		&str_init(MESSAGE_401), &str_init(WWW_AUTH_CHALLENGE));
}


/*
 * Challenge a user to send credentials using Proxy-Authorize header field
 */
int proxy_challenge(struct sip_msg* _msg, str* _realm, void* _qop)
{
	return challenge(_msg, _realm, (int)(long)_qop, 407,
		&str_init(MESSAGE_407), &str_init(PROXY_AUTH_CHALLENGE));
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
