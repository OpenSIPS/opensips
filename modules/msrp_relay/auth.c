/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../auth/api.h"
#include "../proto_msrp/msrp_api.h"
#include "../../ut.h"
#include "../../lib/hash.h"
#include "../../timer.h"

#include "msrp_relay.h"
#include "auth.h"

#define AUTH_STR "AUTH"

#define REASON_UNAUTHORIZED_STR "Unauthorized"
#define REASON_INVALID_CREDS_STR "Invalid credentials"
#define REASON_SERVER_ERROR_STR "Server Error"
#define REASON_BAD_NONCE_STR "Bad nonce"
#define REASON_UNSUPPORTED_ALG_STR "Unsupported algorithm"
#define REASON_UNSUPPORTED_QOP_STR "Unsupported qop"

#define USE_PATH_HDR_S     "Use-Path: msrp://"
#define USE_PATH_SEC_HDR_S "Use-Path: msrps://"
#define USE_PATH_HDR_LEN (sizeof(USE_PATH_HDR_S) - 1)
#define USE_PATH_SEC_HDR_LEN (sizeof(USE_PATH_SEC_HDR_S) - 1)
#define MSRP_URL_TCP_PARAM ";tcp"
#define MSRP_URL_TCP_PARAM_LEN (sizeof(MSRP_URL_TCP_PARAM) - 1)

#define EXPIRES_HDR_S     "Expires: "
#define MIN_EXPIRES_HDR_S "Min-Expires: "
#define MAX_EXPIRES_HDR_S "Max-Expires: "
#define EXPIRES_HDR_LEN (sizeof(EXPIRES_HDR_S) - 1)
#define MIN_EXPIRES_HDR_LEN (sizeof(MIN_EXPIRES_HDR_S) - 1)
#define MAX_EXPIRES_HDR_LEN (sizeof(MAX_EXPIRES_HDR_S) - 1)

#define EXPIRES_STR "Expires"

#define OUT_OF_BOUNDS_STR "Interval Out-of-Bounds"

pv_spec_t user_spec;
pv_spec_t realm_spec;
pv_spec_t passwd_spec;

int auth_calc_ha1 = 0;

unsigned int nonce_expire = DEFAULT_NONCE_EXPIRE; /* Nonce lifetime */
unsigned int auth_expires = DEFAULT_AUTH_EXPIRES;
unsigned int auth_min_expires;
unsigned int auth_max_expires;

struct nonce_context *ncp = NULL;

str default_auth_realm;

int init_digest_auth(void)
{
	ncp = dauth_noncer_new();
	if (ncp == NULL) {
		LM_ERR("can't init nonce generator\n");
		return -1;
	}

	/* Generate secret using random generator */
	if (generate_random_secret(ncp) < 0) {
		LM_ERR("failed to generate random secret\n");
		return -1;
	}

	if (dauth_noncer_init(ncp) < 0) {
		LM_ERR("dauth_noncer_init() failed\n");
		return -1;
	}

	return 0;
}

int init_digest_auth_child(void)
{
	dauth_noncer_reseed();

	return 0;
}

void destroy_digest_auth(void)
{
	if (ncp == NULL)
		return;

	dauth_noncer_dtor(ncp);
}

static int generate_nonce(struct nonce_params *calc_np, char *buf)
{
	if (clock_gettime(CLOCK_REALTIME, &calc_np->expires) != 0) {
		LM_ERR("clock_gettime failed\n");
		return -1;
	}
	calc_np->expires.tv_sec += nonce_expire;
	calc_np->index = 0;
	calc_np->qop = QOP_AUTH_D;
	calc_np->alg = ALG_MD5;

	if (calc_nonce(ncp, buf, calc_np) != 0) {
		LM_ERR("calc_nonce failed\n");
		return -1;
	}

	return 0;
}

static int send_challenge(struct msrp_msg *req, str *realm, int stale)
{
	str auth_hdr_str;
	struct nonce_params calc_np;
	str opaque;

	opaque.len = ncp->nonce_len;
	opaque.s = pkg_malloc(opaque.len);
	if (!opaque.s) {
		LM_ERR("out of memory\n");
		return -1;
	}

	if (generate_nonce(&calc_np, opaque.s) < 0) {
		LM_ERR("Failed to generate opaque digest param\n");
		pkg_free(opaque.s);
		return -1;
	}

	auth_hdr_str.s = auth_api.build_auth_hf(ncp, &calc_np, stale,
		str2const(realm), &auth_hdr_str.len, NULL,
		&str_const_init(WWW_AUTH_HDR), str2const(&opaque));
	if (!auth_hdr_str.s) {
		LM_ERR("Failed to build WWW-Authenticate header\n");
		pkg_free(opaque.s);
		return -1;
	}
	/* send_reply() will add the CRLF itself */
	auth_hdr_str.len -= CRLF_LEN;

	pkg_free(opaque.s);

	if (msrp_api.send_reply(msrp_hdl, req, 401,
		&str_init(REASON_UNAUTHORIZED_STR), &auth_hdr_str, 1) < 0) {
		LM_ERR("Failed to send MSRP reply\n");
		goto error;
	}

	pkg_free(auth_hdr_str.s);

	LM_DBG("Challenged MSRP endpoint\n");
	return 0;
error:
	pkg_free(auth_hdr_str.s);
	return -1;
}

static str build_expires_hdr(char *hname, int hname_len, int expires)
{
	char *tmp;
	int l;
	str hdr = {NULL, 0};

	tmp = int2str(expires, &l);

	hdr.len = hname_len + l;
	hdr.s = pkg_malloc(hdr.len);
	if (!hdr.s) {
		LM_ERR("no more pkg memory\n");
		return hdr;
	}

	memcpy(hdr.s, hname, hname_len);
	memcpy(hdr.s + hname_len, tmp, l);

	return hdr;
}

static int run_msrp_auth_route(str *realm, str *user, pv_value_t *passwd_pval)
{
	pv_value_t pval;
	struct sip_msg *dummy_msg;

	/* prepare a fake/dummy request */
	dummy_msg = get_dummy_sip_msg();
	if(dummy_msg == NULL) {
		LM_ERR("cannot create new dummy sip request\n");
		return -1;
	}

	pval.flags = PV_VAL_STR;
	pval.rs = *user;
	if (pv_set_value(dummy_msg, &user_spec, 0, &pval) < 0) {
		LM_ERR("Failed to set user var\n");
		goto error;
	}

	pval.flags = PV_VAL_STR;
	pval.rs = *realm;
	if (pv_set_value(dummy_msg, &realm_spec, 0, &pval) < 0) {
		LM_ERR("Failed to set user var\n");
		goto error;
	}

	set_route_type(REQUEST_ROUTE);

	run_top_route(sroutes->request[auth_routeid], dummy_msg);

	if (pv_get_spec_value(dummy_msg, &passwd_spec, passwd_pval) < 0) {
		LM_ERR("Failed to get value from password var\n");
		release_dummy_sip_msg(dummy_msg);
		reset_avps();
		return -1;		
	}
	if (passwd_pval->flags & PV_VAL_NULL || !(passwd_pval->flags & PV_VAL_STR) ||
		passwd_pval->rs.len == 0) {
		LM_DBG("Empty value in password var\n");
		release_dummy_sip_msg(dummy_msg);
		reset_avps();
		return 1;
	}

	release_dummy_sip_msg(dummy_msg);
	reset_avps();

	return 0;
error:
	release_dummy_sip_msg(dummy_msg);
	return -1;
}

static int authorize(struct msrp_msg *req, str *realm, unsigned int *expires)
{
	int rc;
	int reply_code;
	dig_cred_t *cred;
	struct nonce_params np;
	HASHHEX ha1;
	const struct digest_auth_calc *digest_calc;
	str _;
	const str method = str_init(AUTH_STR);
	struct msrp_url *to;
	str tmp;
	str reply_hdr = {NULL, 0};
	str reason = {NULL, 0};
	pv_value_t passwd_pval;

	if (req->expires) {
		tmp = req->expires->body;
		trim(&tmp);
		if (str2int(&tmp, expires) < 0) {
			LM_ERR("Expires header body is not an integer\n");
			reply_code = 400;
			goto err_reply;
		}

		if (auth_min_expires > 0 && *expires < auth_min_expires) {
			LM_DBG("Received 'Expires' value not allowed\n");

			reply_hdr = build_expires_hdr(MIN_EXPIRES_HDR_S,
				MIN_EXPIRES_HDR_LEN, auth_min_expires);
			if (!reply_hdr.s) {
				reply_code = 403;
				reason = str_init(REASON_SERVER_ERROR_STR);
				goto err_reply;
			}

			reason = str_init(OUT_OF_BOUNDS_STR);
			reply_code = 423;
			goto err_reply;
		} else if (auth_max_expires > 0 && *expires > auth_max_expires) {
			LM_DBG("Received 'Expires' value not allowed\n");

			reply_hdr = build_expires_hdr(MAX_EXPIRES_HDR_S,
				MAX_EXPIRES_HDR_LEN, auth_max_expires);
			if (!reply_hdr.s) {
				reply_code = 403;
				reason = str_init(REASON_SERVER_ERROR_STR);
				goto err_reply;
			}

			reason = str_init(OUT_OF_BOUNDS_STR);
			reply_code = 423;
			goto err_reply;
		}
	} else {
		*expires = auth_expires;
	}

	if (parse_credentials(req->authorization) < 0) {
		LM_ERR("failed to parse credentials\n");
		reply_code = 400;
		reason = str_init(REASON_INVALID_CREDS_STR);
		goto err_reply;
	}
	cred = &((auth_body_t *)(req->authorization->parsed))->digest;

	/* the request-URI for H(A2) is the rightmost URI in To-Path */
	to = (struct msrp_url *)req->to_path->parsed;
	while (to->next)
		to = to->next;
	cred->uri = to->whole;

	rc = check_dig_cred(cred);
	if (rc != E_DIG_OK) {
		LM_ERR("received credentials are not filled properly, err=%d\n", rc);
		reply_code = 400;
		reason = str_init(REASON_INVALID_CREDS_STR);
		goto err_reply;
	}

	if (str_strcasecmp(&cred->realm, realm)) {
		LM_DBG("No credentials for given realm\n");
		reply_code = 400;
		reason = str_init(REASON_INVALID_CREDS_STR);
		goto err_reply;
	}

	if (decr_nonce(ncp, str2const(&cred->nonce), &np) != 0) {
		LM_ERR("failed to decrypt nonce (stale/invalid)\n");
		reply_code = 400;
		reason = str_init(REASON_BAD_NONCE_STR);
		goto err_reply;
	}
	alg_t ealg = (cred->alg.alg_parsed == ALG_UNSPEC) ? ALG_MD5 :
	    cred->alg.alg_parsed;
	if (np.alg != ealg) {
		LM_ERR("nonce does not match algorithm\n");
		reply_code = 400;
		reason = str_init(REASON_BAD_NONCE_STR);
		goto err_reply;
	}
	if (np.qop != QOP_AUTH_D) {
		LM_ERR("nonce does not match qop\n");
		reply_code = 400;
		reason = str_init(REASON_BAD_NONCE_STR);
		goto err_reply;
	}

	if (ealg != ALG_MD5) {
		LM_ERR("Unsupported algorithm\n");
		reply_code = 403;
		reason = str_init(REASON_UNSUPPORTED_ALG_STR);
		goto err_reply;
	}
	qop_type_t qop = cred->qop.qop_parsed;
	if (qop != QOP_AUTH_D) {
		LM_DBG("Unsupported qop type\n");
		reply_code = 403;
		reason = str_init(REASON_UNSUPPORTED_QOP_STR);
		goto err_reply;	
	}

	if (is_nonce_stale(&np, nonce_expire)) {
		LM_DBG("stale nonce value received\n");
		return STALE_NONCE;
	}

	rc = run_msrp_auth_route(realm, &cred->username.whole, &passwd_pval);
	if (rc < 0) {
		reply_code = 403;
		reason = str_init(REASON_SERVER_ERROR_STR);
		goto err_reply;	
	} else if (rc > 0) {
		reply_code = 403;
		reason = str_init(REASON_UNAUTHORIZED_STR);
		goto err_reply;	
	}

	if (auth_calc_ha1) {
		struct digest_auth_credential creds = {.realm = *realm,
			.user = cred->username.whole, .passwd = passwd_pval.rs};

		digest_calc = get_digest_calc(cred->alg.alg_parsed);
		if (digest_calc->HA1(&creds, &ha1) != 0) {
			LM_ERR("Failed to calc HA1\n");
			reply_code = 403;
			reason = str_init(REASON_SERVER_ERROR_STR);
			goto err_reply;
		}
	} else {
		if (passwd_pval.rs.len != HASHHEXLEN_MD5) {
			LM_ERR("Bad HA1 length in password variable\n");
			reply_code = 403;
			reason = str_init(REASON_UNAUTHORIZED_STR);
			goto err_reply;
		}

		memcpy(ha1._start, passwd_pval.rs.s, passwd_pval.rs.len);
		ha1._start[passwd_pval.rs.len] = '\0';
	}

	if (!auth_api.check_response(cred, &method, &_, &ha1)) {
		return AUTHORIZED;
	} else { 
		LM_DBG("Failed to check response\n");
		reply_code = 403;
		reason = str_init(REASON_UNAUTHORIZED_STR);
	}

err_reply:
	if (msrp_api.send_reply(msrp_hdl, req, reply_code, reason.s ? &reason:NULL,
		reply_hdr.s ? &reply_hdr:NULL, reply_hdr.s ? 1:0) < 0)
		LM_ERR("Failed to send MSRP reply\n");
	return ERROR;
}

static struct msrp_session *new_msrp_session(struct msrp_url *top_from,
	unsigned int expires)
{
	struct nonce_params _;
	unsigned int hentry;
	struct msrp_session *new;
	void **val;

	new = shm_malloc(sizeof *new + ncp->nonce_len + top_from->whole.len);
	if (!new) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}
	memset(new, 0, sizeof *new);

	new->session_id.s = (char*)(new + 1);
	new->session_id.len = ncp->nonce_len;	
	if (generate_nonce(&_, new->session_id.s) < 0) {
		LM_ERR("Failed to generate session-id\n");
		goto error;
	}

	new->top_from.s = (char*)(new + 1) + new->session_id.len;
	new->top_from.len = top_from->whole.len;
	memcpy(new->top_from.s, top_from->whole.s, top_from->whole.len);

	new->expires = expires + get_ticks();

	hentry = hash_entry(msrp_sessions, new->session_id);
	hash_lock(msrp_sessions, hentry);

	val = hash_get(msrp_sessions, hentry, new->session_id);
	if (!val) {
		hash_unlock(msrp_sessions, hentry);
		LM_ERR("Failed to allocate new hash entry\n");
		goto error;
	}

	if (*val != NULL) {
		hash_unlock(msrp_sessions, hentry);
		LM_ERR("Generated duplicate session-id\n");
		goto error;
	}
	*val = new;

	hash_unlock(msrp_sessions, hentry);

	LM_DBG("New MSRP session: %.*s\n",
		new->session_id.len, new->session_id.s);

	return new;
error:
	shm_free(new);
	return NULL;
}

static int send_auth_200ok(struct msrp_msg *req, str *session_id,
	str *use_path_host, int use_path_port, int secured, int expires)
{
	str hdrs[2] = {{.s = NULL}, {.s = NULL}};
	char *p, *tmp;
	int l;

	tmp = int2str(use_path_port, &l);

	hdrs[0].len = secured ? USE_PATH_SEC_HDR_LEN : USE_PATH_HDR_LEN +
		use_path_host->len + 1/*':'*/ + l/*port*/ + 1/*'/'*/ +
		session_id->len + MSRP_URL_TCP_PARAM_LEN;

	hdrs[0].s = pkg_malloc(hdrs[0].len);
	if (!hdrs[0].s) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}

	p = hdrs[0].s;
	memcpy(p, secured ? USE_PATH_SEC_HDR_S : USE_PATH_HDR_S,
		secured ? USE_PATH_SEC_HDR_LEN : USE_PATH_HDR_LEN);
	p += secured ? USE_PATH_SEC_HDR_LEN : USE_PATH_HDR_LEN;

	memcpy(p, use_path_host->s, use_path_host->len);
	p += use_path_host->len;
	*(p++) = ':';
	memcpy(p, tmp, l);
	p += l;

	*(p++) = '/';
	memcpy(p, session_id->s, session_id->len);
	p += session_id->len;

	memcpy(p, MSRP_URL_TCP_PARAM, MSRP_URL_TCP_PARAM_LEN);

	hdrs[1] = build_expires_hdr(EXPIRES_HDR_S, EXPIRES_HDR_LEN, expires);
	if (!hdrs[1].s)
		goto error;

	if (msrp_api.send_reply(msrp_hdl, req, 200, &str_init(REASON_OK_STR),
		hdrs, 2) < 0) {
		LM_ERR("Failed to send MSRP reply\n");
		goto error;
	}

	pkg_free(hdrs[0].s);
	pkg_free(hdrs[1].s);

	return 0;
error:
	if (hdrs[0].s)
		pkg_free(hdrs[0].s);
	if (hdrs[1].s)
		pkg_free(hdrs[1].s);

	return -1;
}

int handle_msrp_auth_req(struct msrp_msg *req, struct msrp_url *my_url)
{
	int ret;
	struct msrp_session *session;
	unsigned int expires;
	struct msrp_url *to = (struct msrp_url *)req->to_path->parsed;
	str *realm;

	if (default_auth_realm.s)
		realm = &default_auth_realm;
	else
		realm = &to->host;

	if (!req->authorization) {
		if (send_challenge(req, realm, 0) < 0) {
			LM_ERR("Failed to send challenge\n");
			return -1;
		}
	} else {
		ret = authorize(req, realm, &expires);
		switch (ret) {
		case AUTHORIZED:
			if (req->from_path->parsed == NULL) {
				req->from_path->parsed = parse_msrp_path(&req->from_path->body);
				if (req->from_path->parsed == NULL) {
					LM_ERR("Failed to parse From-Path\n");
					return -1;
				}
			}

			session = new_msrp_session(req->from_path->parsed, expires);
			if (!session) {
				LM_ERR("Failed to create new MSRP session\n");
				return -1;
			}

			if (send_auth_200ok(req, &session->session_id, &my_url->host,
				my_url->port_no, 0/* no TLS for now */, expires) < 0) {
				LM_ERR("Failed to send 200 OK\n");
				return -1;
			}

			LM_DBG("Authorized MSRP client\n");
			break;
		case STALE_NONCE:
			LM_DBG("Authorization failed\n");

			if (send_challenge(req, realm, 1) < 0) {
				LM_ERR("Failed to send re-challenge\n");
				return -1;
			}
			break;
		default:
			LM_DBG("Authorization failed\n");
		}
	}

	return 0;
}
