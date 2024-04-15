/*
 * AKA Authentication - AKA authentication support
 *
 * Copyright (C) 2024 Razvan Crainea
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/eventfd.h>

#include "../../sr_module.h"
#include "../../error.h"
#include "../../config.h"
#include "../../mod_fix.h"
#include "../../ipc.h"

#include "auth_aka.h"
#include "aka_av_mgm.h"
#include "../auth/api.h"
#include "../auth/qop.h"
#include "../auth/common.h"
#include "../auth/challenge.h"

#include "../../parser/digest/digest.h"
#include "../../parser/digest/digest_parser.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"


auth_api_t auth_api;

static int aka_www_authorize(struct sip_msg *msg, str *realm);
static int aka_proxy_authorize(struct sip_msg *msg, str *realm);
static int aka_www_challenge(struct sip_msg *msg, struct aka_av_mgm *mgm,
		str *realm, qop_type_t qop, intptr_t algmask);
static int aka_proxy_challenge(struct sip_msg *msg, struct aka_av_mgm *mgm,
		str *realm, qop_type_t qop, intptr_t algmask);
static int aka_www_challenge_async(struct sip_msg *msg, async_ctx *ctx,
		struct aka_av_mgm *mgm, str *realm, qop_type_t qop, intptr_t algmask);
static int aka_proxy_challenge_async(struct sip_msg *msg, async_ctx *ctx,
		struct aka_av_mgm *mgm, str *realm, qop_type_t qop, intptr_t algmask);
static int fixup_av_mgm(void** param);
static int fixup_aka_qop(void** param);
static int fixup_aka_alg(void** param);
static int fixup_check_var(void** param);

static int script_aka_av_add(struct sip_msg *msg, str *pub_id, str *priv_id,
		str *authenticate, str *authorize, str *ck, str *ik, intptr_t algmask);
static int script_aka_av_drop(struct sip_msg *msg, str *pub_id, str *priv_id,
		str *authenticate);
static int script_aka_av_drop_all(struct sip_msg *msg, str *pub_id, str *priv_id,
		pv_spec_t *count);
static int script_aka_av_fail(struct sip_msg *msg, str *pub_id, str *priv_id,
		int *count);
static mi_response_t *mi_aka_av_add(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_aka_av_drop(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_aka_av_drop_all(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_aka_av_fail(const mi_params_t *params,
								struct mi_handler *async_hdl);
int load_aka_av_api_bind(aka_av_api *api);

static int mod_init(void);         /* Module initialization function */

/*
 * Module parameter variables
 */
static str aka_default_av_mgm_s;
static str aka_default_qop_s = str_init("auth-int");
static str aka_default_alg_s = str_init("AKAv1-MD5");
static qop_type_t aka_default_qop = -1; /* XXX: use an invalid value */
static intptr_t aka_default_alg = ALGFLG_UNSPEC;
static intptr_t aka_algs_mask = ALGFLG_UNSPEC;
static int aka_hash_size = 4096;
static int aka_sync_timeout = 100; /* ms */
static int aka_async_timeout = 1000; /* ms */
static int aka_unused_timeout = 60; /* s */
static int aka_pending_timeout = 30; /* s */

/*
 * Exported functions
 */

static const cmd_export_t cmds[] = {
	{"aka_www_authorize", (cmd_function)aka_www_authorize, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},                               /* realm */
		{0,0,0}},
		REQUEST_ROUTE},
	{"aka_proxy_authorize", (cmd_function)aka_proxy_authorize, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},                               /* realm */
		{0,0,0}},
		REQUEST_ROUTE},
	{"aka_www_challenge", (cmd_function)aka_www_challenge, {
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_av_mgm, 0}, /* AV mgm */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},                               /* realm */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_qop, 0},/* qop */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_alg, 0},/* alg */
		{0,0,0}},
		REQUEST_ROUTE},
	{"aka_proxy_challenge", (cmd_function)aka_proxy_challenge, {
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_av_mgm, 0}, /* AV mgm */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},                               /* realm */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_qop, 0},/* qop */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_alg, 0},/* alg */
		{0,0,0}},
		REQUEST_ROUTE},
	{"aka_av_add", (cmd_function)script_aka_av_add, {
		{CMD_PARAM_STR, NULL, 0}, /* public_identity */
		{CMD_PARAM_STR, NULL, 0}, /* private_identity */
		{CMD_PARAM_STR, NULL, 0}, /* authenticate */
		{CMD_PARAM_STR, NULL, 0}, /* authorize */
		{CMD_PARAM_STR, NULL, 0}, /* ck */
		{CMD_PARAM_STR, NULL, 0}, /* ik */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_alg, 0},/* alg */
		{0,0,0}},
		ALL_ROUTES},
	{"aka_av_drop", (cmd_function)script_aka_av_drop, {
		{CMD_PARAM_STR, NULL, 0}, /* public_identity */
		{CMD_PARAM_STR, NULL, 0}, /* private_identity */
		{CMD_PARAM_STR, NULL, 0}, /* authenticate */
		{0,0,0}},
		ALL_ROUTES},
	{"aka_av_drop_all", (cmd_function)script_aka_av_drop_all, {
		{CMD_PARAM_STR, NULL, 0}, /* public_identity */
		{CMD_PARAM_STR, NULL, 0}, /* private_identity */
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_var, 0}, /* count */
		{0,0,0}},
		ALL_ROUTES},
	{"aka_av_fail", (cmd_function)script_aka_av_fail, {
		{CMD_PARAM_STR, NULL, 0}, /* public_identity */
		{CMD_PARAM_STR, NULL, 0}, /* private_identity */
		{CMD_PARAM_INT|CMD_PARAM_OPT, NULL, 0}, /* count */
		{0,0,0}},
		ALL_ROUTES},
	{"aka_av_api_bind", (cmd_function)load_aka_av_api_bind, {
		{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static const acmd_export_t acmds[] = {
	{"aka_www_challenge", (acmd_function)aka_www_challenge_async, {
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_av_mgm, 0}, /* AV mgm */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},                               /* realm */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_qop, 0},/* qop */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_alg, 0},/* alg */
		{0,0,0}}},
	{"aka_proxy_challenge", (acmd_function)aka_proxy_challenge_async, {
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_av_mgm, 0}, /* AV mgm */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},                               /* realm */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_qop, 0},/* qop */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL, fixup_aka_alg, 0},/* alg */
		{0,0,0}}},
	{0,0,{{0,0,0}}}
};

/*
 * Exported parameters
 */
static const param_export_t params[] = {
	{"default_av_mgm",    STR_PARAM, &aka_default_av_mgm_s.s },
	{"default_qop",       STR_PARAM, &aka_default_qop_s.s },
	{"default_algorithm", STR_PARAM, &aka_default_alg_s.s },
	{"hash_size",         INT_PARAM, &aka_hash_size },
	{"sync_timeout",      INT_PARAM, &aka_sync_timeout },
	{"async_timeout",      INT_PARAM, &aka_async_timeout },
	{0, 0, 0}
};

static const mi_export_t mi_cmds[] = {
	{ "aka_av_add", 0, 0, 0, {
		{mi_aka_av_add, {"public_identity", "private_identity", "authenticate",
							"authorize", "confidentiality-key", "integrity-key", 0}},
		{mi_aka_av_add, {"public_identity", "private_identity", "authenticate",
							"authorize", "confidentiality-key", "integrity-key",
							"algorithms", 0}},
		{EMPTY_MI_RECIPE}}},
	{ "aka_av_drop", 0, 0, 0, {
		{mi_aka_av_drop, {"public_identity", "private_identity",
							 "authenticate", 0}},
		{EMPTY_MI_RECIPE}}},
	{ "aka_av_drop_all", 0, 0, 0, {
		{mi_aka_av_drop_all, {"public_identity", "private_identity", 0}},
		{EMPTY_MI_RECIPE}}},
	{ "aka_av_fail", 0, 0, 0, {
		{mi_aka_av_fail, {"public_identity", "private_identity", 0}},
		{mi_aka_av_fail, {"public_identity", "private_identity",
							 "count", 0}},
		{EMPTY_MI_RECIPE}}},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "auth", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};


/*
 * Module interface
 */
struct module_exports exports = {
	"auth_aka",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,      /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	acmds,      /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* child initialization function */
	0           /* reload confirm function */
};


/*
 * Module initialization function
 */
static int mod_init(void)
{
	bind_auth_t bind_auth;

	LM_INFO("initializing...\n");
	
	if (aka_sync_timeout < 0) {
		LM_ERR("invalid sync_timeout value %d\n", aka_sync_timeout);
		return -1;
	}
	if (aka_async_timeout < 0) {
		LM_ERR("invalid async_timeout value %d\n", aka_async_timeout);
		return -1;
	}
	if (aka_unused_timeout < 0) {
		LM_ERR("invalid unused_timeout value %d\n", aka_unused_timeout);
		return -1;
	}
	if (aka_pending_timeout < 0) {
		LM_ERR("invalid pending_timeout value %d\n", aka_pending_timeout);
		return -1;
	}
	aka_async_timeout /= 1000; /* XXX: add support for milliseconds */

	if (aka_init_mgm(aka_hash_size) < 0) {
		LM_ERR("cannot initialize aka management hash\n");
		return -1;
	}

	bind_auth = (bind_auth_t)find_export("bind_auth", 0);
	if (!bind_auth) {
		LM_ERR("unable to find bind_auth function. Check if you "
			"loaded the auth module.\n");
		return -1;
	}

	if (bind_auth(&auth_api) < 0) {
		LM_ERR("cannot bind to auth module\n");
		return -4;
	}

	if (register_timer("AKA timeout", aka_async_expire, NULL, 1,
			TIMER_FLAG_SKIP_ON_DELAY)<0 ) {
		LM_ERR("failed to register timer, halting...");
		return -1;
	}


	return 0;
}

static int fixup_av_mgm(void** param)
{
	struct aka_av_mgm *av_mgm;
	str *aka_av_mgm_name = (str *)*param;

	if (!*param) {
		if (aka_default_av_mgm_s.s == NULL) {
			LM_ERR("no default AV manager provided\n");
			return -1;
		}
		aka_default_av_mgm_s.len = strlen(aka_default_av_mgm_s.s);
		aka_av_mgm_name = &aka_default_av_mgm_s;
	}
	av_mgm = aka_get_mgm(aka_av_mgm_name);
	if (!av_mgm) {
		av_mgm = aka_load_mgm(aka_av_mgm_name);
		if (!av_mgm) {
			LM_ERR("no AV manager for <%.*s>\n", aka_av_mgm_name->len, aka_av_mgm_name->s);
			return -1;
		}
	}
	*param = av_mgm;
	return 0;
}

static int fixup_aka_qop(void** param)
{
	if (*param == NULL) {
		if (aka_default_qop == -1) {
			aka_default_qop_s.len = strlen(aka_default_qop_s.s);
			*param = &aka_default_qop_s;
			if (fixup_qop(param) < 0) {
				LM_ERR("could not parse default_qop param [%s]\n", aka_default_qop_s.s);
				return -2;
			}
			aka_default_qop = (qop_type_t)(long)(*param);
		} else {
			*param = (void *)(long)aka_default_qop;
		}
		return 0;
	} else {
		return fixup_qop(param);
	}
}

static int fixup_aka_alg(void** param)
{
	alg_t alg;
	int algmask;
	str *dbg = (str *)*param;

	if (aka_algs_mask == ALGFLG_UNSPEC) {
		for (alg = ALG_AKAv1_FIRST; alg <= ALG_AKAv1_LAST; alg++)
			aka_algs_mask |= (1<<alg);
		for (alg = ALG_AKAv2_FIRST; alg <= ALG_AKAv2_LAST; alg++)
			aka_algs_mask |= (1<<alg);
	}

	if (*param == NULL) {
		dbg = &aka_default_alg_s;
		if (aka_default_alg == ALGFLG_UNSPEC) {
			aka_default_alg_s.len = strlen(aka_default_alg_s.s);
			*param = &aka_default_alg_s;
			if (dauth_fixup_algorithms(param) < 0) {
				LM_ERR("could not parse default_algorithm param [%s]\n", aka_default_alg_s.s);
				return -2;
			}
			aka_default_alg = *(intptr_t *)(param);
			if ((aka_default_alg | aka_algs_mask) != aka_algs_mask) {
				LM_WARN("non-AKA algorithms have been used in default algorithm "
						"0x%x/0x%x/%s\n", (int)aka_default_alg, (int)aka_algs_mask, dbg->s);
				return -2;
			}
			if (aka_default_alg == 0)
				LM_DBG("using unknown algorithm for authentication\n");
		} else {
			*param = (void *)(long)aka_default_alg;
		}
	} else if (dauth_fixup_algorithms(param) < 0) {
		LM_ERR("could not parse default_algorithm param [%s]\n", ((str *)*param)->s);
		return -2;
	}
	algmask = *(intptr_t *)(param);
	if ((algmask | aka_algs_mask) != aka_algs_mask) {
		LM_WARN("non-AKA algorithms have been used in 0x%x/%s; ignoring them...\n",
				algmask, dbg->s);
		algmask &= aka_algs_mask;
	}
	return 0;
}

static int fixup_check_var(void** param)
{
	if (!pv_is_w((pv_spec_t *)*param)) {
		LM_ERR("the return parameter must be a writable pseudo-variable\n");
		return E_SCRIPT;
	}

	return 0;
}

static struct to_body *aka_get_identity_body(struct sip_msg *msg, hdr_types_t hftype)
{
	switch (hftype) {
	case HDR_AUTHORIZATION_T:
		if (!msg->to && ((parse_headers(msg, HDR_TO_F, 0)==-1) || (!msg->to))) {
			LM_ERR("failed to parse TO headers\n");
			return NULL;
		}
		/* force parsing */
		if (!parse_to_uri(msg)) {
			LM_ERR("failed to parse TO URI\n");
			return NULL;
		}
		return get_to(msg);

	case HDR_PROXYAUTH_T:
		if (parse_from_header(msg) < 0) {
			LM_ERR("failed to parse From headers\n");
			return NULL;
		}
		/* force parsing */
		if (!parse_from_uri(msg)) {
			LM_ERR("failed to parse From URI\n");
			return NULL;
		}
		return get_from(msg);

	default:
		LM_ERR("Unhandld header type %d\n", hftype);
		return NULL;
	}
}

static inline void aka_strip_uri_params(struct to_body *body, str *res)
{
	char *p;
	*res = body->uri;
	/* limit the result to the end of the host/port, to skip parameters */
	if (body->parsed_uri.port.len)
		p = body->parsed_uri.port.s + body->parsed_uri.port.len;
	else
		p = body->parsed_uri.host.s + body->parsed_uri.host.len;
	res->len = p - res->s;
}

static str *aka_get_public_identity(struct sip_msg *msg, hdr_types_t hftype)
{
	static str res;
	struct to_body *body = aka_get_identity_body(msg, hftype);
	if (!body)
		return NULL;
	aka_strip_uri_params(body, &res);
	return &res;
}

static str *aka_get_private_identity(struct sip_msg *msg, auth_body_t *auth, hdr_types_t hftype)
{
	int len;
	static str res;
	struct to_body *body;

	if (auth)
		return &auth->digest.username.whole;

	body = aka_get_identity_body(msg, hftype);
	if (!body)
		return NULL;

	aka_strip_uri_params(body, &res);

	if (body->parsed_uri.type != ERROR_URI_T) {
		len = uri_typestrlen(body->parsed_uri.type);
		res.s += len + 1;
		res.len -= len + 1;
	}

	return &res;
}

/* according to ETSI TS 129 229 V17.2.0 (2022-07), the buffer is 30 bytes long */
#define AKA_RAND_LEN 16
#define AKA_AUTS_LEN 14
#define AKA_AUTHORIZATION_LEN (AKA_RAND_LEN + AKA_AUTS_LEN)

static int aka_build_resync(str *nonce, str* auts, str *resync)
{
	unsigned char auth_buf[AKA_AUTHORIZATION_LEN];
	int len;

	/* check what we have */
	if (calc_base64_encode_len(AKA_RAND_LEN) > nonce->len) {
		LM_ERR("invalid RAND length - have %d, need %d\n",
				nonce->len, calc_base64_encode_len(AKA_RAND_LEN));
		return -1;
	}
	if (calc_base64_encode_len(AKA_AUTS_LEN) != auts->len) {
		if (calc_base64_encode_len(AKA_AUTS_LEN) > auts->len) {
			LM_ERR("invalid AUTS length - have %d, need %d\n",
					auts->len, calc_base64_encode_len(AKA_AUTS_LEN));
			return -1;
		} else {
			LM_WARN("AUTS length too long - have %d, need %d; dropping the tail\n",
					auts->len, calc_base64_encode_len(AKA_AUTS_LEN));
		}
	}
	len = base64decode(auth_buf, (unsigned char *)nonce->s, calc_max_base64_decode_len(AKA_AUTHORIZATION_LEN));
	if (len < AKA_RAND_LEN) {
		LM_ERR("not enough bytes for RAND - have %d, need %d\n", len, AKA_RAND_LEN);
		return -1;
	}
	len = base64decode(auth_buf + AKA_RAND_LEN, (unsigned char *)auts->s, auts->len);
	if (len + AKA_RAND_LEN != AKA_AUTHORIZATION_LEN) {
		LM_ERR("mismatch bytes for RAND + AUTS - have %d, need %d\n", len, AKA_AUTHORIZATION_LEN);
		return -1;
	}
	resync->s = (char *)auth_buf;
	resync->len = AKA_AUTHORIZATION_LEN;
	return 0;
}

static int aka_challenge_pre(struct sip_msg *_msg, str *realm, int _code,
		hdr_types_t *hftype, struct hdr_field **h, struct aka_user **user,
		str *sync, int *sync_count)
{
	dig_err_t ret;
	dig_cred_t *cred;
	auth_body_t* auth = NULL;
	auth_result_t auth_res = AUTH_ERROR;
	str *public_id, *private_id, *auts = NULL, *nonce = NULL;
	*user = NULL;

	sync->len = 0;
	*sync_count = 0;

	switch(_code) {
	case WWW_AUTH_CODE:
		*hftype = HDR_AUTHORIZATION_T;
		break;
	case PROXY_AUTH_CODE:
		*hftype = HDR_PROXYAUTH_T;
		break;
	default:
		LM_BUG("unknown code %d\n", _code);
		return -1;
	}

	auth_res = auth_api.pre_auth(_msg, realm, *hftype, h, AUTH_SKIP_CRED_CHECK);
	if (auth_res != DO_AUTHORIZATION && auth_res != NO_CREDENTIALS)
		return auth_res;

	if (auth_res != NO_CREDENTIALS) {
		auth = (auth_body_t*)(*h)->parsed;
		cred = &auth->digest;
		/* check the correct format, according to 3GPP TS 24.229, 5.1.1.2.2:
		 * - the "username" header field parameter, set to the value of the
		 *   private user identity;
		 * - the "realm" header field parameter, set to the domain name of
		 *   the home network;
		 * - the "uri" header field parameter, set to the SIP URI of the
		 *   domain name of the home network;
		 * - the "nonce" header field parameter, set to an empty value; and
		 * - the "response" header field parameter, set to an empty value;
		 */
		ret = check_dig_cred(cred);
		if (ret & E_DIG_USERNAME) {
			LM_ERR("no username in credentials\n");
			return -1;
		}
		if (ret & E_DIG_REALM) {
			LM_ERR("no realm in credentials\n");
			return -1;
		}
		if (ret & E_DIG_URI) {
			LM_ERR("no uri in credentials\n");
			return -1;
		}
		if (cred->auts.len) {
			/* if we have an auts, we need a nonce */
			if (ret & E_DIG_NONCE) {
				LM_ERR("\"auts\" parameter without a \"nonce\"\n");
				return -1;
			}
			auts = &cred->auts;
			nonce = &cred->nonce;
		}

		if (mark_authorized_cred(_msg, *h) < 0) {
			LM_ERR("could not mark credentials\n");
			return -1;
		}
	}

	public_id = aka_get_public_identity(_msg, *hftype);
	if (!public_id) {
		LM_ERR("could not get public identity/IMPU\n");
		return -1;
	}

	private_id = aka_get_private_identity(_msg, auth, *hftype);
	if (!private_id) {
		LM_ERR("could not get private identity/IMPI\n");
		return -1;
	}
	LM_DBG("challenging realm=[%.*s] impu=[%.*s] impi=[%.*s]\n",
			realm->len, realm->s, public_id->len, public_id->s,
			private_id->len, private_id->s);
	*user = aka_user_get(public_id, private_id);
	if (*user == NULL) {
		LM_ERR("could not get AKA user %.*s/%.*s\n", public_id->len, public_id->s,
				private_id->len, private_id->s);
		return -1;
	}
	if (auts && nonce) {
		/* drop all vectors */
		*sync_count = aka_av_drop_all_user(*user);
		if (aka_build_resync(nonce, auts, sync) < 0) {
			LM_ERR("could not build resync!\n");
			aka_user_release(*user);
			return -1;
		}
	}

	return 0;
}

static int aka_count_avs(int algmask)
{
	int alg, n = 0;
	for (alg = ALG_AKAv1_FIRST; alg <= ALG_AKAv1_LAST; alg++)
		if (algmask & ALG2ALGFLG(alg))
			n++;
	for (alg = ALG_AKAv2_FIRST; alg <= ALG_AKAv2_LAST; alg++)
		if (algmask & ALG2ALGFLG(alg))
			n++;
	return n;
}

#define AKA_DIGEST_REALM	  ": Digest realm=\""
#define AKA_DIGEST_NONCE	  "\", nonce=\""
#define AKA_DIGEST_ALGORITHM  "\", algorithm="
#define AKA_DIGEST_CK  ", ck=\""
#define AKA_DIGEST_IK  "\", ik=\""
#define AKA_DIGEST_END  "\""
#define CSL(_c) (sizeof(_c) - 1)

static char *build_aka_auth_hf(struct aka_av *av, str *_realm,
		qop_type_t qop, alg_t alg, const str_const *_hf_name, int *_len)
{
	char *hf, *p;
	str_const qop_param = get_qop_param(qop);
	const str *alg_val = print_digest_algorithm(alg);

	LM_DBG("Challenging with av %p\n", av);
	*_len =_hf_name->len +
		CSL(AKA_DIGEST_REALM) +
		_realm->len +
		CSL(AKA_DIGEST_NONCE) +
		av->authenticate.len +
		CSL(AKA_DIGEST_ALGORITHM) +
		alg_val->len +
		CSL(AKA_DIGEST_CK) +
		av->ck.len +
		CSL(AKA_DIGEST_IK) +
		av->ik.len +
		qop_param.len +
		CRLF_LEN + 1;


	p = hf = pkg_malloc(*_len + 1);
	if (!hf) {
		LM_ERR("cannot allocate aka auth buffer\n");
		goto e1;
	}
	memcpy(p, _hf_name->s, _hf_name->len);
	p += _hf_name->len;
	memcpy(p, AKA_DIGEST_REALM, CSL(AKA_DIGEST_REALM));
	p+=CSL(AKA_DIGEST_REALM);
	memcpy(p, _realm->s, _realm->len);
	p += _realm->len;
	memcpy(p, AKA_DIGEST_NONCE, CSL(AKA_DIGEST_NONCE));
	p += CSL(AKA_DIGEST_NONCE);
	memcpy(p, av->authenticate.s, av->authenticate.len);
	p += av->authenticate.len;
	memcpy(p, AKA_DIGEST_ALGORITHM, CSL(AKA_DIGEST_ALGORITHM));
	p += CSL(AKA_DIGEST_ALGORITHM);
	memcpy(p, alg_val->s, alg_val->len);
	p += alg_val->len;
	memcpy(p, AKA_DIGEST_CK, CSL(AKA_DIGEST_CK));
	p += CSL(AKA_DIGEST_CK);
	memcpy(p, av->ck.s, av->ck.len);
	p += av->ck.len;
	memcpy(p, AKA_DIGEST_IK, CSL(AKA_DIGEST_IK));
	p += CSL(AKA_DIGEST_IK);
	memcpy(p, av->ik.s, av->ik.len);
	p += av->ik.len;
	memcpy(p, AKA_DIGEST_END, CSL(AKA_DIGEST_END));
	p += CSL(AKA_DIGEST_END);
	if (qop_param.len) {
		memcpy(p, qop_param.s, qop_param.len);
		p += qop_param.len;
	}

	memcpy(p, CRLF, CRLF_LEN ); p+=CRLF_LEN;
	*p=0; /* zero terminator, just in case */

	LM_DBG("'%s'\n", hf);
	return hf;
e1:
	*_len = 0;
	return NULL;
}

#undef AKA_DIGEST_REALM
#undef AKA_DIGEST_NONCE
#undef AKA_DIGEST_ALGORITHM
#undef AKA_DIGEST_CK
#undef AKA_DIGEST_IK
#undef AKA_DIGEST_END
#undef CSL

static int aka_send_resp(struct sip_msg *_msg, str *realm, struct aka_user *user,
		struct aka_av **avs, int count, qop_type_t qop,
		int _code, const str_const *_challenge_msg)
{
	int ret = -1;
	int nalgs, c;
	str auth_hfs[LAST_ALG_SPTD - FIRST_ALG_SPTD + 1];

	for (nalgs = 0; nalgs < count; nalgs++) {
		auth_hfs[nalgs].s = build_aka_auth_hf(avs[nalgs], realm, qop,
				avs[nalgs]->alg, _challenge_msg, &auth_hfs[nalgs].len);
		if (!auth_hfs[nalgs].s) {
			LM_ERR("could not build authentication vector!\n");
			goto reply;
		}
	}

reply:
	if (nalgs > 0) {
		ret = nalgs; /* number of successful AVs/headers */
		/* release unused AVs */
		for (c = nalgs; c < count; c++)
			aka_av_set_new(user, avs[c]);
	} else {
		ret = -3;
	}
	if (auth_api.send_resp(_msg, _code, NULL, auth_hfs, nalgs) < 0)
		ret = -5;
	while (--nalgs > 0)
		pkg_free(auth_hfs[nalgs].s);
	return ret;
}

static inline int aka_avs_new_wait(struct aka_user *user, int *algmask,
		struct aka_av **avs, int count)
{
	int c, err = 0;
	for (c = 0; c < count - err;) {
		switch (aka_av_get_new_wait(user, *algmask, aka_sync_timeout, &avs[c])) {
			case -1: /* error */
			case  0: /* no AV found within the expected time */
				err++;
				break;
			case  1: /* a proper AV was found */
				*algmask &= ~ALG2ALGFLG(avs[c]->alg);
				c++;
				break;
		}
	}
	LM_DBG("got %d AVs out of %d (%d errors)\n", c, count, err);
	return c;
}


static inline int aka_avs_get_new(struct aka_user *user, int *algmask,
		struct aka_av **avs, int count, int *err_count)
{
	int c;
	*err_count = 0;
	for (c = 0; c < count - *err_count;) {
		switch (aka_av_get_new(user, *algmask, &avs[c])) {
			case -1: /* error */
				c--;
				(*err_count)++;
				break;
			case  0: /* no AV found within the expected time */
				goto end;
			case  1: /* a proper AV was found */
				*algmask &= ~ALG2ALGFLG(avs[c]->alg);
				c++;
				break;
		}
	}
end:
	LM_DBG("got %d AVs out of %d (%d error)\n", c, count, *err_count);
	return c;
}

static int aka_challenge(struct sip_msg *_msg, struct aka_av_mgm *mgm, str *_realm,
		qop_type_t qop, int algmask, int _code, const str_const *_challenge_msg)
{
	int ret = AUTH_ERROR;
	str realm, auts;
	hdr_types_t hftype;
	struct hdr_field *h;
	struct aka_user *user;
	struct aka_av *av, **avs;
	int count = aka_count_avs(algmask), new_count;
	int sync_count, err_count;

	realm = (_realm?*_realm:str_init(""));
	if (count > 1) {
		avs = pkg_malloc(count * sizeof *av);
		if (!avs) {
			LM_ERR("could not allocate %d AVs\n", count);
			return -1;
		}
	} else {
		avs = &av;
	}

	if (aka_challenge_pre(_msg, &realm, _code, &hftype, &h, &user, &auts, &sync_count) < 0) {
		LM_ERR("cannot prepare challenge from message\n");
		goto end;
	}
	count += sync_count;
	/* try to fetch as many local AVs as possible */
	new_count = aka_avs_get_new(user, &algmask, avs, count, &err_count);

	/* if we need more, fetch them remotely */
	if (new_count + err_count != count) {
		if (mgm->binds.fetch(&realm, &user->impu, &user->impi->impi,
				(auts.len?&auts:NULL), algmask, 1, 0) != 0) {
			LM_INFO("Could not fetch %d authentication vector(s)!\n", count);
			ret = -2;
			goto release;
		}
		new_count += aka_avs_new_wait(user, &algmask, avs + new_count, count - new_count - err_count);
		if (new_count < count)
			LM_WARN("Could not get get %d (out of %d) authentication vectors!\n",
					count - new_count, count);
	}

	ret = aka_send_resp(_msg, &realm, user, avs, new_count, qop,
			_code, _challenge_msg);

release:
	aka_user_release(user);
end:
	if (count > 1)
		pkg_free(avs);
	return ret;
}

static inline int aka_get_ha1(dig_cred_t* digest, str* realm,
    struct aka_av *av, HASHHEX* _ha1)
{
	struct calc_HA1_arg cprms = {
		.alg = digest->alg.alg_parsed
	};
	struct digest_auth_credential ocreds = {
		.realm = *realm,
		.user = digest->username.whole,
		.passwd = av->authorize
	};
	cprms.creds.open = &ocreds;
	cprms.use_hashed = 0;
	cprms.nonce = &digest->nonce;
	cprms.cnonce = &digest->cnonce;
	if (auth_api.calc_HA1(&cprms, _ha1) != 0)
		return (-1);
	LM_DBG("HA1 string calculated: %s\n", _ha1->_start);

	return 0;
}

static int aka_authorize(struct sip_msg *_msg, str *_realm,
		int _code, const str_const *_challenge_msg)
{
	int ret;
	str msg_body;
	struct hdr_field *h;
	struct aka_av *av;
	struct aka_user *user;
	dig_cred_t *digest;
	hdr_types_t hftype;
	auth_body_t* auth = NULL;
	auth_result_t auth_res = AUTH_ERROR;
	str *public_id, *private_id;
	str realm = (_realm?*_realm:str_init(""));
	HASHHEX ha1;

	switch(_code) {
	case WWW_AUTH_CODE:
		hftype = HDR_AUTHORIZATION_T;
		break;
	case PROXY_AUTH_CODE:
		hftype = HDR_PROXYAUTH_T;
		break;
	default:
		LM_BUG("unknown code %d\n", _code);
		return -1;
	}

	auth_res = auth_api.pre_auth(_msg, &realm, hftype, &h, AUTH_SKIP_NONCE_CHECK);
	if (auth_res != DO_AUTHORIZATION)
		return auth_res;

	public_id = aka_get_public_identity(_msg, hftype);
	if (!public_id) {
		LM_ERR("could not get public identity/IMPU\n");
		return AUTH_ERROR;
	}

	private_id = aka_get_private_identity(_msg, auth, hftype);
	if (!private_id) {
		LM_ERR("could not get private identity/IMPI\n");
		return AUTH_ERROR;
	}
	auth = (auth_body_t*)h->parsed;
	digest = &auth->digest;
	LM_DBG("authorizing realm=[%.*s] impu=[%.*s] impi=[%.*s]\n",
			realm.len, realm.s, public_id->len, public_id->s,
			private_id->len, private_id->s);
	user = aka_user_find(public_id, private_id);
	if (user == NULL) {
		if (digest->nonce.len)
			LM_ERR("could not get AKA user %.*s/%.*s with nonce %.*s\n",
					public_id->len, public_id->s, private_id->len, private_id->s,
					digest->nonce.len, digest->nonce.s);
		else
			LM_DBG("could not get AKA user %.*s/%.*s\n", public_id->len, public_id->s,
					private_id->len, private_id->s);
		return STALE_NONCE;
	}
	av = aka_av_get_nonce(user, ALG2ALGFLG(digest->alg.alg_parsed), &digest->nonce);
	if (!av) {
		LM_ERR("could not find AKA AV for user %.*s/%.*s with nonce %.*s\n",
				public_id->len, public_id->s, private_id->len, private_id->s,
				digest->nonce.len, digest->nonce.s);
		ret = STALE_NONCE;
		goto release;
	}

	/* now that we are trusting the user, check whether it has an auts
	 * parameter - if it does, we need to re-challenge him */
	if (digest->auts.len) {
		LM_DBG("re-sync request for for user %.*s/%.*s with nonce %.*s\n",
				public_id->len, public_id->s, private_id->len, private_id->s,
				digest->nonce.len, digest->nonce.s);
		ret = -6;
		goto release;
	}

	ret = AUTH_ERROR;
	if (digest->qop.qop_parsed == QOP_AUTHINT_D &&
		get_body(_msg, &msg_body) < 0) {
		LM_ERR("Failed to get body of SIP message\n");
		goto release;
	}
	if (aka_get_ha1(digest, &realm, av, &ha1) < 0) {
		LM_ERR("Failed to compute HA1\n");
		goto release;
	}

	if (!auth_api.check_response(digest,
			&_msg->first_line.u.request.method, &msg_body, &ha1))
		ret = auth_api.post_auth(_msg, h);
	else
		ret = INVALID_PASSWORD;

release:
	aka_user_release(user);
	return ret;
}

struct aka_async_param {
	int replied;
	int ref;
	str realm;
	qop_type_t qop;
	int algmask;
	int code;
	str challenge_msg;
	struct aka_user *user;
	struct aka_av **avs;
	int avs_count, avs_fetched, avs_error;
	int process_no;
	unsigned int ticks;
	struct list_head list;
	async_ctx *async;
	char buf[0];
};

static inline void aka_async_param_remove(struct aka_async_param *param)
{
	if (list_is_valid(&param->list))
		aka_pop_async(param->user, &param->list);
}

static int aka_async_param_unref(struct aka_async_param *param)
{
	param->ref--;
	if (param->ref == 0) {
		/* the last user should also delete */
		aka_user_release(param->user);
		shm_free(param);
		return 1;
	} else {
		return 0;
	}
}

static int aka_challenge_async_resume_handle(struct sip_msg *msg, void *_param, int timeout)
{
	int left, err_count;
	struct aka_async_param *param = _param;

	/* if this handling has already been completed, drop it */
	if (param->avs_fetched + param->avs_error >= param->avs_count) {
		left = 0;
		goto end;
	}

	/* check to see how many events we got */
	param->avs_fetched += aka_avs_get_new(param->user, &param->algmask,
			param->avs + param->avs_fetched, param->avs_count - param->avs_fetched, &err_count);
	param->avs_error += err_count;
	left = param->avs_count - param->avs_fetched - param->avs_error;
	/* check to see if we still have AVS to wait for */
	if (!timeout && (param->avs_fetched + param->avs_error) != param->avs_count) {
		LM_DBG("waiting for more %d AVs to a total of %d (%d errors)\n",
				left, param->avs_count, param->avs_error);
		goto end;
	}
	if (timeout && left)
		LM_ERR("timeout waiting for AVs - got %d out of %d so far (%d error)\n",
				param->avs_fetched, param->avs_count, param->avs_error);
	else
		LM_DBG("fetched all %d out of %d AVs (%d error)\n",
				param->avs_fetched, param->avs_count, param->avs_error);
	async_status = ASYNC_DONE_NO_IO;
	if (!param->replied) {
		if (param->avs_fetched) {
			/* now send whatever we have fetched so far */
			aka_send_resp(msg, &param->realm, param->user, param->avs, param->avs_fetched,
					param->qop, param->code, _cs2cc(&param->challenge_msg));
		} else if (param->avs_error) {
			if (auth_api.send_resp(msg, 500, NULL, NULL, 0) < 0)
				LM_ERR("could not send error back\n");
		} else if (auth_api.send_resp(msg, 504, NULL, NULL, 0) < 0) {
			LM_ERR("could not send timeout back\n");
		}
		param->replied = 1;
	}
	aka_async_param_remove(param);
	aka_async_param_unref(param); /* finish everything */
end:
	if (!aka_async_param_unref(param)) {
		/* we still have some possible signals in the queue, so let's wait for
		 * everyone before releasing the context */
		async_status = ASYNC_CONTINUE;
	}
	return left;
}

static int aka_challenge_async_resume(int fd,
		struct sip_msg *msg, void *_param)
{
	return aka_challenge_async_resume_handle(msg, _param, 0);
}

static int aka_challenge_async_resume_tout(int fd,
		struct sip_msg *msg, void *_param)
{
	return aka_challenge_async_resume_handle(msg, _param, 1);
}

static int aka_challenge_async(struct sip_msg *_msg, async_ctx *ctx,
		struct aka_av_mgm *mgm, str *_realm, qop_type_t qop,
		int algmask, int _code, const str_const *_challenge_msg)
{
	hdr_types_t hftype;
	struct hdr_field *h;
	str realm, sync;
	struct aka_user *user;
	struct aka_av *av, **avs;
	int count = aka_count_avs(algmask);
	struct aka_async_param *param = NULL;
	int ret = AUTH_ERROR, c;
	char *p;
	int sync_count, err_count;

	realm = (_realm?*_realm:str_init(""));

	if (aka_challenge_pre(_msg, &realm, _code, &hftype, &h, &user, &sync, &sync_count) < 0) {
		LM_ERR("cannot prepare challenge from message\n");
		return -1;
	}
	count += sync_count;
	/* try to sort them out synchronously */
	if (count == 1) {
		avs = &av;
		if (aka_avs_get_new(user, &algmask, &av, 1, &err_count) == 1)
			goto synchronous;
		if (err_count)
			goto error;
	}
	/* unfortunately we might need to do it asynchronously */
	param = shm_malloc(sizeof *param + realm.len + _challenge_msg->len +
			count * sizeof *av);
	if (!param) {
		LM_ERR("oom for preparing async params!\n");
		goto release;
	}
	memset(param, 0, sizeof *param);
	p = param->buf;
	param->realm.s = p;
	p += realm.len;
	param->challenge_msg.s = p;
	p += _challenge_msg->len;
	param->avs = (struct aka_av **)p;
	avs = param->avs;
	/* do not prepare the param yet, as we might still have AVs available */

	c = aka_avs_get_new(user, &algmask, avs, count, &err_count);
	if (c + err_count == count)
		goto synchronous;
	LM_DBG("we still need %d out of %d AVs\n", count - c, count);

	/* now that we finished preparing, go fetch the vectors */
	if (mgm->binds.fetch(&realm, &user->impu, &user->impi->impi,
			 (sync.len?&sync:NULL), algmask, 1, 1) != 0) {
		LM_INFO("Could not fetch %d authentication vector(s)!\n", count);
		ret = -2;
		goto error;
	}

	/* now prepare all parameters */
	memcpy(param->realm.s, realm.s, realm.len);
	param->realm.len = realm.len;
	memcpy(param->challenge_msg.s, _challenge_msg->s, _challenge_msg->len);
	param->challenge_msg.len = _challenge_msg->len;
	param->ref = 1;
	param->qop = qop;
	param->algmask = algmask;
	param->code = _code;
	param->user = user;
	param->avs_count = count;
	param->avs_fetched = c;
	param->async = ctx;
	param->process_no = process_no;
	param->ticks = get_ticks();

	async_status = ASYNC_NO_FD;

	ctx->resume_f = aka_challenge_async_resume;
	ctx->resume_param = param;
	ctx->timeout_f = aka_challenge_async_resume_tout;
	ctx->timeout_s = aka_async_timeout;

	aka_push_async(user, &param->list);
	return 1;

synchronous:
	async_status = ASYNC_NO_IO;
	ret = aka_send_resp(_msg, &realm, user, avs, count, qop,
			_code, _challenge_msg);
error:
	if (param)
		shm_free(param);
release:
	aka_user_release(user);
	return ret;
}

static void aka_challenge_resume(int fd, void *_param)
{
	struct aka_async_param *param = (struct aka_async_param *)_param;
	async_script_resume_f(ASYNC_FD_NONE, param->async, 0);
}

static void aka_challenge_resume_tout(int fd, void *_param)
{
	struct aka_async_param *param = (struct aka_async_param *)_param;
	async_script_resume_f(ASYNC_FD_NONE, param->async, 1);
}

static void aka_signal_async_resume(struct aka_async_param *param, ipc_rpc_f *func)
{
	param->ref++;
	if (ipc_send_rpc(param->process_no, func, param) < 0) {
		LM_ERR("could not resume aka challenge\n");
		aka_async_param_remove(param);
		aka_async_param_unref(param);
	}
}

void aka_signal_async(struct aka_user *user, struct  list_head *subs)
{
	struct aka_async_param *param = list_entry(subs, struct aka_async_param, list);
	aka_signal_async_resume(param, aka_challenge_resume);
}

void aka_check_expire_async(unsigned int ticks, struct list_head *subs)
{
	struct aka_async_param *param = list_entry(subs, struct aka_async_param, list);
	if (param->ticks + aka_async_timeout > ticks)
		return;
	/* this subscription expired - should drop it */
	aka_pop_unsafe_async(param->user, subs);
	aka_signal_async_resume(param, aka_challenge_resume_tout);
}

void aka_check_expire_av(unsigned int ticks, struct aka_av *av)
{
	int timeout;
	switch (av->state) {
		case AKA_AV_NEW:
			timeout = aka_unused_timeout;
			break;
		case AKA_AV_INVALID: /* for invalid, drop it asap */
			timeout = 0;
			av->ts = ticks;
			break;
		case AKA_AV_USING:
		case AKA_AV_USED:
			timeout = aka_pending_timeout;
			break;
		default:
			return;
	}
	if (av->ts + timeout > ticks)
		return;
	LM_DBG("removing av %p in state %d after %ds now %ds\n",
			av, av->state, timeout, ticks);
	aka_av_free(av);
}


static int aka_www_challenge(struct sip_msg *msg, struct aka_av_mgm *mgm,
		str *realm, qop_type_t qop, intptr_t algmask)
{
	return aka_challenge(msg, mgm, realm, qop, algmask,
			WWW_AUTH_CODE, &str_const_init(WWW_AUTH_HDR));
}

static int aka_proxy_challenge(struct sip_msg *msg, struct aka_av_mgm *mgm,
		str *realm, qop_type_t qop, intptr_t algmask)
{
	return aka_challenge(msg, mgm, realm, qop, algmask,
			PROXY_AUTH_CODE, &str_const_init(PROXY_AUTH_HDR));
}

static int aka_www_challenge_async(struct sip_msg *msg, async_ctx *ctx,
		struct aka_av_mgm *mgm, str *realm, qop_type_t qop, intptr_t algmask)
{
	return aka_challenge_async(msg, ctx, mgm, realm, qop, algmask,
			WWW_AUTH_CODE, &str_const_init(WWW_AUTH_HDR));
}

static int aka_proxy_challenge_async(struct sip_msg *msg, async_ctx *ctx,
		struct aka_av_mgm *mgm, str *realm, qop_type_t qop, intptr_t algmask)
{
	return aka_challenge_async(msg, ctx, mgm, realm, qop, algmask,
			PROXY_AUTH_CODE, &str_const_init(PROXY_AUTH_HDR));
}

static int aka_www_authorize(struct sip_msg *msg, str *realm)
{
	return aka_authorize(msg, realm, WWW_AUTH_CODE, &str_const_init(WWW_AUTH_HDR));
}

static int aka_proxy_authorize(struct sip_msg *msg, str *realm)
{
	return aka_authorize(msg, realm, PROXY_AUTH_CODE, &str_const_init(PROXY_AUTH_HDR));
}


static int script_aka_av_add(struct sip_msg *msg, str *pub_id, str *priv_id,
		str *authenticate, str *authorize, str *ck, str *ik, intptr_t algmask)
{
	return aka_av_add(pub_id, priv_id, algmask, authenticate, authorize, ck, ik);
}

static int script_aka_av_drop(struct sip_msg *msg, str *pub_id, str *priv_id, str *auth)
{
	return (aka_av_drop(pub_id, priv_id, auth) < 0?-1:1);
}

static int script_aka_av_drop_all(struct sip_msg *msg, str *pub_id, str *priv_id, pv_spec_t *count)
{
	pv_value_t val;
	int ret = aka_av_drop_all(pub_id, priv_id);
	if (count) {
		memset(&val, 0, sizeof val);
		val.flags = PV_TYPE_INT|PV_VAL_INT;
		val.ri = ret;
		if (str2int(&val.rs, (unsigned int *)&val.ri) == 0)
			val.flags |= PV_VAL_STR;
		return pv_set_value(msg, count, 0, &val)<0?-1:1;
	}
	return 1;
}

static int script_aka_av_fail(struct sip_msg *msg, str *pub_id, str *priv_id,
		int *count)
{
	return aka_av_fail(pub_id, priv_id, (count?*count:1));
}

static mi_response_t *mi_aka_av_add(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str public_identity, private_identity, algorithms, authenticate, authorize, ck, ik;
	int algmask;
	void *param = NULL;

	if (get_mi_string_param(params, "public_identity",
			&public_identity.s, &public_identity.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "private_identity",
			&private_identity.s, &private_identity.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "authenticate",
			&authenticate.s, &authenticate.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "authorize",
			&authorize.s, &authorize.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "confidentiality-key", &ck.s, &ck.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "integrity-key", &ik.s, &ik.len) < 0)
		return init_mi_param_error();
	switch (try_get_mi_string_param(params, "algorithms",
				&algorithms.s, &algorithms.len)) {
		case 0:
			param = &algorithms;
			/* fallthrough */
		case -1:
			if (fixup_aka_alg(&param) < 0)
				return init_mi_error(400, MI_SSTR("could not parse algorithms"));
			algmask = (intptr_t)param;
			break;
		default:
			return init_mi_error(400, MI_SSTR("error while fetching algorithms"));
	}
	if (aka_av_add(&public_identity, &private_identity, algmask, &authenticate,
			&authorize, &ck, &ik) < 0)
		return init_mi_error(400, MI_SSTR("could not add AV"));
	return init_mi_result_ok();
}

static mi_response_t *mi_aka_av_drop(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str public_identity, private_identity, authenticate;

	if (get_mi_string_param(params, "public_identity",
			&public_identity.s, &public_identity.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "private_identity",
			&private_identity.s, &private_identity.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "authenticate",
			&authenticate.s, &authenticate.len) < 0)
	if (aka_av_drop(&public_identity, &private_identity, &authenticate) <= 0)
		return init_mi_error(404, MI_SSTR("AV not found"));
	return init_mi_result_ok();
}

static mi_response_t *mi_aka_av_drop_all(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str public_identity, private_identity;

	if (get_mi_string_param(params, "public_identity",
			&public_identity.s, &public_identity.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "private_identity",
			&private_identity.s, &private_identity.len) < 0)
		return init_mi_param_error();
	return init_mi_result_number(aka_av_drop_all(&public_identity, &private_identity));
}

static mi_response_t *mi_aka_av_fail(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int count;
	str public_identity, private_identity;

	if (get_mi_string_param(params, "public_identity",
			&public_identity.s, &public_identity.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "private_identity",
			&private_identity.s, &private_identity.len) < 0)
		return init_mi_param_error();
	switch (try_get_mi_int_param(params, "count", &count)) {
		case -2:
			return init_mi_param_error();
		case -1:
			count = 1;
			break;
		case 0:
			break;
	}
	if (aka_av_fail(&public_identity, &private_identity, count) < 0)
		return init_mi_error(404, MI_SSTR("User not found"));
	return init_mi_result_ok();
}

int load_aka_av_api_bind(aka_av_api *api)
{
	api->add = aka_av_add;
	api->drop = aka_av_drop;
	api->drop_all = aka_av_drop_all;
	api->fail = aka_av_fail;
	return 1;
}
