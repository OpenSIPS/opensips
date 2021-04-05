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
 *
 * History:
 * --------
 * 2003-02-26 checks and group moved to separate modules (janakj)
 * 2003-03-10 New module interface (janakj)
 * 2003-03-16 flags export parameter added (janakj)
 * 2003-03-19 all mallocs/frees replaced w/ pkg_malloc/pkg_free (andrei)
 * 2003-04-28 rpid contributed by Juha Heinanen added (janakj)
 * 2005-05-31 general avp specification added for rpid (bogdan)
 * 2006-03-01 pseudo variables support for domain name (bogdan)
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../error.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../lock_alloc.h"
#include "../signaling/signaling.h"
#include "auth_mod.h"
#include "challenge.h"
#include "rpid.h"
#include "api.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/digest_auth/dauth_calc.h"
#include "../../lib/digest_auth/dauth_nonce.h"
#include "../../lib/dassert.h"

#define DEF_RPID_PREFIX ""
#define DEF_RPID_SUFFIX ";party=calling;id-type=subscriber;screen=yes"
#define DEF_STRIP_REALM ""
#define DEF_RPID_AVP "$avp(rpid)"


static str auth_500_err = str_init("Server Internal Error");

/*
 * Module destroy function prototype
 */
static void destroy(void);

/*
 * Module initialization function prototype
 */
static int mod_init(void);
static int child_init(int _rank);

int pv_proxy_authorize(struct sip_msg* msg, str* realm);
int pv_www_authorize(struct sip_msg* msg, str* realm);

/** SIGNALING binds */
struct sig_binds sigb;


/*
 * Module parameter variables
 */
char* sec_param    = 0;   /* If the parameter was not used, the secret phrase will be auto-generated */
unsigned int nonce_expire = 30; /* Nonce lifetime - default 30 seconds */

struct nonce_context *ncp = NULL;

int auth_calc_ha1 = 0;

/* Default Remote-Party-ID prefix */
str rpid_prefix = {DEF_RPID_PREFIX, sizeof(DEF_RPID_PREFIX) - 1};
/* Default Remote-Party-IDD suffix */
str rpid_suffix = {DEF_RPID_SUFFIX, sizeof(DEF_RPID_SUFFIX) - 1};
/* Prefix to strip from realm */
str realm_prefix = {DEF_STRIP_REALM, sizeof(DEF_STRIP_REALM) - 1};

/* definition of AVP containing rpid value */
char* rpid_avp_param = DEF_RPID_AVP;

/* definition of AVP containing username value */
char* user_spec_param = 0;
static pv_spec_t user_spec;


/* definition of AVP containing password value */
char* passwd_spec_param = 0;
static pv_spec_t passwd_spec;

/* nonce index */
gen_lock_t* nonce_lock= NULL;
char* nonce_buf= NULL;
int* sec_monit= NULL;
int* second= NULL;
int* next_index= NULL;
int disable_nonce_check = 0;

/*
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"www_challenge", (cmd_function)www_challenge, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_qop,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,dauth_fixup_algorithms,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"proxy_challenge", (cmd_function)proxy_challenge, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_qop,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,dauth_fixup_algorithms,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"pv_www_authorize",    (cmd_function)pv_www_authorize, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"pv_proxy_authorize",  (cmd_function)pv_proxy_authorize, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"consume_credentials", (cmd_function)consume_credentials, {{0,0,0}},
		REQUEST_ROUTE},
	{"is_rpid_user_e164",   (cmd_function)is_rpid_user_e164, {{0,0,0}},
		REQUEST_ROUTE},
	{"append_rpid_hf",      (cmd_function)append_rpid_hf, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE},
	{"bind_auth",   (cmd_function)bind_auth, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"secret",              STR_PARAM, &sec_param          },
	{"nonce_expire",        INT_PARAM, &nonce_expire       },
	{"rpid_prefix",         STR_PARAM, &rpid_prefix.s      },
	{"rpid_suffix",         STR_PARAM, &rpid_suffix.s      },
	{"realm_prefix",        STR_PARAM, &realm_prefix.s     },
	{"rpid_avp",            STR_PARAM, &rpid_avp_param     },
	{"username_spec",       STR_PARAM, &user_spec_param    },
	{"password_spec",       STR_PARAM, &passwd_spec_param  },
	{"calculate_ha1",       INT_PARAM, &auth_calc_ha1      },
	{"disable_nonce_check", INT_PARAM, &disable_nonce_check},
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT },
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
	"auth",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	0,
	params,
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* child initialization function */
	0           /* reload confirm function */
};

static int mod_init(void)
{
	str stmp;
	LM_INFO("initializing...\n");

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0){
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	ncp = dauth_noncer_new();
	if (ncp == NULL) {
		LM_ERR("can't init nonce generator\n");
		return -1;
	}

	/* If the parameter was not used */
	if (sec_param == 0) {
		/* Generate secret using random generator */
		if (generate_random_secret(ncp) < 0) {
			LM_ERR("failed to generate random secret\n");
			return -3;
		}
	} else {
		/* Otherwise use the parameter's value */
		ncp->secret.s = sec_param;
		ncp->secret.len = strlen(sec_param);
	}

	if (dauth_noncer_init(ncp) < 0) {
		LM_ERR("dauth_noncer_init() failed\n");
		return -1;
	}


	if ( init_rpid_avp(rpid_avp_param)<0 ) {
		LM_ERR("failed to process rpid AVPs\n");
		return -4;
	}

	rpid_prefix.len = strlen(rpid_prefix.s);
	rpid_suffix.len = strlen(rpid_suffix.s);
	realm_prefix.len = strlen(realm_prefix.s);

	if(user_spec_param!=0)
	{
		stmp.s = user_spec_param; stmp.len = strlen(stmp.s);
		if(pv_parse_spec(&stmp, &user_spec)==NULL)
		{
			LM_ERR("failed to parse username spec\n");
			return -5;
		}
		switch(user_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid username spec\n");
				return -6;
			default: ;
		}
	}
	if(passwd_spec_param!=0)
	{
		stmp.s = passwd_spec_param; stmp.len = strlen(stmp.s);
		if(pv_parse_spec(&stmp, &passwd_spec)==NULL)
		{
			LM_ERR("failed to parse password spec\n");
			return -7;
		}
		switch(passwd_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid password spec\n");
				return -8;
			default: ;
		}
	}

	if(!disable_nonce_check)
	{
		nonce_lock = (gen_lock_t*)lock_alloc();
		if(nonce_lock== NULL)
		{
			LM_ERR("no more shared memory\n");
			return -1;
		}

		/* initialize lock_nonce */
		if(lock_init(nonce_lock)== 0)
		{
			LM_ERR("failed to init lock\n");
			return -9;
		}

		nonce_buf= (char*)shm_malloc(NBUF_LEN);
		if(nonce_buf== NULL)
		{
			LM_ERR("no more share memory\n");
			return -10;
		}
		memset(nonce_buf, 255, NBUF_LEN);

		sec_monit= (int*)shm_malloc((nonce_expire +1)* sizeof(int));
		if(sec_monit== NULL)
		{
			LM_ERR("no more share memory\n");
			return -10;
		}
		memset(sec_monit, -1, (nonce_expire +1)* sizeof(int));
		second= (int*)shm_malloc(sizeof(int));
		next_index= (int*)shm_malloc(sizeof(int));
		if(second==  NULL || next_index== NULL)
		{
			LM_ERR("no more share memory\n");
			return -10;
		}
		*next_index= -1;
	}

	return 0;
}

static int child_init(int _rank)
{

	dauth_noncer_reseed();
	return 0;
}

static void destroy(void)
{
	if (ncp == NULL)
		return;
	if(!disable_nonce_check)
	{
		if(nonce_lock)
		{
			lock_destroy(nonce_lock);
			lock_dealloc(nonce_lock);
		}

		if(nonce_buf)
			shm_free(nonce_buf);
		if(second)
			shm_free(second);
		if(sec_monit)
			shm_free(sec_monit);
		if(next_index)
			shm_free(next_index);
	}
	dauth_noncer_dtor(ncp);
}

static inline int auth_get_ha1(struct sip_msg *msg, dig_cred_t* digest,
		str* _domain, HASHHEX* _ha1)
{
	pv_value_t sval;
	struct username* _username = &digest->username;

	/* get username from PV */
	memset(&sval, 0, sizeof(pv_value_t));
	if(pv_get_spec_value(msg, &user_spec, &sval)==0)
	{
		if(sval.flags==PV_VAL_NONE || (sval.flags&PV_VAL_NULL)
				|| (sval.flags&PV_VAL_EMPTY) || (!(sval.flags&PV_VAL_STR)))
		{
			pv_value_destroy(&sval);
			return -1;
		}
		if(sval.rs.len!= _username->whole.len
				|| strncasecmp(sval.rs.s, _username->whole.s, sval.rs.len))
		{
			LM_DBG("username mismatch [%.*s] [%.*s]\n",
				_username->whole.len, _username->whole.s, sval.rs.len, sval.rs.s);
			pv_value_destroy(&sval);
			return 1;
		}
	} else {
		return 1;
	}
	/* get password from PV */
	memset(&sval, 0, sizeof(pv_value_t));
	if(pv_get_spec_value(msg, &passwd_spec, &sval)==0)
	{
		if(sval.flags==PV_VAL_NONE || (sval.flags&PV_VAL_NULL)
				|| (sval.flags&PV_VAL_EMPTY) || (!(sval.flags&PV_VAL_STR)))
		{
			pv_value_destroy(&sval);
			return -1;
		}
	} else {
		return 1;
	}
	const struct digest_auth_calc *digest_calc;
	digest_calc = get_digest_calc(digest->alg.alg_parsed);
	if (digest_calc == NULL) {
		LM_ERR("digest algorithm (%d) unsupported\n", digest->alg.alg_parsed);
		 return -1;
	}
	if (auth_calc_ha1) {
		struct digest_auth_credential creds = {.realm = *_domain,
		    .user = _username->whole, .passwd = sval.rs};
		/* Only plaintext passwords are stored in database,
		 * we have to calculate HA1 */
		if (digest_calc->HA1(&creds, _ha1) != 0)
			return -1;
		LM_DBG("HA1 string calculated: %s\n", _ha1->_start);
	} else {
		memcpy(_ha1->_start, sval.rs.s, sval.rs.len);
		_ha1->_start[sval.rs.len] = '\0';
	}
	if (digest_calc->HA1sess != NULL) {
		if (digest_calc->HA1sess(str2const(&digest->nonce),
		    str2const(&digest->cnonce), _ha1) != 0)
			return -1;
	}

	return 0;
}

static inline int pv_authorize(struct sip_msg* msg, str *domain,
										hdr_types_t hftype)
{
	HASHHEX ha1;
	int res;
	struct hdr_field* h;
	auth_body_t* cred;
	str msg_body;
	auth_result_t ret;

	if (domain->len==0)
		domain->s = 0;

	ret = pre_auth(msg, domain, hftype, &h);

	if (ret != DO_AUTHORIZATION)
		return ret;

	cred = (auth_body_t*)h->parsed;

	res = auth_get_ha1(msg, &cred->digest, domain, &ha1);
	if (res < 0) {
		/* Error */
		if (sigb.reply(msg, 500, &auth_500_err, NULL) == -1)
			LM_ERR("failed to send 500 reply\n");

		return ERROR;
	} else if (res > 0) {
		/* Username not found */
		return USER_UNKNOWN;
	}

	if (cred->digest.qop.qop_parsed == QOP_AUTHINT_D &&
		get_body(msg, &msg_body) < 0) {
		LM_ERR("Failed to get body of SIP message\n");
		return ERROR;
	}

	/* Recalculate response, it must be same to authorize successfully */
	if (!check_response(&(cred->digest),&msg->first_line.u.request.method,
		&msg_body, &ha1))
	{
		return post_auth(msg, h);
	}
	return INVALID_PASSWORD;
}


int pv_proxy_authorize(struct sip_msg* msg, str* realm)
{
	return pv_authorize(msg, realm, HDR_PROXYAUTH_T);
}


int pv_www_authorize(struct sip_msg* msg, str* realm)
{
	return pv_authorize(msg, realm, HDR_AUTHORIZATION_T);
}

