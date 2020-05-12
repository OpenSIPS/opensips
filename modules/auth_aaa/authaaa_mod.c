/*
 * Digest Authentication - generic AAA support
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice Systems
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

#include "../../sr_module.h"
#include "../../error.h"
#include "../../dprint.h"
#include "../../config.h"
#include "../../mod_fix.h"
#include "../../pvar.h"
#include "../../aaa/aaa.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "authaaa_mod.h"
#include "authorize.h"
#include "checks.h"


aaa_map attrs[A_MAX];
aaa_map vals[V_MAX];
aaa_conn *conn;
aaa_prot proto;

auth_api_t auth_api;

static int mod_init(void);         /* Module initialization function */
static int cfg_validate(void);

/*
 * Module parameter variables
 */
static char* aaa_proto_url = NULL;
static int auth_service_type = -1;
static int check_service_type = -1;

int use_ruri_flag = -1;
char *use_ruri_flag_str = 0;

/*
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"aaa_www_authorize", (cmd_function)aaa_www_authorize, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"aaa_proxy_authorize", (cmd_function)aaa_proxy_authorize, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"aaa_does_uri_exist", (cmd_function)aaa_does_uri_exist, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|LOCAL_ROUTE},
	{"aaa_does_uri_user_exist", (cmd_function)w_aaa_does_uri_user_exist, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"aaa_url",            STR_PARAM, &aaa_proto_url       },
	{"auth_service_type",  INT_PARAM, &auth_service_type   },
	{"check_service_type", INT_PARAM, &check_service_type  },
	{"use_ruri_flag",      STR_PARAM, &use_ruri_flag_str   },
	{0, 0, 0}
};

/* create a dependency to "auth" module if any of the digest auth 
 * functions are used from the script - we do a small trick here and
 * hook on the 'aaa_url' mandatory  param to run the check, even if the
 * param value is not involved in the test */
static module_dependency_t *get_deps_aaa_url(param_export_t *param)
{
	if (is_script_func_used("aaa_www_authorize", -1) ||
	is_script_func_used("aaa_proxy_authorize", -1) )
		return alloc_module_dep(MOD_TYPE_DEFAULT, "auth", DEP_ABORT);

	return NULL;
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_AAA,     NULL,   DEP_WARN  },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "aaa_url", get_deps_aaa_url },
		{ NULL, NULL },
	},
};

/*
 * Module interface
 */
struct module_exports exports = {
	"auth_aaa",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* child initialization function */
	cfg_validate/* reload confirm function */
};


/*
 * Module initialization function
 */
static int mod_init(void)
{
	bind_auth_t bind_auth;
	str proto_url;

	aaa_map map;

	LM_INFO("initializing...\n");

	memset(attrs, 0, sizeof(attrs));
	memset(vals, 0, sizeof(vals));
	attrs[A_SERVICE_TYPE].name			= "Service-Type";
	attrs[A_SIP_URI_USER].name			= "Sip-URI-User";
	attrs[A_SIP_URI_HOST].name			= "SIP-URI-Host";
	attrs[A_DIGEST_RESPONSE].name		= "Digest-Response";
	attrs[A_DIGEST_ALGORITHM].name		= "Digest-Algorithm";
	attrs[A_DIGEST_BODY_DIGEST].name	= "Digest-Body-Digest";
	attrs[A_DIGEST_CNONCE].name			= "Digest-CNonce";
	attrs[A_DIGEST_NONCE_COUNT].name	= "Digest-Nonce-Count";
	attrs[A_DIGEST_QOP].name			= "Digest-QOP";
	attrs[A_DIGEST_METHOD].name			= "Digest-Method";
	attrs[A_DIGEST_URI].name			= "Digest-URI";
	attrs[A_DIGEST_NONCE].name			= "Digest-Nonce";
	attrs[A_DIGEST_REALM].name			= "Digest-Realm";
	attrs[A_DIGEST_USER_NAME].name		= "Digest-User-Name";
	attrs[A_USER_NAME].name				= "User-Name";
	attrs[A_CISCO_AVPAIR].name			= "Cisco-AVPair";
	attrs[A_SIP_AVP].name				= "SIP-AVP";
	attrs[A_ACCT_SESSION_ID].name		= "Acct-Session-Id";
	vals[V_SIP_SESSION].name			= "Sip-Session";
	vals[V_CALL_CHECK].name				= "Call-Check";

	use_ruri_flag = get_flag_id_by_name(FLAG_TYPE_MSG, use_ruri_flag_str, 0);

	if (!aaa_proto_url) {
		LM_ERR("aaa_url is empty\n");
		return -1;
	}

	proto_url.s = aaa_proto_url;
	proto_url.len = strlen(aaa_proto_url);

	if(aaa_prot_bind(&proto_url, &proto)) {
		LM_ERR("aaa protocol bind failure\n");
		return -1;
	}

	if (!(conn = proto.init_prot(&proto_url))) {
		LM_ERR("aaa init protocol failure\n");
		return -2;
	}

	map.name = "Cisco";
	if (proto.dictionary_find(conn, &map, AAA_DICT_FIND_VEND)) {
		LM_DBG("no `Cisco' vendor in AAA protocol dictionary\n");
		attrs[A_CISCO_AVPAIR].name = NULL;
	}

	if (is_script_func_used("aaa_www_authorize", -1) ||
	is_script_func_used("aaa_proxy_authorize", -1) ) {

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
	}

	INIT_AV(proto, conn, attrs, A_MAX, vals, V_MAX, "auth_aaa", -5, -6);

	if (auth_service_type != -1)
		vals[V_SIP_SESSION].value = auth_service_type;
	if (check_service_type != -1)
		vals[V_CALL_CHECK].value = check_service_type;

	return 0;
}


static int cfg_validate(void)
{
	/* if auth API already loaded, it is fine */
	if (auth_api.pre_auth)
		return 1;

	if (is_script_func_used("aaa_www_authorize", -1) ||
	is_script_func_used("aaa_proxy_authorize", -1) ) {
		LM_ERR("aaa_xxx_authorize() was found, but module started without "
			"auth support/binding, better restart\n");
		return 0;
	}

	return 0;
}
