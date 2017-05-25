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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../error.h"
#include "../../dprint.h"
#include "../../config.h"
#include "../../pvar.h"
#include "../../aaa/aaa.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "authaaa_mod.h"
#include "authorize.h"


aaa_map attrs[A_MAX];
aaa_map vals[V_MAX];
aaa_conn *conn;
aaa_prot proto;

auth_api_t auth_api;

static int mod_init(void);         /* Module initialization function */
static int auth_fixup(void** param, int param_no); /* char* -> str* */


/*
 * Module parameter variables
 */
static char* aaa_proto_url = NULL;
static int service_type = -1;

int use_ruri_flag = -1;
char *use_ruri_flag_str = 0;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"aaa_www_authorize", (cmd_function)aaa_www_authorize,   1, auth_fixup,
			0, REQUEST_ROUTE},
	{"aaa_www_authorize", (cmd_function)aaa_www_authorize,   2, auth_fixup,
			0, REQUEST_ROUTE},
	{"aaa_proxy_authorize", (cmd_function)aaa_proxy_authorize_1, 1, auth_fixup,
			0, REQUEST_ROUTE},
	{"aaa_proxy_authorize", (cmd_function)aaa_proxy_authorize_2, 2, auth_fixup,
			0, REQUEST_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"aaa_url",  	 STR_PARAM, &aaa_proto_url   },
	{"service_type",     INT_PARAM, &service_type        },
	{"use_ruri_flag",    STR_PARAM, &use_ruri_flag_str   },
	{"use_ruri_flag",    INT_PARAM, &use_ruri_flag       },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "auth", DEP_ABORT },
		{ MOD_TYPE_AAA,     NULL,   DEP_WARN  },
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
	"auth_aaa",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0           /* child initialization function */
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

	fix_flag_name(use_ruri_flag_str, use_ruri_flag);
	use_ruri_flag = get_flag_id_by_name(FLAG_TYPE_MSG, use_ruri_flag_str);

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

	bind_auth = (bind_auth_t)find_export("bind_auth", 0, 0);
	if (!bind_auth) {
		LM_ERR("unable to find bind_auth function. Check if you load the auth module.\n");
		return -1;
	}

	if (bind_auth(&auth_api) < 0) {
		LM_ERR("cannot bind to auth module\n");
		return -4;
	}

	INIT_AV(proto, conn, attrs, A_MAX, vals, V_MAX, "auth_aaa", -5, -6);

	if (service_type != -1) {
		vals[V_SIP_SESSION].value = service_type;
	}

	return 0;
}


/*
 * Convert char* parameter to pv_elem_t* parameter
 */
static int auth_fixup(void** param, int param_no)
{
	pv_elem_t *model;
	str s;
	pv_spec_t *sp;

	if (param_no == 1) { /* realm (string that may contain pvars) */
		s.s = (char*)*param;
		if (s.s==0 || s.s[0]==0) {
			model = 0;
		} else {
			s.len = strlen(s.s);
			if (pv_parse_format(&s,&model)<0) {
				LM_ERR("pv_parse_format failed\n");
				return E_OUT_OF_MEM;
			}
		}
		*param = (void*)model;
	}

	if (param_no == 2) { /* URI user (a pvar) */
		sp = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
		if (sp == 0) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
		s.s = (char*)*param;
		s.len = strlen(s.s);
		if (pv_parse_spec(&s, sp) == 0) {
			LM_ERR("parsing of pseudo variable %s failed!\n", (char*)*param);
			pkg_free(sp);
			return -1;
		}
		if (sp->type == PVT_NULL) {
			LM_ERR("bad pseudo variable\n");
			pkg_free(sp);
			return -1;
		}
		*param = (void*)sp;
	}

	return 0;
}
