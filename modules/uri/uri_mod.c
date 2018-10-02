/*
 * Various URI related functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice Systems
 *
 * This file is part of ser, a free SIP server.
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
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../../aaa/aaa.h"
#include "uri_mod.h"
#include "aaa_checks.h"



/*
 * AAA protocol variables
 */
aaa_map attrs[A_MAX];
aaa_map vals[V_MAX];
aaa_conn *conn;
aaa_prot proto;

static int mod_init(void); /* Module initialization function */
static void destroy(void);       /* Module destroy function */
static int child_init(int rank); /* Per-child initialization function */


/*
 * Module parameter variables
 */
static char *aaa_proto_url = NULL;
static int service_type = -1;
int use_sip_uri_host = 0;

static int aaa_fixup_0(void** param, int param_no);
static int aaa_fixup_1(void** param, int param_no);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"aaa_does_uri_exist", (cmd_function)aaa_does_uri_exist_0, 0,
			aaa_fixup_0, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"aaa_does_uri_exist", (cmd_function)aaa_does_uri_exist_1, 1,
			aaa_fixup_1, fixup_free_pvar_null,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"aaa_does_uri_user_exist", (cmd_function)aaa_does_uri_user_exist_0, 0,
			aaa_fixup_0, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"aaa_does_uri_user_exist", (cmd_function)aaa_does_uri_user_exist_1, 1,
			aaa_fixup_1, fixup_free_pvar_null,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"aaa_url", 				 STR_PARAM, &aaa_proto_url},
	{"service_type", 			 INT_PARAM, &service_type},
	{"use_sip_uri_host", 		 INT_PARAM, &use_sip_uri_host},
	{0, 0, 0}
};


static module_dependency_t *get_deps_aaa_url(param_export_t *param)
{
	char *url = *(char **)param->param_pointer;

	if (url || strlen(url) == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_AAA, NULL, DEP_SILENT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "aaa_url", get_deps_aaa_url   },
		{ NULL, NULL },
	},
};

/*
 * Module interface
 */
struct module_exports exports = {
	"uri",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,      /* Exported functions */
	0,         /* Exported async functions */
	params,    /* Exported parameters */
	0,         /* exported statistics */
	0,         /* exported MI functions */
	0,         /* exported pseudo-variables */
	0,		   /* exported transformations */
	0,         /* extra processes */
	mod_init,   /* module initialization function */
	0,         /* response function */
	destroy,   /* destroy function */
	child_init /* child initialization function */
};


static int mod_init(void)
{
	str proto_url;

	LM_DBG("initializing\n");

	if (aaa_proto_url) {
		memset(attrs, 0, sizeof(attrs));
		memset(vals, 0, sizeof(vals));
		attrs[A_SERVICE_TYPE].name		= "Service-Type";
		attrs[A_USER_NAME].name			= "User-Name";

		if (use_sip_uri_host)
			attrs[A_SIP_URI_HOST].name	= "SIP-URI-Host";

		attrs[A_SIP_AVP].name			= "SIP-AVP";
		attrs[A_ACCT_SESSION_ID].name	= "Acct-Session-Id";
		vals[V_CALL_CHECK].name			= "Call-Check";

		proto_url.s = aaa_proto_url;
		proto_url.len = strlen(aaa_proto_url);

		if(aaa_prot_bind(&proto_url, &proto)) {
			LM_ERR("aaa protocol bind failure\n");
			return -1;
		}

		conn = proto.init_prot(&proto_url);
		if (!conn) {
			LM_ERR("aaa protocol initialization failure\n");
			return -2;
		}

		INIT_AV(proto, conn, attrs, A_MAX, vals, V_MAX, "uri", -3, -4);

		if (service_type != -1)
			vals[V_CALL_CHECK].value = service_type;
	}

	return 0;
}



/**
 * Module initialization function callee in each child separately
 */
static int child_init(int rank)
{
	return 0;
}

static void destroy(void)
{
	return;
}


static int aaa_fixup_0(void** param, int param_no) {

	if (!aaa_proto_url) {
		LM_ERR("configuration error - no aaa protocol url\n");
		return E_CFG;
	}

	return 0;
}

static int aaa_fixup_1(void** param, int param_no) {

	if (!aaa_proto_url) {
		LM_ERR("configuration error - no aaa protocol url\n");
		return E_CFG;
	}

	return fixup_pvar_null(param, param_no);
}


