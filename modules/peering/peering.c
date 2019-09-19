/*
 * Peering module
 *
 * Copyright (C) 2008 Juha Heinanen
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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


#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../config.h"
#include "../../aaa/aaa.h"
#include "verify.h"



aaa_map attrs[A_MAX];
aaa_map vals[V_MAX];
aaa_conn *conn;
aaa_prot proto;

static int mod_init(void);         /* Module initialization function */


/*
 * Module parameter variables
 */
static char* aaa_proto_url = NULL;
int verify_destination_service_type = -1;
int verify_source_service_type = -1;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
    {"verify_destination", (cmd_function)verify_destination, {{0,0,0}},
        REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
    {"verify_source", (cmd_function)verify_source, {{0,0,0}},
        REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
    {0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
    {"aaa_url", STR_PARAM, &aaa_proto_url},
    {"verify_destination_service_type", INT_PARAM,
     &verify_destination_service_type},
    {"verify_source_service_type", INT_PARAM,
     &verify_source_service_type},
    {0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_AAA, NULL, DEP_WARN },
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
    "peering",
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
    0           /* reload confirm function */
};


/*
 * Module initialization function
 */
static int mod_init(void)
{
	str prot_url;

	LM_DBG("initializing\n");

    memset(attrs, 0, sizeof(attrs));
    memset(vals, 0, sizeof(vals));
    attrs[A_USER_NAME].name 			= "User-Name";
    attrs[A_SIP_URI_USER].name 			= "SIP-URI-User";
    attrs[A_SIP_FROM_TAG].name 			= "SIP-From-Tag";
    attrs[A_SIP_CALL_ID].name 			= "SIP-Call-Id";
    attrs[A_SIP_REQUEST_HASH].name		= "SIP-Request-Hash";
    attrs[A_SIP_AVP].name	 			= "SIP-AVP";
    attrs[A_SERVICE_TYPE].name 			= "Service-Type";
    vals[V_SIP_VERIFY_DESTINATION].name = "Sip-Verify-Destination";
    vals[V_SIP_VERIFY_SOURCE].name		= "Sip-Verify-Source";

	prot_url.s = aaa_proto_url;
	prot_url.len = strlen(aaa_proto_url);

	if(aaa_prot_bind(&prot_url, &proto)) {
		LM_ERR("aaa protocol bind failure\n");
		return -1;
	}

	if (!(conn = proto.init_prot(&prot_url))) {
		LM_ERR("aaa protocol initialization failure\n");
		return -2;
	}

    INIT_AV(proto, conn, attrs, A_MAX, vals, V_MAX, "peering", -3, -4);

    if (verify_destination_service_type != -1)
		vals[V_SIP_VERIFY_DESTINATION].value = verify_destination_service_type;

    if (verify_source_service_type != -1)
		vals[V_SIP_VERIFY_SOURCE].value = verify_source_service_type;

    return 0;
}
