/*
 * OpenSIPS H.350 Module
 *
 * Copyright (C) 2007 University of North Carolina
 *
 * Original author: Christian Schlatter, cs@unc.edu
 *
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
 * 2007-03-12: Initial version
 */

#include "../../sr_module.h"
#include "../../ut.h"
#include "h350_mod.h"
#include "h350_exp_fn.h"




/*
 * Module management function prototypes
 */
static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

/*
 * exported functions
 */

static int w_h350_sipuri_lookup(struct sip_msg* msg, str* sip_uri);
static int w_h350_auth_lookup(struct sip_msg* msg, str* digest_username,
						pv_spec_t *username_avp, pv_spec_t *pwd_avp);
static int w_h350_call_preferences(struct sip_msg* msg, str* avp_name_prefix);
static int w_h350_service_level(struct sip_msg* msg, str* avp_name_prefix);

/*
 * Module parameter variables
 */
str h350_ldap_session = str_init(H350_LDAP_SESSION);
str h350_base_dn = str_init(H350_BASE_DN);
str h350_search_scope = str_init(H350_SEARCH_SCOPE);
int h350_search_scope_int = -1;


/*
 * LDAP API
 */
ldap_api_t ldap_api;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"h350_sipuri_lookup", (cmd_function)w_h350_sipuri_lookup, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE},
	{"h350_auth_lookup", (cmd_function)w_h350_auth_lookup, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"h350_result_call_preferences", (cmd_function)w_h350_call_preferences, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE},
	{"h350_result_service_level", (cmd_function)w_h350_service_level, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"ldap_session",     STR_PARAM, &h350_ldap_session.s},
	{"base_dn",          STR_PARAM, &h350_base_dn.s},
	{"search_scope",     STR_PARAM, &h350_search_scope.s},
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "ldap", DEP_ABORT },
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
	"h350",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
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

static int child_init(int rank)
{
	h350_search_scope_int = ldap_api.ldap_str2scope(h350_search_scope.s);

	/*
	 * initialize h350_exp_fn
	 */
	if (h350_exp_fn_init() != 0)
	{
		LM_ERR("h350_exp_fn_init failed\n");
		return -1;
	}

	return 0;
}


static int mod_init(void)
{
	LM_INFO("H350 module - initializing\n");

	/*
	 * load the LDAP API
	 */
	if (load_ldap_api(&ldap_api) != 0)
	{
		LM_ERR("Unable to load LDAP API - this module requires ldap module\n");
		return -1;
	}

	return 0;

	/*
	 * check module parameters
	 */
	if (ldap_api.ldap_str2scope(h350_search_scope.s) == -1)
	{
		LM_ERR("Invalid search_scope [%s]\n", h350_search_scope.s);
		return -1;
	}

}


static void destroy(void)
{
}


/*
 * EXPORTED functions
 */
static int w_h350_sipuri_lookup(struct sip_msg* msg, str* sip_uri)
{
	return h350_sipuri_lookup(msg, sip_uri);
}

static int w_h350_auth_lookup(struct sip_msg* msg, str* digest_username,
						pv_spec_t *username_avp, pv_spec_t *pwd_avp)
{
	return h350_auth_lookup( msg, digest_username, username_avp, pwd_avp);
}

static int w_h350_call_preferences(struct sip_msg* msg, str* avp_name_prefix)
{
	return h350_call_preferences(msg, avp_name_prefix);
}

static int w_h350_service_level(struct sip_msg* msg, str* avp_name_prefix)
{
	return h350_service_level(msg, avp_name_prefix);
}
