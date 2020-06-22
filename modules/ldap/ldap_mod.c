/*
 * OpenSIPS LDAP Module
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
 * 2007-02-18: Initial version
 */


#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../parser/hf.h"
#include "../../pvar.h"
#include "../../mem/mem.h"

#include "ld_session.h"
#include "ldap_exp_fn.h"
#include "api.h"
#include "ldap_connect.h"
#include "ldap_api_fn.h"
#include "iniparser.h"

int max_async_connections=30;

/*
* Module management function prototypes
*/
static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

/*
* fixup functions
*/
static int fixup_result_avp_type(void **param);
static int fixup_substre(void** param);

/*
* exported functions
*/

static int w_ldap_search_async(struct sip_msg* msg, async_ctx *ctx, str* ldap_url);
static int w_ldap_search(struct sip_msg* msg, str* ldap_url);
static int w_ldap_result(struct sip_msg* msg, str *attr_name,
				pv_spec_t *dst_avp, void *avp_type, struct subst_expr *subst);
static int w_ldap_result_next(struct sip_msg* msg);
static int w_ldap_filter_url_encode(struct sip_msg* msg,
		str* filter_component, pv_spec_t* dst_avp_name);
static int w_ldap_result_check(struct sip_msg* msg, str* attr_name,
				str *check_str, struct subst_expr *subst);


/*
* Default module parameter values
*/
#define DEF_LDAP_CONFIG "/usr/local/etc/opensips/ldap.cfg"
#define DEF_REQ_CERT	"NEVER"

/*
* Module parameter variables
*/
str ldap_config = str_init(DEF_LDAP_CONFIG);
static dictionary* config_vals = NULL;

static acmd_export_t acmds[] = {
	{"ldap_search", (acmd_function)w_ldap_search_async, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}}},
	{0,0,{{0,0,0}}}
};

static cmd_export_t cmds[] = {
	{"ldap_search", (cmd_function)w_ldap_search, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"ldap_result", (cmd_function)w_ldap_result, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, fixup_result_avp_type, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, fixup_substre, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"ldap_result_next", (cmd_function)w_ldap_result_next, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"ldap_result_check", (cmd_function)w_ldap_result_check, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, fixup_substre, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|
		BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"ldap_filter_url_encode", (cmd_function)w_ldap_filter_url_encode, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|
		BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"load_ldap", (cmd_function)load_ldap, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};


/*
* Exported parameters
*/
static param_export_t params[] = {

	{"config_file",                    STR_PARAM, &ldap_config.s},
	{"max_async_connections",          INT_PARAM, &max_async_connections},
	{0, 0, 0}
};


/*
* Module interface
*/
struct module_exports exports = {
	"ldap",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	acmds,       /* Exported async functions */
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
	int i = 0, ld_count = 0;
	char* ld_name;

	/* don't do anything for non-worker process */
	if (rank<1)
		return 0;

	/*
	* build ld_sessions and connect all sessions
	*/
	ld_count = iniparser_getnsec(config_vals);
	for (i = 0; i < ld_count; i++)
	{
		ld_name = iniparser_getsecname(config_vals, i);
		if (add_ld_session(ld_name, config_vals)
				!= 0)
		{
			LM_ERR("[%s]: add_ld_session failed\n", ld_name);
			return -1;
		}

		/* won't check for null in get_ld_session since it's barely been initialized */
		if (ldap_connect(ld_name, &get_ld_session(ld_name)->conn_s) != 0)
		{
			LM_ERR("[%s]: failed to connect to LDAP host(s)\n", ld_name);
			ldap_disconnect(ld_name, NULL);
			return -1;
		}

	}

	return 0;
}


static int mod_init(void)
{
	int ld_count = 0, i = 0;
	char* section_name;
	char* ldap_version;

	LM_INFO("LDAP_H350 module - initializing\n");

	/*
	* read config file
	*/
	if (strlen(ldap_config.s) == 0)
	{
		LM_ERR("config_file is empty - this module param is mandatory\n");
		return -2;
	}
	if ((config_vals = iniparser_new(ldap_config.s)) == NULL)
	{
		LM_ERR("failed to read config_file [%s]\n", ldap_config.s);
		return -2;
	}
	if ((ld_count = iniparser_getnsec(config_vals)) < 1)
	{
		LM_ERR("no section found in config_file [%s]\n", ldap_config.s);
		return -2;
	}
	/* check if mandatory settings are present */
	for (i = 0; i < ld_count; i++)
	{
		section_name = iniparser_getsecname(config_vals, i);
		if (strlen(section_name) > 255)
		{
			LM_ERR(	"config_file section name [%s]"
				" longer than allowed 255 characters",
				section_name);
			return -2;
		}
		if (!iniparser_find_entry(config_vals,
					get_ini_key_name(section_name, CFG_N_LDAP_HOST)))
		{
			LM_ERR(	"mandatory %s not defined in [%s]\n",
				CFG_N_LDAP_HOST,
				section_name);
			return -2;
		}
	}

	/*
	* print ldap version string
	*/
	if (ldap_get_vendor_version(&ldap_version) != 0)
	{
		LM_ERR("ldap_get_vendor_version failed\n");
		return -2;
	}

	return 0;
}


static void destroy(void)
{
	/* ldap_unbind */
	free_ld_sessions();

	/* free config file memory */
	iniparser_free(config_vals);
}


/*
* EXPORTED functions
*/

static int w_ldap_search_async(struct sip_msg* msg, async_ctx *ctx, str* ldap_url)
{
	return ldap_search_impl_async(msg, ctx, ldap_url);
}

static int w_ldap_search(struct sip_msg* msg, str* ldap_url)
{
	return ldap_search_impl(msg, ldap_url);
}

static int w_ldap_result(struct sip_msg* msg, str *attr_name,
				pv_spec_t *dst_avp, void *avp_type, struct subst_expr *subst)
{
	return ldap_write_result(msg, attr_name, dst_avp, (int)(unsigned long)avp_type, subst);
}

static int w_ldap_result_next(struct sip_msg* msg)
{
	return ldap_result_next();
}

static int w_ldap_filter_url_encode(struct sip_msg* msg,
		str* filter_component, pv_spec_t* dst_avp_name)
{
	return ldap_filter_url_encode(msg, filter_component, dst_avp_name);
}

static int w_ldap_result_check(struct sip_msg* msg, str* attr_name,
				str *check_str, struct subst_expr *subst)
{
	return ldap_result_check(msg, attr_name, check_str, subst);
}

/*
* FIXUP functions
*/

static int fixup_result_avp_type(void **param)
{
	static str ints = str_init("int");
	static str strs = str_init("str");
	int dst_avp_val_type = 0;

	if (!str_strcmp((str*)*param, &ints))
	{
		dst_avp_val_type = 1;
	}
	else if (str_strcmp((str*)*param, &strs))
	{
		LM_ERR(	"invalid avp_type [%.*s]\n",
			((str*)*param)->len, ((str*)*param)->s);
		return E_UNSPEC;
	}

	*param = (void*)(long)dst_avp_val_type;
	return 0;
}

static int fixup_substre(void** param)
{
	struct subst_expr* se;

	se=subst_parser((str*)*param);
	if (se==0){
		LM_ERR("bad subst re [%.*s]\n", ((str*)*param)->len, ((str*)*param)->s);
		return E_BAD_RE;
	}

	*param=se;
	return 0;
}
