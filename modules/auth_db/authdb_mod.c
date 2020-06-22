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
 * 2003-02-26: checks and group moved to separate modules (janakj)
 * 2003-03-11: New module interface (janakj)
 * 2003-03-16: flags export parameter added (janakj)
 * 2003-03-19  all mallocs/frees replaced w/ pkg_malloc/pkg_free (andrei)
 * 2003-04-05: default_uri #define used (jiri)
 * 2004-06-06  cleanup: static & auth_db_{init,bind,close.ver} used (andrei)
 * 2005-05-31  general definition of AVPs in credentials now accepted - ID AVP,
 *             STRING AVP, AVP aliases (bogdan)
 * 2006-03-01 pseudo variables support for domain name (bogdan)
 */

#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../auth/api.h"
#include "../signaling/signaling.h"
#include "aaa_avps.h"
#include "authorize.h"
#include "checks.h"

/*
 * Version of domain table required by the module,
 * increment this value if you change the table in
 * an backwards incompatible way
 */
#define SUBSCRIBER_TABLE_VERSION 7
#define URI_TABLE_VERSION        2

/*
 * Module destroy function prototype
 */
static void destroy(void);


/*
 * Module child-init function prototype
 */
static int child_init(int rank);


/*
 * Module initialization function prototype
 */
static int mod_init(void);


static int auth_fixup_table(void** param);
static int fixup_check_outvar(void **param);

/** SIGNALING binds */
struct sig_binds sigb;

#define USER_COL "username"
#define USER_COL_LEN (sizeof(USER_COL) - 1)

#define DOMAIN_COL "domain"
#define DOMAIN_COL_LEN (sizeof(DOMAIN_COL) - 1)

#define PASS_COL "ha1"
#define PASS_COL_LEN (sizeof(PASS_COL) - 1)

#define PASS_COL_2 "ha1b"
#define PASS_COL_2_LEN (sizeof(PASS_COL_2) - 1)

#define DEFAULT_CRED_LIST "rpid"

/*
 * Module parameter variables
 */
static str db_url           = {NULL,0};
str user_column             = {USER_COL, USER_COL_LEN};
str domain_column           = {DOMAIN_COL, DOMAIN_COL_LEN};
str pass_column             = {PASS_COL, PASS_COL_LEN};
str pass_column_2           = {PASS_COL_2, PASS_COL_2_LEN};

str uri_user_column         = str_init("username");
str uri_domain_column       = str_init("domain");
str uri_uriuser_column      = str_init("uri_user");

int calc_ha1                = 0;
int use_domain              = 0; /* Use also domain when looking up in table */

db_con_t* auth_db_handle    = 0; /* database connection handle */
db_func_t auth_dbf;
auth_api_t auth_api;

char *credentials_list      = DEFAULT_CRED_LIST;
struct aaa_avp *credentials = 0; /* Parsed list of credentials to load */
int credentials_n           = 0; /* Number of credentials in the list */
int skip_version_check      = 0; /* skips version check for custom db */


/*
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"www_authorize", (cmd_function)www_authorize, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, auth_fixup_table, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"proxy_authorize", (cmd_function)proxy_authorize, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, auth_fixup_table, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"db_does_uri_exist", (cmd_function)does_uri_exist, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, auth_fixup_table, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"db_is_to_authorized", (cmd_function)check_to, {
		{CMD_PARAM_STR, auth_fixup_table, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"db_is_from_authorized", (cmd_function)check_from, {
		{CMD_PARAM_STR, auth_fixup_table, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"db_get_auth_id", (cmd_function) get_auth_id, {
		{CMD_PARAM_STR, auth_fixup_table, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_outvar, 0},
		{CMD_PARAM_VAR, fixup_check_outvar, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",            STR_PARAM, &db_url.s            },
	{"user_column",       STR_PARAM, &user_column.s       },
	{"domain_column",     STR_PARAM, &domain_column.s     },
	{"password_column",   STR_PARAM, &pass_column.s       },
	{"password_column_2", STR_PARAM, &pass_column_2.s     },
	{"uri_user_column",   STR_PARAM, &uri_user_column.s   },
	{"uri_domain_column", STR_PARAM, &uri_domain_column.s },
	{"uri_uriuser_column",STR_PARAM, &uri_uriuser_column.s},
	{"calculate_ha1",     INT_PARAM, &calc_ha1            },
	{"use_domain",        INT_PARAM, &use_domain          },
	{"load_credentials",  STR_PARAM, &credentials_list    },
	{"skip_version_check",INT_PARAM, &skip_version_check  },
	{0, 0, 0}
};


static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "auth", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

/*
 * Module interface
 */
struct module_exports exports = {
	"auth_db",
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
	auth_db_handle = auth_dbf.init(&db_url);
	if (auth_db_handle == 0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}


static int mod_init(void)
{
	bind_auth_t bind_auth;

	LM_INFO("initializing...\n");

	init_db_url( db_url , 0 /*cannot be null*/);
	user_column.len = strlen(user_column.s);
	domain_column.len = strlen(domain_column.s);
	pass_column.len = strlen(pass_column.s);
	pass_column_2.len = strlen(pass_column_2.s);

	uri_user_column.len = strlen(uri_user_column.s);
	uri_domain_column.len = strlen(uri_domain_column.s);
	uri_uriuser_column.len = strlen(uri_uriuser_column.s);

	/* Find a database module */
	if (db_bind_mod(&db_url, &auth_dbf) < 0){
		LM_ERR("unable to bind to a database driver\n");
		return -1;
	}

	/* bind to auth module and import the API */
	bind_auth = (bind_auth_t)find_export("bind_auth", 0);
	if (!bind_auth) {
		LM_ERR("unable to find bind_auth function."
			" Check if you load the auth module.\n");
		return -2;
	}

	if (bind_auth(&auth_api) < 0) {
		LM_ERR("unable to bind auth module\n");
		return -3;
	}

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0) {
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	/* process additional list of credentials */
	if (parse_aaa_avps( credentials_list, &credentials, &credentials_n)!=0) {
		LM_ERR("failed to parse credentials\n");
		return -5;
	}

	return 0;
}


static void destroy(void)
{
	if (credentials) {
		free_aaa_avp_list(credentials);
		credentials = 0;
		credentials_n = 0;
	}
}

static int auth_fixup_table(void** param)
{
	db_con_t *dbh = NULL;

	dbh = auth_dbf.init(&db_url);
	if (!dbh) {
		LM_ERR("unable to open database connection\n");
		return -1;
	}
	if(skip_version_check == 0 &&
	db_check_table_version(&auth_dbf, dbh, (str*)*param,
	SUBSCRIBER_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		auth_dbf.close(dbh);
		return -1;
	}
	auth_dbf.close(dbh);

	return 0;
}

static int fixup_check_outvar(void **param)
{
	if (((pv_spec_t*)*param)->type != PVT_AVP &&
		((pv_spec_t*)*param)->type != PVT_SCRIPTVAR) {
		LM_ERR("return must be an AVP or SCRIPT VAR!\n");
		return E_SCRIPT;
	}

	return 0;
}
