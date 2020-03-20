/*
 * JWT Authentication Module
 *
 * Copyright (C) 2020 OpenSIPS Project
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * --------
 * 2020-03-12 initial release (vlad)
 */

#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "jwt_avps.h"
#include "authorize.h"

/*
 * Version of JWT profiles & secrets required by the module,
 * increment this value if you change the table in
 * an backwards incompatible way
 */
#define PROFILES_TABLE_VERSION	1
#define SECRETS_TABLE_VERSION	1

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
static int fixup_check_outvar(void **param);

/* profile columns */
#define TAG_COL "tag"
#define TAG_COL_LEN (sizeof(TAG_COL) - 1)
#define USER_COL "sip_username"
#define USER_COL_LEN (sizeof(USER_COL) - 1)

/* secrets columns */
#define SECRET_TAG_COL "corresponding_tag"
#define SECRET_TAG_COL_LEN (sizeof(SECRET_TAG_COL) - 1)
#define SECRET_COL "secret"
#define SECRET_COL_LEN (sizeof(SECRET_COL) - 1)
#define START_TS_COL "start_ts"
#define START_TS_COL_LEN (sizeof(START_TS_COL) - 1)
#define END_TS_COL "end_ts"
#define END_TS_COL_LEN (sizeof(END_TS_COL) - 1)

/*
 * Module parameter variables
 */
static str db_url           = {NULL,0};

str profiles_table          = str_init("jwt_profiles");
str secrets_table           = str_init("jwt_secrets");
str tag_column              = {TAG_COL, TAG_COL_LEN};
str username_column         = {USER_COL, USER_COL_LEN};
str secret_tag_column       = {SECRET_TAG_COL, SECRET_TAG_COL_LEN};
str secret_column           = {SECRET_COL, SECRET_COL_LEN};
str start_ts_column         = {START_TS_COL, START_TS_COL_LEN};
str end_ts_column           = {END_TS_COL, END_TS_COL_LEN};

str jwt_tag_claim           = {TAG_COL, TAG_COL_LEN};

db_con_t* auth_db_handle    = 0; /* database connection handle */
db_func_t auth_dbf;

char *jwt_credentials_list      = "";
struct jwt_avp *jwt_credentials = 0; /* Parsed list of credentials to load */
int jwt_credentials_n           = 0; /* Number of credentials in the list */

/*
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"jwt_authorize", (cmd_function)jwt_authorize, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_outvar, 0},
		{CMD_PARAM_VAR, fixup_check_outvar, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",            STR_PARAM, &db_url.s                },
	{"profiles_table",    STR_PARAM, &profiles_table.s        },
	{"secrets_table",     STR_PARAM, &secrets_table.s         },
	{"tag_column",        STR_PARAM, &tag_column.s            },
	{"username_column",   STR_PARAM, &username_column.s       },
	{"secret_tag_column", STR_PARAM, &secret_tag_column.s     },
	{"secret_column",     STR_PARAM, &secret_column.s         },
	{"start_ts_column",   STR_PARAM, &start_ts_column.s       },
	{"end_ts_column",     STR_PARAM, &end_ts_column.s         },
	{"tag_claim",         STR_PARAM, &jwt_tag_claim.s         },
	{"load_credentials",  STR_PARAM, &jwt_credentials_list    },
	{0, 0, 0}
};


static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
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
	"auth_jwt",
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
	0,   	    /* exported transformations */
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
	LM_INFO("initializing...\n");

	init_db_url( db_url , 0 /*cannot be null*/);

	profiles_table.len = strlen(profiles_table.s);
	secrets_table.len = strlen(secrets_table.s);
	tag_column.len = strlen(tag_column.s);
	username_column.len = strlen(username_column.s);
	secret_tag_column.len = strlen(secret_tag_column.s);
	secret_column.len = strlen(secret_column.s);
	start_ts_column.len = strlen(start_ts_column.s);
	end_ts_column.len = strlen(end_ts_column.s);
	jwt_tag_claim.len = strlen(jwt_tag_claim.s);

	/* Find a database module */
	if (db_bind_mod(&db_url, &auth_dbf) < 0){
		LM_ERR("unable to bind to a database driver\n");
		return -1;
	}

	/* process additional list of credentials */
	if (parse_jwt_avps( jwt_credentials_list, &jwt_credentials, &jwt_credentials_n)!=0) {
		LM_ERR("failed to parse credentials\n");
		return -5;
	}

	auth_db_handle = auth_dbf.init(&db_url);
	if (auth_db_handle == 0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if (db_check_table_version(&auth_dbf, auth_db_handle, &profiles_table,
	PROFILES_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		auth_dbf.close(auth_db_handle);
		return -1;
	}

	if (db_check_table_version(&auth_dbf, auth_db_handle, &secrets_table,
	SECRETS_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		auth_dbf.close(auth_db_handle);
		return -1;
       	}

	auth_dbf.close(auth_db_handle);
	return 0;
}


static void destroy(void)
{
	if (jwt_credentials) {
		free_jwt_avp_list(jwt_credentials);
		jwt_credentials = 0;
		jwt_credentials_n = 0;
	}
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
