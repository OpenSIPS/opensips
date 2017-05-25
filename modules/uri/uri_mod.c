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
#include "checks.h"
#include "aaa_checks.h"
#include "db_checks.h"



/*
 * AAA protocol variables
 */
aaa_map attrs[A_MAX];
aaa_map vals[V_MAX];
aaa_conn *conn;
aaa_prot proto;

/*
 * Version of domain table required by the module,
 * increment this value if you change the table in
 * an backwards incompatible way
 */
#define URI_TABLE_VERSION 2
#define SUBSCRIBER_TABLE_VERSION 7


static int mod_init(void); /* Module initialization function */
static void destroy(void);       /* Module destroy function */
static int child_init(int rank); /* Per-child initialization function */

#define URI_TABLE "uri"

#define SUBSCRIBER_TABLE "subscriber"

#define USER_COL "username"
#define USER_COL_LEN (sizeof(USER_COL) - 1)

#define DOMAIN_COL "domain"
#define DOMAIN_COL_LEN (sizeof(DOMAIN_COL) - 1)

#define URI_USER_COL "uri_user"
#define URI_USER_COL_LEN (sizeof(URI_USER_COL) - 1)


/*
 * Module parameter variables
 */
static char *aaa_proto_url = NULL;
static int service_type = -1;
int use_sip_uri_host = 0;
static str db_url         = {NULL, 0};
str db_table              = {NULL, 0};
str uridb_user_col        = {USER_COL, USER_COL_LEN};
str uridb_domain_col      = {DOMAIN_COL, DOMAIN_COL_LEN};
str uridb_uriuser_col     = {URI_USER_COL, URI_USER_COL_LEN};

int use_uri_table = 0;     /* Should uri table be used */
int use_domain = 0;        /* Should does_uri_exist honor the domain part ? */

static int db_checks_fixup1(void** param, int param_no);
static int db_checks_fixup2(void** param, int param_no);
static int db_fixup_get_auth_id(void** param, int param_no);

static int aaa_fixup_0(void** param, int param_no);
static int aaa_fixup_1(void** param, int param_no);

static int obsolete_fixup_0(void** param, int param_no);
static int obsolete_fixup_1(void** param, int param_no);
static int obsolete_fixup_2(void** param, int param_no);
/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"check_to", (cmd_function)NULL, 0, obsolete_fixup_0, 0,
			REQUEST_ROUTE},
	{"check_from", (cmd_function)NULL, 0, obsolete_fixup_0, 0,
			REQUEST_ROUTE},
	{"does_uri_exist", (cmd_function)NULL, 0, obsolete_fixup_1, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"does_uri_exist", (cmd_function)NULL, 1, obsolete_fixup_1, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"get_auth_id", (cmd_function)NULL, 3, obsolete_fixup_0, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"does_uri_user_exist", (cmd_function)NULL, 0, obsolete_fixup_2, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"does_uri_user_exist", (cmd_function)NULL, 1, obsolete_fixup_2, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
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
	{"db_check_to", (cmd_function)check_to, 0, db_checks_fixup2, 0,
			REQUEST_ROUTE},
	{"db_check_from", (cmd_function)check_from, 0, db_checks_fixup2, 0,
			REQUEST_ROUTE},
	{"db_does_uri_exist", (cmd_function)does_uri_exist, 0,
			db_checks_fixup1, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"db_get_auth_id", (cmd_function) get_auth_id, 3,
			db_fixup_get_auth_id, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"is_user", (cmd_function)is_user, 1,
			fixup_str_null, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"has_totag", (cmd_function)has_totag, 0, 0, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"uri_param", (cmd_function)uri_param_1, 1,
			fixup_str_null, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"uri_param", (cmd_function)uri_param_2, 2,
			fixup_str_str, 0,
			REQUEST_ROUTE|LOCAL_ROUTE},
	{"add_uri_param", (cmd_function)add_uri_param, 1,
			fixup_str_null, 0,
			REQUEST_ROUTE},
	{"del_uri_param", (cmd_function)del_uri_param, 1,
			fixup_str_null, 0,
			REQUEST_ROUTE},
	{"tel2sip", (cmd_function)tel2sip, 0, 0, 0,
			REQUEST_ROUTE},
	{"is_uri_user_e164", (cmd_function)is_uri_user_e164, 1,
			fixup_pvar_null, fixup_free_pvar_null,
			REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"aaa_url", 				 STR_PARAM, &aaa_proto_url},
	{"db_url",                   STR_PARAM, &db_url.s               },
	{"db_table",                 STR_PARAM, &db_table.s             },
	{"user_column",              STR_PARAM, &uridb_user_col.s       },
	{"domain_column",            STR_PARAM, &uridb_domain_col.s     },
	{"uriuser_column",           STR_PARAM, &uridb_uriuser_col.s    },
	{"use_uri_table",            INT_PARAM, &use_uri_table          },
	{"use_domain",               INT_PARAM, &use_domain             },
	{"service_type", 			 INT_PARAM, &service_type},
	{"use_sip_uri_host", 		 INT_PARAM, &use_sip_uri_host},
	{0, 0, 0}
};


/*
 *  * Module statistics
 *   */

static stat_export_t uridb_stats[] = {
	{"positive checks" ,  0,  &positive_checks  },
	{"negative_checks" ,  0,  &negative_checks  },
	{0,0,0}
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
		{ "db_url",  get_deps_sqldb_url },
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
	uridb_stats, /* exported statistics */
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
	int checkver=-1;
	db_func_t db_funcs;
	db_con_t *db_conn = NULL;

	LM_DBG("initializing\n");

	init_db_url( db_url , 1 /*can be null*/);
	if (db_url.s) {
		if (db_url.len == 0) {
			if (use_uri_table != 0) {
				LM_ERR("configuration error - no database URL, "
					"but use_uri_table is set!\n");
				return -1;
			}
			return 0;
		}

		if (db_table.s == NULL) {
			/* no table set -> use defaults */
			if (use_uri_table != 0){
				db_table.s = URI_TABLE;
			}
			else {
				db_table.s = SUBSCRIBER_TABLE;
			}
		}

		db_table.len = strlen(db_table.s);
		uridb_user_col.len = strlen(uridb_user_col.s);
		uridb_domain_col.len = strlen(uridb_domain_col.s);
		uridb_uriuser_col.len = strlen(uridb_uriuser_col.s);

		if ( db_bind_mod(&db_url, &db_funcs) != 0 ) {
			LM_ERR("No database module found\n");
			return -1;
		}

		db_conn = db_funcs.init(&db_url);
		if( db_conn == NULL ) {
			LM_ERR("Could not connect to database\n");
			return -1;
		}

		checkver = db_check_table_version( &db_funcs, db_conn, &db_table,
			use_uri_table?URI_TABLE_VERSION:SUBSCRIBER_TABLE_VERSION );

		/** If checkver == -1, table validation failed */
		if( checkver == -1 ) {
			LM_ERR("Invalid table version.\n");
			db_funcs.close(db_conn);
			return -1;
		}

		db_funcs.close(db_conn);

		/* done with checkings - init the working connection */
		if (uridb_db_bind(&db_url)!=0) {
			LM_ERR("Failed to bind to a DB module\n");
			return -1;
		}
	}


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
	if (db_url.len != 0)
		return uridb_db_init(&db_url);
	else
		return 0;
}

static void destroy(void)
{
	if (db_url.len != 0)
		uridb_db_close();
}


static int db_checks_fixup1(void** param, int param_no)
{
	if (db_url.len == 0) {
		LM_ERR("configuration error - no database URL is configured!\n");
		return E_CFG;
	}
	return 0;
}

static int db_checks_fixup2(void** param, int param_no)
{
	if (use_uri_table && db_url.len == 0) {
		LM_ERR("configuration error - no database URL is configured!\n");
		return E_CFG;
	}
	return 0;
}



static int obsolete_fixup_0(void** param, int param_no) {

	LM_ERR("You are using one of these obsolete functions\
: \"check_to\", \"check_from\", \"does_uri_exist\",\"get_auth_id\".\
 They have been renamed with the \"db_\" prefix.\n");

	return E_CFG;
}

static int obsolete_fixup_1(void** param, int param_no) {

	LM_ERR("You are using does_uri_exist function that is now obsolete. \
If you want to use it with DB support, use db_does_uri_exist. \
If you want to use it with AAA support, use aaa_does_uri_exist.\n");

	return E_CFG;
}

static int obsolete_fixup_2(void** param, int param_no) {

	LM_ERR("You are using does_uri_user_exist function that has been renamed\
into aaa_does_uri_user_exist.\n");

	return E_CFG;
}

/**
 * Check proper configuration for 'get_auth_id()' and convert function parameters.
 */
static int db_fixup_get_auth_id(void** param, int param_no)
{
	pv_elem_t *model = NULL;
	pv_spec_t *sp;
	str s;
	int ret;

	// just to avoid doing the folowing checks multiple times
	// currently unnecessary because only one check is done
	//if (param_no == 1) {
		if (db_url.len == 0) {
			LM_ERR("configuration error - 'get_auth_id()' requires a configured database backend");
			return E_CFG;
		}
	//}

	if (param_no > 0 && param_no <= 3) {
		switch (param_no) {
			case 1:		// pv which contains the sip id searched for
				s.s = (char*) (*param);
				s.len = strlen(s.s);
				if (s.len == 0) {
					LM_ERR("param %d is empty string!\n", param_no);
					return E_CFG;
				}
				if(pv_parse_format(&s ,&model) || model == NULL) {
					LM_ERR("wrong format [%s] for value param!\n", s.s);
					return E_CFG;
				}
				*param = (void*) model;
				break;

			case 2:		// pv to return the result auth id
			case 3:		// pv to return the result auth realm
				ret = fixup_pvar(param);
				if (ret < 0) return ret;
				sp = (pv_spec_t*) (*param);
				if (sp->type != PVT_AVP && sp->type != PVT_SCRIPTVAR) {
					LM_ERR("return must be an AVP or SCRIPT VAR!\n");
					return E_SCRIPT;
				}
				break;
		}

	} else {
		LM_ERR("wrong number of parameters\n");
		return E_UNSPEC;
	}

	return 0;
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


