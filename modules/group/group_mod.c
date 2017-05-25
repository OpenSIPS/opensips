/*
 * Group membership - module interface
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
 * History:
 * --------
 *  2003-02-25 - created by janakj
 *  2003-03-11 - New module interface (janakj)
 *  2003-03-16 - flags export parameter added (janakj)
 *  2003-03-19  all mallocs/frees replaced w/ pkg_malloc/pkg_free
 *  2003-04-05  default_uri #define used (jiri)
 *  2004-06-07  updated to the new DB api: calls to group_db_* (andrei)
 *  2005-10-06 - added support for regexp-based groups (bogdan)
 *  2008-12-26  pseudovar argument for group parameter at is_user_in (saguti).
 *  2009-08-07 - joined with group_radius module to support generic AAA group
 *		requests (Irina Stanescu)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "group_mod.h"
#include "group.h"
#include "re_group.h"
#include "../../mod_fix.h"
#include "../../aaa/aaa.h"



#define TABLE_VERSION    3
#define RE_TABLE_VERSION 2

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

static int aaa_is_user_fixup(void** param, int param_no);
static int db_is_user_fixup(void** param, int param_no);
static int db_get_gid_fixup(void** param, int param_no);

static int obsolete_fixup_0(void** param, int param_no);
static int obsolete_fixup_1(void** param, int param_no);

#define TABLE "grp"
#define TABLE_LEN (sizeof(TABLE) - 1)

#define USER_COL "username"
#define USER_COL_LEN (sizeof(USER_COL) - 1)

#define DOMAIN_COL "domain"
#define DOMAIN_COL_LEN (sizeof(DOMAIN_COL) - 1)

#define GROUP_COL "grp"
#define GROUP_COL_LEN (sizeof(GROUP_COL) - 1)

#define RE_TABLE "re_grp"
#define RE_TABLE_LEN (sizeof(TABLE) - 1)

#define RE_EXP_COL "reg_exp"
#define RE_EXP_COL_LEN (sizeof(USER_COL) - 1)

#define RE_GID_COL "group_id"
#define RE_GID_COL_LEN (sizeof(DOMAIN_COL) - 1)

/*
 * Module parameter variables
 */
static str db_url = {NULL, 0};
static str aaa_proto_url = {NULL, 0};

/* Table name where group definitions are stored */
str table         = {TABLE, TABLE_LEN};
str user_column   = {USER_COL, USER_COL_LEN};
str domain_column = {DOMAIN_COL, DOMAIN_COL_LEN};
str group_column  = {GROUP_COL, GROUP_COL_LEN};
int use_domain    = 0;

/* tabel and columns used for re-based groups */
str re_table      = {0, 0};
str re_exp_column = {RE_EXP_COL, RE_EXP_COL_LEN};
str re_gid_column = {RE_GID_COL, RE_GID_COL_LEN};
int multiple_gid  = 1;

/* DB functions and handlers */
db_func_t group_dbf;
db_con_t* group_dbh = 0;

aaa_conn *conn = NULL;
aaa_prot proto = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};

aaa_map attrs[A_MAX];
aaa_map vals[V_MAX];

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"is_user_in",      (cmd_function)NULL, 2,  obsolete_fixup_0, 0,
			REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"get_user_group",  (cmd_function)NULL, 2,  obsolete_fixup_1, 0,
			REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"aaa_is_user_in", (cmd_function)aaa_is_user_in, 2, aaa_is_user_fixup,     0,
			REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"db_is_user_in",      (cmd_function)db_is_user_in, 2, db_is_user_fixup, 0,
			REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"db_get_user_group",  (cmd_function)get_user_group, 2, db_get_gid_fixup, 0,
			REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"aaa_url", 	  STR_PARAM, &aaa_proto_url.s},
	{"db_url",        STR_PARAM, &db_url.s       },
	{"table",         STR_PARAM, &table.s        },
	{"user_column",   STR_PARAM, &user_column.s  },
	{"domain_column", STR_PARAM, &domain_column.s},
	{"group_column",  STR_PARAM, &group_column.s },
	{"use_domain",    INT_PARAM, &use_domain     },
	{"re_table",      STR_PARAM, &re_table.s     },
	{"re_exp_column", STR_PARAM, &re_exp_column.s},
	{"re_gid_column", STR_PARAM, &re_gid_column.s},
	{"multiple_gid",  INT_PARAM, &multiple_gid   },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_AAA, NULL, DEP_SILENT },
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
	"group",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
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
	destroy,    /* destroy function */
	child_init  /* child initialization function */
};


static int child_init(int rank)
{
	if (db_url.s)
		return group_db_init(&db_url);

	LM_DBG("db_url is null\n");
	return 0;

}


static int mod_init(void)
{
	LM_DBG("group module - initializing\n");

	/* check for a database module */
	if (db_url.s) {

		db_url.len = strlen(db_url.s);
		table.len = strlen(table.s);
		user_column.len = strlen(user_column.s);
		domain_column.len = strlen(domain_column.s);
		group_column.len = strlen(group_column.s);

		re_table.len = (re_table.s && re_table.s[0])?strlen(re_table.s):0;
		re_exp_column.len = strlen(re_exp_column.s);
		re_gid_column.len = strlen(re_gid_column.s);

		if (group_db_bind(&db_url)) {
			LM_ERR("unable to bind database module\n");
			return -1;
		}

		if (group_db_init(&db_url) < 0 ){
			LM_ERR("unable to open database connection\n");
			return -1;
		}

		/* check version for group table */
		if (db_check_table_version(&group_dbf, group_dbh, &table, TABLE_VERSION) < 0) {
			LM_ERR("error during group table version check.\n");
			return -1;
		}

		if (re_table.len) {
			/* check version for group re_group table */
			if (db_check_table_version(&group_dbf, group_dbh, &re_table, RE_TABLE_VERSION) < 0) {
				LM_ERR("error during re_group table version check.\n");
				return -1;
			}
			if (load_re( &re_table )!=0 ) {
				LM_ERR("failed to load <%s> table\n", re_table.s);
				return -1;
			}
		}

		group_db_close();

		LM_DBG("group database loaded\n");
	}

	/* check for an aaa module */
	if (aaa_proto_url.s) {

		aaa_proto_url.len = strlen(aaa_proto_url.s);

		memset(attrs, 0, sizeof(attrs));
		memset(vals, 0, sizeof(vals));
		attrs[A_SERVICE_TYPE].name		= "Service-Type";
		attrs[A_USER_NAME].name			= "User-Name";
		attrs[A_SIP_GROUP].name			= "Sip-Group";
		attrs[A_ACCT_SESSION_ID].name	= "Acct-Session-Id";
		vals[V_GROUP_CHECK].name		= "Group-Check";

		if (aaa_prot_bind(&aaa_proto_url, &proto)) {
			LM_ERR("unable to bind aaa protocol module\n");
			return -1;
		}

		if (!(conn = proto.init_prot(&aaa_proto_url))) {
			LM_ERR("unable to initialize aaa protocol module\n");
			return -1;
		}

		INIT_AV(proto, conn, attrs, A_MAX, vals, V_MAX, "group", -3, -4);

		LM_DBG("aaa protocol module loaded\n");
	}

	return 0;
}


static void destroy(void)
{
	if (!db_url.s)
		group_db_close();
}


static int obsolete_fixup_0(void** param, int param_no) {

	LM_ERR("You are using is_user_in function that is now obsolete. \
If you want to use it with DB support, use db_is_user_in. \
If you want to use it with AAA support, use aaa_is_user_in.\n");

	return E_CFG;
}

static int obsolete_fixup_1(void** param, int param_no) {

	LM_ERR("You are get_user_group function that has been renamed\
into db_get_user_group\n");

	return E_CFG;
}

static int db_get_gid_fixup(void** param, int param_no)
{
	pv_spec_t *sp;
	str  name;

	if (!db_url.s) {
		LM_ERR("no database url\n");
		return E_CFG;
	}

	if (param_no == 1) {
		return fixup_spve_spve(param, param_no);
	} else if (param_no == 2) {
		name.s = (char*)*param;
		name.len = strlen(name.s);
		sp = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
		if (sp == NULL) {
			LM_ERR("no more pkg memory\n");
			return E_UNSPEC;
		}
		if(pv_parse_spec(&name, sp)==NULL || sp->type!=PVT_AVP)
		{
			LM_ERR("bad AVP spec <%s>\n", name.s);
			pv_spec_free(sp);
			return E_UNSPEC;
		}

		*param = sp;
	}

	return 0;
}


static int aaa_is_user_fixup(void** param, int param_no)
{
	void* ptr;
	str* s;

	if (!aaa_proto_url.s) {
		LM_ERR("no aaa protocol url\n");
		return E_CFG;
	}

	if (param_no == 1) {
		ptr = *param;

		if (!strcasecmp((char*)*param, "Request-URI")) {
			*param = (void*)1;
		} else if (!strcasecmp((char*)*param, "To")) {
			*param = (void*)2;
		} else if (!strcasecmp((char*)*param, "From")) {
			*param = (void*)3;
		} else if (!strcasecmp((char*)*param, "Credentials")) {
			*param = (void*)4;
		} else {
			LM_ERR("unsupported Header Field identifier\n");
			return E_UNSPEC;
		}

		pkg_free(ptr);
	} else if (param_no == 2) {

		s = (str*)pkg_malloc(sizeof(str));
		if (!s) {
			LM_ERR("no pkg memory left\n");
			return E_UNSPEC;
		}

		s->s = (char*)*param;
		s->len = strlen(s->s);
		*param = (void*)s;
	}

	return 0;
}


static int db_is_user_fixup(void** param, int param_no) {

	if (db_url.s) {
		fixup_spve_spve(param, param_no);
		return 0;
	}

	LM_ERR("no database url\n");
	return E_CFG;
}
