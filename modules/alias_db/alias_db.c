/*
 * ALIAS_DB Module
 *
 * Copyright (C) 2004-2009 Voice Sistem SRL
 *
 * This file is part of a module for opensips, a free SIP server.
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
 * 2004-09-01: first version (ramona)
 * 2009-04-30: alias_db_find() added; NO_DOMAIN and REVERT flags added;
 *             use_domain param removed (bogdan)
 */


#include <stdio.h>
#include <string.h>
#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../ut.h"

#include "alookup.h"


/* Module destroy function prototype */
static void destroy(void);


/* Module child-init function prototype */
static int child_init(int rank);


/* Module initialization function prototype */
static int mod_init(void);

/* Fixup functions */
static int alias_flags_fixup(void** param);
static int fixup_check_wr_var(void **param);

/* Module parameter variables */
static str db_url       = {NULL,0};
str user_column         = str_init("username");
str domain_column       = str_init("domain");
str alias_user_column   = str_init("alias_username");
str alias_domain_column = str_init("alias_domain");
str domain_prefix       = {NULL, 0};
int ald_append_branches = 0;

db_con_t* db_handle;   /* Database connection handle */
db_func_t adbf;  /* DB functions */

/* Exported functions */
static cmd_export_t cmds[] = {
	{"alias_db_lookup", (cmd_function)alias_db_lookup, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, alias_flags_fixup ,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"alias_db_find", (cmd_function)alias_db_find, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_check_wr_var, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, alias_flags_fixup ,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* Exported parameters */
static param_export_t params[] = {
	{"db_url",              STR_PARAM, &db_url.s        },
	{"user_column",         STR_PARAM, &user_column.s   },
	{"domain_column",       STR_PARAM, &domain_column.s },
	{"alias_user_column",   STR_PARAM, &alias_user_column.s   },
	{"alias_domain_column", STR_PARAM, &alias_domain_column.s },
	{"domain_prefix",       STR_PARAM, &domain_prefix.s },
	{"append_branches",     INT_PARAM, &ald_append_branches   },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* Module interface */
struct module_exports exports = {
	"alias_db",
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
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* child initialization function */
	0           /* reload confirm function */
};


static int alias_flags_fixup(void** param)
{
	unsigned int flags;
	int i;
	str *s = (str*)*param;

	flags = 0;
	for (i = 0; i < s->len; i++)
		switch (s->s[i]) {
			case 'r':
			case 'R':
				flags |= ALIAS_REVERT_FLAG;
				break;
			case 'd':
			case 'D':
				flags |= ALIAS_NO_DOMAIN_FLAG;
				break;
			default:
				LM_ERR("unsupported flag '%c'\n", s->s[i]);
				return -1;
		}

	*param = (void*)(unsigned long)flags;
	return 0;
}


static int fixup_check_wr_var(void **param)
{
	if (((pv_spec_t*)*param)->setf==NULL) {
		LM_ERR("PV type %d cannot be written\n", ((pv_spec_t*)*param)->type);
		return E_CFG;
	}

	return 0;
}


/**
 *
 */
static int child_init(int rank)
{
	db_handle = adbf.init(&db_url);
	if (!db_handle)
	{
		LM_ERR("unable to connect database\n");
		return -1;
	}
	return 0;

}


/**
 *
 */
static int mod_init(void)
{
	LM_INFO("initializing...\n");
	init_db_url( db_url , 0 /*cannot be null*/);
	user_column.len = strlen(user_column.s);
	domain_column.len = strlen(domain_column.s);
	alias_domain_column.len = strlen(alias_domain_column.s);
	alias_user_column.len = strlen(alias_user_column.s);
	if (domain_prefix.s)
		domain_prefix.len = strlen(domain_prefix.s);

	/* Find a database module */
	if (db_bind_mod(&db_url, &adbf)) {
		LM_ERR("unable to bind database module\n");
		return -1;
	}
	if (!DB_CAPABILITY(adbf, DB_CAP_QUERY)) {
		LM_CRIT("database modules does not "
			"provide all functions needed by alias_db module\n");
		return -1;
	}

	return 0;
}


/**
 *
 */
static void destroy(void)
{
}

