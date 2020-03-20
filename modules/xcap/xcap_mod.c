/*
 * xcap module - XCAP operations module
 *
 * Copyright (C) 2012 AG Projects
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
#include "xcap_mod.h"
#include "api.h"


#define XCAP_TABLE_VERSION   4

/* database connection */
db_con_t *xcap_db = NULL;
db_func_t xcap_dbf;

/* module variables */
str xcap_table = str_init("xcap");
str xcap_db_url = {NULL, 0};
int integrated_xcap_server = 0;

str xcap_username_col = str_init("username");
str xcap_domain_col = str_init("domain");
str xcap_doc_col = str_init("doc");
str xcap_doc_type_col = str_init("doc_type");
str xcap_doc_uri_col = str_init("doc_uri");
str xcap_doc_etag_col = str_init("etag");


/* module functions */
static int mod_init(void);
static int child_init(int);
void destroy(void);

static cmd_export_t cmds[]=
{
	{ "bind_xcap", (cmd_function)bind_xcap, {{0, 0, 0}}, 0},
	{ 0, 0, {{0, 0, 0}}, 0}
};

static param_export_t params[]={
	{ "db_url",                 STR_PARAM, &xcap_db_url.s          },
	{ "xcap_table",             STR_PARAM, &xcap_table.s           },
	{ "integrated_xcap_server", INT_PARAM, &integrated_xcap_server },
	{ 0, 0, 0 }
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

/** module exports */
struct module_exports exports = {
	"xcap",                     /* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,				            /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,							/* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};



static int mod_init(void)
{
	init_db_url(xcap_db_url , 0 /*cannot be null*/);
	xcap_table.len = strlen(xcap_table.s);

	if (db_bind_mod(&xcap_db_url, &xcap_dbf))
	{
		LM_ERR("Database module not found\n");
		return -1;
	}

	if (!DB_CAPABILITY(xcap_dbf, DB_CAP_ALL))
	{
		LM_ERR("Database module does not implement all functions needed by the module\n");
		return -1;
	}

	xcap_db = xcap_dbf.init(&xcap_db_url);
	if (!xcap_db)
	{
		LM_ERR("while connecting to database\n");
		return -1;
	}

	if(db_check_table_version(&xcap_dbf, xcap_db, &xcap_table, XCAP_TABLE_VERSION) < 0)
	{
		LM_ERR("error during table version check.\n");
		return -1;
	}

	if(xcap_db)
		xcap_dbf.close(xcap_db);
	xcap_db = NULL;

	return 0;
}


static int child_init(int rank)
{
	if (xcap_dbf.init == 0)
	{
		LM_CRIT("child_init: database not bound\n");
		return -1;
	}

	xcap_db = xcap_dbf.init(&xcap_db_url);
	if (!xcap_db)
	{
		LM_ERR("child %d: unsuccessful connecting to database\n", rank);
		return -1;
	}

	return 0;
}


void destroy(void)
{
}

