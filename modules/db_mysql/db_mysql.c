/*
 * MySQL module interface
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2008 1&1 Internet AG
 * Copyright (C) 2016 OpenSIPS Solutions
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
 */
/*
 * History:
 * --------
 *  2003-03-11  updated to the new module exports interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 */

#define _GNU_SOURCE

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../db/db_cap.h"
#include "../tls_mgm/api.h"

#include "dbase.h"
#include "db_mysql.h"

#include <mysql.h>


unsigned int db_mysql_timeout_interval = 2;   /* Default is 6 seconds */
unsigned int db_mysql_exec_query_threshold = 0;   /* Warning in case DB query
											takes too long disabled by default*/
int max_db_retries = 3;
int max_db_queries = 2;

static int mysql_mod_init(void);

int db_mysql_bind_api(const str* mod, db_func_t *dbb);

/*
 * MySQL database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api",         (cmd_function)db_mysql_bind_api,      {{0, 0, 0}}, 0},
	{0, 0, {{0, 0, 0}}, 0}
};

struct tls_mgm_binds tls_api;
struct tls_domain *tls_dom;
int use_tls;

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"timeout_interval", INT_PARAM, &db_mysql_timeout_interval},
	{"exec_query_threshold", INT_PARAM, &db_mysql_exec_query_threshold},
	{"max_db_retries", INT_PARAM, &max_db_retries},
	{"max_db_queries", INT_PARAM, &max_db_queries},
	{"use_tls", INT_PARAM, &use_tls},
	{0, 0, 0}
};

static module_dependency_t *get_deps_use_tls(param_export_t *param)
{
	if (*(int *)param->param_pointer == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "tls_mgm", DEP_ABORT);
}

static dep_export_t deps = {
	{
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{
		{ "use_tls", get_deps_use_tls },
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"db_mysql",
	MOD_TYPE_SQLDB,  /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	0,               /* exported async functions */
	params,          /* module parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mysql_mod_init,  /* module initialization function */
	0,               /* response function*/
	0,               /* destroy function */
	0,               /* per-child init function */
	0                /* reload confirm function */
};


static int mysql_mod_init(void)
{
	LM_DBG("mysql: MySQL client version is %s\n", mysql_get_client_info());
	/* also register the event */
	if (mysql_register_event() < 0) {
		LM_ERR("Cannot register mysql event\n");
		return -1;
	}
	
	if(max_db_queries < 1){
		LM_WARN("Invalid number for max_db_queries\n");
		max_db_queries = 2;
	}
	
	if(max_db_retries < 0){
		LM_WARN("Invalid number for max_db_retries\n");
		max_db_retries = 3;
	}

	if (use_tls && load_tls_mgm_api(&tls_api) != 0) {
		LM_ERR("failed to load tls_mgm API!\n");
		return -1;
	}

	return 0;
}

int db_mysql_bind_api(const str* mod, db_func_t *dbb)
{
	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table         = db_mysql_use_table;
	dbb->init              = db_mysql_init;
	dbb->close             = db_mysql_close;
	dbb->query             = db_mysql_query;
	dbb->fetch_result      = db_mysql_fetch_result;
	dbb->raw_query         = db_mysql_raw_query;
	dbb->free_result       = db_mysql_free_result;
	dbb->insert            = db_mysql_insert;
	dbb->delete            = db_mysql_delete;
	dbb->update            = db_mysql_update;
	dbb->replace           = db_mysql_replace;
	dbb->last_inserted_id  = db_last_inserted_id;
	dbb->insert_update     = db_insert_update;
	dbb->async_raw_query   = db_mysql_async_raw_query;
	dbb->async_resume      = db_mysql_async_resume;
	dbb->async_free_result = db_mysql_async_free_result;

	dbb->cap |= DB_CAP_MULTIPLE_INSERT;
	return 0;
}

