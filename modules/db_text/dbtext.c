/*
 * DBText module interface
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
 * 2003-01-30 created by Daniel
 * 2003-03-11 New module interface (janakj)
 * 2003-03-16 flags export parameter added (janakj)
 *
 */

#include <stdio.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../db/db.h"
#include "dbtext.h"
#include "dbt_lib.h"
#include "dbt_api.h"



static int mod_init(void);
static void destroy(void);

static mi_response_t *mi_dbt_dump(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_dbt_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_dbt_reload_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_dbt_reload_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

/*
 * Module parameter variables
 */
int db_mode = 0;  /* Database usage mode: 0 = cache, 1 = no cache */

int dbt_bind_api(const str* mod, db_func_t *dbb);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"db_bind_api", (cmd_function)dbt_bind_api, {{0,0,0}}, 0},
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_mode", INT_PARAM, &db_mode},
	{0, 0, 0}
};


/** MI commands */
static mi_export_t mi_cmds[] = {
	{"dbt_dump", 0, 0, 0, {
		{mi_dbt_dump, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"dbt_reload", 0, 0, 0, {
		{mi_dbt_reload, {0}},
		{mi_dbt_reload_1, {"db_name", 0}},
		{mi_dbt_reload_2, {"db_name", "table_name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

struct module_exports exports = {
	"db_text",
	MOD_TYPE_SQLDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	NULL,     /* Exported async functions */
	params,   /* Exported parameters */
	NULL,     /* exported statistics */
	mi_cmds,  /* exported MI functions */
	NULL,     /* exported pseudo-variables */
	0,		  /* exported transformations */
	0,        /* extra processes */
	0,        /* module pre-initialization function */
	mod_init, /* module initialization function */
	NULL,     /* response function*/
	destroy,  /* destroy function */
	NULL,     /* per-child init function */
	NULL      /* reload confirm function */
};


static int mod_init(void)
{
	if(dbt_init_cache())
		return -1;
	/* return make_demo(); */

	return 0;
}

static void destroy(void)
{
	LM_DBG("destroy ...\n");
	dbt_cache_print(0);
	dbt_cache_destroy();
}



int dbt_bind_api(const str* mod, db_func_t *dbb)
{
	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table   = dbt_use_table;
	dbb->init        = dbt_init;
	dbb->close       = dbt_close;
	dbb->query       = (db_query_f)dbt_query;
	dbb->free_result = dbt_free_result;
	dbb->insert      = (db_insert_f)dbt_insert;
	dbb->delete      = (db_delete_f)dbt_delete;
	dbb->update      = (db_update_f)dbt_update;

	return 0;
}

static mi_response_t *mi_dbt_dump(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (dbt_cache_print(0)!=0)
		return NULL;

	return init_mi_result_ok();
}

static mi_response_t *mi_dbt_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int res;

	if( (res = dbt_cache_reload(NULL, NULL)) >= 0 ) {
		return init_mi_result_ok();
	} else if( res == -1 ) {
		return init_mi_error(400, MI_SSTR("Bad parameter value"));
	} else {
		return init_mi_error(500, MI_SSTR("Internal error"));
	}
}

static mi_response_t *mi_dbt_reload_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str dbname;
	int res;

	if (get_mi_string_param(params, "db_name", &dbname.s, &dbname.len) < 0)
		return init_mi_param_error();

	if( (res = dbt_cache_reload(&dbname, NULL)) >= 0 ) {
		return init_mi_result_ok();
	} else if( res == -1 ) {
		return init_mi_error(400, MI_SSTR("Bad parameter value"));
	} else {
		return init_mi_error(500, MI_SSTR("Internal error"));
	}
}

static mi_response_t *mi_dbt_reload_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str dbname, name;
	int res;

	if (get_mi_string_param(params, "db_name", &dbname.s, &dbname.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "table_name", &name.s, &name.len) < 0)
		return init_mi_param_error();

	if ( (res = dbt_cache_reload(&dbname, &name)) >= 0 ) {
		return init_mi_result_ok();
	} else if( res == -1 ) {
		return init_mi_error(400, MI_SSTR("Bad parameter value"));
	} else {
		return init_mi_error(500, MI_SSTR("Internal error"));
	}
}
