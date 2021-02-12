/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
 *
 * This file is part of opensips, a free SIP server.
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
 *
 * History:
 * ---------
 *  2009-08-12  first version (andreidragus)
 */



#define _GNU_SOURCE

#include "../../sr_module.h"
#include "../../db/db.h"
#include "http_dbase.h"
#include "../../ssl_init_tweaks.h"
#include "../../pt.h"


static int http_mod_init(void);



int db_http_bind_api( const str* mod, db_func_t *dbb);



int cap_raw_query = 0;
int cap_id = 0;
int cap_replace = 0;
int cap_insert_update = 0;
int use_ssl = 0 ;
int disable_expect = 0;

unsigned int db_http_timeout = 30000; /* Default is 30 seconds */


/*
 * MySQL database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api",         (cmd_function)db_http_bind_api, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"SSL", INT_PARAM  ,&use_ssl},
	{"cap_raw_query", INT_PARAM  ,&cap_raw_query},
	{"cap_replace", INT_PARAM  , &cap_replace},
	{"cap_last_inserted_id", INT_PARAM  , &cap_id},
	{"cap_insert_update", INT_PARAM  , &cap_insert_update},
	{"field_delimiter", STR_PARAM | USE_FUNC_PARAM ,set_col_delim},
	{"row_delimiter", STR_PARAM | USE_FUNC_PARAM ,set_line_delim},
	{"quote_delimiter", STR_PARAM | USE_FUNC_PARAM ,set_quote_delim},
	{"value_delimiter", STR_PARAM | USE_FUNC_PARAM ,set_value_delim},
	{"timeout", INT_PARAM,&db_http_timeout},
	{"disable_expect", INT_PARAM,&disable_expect},
	{0, 0, 0}
};


struct module_exports exports = {
	"db_http",
	MOD_TYPE_SQLDB,  /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	0,               /* OpenSIPS module dependencies */
	cmds,
	0,
	params,          /*  module parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	http_mod_init,   /* module initialization function */
	0,               /* response function*/
	0,               /* destroy function */
	0,               /* per-child init function */
	0                /* reload confirm function */
};


static int http_mod_init(void)
{
	return 0;
}

int db_http_bind_api( const str* mod, db_func_t *dbb)
{
	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->cap = DB_CAP_QUERY | DB_CAP_INSERT | DB_CAP_DELETE |
			DB_CAP_UPDATE ;

	if( cap_id)
	{
		dbb->cap |= DB_CAP_LAST_INSERTED_ID;
		dbb->last_inserted_id = db_last_inserted_id;
	}


	if( cap_raw_query)
	{
		dbb->cap |= DB_CAP_RAW_QUERY;
		dbb->raw_query = db_http_raw_query;
	}

	if( cap_replace)
	{
		dbb->cap |= DB_CAP_REPLACE;
		dbb->replace = db_http_replace;

	}

	if( cap_insert_update)
	{
		dbb->cap |= DB_CAP_INSERT_UPDATE;
		dbb->insert_update = db_insert_update;

	}

	dbb->use_table        = db_http_use_table;
	dbb->init             = db_http_init;
	dbb->close            = db_http_close;
	dbb->query            = db_http_query;
	dbb->fetch_result     = NULL;
	dbb->free_result      = db_http_free_result;
	dbb->insert           = db_http_insert;
	dbb->delete           = db_http_delete;
	dbb->update           = db_http_update;


	return 0;
}

