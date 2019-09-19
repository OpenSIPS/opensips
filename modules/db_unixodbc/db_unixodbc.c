/*
 * UNIXODBC module interface
 *
 * Copyright (C) 2005-2006 Marco Lorrai
 * Copyright (C) 2008 1&1 Internet AG
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
 *
 * History:
 * --------
 *  2005-12-01  initial commit (chgen)
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "dbase.h"
#include "db_unixodbc.h"

int auto_reconnect = 1;     /* Default is enabled */
int use_escape_common = 0;  /* Enable common escaping */



int db_unixodbc_bind_api(const str* mod, db_func_t *dbb);

/*
 * MySQL database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api",    (cmd_function)db_unixodbc_bind_api, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"auto_reconnect",    INT_PARAM, &auto_reconnect},
	{"use_escape_common", INT_PARAM, &use_escape_common},
	{0, 0, 0}
};


struct module_exports exports = {
	"db_unixodbc",
	MOD_TYPE_SQLDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,
	0,
	params,     /*  module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	0,          /* module initialization function */
	0,          /* response function*/
	0,          /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

int db_unixodbc_bind_api(const str* mod, db_func_t *dbb)
{
	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table        = db_unixodbc_use_table;
	dbb->init             = db_unixodbc_init;
	dbb->close            = db_unixodbc_close;
	dbb->query            = db_unixodbc_query;
	dbb->raw_query        = db_unixodbc_raw_query;
	dbb->free_result      = db_unixodbc_free_result;
	dbb->insert           = db_unixodbc_insert;
	dbb->delete           = db_unixodbc_delete;
	dbb->update           = db_unixodbc_update;
	dbb->replace          = db_unixodbc_replace;

	return 0;
}

