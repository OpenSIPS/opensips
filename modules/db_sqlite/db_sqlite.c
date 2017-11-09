/**
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * History
 * -------
 *  2015-02-18  initial version (Ionut Ionita)
*/

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../db/db_cap.h"
#include "db_sqlite.h"
#include "dbase.h"

#include <sqlite3.h>
#define ALLOC_LIMIT 10
#define LDEXT_LIST_DELIM ';'

unsigned int db_sqlite_timeout_interval = 2;   /* Default is 6 seconds */
unsigned int db_sliqte_exec_query_threshold = 0;   /* Warning in case DB query
											takes too long disabled by default*/
int db_sqlite_alloc_limit=ALLOC_LIMIT;



static int sqlite_mod_init(void);
static void sqlite_mod_destroy(void);
static int db_sqlite_add_extension(modparam_t type, void *val);
struct db_sqlite_extension_list *extension_list=0;

/*
 * MySQL database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api", (cmd_function)db_sqlite_bind_api,	0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"alloc_limit", INT_PARAM, &db_sqlite_alloc_limit},
	{"load_extension", STR_PARAM|USE_FUNC_PARAM,
								(void *)db_sqlite_add_extension},
	{0, 0, 0}
};


struct module_exports exports = {
	"db_sqlite",
	MOD_TYPE_SQLDB,  /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,
	0,               /* exported async functions */
	params,          /* module parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* extra processes */
	sqlite_mod_init,  /* module initialization function */
	0,               /* response function*/
	sqlite_mod_destroy,               /* destroy function */
	0                /* per-child init function */
};

static int sqlite_mod_init(void)
{
	return 0;
}

static void sqlite_mod_destroy(void)
{
	struct db_sqlite_extension_list *foo=NULL;
	while (extension_list) {
		foo=extension_list;
		extension_list=extension_list->next;
		pkg_free(foo);
	}
}


int db_sqlite_bind_api(const str* mod, db_func_t *dbb)
{
	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table        = db_sqlite_use_table;
	dbb->init             = db_sqlite_init;
	dbb->close            = db_sqlite_close;
	dbb->query            = db_sqlite_query;
	dbb->fetch_result     = db_sqlite_fetch_result;
	dbb->raw_query        = db_sqlite_raw_query;
	dbb->free_result      = db_sqlite_free_result;
	dbb->insert           = db_sqlite_insert;
	dbb->delete           = db_sqlite_delete;
	dbb->update           = db_sqlite_update;
	dbb->replace          = db_sqlite_replace;
	dbb->last_inserted_id = db_last_inserted_id;
	dbb->insert_update    = db_insert_update;

	return 0;
}


static int db_sqlite_add_extension(modparam_t type, void *val)
{
	struct db_sqlite_extension_list *node;

	int len;

	node=pkg_malloc(sizeof(struct db_sqlite_extension_list));
	if (!node)
		goto out;

	len = strlen((char *)val);

	node->ldpath=(char *)val;
	node->entry_point=q_memchr(node->ldpath, LDEXT_LIST_DELIM, len);

	if (node->entry_point) {
		/* sqlite requires null terminated strings */
		(node->entry_point++)[0] = '\0';
	}

	/* Reduce the overhead of introducing in the end */
	node->next=extension_list;
	extension_list=node;

	return 0;
out:
	LM_ERR("no more pkg mem\n");
	return -1;
}
