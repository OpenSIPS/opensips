/*
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * history:
 * ---------
 *  2013-02-xx  created (vlad-paiu)
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "dbase.h"
#include "../../mi/mi.h"
#include "../../pt.h"
#include <string.h>
#include "../../mem/shm_mem.h"

#include <stdio.h>

static int mod_init(void);
static void destroy(void);
int db_cachedb_bind_api(const str* mod, db_func_t *dbb);

struct cachedb_url *db_cachedb_script_urls = NULL;

int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&db_cachedb_script_urls,(char *)val);
}

/*
 * Virtual database module interface
 */
static cmd_export_t cmds[] = {
	{"db_bind_api", (cmd_function)db_cachedb_bind_api, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"cachedb_url",     STR_PARAM|USE_FUNC_PARAM,(void*)&set_connection},
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_CACHEDB, NULL, DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"db_cachedb",
	MOD_TYPE_SQLDB,  /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	NULL,
	params,          /* module parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* response function*/
	destroy,         /* destroy function */
	0,               /* per-child init function */
	0                /* reload confirm function */
};


int db_cachedb_bind_api(const str* mod, db_func_t *dbb)
{
	LM_DBG("BINDING API for : %.*s\n", mod->len, mod->s);

	if(dbb==NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table        = db_cachedb_use_table;
	dbb->init             = db_cachedb_init;
	dbb->close            = db_cachedb_close;
	dbb->query            = db_cachedb_query;
	dbb->free_result      = db_cachedb_free_result;
	dbb->insert           = db_cachedb_insert;
	dbb->delete           = db_cachedb_delete;
	dbb->update           = db_cachedb_update;
	dbb->raw_query        = db_cachedb_raw_query;

	return 0;
}

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module db_cachedb ...\n");
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module db_cachedb ...\n");
	return;
}
