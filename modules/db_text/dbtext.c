/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

static struct mi_root* mi_dbt_dump(struct mi_root* cmd, void* param);

/*
 * Module parameter variables
 */
int db_mode = 0;  /* Database usage mode: 0 = cache, 1 = no cache */

int dbt_bind_api(const str* mod, db_func_t *dbb);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"db_bind_api",    (cmd_function)dbt_bind_api,   0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
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
	{"dbt_dump", 0, mi_dbt_dump, 0, 0, 0},
	{0,          0,           0, 0, 0, 0}
};

struct module_exports exports = {
	"db_text",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,     /* Exported functions */
	params,   /* Exported parameters */
	NULL,     /* exported statistics */
	mi_cmds,  /* exported MI functions */
	NULL,     /* exported pseudo-variables */
	0,        /* extra processes */
	mod_init, /* module initialization function */
	NULL,     /* response function*/
	destroy,  /* destroy function */
	NULL      /* per-child init function */
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

static struct mi_root* mi_dbt_dump(struct mi_root* cmd, void* param)
{
	struct mi_root *rpl_tree;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	if (dbt_cache_print(0)!=0)
		return NULL;
	return rpl_tree;
}
