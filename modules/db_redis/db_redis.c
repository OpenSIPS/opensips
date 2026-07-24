/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "db_redis.h"
#include "dbase.h"

int rdb_connect_timeout = 1000;   /* ms */
int rdb_query_timeout   = 2000;   /* ms */
int rdb_scan_count      = 100;
int rdb_mode            = RDB_MODE_AUTO;

static char *rdb_mode_str;

static int redis_mod_init(void);

static const cmd_export_t cmds[] = {
	{"db_bind_api", (cmd_function)db_redis_bind_api, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[] = {
	{"connect_timeout", INT_PARAM, &rdb_connect_timeout},
	{"query_timeout",   INT_PARAM, &rdb_query_timeout},
	{"scan_count",      INT_PARAM, &rdb_scan_count},
	{"mode",            STR_PARAM, &rdb_mode_str},
	{0, 0, 0}
};

struct module_exports exports = {
	"db_redis",
	MOD_TYPE_SQLDB,  /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,
	0,               /* exported async functions */
	params,          /* module parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	redis_mod_init,  /* module initialization function */
	0,               /* response function */
	0,               /* destroy function */
	0,               /* per-child init function */
	0                /* reload confirm function */
};

static int redis_mod_init(void)
{
	if (rdb_mode_str) {
		if (strcasecmp(rdb_mode_str, "auto") == 0)
			rdb_mode = RDB_MODE_AUTO;
		else if (strcasecmp(rdb_mode_str, "single") == 0)
			rdb_mode = RDB_MODE_SINGLE;
		else if (strcasecmp(rdb_mode_str, "cluster") == 0)
			rdb_mode = RDB_MODE_CLUSTER;
		else {
			LM_ERR("invalid mode parameter <%s>, use one of "
				"auto|single|cluster\n", rdb_mode_str);
			return -1;
		}
	}

	if (rdb_connect_timeout <= 0 || rdb_query_timeout <= 0) {
		LM_ERR("connect_timeout and query_timeout must be positive\n");
		return -1;
	}
	if (rdb_scan_count <= 0)
		rdb_scan_count = 100;

	return 0;
}

int db_redis_bind_api(const str* mod, db_func_t *dbb)
{
	if (dbb == NULL)
		return -1;

	memset(dbb, 0, sizeof(db_func_t));

	dbb->use_table        = db_redis_use_table;
	dbb->init             = db_redis_init;
	dbb->close            = db_redis_close;
	dbb->query            = db_redis_query;
	dbb->free_result      = db_redis_free_result;
	dbb->insert           = db_redis_insert;
	dbb->delete           = db_redis_delete;
	dbb->update           = db_redis_update;
	dbb->replace          = db_redis_replace;
	dbb->insert_update    = db_redis_insert_update;
	dbb->last_inserted_id = db_redis_last_inserted_id;
	/* no raw_query / fetch_result / async in phase 1 - the core derives
	 * the exported capabilities from the functions set above */

	return 0;
}
