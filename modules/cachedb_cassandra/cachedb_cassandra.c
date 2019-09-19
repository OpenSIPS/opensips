/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 */

#include <string.h>
#include <cassandra.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_cassandra.h"
#include "cachedb_cassandra_dbase.h"

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

int cassandra_conn_timeout = CASS_DEFAULT_CONN_TIMEOUT;
int cassandra_query_timeout = CASS_DEFAULT_QUERY_TIMEOUT;
int cassandra_exec_threshold = CASS_DEFAULT_EXEC_THRESH;
int cassandra_query_retries = CASS_DEFAULT_QUERY_RETRIES;

static str cassandra_rd_consistency = str_init(CASS_DEFAULT_CONSISTENCY_STR);
static str cassandra_wr_consistency = str_init(CASS_DEFAULT_CONSISTENCY_STR);

/* the index of each consistency level name in the array corresponds to the
 * actual value of the CassConsistency enum */
static char *consistency_str_table[] = {"any", "one", "two", "three", "quorum", "all",
		"local_quorum", "each_quorum", "serial", "local_serial", "local_one", NULL};

static str cache_mod_name = str_init("cassandra");
struct cachedb_url *cassandra_script_urls = NULL;

int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&cassandra_script_urls,(char *)val);
}

static param_export_t params[]={
	{"connect_timeout", INT_PARAM, &cassandra_conn_timeout},
	{"query_timeout", INT_PARAM, &cassandra_query_timeout},
	{"exec_threshold", INT_PARAM, &cassandra_exec_threshold},
	{"query_retries", INT_PARAM, &cassandra_query_retries},
	{"rd_consistency_level", STR_PARAM, &cassandra_rd_consistency},
	{"wr_consistency_level", STR_PARAM, &cassandra_wr_consistency},
	{"cachedb_url", STR_PARAM|USE_FUNC_PARAM, (void *)&set_connection},
	{0,0,0},
};

struct module_exports exports= {
	"cachedb_cassandra",        	 /* module's name */
	MOD_TYPE_CACHEDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	NULL,            /* exported functions */
	0,               /* exported async functions */
	params,          /* param exports */
	0,       		 /* exported statistics */
	0,         		 /* exported MI functions */
	0,       		 /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init,      /* per-child init function */
	0                /* reload confirm function */
};


static int mod_init(void)
{
	cachedb_engine cde;
	int i;

	LM_NOTICE("initializing module cachedb_cassandra\n");

	cassandra_rd_consistency.len = strlen(cassandra_rd_consistency.s);
	cassandra_wr_consistency.len = strlen(cassandra_wr_consistency.s);

	/* translate from the consistency levels string modparams to actual 
	 * CassConsistency enum values */
	for (i = 0; consistency_str_table[i]; i++)
		if (!strncasecmp(consistency_str_table[i], cassandra_rd_consistency.s,
			cassandra_rd_consistency.len))
			rd_consistency = i;
	for (i = 0; consistency_str_table[i]; i++)
		if (!strncasecmp(consistency_str_table[i], cassandra_wr_consistency.s,
			cassandra_wr_consistency.len))
			wr_consistency = i;

	if (rd_consistency == CASS_CONSISTENCY_UNKNOWN) {
		LM_ERR("Bad value for rd_consistency_level\n");
		return -1;
	}
	if (wr_consistency == CASS_CONSISTENCY_UNKNOWN) {
		LM_ERR("Bad value for wr_consistency_level\n");
		return -1;
	}

	memset(&cde, 0, sizeof(cachedb_engine));

	cde.name = cache_mod_name;

	cde.cdb_func.init = cassandra_init;
	cde.cdb_func.destroy = cassandra_destroy;
	cde.cdb_func.get = cassandra_get;
	cde.cdb_func.get_counter = cassandra_get_counter;
	cde.cdb_func.set = cassandra_set;
	cde.cdb_func.remove = cassandra_remove;
	cde.cdb_func._remove = _cassandra_remove;
	cde.cdb_func.add = cassandra_add;
	cde.cdb_func.sub = cassandra_sub;
	cde.cdb_func.query = cassandra_col_query;
	cde.cdb_func.update = cassandra_col_update;
	cde.cdb_func.truncate = cassandra_truncate;

	cde.cdb_func.capability = CACHEDB_CAP_BINARY_VALUE;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to initialize cachedb_cassandra\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;

	for (it = cassandra_script_urls; it; it = it->next) {
		LM_DBG("iterating through conns - [%.*s]\n", it->url.len, it->url.s);
		con = cassandra_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name, con) < 0) {
			LM_ERR("failed to insert connection\n");
			return -1;
		}
	}
	cachedb_free_url(cassandra_script_urls);

	return 0;
}

static void mod_destroy(void)
{
	cachedb_end_connections(&cache_mod_name);

	return;
}
