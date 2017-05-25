/*
 * Copyright (C) 2011-2017 OpenSIPS Project
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_mongodb_dbase.h"
#include "cachedb_mongodb_json.h"

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static str cache_mod_name = str_init("mongodb");
struct cachedb_url *mongodb_script_urls = NULL;

int mongo_op_timeout=3000; /* 3000 milliseconds */
int mongo_slave_ok=0;      /* not ok to send read requests to secondaries */
str mongo_write_concern_str = {0,0};
bson_t mongo_write_concern_b;
//mongo_write_concern mwc;
int mongo_exec_threshold=0;

int compat_mode_30;
int compat_mode_24;

int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&mongodb_script_urls,(char *)val);
}

static param_export_t params[]={
	{ "cachedb_url",   STR_PARAM|USE_FUNC_PARAM, (void *)&set_connection},
	{ "op_timeout",    INT_PARAM, &mongo_op_timeout},
	{ "slave_ok",      INT_PARAM, &mongo_slave_ok},
	{ "write_concern", STR_PARAM, &mongo_write_concern_str },
	{ "exec_treshold", INT_PARAM, &mongo_exec_threshold },
	{ "compat_mode_3.0", INT_PARAM, &compat_mode_30 },
	{ "compat_mode_2.4", INT_PARAM, &compat_mode_24 },
	{0,0,0}
};


/** module exports */
struct module_exports exports= {
	"cachedb_mongodb",					/* module name */
	MOD_TYPE_CACHEDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	0,						/* exported functions */
	0,						/* exported async functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,	/* destroy function */
	child_init			        /* per-child init function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_mongodb ...\n");
	memset(&cde,0,sizeof(cachedb_engine));

	cde.name = cache_mod_name;

	cde.cdb_func.init = mongo_con_init;
	cde.cdb_func.destroy = mongo_con_destroy;
	cde.cdb_func.get = mongo_con_get;
	cde.cdb_func.get_counter = mongo_con_get_counter;
	cde.cdb_func.set = mongo_con_set;
	cde.cdb_func.remove = mongo_con_remove;
	cde.cdb_func.add = mongo_con_add;
	cde.cdb_func.sub = mongo_con_sub;
	cde.cdb_func.raw_query = mongo_con_raw_query;
	cde.cdb_func.db_query_trans = mongo_db_query_trans;
	cde.cdb_func.db_free_trans = mongo_db_free_result_trans;
	cde.cdb_func.db_insert_trans = mongo_db_insert_trans;
	cde.cdb_func.db_delete_trans = mongo_db_delete_trans;
	cde.cdb_func.db_update_trans = mongo_db_update_trans;

	cde.cdb_func.capability = 0;

#if 0
	if (mongo_write_concern_str.s != NULL) {
		/* TODO - try manually building the getlasterror bson_t */
		memset(&mongo_write_concern_b,0,sizeof(bson_t));
		if (json_to_bson(mongo_write_concern_str.s,&mongo_write_concern_b) != 0) {
			LM_ERR("Invalid write concern json\n");
			return -1;
		}

		mongo_write_concern_init(&mwc);
		mwc.cmd = &mongo_write_concern_b;
	}
#endif


#if 0
	if (mongo_slave_ok == 1) {
		mongo_slave_ok = MONGO_SLAVE_OK | MONGO_PARTIAL ;
	}
#endif

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to initialize cachedb_redis\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;

	if(rank == PROC_MAIN || rank == PROC_TCP_MAIN) {
		return 0;
	}

	mongoc_init();

	for (it = mongodb_script_urls;it;it=it->next) {
		LM_DBG("iterating through conns - [%.*s]\n",it->url.len,it->url.s);
		con = mongo_con_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name,con) < 0) {
			LM_ERR("failed to insert connection\n");
			return -1;
		}
	}

	cachedb_free_url(mongodb_script_urls);
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module cachedb_mongodb ...\n");

	cachedb_end_connections(&cache_mod_name);
	mongoc_cleanup();
}
