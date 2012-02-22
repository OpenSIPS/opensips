/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-12-xx  created (vlad-paiu)
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

#include "cachedb_cassandra_dbase.h"

int conn_timeout=1000; /* ms */
int send_timeout=2000; /* ms */
int recv_timeout=2000; /* ms */
int rd_consistency_level=1;
int wr_consistency_level=1;

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static str cache_mod_name = str_init("cassandra");
struct cachedb_url *cassandra_script_urls = NULL;

int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&cassandra_script_urls,(char *)val);
}

static param_export_t params[]={
	{ "cachedb_url",                 STR_PARAM|USE_FUNC_PARAM, (void *)&set_connection},
	{ "connection_timeout",          INT_PARAM, &conn_timeout},
	{ "send_timeout",                INT_PARAM, &send_timeout},
	{ "receive_timeout",             INT_PARAM, &recv_timeout},
	{ "rd_consistency_level",        INT_PARAM, &rd_consistency_level},
	{ "wr_consistency_level",        INT_PARAM, &wr_consistency_level},
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"cachedb_cassandra",
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,
	params,	
	0,
	0,
	0,
	0,
	mod_init,
	(response_function) 0,
	(destroy_function)destroy,
	child_init
};


/**
 * init module function
 */
static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_cassandra ...\n");
	if (rd_consistency_level<1 || rd_consistency_level > 8)
		rd_consistency_level=1;
	if (wr_consistency_level<1 || wr_consistency_level > 8)
		wr_consistency_level=1;

	cde.name = cache_mod_name;

	cde.cdb_func.init = cassandra_init;
	cde.cdb_func.destroy = cassandra_destroy;
	cde.cdb_func.get = cassandra_get;
	cde.cdb_func.set = cassandra_set;
	cde.cdb_func.remove = cassandra_remove;
	/* TODO */
	cde.cdb_func.add = NULL;
	cde.cdb_func.sub = NULL;

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

	for (it = cassandra_script_urls;it;it=it->next) {
		LM_DBG("iterating through conns - [%.*s]\n",it->url.len,it->url.s);
		con = cassandra_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name,con) < 0) {
			LM_ERR("failed to insert connection\n");
			return -1;
		}
	}
	cachedb_free_url(cassandra_script_urls);
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module cachedb_cassandra ...\n");
	cachedb_end_connections(&cache_mod_name);
	return;
}
