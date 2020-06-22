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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2013-01-xx  created (vlad-paiu)
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

#include "cachedb_couchbase_dbase.h"

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static str cache_mod_name = str_init("couchbase");
struct cachedb_url *couchbase_script_urls = NULL;

int couch_timeout_usec=3000000; /* defaults to 3 seconds */
int couch_lazy_connect=0;/*Don't be lazy, connect on start*/
int couch_exec_threshold=0;

int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&couchbase_script_urls,(char *)val);
}

static param_export_t params[]={
	{ "cachedb_url",	STR_PARAM|USE_FUNC_PARAM,	(void *)&set_connection},
	{ "timeout",		INT_PARAM,					&couch_timeout_usec },
	{ "lazy_connect",       INT_PARAM,                                      &couch_lazy_connect },
	{ "exec_threshold",     INT_PARAM,                                      &couch_exec_threshold },
	{0,0,0}
};


/** module exports */
struct module_exports exports= {
	"cachedb_couchbase",					/* module name */
	MOD_TYPE_CACHEDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,						/* OpenSIPS module dependencies */
	0,						/* exported functions */
	0,						/* exported async functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,	/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_couchbase ...\n");
	memset(&cde, 0, sizeof cde);

	cde.name = cache_mod_name;

	cde.cdb_func.init = couchbase_init;
	cde.cdb_func.destroy = couchbase_destroy;
	cde.cdb_func.get = couchbase_get;
	cde.cdb_func.get_counter = couchbase_get_counter;
	cde.cdb_func.set = couchbase_set;
	cde.cdb_func.remove = couchbase_remove;
	cde.cdb_func.add = couchbase_add;
	cde.cdb_func.sub = couchbase_sub;

	cde.cdb_func.capability = 0;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to initialize cachedb_couchbase\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;

	for (it = couchbase_script_urls;it;it=it->next) {
		LM_DBG("iterating through couchbase conns - [%.*s]\n",it->url.len,it->url.s);
		con = couchbase_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name,con) < 0) {
			LM_ERR("failed to insert connection\n");
			return -1;
		}
	}

	cachedb_free_url(couchbase_script_urls);
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module cachedb_couchbase ...\n");
	cachedb_end_connections(&cache_mod_name);
	return;
}
