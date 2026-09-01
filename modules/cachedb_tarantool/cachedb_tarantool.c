/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * Module: cachedb_tarantool - OpenSIPS 3.x CacheDB driver for Tarantool 3.x
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#if __has_include("../../sr_module.h")
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../cachedb/cachedb.h"
#endif

#include "cachedb_tarantool_dbase.h"

#ifndef MODULE_VERSION
#define MODULE_VERSION "3.5.0-dev"
#define DEFAULT_DLFLAGS 0
#define MOD_TYPE_CACHEDB 2
#define STR_PARAM 1
#define INT_PARAM 2
#define USE_FUNC_PARAM 4
typedef struct param_export_t {
	char *name;
	int type;
	void *param_pointer;
} param_export_t;
typedef int (*response_function)(void);
typedef void (*destroy_function)(void);
typedef struct module_exports {
	char *name;
	int type;
	char *version;
	int dlflags;
	void *load_f;
	void *deps;
	void *cmds;
	void *acmds;
	const param_export_t *params;
	void *stats;
	void *mi_cmds;
	void *pvs;
	void *trans;
	void *procs;
	void *preinit_f;
	int (*init_f)(void);
	response_function resp_f;
	destroy_function destroy_f;
	int (*child_init_f)(int);
	void *reload_f;
} module_exports;
#endif

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

static str cache_mod_name = str_init("tarantool");
static struct cachedb_url *tnt_script_urls = NULL;

static int set_connection(unsigned int type, void *val)
{
	(void)type;
	return cachedb_store_url(&tnt_script_urls, (char *)val);
}

static const param_export_t params[] = {
	{ "cachedb_url",             STR_PARAM | USE_FUNC_PARAM, (void *)&set_connection },
	{ "connect_timeout",         INT_PARAM,                  &tarantool_connect_tout },
	{ "query_timeout",           INT_PARAM,                  &tarantool_query_tout },
	{ "lazy_connect",            INT_PARAM,                  &tarantool_lazy_connect },
	{ "disable_time",            INT_PARAM,                  &tarantool_disable_time },
	{ "allowed_errors",          INT_PARAM,                  &tarantool_allowed_errors },
	{ "pool_size",               INT_PARAM,                  &tarantool_pool_size },
	{ "init_without_tarantool",  INT_PARAM,                  &tarantool_init_without_tnt },
	{ "tcp_keepalive",           INT_PARAM,                  &tarantool_tcp_keepalive },
	{ 0, 0, 0 }
};

struct module_exports exports = {
	"cachedb_tarantool",        /* module name */
	MOD_TYPE_CACHEDB,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	0,                          /* OpenSIPS module dependencies */
	0,                          /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function)0,       /* response handling function */
	(destroy_function)destroy,  /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

static int mod_init(void)
{
	cachedb_engine cde;

	LM_INFO("Initializing module cachedb_tarantool (Tarantool 3.x)...\n");

	memset(&cde, 0, sizeof(cachedb_engine));

	cde.name = cache_mod_name;
	cde.cdb_func.init = tarantool_init;
	cde.cdb_func.destroy = tarantool_destroy;
	cde.cdb_func.get = tarantool_get;
	cde.cdb_func.set = tarantool_set;
	cde.cdb_func.remove = tarantool_remove;
	cde.cdb_func.raw_query = tarantool_raw_query;
	cde.cdb_func.capability = 0;

#ifdef CACHEDB_HAVE_GET_BUF
	cde.cdb_func.get_buf = tarantool_get_buf;
	cde.cdb_func.capability |= CACHEDB_CAP_GET_BUF;
#endif

	if (register_cachedb(&cde) < 0) {
		LM_ERR("Failed to initialize cachedb_tarantool engine\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	(void)rank;
	struct cachedb_url *it;

	for (it = tnt_script_urls; it; it = it->next) {
		cachedb_con *con = tarantool_init(&it->url);
		if (con == NULL) {
			LM_ERR("Failed to open connection to Tarantool cluster\n");
			if (!tarantool_init_without_tnt)
				return -1;
			continue;
		}
		if (cachedb_put_connection(&cache_mod_name, con) < 0) {
			LM_ERR("Failed to insert Tarantool connection into OpenSIPS pool\n");
			return -1;
		}
	}

	cachedb_free_url(tnt_script_urls);
	return 0;
}

static void destroy(void)
{
	LM_NOTICE("Destroy module cachedb_tarantool...\n");
	cachedb_end_connections(&cache_mod_name);
}
