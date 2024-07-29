/*
 * Copyright (C) 2024 OpenSIPS Solutions
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

#include <stdio.h>
#include <string.h>
#include "cachedb_dynamodb_dbase.h"
#include "../../lib/csv.h"


static int mod_init(void);
static int child_init(int rank);
static void destroy(void);


str cache_mod_name = str_init("dynamodb");
struct cachedb_url *dynamo_script_urls = NULL;


int set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&dynamo_script_urls,(char *)val);
}


dynamodb_con *dynamodb_new_connection(struct cachedb_id* id)
{
	dynamodb_con *con;
	csv_record *cols, *col, *kv;
	str collection_list;
	char *endpoint;
	int endpoint_len, ret;
	con = NULL;
	cols = NULL;
	kv = NULL;
	endpoint = NULL;
	LM_DBG("Connecting to DynamoDB with URL: %s\n", id->initial_url);

	con = (dynamodb_con *)pkg_malloc(sizeof(dynamodb_con));
	if (!con) {
		LM_ERR("malloc failed\n");
		return NULL;
	}

	memset(con, 0, sizeof(dynamodb_con));

	if (id->database) {
		con->tableName = id->database;
	} else {
		LM_ERR("No table\n");
		goto out_err3;
	}

	init_str(&collection_list, id->extra_options);

	cols = __parse_csv_record(&collection_list, 0, ';');
	if (!cols) {
		LM_ERR("Parse failed\n");
		goto out_err3;
	}

	/* Parse each key-value pair */
	for (col = cols; col; col = col->next) {
		kv = __parse_csv_record(&col->s, 0, '=');
		if (!kv) {
			LM_ERR("Parse failed\n");
			goto out_err2;
		}

		if (strncasecmp(kv->s.s, "region", kv->s.len) == 0) {
			con->region = from_str_to_string(&(kv->next)->s);
			if(con->region == NULL) {
				LM_ERR("No more pkg mem for con->region\n");
				goto out_err1;
			}

		} else if (strncasecmp(kv->s.s, "key", kv->s.len) == 0) {
			con->key = from_str_to_string(&(kv->next)->s);
			if(con->key == NULL) {
				LM_ERR("No more pkg mem for con->key\n");
				goto out_err1;
			}
		} else if (strncasecmp(kv->s.s, "val", kv->s.len) == 0) {
			con->value = from_str_to_string(&(kv->next)->s);
			if(con->value == NULL) {
				LM_ERR("No more pkg mem for con->value\n");
				goto out_err1;
			}
		}

		free_csv_record(kv);

	}
	free_csv_record(cols);

	/* default key & value */
	if (!con->key) {
		con->key = DYNAMODB_KEY_COL_S;
	}

	if (!con->value) {
		con->value = DYNAMODB_VAL_COL_S;
	}

	con->cache_con.id = id;

	if(strcmp(id->host, "") != 0) {
		/* build endpoint */
		endpoint_len = MAX_PORT_LEN + sizeof(id->host) + 8 + 1 /* \0 */;
		endpoint = pkg_malloc(endpoint_len * sizeof(char));
		if (!endpoint) {
			LM_ERR("No more pkg mem\n");
			goto out_err3;
		}

		snprintf(endpoint, endpoint_len, "http://%s:%d", id->host, id->port);

		con->endpoint = endpoint;

	}

	if(con->endpoint == NULL && con->region == NULL) {
		LM_ERR("Can't init connection\n");
		goto out_err3;
	}

	ret = init_dynamodb(con);
	if (ret == -1) {
		LM_ERR("Init API failed\n");
		goto out_err3;
	}
	return con;

out_err1:
	if (kv) free_csv_record(kv);
out_err2:
	if (cols) free_csv_record(cols);
out_err3:
	pkg_free(con);
	return NULL;
}


cachedb_con *dynamodb_init(str *url)
{
	return cachedb_do_init(url,(void *)dynamodb_new_connection);
}


static const cmd_export_t cmds[] =
{
	{0,0,{{0,0,0}},0}
};


static const param_export_t params[]={
	{ "cachedb_url",        STR_PARAM|USE_FUNC_PARAM, (void *)set_connection},
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"cachedb_dynamodb",					/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	0,							/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported asynchronous functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,			/* response handling function */
	(destroy_function)destroy,	/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload-ack function */
};



/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing cachedb_dynamodb module ...\n");
	cachedb_engine cde;

	memset(&cde, 0, sizeof cde);

	cde.name = cache_mod_name;

	cde.cdb_func.init = dynamodb_init;
	cde.cdb_func.get = dynamodb_get;
	cde.cdb_func.get_counter = dynamodb_get_counter;
	cde.cdb_func.set = dynamodb_set;
	cde.cdb_func.remove = dynamodb_remove;
	cde.cdb_func.add = dynamodb_add;
	cde.cdb_func.sub = dynamodb_sub;
	cde.cdb_func.map_get = dynamodb_map_get;
	cde.cdb_func.map_set = dynamodb_map_set;
	cde.cdb_func.map_remove = dynamodb_map_remove;
	cde.cdb_func.destroy = dynamodb_destroy;

	if (register_cachedb(&cde)< 0)
	{
		LM_ERR("failed to register to core memory store interface\n");
		return -1;
	}
	return 0;
}

static int child_init(int rank)
{
	LM_DBG("initializing cachedb_dynamodb child ...\n");

	cachedb_con *con;
	struct cachedb_url *it;

	for (it = dynamo_script_urls;it;it=it->next) {
		LM_DBG("iterating through conns - [%s]\n", db_url_escape(&it->url));
		con = dynamodb_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			return -1;
		}
		if (cachedb_put_connection(&cache_mod_name,con) < 0) {
			LM_ERR("failed to insert connection\n");
			return -1;
		}

	}

	cachedb_free_url(dynamo_script_urls);
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	cachedb_end_connections(&cache_mod_name);
	LM_DBG("destroying cachedb_dynamodb module ...\n");
}
