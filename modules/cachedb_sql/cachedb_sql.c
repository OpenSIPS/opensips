/*
 * Copyright (C) 2013 Steve Frécinaux
 *    Be IP s.a. http://www.beip.be
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2013-01-xx  created (Steve Frécinaux)
 *  2013-01-xx  improved implementation of cachedb (vlad-paiu)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../../cachedb/cachedb.h"
#include "../../db/db.h"
#include "../../timer.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

#define MAX_RAW_QUERY_SIZE	512
static str cache_mod_name = str_init("sql");
static char query_buf[MAX_RAW_QUERY_SIZE];
static str query_str;

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

#define KEY_COL "keyname"
#define KEY_COL_LEN (sizeof(KEY_COL) - 1)
#define VALUE_COL "value"
#define VALUE_COL_LEN (sizeof(VALUE_COL) - 1)
#define COUNTER_VALUE_COL "counter"
#define COUNTER_VALUE_COL_LEN (sizeof(COUNTER_VALUE_COL) - 1)
#define EXPIRES_COL "expires"
#define EXPIRES_COL_LEN (sizeof(EXPIRES_COL) - 1)

#define CACHEDB_SQL_TABLE_VERSION	2

static str db_url = {NULL, 0};
static str db_table = str_init("cachedb");
static str key_column = {KEY_COL, KEY_COL_LEN};
static str value_column = {VALUE_COL, VALUE_COL_LEN};
static str counter_column = {COUNTER_VALUE_COL, COUNTER_VALUE_COL_LEN};
static str expires_column = {EXPIRES_COL, EXPIRES_COL_LEN};
static int cache_clean_period = 60;

static db_con_t* cdb_db_handle = 0;
static db_func_t cdb_dbf;



static param_export_t params[] = {
	{"db_url",              STR_PARAM, &db_url.s           },
	{"db_table",            STR_PARAM, &db_table.s         },
	{"key_column",          STR_PARAM, &key_column.s       },
	{"value_column",        STR_PARAM, &value_column.s     },
	{"counter_column",      STR_PARAM, &counter_column.s   },
	{"expires_column",      STR_PARAM, &expires_column.s   },
	{"cache_clean_period",  INT_PARAM, &cache_clean_period },
	{0, 0, 0}
};

/** module exports */
struct module_exports exports = {
	"cachedb_sql",               /* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* exported functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init                  /* per-child init function */
};

cachedb_pool_con* dbcache_new_connection(struct cachedb_id* id)
{
	cachedb_pool_con *con;

	if(id == NULL) {
		LM_ERR("null db_id\n");
		return 0;
	}

	if(id->flags != CACHEDB_ID_NO_URL) {
		LM_ERR("bogus url for local cachedb\n");
		return 0;
	}

	con = pkg_malloc(sizeof(cachedb_pool_con));
	if(con == NULL) {
		LM_ERR("no more pkg\n");
		return 0;
	}

	con->id = id;
	con->ref = 1;
	con->next = NULL;

	return con;
}

static cachedb_con* dbcache_init(str *url)
{
	return cachedb_do_init(url, (void *)dbcache_new_connection);
}

void dbcache_free_connection(cachedb_pool_con *con)
{
	pkg_free(con);
}

static void dbcache_destroy(cachedb_con *con)
{
	cachedb_do_close(con, dbcache_free_connection);
}

static int dbcache_set(cachedb_con *con, str* attr, str* value, int expires)
{
	db_key_t keys[3];
	db_val_t vals[3];

	keys[0] = &key_column;
	keys[1] = &value_column;
	keys[2] = &expires_column;

	vals[0].type = DB_STR;
	vals[0].nul = 0;
	vals[0].val.str_val.s = attr->s;
	vals[0].val.str_val.len = attr->len;

	vals[1].type = DB_STR;
	vals[1].nul = 0;
	vals[1].val.str_val.s = value->s;
	vals[1].val.str_val.len = value->len;

	vals[2].type = DB_INT;
	vals[2].nul = 0;
	if (expires > 0)
		vals[2].val.int_val = (int)time(NULL) + expires;
	else
		vals[2].val.int_val = 0;

	if (cdb_dbf.use_table(cdb_db_handle, &db_table) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

	if (cdb_dbf.insert_update(cdb_db_handle, keys, vals, 3) < 0) {
		LM_ERR("inserting cache entry in db failed\n");
		return -1;
	}

	return 1;
}

static int dbcache_get(cachedb_con *con, str* attr, str* res)
{
	db_key_t key;
	db_val_t val;
	db_key_t col;
	db_res_t* db_res = NULL;

	key = &key_column;

	val.type = DB_STR;
	val.nul = 0;
	val.val.str_val.s = attr->s;
	val.val.str_val.len = attr->len;

	col = &value_column;

	if (cdb_dbf.use_table(cdb_db_handle, &db_table) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

	if(cdb_dbf.query(cdb_db_handle, &key, NULL, &val, &col, 1, 1, NULL, &db_res) < 0) {
		LM_ERR("failed to query database\n");
		return -1;
	}

	if (RES_ROW_N(db_res) <= 0 || RES_ROWS(db_res)[0].values[0].nul != 0) {
		LM_DBG("no value found for keyI\n");
		if (db_res != NULL && cdb_dbf.free_result(cdb_db_handle, db_res) < 0)
			LM_DBG("failed to free result of query\n");
		return -2;
	}

	switch(RES_ROWS(db_res)[0].values[0].type) {
		case DB_STRING:
			res->len = strlen((char*)RES_ROWS(db_res)[0].values[0].val.string_val);
			res->s = pkg_malloc(res->len + 1);

			if (res->s == NULL) {
				LM_ERR("no more pkg\n");
				goto out_err;
			}

			memcpy(res->s, (char*)RES_ROWS(db_res)[0].values[0].val.string_val, res->len);
			break;
		case DB_STR:
			res->len = RES_ROWS(db_res)[0].values[0].val.str_val.len;
			res->s = pkg_malloc(res->len + 1);

			if (res->s == NULL) {
				LM_ERR("no more pkg\n");
				goto out_err;
			}

			memcpy(res->s, (char*)RES_ROWS(db_res)[0].values[0].val.str_val.s, res->len);
			break;
		case DB_BLOB:
			res->len = RES_ROWS(db_res)[0].values[0].val.blob_val.len;
			res->s = pkg_malloc(res->len + 1);
			if (res->s == NULL) {
				LM_ERR("no more pkg\n");
				goto out_err;
			}
			memcpy(res->s, (char*)RES_ROWS(db_res)[0].values[0].val.blob_val.s, res->len);
			break;
		default:
			LM_ERR("unknown type of DB user column\n");
			goto out_err;
	}

	if (cdb_dbf.free_result(cdb_db_handle, db_res) < 0)
		LM_DBG("failed to free result of query\n");

	return 1;

out_err:
	if (cdb_dbf.free_result(cdb_db_handle, db_res) < 0)
		LM_DBG("failed to free result of query\n");

	return -1;
}

static int dbcache_remove(cachedb_con *con, str* attr)
{
	db_key_t key;
	db_val_t val;

	key = &key_column;

	val.type = DB_STR;
	val.nul = 0;
	val.val.str_val.s = attr->s;
	val.val.str_val.len = attr->len;

	if (cdb_dbf.use_table(cdb_db_handle, &db_table) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

	if (cdb_dbf.delete(cdb_db_handle, &key, 0, &val, 1) < 0) {
		LM_ERR("deleting from database failed\n");
		return -1;
	}

	return 0;
}

static int dbcache_add(cachedb_con *con, str *attr, int val, int expires, int *new_val)
{
	int i;
	db_res_t* res = NULL;

	if (expires > 0)
		expires += (int)time(NULL);
	else
		expires = 0;

	i = snprintf(query_buf, sizeof(query_buf),
				 "insert into %.*s (%.*s, %.*s, %.*s) values ('%.*s', %d, %d)"
				 "on duplicate key update %.*s=%.*s %c %d, %.*s=%d",
				 db_table.len, db_table.s,
				 key_column.len, key_column.s,
				 counter_column.len, counter_column.s,
				 expires_column.len, expires_column.s,
				 attr->len, attr->s,
				 val, expires,
				 counter_column.len, counter_column.s,
				 counter_column.len, counter_column.s,
				 val > 0 ? '+' : '-',
				 val > 0 ? val : -val,
				 expires_column.len, expires_column.s,
				 expires);

	if(i >= sizeof(query_buf)) {
		LM_ERR("DB query too long\n");
		return -1;
	}
	query_str.s = query_buf;
	query_str.len = i;

	if(cdb_dbf.raw_query(cdb_db_handle, &query_str, &res) < 0) {
		LM_ERR("raw_query failed\n");
		return -1;
	}

	if(res != NULL)
		cdb_dbf.free_result(cdb_db_handle, res);

	/* Beware of the race conditions! */
	if(new_val) {
		str val;
		if (dbcache_get(con, attr, &val) < 0) {
			LM_ERR("could not get the new value");
			return -1;
		}
		*new_val = atoi(val.s);
		pkg_free(val.s);
	}

	return 0;
}

static int dbcache_sub(cachedb_con *con, str *attr, int val, int expires, int *new_val)
{
	return dbcache_add(con, attr, -val, expires, new_val);
}

static int dbcache_fetch_counter(cachedb_con *con,str *attr,int *ret_val)
{
	db_key_t key;
	db_val_t val;
	db_key_t col;
	db_res_t* db_res = NULL;

	key = &key_column;

	val.type = DB_STR;
	val.nul = 0;
	val.val.str_val.s = attr->s;
	val.val.str_val.len = attr->len;

	col = &counter_column;

	if (cdb_dbf.use_table(cdb_db_handle, &db_table) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

	if(cdb_dbf.query(cdb_db_handle, &key, NULL, &val, &col, 1, 1, NULL, &db_res) < 0) {
		LM_ERR("failed to query database\n");
		return -1;
	}

	if (RES_ROW_N(db_res) <= 0 || RES_ROWS(db_res)[0].values[0].nul != 0) {
		LM_DBG("no value found for keyI\n");
		if (db_res != NULL && cdb_dbf.free_result(cdb_db_handle, db_res) < 0)
			LM_DBG("failed to free result of query\n");
		return -2;
	}

	switch(RES_ROWS(db_res)[0].values[0].type) {
		case DB_INT:
			if (ret_val)
				*ret_val = RES_ROWS(db_res)[0].values[0].val.int_val;
				if (cdb_dbf.free_result(cdb_db_handle, db_res) < 0)
					LM_ERR("failed to freeing result of query\n");
			break;
		default:
			LM_ERR("unknown type of DB user column\n");
			if (db_res != NULL && cdb_dbf.free_result(cdb_db_handle, db_res) < 0)
				LM_ERR("failed to freeing result of query\n");
				return -1;
	}

	return 1;
}

static void dbcache_clean(unsigned int ticks, void* param)
{
	db_key_t keys[2];
	db_op_t ops[2];
	db_val_t vals[2];

	keys[0] = &expires_column;
	keys[1] = &expires_column;

	ops[0] = OP_NEQ;
	ops[1] = OP_LT;

	vals[0].type = DB_INT;
	vals[0].nul = 0;
	vals[0].val.int_val = 0;

	vals[1].type = DB_INT;
	vals[1].nul = 0;
	vals[1].val.int_val = (int)time(NULL);

	if (cdb_dbf.use_table(cdb_db_handle, &db_table) < 0) {
		LM_ERR("sql use_table failed\n");
		return;
	}

	if (cdb_dbf.delete(cdb_db_handle, keys, ops, vals, 2) < 0) {
		LM_ERR("deleting from database failed\n");
		return;
	}
}

/**
 * init module function
 */
static int mod_init(void)
{
	cachedb_engine cde;
	cachedb_con *con;
	str url = str_init("sql://");
	str name = str_init("sql");

	LM_INFO("initializing...\n");

	init_db_url(db_url , 0 /*cannot be null*/);
	db_table.len = strlen(db_table.s);
	key_column.len = strlen(key_column.s);
	value_column.len = strlen(value_column.s);
	counter_column.len = strlen(counter_column.s);
	expires_column.len = strlen(expires_column.s);

	/* Find a database module */
	if (db_bind_mod(&db_url, &cdb_dbf) < 0){
			LM_ERR("unable to bind to a database driver\n");
			return -1;
	}

	/* register the cache system */
	cde.name = cache_mod_name;
	cde.cdb_func.init = dbcache_init;
	cde.cdb_func.destroy = dbcache_destroy;
	cde.cdb_func.get = dbcache_get;
	cde.cdb_func.set = dbcache_set;
	cde.cdb_func.remove = dbcache_remove;
	cde.cdb_func.add = dbcache_add;
	cde.cdb_func.sub = dbcache_sub;
	cde.cdb_func.get_counter = dbcache_fetch_counter;
	cde.cdb_func.capability = 0;

	cdb_db_handle = cdb_dbf.init(&db_url);
	if (cdb_db_handle == 0) {
		LM_ERR("Failed to connect to the DB \n");
		return -1;
	}

	if(db_check_table_version(&cdb_dbf, cdb_db_handle,
	&db_table, CACHEDB_SQL_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}

	/* do not close the connection here - since we're using a
	global connection instead of relying on the cachedb interface
	cdb_dbf.close(cdb_db_handle);
	cdb_db_handle = 0;
	*/

	if(cache_clean_period <= 0) {
			LM_ERR("wrong parameter cache_clean_period - need a postive value\n");
			return -1;
	}

	if(register_cachedb(&cde) < 0) {
			LM_ERR("failed to register to core memory store interface\n");
			return -1;
	}

	con = dbcache_init(&url);
	if(con == NULL) {
			LM_ERR("failed to init connection for script\n");
			return -1;
	}

	if(cachedb_put_connection(&name, con) < 0) {
			LM_ERR("failed to insert connection for script\n");
			return -1;
	}

	/* register timer to delete the expired entries */
	register_timer("cachedb_sql",dbcache_clean, 0, cache_clean_period);

	return 0;
}

/**
 * Initialize children
 */
static int child_init(int rank)
{
	cdb_db_handle = cdb_dbf.init(&db_url);
	if (cdb_db_handle == 0) {
			LM_ERR("unable to connect to the database\n");
			return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	if (cdb_db_handle) {
			cdb_dbf.close(cdb_db_handle);
			cdb_db_handle = 0;
	}
}
