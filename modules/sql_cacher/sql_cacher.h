/**
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 *  2015-09-xx  initial version (Vlad Patrascu)
*/

#ifndef _SQL_CACHER_H_
#define _SQL_CACHER_H_

#include "../../db/db.h"
#include "../../cachedb/cachedb.h"

#define DEFAULT_SPEC_DELIM "\n"
#define DEFAULT_COLUMNS_DELIM " "
#define DEFAULT_PVAR_DELIM ":"

#define ID_STR "id"
#define ID_STR_LEN ((int)(sizeof(ID_STR) - 1))
#define DB_URL_STR "db_url"
#define DB_URL_LEN ((int)(sizeof(DB_URL_STR) - 1))
#define CACHEDB_URL_STR "cachedb_url"
#define CACHEDB_URL_LEN ((int)(sizeof(CACHEDB_URL_STR) - 1))
#define TABLE_STR "table"
#define TABLE_STR_LEN ((int)(sizeof(TABLE_STR) - 1))
#define KEY_STR "key"
#define KEY_STR_LEN ((int)(sizeof(KEY_STR) - 1))
#define KEY_TYPE_STR "key_type"
#define KEY_TYPE_STR_LEN ((int)(sizeof(KEY_TYPE_STR) - 1))
#define COLUMNS_STR "columns"
#define COLUMNS_STR_LEN ((int)(sizeof(COLUMNS_STR) - 1))
#define ONDEMAND_STR "on_demand"
#define ONDEMAND_STR_LEN ((int)(sizeof(ONDEMAND_STR) - 1))
#define EXPIRE_STR "expire"
#define EXPIRE_STR_LEN ((int)(sizeof(EXPIRE_STR) - 1))

#define TYPE_STR_STR "string"
#define TYPE_STR_LEN ((int)(sizeof(TYPE_STR_STR) - 1))
#define TYPE_INT_STR "int"
#define TYPE_INT_LEN ((int)(sizeof(TYPE_INT_STR) - 1))

#define DEFAULT_ON_DEMAND_EXPIRE 3600
#define DEFAULT_FULL_CACHING_EXPIRE 86400 /* 24h */
#define DEFAULT_RELOAD_INTERVAL 60
#define DEFAULT_FETCH_NR_ROWS 100
#define TEST_QUERY_STR "sql_cacher_test_query_key"
#define TEST_QUERY_INT 555666555
#define CDB_TEST_KEY_STR "sql_cacher_cdb_test_key"
#define CDB_TEST_VAL_STR "sql_cacher_cdb_test_val"
#define INT_B64_ENC_LEN 8

#define PV_VAL_BUF_NO 7

#define is_str_column(pv_name_fix_p) \
	((pv_name_fix_p)->c_entry->column_types & (1LL << (pv_name_fix_p)->col_nr))

typedef struct _cache_entry {
	str id;
	str db_url;
	str cachedb_url;
	str table;
	str key;
	str **columns;
	db_type_t key_type;
	unsigned int nr_columns;
	unsigned int on_demand;
	unsigned int expire;
	unsigned int nr_ints, nr_strs;
	long long column_types;
	rw_lock_t *ref_lock;
	struct _cache_entry *next;
} cache_entry_t;

typedef struct _db_handlers {
	cache_entry_t *c_entry;
	db_func_t db_funcs;
	db_con_t *db_con;
	db_ps_t query_ps;
	cachedb_funcs cdbf;
	cachedb_con *cdbcon;
	struct _db_handlers *next;
} db_handlers_t;

struct queried_key {
	str key;
	int nr_waiting_procs;
	gen_lock_t *wait_sql_query;
	struct queried_key *next;
};

typedef struct _pv_name_fix
{
	str id;
	str col;
	str key;
	cache_entry_t *c_entry;
	db_handlers_t *db_hdls;
	pv_elem_t *pv_elem_list;
	int col_offset;
	int col_nr;
	char last_str;
} pv_name_fix_t;

#endif
