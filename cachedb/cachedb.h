/*
 * Copyright (C) 2011-2019 OpenSIPS Solutions
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

#ifndef _CACHEDB_H
#define _CACHEDB_H

#include "../str.h"
#include "../db/db_query.h"
#include "cachedb_con.h"
#include "cachedb_pool.h"
#include "cachedb_id.h"
#include "cachedb_types.h"

struct cachedb_url
{
	str url;
	struct cachedb_url *next;
};

typedef struct {
	cdb_type_t type;
	union {
		int n;
		str s;
	} val;
} cdb_raw_entry;

extern stat_var *cdb_total_queries;
extern stat_var *cdb_slow_queries;

int init_cdb_support(void);

int cachedb_store_url(struct cachedb_url **list,char *val);
void cachedb_free_url(struct cachedb_url *list);

cachedb_con* cachedb_do_init(str *url,void* (*new_connection)(struct cachedb_id *));
void cachedb_do_close(cachedb_con *con, void (*free_connection)(cachedb_pool_con *));

typedef struct cachedb_funcs_t {
	cachedb_con * (*init) (str *url);
	void (*destroy) (cachedb_con *con);

	/* NOTE: "val->s" shall be allocated in PKG memory,
	 * and MUST be freed by the calling layer! */
	int (*get) (cachedb_con *con, str *attr, str *val);

	/**
	 * Gets the value of a counter.
	 * Return values:
	 *  -2: key does not exist
	 *  -1: internal error
	 *   0: key found and value returned in the `val` parameter
	 */
	int (*get_counter) (cachedb_con *con, str *attr, int *val);
	int (*set) (cachedb_con *con, str *attr, str *val, int expires);
	int (*remove) (cachedb_con *con, str *attr);
	/*
	 * _remove() - Remove a key/value record matching @key == @attr
	 * Note: on some backends (e.g. MongoDB), the @key may be ignored,
	 *       since the primary key name is hardcoded (e.g. "_id")
	 */
	int (*_remove) (cachedb_con *con, str *attr, const str *key);
	int (*add) (cachedb_con *con, str *attr, int val,
	        int expires, int *new_val);
	int (*sub) (cachedb_con *con, str *attr, int val,
	        int expires, int *new_val);
	/* bi-dimensional array will be returned */
	int (*raw_query) (cachedb_con *con, str *query, cdb_raw_entry ***reply,
	                  int num_cols, int *num_rows);
	int (*truncate) (cachedb_con *con);

	int (*db_query_trans) (cachedb_con *con, const str *table,
	        const db_key_t* _k, const db_op_t* _op, const db_val_t* _v,
	        const db_key_t* _c, int _n, int _nc, const db_key_t _o,
	        db_res_t** _r);
	int (*db_free_trans) (cachedb_con* con, db_res_t* _r);
	int (*db_insert_trans) (cachedb_con *con, const str *table,
	        const db_key_t* _k, const db_val_t* _v, int _n);
	int (*db_delete_trans) (cachedb_con *con, const str *table,
	        const db_key_t* _k, const db_op_t *_o, const db_val_t* _v, int _n);
	int (*db_update_trans) (cachedb_con *con, const str *table,
	        const db_key_t* _k, const db_op_t *_o, const db_val_t* _v,
	        const db_key_t* _uk, const db_val_t* _uv, int _n, int _un);

	/*
	 * Endpoints specific to "column-oriented" NoSQL DBs (Cassandra, Mongo)
	 * Support for these endpoints can be verified via CACHEDB_CAP_COL_ORIENTED
	 */

	/**
	 * query() - SQL-like select function.
	 * @con: The cacheDB connection to use.
	 * @filter: NULL, one or more AND'ed filters for the query.
	 * @res: Will contain zero or more results.
	 *
	 * Return: 0 on success, -1 otherwise. @res is always safe to clean.
	 */
	int (*query) (cachedb_con *con, const cdb_filter_t *filter, cdb_res_t *res);

	/**
	 * update() - SQL-like update function with "set", "unset" and TTL support.
	 * @con: The cacheDB connection to use.
	 * @row_filter: NULL, one or more AND'ed filters for the update.
	 * @pairs: A list of columns (and values) to set or unset.
	 *
	 * In addition to behaving like the SQL equivalent, the update() function
	 * shall _always_ perform an "UPSERT" operation wherever possible,
	 * i.e. it will insert any missing rows or columns (keys) without failing.
	 *
	 * Key naming restrictions: apparently, there are none. However, depending
	 * on the destination backend, you might need to base64encode() some of
	 * your keys and/or subkeys. For example, any keys containing '.' will
	 * cause MongoDB to chop them and create something resembling:
	 * "key1: {key2: value}" instead of "key1.key2: value".
	 *
	 * Regarding the TTL support -- the input allows for maximal flexibility,
	 * allowing calling code to set a TTL per either each key/value or
	 * key.subkey/value pair. From here onwards, it is up to the cacheDB API
	 * implementation to decide how to use this information. For example, some
	 * backends may only support row-level TTLs and set a TTL equal to the
	 * max TTL between all input and existing DB TTL (e.g. MongoDB), others
	 * may actually fully support dictionary-level TTLs (e.g. Cassandra).
	 *
	 * Return: 0 on success, -1 otherwise.
	 */
	int (*update) (cachedb_con *con, const cdb_filter_t *row_filter,
	               const cdb_dict_t *pairs);
	/* TODO: can we also implement these ^ with Redis, or can we adapt them? */

	int capability;
} cachedb_funcs;

typedef struct cachedb_engines {
	str name;					/* name of the engine */
	cachedb_funcs cdb_func;		/* exported functions */
	cachedb_con *default_connection; /* default connection to be used from script */
	cachedb_con_list *connections; /* connection potentially used from script
									  for this particular cachedb engine */
} cachedb_engine;

#include "cachedb_cap.h"

int register_cachedb(cachedb_engine* cde_entry);

/* functions to be used from script */
int cachedb_store(str* cachedb_engine, str* attr, str* val,int expires);
int cachedb_remove(str* cachedb_engine, str* attr);
int cachedb_fetch(str* cachedb_engine, str* attr, str* val);
int cachedb_counter_fetch(str* cachedb_engine, str* attr, int* val);
int cachedb_add(str* cachedb_engine, str* attr, int val,int expires,int *new_val);
int cachedb_sub(str* cachedb_engine, str* attr, int val,int expires,int *new_val);
int cachedb_raw_query(str* cachedb_engine, str* attr, cdb_raw_entry ***reply,
			int expected_key_no,int *val_no);

int cachedb_bind_mod(str *url,cachedb_funcs *funcs);
int cachedb_put_connection(str *cachedb_name,cachedb_con *con);

void cachedb_end_connections(str *cachedb_name);
void free_raw_fetch(cdb_raw_entry **reply, int num_cols, int num_rows);
#endif
