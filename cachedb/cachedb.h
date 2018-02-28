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
 *  2011-09-xx  created (vlad-paiu)
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

int cachedb_store_url(struct cachedb_url **list,char *val);
void cachedb_free_url(struct cachedb_url *list);

cachedb_con* cachedb_do_init(str *url,void* (*new_connection)(struct cachedb_id *));
void cachedb_do_close(cachedb_con *con, void (*free_connection)(cachedb_pool_con *));

typedef cachedb_con* (cachedb_init_f)(str *url);
typedef void (cachedb_destroy_f)(cachedb_con *con);

/* NOTE: "val->s" shall be allocated in PKG memory,
 * and MUST be freed by the calling layer! */
typedef int (cachedb_get_f)(cachedb_con *con,str *attr,str *val);
typedef int (cachedb_getcounter_f)(cachedb_con *con,str *attr,int *val);
typedef int (cachedb_set_f)(cachedb_con *con,str *attr,str *val,int expires);
typedef int (cachedb_remove_f)(cachedb_con *con,str *attr);
typedef int (cachedb_add_f)(cachedb_con *con,str *attr,int val,int expires,int *new_val);
typedef int (cachedb_sub_f)(cachedb_con *con,str *attr,int val,int expires,int *new_val);

typedef int (cachedb_query_f)(cachedb_con *con, const cdb_filter_t *filter,
                              cdb_res_t *res);
typedef int (cachedb_update_f)(cachedb_con *con,
                               const cdb_filter_t *row_filter,
                               const cdb_dict_t *pairs);

/* bi-dimensional array will be returned */
typedef int (cachedb_raw_f)(cachedb_con *con,str *query,cdb_raw_entry ***reply,int expected_key_no,int *reply_no);

typedef int (cachedb_truncate_f)(cachedb_con *con);

typedef int(cachedb_query_trans_f)(cachedb_con *con,const str *table,const db_key_t* _k, const db_op_t* _op,const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,const db_key_t _o, db_res_t** _r);
typedef int(cachedb_free_trans_f)(cachedb_con* con, db_res_t* _r);
typedef int(cachedb_insert_trans_f)(cachedb_con *con,const str *table,const db_key_t* _k, const db_val_t* _v,const int _n);
typedef int(cachedb_delete_trans_f)(cachedb_con *con,const str *table,const db_key_t* _k,const db_op_t *_o, const db_val_t* _v,const int _n);
typedef int (cachedb_update_trans_f)(cachedb_con *con,const str *table,const db_key_t* _k,const db_op_t *_o, const db_val_t* _v,const db_key_t* _uk, const db_val_t* _uv, const int _n,const int _un);

typedef struct cachedb_funcs_t {
	cachedb_init_f			*init;
	cachedb_destroy_f		*destroy;
	cachedb_get_f			*get;
	cachedb_getcounter_f	*get_counter;
	cachedb_set_f			*set;
	cachedb_remove_f		*remove;
	cachedb_add_f			*add;
	cachedb_sub_f			*sub;
	cachedb_raw_f			*raw_query;
	cachedb_truncate_f		*truncate;

	cachedb_query_trans_f	*db_query_trans;
	cachedb_free_trans_f	*db_free_trans;
	cachedb_insert_trans_f	*db_insert_trans;
	cachedb_delete_trans_f	*db_delete_trans;
	cachedb_update_trans_f	*db_update_trans;

	/*
	 * Endpoints specific to "column-oriented" NoSQL DBs (Cassandra, Mongo)
	 * Support for these endpoints can be verified via CACHEDB_CAP_COL_ORIENTED
	 */

	/**
	 * query() - SQL-like select function.
	 * @con: The cacheDB connection to use.
	 * @filter: NULL, one or more AND'ed filters for the query.
	 * @res: Will contain zero or more results.
	 */
	cachedb_query_f         *query;

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
	 * Regarding the TTL support -- the input allows for maximal flexibility,
	 * allowing calling code to set a TTL per either each key/value or
	 * key.subkey/value pairs. From here onwards, it is up to the cacheDB
	 * implementation to decide how to use this information. For example, some
	 * backends may only support row-level TTLs and set a TTL equal to the
	 * max TTL between all input and existing DB TTL (e.g. MongoDB), others
	 * may actually fully support dictionary-level TTLs (e.g. Cassandra).
	 */
	cachedb_update_f        *update;
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

int register_cachedb(cachedb_engine* cde_entry);

/*
 * Create a new row filter or append to existing ones. Multiple filters shall
 * only be linked using a logical AND, due to limitations of some backends
 *
 * Returns NULL in case of an error, without touching existing filters
 */
cdb_filter_t *cdb_append_filter(cdb_filter_t *existing, const cdb_key_t *key,
                                enum cdb_filter_op op, const int_str_t *val);
static inline void cdb_free_filters(cdb_filter_t *filters)
{
	pkg_free_all(filters);
}

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
void free_raw_fetch(cdb_raw_entry **reply, int no_val, int no_key);
#endif
