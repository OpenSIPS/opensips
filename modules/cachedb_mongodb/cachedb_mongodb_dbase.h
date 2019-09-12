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

#ifndef CACHEDBMONGO_DBASE_H
#define CACHEDBMONGO_DBASE_H

#include "../../cachedb/cachedb.h"
#include "../../db/db.h"
#include "../../lib/json/opensips_json_c_helper.h"

#define MONGO_HAVE_STDINT 1

#include <mongoc.h>
#include <bson.h>

#include <stdint.h>

extern int mongo_op_timeout;

#define MDB_PK    "_id"
#define MDB_PKLEN 3
#define MDB_MAX_NS_LEN 120

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	/* shortcuts for raw queries */
	char *db;
	char *col;

	/* only if we connect to a repl set*/
	char *replset_name;

	mongoc_client_t *client;
	mongoc_collection_t *collection;
	mongoc_database_t *database;

	/* cursor result for the query */
	mongoc_cursor_t *cursor;
} mongo_con;

#define MONGO_CON(mon_con)			((mon_con)->connection)
#define MONGO_CLIENT(cdb_con)		(((mongo_con *)((cdb_con)->data))->client)
#define MONGO_CURSOR(cdb_con)		(((mongo_con *)((cdb_con)->data))->cursor)
#define MONGO_NAMESPACE(cdb_con)	(((mongo_con *)((cdb_con)->data))->id->database)
#define MONGO_DB_STR(cdb_con)		(((mongo_con *)((cdb_con)->data))->db)
#define MONGO_COL_STR(cdb_con)		(((mongo_con *)((cdb_con)->data))->col)
#define MONGO_DATABASE(cdb_con)		(((mongo_con *)((cdb_con)->data))->database)
#define MONGO_COLLECTION(cdb_con)	(((mongo_con *)((cdb_con)->data))->collection)

cachedb_con* mongo_con_init(str *url);
void mongo_con_destroy(cachedb_con *con);
int mongo_con_get(cachedb_con *con,str *attr,str *val);
int mongo_con_set(cachedb_con *con,str *attr,str *val,int expires);
int mongo_con_remove(cachedb_con *connection,str *attr);
int _mongo_con_remove(cachedb_con *con, str *attr, const str *key);
int mongo_con_raw_query(cachedb_con *con, str *qstr, cdb_raw_entry ***reply,
                        int expected_kv_no, int *reply_no);
int mongo_con_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val);
int mongo_con_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val);
int mongo_con_get_counter(cachedb_con *connection,str *attr,int *val);
int mongo_db_query_trans(cachedb_con *con, const str *table, const db_key_t *_k,
                         const db_op_t *_op, const db_val_t *_v,
                         const db_key_t *_c, const int _n, const int _nc,
                         const db_key_t _o, db_res_t **_r);
int mongo_db_free_result_trans(cachedb_con* con, db_res_t* _r);
int mongo_db_insert_trans(cachedb_con *con, const str *table,
                          const db_key_t *_k, const db_val_t *_v, const int _n);
int mongo_db_delete_trans(cachedb_con *con, const str *table,
                          const db_key_t *_k, const db_op_t *_o,
                          const db_val_t *_v, const int _n);
int mongo_db_update_trans(cachedb_con *con, const str *table,
                          const db_key_t *_k, const db_op_t *_o,
                          const db_val_t *_v, const db_key_t *_uk,
                          const db_val_t *_uv, const int _n, const int _un);
int mongo_truncate(cachedb_con *con);

int mongo_con_query(cachedb_con *con, const cdb_filter_t *row_filter,
                    cdb_res_t *res);
int mongo_con_update(cachedb_con *con, const cdb_filter_t *row_filter,
                     const cdb_dict_t *pairs);
#endif /* CACHEDBMONGO_DBASE_H */
