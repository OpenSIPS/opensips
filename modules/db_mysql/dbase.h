/*
 * MySQL module core functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2008 1&1 Internet AG
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
 */


#ifndef DBASE_H
#define DBASE_H


#include "../../db/db_con.h"
#include "../../db/db_res.h"
#include "../../db/db_key.h"
#include "../../db/db_op.h"
#include "../../db/db_val.h"
#include "../../str.h"
#include "my_con.h"

/*
 * Initialize database connection
 */
db_con_t* db_mysql_init(const str* _sqlurl);


/*
 * Close a database connection
 */
void db_mysql_close(db_con_t* _h);


/*
 * Free all memory allocated by get_result
 */
int db_mysql_free_result(db_con_t* _h, db_res_t* _r);


/*
 * Do a query
 */
int db_mysql_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	     const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	     const db_key_t _o, db_res_t** _r);


/*
 * fetch rows from a result
 */
int db_mysql_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows);


/*
 * Raw SQL query
 */
int db_mysql_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r);


/*
 * Insert a row into table
 */
int db_mysql_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n);


/*
 * Delete a row from table
 */
int db_mysql_delete(const db_con_t* _h, const db_key_t* _k, const
	db_op_t* _o, const db_val_t* _v, const int _n);


/*
 * Update a row in table
 */
int db_mysql_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
	const int _un);


/*
 * Just like insert, but replace the row if it exists
 */
int db_mysql_replace(const db_con_t* handle, const db_key_t* keys, const db_val_t* 	vals, const int n);

/*
 * Returns the last inserted ID
 */
int db_last_inserted_id(const db_con_t* _h);

/*
 * Begins execution of an asynchronous, raw MySQL query. Possibly opens new TCP
 * connections up to "db_max_async_connections". Returns immediately.
 *
 * \return
 *		success: Unix FD for polling
 *		failure: negative error code
 */
int db_mysql_async_raw_query(db_con_t *_h, const str *_s, void** _data);

/*
 * Reads data from the given connection file descriptor. If the query is fully
 * completed, the global "async_status" will be equal to ASYNC_DONE.
 *
 * \return:
 *		-> 0 on success, negative on failure
 *		-> also populates the global "async_status": ASYNC_CONTINUE / ASYNC_DONE
 */
int db_mysql_async_resume(db_con_t *_h, int fd, db_res_t **_r, void* _data);

/*
 * Cleans up asynchronous query results along with other associated structures
 *
 * \return:
 *		-> 0 on success, negative on failure
 */
int db_mysql_async_free_result(db_con_t *_h, db_res_t *_r, void *_data);

/*
 * Insert a row into table, update on duplicate key
 */
int db_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n);


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_mysql_use_table(db_con_t* _h, const str* _t);


/*
 *	Free all allocated prep_stmt structures
 */
void db_mysql_free_stmt_list(struct prep_stmt *head);

#endif /* DBASE_H */
