/*
 * POSTGRES module, portions of this code were templated using
 * the mysql module, thus it's similarity.
 *
 * Copyright (C) 2003 August.Net Services, LLC
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
 *
 * ---
 *
 * History
 * -------
 * 2003-04-06 initial code written (Greg Fausak/Andy Fullford)
 *
 */


#ifndef DBASE_H
#define DBASE_H

#include "../../db/db_con.h"
#include "../../db/db_res.h"
#include "../../db/db_key.h"
#include "../../db/db_op.h"
#include "../../db/db_val.h"

/**
 * Postgres default timeout
 */
extern int pg_timeout;

/**
 * Initialize database connection
 */
db_con_t* db_postgres_init(const str* _url);

/**
 * Close a database connection
 */
void db_postgres_close(db_con_t* _h);

/**
 * Return result of previous query
 */
int db_postgres_store_result(const db_con_t* _h, db_res_t** _r);

/**
 * Free all memory allocated by get_result
 */
int db_postgres_free_result(db_con_t* _h, db_res_t* _r);


/**
 * Do a query
 */
int db_postgres_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
		const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
		const db_key_t _o, db_res_t** _r);

/**
 * Raw SQL query
 */
int db_postgres_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r);


/**
 * Insert a row into table
 */
int db_postgres_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
		const int _n);


/**
 * Delete a row from table
 */
int db_postgres_delete(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
		const db_val_t* _v, const int _n);


/**
 * Update a row in table
 */
int db_postgres_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
		const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
		const int _un);

/**
 * fetch rows from a result
 */
int db_postgres_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows);


/**
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_postgres_use_table(db_con_t* _h, const str* _t);

int db_postgres_async_raw_query(db_con_t *_h, const str *_s, void **_priv);

int db_postgres_async_resume(db_con_t *_h, int fd, db_res_t **_r, void *_priv);

int db_postgres_async_free_result(db_con_t *_h, db_res_t *_r, void *_priv);

#endif /* DBASE_H */
