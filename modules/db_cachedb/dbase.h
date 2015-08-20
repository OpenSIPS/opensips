/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2013-02-xx  created (vlad-paiu)
 */

#ifndef DB_CACHEDB_DBASE_H
#define DB_CACHEDB_DBASE_H


#include "../../db/db_val.h"
#include "../../cachedb/cachedb.h"
#include "../../str.h"

struct db_cachedb_con {
	struct db_id* id;        /**< Connection identifier */
	unsigned int ref;        /**< Reference count */
	struct pool_con *async_pool; /**< Subpool of identical database handles */
	int no_transfers;        /**< Number of async queries to this backend */
	struct db_transfer *transfers; /**< Array of ongoing async operations */
	struct pool_con *next;   /**< Next element in the pool (different db_id) */

	cachedb_funcs cdbf;      /* pointers to the NoSQL specific functions */
	cachedb_con *cdbc;       /* connection to actual NoSQL back-end */
};

/*
 * Initialize database connection
 */
db_con_t* db_cachedb_init(const str* _sqlurl);


/*
 * Close a database connection
 */
void db_cachedb_close(db_con_t* _h);


/*
 * Free all memory allocated by get_result
 */
int db_cachedb_free_result(db_con_t* _h, db_res_t* _r);


/*
 * Do a query
 */
int db_cachedb_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
        const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
        const db_key_t _o, db_res_t** _r);


/*
 * Insert a row into table
 */
int db_cachedb_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n);


/*
 * Delete a row from table
 */
int db_cachedb_delete(const db_con_t* _h, const db_key_t* _k, const
        db_op_t* _o, const db_val_t* _v, const int _n);


/*
 * Update a row in table
 */
int db_cachedb_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
        const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
        const int _un);

/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_cachedb_use_table(db_con_t* _h, const str* _t);

/*
 * Raw SQL query
 */
int db_cachedb_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r);

#endif /* DB_CACHEDB_DBASE_H */
