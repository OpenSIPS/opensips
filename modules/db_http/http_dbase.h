/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
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
 * History:
 * ---------
 *  2009-08-12  first version (andreidragus)
 */


#ifndef HTTP_DBASE_H
#define HTTP_DBASE_H


#include "../../db/db_con.h"
#include "../../db/db_res.h"
#include "../../db/db_key.h"
#include "../../db/db_op.h"
#include "../../db/db_val.h"
#include "../../str.h"


/* parameter setting methods */
int set_col_delim( unsigned int type, void *val);
int set_line_delim( unsigned int type, void *val);
int set_quote_delim( unsigned int type, void *val);
int set_value_delim( unsigned int type, void *val);



/*
 * Initialize database connection
 */
db_con_t* db_http_init(const str* _sqlurl);


/*
 * Close a database connection
 */
void db_http_close(db_con_t* _h);


/*
 * Free all memory allocated by get_result
 */
int db_http_free_result(db_con_t* _h, db_res_t* _r);


/*
 * Do a query
 */
int db_http_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	     const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	     const db_key_t _o, db_res_t** _r);


/*
 * Raw SQL query
 */
int db_http_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r);


/*
 * Insert a row into table
 */
int db_http_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n);


/*
 * Delete a row from table
 */
int db_http_delete(const db_con_t* _h, const db_key_t* _k, const
	db_op_t* _o, const db_val_t* _v, const int _n);


/*
 * Update a row in table
 */
int db_http_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
	const int _un);


/*
 * Just like insert, but replace the row if it exists
 */
int db_http_replace(const db_con_t* handle, const db_key_t* keys, const db_val_t* 	vals, const int n);

/*
 * Returns the last inserted ID
 */
int db_last_inserted_id(const db_con_t* _h);

/*
 * Insert a row into table, update on duplicate key
 */
int db_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n);


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_http_use_table(db_con_t* _h, const str* _t);



#endif /* HTTP_DBASE_H */
