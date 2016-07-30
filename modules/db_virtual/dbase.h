/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Razvan
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
 * History:
 * --------
 *  2009-07-29 initial version (razvan)
 */


#ifndef DBASE_H
#define DBASE_H


#include "../../db/db_val.h"
#include "../../str.h"



/*
 * private handle
 *
 * handle_con
 *
 *      con
 *      flags
 *      no_retries
 *
 *
 *
 * handle_set
 *      curent
 *
 *      con_list
 *      size
 *
 *      refcount
 *
 *
 *
 * handle_private
 *
 *      hset_list
 *      size
 *
 */


/*
 * global info
 *
 * info_db
 *      url
 *      func
 *      flags
 *
 * info_set
 *      name
 *      mode
 *
 *      db_list
 *      size
 *
 * info_global
 *
 *      hset_list
 *      size
 */

/*
 * Each process has "private handle".
 * There is a global shared "global info".
 * Each "private handle" coresponds to "global info".
 *
 */

typedef struct handle_con {

    db_con_t*       con;        /* handle for using a real database */
    int             flags;      /* private CAN, MAY flags */
    int             no_retries; /* failed retries left before giving up */
} handle_con_t;


typedef struct handle_set {
    /* index in the info_global list; used for the 1 to 1 relationship */
    int             set_index;

    /* index in con_list; used for FAILOVER and ROUNDROBIN mode */
    int             curent_con;
    handle_con_t*   con_list;
    int             size;

    /* used for exactly once call of real init() and close() */
    int             refcount;
} handle_set_t;


typedef struct handle_private {

    handle_set_t*   hset_list;
    int             size;
} handle_private_t;


typedef struct handle_async {
	int current_con; /* current connection index */
	int cons_rem;    /* number of cons to try */
	str query;       /* the query for this function call */
	void *_priv;     /* backend-specific data related to the async query */
} handle_async_t;

/*
 * Initialize database connection
 */
db_con_t* db_virtual_init(const str* _sqlurl);


/*
 * Close a database connection
 */
void db_virtual_close(db_con_t* _h);


/*
 * Free all memory allocated by get_result
 */
int db_virtual_free_result(db_con_t* _h, db_res_t* _r);


/*
 * Do a query
 */
int db_virtual_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
        const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
        const db_key_t _o, db_res_t** _r);


/*
 * fetch rows from a result
 */
int db_virtual_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows);


/*
 * Raw SQL query
 */
int db_virtual_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r);


/*
 * Insert a row into table
 */
int db_virtual_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n);


/*
 * Delete a row from table
 */
int db_virtual_delete(const db_con_t* _h, const db_key_t* _k, const
        db_op_t* _o, const db_val_t* _v, const int _n);


/*
 * Update a row in table
 */
int db_virtual_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
        const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
        const int _un);


/*
 * Just like insert, but replace the row if it exists
 */
int db_virtual_replace(const db_con_t* handle, const db_key_t* keys, const db_val_t* vals, const int n);

/*
 * Returns the last inserted ID
 */
int db_virtual_last_inserted_id(const db_con_t* _h);

/*
 * Insert a row into table, update on duplicate key
 */
int db_virtual_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
        const int _n);

/*
 * Async raw SQL query
 */
int db_virtual_async_raw_query(db_con_t *_h, const str *_s, void **_priv);

/*
 * Async SQL query resume function
 */
int db_virtual_async_resume(db_con_t *_h, int fd, db_res_t **_r, void *_priv);

/*
 * Cleans up anything related to (and including) an async SQL result
 */
int db_virtual_async_free_result(db_con_t *_h, db_res_t *_r, void *_priv);

/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_virtual_use_table(db_con_t* _h, const str* _t);

#endif /* DBASE_H */
