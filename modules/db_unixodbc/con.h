/*
 * UNIXODBC module
 *
 * Copyright (C) 2005-2006 Marco Lorrai
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
 *
 * History:
 * --------
 *  2005-12-01  initial commit (chgen)
 */


#ifndef MY_CON_H
#define MY_CON_H

#include "../../db/db_pool.h"
#include "../../db/db_id.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sql.h>
#include <sqlext.h>
#include <sqlucode.h>


#define STRN_LEN 1024

typedef struct strn
{
	char s[STRN_LEN];
} strn;


struct my_con
{
	struct db_id* id;        /**< Connection identifier */
	unsigned int ref;        /**< Reference count */
	struct pool_con *async_pool; /**< Subpool of identical database handles */
	int no_transfers;        /**< Number of async queries to this backend */
	struct db_transfer *transfers; /**< Array of ongoing async operations */
	struct pool_con *next;   /**< Next element in the pool (different db_id) */

	SQLHENV env;
	SQLHSTMT stmt_handle;			  /* Actual result */
	SQLHDBC dbc;					  /* Connection representation */
	char** row;						  /* Actual row in the result */
	time_t timestamp;				  /* Timestamp of last query */
};

/*
 * Some convenience wrappers
 */
#define CON_RESULT(db_con)	 (((struct my_con*)((db_con)->tail))->stmt_handle)
#define CON_CONNECTION(db_con) (((struct my_con*)((db_con)->tail))->dbc)
#define CON_ROW(db_con)		(((struct my_con*)((db_con)->tail))->row)
#define CON_TIMESTAMP(db_con)  (((struct my_con*)((db_con)->tail))->timestamp)
#define CON_ID(db_con) 		(((struct my_con*)((db_con)->tail))->id)
#define CON_ENV(db_con)		(((struct my_con*)((db_con)->tail))->env)

#define MAX_CONN_STR_LEN 2048

/*
 * Create a new connection structure,
 * open the UNIXODBC connection and set reference count to 1
 */
struct my_con* db_unixodbc_new_connection(struct db_id* id);

/*
 * Close the connection and release memory
 */
void db_unixodbc_free_connection(struct my_con* con);

char *db_unixodbc_build_conn_str(const struct db_id* id, char *buf);

void db_unixodbc_extract_error(const char *fn, const SQLHANDLE handle, const SQLSMALLINT type, char* stret);

#endif  /* MY_CON_H */
