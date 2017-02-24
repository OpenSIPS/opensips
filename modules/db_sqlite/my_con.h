/**
 *
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 *  2015-02-18  initial version (Ionut Ionita)
*/
#ifndef MY_CON_H_
#define MY_CON_H_
#define PREP_STMT_VAL_LEN	1024

#include <sqlite3.h>


struct my_con {
	struct db_id* id;        /**< Connection identifier */
	unsigned int ref;        /**< Reference count */
	struct pool_con *async_pool; /**< Subpool of identical database handles */
	int no_transfers;        /**< Number of async queries to this backend */
	struct db_transfer *transfers; /**< Array of ongoing async operations */
	struct pool_con *next;   /**< Next element in the pool (different db_id) */

	int raw_query;           /**< indicates whether a select query
									is a raw query*/

	sqlite3* con;              /* Connection representation */
	sqlite3_stmt* curr_ps;
	int			curr_ps_rows;
	unsigned int init;       /* If the mysql conn was initialized */

	struct prep_stmt *ps_list; /* list of prepared statements */
};

struct my_stmt_ctx {
	sqlite3_stmt *stmt;
	str query;
	int query_rows;

	struct my_stmt_ctx *next;
};

struct prep_stmt {
	struct my_stmt_ctx *stmt_list;
	struct my_stmt_ctx *ctx;
};


#define CON_CONNECTION(db_con) (((struct my_con*)((db_con)->tail))->con)
#define CON_ROW(db_con)        (((struct my_con*)((db_con)->tail))->row)
#define CON_SQLITE_PS(db_con)  (((struct my_con*)((db_con)->tail))->curr_ps)
#define CON_RAW_QUERY(db_con)  (((struct my_con*)((db_con)->tail))->raw_query)
#define CON_PS_ROWS(db_con)  (((struct my_con*)((db_con)->tail))->curr_ps_rows)
#define CON_DISCON(db_con)     (((struct my_con*)((db_con)->tail))->disconnected)





int db_sqlite_connect(struct my_con* ptr);
struct my_con* db_sqlite_new_connection(const struct db_id* id);
void db_sqlite_free_connection(struct pool_con* con);

#endif
