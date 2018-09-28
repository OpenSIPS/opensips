/*
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

#ifndef MY_CON_H
#define MY_CON_H

#include "../../db/db_pool.h"
#include "../../db/db_id.h"

#include <time.h>
#include <mysql.h>

#include "../tls_mgm/tls_helper.h"
#if (defined LIBMYSQL_VERSION_ID) && (LIBMYSQL_VERSION_ID >= 80000)
# define my_bool bool
#endif

#define PREP_STMT_VAL_LEN	1024

struct bind_icontent {
	unsigned long len;
	my_bool null;
};

struct bind_ocontent {
	char buf[PREP_STMT_VAL_LEN];
	unsigned long len;
	my_bool null;
	my_bool error;
};


struct my_stmt_ctx {
	MYSQL_STMT *stmt;
	str table;
	str query;
	int has_out;
	struct my_stmt_ctx *next;
};

struct prep_stmt {
	struct my_stmt_ctx *stmts;
	struct my_stmt_ctx *ctx;
	/*in*/
	MYSQL_BIND *bind_in;
	struct bind_icontent *in_bufs;
	/*out*/
	int cols_out;
	MYSQL_BIND *bind_out;
	struct bind_ocontent *out_bufs;
	/*linking*/
	struct prep_stmt *next;
};


struct my_con {
	struct db_id* id;        /**< Connection identifier */
	unsigned int ref;        /**< Reference count */
	struct pool_con *async_pool; /**< Subpool of identical database handles */
	int no_transfers;        /**< Number of async queries to this backend */
	struct db_transfer *transfers; /**< Array of ongoing async operations */
	struct pool_con *next;   /**< Next element in the pool (different db_id) */

	MYSQL_RES* res;          /* Actual result */
	MYSQL* con;              /* Connection representation */
	MYSQL_ROW row;           /* Actual row in the result */
	unsigned int init;       /* If the mysql conn was initialized */

	struct prep_stmt *ps_list; /* list of prepared statements */
	unsigned int disconnected; /* (CR_CONNECTION_ERROR) was detected */

	struct tls_domain *tls_dom;;  /* TLS domain */
};



/*
 * Some convenience wrappers
 */
#define CON_RESULT(db_con)     (((struct my_con*)((db_con)->tail))->res)
#define CON_CONNECTION(db_con) (((struct my_con*)((db_con)->tail))->con)
#define CON_ROW(db_con)        (((struct my_con*)((db_con)->tail))->row)
#define CON_PS_LIST(db_con)    (((struct my_con*)((db_con)->tail))->ps_list)
#define CON_DISCON(db_con)     (((struct my_con*)((db_con)->tail))->disconnected)

#define CON_MYSQL_PS(db_con) \
	((struct prep_stmt*)(CON_CURR_PS(db_con)))
#define CON_PS_STMT(db_con) \
	(CON_MYSQL_PS(db_con)->ctx->stmt)
#define CON_PS_STMTS(db_con) \
	(CON_MYSQL_PS(db_con)->stmts)
#define CON_PS_OUTCOL(_db_con, _i) \
	((CON_MYSQL_PS(_db_con)->out_bufs)[_i])


int db_mysql_connect(struct my_con* ptr);


/*
 * Create a new connection structure,
 * open the MySQL connection and set reference count to 1
 */
struct my_con* db_mysql_new_connection(const struct db_id* id);


/*
 * Close the connection and release memory
 */
void db_mysql_free_connection(struct pool_con* con);

#endif /* MY_CON_H */
