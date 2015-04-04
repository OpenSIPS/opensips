/**
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 *  2015-02-18  initial version (Ionut Ionita)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../db/db_query.h"
#include "../../db/db_async.h"
#include "../../db/db_ut.h"
#include "../../db/db_insertq.h"
#include "../../db/db_res.h"
#include "my_con.h"
#include "val.h"
#include "res.h"
#include "row.h"
#include "dbase.h"

#define COUNT_QUERY "select count(*)"

static str query_holder = {NULL,0};
extern int db_sqlite_alloc_limit;

/* TODO set this value somehow(200) */
char count_buf[200]="select count(*)";
str count_str = {count_buf, sizeof(COUNT_QUERY)-1};

static int db_sqlite_prepare_query(const db_con_t* conn, const str *query,
	const db_val_t* v, int n, const db_val_t* uv, int un);
static inline int db_copy_rest_of_count(const str* query_holder, str* count_query);
static int db_sqlite_store_result(const db_con_t* _h,
							const db_val_t* v, const int _n, db_res_t** _r);
static int db_sqlite_bind_values(sqlite3_stmt* stmt, const db_val_t* v, const int n);

static int db_sqlite_submit_dummy_query(const db_con_t* _h, const str* _s)
{
	query_holder = *_s;

	return 0;
}

static inline int connect_with_retry(const db_con_t *conn, const int max_tries)
{
	int try, code;

	for (try = 0 ; try<max_tries ; try++) {
		if ((code = db_sqlite_connect((struct my_con*)(conn)->tail)) == 0) {
			/* we reconnected back */
			CON_DISCON(conn) = 0;
			LM_INFO("re-connected successful for %p\n", (void*)conn->tail);
			return 0;
		} else {
			LM_INFO("temporary re-connect failure for %p\n",(void*)conn->tail);
		}
	}
	LM_ERR("permanent re-connect failure for %p\n", (void*)conn->tail);
	return 1;
}


static inline void reset_all_statements(const db_con_t* conn)
{
	struct prep_stmt *pq_ptr;
	struct my_stmt_ctx *ctx;

	LM_INFO("reseting all statements on connection: (%p) %p\n",
		conn,(void*)conn->tail);
	for( pq_ptr=CON_PS_LIST(conn); pq_ptr ; pq_ptr=pq_ptr->next ) {
		for (ctx = pq_ptr->stmts ; ctx ; ctx=ctx->next ) {
			LM_DBG("resetting statement (%p,%p) for context %p (%.*s)\n",
				pq_ptr,ctx->stmt, ctx, ctx->table.len,ctx->table.s);
			if (ctx->stmt) {
				sqlite3_clear_bindings(ctx->stmt);
				ctx->stmt = NULL;
				ctx->has_out = 0;
			}
		}
	}
}


static inline void switch_state_to_disconnected(const db_con_t *conn) {
	LM_INFO("disconnect event for %p\n",(void*)conn->tail);
	if (CON_DISCON(conn) == 0) {
		CON_DISCON(conn) = 1;
		reset_all_statements(conn);
	}
}

static inline int wrapper_single_sqlite_stmt_prepare(const db_con_t *conn,
												struct my_stmt_ctx *ctx)
{
	int code;
	if (CON_DISCON(conn))
		return -1;

	code = sqlite3_prepare_v2(CON_CONNECTION(conn), ctx->query.s,
						ctx->query.len, &ctx->stmt, NULL);

	if (code == SQLITE_OK)
		return 0;

	LM_ERR("Can't create sqlite3 statement: %s\n",
			sqlite3_errmsg((sqlite3*)CON_CONNECTION(conn)));
	return -1;
}

/**
 * Initialize the database module.
 * No function should be called before this
 * \param _url URL used for initialization
 * \return zero on success, negative value on failure
 */
db_con_t* db_sqlite_init(const str* _url)
{
	return db_do_init(_url, (void *)db_sqlite_new_connection);
}

/**
 * Shut down the database module.
 * No function should be called after this
 * \param _h handle to the closed connection
 * \return zero on success, negative value on failure
 */
void db_sqlite_close(db_con_t* _h)
{
	db_do_close(_h, db_sqlite_free_connection);
}


/* complete */
static int has_stmt_ctx(const db_con_t* conn, struct my_stmt_ctx **ctx_p)
{
	struct my_stmt_ctx *ctx;

	if (CON_SQLITE_PS(conn) != NULL) {
		/* search for the context */
		for ( ctx=CON_PS_STMTS(conn) ; ctx ; ctx=ctx->next ) {
			if (ctx->table.len== CON_TABLE(conn)->len &&
			memcmp(ctx->table.s, CON_TABLE(conn)->s, CON_TABLE(conn)->len)==0){
				LM_DBG("ctx found for %.*s\n", ctx->table.len,ctx->table.s);
				*ctx_p = ctx;
				return 1;
			}
		}
	}
	*ctx_p = NULL;
	LM_DBG("ctx not found for %.*s\n",
		CON_TABLE(conn)->len, CON_TABLE(conn)->s);
	return 0;
}


static inline int db_copy_rest_of_count(const str* query_holder, str* count_query)
{

	char* found;
	const str searched_str = {" from ", sizeof(" from ")-1};

	if ((found=str_strstr(query_holder, &searched_str)) != NULL) {
		const int len=query_holder->len-(found-query_holder->s);
		memcpy(count_query->s+count_query->len, found, len);
		count_query->len += len;

		return 0;
	}

	return -1;
}

static inline int db_sqlite_get_query_rows(const db_con_t* _h,
							const db_val_t* _v, const int _n, const str* query)
{
	int ret;
	sqlite3_stmt* stmt;

	sqlite3_prepare_v2(CON_CONNECTION(_h), query->s, query->len, &stmt, NULL);

	if (_n && _v) {
		ret=db_sqlite_bind_values(stmt, _v, _n);
		if (ret != SQLITE_OK) {
			LM_ERR("failed to bind values %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
			return -1;
		}
	}


again:
	ret=sqlite3_step(stmt);
	if (ret == SQLITE_BUSY)
		goto again;

	if (ret != SQLITE_ROW) {
		LM_ERR("failed to fetch query size\n");
		return -1;
	}

	ret=sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);

	return ret;
}

int db_sqlite_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	     const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	     const db_key_t _o, db_res_t** _r)
{
	int ret=-1;
	db_ps_t* ps;


	if (!CON_PS_REFERENCE(_h)) {
		/* hack to be able to always use prepared statements */
		ps = pkg_malloc(sizeof(db_ps_t));
		if (!ps) {
			LM_ERR("no more pkg\n");
			return -1;
		}

		memset(ps, 0, sizeof(db_ps_t));

		*((void***)&_h->curr_ps) = ps;
	}

	/* sqlite supports only prepared statements so all queries will
	 * be treated as prepared statements */

	if (CON_HAS_UNINIT_PS(_h)||!has_stmt_ctx(_h,&(CON_SQLITE_PS(_h)->ctx))) {
		ret = db_do_query(_h, _k, _op, _v, _c, _n, _nc, _o, NULL,
			db_sqlite_val2str, db_sqlite_submit_dummy_query, NULL);
		if (ret != 0) {
			CON_RESET_CURR_PS(_h);
			if (_r)
				*_r = NULL;
			return ret;
		}
	}

	if (db_copy_rest_of_count(&query_holder, &count_str)) {
		LM_ERR("failed to build row counter query\n");
		return -1;
	}

	ret = db_sqlite_prepare_query(_h, &query_holder, _v, _n, NULL, 0);
	if (ret != 0) {
		CON_RESET_CURR_PS(_h);
		if (_r)
			*_r = NULL;
		return ret;
	}

	if (_r) {
		ret = db_sqlite_store_result(_h, _v, _n, _r);
		CON_RESET_CURR_PS(_h);
	} else {
		/* need to fetch now the total number of rows in query
		 * because later won't have the query string */
		CON_PS_ROWS(_h) = db_sqlite_get_query_rows(_h, _v, _n, &count_str);
	}

	return ret;
}

/**
 * Gets a partial result set.
 * \param _h structure representing the database connection
 * \param _r pointer to a structure representing the result
 * \param nrows number of fetched rows
 * \return zero on success, negative value on failure
 */
int db_sqlite_fetch_result(const db_con_t* _h, db_res_t** _r, const int nrows)
{

	int ret;
	int rows, i;

	if (!_h || !_r || nrows < 0) {
		LM_ERR("Invalid parameter value\n");
		return -1;
	}

	/* exit if the fetch count is zero */
	if (nrows == 0) {
		db_free_result(*_r);
		*_r = 0;
		return 0;
	}

	if (!CON_HAS_PS(_h)) {
		LM_ERR("conn should have prepared statement here!\n");
		return -2;
	}

	if(*_r==0) {
		/* Allocate a new result structure */
		*_r = db_new_result();
		if (*_r == 0) {
			LM_ERR("no memory left\n");
			return -2;
		}

		if (db_sqlite_get_columns(_h, *_r) < 0) {
			LM_ERR("error while getting column names\n");
			return -4;
		}

		RES_NUM_ROWS(*_r) = CON_PS_ROWS(_h);

		if (!RES_NUM_ROWS(*_r)) {
			LM_DBG("no rows returned from the query\n");
			RES_ROWS(*_r) = 0;
			return 0;
		}
	} else {
		/* free old rows */
		if(RES_ROWS(*_r)!=0)
			db_free_rows(*_r);
		RES_ROWS(*_r) = 0;
		RES_ROW_N(*_r) = 0;
	}

	/* determine the number of rows remaining to be processed */
	rows = RES_NUM_ROWS(*_r) - RES_LAST_ROW(*_r);

	/* If there aren't any more rows left to process, exit */
	if(rows<=0)
		return 0;

	/* if the fetch count is less than the remaining rows to process */
	/* set the number of rows to process (during this call) equal
	to the fetch count */
	if(nrows < rows)
		rows = nrows;


	RES_ROW_N(*_r) = rows;


	if (db_sqlite_allocate_rows(*_r, rows)!=0) {
		LM_ERR("no memory left\n");
		return -5;
	}

	i = 0;
	ret=-1;
	while (ret != SQLITE_DONE) {
		if (i == nrows) {
			RES_LAST_ROW(*_r) = i - 1;
			break;
		}

		ret = sqlite3_step(CON_PS_STMT(_h));
		if (ret == SQLITE_DONE) {
			RES_ROW_N(*_r) = RES_LAST_ROW(*_r) = RES_NUM_ROWS(*_r) = i;
			sqlite3_reset(CON_PS_STMT(_h));
			break;
		}

		if (i >= RES_ROW_N(*_r) && i < nrows) {
			db_sqlite_realloc_rows(*_r, RES_ROW_N(*_r) + db_sqlite_alloc_limit);
			RES_ROW_N(*_r) += db_sqlite_alloc_limit;
		}

		if ((ret=db_sqlite_convert_row(_h, *_r, &(RES_ROWS(*_r)[i]))) < 0) {
			LM_ERR("error while converting row #%d\n", i);
			RES_ROW_N(*_r) = i;
			db_free_rows(*_r);
			return -4;
		}

		i++;
	}

	return 0;
}


/**
 * Execute a raw SQL query.
 * \param _h handle for the database
 * \param _s raw query string
 * \param _r result set for storage
 * \return zero on success, negative value on failure
 */
int db_sqlite_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r)
{
	int ret=-1;
	char* errmsg;
	db_ps_t* ps;


	if (!CON_PS_REFERENCE(_h)) {
		/* hack to be able to always use prepared statements */
		ps = pkg_malloc(sizeof(db_ps_t));
		if (!ps) {
			LM_ERR("no more pkg\n");
			return -1;
		}

		memset(ps, 0, sizeof(db_ps_t));

		*((void***)&_h->curr_ps) = ps;
	}

	if (db_copy_rest_of_count(&query_holder, &count_str)) {
		/* not a select statement; can execute the query and exit*/
		if (sqlite3_exec(CON_CONNECTION(_h),
							query_holder.s, NULL, NULL, &errmsg)) {
			LM_ERR("query failed: %s\n", errmsg);
			return -2;
		}
		CON_RESET_CURR_PS(_h);

		return 0;
	}



	ret = db_sqlite_prepare_query(_h,_s, NULL, 0, NULL, 0);
	if (ret != 0) {
		CON_RESET_CURR_PS(_h);
		if (_r)
			*_r = NULL;
		return ret;
	}

	if (_r) {
		ret = db_sqlite_store_result(_h, NULL, 0, _r);
		CON_RESET_CURR_PS(_h);
	} else {
		/* need to fetch now the total number of rows in query
		 * because later won't have the query string */
		CON_PS_ROWS(_h) = db_sqlite_get_query_rows(_h, NULL, 0, &count_str);
	}


	return ret;
}

/**
 * Insert a row into a specified table.
 * \param _h structure representing database connection
 * \param _k key names
 * \param _v values of the keys
 * \param _n number of key=value pairs
 * \return zero on success, negative value on failure
 */

int db_sqlite_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n)
{
	int ret=-1;
	db_ps_t* ps;


	if (!CON_PS_REFERENCE(_h)) {
		/* hack to be able to always use prepared statements */
		ps = pkg_malloc(sizeof(db_ps_t));
		if (!ps) {
			LM_ERR("no more pkg\n");
			return -1;
		}

		memset(ps, 0, sizeof(db_ps_t));

		*((void***)&_h->curr_ps) = ps;
	}

	/* sqlite supports only prepared statements so all queries will
	 * be treated as prepared statements */
	if (CON_HAS_UNINIT_PS(_h)||!has_stmt_ctx(_h,&(CON_SQLITE_PS(_h)->ctx))) {
		ret = db_do_insert(_h, _k, _v, _n, db_sqlite_val2str,
			db_sqlite_submit_dummy_query);
		if (ret != 0) {
			CON_RESET_CURR_PS(_h);
			return ret;
		}
	}


	ret = db_sqlite_prepare_query(_h, &query_holder, _v, _n, NULL, 0);
	if (ret != 0) {
		CON_RESET_CURR_PS(_h);
		return ret;
	}

again:
	ret = sqlite3_step(CON_PS_STMT(_h));
	if (ret==SQLITE_BUSY)
		goto again;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	return 0;
}


/**
 * Delete a row from the specified table
 * \param _h structure representing database connection
 * \param _k key names
 * \param _o operators
 * \param _v values of the keys that must match
 * \param _n number of key=value pairs
 * \return zero on success, negative value on failure
 */
int db_sqlite_delete(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const int _n)
{
	int ret;
	db_ps_t* ps;


	if (!CON_PS_REFERENCE(_h)) {
		/* hack to be able to always use prepared statements */
		ps = pkg_malloc(sizeof(db_ps_t));
		if (!ps) {
			LM_ERR("no more pkg\n");
			return -1;
		}

		memset(ps, 0, sizeof(db_ps_t));

		*((void***)&_h->curr_ps) = ps;
	}

	if (CON_HAS_UNINIT_PS(_h)||!has_stmt_ctx(_h,&(CON_SQLITE_PS(_h)->ctx))) {
		ret = db_do_delete(_h, _k, _o, _v, _n, db_sqlite_val2str,
			db_sqlite_submit_dummy_query);
		if (ret != 0) {
			CON_RESET_CURR_PS(_h);
			return ret;
		}
	}

	ret = db_sqlite_prepare_query(_h, &query_holder, _v, _n, NULL, 0);
	if (ret != 0) {
		CON_RESET_CURR_PS(_h);
		return ret;
	}

again:
	ret = sqlite3_step(CON_PS_STMT(_h));
	if (ret==SQLITE_BUSY)
		goto again;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	return 0;
}

/**
 * Update some rows in the specified table
 * \param _h structure representing database connection
 * \param _k key names
 * \param _o operators
 * \param _v values of the keys that must match
 * \param _uk updated columns
 * \param _uv updated values of the columns
 * \param _n number of key=value pairs
 * \param _un number of columns to update
 * \return zero on success, negative value on failure
 */
int db_sqlite_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
	const int _un)
{
	int ret;
	db_ps_t* ps;


	if (!CON_PS_REFERENCE(_h)) {
		/* hack to be able to always use prepared statements */
		ps = pkg_malloc(sizeof(db_ps_t));
		if (!ps) {
			LM_ERR("no more pkg\n");
			return -1;
		}

		memset(ps, 0, sizeof(db_ps_t));

		*((void***)&_h->curr_ps) = ps;
	}

	if (CON_HAS_UNINIT_PS(_h)||!has_stmt_ctx(_h,&(CON_SQLITE_PS(_h)->ctx))) {
		ret = db_do_update(_h, _k, _o, _v, _uk, _uv, _n, _un,
			db_sqlite_val2str, db_sqlite_submit_dummy_query);
		if (ret != 0) {
			CON_RESET_CURR_PS(_h);
			return ret;
		}
	}

	ret = db_sqlite_prepare_query(_h, &query_holder, _v, _n, NULL, 0);
	if (ret != 0) {
		CON_RESET_CURR_PS(_h);
		return ret;
	}

again:
	ret = sqlite3_step(CON_PS_STMT(_h));
	if (ret==SQLITE_BUSY)
		goto again;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	return 0;
}

/**
 * Just like insert, but replace the row if it exists.
 * \param _h database handle
 * \param _k key names
 * \param _v values of the keys that must match
 * \param _n number of key=value pairs
 * \return zero on success, negative value on failure
 */
int db_sqlite_replace(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v, const int _n)
{
	int ret;
	db_ps_t* ps;


	if (!CON_PS_REFERENCE(_h)) {
		/* hack to be able to always use prepared statements */
		ps = pkg_malloc(sizeof(db_ps_t));
		if (!ps) {
			LM_ERR("no more pkg\n");
			return -1;
		}

		memset(ps, 0, sizeof(db_ps_t));

		*((void***)&_h->curr_ps) = ps;
	}

	if (CON_HAS_UNINIT_PS(_h)||!has_stmt_ctx(_h,&(CON_SQLITE_PS(_h)->ctx))) {
		ret = db_do_replace(_h, _k, _v, _n, db_sqlite_val2str,
				db_sqlite_submit_dummy_query);
		if (ret != 0) {
			CON_RESET_CURR_PS(_h);
			return ret;
		}
	}

	ret = db_sqlite_prepare_query(_h, &query_holder, _v, _n, NULL, 0);
	if (ret != 0) {
		CON_RESET_CURR_PS(_h);
		return ret;
	}

again:
	ret = sqlite3_step(CON_PS_STMT(_h));
	if (ret==SQLITE_BUSY)
		goto again;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	return 0;
}

/**
 * Returns the last inserted ID.
 * \param _h database handle
 * \return returns the ID as integer or returns 0 if the previous statement
 * does not use an AUTO_INCREMENT value.
 */
int db_last_inserted_id(const db_con_t* _h)
{
	if (!_h) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	return sqlite3_last_insert_rowid(CON_CONNECTION(_h));
}

 /**
  * Insert a row into a specified table, update on duplicate key.
  * \param _h structure representing database connection
  * \param _k key names
  * \param _v values of the keys
  * \param _n number of key=value pairs
 */
 int db_insert_update(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n)
 {
#define SQL_BUF_LEN 65536
	int off, ret;
	char *errmsg;
	static str  sql_str;
	static char sql_buf[SQL_BUF_LEN];

	if ((!_h) || (!_k) || (!_v) || (!_n)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	CON_RESET_CURR_PS(_h); /* no prepared statements support */

	ret = snprintf(sql_buf, SQL_BUF_LEN, "insert into %.*s (",
		CON_TABLE(_h)->len, CON_TABLE(_h)->s);
	if (ret < 0 || ret >= SQL_BUF_LEN) goto error;
	off = ret;

	ret = db_print_columns(sql_buf + off, SQL_BUF_LEN - off, _k, _n);
	if (ret < 0) return -1;
	off += ret;

	ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, ") values (");
	if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
	off += ret;
	ret = db_print_values(_h, sql_buf + off, SQL_BUF_LEN - off, _v, _n,
		db_sqlite_val2str);
	if (ret < 0) return -1;
	off += ret;

	*(sql_buf + off++) = ')';

	ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, " on duplicate key update ");
	if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
	off += ret;

	ret = db_print_set(_h, sql_buf + off, SQL_BUF_LEN - off, _k, _v, _n,
		db_sqlite_val2str);
	if (ret < 0) return -1;
	off += ret;

	sql_str.s = sql_buf;
	sql_str.len = off;

again:
	ret=sqlite3_exec(CON_CONNECTION(_h), sql_str.s, NULL, NULL, &errmsg);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret) {
		LM_ERR("query failed: %s\n", errmsg);
		return -2;
	}

	return 0;

#undef SQL_BUF_LEN
error:
	LM_ERR("error while preparing insert_update operation\n");
	return -1;
}

/**
 * Release a result set from memory.
 * \param _h handle to the database
 * \param _r result set that should be freed
 * \return zero on success, negative value on failure
 */
int db_sqlite_free_result(db_con_t* _h, db_res_t* _r)
{
	int i;

	if ((!_h) || (!_r)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}


	if (RES_ROWS(_r)) {
		for(i = 0; i < RES_ROW_N(_r); i++)
			db_free_row(&(RES_ROWS(_r)[i]));

		LM_DBG("freeing rows at %p\n", RES_ROWS(_r));
		pkg_free(ROW_VALUES ( &(RES_ROWS(_r)[0]) ));
		pkg_free(RES_ROWS(_r));
		RES_ROWS(_r) = NULL;
	}

	RES_ROW_N(_r) = 0;


	pkg_free(_r);
	_r = NULL;

	return 0;
}





static struct prep_stmt* alloc_new_prepared_stmt(const db_con_t *conn,const db_val_t* v, int n,
			const db_val_t* uv, int un)
{
	struct prep_stmt *pq_ptr;

	pq_ptr = (struct prep_stmt*)pkg_malloc( sizeof(struct prep_stmt) );
	if (pq_ptr==NULL) {
		LM_ERR("no more pkg mem for the a new prepared statement\n");
		return NULL;
	}
	memset( pq_ptr, 0, sizeof(struct prep_stmt));

	return pq_ptr;
}


static int sqlite_re_init_statement(const db_con_t* conn, struct prep_stmt *pq_ptr,
										struct my_stmt_ctx *ctx, int free_ctx)
{
	struct my_stmt_ctx *ctx1, *ctx2;
	int code;
	int i;

	LM_DBG(" query  is <%.*s>, ptr=%p\n",
		ctx->query.len, ctx->query.s, ctx->stmt);

	for( i=0 ; i<2 ; i++ ) {
		/* re-init the statement */
		code = wrapper_single_sqlite_stmt_prepare(conn, ctx);

		if (code < 0) {
			/* got disconnected during call */
			switch_state_to_disconnected(conn);
			if (connect_with_retry(conn, 3) != 0) {
				/* mysql reconnection problem */
				LM_ERR("failed to reconnect before trying "
					"mysql_stmt_prepare()\n");
				break;
			}
			/* if reconnected, run the loop again */
		} else if (code > 0) {
			/* other problems */
			goto error;
		} else {
			return 0; /* success */
		}
	}

	/* destroy the statement only, but keep the context */
	if (ctx->stmt)
		sqlite3_clear_bindings(ctx->stmt);
	else
		LM_ERR("statement already uninitialised while trying to clean up\n");
	ctx->stmt = NULL;
	return -1;

error:
	/* error -> destroy the context only */
	if (ctx->stmt)
		sqlite3_clear_bindings(ctx->stmt);
	else
		LM_ERR("statement already uninitialised while trying to "
			"clean up after error\n");

	if (free_ctx) {
		/* remove the context from STMT list */
		for( ctx1=NULL,ctx2=pq_ptr->stmts ; ctx2 ; ) {
			if (ctx2==ctx) {
				if (ctx1)
					ctx1->next = ctx2->next;
				else
					pq_ptr->stmts = ctx2->next;
				break;
			}
			ctx1 = ctx2;
			ctx2 = ctx2->next;
		}
		pkg_free(ctx);
	} else
		ctx->stmt = NULL;

	return -1;
}

static struct my_stmt_ctx * sqlite_get_new_stmt_ctx(const db_con_t* conn,
														const str *query)
{
	struct my_stmt_ctx *ctx;

	/* new one */
	ctx = (struct my_stmt_ctx*)pkg_malloc
		( sizeof(struct my_stmt_ctx) + CON_TABLE(conn)->len + query->len);
	if (ctx==NULL) {
		LM_ERR("no more pkg mem for statement context\n");
		return NULL;
	}
	memset( ctx, 0,
		sizeof(struct my_stmt_ctx) + CON_TABLE(conn)->len + query->len);
	ctx->table.s = (char*)(ctx+1);
	ctx->table.len = CON_TABLE(conn)->len;
	memcpy( ctx->table.s, CON_TABLE(conn)->s, ctx->table.len);
	ctx->query.s = ctx->table.s + ctx->table.len;
	ctx->query.len = query->len;
	memcpy( ctx->query.s, query->s, query->len);
	ctx->next = 0;
	ctx->has_out = 0;

	if (sqlite_re_init_statement(conn, NULL, ctx, 0) == 0)
		return ctx;
	else {
		/* make sure ctx is freed on every error in re_init_statement */
		pkg_free(ctx);
		return NULL;
	}
}


static int db_sqlite_bind_values(sqlite3_stmt* stmt, const db_val_t* v, const int n)
{
	int i, ret;

	if (n>0 && v) {
		for (i=0; i<n; i++) {
			switch(VAL_TYPE(v+i)) {
				/* every param has '+1' index because in sqlite the leftmost
				 * parameter has index '1' */
				case DB_INT:
					ret=sqlite3_bind_int(stmt, i+1, VAL_INT(v+i));
					break;
				case DB_BIGINT:
					ret=sqlite3_bind_int64(stmt, i+1, VAL_BIGINT(v+i));
					break;
				case DB_DOUBLE:
					ret=sqlite3_bind_double(stmt, i+1, VAL_DOUBLE(v+i));
					break;
				case DB_STRING:
					ret=sqlite3_bind_text(stmt, i+1, VAL_STRING(v+i),
											strlen(VAL_STRING(v+i)), SQLITE_STATIC);
					break;
				case DB_STR:
					ret=sqlite3_bind_text(stmt, i+1, VAL_STR(v+i).s,
											VAL_STR(v+i).len, SQLITE_STATIC);
					break;
				case DB_DATETIME:
					ret=sqlite3_bind_int64(stmt, i+1, (long int)VAL_TIME(v+i));
					break;
				case DB_BLOB:
					ret=sqlite3_bind_blob(stmt, i+1, (void*)VAL_BLOB(v+i).s,
											VAL_BLOB(v+i).len, SQLITE_STATIC);
					break;
				case DB_BITMAP:
					ret=sqlite3_bind_int(stmt, i+1, (int)VAL_BITMAP(v+i));
					break;
				default:
					LM_BUG("invalid db type\n");
					return -1;
			}

			if (ret != SQLITE_OK)
				return ret;
		}
	}

	return SQLITE_OK;
}

/**	only bind the values to the statmenet
 ** the effective query shall be done when the result is fetched
 ** since sqlite only supports synchronous queries
 */
static int db_sqlite_prepare_query(const db_con_t* conn, const str *query,
	const db_val_t* v, int n, const db_val_t* uv, int un)
{
	int ret;
	struct prep_stmt *pq_ptr;
	struct my_stmt_ctx *ctx;

	LM_DBG("conn=%p (tail=%ld) MC=%p\n",conn, conn->tail,CON_CONNECTION(conn));

	if ( CON_SQLITE_PS(conn) == NULL ) {
		/*  First time when this query is run, so we need to init it ->
		**  allocate new structure for prepared statemet and its values
		*/
		LM_DBG("new query=|%.*s|\n", query->len, query->s);

		pq_ptr = alloc_new_prepared_stmt(conn,v, n, uv, un);
		if (pq_ptr==NULL) {
			LM_ERR("failed to allocate a new statement\n");
			return -1;
		}
		/* get a new context */
		ctx = sqlite_get_new_stmt_ctx(conn, query);
		if (ctx==NULL) {
			LM_ERR("failed to create new context\n");
			pkg_free(pq_ptr);
			return -1;
		}

		/* link it */
		pq_ptr->stmts = ctx;
		/* set it as current */
		pq_ptr->ctx = ctx;

		/* link it to the connection */
		pq_ptr->next = CON_PS_LIST(conn);
		CON_PS_LIST(conn) = pq_ptr;
		LM_DBG("new statement(%p) on connection: (%p) %p\n",
			pq_ptr, conn, (void*)conn->tail);
		/* also return it for direct future usage */
		CON_CURR_PS(conn) = pq_ptr;
	} else {
		pq_ptr = CON_SQLITE_PS(conn);

		if (pq_ptr->ctx==NULL) {
			/* get a new context */
			ctx = sqlite_get_new_stmt_ctx(conn, query);
			if (ctx==NULL) {
				LM_ERR("failed to create new context\n");
				return -1;
			}
			/* link it */
			ctx->next = pq_ptr->stmts;
			pq_ptr->stmts = ctx;
			/* set it as current */
			pq_ptr->ctx = ctx;
		} else {
			ctx = pq_ptr->ctx;
			if ( ctx->stmt!=NULL && sqlite_re_init_statement(conn, pq_ptr, ctx, 1)!=0 ) {
				LM_ERR("failed to re-init statement!\n");
				return -1;
			}
		}
	}

	ret=db_sqlite_bind_values(CON_PS_STMT(conn), v, n);
	if (ret != SQLITE_OK)
		goto bind_err;

	ret=db_sqlite_bind_values(CON_PS_STMT(conn), uv, un);
	if (ret != SQLITE_OK)
		goto bind_err;

	return 0;

bind_err:
	LM_ERR("binding values failed\n");
	return -1;
}

/**
 * Retrieve a result set
 * \param _h handle to the database
 * \param _r result set that should be retrieved
 * \return zero on success, negative value on failure
 */

static int db_sqlite_store_result(const db_con_t* _h,
							const db_val_t* _v, const int _n,db_res_t** _r)
{
	int rows;

	if ((!_h) || (!_r)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	*_r = db_new_result();
	if (*_r == 0) {
		LM_ERR("no memory left\n");
		return -2;
	}

	rows=db_sqlite_get_query_rows(_h, _v, _n, &count_str);

	/* reset the length to initial for future uses */
	count_str.len = sizeof(COUNT_QUERY)-1;
	if (rows < 0) {
		LM_ERR("failed to fetch number of rows\n");
		return -1;
	}

	/* trying to fetch all rows
	 * these values are not final values as, in the
	 * meantime, the db can be changed by another process */
	RES_NUM_ROWS(*_r) = RES_ROW_N(*_r) = rows;

	if (db_sqlite_convert_result(_h, *_r) < 0) {
		LM_ERR("error while converting result\n");
		pkg_free(*_r);
		*_r = 0;

		return -4;
	}

	return 0;
}

/**
 * Store the name of table that will be used by subsequent database functions
 * \param _h database handle
 * \param _t table name
 * \return zero on success, negative value on failure
 */
int db_sqlite_use_table(db_con_t* _h, const str* _t)
{
	return db_use_table(_h, _t);
}
