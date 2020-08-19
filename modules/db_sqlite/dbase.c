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
#define COUNT_BUF_SIZE 2048

static str query_holder = {NULL,0};
extern int db_sqlite_alloc_limit;

char count_buf[COUNT_BUF_SIZE]="select count(*)";
str count_str = {count_buf, sizeof(COUNT_QUERY)-1};

static inline int db_copy_rest_of_count(const str* _qh, str* count_query);
static int db_sqlite_store_result(const db_con_t* _h, db_res_t** _r, const db_val_t* v, const int n);
#ifdef SQLITE_BIND
static int db_sqlite_bind_values(sqlite3_stmt* stmt, const db_val_t* _v, const int _n);
#endif
static int db_sqlite_free_result_internal(const db_con_t* _h, db_res_t* _r);

static int db_sqlite_submit_dummy_query(const db_con_t* _h, const str* _s)
{
	query_holder = *_s;

	return 0;
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

static inline int db_copy_rest_of_count(const str* _qh, str* count_query)
{

	char* found;
	const str searched_str = {" from ", sizeof(" from ")-1};

	count_query->len = sizeof(COUNT_QUERY)-1;
	if ((found=str_strstr(_qh, &searched_str)) != NULL) {
		const int len=_qh->len-(found-_qh->s);
		/* check for overflow */
		if (len > COUNT_BUF_SIZE-(sizeof(COUNT_QUERY)-1)) {
			LM_ERR("query too big! try reducing the size of your query!"
					"Current max size [%d]!\n", COUNT_BUF_SIZE);
			return -1;
		}

		memcpy(count_query->s+count_query->len, found, len);
		count_query->len += len;

		return 0;
	}

	return -1;
}

static inline int
db_sqlite_get_query_rows(const db_con_t* _h, const str* query, const db_val_t* _v, const int _n)
{
	int ret;
	sqlite3_stmt* stmt;

again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h), query->s, query->len, &stmt, NULL);
	if (ret == SQLITE_BUSY)
		goto again;

	if (ret != SQLITE_OK) {
		LM_ERR("failed to prepare query\n");
		return -1;
	}

#ifdef SQLITE_BIND
	if (db_sqlite_bind_values(stmt, _v, _n) != SQLITE_OK) {
		LM_ERR("failed to bind values\n");
		return -1;
	}
#endif

again2:
	ret=sqlite3_step(stmt);
	if (ret == SQLITE_BUSY)
		goto again2;

	if (ret != SQLITE_ROW) {
		sqlite3_finalize(stmt);
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
#ifdef SQLITE_BIND
	db_ps_t ps;

	CON_SET_CURR_PS(_h, &ps);
#else
	CON_RESET_CURR_PS(_h);
#endif
	CON_RAW_QUERY(_h) = 0;

	ret = db_do_query(_h, _k, _op, _v, _c, _n, _nc, _o, NULL,
		db_sqlite_val2str, db_sqlite_submit_dummy_query, NULL);
	if (ret != 0) {
		if (_r)
			*_r = NULL;
		return ret;
	}

	if (db_copy_rest_of_count(&query_holder, &count_str)) {
		LM_ERR("failed to build row counter query\n");
		return -1;
	}


again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
				query_holder.s, query_holder.len, &CON_SQLITE_PS(_h), NULL);

	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n", sqlite3_errmsg(CON_CONNECTION(_h)));

#ifdef SQLITE_BIND
	if (db_sqlite_bind_values(CON_SQLITE_PS(_h), _v, _n) != SQLITE_OK) {
		LM_ERR("failed to bind values\n");
		sqlite3_finalize(CON_SQLITE_PS(_h));
		return -1;
	}
#endif

	if (_r) {
		ret = db_sqlite_store_result(_h, _r, _v, _n);
	} else {
		/* need to fetch now the total number of rows in query
		 * because later won't have the query string */
		ret = CON_PS_ROWS(_h) = db_sqlite_get_query_rows(_h, &count_str, _v, _n);
	}
	if( ret < 0 ){
		db_sqlite_free_result_internal(_h,*_r);
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
	sqlite3_stmt* stmt;

	if (!_r) {
		LM_ERR("null result!\n");
		return -1;
	}

	if (!_h || nrows < 0) {
		LM_ERR("Invalid parameter value\n");
		db_sqlite_free_result_internal(_h,*_r);
		return -1;
	}

	/* exit if the fetch count is zero */
	if (nrows == 0) {
		db_sqlite_free_result_internal(_h,*_r);
		*_r = 0;
		return 0;
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
			db_sqlite_free_result_internal(_h,*_r);
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
		db_sqlite_free_result_internal(_h,*_r);
		return -5;
	}

	i = 0;
	ret=-1;

	stmt = CON_SQLITE_PS(_h);
	while (ret != SQLITE_DONE) {
		if (i == nrows) {
			RES_LAST_ROW(*_r) = i - 1;
			break;
		}

		ret = sqlite3_step(stmt);
		if (ret == SQLITE_DONE) {
			RES_ROW_N(*_r) = RES_LAST_ROW(*_r) = RES_NUM_ROWS(*_r) = i;
			sqlite3_finalize(CON_SQLITE_PS(_h));
			CON_SQLITE_PS(_h) = NULL;
			break;
		}

		if (i >= RES_ROW_N(*_r) && i < nrows) {
			db_sqlite_realloc_rows(*_r, RES_ROW_N(*_r) + db_sqlite_alloc_limit);
			RES_ROW_N(*_r) += db_sqlite_alloc_limit;
		}

		if ((ret=db_sqlite_convert_row(_h, *_r, &(RES_ROWS(*_r)[i]))) < 0) {
			LM_ERR("error while converting row #%d\n", i);
			RES_ROW_N(*_r) = i;
			db_sqlite_free_result_internal(_h,*_r);
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
	static char sql_str[SQL_BUF_LEN];
	int ret=-1, i=0;
	char* errmsg;
	str select_str={"select", 6};

	str _scpy;

	CON_RESET_CURR_PS(_h);
	while (i < _s->len && !isalpha(_s->s[i])) i++;

	/* if any blank spaces or anything else before the actual query */
	if (i) {
		_scpy.s   = _s->s+i;
		_scpy.len = _s->len-i;
	} else {
		_scpy = *_s;
	}

	if (_scpy.len >= select_str.len &&
		str_strncasecmp(&_scpy, &select_str, select_str.len)) {
		/* not a select statement; can execute the query and exit*/
		if (_s->len + 1 > SQL_BUF_LEN) {
			LM_ERR("query too big! try reducing the size of your query!"
				"Current max size [%d]!\n", SQL_BUF_LEN);
			return -1;
		}
		memcpy(sql_str, _s->s, _s->len);
		sql_str[_s->len] = '\0';
		if (sqlite3_exec(CON_CONNECTION(_h),
			sql_str, NULL, NULL, &errmsg)) {
			LM_ERR("query failed: %s\n", errmsg);
			sqlite3_free(errmsg);
			return -2;
		}

		return 0;
	}

	CON_RAW_QUERY(_h) = 1;

	if (db_copy_rest_of_count(&_scpy, &count_str)) {
		LM_ERR("failed to build count str!\n");
		return -1;
	}

again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
				_s->s, _s->len, &CON_SQLITE_PS(_h), NULL);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n",
				sqlite3_errmsg(CON_CONNECTION(_h)));

	if (_r) {
		ret = db_sqlite_store_result(_h, _r, NULL, 0);
	} else {
		/* need to fetch now the total number of rows in query
		 * because later won't have the query string */
		ret = CON_PS_ROWS(_h) = db_sqlite_get_query_rows(_h, &count_str, NULL, 0);
	}
	if( ret < 0 ){
		db_sqlite_free_result_internal(_h,*_r);
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
	sqlite3_stmt* stmt;
#ifdef SQLITE_BIND
	db_ps_t ps;

	CON_SET_CURR_PS(_h, &ps);
#else
	CON_RESET_CURR_PS(_h);
#endif
	ret = db_do_insert(_h, _k, _v, _n, db_sqlite_val2str,
								db_sqlite_submit_dummy_query);
	if (ret != 0) {
		return ret;
	}

again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
			query_holder.s, query_holder.len, &stmt, NULL);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n",
				sqlite3_errmsg(CON_CONNECTION(_h)));

#ifdef SQLITE_BIND
	if ((ret=db_sqlite_bind_values(stmt, _v, _n)) != SQLITE_OK) {
		LM_ERR("failed to bind values (%d)\n", ret);
		return -1;
	}
#endif

again2:
	ret = sqlite3_step(stmt);
	if (ret==SQLITE_BUSY)
		goto again2;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	sqlite3_finalize(stmt);

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
	sqlite3_stmt* stmt;
#ifdef SQLITE_BIND
	db_ps_t ps;

	CON_SET_CURR_PS(_h, &ps);
#else
	CON_RESET_CURR_PS(_h);
#endif
	ret = db_do_delete(_h, _k, _o, _v, _n, db_sqlite_val2str,
		db_sqlite_submit_dummy_query);
	if (ret != 0) {
		return ret;
	}


again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
			query_holder.s, query_holder.len, &stmt, NULL);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n",
				sqlite3_errmsg(CON_CONNECTION(_h)));

#ifdef SQLITE_BIND
	if (db_sqlite_bind_values(stmt, _v, _n) != SQLITE_OK) {
		LM_ERR("failed to bind values\n");
		return -1;
	}
#endif

again2:
	ret = sqlite3_step(stmt);
	if (ret==SQLITE_BUSY)
		goto again2;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	sqlite3_finalize(stmt);

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
	sqlite3_stmt* stmt;
#ifdef SQLITE_BIND
	db_ps_t ps;

	CON_SET_CURR_PS(_h, &ps);
#else
	CON_RESET_CURR_PS(_h);
#endif
	ret = db_do_update(_h, _k, _o, _v, _uk, _uv, _n, _un,
			db_sqlite_val2str, db_sqlite_submit_dummy_query);
	if (ret != 0) {
		return ret;
	}

again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
			query_holder.s, query_holder.len, &stmt, NULL);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n",
				sqlite3_errmsg(CON_CONNECTION(_h)));

#ifdef SQLITE_BIND
	if (db_sqlite_bind_values(stmt, _uv, _un) != SQLITE_OK
			&& db_sqlite_bind_values(stmt, _v, _n)) {
		LM_ERR("failed to bind values\n");
		return -1;
	}
#endif

again2:
	ret = sqlite3_step(stmt);
	if (ret==SQLITE_BUSY)
		goto again2;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	sqlite3_finalize(stmt);

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
	sqlite3_stmt* stmt;
#ifdef SQLITE_BIND
	db_ps_t ps;

	CON_SET_CURR_PS(_h, &ps);
#else
	CON_RESET_CURR_PS(_h);
#endif
	ret = db_do_replace(_h, _k, _v, _n, db_sqlite_val2str,
			db_sqlite_submit_dummy_query);
	if (ret != 0) {
		return ret;
	}

again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
			query_holder.s, query_holder.len, &stmt, NULL);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n",
				sqlite3_errmsg(CON_CONNECTION(_h)));

#ifdef SQLITE_BIND
	if (db_sqlite_bind_values(stmt, _v, _n) != SQLITE_OK) {
		LM_ERR("failed to bind values\n");
		return -1;
	}
#endif

again2:
	ret = sqlite3_step(stmt);
	if (ret==SQLITE_BUSY)
		goto again2;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	sqlite3_finalize(stmt);

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
	static str  sql_str;
	static char sql_buf[SQL_BUF_LEN];
	sqlite3_stmt* stmt;

	if ((!_h) || (!_k) || (!_v) || (!_n)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
#ifdef SQLITE_BIND
	db_ps_t ps;

	CON_SET_CURR_PS(_h, &ps);
#endif
	ret = snprintf(sql_buf, SQL_BUF_LEN, "insert or replace into %.*s (",
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

	sql_str.s = sql_buf;
	sql_str.len = off;

again:
	ret=sqlite3_prepare_v2(CON_CONNECTION(_h),
			sql_str.s, sql_str.len, &stmt, NULL);
	if (ret==SQLITE_BUSY)
		goto again;
	if (ret!=SQLITE_OK)
		LM_ERR("failed to prepare: (%s)\n",
				sqlite3_errmsg(CON_CONNECTION(_h)));

#ifdef SQLITE_BIND
	if (db_sqlite_bind_values(stmt, _v, _n) != SQLITE_OK) {
		LM_ERR("failed to bind values\n");
		return -1;
	}
#endif

again2:
	ret = sqlite3_step(stmt);
	if (ret==SQLITE_BUSY)
		goto again2;

	if (ret != SQLITE_DONE) {
		LM_ERR("insert query failed %s\n", sqlite3_errmsg(CON_CONNECTION(_h)));
		return -1;
	}

	sqlite3_finalize(stmt);

	return 0;

#undef SQL_BUF_LEN
error:
	LM_ERR("error while preparing insert_update operation\n");
	return -1;
}


static int db_sqlite_free_result_internal(const db_con_t* _h, db_res_t* _r)
{
	return db_sqlite_free_result(*(db_con_t**)&_h, _r);
}

/**
 * Release a result set from memory.
 * \param _h handle to the database
 * \param _r result set that should be freed
 * \return zero on success, negative value on failure
 */
int db_sqlite_free_result(db_con_t* _h, db_res_t* _r)
{
	int i, j;
	db_val_t* val;

	if (!_h) {
		LM_ERR("invalid database handle\n");
		return -1;
	}

	if( CON_SQLITE_PS(_h) ){
		sqlite3_finalize(CON_SQLITE_PS(_h));
		CON_SQLITE_PS(_h) = NULL;
	}

	if (!_r) {
		LM_DBG("nothing to free!\n");
		return 0;
	}


	db_free_columns(_r);

	/* for each row iterate through all the values and free them
	 * the values array(RES_ROW_N rows with RES_COL_N values for
	 * each row) is allocated using a single chunk so in order
	 * to free the array(check db_sqlite_allocate_rows function ) */
	if (RES_ROWS(_r)) {
		for(i=0; i < RES_ROW_N(_r); i++) {
			for (j=0; j < RES_COL_N(_r); j++) {
				val = &(_r->rows[i].values[j]);
				if (VAL_NULL(val) || !VAL_FREE(val))
					continue;

				switch (VAL_TYPE(val)) {
					case DB_STRING:
					case DB_STR:
						/*
						 * FIXME
						 * see row.c +121 ( last comment ) for
						 * explanation why this will work
						 *
						 */
						pkg_free(VAL_STR(val).s);
						VAL_STR(val).s = 0;
						break;
					case DB_BLOB:
						pkg_free(VAL_BLOB(val).s);
						VAL_BLOB(val).s = 0;
						break;
					default:
						break;
				}

			}
		}
		/* free all the columns; they are all allocated at once */
		pkg_free( _r->rows[0].values);
		/* free the rows */
		pkg_free( _r->rows);
		_r->rows = NULL;
	}

	RES_ROW_N(_r) = 0;
	pkg_free(_r);
	_r = NULL;

	return 0;
}

/**
 * Retrieve a result set
 * \param _h handle to the database
 * \param _r result set that should be retrieved
 * \return zero on success, negative value on failure
 */

static int db_sqlite_store_result(const db_con_t* _h, db_res_t** _r, const db_val_t* _v, const int _n)
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

	rows=db_sqlite_get_query_rows(_h, &count_str, _v, _n);

	/* reset the length to initial for future uses */
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

#ifdef SQLITE_BIND
static int db_sqlite_bind_values(sqlite3_stmt* stmt, const db_val_t* v, const int n)
{
	int i, ret;

	if (n>0 && v) {
		for (i=0; i<n; i++) {
			if (VAL_NULL(v+i)) {
				ret=sqlite3_bind_null(stmt, i+1);
				goto check_ret;
			}


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
					return 1;
			}

check_ret:
			if (ret != SQLITE_OK) {
				return ret;
			}
		}
	}

	return SQLITE_OK;
}
#endif
