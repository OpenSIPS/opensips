/*
 * Copyright (C) 2007-2008 1&1 Internet AG
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
 */

/**
 * \file db/db_query.c
 * \brief Query helper for database drivers
 *
 * This helper methods for database queries are used from the database
 * SQL driver to do the actual work. Each function uses some functions from
 * the actual driver with function pointers to the concrete, specific
 * implementation.
*/

#include <stdio.h>
#include "../dprint.h"
#include "../locking.h"
#include "db_ut.h"
#include "db_query.h"
#include "db_insertq.h"

static str  sql_str;
static char sql_buf[SQL_BUF_LEN];

int db_do_query(const db_con_t* _h, const db_key_t* _k, const db_op_t* _op,
	const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,
	const db_key_t _o, db_res_t** _r, int (*val2str) (const db_con_t*,
	const db_val_t*, char*, int* _len), int (*submit_query)(const db_con_t*,
	const str*), int (*store_result)(const db_con_t* _h, db_res_t** _r))
{
	int off, ret;

	if (!_h || !val2str || !submit_query || (_r && !store_result)) {
		LM_ERR("invalid parameter value\n");
		goto err_exit;
	}

	if (!_c) {
		ret = snprintf(sql_buf, SQL_BUF_LEN, "select * from %.*s ", CON_TABLE(_h)->len, CON_TABLE(_h)->s);
		if (ret < 0 || ret >= SQL_BUF_LEN) goto error;
		off = ret;
	} else {
		ret = snprintf(sql_buf, SQL_BUF_LEN, "select ");
		if (ret < 0 || ret >= SQL_BUF_LEN) goto error;
		off = ret;

		ret = db_print_columns(sql_buf + off, SQL_BUF_LEN - off, _c, _nc);
		if (ret < 0) goto err_exit;
		off += ret;

		ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, "from %.*s ", CON_TABLE(_h)->len, CON_TABLE(_h)->s);
		if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
		off += ret;
	}
	if (_n) {
		ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, "where ");
		if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
		off += ret;

		ret = db_print_where(_h, sql_buf + off,
				SQL_BUF_LEN - off, _k, _op, _v, _n, val2str);
		if (ret < 0) goto err_exit;
		off += ret;
	}
	if (_o) {
		ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, " order by %.*s", _o->len, _o->s);
		if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
		off += ret;
	}
	/*
	 * Null-terminate the string for the postgres driver. Its query function
	 * don't support a length parameter, so they need this for the correct
	 * function of strlen. This zero is not included in the 'str' length.
	 * We need to check the length here, otherwise we could overwrite the buffer
	 * boundaries if off is equal to SQL_BUF_LEN.
	 */
	if (off + 1 >= SQL_BUF_LEN) goto error;
	sql_buf[off + 1] = '\0';
	sql_str.s = sql_buf;
	sql_str.len = off;

	if (submit_query(_h, &sql_str) < 0) {
		LM_ERR("error while submitting query - [%.*s]\n",sql_str.len,sql_str.s);
		goto err_exit;
	}

	if(_r) {
		int tmp = store_result(_h, _r);
		if (tmp < 0) {
			LM_ERR("error while storing result for query [%.*s]\n",sql_str.len,sql_str.s);
			CON_OR_RESET(_h);
			return tmp;
		}
	}

	CON_OR_RESET(_h);
	return 0;

error:
	LM_ERR("error while preparing query\n");
err_exit:
	if (_r)
		*_r = NULL;
	if (_h)
		CON_OR_RESET(_h);
	return -1;
}


int db_do_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r,
	int (*submit_query)(const db_con_t* _h, const str* _c),
	int (*store_result)(const db_con_t* _h, db_res_t** _r))
{
	if (!_h || !_s || !submit_query || !store_result) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (submit_query(_h, _s) < 0) {
		LM_ERR("error while submitting query\n");
		return -2;
	}

	if(_r) {
		int tmp = store_result(_h, _r);
		if (tmp < 0) {
			LM_ERR("error while storing result\n");
			return tmp;
		}
	}
	return 0;
}


int db_do_insert(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n, int (*val2str) (const db_con_t*, const db_val_t*, char*, int*),
	int (*submit_query)(const db_con_t* _h, const str* _c))
{
	int off, ret,i,no_rows=0;
	db_val_t **buffered_rows = NULL;

	if (!_h || !_k || !_v || !_n || !val2str || !submit_query) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* insert buffering is enabled ? */
	if (CON_HAS_INSLIST(_h) && !CON_HAS_PS(_h))
	{
		LM_DBG("inlist %p\n",CON_HAS_INSLIST(_h));
		if (IS_INSTANT_FLUSH(_h))
		{
			LM_DBG("timer wishing to flush \n");
			/* if caller signals it's flush time ( timer, etc ),
			 * detach rows in queue
			 * the caller is holding the lock at this point */
			no_rows = ql_detach_rows_unsafe(_h->ins_list,&buffered_rows);
			CON_FLUSH_RESET(_h,_h->ins_list);

			if (no_rows == -1)
			{
				LM_ERR("failed to detach rows for insertion\n");
				goto error;
			}

			if (no_rows > 0)
				goto build_query;
			else
			{
				/* caller wanted to make sure that everything if flushed
				 * but queue is empty */
				return 0;
			}
		}

		/* if connection has prepared statement, leave
		the row insertion to the proper module func,
		as the submit_query func provided is a dummy one*/
		if ( (no_rows = ql_row_add(_h->ins_list,_v,&buffered_rows)) < 0)
		{
			LM_ERR("failed to insert row to buffered list \n");
			goto error;
		}

		LM_DBG("no rows = %d\n",no_rows);

		if (no_rows == 0)
		{
			/* wait for queries to pile up */
			return 0;
		}
	}

build_query:
	ret = snprintf(sql_buf, SQL_BUF_LEN, "insert into %.*s (", CON_TABLE(_h)->len, CON_TABLE(_h)->s);
	if (ret < 0 || ret >= SQL_BUF_LEN) goto error;
	off = ret;

	ret = db_print_columns(sql_buf + off, SQL_BUF_LEN - off, _k, _n);
	if (ret < 0) goto error;
	off += ret;

	if (CON_HAS_INSLIST(_h))
	{
		if (buffered_rows != NULL || CON_HAS_PS(_h))
		{
			/* if we have to insert now, build the query
			 *
			 * if a prep stmt is provided,
			 * build a prep stmt with query_buffer_size elements */

			if (CON_HAS_PS(_h))
				no_rows = query_buffer_size;

			ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, ") values");
			if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
			off += ret;

			for (i=0;i<no_rows;i++)
			{
				sql_buf[off++]='(';
				ret = db_print_values(_h, sql_buf + off, SQL_BUF_LEN - off,
										CON_HAS_PS(_h)?_v:buffered_rows[i], _n, val2str);
				if (ret < 0) goto error;
				off += ret;
				sql_buf[off++]=')';

				if (i != (no_rows -1))
					sql_buf[off++]=',';

				/* if we have a PS, leave the function handling prep stmts
				   in the module to free the rows once it's done */
				if (!CON_HAS_PS(_h)) {
					shm_free(buffered_rows[i]);
					buffered_rows[i] = NULL;
				}
			}

			if (off + 1 > SQL_BUF_LEN) goto error0;
			sql_buf[off] = '\0';
			sql_str.s = sql_buf;
			sql_str.len = off;

			goto submit;
		}
		else
		{
			/* wait for queries to pile up */
			return 0;
		}
	}
	else
	{
		ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, ") values (");
		if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error0;
		off += ret;

		ret = db_print_values(_h, sql_buf + off, SQL_BUF_LEN - off, _v, _n, val2str);
		if (ret < 0) goto error0;
		off += ret;

		if (off + 2 > SQL_BUF_LEN) goto error0;
	}

	sql_buf[off++] = ')';
	sql_buf[off] = '\0';
	sql_str.s = sql_buf;
	sql_str.len = off;

submit:
	if (submit_query(_h, &sql_str) < 0) {
	        LM_ERR("error while submitting query\n");
		return -2;
	}
	return 0;

error:
	cleanup_rows(buffered_rows);
error0:
	LM_ERR("error while preparing insert operation\n");
	return -1;
}


int db_do_delete(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const int _n, int (*val2str) (const db_con_t*,
	const db_val_t*, char*, int*), int (*submit_query)(const db_con_t* _h,
	const str* _c))
{
	int off, ret;

	if (!_h || !val2str || !submit_query) {
		LM_ERR("invalid parameter value\n");
		goto err_exit;
	}

	ret = snprintf(sql_buf, SQL_BUF_LEN, "delete from %.*s", CON_TABLE(_h)->len, CON_TABLE(_h)->s);
	if (ret < 0 || ret >= SQL_BUF_LEN) goto error;
	off = ret;

	if (_n) {
		ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, " where ");
		if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
		off += ret;

		ret = db_print_where(_h, sql_buf + off,
				SQL_BUF_LEN - off, _k, _o, _v, _n, val2str);
		if (ret < 0) goto err_exit;
		off += ret;
	}
	if (off + 1 > SQL_BUF_LEN) goto error;
	sql_buf[off] = '\0';
	sql_str.s = sql_buf;
	sql_str.len = off;

	if (submit_query(_h, &sql_str) < 0) {
		LM_ERR("error while submitting query\n");
		CON_OR_RESET(_h);
		return -2;
	}

	CON_OR_RESET(_h);
	return 0;

error:
	LM_ERR("error while preparing delete operation\n");
err_exit:
	if (_h)
		CON_OR_RESET(_h);
	return -1;
}


int db_do_update(const db_con_t* _h, const db_key_t* _k, const db_op_t* _o,
	const db_val_t* _v, const db_key_t* _uk, const db_val_t* _uv, const int _n,
	const int _un, int (*val2str) (const db_con_t*, const db_val_t*, char*, int*),
	int (*submit_query)(const db_con_t* _h, const str* _c))
{
	int off, ret;

	if (!_h || !_uk || !_uv || !_un || !val2str || !submit_query) {
		LM_ERR("invalid parameter value\n");
		goto err_exit;
	}

	ret = snprintf(sql_buf, SQL_BUF_LEN, "update %.*s set ", CON_TABLE(_h)->len, CON_TABLE(_h)->s);
	if (ret < 0 || ret >= SQL_BUF_LEN) goto error;
	off = ret;

	ret = db_print_set(_h, sql_buf + off, SQL_BUF_LEN - off, _uk, _uv, _un, val2str);
	if (ret < 0) goto err_exit;
	off += ret;

	if (_n) {
		ret = snprintf(sql_buf + off, SQL_BUF_LEN - off, " where ");
		if (ret < 0 || ret >= (SQL_BUF_LEN - off)) goto error;
		off += ret;

		ret = db_print_where(_h, sql_buf + off, SQL_BUF_LEN - off, _k, _o, _v, _n, val2str);
		if (ret < 0) goto err_exit;
		off += ret;
	}
	if (off + 1 > SQL_BUF_LEN) goto error;
	sql_buf[off] = '\0';
	sql_str.s = sql_buf;
	sql_str.len = off;

	if (submit_query(_h, &sql_str) < 0) {
		LM_ERR("error while submitting query\n");
		CON_OR_RESET(_h);
		return -2;
	}

	CON_OR_RESET(_h);
	return 0;

error:
	LM_ERR("error while preparing update operation\n");
err_exit:
	if(_h)
		CON_OR_RESET(_h);
	return -1;
}


int db_do_replace(const db_con_t* _h, const db_key_t* _k, const db_val_t* _v,
	const int _n, int (*val2str) (const db_con_t*, const db_val_t*, char*,
	int*), int (*submit_query)(const db_con_t* _h, const str* _c))
{
	int off, ret;

	if (!_h || !_k || !_v || !val2str|| !submit_query) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	ret = snprintf(sql_buf, SQL_BUF_LEN, "replace into %.*s (",
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
	val2str);
	if (ret < 0) return -1;
	off += ret;

	if (off + 2 > SQL_BUF_LEN) goto error;
	sql_buf[off++] = ')';
	sql_buf[off] = '\0';
	sql_str.s = sql_buf;
	sql_str.len = off;

	if (submit_query(_h, &sql_str) < 0) {
	        LM_ERR("error while submitting query\n");
		return -2;
	}
	return 0;

 error:
	LM_ERR("error while preparing replace operation\n");
	return -1;
}
