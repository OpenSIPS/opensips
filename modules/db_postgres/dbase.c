/*
 * POSTGRES module, portions of this code were templated using
 * the mysql module, thus it's similarity.
 *
 * Copyright (C) 2003 August.Net Services, LLC
 * Copyright (C) 2006 Norman Brandinger
 * Copyright (C) 2008 1&1 Internet AG
 * Copyright (C) 2019 OpenSIPS project
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
 * 2006-07-28 within pg_get_result(): added check to immediatly return of no
 *            result set was returned added check to only execute
 *            convert_result() if PGRES_TUPLES_OK added safety check to avoid
 *            double pg_free_result() (norm)
 * 2006-08-07 Rewrote pg_get_result().
 *            Additional debugging lines have been placed through out the code.
 *            Added Asynchronous Command Processing (PQsendQuery/PQgetResult)
 *            instead of PQexec. this was done in preparation of adding FETCH
 *            support.  Note that PQexec returns a result pointer while
 *            PQsendQuery does not.  The result set pointer is obtained from
 *            a call (or multiple calls) to PQgetResult.
 *            Removed transaction processing calls (BEGIN/COMMIT/ROLLBACK) as
 *            they added uneeded overhead.  Klaus' testing showed in excess of
 *            1ms gain by removing each command.  In addition, OpenSIPS only
 *            issues single queries and is not, at this time transaction aware.
 *            The transaction processing routines have been left in place
 *            should this support be needed in the future.
 *            Updated logic in pg_query / pg_raw_query to accept a (0) result
 *            set (_r) parameter.  In this case, control is returned
 *            immediately after submitting the query and no call to
 *            pg_get_results() is performed. This is a requirement for
 *            FETCH support. (norm)
 * 2006-10-27 Added fetch support (norm)
 *            Removed dependency on aug_* memory routines (norm)
 *            Added connection pooling support (norm)
 *            Standardized API routines to pg_* names (norm)
 * 2006-11-01 Updated pg_insert(), pg_delete(), pg_update() and
 *            pg_get_result() to handle failed queries.  Detailed warnings
 *            along with the text of the failed query is now displayed in the
 *            log. Callers of these routines can now assume that a non-zero
 *            rc indicates the query failed and that remedial action may need
 *            to be taken. (norm)
 */

#define MAXCOLUMNS	512

#include <string.h>
#include <stdio.h>
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../db/db.h"
#include "../../db/db_ut.h"
#include "../../db/db_query.h"
#include "../../db/db_insertq.h"
#include "../../db/db_async.h"
#include "dbase.h"
#include "pg_con.h"
#include "val.h"
#include "res.h"

extern int db_postgres_exec_query_threshold;
extern int max_db_queries;

static int submit_func_called;

static int free_query(const db_con_t* _con);


/*
** pg_init	initialize database for future queries
**
**	Arguments :
**		char *_url;	sql database to open
**
**	Returns :
**		db_con_t * NULL upon error
**		db_con_t * if successful
**
**	Notes :
**		pg_init must be called prior to any database functions.
*/

db_con_t *db_postgres_init(const str* _url)
{
	return db_do_init(_url, (void*) db_postgres_new_connection);
}


/*
** pg_close	last function to call when db is no longer needed
**
**	Arguments :
**		db_con_t * the connection to shut down, as supplied by pg_init()
**
**	Returns :
**		(void)
**
**	Notes :
**		All memory and resources are freed.
*/

void db_postgres_close(db_con_t* _h)
{
	db_do_close(_h, db_postgres_free_connection);
}

/*
** submit_query	run a query
**
**	Arguments :
**		db_con_t *	as previously supplied by pg_init()
**		char *_s	the text query to run
**
**	Returns :
**		0 upon success
**		negative number upon failure
*/

static int db_postgres_submit_query(const db_con_t* _con, const str* _s)
{
	int i,ret=0;
	ExecStatusType result;
	PGresult *res = NULL;
	struct timeval start;

	if(! _con || !_s || !_s->s)
	{
		LM_ERR("invalid parameter value\n");
		return(-1);
	}

	submit_func_called = 1;

	/* this bit of nonsense in case our connection get screwed up */
	switch(PQstatus(CON_CONNECTION(_con)))
	{
		case CONNECTION_OK:
			break;
		case CONNECTION_BAD:
			LM_DBG("connection reset\n");
			PQreset(CON_CONNECTION(_con));
			break;
		case CONNECTION_STARTED:
		case CONNECTION_MADE:
		case CONNECTION_AWAITING_RESPONSE:
		case CONNECTION_AUTH_OK:
		case CONNECTION_SETENV:
		case CONNECTION_SSL_STARTUP:
		case CONNECTION_NEEDED:
		default:
			LM_ERR("%p PQstatus(%s) invalid: %.*s\n", _con,
				PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
			return -1;
	}

	for (i=0;i<max_db_queries;i++) {
		/* free any previous query that is laying about */
		if(CON_RESULT(_con)) {
			free_query(_con);
		}
		start_expire_timer(start,db_postgres_exec_query_threshold);
		ret = PQsendQuery(CON_CONNECTION(_con), _s->s);
		_stop_expire_timer(start, db_postgres_exec_query_threshold,
							"pgsql query", _s->s, _s->len, 0,
							sql_slow_queries, sql_total_queries);
		/* exec the query */
		if (ret) {
			LM_DBG("%p PQsendQuery(%.*s)\n", _con, _s->len, _s->s);

			while (1) {
				if ((res = PQgetResult(CON_CONNECTION(_con)))) {
					CON_RESULT(_con) = res;
				} else {
					break;
				}
			}

			result = PQresultStatus(CON_RESULT(_con));
			if(result==PGRES_FATAL_ERROR)
				goto reconnect;
			else return 0;
		} else {
reconnect:
			/*  reconnection attempt - if this is the case */
			LM_DBG("%p PQsendQuery failed: %s Query: %.*s\n", _con,
			PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
			if(PQstatus(CON_CONNECTION(_con))!=CONNECTION_OK) {
				LM_DBG("connection reset\n");
				PQreset(CON_CONNECTION(_con));
			} else {
				/* failure not due to connection loss - no point in retrying */
				if(CON_RESULT(_con)) {
					free_query(_con);
				}
				break;
			}
		}
	}

	LM_ERR("%p PQsendQuery Error: %s Query: %.*s\n", _con,
	PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
	return -1;
}

/*
** run an async query
**
**	Arguments :
**		db_con_t *	as previously supplied by pg_init()
**		char *_s	the text query to run
**
**	Returns :
**		0 upon success
**		negative number upon failure
*/

static int db_postgres_submit_async_query(const db_con_t* _con, const str* _s)
{
	int i,ret=0;
	struct timeval start;

	if(! _con || !_s || !_s->s)
	{
		LM_ERR("invalid parameter value\n");
		return(-1);
	}

	submit_func_called = 1;

	/* this bit of nonsense in case our connection get screwed up */
	switch(PQstatus(CON_CONNECTION(_con)))
	{
		case CONNECTION_OK:
			break;
		case CONNECTION_BAD:
			LM_DBG("connection reset\n");
			PQreset(CON_CONNECTION(_con));
			break;
		case CONNECTION_STARTED:
		case CONNECTION_MADE:
		case CONNECTION_AWAITING_RESPONSE:
		case CONNECTION_AUTH_OK:
		case CONNECTION_SETENV:
		case CONNECTION_SSL_STARTUP:
		case CONNECTION_NEEDED:
		default:
			LM_ERR("%p PQstatus(%s) invalid: %.*s\n", _con,
				PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
			return -1;
	}

	for (i=0;i<max_db_queries;i++) {
		/* free any previous query that is laying about */
		if(CON_RESULT(_con)) {
			free_query(_con);
		}
		start_expire_timer(start,db_postgres_exec_query_threshold);
		ret = PQsendQuery(CON_CONNECTION(_con), _s->s);
		_stop_expire_timer(start, db_postgres_exec_query_threshold,
						"pgsql query", _s->s, _s->len, 0,
						sql_slow_queries, sql_total_queries);
		/* exec the query */
		if (ret) {
			LM_DBG("%p PQsendQuery(%.*s)\n", _con, _s->len, _s->s);
			return 0;
		} else {
			LM_DBG("%p PQsendQuery failed: %s Query: %.*s\n", _con,
			PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
			if(PQstatus(CON_CONNECTION(_con))!=CONNECTION_OK) {
				LM_DBG("connection reset\n");
				PQreset(CON_CONNECTION(_con));
			} else {
				/* failure not due to connection loss - no point in retrying */
				if(CON_RESULT(_con)) {
					free_query(_con);
				}
				break;
			}
		}
	}

	LM_ERR("%p PQsendQuery Error: %s Query: %.*s\n", _con,
	PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
	return -1;
}

/*
 *
 * pg_fetch_result: Gets a partial result set.
 *
 */
int db_postgres_fetch_result(const db_con_t* _con, db_res_t** _res, const int nrows)
{
	int rows;
	ExecStatusType pqresult;

	if (!_con || !_res || nrows < 0) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* exit if the fetch count is zero */
	if (nrows == 0) {
		if (*_res)
			db_free_result(*_res);

		*_res = 0;
		return 0;
	}

	if (*_res == NULL) {
		/* Allocate a new result structure */
		*_res = db_new_result();

		pqresult = PQresultStatus(CON_RESULT(_con));
		LM_DBG("%p PQresultStatus(%s) PQgetResult(%p)\n", _con,
			PQresStatus(pqresult), CON_RESULT(_con));

		switch(pqresult) {
			case PGRES_COMMAND_OK:
				/* Successful completion of a command returning no data
				 * (such as INSERT or UPDATE). */
				return 0;

			case PGRES_TUPLES_OK:
				/* Successful completion of a command returning data
				 * (such as a SELECT or SHOW). */
				if (db_postgres_get_columns(_con, *_res) < 0) {
					LM_ERR("failed to get column names\n");
					return -2;
				}
				break;

			case PGRES_FATAL_ERROR:
				LM_ERR("%p - invalid query, execution aborted\n", _con);
				LM_ERR("%p - PQresultStatus(%s)\n",_con,PQresStatus(pqresult));
				LM_ERR("%p: %s\n",_con,PQresultErrorMessage(CON_RESULT(_con)));
				if (*_res) {
					db_free_result(*_res);
					*_res = 0;
				}
				return -3;

			case PGRES_EMPTY_QUERY:
			/* notice or warning */
			case PGRES_NONFATAL_ERROR:
			/* status for COPY command, not used */
			case PGRES_COPY_OUT:
			case PGRES_COPY_IN:
			/* unexpected response */
			case PGRES_BAD_RESPONSE:
			default:
				LM_ERR("%p - probable invalid query\n", _con);
				LM_ERR("%p - PQresultStatus(%s)\n",_con,PQresStatus(pqresult));
				LM_ERR("%p: %s\n",_con,PQresultErrorMessage(CON_RESULT(_con)));
				if (*_res)
					db_free_result(*_res);
				*_res = 0;
				return -4;
		}

	} else {
		if(RES_ROWS(*_res) != NULL) {
			db_free_rows(*_res);
		}
		RES_ROWS(*_res) = 0;
		RES_ROW_N(*_res) = 0;
	}

	/* Get the number of rows (tuples) in the query result. */
	RES_NUM_ROWS(*_res) = PQntuples(CON_RESULT(_con));

	/* determine the number of rows remaining to be processed */
	rows = RES_NUM_ROWS(*_res) - RES_LAST_ROW(*_res);

	/* If there aren't any more rows left to process, exit */
	if (rows <= 0)
		return 0;

	/* if the fetch count is less than the remaining rows to process                 */
	/* set the number of rows to process (during this call) equal to
	 * the fetch count */
	if (nrows < rows)
		rows = nrows;

	RES_ROW_N(*_res) = rows;

	LM_DBG("converting row %d of %d count %d\n", RES_LAST_ROW(*_res),
			RES_NUM_ROWS(*_res), RES_ROW_N(*_res));

	if (db_postgres_convert_rows(_con, *_res) < 0) {
		LM_ERR("failed to convert rows\n");
		if (*_res)
			db_free_result(*_res);

		*_res = 0;
		return -3;
	}

	/* update the total number of rows processed */
	RES_LAST_ROW(*_res) += rows;
	return 0;
}

/*
** free_query	clear the db channel and clear any old query result status
**
**	Arguments :
**		db_con_t *	as previously supplied by pg_init()
**
**	Returns :
**		0 upon success
**		negative number upon failure
*/

static int free_query(const db_con_t* _con)
{
	if(CON_RESULT(_con))
	{
		LM_DBG("PQclear(%p) result set\n", CON_RESULT(_con));
		PQclear(CON_RESULT(_con));
		CON_RESULT(_con) = 0;
	}

	return 0;
}

/*
** db_free_result	free the query and free the result memory
**
**	Arguments :
**		db_con_t *	as previously supplied by pg_init()
**		db_res_t *	the result of a query
**
**	Returns :
**		0 upon success
**		negative number upon failure
*/

int db_postgres_free_result(db_con_t* _con, db_res_t* _r)
{
	free_query(_con);
	if (_r) db_free_result(_r);
	_r = 0;

	return 0;
}

/*
 * Query table for specified rows
 * _con: structure representing database connection
 * _k: key names
 * _op: operators
 * _v: values of the keys that must match
 * _c: column names to return
 * _n: nmber of key=values pairs to compare
 * _nc: number of columns to return
 * _o: order by the specified column
 */
int db_postgres_query(const db_con_t* _h, const db_key_t* _k,
	const db_op_t* _op, const db_val_t* _v, const db_key_t* _c, const int _n,
	const int _nc, const db_key_t _o, db_res_t** _r)
{
	CON_RESET_CURR_PS(_h); /* no prepared statements support */
	return db_do_query(_h, _k, _op, _v, _c, _n, _nc, _o, _r,
		db_postgres_val2str, db_postgres_submit_query,
		db_postgres_store_result);
}


/*
 * Execute a raw SQL query
 */
int db_postgres_raw_query(const db_con_t* _h, const str* _s, db_res_t** _r)
{
	CON_RESET_CURR_PS(_h); /* no prepared statements support */
	return db_do_raw_query(_h, _s, _r, db_postgres_submit_query,
		db_postgres_store_result);
}

/*
 * Retrieve result set
 *
 * Input:
 *   db_con_t*  _con Structure representing the database connection
 *   db_res_t** _r pointer to a structure represending the result set
 *
 * Output:
 *   return 0: If the status of the last command produced a result set and,
 *   If the result set contains data or the convert_result() routine
 *   completed successfully.
 *
 *   return < 0: If the status of the last command was not handled or if the
 *   convert_result() returned an error.
 *
 * Notes:
 *   A new result structure is allocated on every call to this routine.
 *
 *   If this routine returns 0, it is the callers responsbility to free the
 *   result structure. If this routine returns < 0, then the result structure
 *   is freed before returning to the caller.
 *
 */

int db_postgres_store_result(const db_con_t* _con, db_res_t** _r)
{
	ExecStatusType pqresult;
	int rc = 0;

	*_r = db_new_result();
	if (*_r==NULL) {
		LM_ERR("failed to init new result\n");
		rc = -1;
		goto done;
	}

	pqresult = PQresultStatus(CON_RESULT(_con));

	LM_DBG("%p PQresultStatus(%s) PQgetResult(%p)\n", _con,
		PQresStatus(pqresult), CON_RESULT(_con));

	switch(pqresult) {
		case PGRES_COMMAND_OK:
		/* Successful completion of a command returning no data
		 * (such as INSERT or UPDATE). */
		rc = 0;
		break;

		case PGRES_TUPLES_OK:
			/* Successful completion of a command returning data
			 * (such as a SELECT or SHOW). */
			if (db_postgres_convert_result(_con, *_r) < 0) {
				LM_ERR("%p Error returned from convert_result()\n", _con);
				db_free_result(*_r);
				*_r = 0;
				rc = -4;
				break;
			}
			rc =  0;
			break;
		/* query failed */
		case PGRES_FATAL_ERROR:
			LM_ERR("%p - invalid query, execution aborted\n", _con);
			LM_ERR("%p: %s\n", _con, PQresStatus(pqresult));
			LM_ERR("%p: %s\n", _con, PQresultErrorMessage(CON_RESULT(_con)));
			db_free_result(*_r);
			*_r = 0;
			rc = -3;
			break;

		case PGRES_EMPTY_QUERY:
		/* notice or warning */
		case PGRES_NONFATAL_ERROR:
		/* status for COPY command, not used */
		case PGRES_COPY_OUT:
		case PGRES_COPY_IN:
		/* unexpected response */
		case PGRES_BAD_RESPONSE:
		default:
			LM_ERR("%p Probable invalid query\n", _con);
			LM_ERR("%p: %s\n", _con, PQresStatus(pqresult));
			LM_ERR("%p: %s\n", _con, PQresultErrorMessage(CON_RESULT(_con)));
			db_free_result(*_r);
			*_r = 0;
			rc = -4;
			break;
	}

done:
	free_query(_con);
	return (rc);
}

/*
 * Insert a row into specified table
 * _con: structure representing database connection
 * _k: key names
 * _v: values of the keys
 * _n: number of key=value pairs
 */
int db_postgres_insert(const db_con_t* _h, const db_key_t* _k,
		const db_val_t* _v, const int _n)
{
	db_res_t* _r = NULL;

	CON_RESET_CURR_PS(_h); /* no prepared statements support */

	/* This needs to be reset before each call to db_do_insert.
	   This is only used by inserts, but as a side effect delete and updates
	   will set it to 1 without resetting it. */
	submit_func_called = 0;

	int tmp = db_do_insert(_h, _k, _v, _n, db_postgres_val2str,
		db_postgres_submit_query);

	/* For bulk queries the insert may not be submitted until enough rows are queued */
	if (submit_func_called)
	{
		/* Query was submitted.
		   Result must be handled. */
		if (db_postgres_store_result(_h, &_r) != 0)
			LM_WARN("unexpected result returned\n");
	}

	if (_r)
		db_free_result(_r);

	if (CON_HAS_INSLIST(_h))
		CON_RESET_INSLIST(_h);

	return tmp;
}


/*
 * Delete a row from the specified table
 * _con: structure representing database connection
 * _k: key names
 * _o: operators
 * _v: values of the keys that must match
 * _n: number of key=value pairs
 */
int db_postgres_delete(const db_con_t* _h, const db_key_t* _k,
		const db_op_t* _o, const db_val_t* _v, const int _n)
{
	db_res_t* _r = NULL;

	CON_RESET_CURR_PS(_h); /* no prepared statements support */
	int tmp = db_do_delete(_h, _k, _o, _v, _n, db_postgres_val2str,
		db_postgres_submit_query);

	if (db_postgres_store_result(_h, &_r) != 0)
		LM_WARN("unexpected result returned\n");

	if (_r)
		db_free_result(_r);

	return tmp;
}


/*
 * Update some rows in the specified table
 * _con: structure representing database connection
 * _k: key names
 * _o: operators
 * _v: values of the keys that must match
 * _uk: updated columns
 * _uv: updated values of the columns
 * _n: number of key=value pairs
 * _un: number of columns to update
 */
int db_postgres_update(const db_con_t* _h, const db_key_t* _k,
		const db_op_t* _o, const db_val_t* _v, const db_key_t* _uk,
		const db_val_t* _uv, const int _n, const int _un)
{
	db_res_t* _r = NULL;

	CON_RESET_CURR_PS(_h); /* no prepared statements support */
	int tmp = db_do_update(_h, _k, _o, _v, _uk, _uv, _n, _un,
		db_postgres_val2str, db_postgres_submit_query);

	if (db_postgres_store_result(_h, &_r) != 0)
		LM_WARN("unexpected result returned\n");

	if (_r)
		db_free_result(_r);

	return tmp;
}


/*
 * Store name of table that will be used by
 * subsequent database functions
 */
int db_postgres_use_table(db_con_t* _con, const str* _t)
{
	return db_use_table(_con, _t);
}

static inline int db_postgres_get_con_fd(void *con)
{
	return PQsocket(((struct pg_con *)con)->con);
}

/**
 * Begins execution of a raw SQL query. Returns immediately.
 *
 * \param _h handle for the database
 * \param _s raw query string
 * \param _priv internal parameter; holds the conn that the query is bound to
 * \return
 *		success: Unix FD for polling
 *		failure: negative error code
 */
int db_postgres_async_raw_query(db_con_t *_h, const str *_s, void **_priv)
{
	int *fd_ref;
	int code;
	struct timeval start;
	struct my_con *con;

	if (!_h || !_s || !_s->s) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	con = (struct my_con *)db_init_async(_h, db_postgres_get_con_fd,
	                           &fd_ref, (void *)db_postgres_new_async_connection);
	*_priv = con;
	if (!con)
		LM_INFO("Failed to open new connection (current: 1 + %d). Running "
				"in sync mode!\n", ((struct pool_con *)_h->tail)->no_transfers);

	/* no prepared statements support */
	CON_RESET_CURR_PS(_h);
	start_expire_timer(start, db_postgres_exec_query_threshold);

	/* async mode */
	if (con) {
		code = db_postgres_submit_async_query(_h, _s);
	/* sync mode */
	} else {
		code = db_postgres_submit_query(_h, _s);
	}
	_stop_expire_timer(start, db_postgres_exec_query_threshold,
		"pgsql async query", _s->s, _s->len, 0,
		sql_slow_queries, sql_total_queries);

	if (code < 0) {
		LM_ERR("failed to send postgres query %.*s",_s->len,_s->s);
		goto out;
	} else {
		/* success */
		if (!con)
			return -1;

		*fd_ref = db_postgres_get_con_fd(con);
		db_switch_to_sync(_h);
		return *fd_ref;
	}

out:
	if (!con)
		return -1;

	db_switch_to_sync(_h);
	db_store_async_con(_h, (struct pool_con *)con);

	return -2;
}

int db_postgres_async_resume(db_con_t *_h, int fd, db_res_t **_r, void *_priv)
{
	struct pool_con *con = (struct pool_con *)_priv;
	PGresult *res = NULL;

#ifdef EXTRA_DEBUG
	if (!db_match_async_con(fd, _h)) {
		LM_BUG("no conn match for fd %d", fd);
		abort();
	}
#endif


	db_switch_to_async(_h, con);

	if( PQconsumeInput(CON_CONNECTION(_h)) == 0) {
		LM_ERR("Unable to consume input\n");
		db_switch_to_sync(_h);
		db_store_async_con(_h, con);
		return -1;
	}

	if(PQisBusy(CON_CONNECTION(_h))) {
		async_status = ASYNC_CONTINUE;

		db_switch_to_sync(_h);
		return 1;
	}

	while (1) {
		if ((res = PQgetResult(CON_CONNECTION(_h)))) {
			CON_RESULT(_h) = res;
		} else {
			break;
		}
	}

	if (_r) {
		if (db_postgres_store_result(_h, _r) != 0) {
			LM_ERR("failed to store result\n");
			db_switch_to_sync(_h);
			db_store_async_con(_h, con);
			return -2;
		}
	}

	db_switch_to_sync(_h);
	db_store_async_con(_h, con);

	return 0;
}

int db_postgres_async_free_result(db_con_t *_h, db_res_t *_r, void *_priv)
{
	struct pg_con *con = (struct pg_con *)_priv;

	if (_r && db_free_result(_r) < 0) {
		LM_ERR("error while freeing result structure\n");
	}

	PQclear(con->res);
	con->res = NULL;
	return 0;
}
