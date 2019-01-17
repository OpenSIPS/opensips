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


static inline int db_postgres_conn_ok(const db_con_t* _con)
{
	switch(PQstatus(CON_CONNECTION(_con)))
	{
		case CONNECTION_OK:
			return 1;

		case CONNECTION_BAD:
			LM_DBG("connection reset (%s)\n", CON_SQLURL(_con));
			PQreset(CON_CONNECTION(_con));

			if (PQstatus(CON_CONNECTION(_con)) == CONNECTION_OK) {
				LM_DBG("connection reset success (%s)\n", CON_SQLURL(_con));
				return 1;
			}
			break;

		default:
			goto connection_err;
	}

	connection_err:
	LM_ERR("%p PQstatus(%s) invalid: (%s)\n", _con,
		   PQerrorMessage(CON_CONNECTION(_con)), CON_SQLURL(_con));
	return -1;
}


/**
 *  Helper function to pick a result from multiple statements in a single query.
 *  Picks one and frees the other.
 *
 *  Arguments :
 *	    PGresult *new:  the new result.
 *      PGresult *old:  the previous result.
 *
 *  Returns :
 *  	the result with tuples or the newer one.
 */
inline static PGresult* db_postgres_pick_result(PGresult *new, PGresult *old)
{
	ExecStatusType status_new = PQresultStatus(new);
	ExecStatusType status_old = PQresultStatus(old);

	if (!old) {
		LM_DBG("PQgetResult: %s\n", PQresStatus(status_new));
		return new;
	}

	/*
	 * we do not call PQsetSingleRowMode() the query always fetches all
	 * rows so we do not expect to get PGRES_SINGLE_TUPLE.
	 */
	if (status_new != PGRES_TUPLES_OK && status_old == PGRES_TUPLES_OK) {
		LM_DBG("PQgetResult: picking old [%s] over new [%s]\n", PQresStatus(status_old), PQresStatus(status_new));
		PQclear(new);
		return old;
	}

	LM_DBG("PQgetResult: picking new [%s] over old [%s]\n", PQresStatus(status_new), PQresStatus(status_old));
	PQclear(old);
	return new;
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
	PGresult *res = NULL;
	struct timeval start;
	int failed_query, successful_query = 0;

	if(! _con || !_s || !_s->s)
	{
		LM_ERR("invalid parameter value\n");
		return(-1);
	}

	submit_func_called = 1;

	for (i=0; i<max_db_queries && !successful_query; i++) {
		failed_query = 0;
		/* free any previous query that is laying about */
		free_query(_con);
		if ( db_postgres_conn_ok(_con) < 0 ) {
			continue;
		}

		start_expire_timer(start,db_postgres_exec_query_threshold);
		ret = PQsendQuery(CON_CONNECTION(_con), _s->s);
		stop_expire_timer(start,db_postgres_exec_query_threshold,"pgsql query",_s->s,_s->len,0);
		/* exec the query */
		if (ret) {
			LM_DBG("%p PQsendQuery(%.*s)\n", _con, _s->len, _s->s);

			while ((res = PQgetResult(CON_CONNECTION(_con)))) {
				/* If this query included multiple statements
				 * if one statement already completed, it could be unsafe to resend the query.
				 *
				 * In addition, if multiple queries were sent at once.
				 * Let's return to the user the last query with result rows.
				 * So if a query like BEGIN; UPDATE ...; DELETE RETURNING *; COMMIT;
				 * we get the results of the DELETE instead of COMMIT;
				 */
				if (PQresultStatus(res) != PGRES_FATAL_ERROR) {
					successful_query++;
				} else {
					failed_query++;
				}

				CON_RESULT(_con) = db_postgres_pick_result(res, CON_RESULT(_con));
			}
		}

		if(successful_query) {
			if (! failed_query)
				return 0;
			else
				goto err;
		}

		if ( PQstatus(CON_CONNECTION(_con)) == CONNECTION_OK ) {
			// server disconnect unexpectedly, retry.
			break;
		}

		LM_ERR("%p PQsendQuery Failed: %s Query: %.*s\n", _con,
			   PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
	}

err:
	LM_ERR("%p PQsendQuery Error: %s Query: %.*s\n", _con,
			PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
	free_query(_con);
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

	for (i=0;i<max_db_queries;i++) {
		if ( db_postgres_conn_ok(_con) < 0 ) {
			continue;
		}

		/* free any previous query that is laying about */
		free_query(_con);
		start_expire_timer(start,db_postgres_exec_query_threshold);
		ret = PQsendQuery(CON_CONNECTION(_con), _s->s);
		stop_expire_timer(start,db_postgres_exec_query_threshold,"pgsql query",_s->s,_s->len,0);
		/* exec the query */
		if (ret) {
			LM_DBG("%p PQsendQuery(%.*s)\n", _con, _s->len, _s->s);
			return 0;
		}

		LM_DBG("%p PQsendQuery failed: %s Query: %.*s\n", _con,
		PQerrorMessage(CON_CONNECTION(_con)), _s->len, _s->s);
		if( PQstatus(CON_CONNECTION(_con)) != CONNECTION_OK ) {
			LM_DBG("connection reset\n");
			PQreset(CON_CONNECTION(_con));
		} else {
			/* failure not due to connection loss - no point in retrying */
			free_query(_con);
			break;
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
	int rc = 0;
	ExecStatusType pqresult = PQresultStatus(CON_RESULT(_con));

	LM_DBG("%p PQresultStatus(%s) PQgetResult(%p)\n", _con,
		PQresStatus(pqresult), CON_RESULT(_con));

	if (_r == NULL) {
		// Not an error
		LM_DBG("result output param not provided\n");
		goto done;
	}

	*_r = db_new_result();
	if (*_r==NULL) {
		LM_ERR("failed to init new result\n");
		rc = -1;
		goto done;
	}

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
	int tmp = db_do_insert(_h, _k, _v, _n, db_postgres_val2str,
		db_postgres_submit_query);

	if (submit_func_called)
	{
		/* finish the async query,
		 * otherwise the next query will not complete */

		/* only call this if the DB API has effectively called
		 * our submit_query function
		 *
		 * in case of insert queueing,
		 * it may postpone calling the insert func until
		 * enough rows have piled up */
		if (db_postgres_store_result(_h, &_r) != 0)
			LM_WARN("unexpected result returned\n");

		submit_func_called = 0;
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
	struct pg_con *con;

	if (!_h || !_s || !_s->s) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	con = (struct pg_con *)db_init_async(_h, db_postgres_get_con_fd,
	                           &fd_ref, (void *)db_postgres_new_async_connection);
	*_priv = con;
	if (!con) {
		LM_INFO("Failed to open new connection (current: 1 + %d). Running "
				"in sync mode!\n", ((struct pool_con *) _h->tail)->no_transfers);
		return ASYNC_CON_UNAVAILABLE;
	}

	/* no prepared statements support */
	CON_RESET_CURR_PS(_h);

	code = db_postgres_submit_async_query(_h, _s);

	if (code < 0) {
		LM_ERR("failed to send postgres query %.*s",_s->len,_s->s);
		goto out;
	} else {
		/* success */
		*fd_ref = db_postgres_get_con_fd(con);
		db_switch_to_sync(_h);
		return *fd_ref;
	}

out:
	db_switch_to_sync(_h);
	db_store_async_con(_h, (struct pool_con *)con);

	return -2;
}

int db_postgres_async_resume(db_con_t *_h, int fd, db_res_t **_r, void *_priv)
{
	struct pool_con *con = (struct pool_con *)_priv;
	PGresult *res = NULL;
	int ret = 0;

#ifdef EXTRA_DEBUG
	if (!db_match_async_con(fd, _h)) {
		LM_BUG("no conn match for fd %d", fd);
		abort();
	}
#endif

	db_switch_to_async(_h, con);

	while (1) {
		if (! PQconsumeInput(CON_CONNECTION(_h))) {
			LM_ERR("Unable to consume input: (%s)\n", PQerrorMessage(CON_CONNECTION(_h)));
			ret = -1;
			goto out;
		}

		if (PQisBusy(CON_CONNECTION(_h))) {
			async_status = ASYNC_CONTINUE;
			db_switch_to_sync(_h);
			return 1;
		}

		res = PQgetResult(CON_CONNECTION(_h));

		if (!res) {
			break;
		}

		/* If this query included multiple statements, return error if any of them failed.
		 * In addition, if multiple queries were sent at once.
		 */
		if (PQresultStatus(res) == PGRES_FATAL_ERROR) {
			ret = -2;
		}

		CON_RESULT(_h) = db_postgres_pick_result(res, CON_RESULT(_h));
	}

	/* from here on the result is freed by
	 * db_postgres_store_result` or `resume_async_dbquery`*/
	if (db_postgres_store_result(_h, _r) != 0) {
		LM_ERR("failed to store result\n");
		ret = -3;
	}

out:
	db_switch_to_sync(_h);
	db_store_async_con(_h, con);
	return ret;
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
