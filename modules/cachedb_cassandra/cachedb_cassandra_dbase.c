/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 */

#include <string.h> 

#include <cassandra.h>
#include "cachedb_cassandra.h"
#include "cachedb_cassandra_dbase.h"

CassConsistency rd_consistency = CASS_CONSISTENCY_UNKNOWN;
CassConsistency wr_consistency = CASS_CONSISTENCY_UNKNOWN;

static str cql_query_buf = {0,0};

#define CASS_PRINT_FUTURE_ERR(_future)  \
	do {  \
		const char *cass_err_msg;  \
	    size_t cass_err_msg_len;  \
	    cass_future_error_message((_future), &cass_err_msg, &cass_err_msg_len);  \
	    LM_ERR("driver error: %.*s\n", (int)cass_err_msg_len, cass_err_msg);  \
	} while(0)


int cassandra_open(cassandra_con *cass_con)
{
	CassFuture *conn_future = NULL;

	conn_future = cass_session_connect(cass_con->session, cass_con->cluster);
	if (!conn_future) {
		LM_ERR("Failed to get Cassandra Future object\n");
		return -1;
	}

	if (cass_future_wait_timed(conn_future, 1000*cassandra_conn_timeout) == 0) {
		LM_ERR("Connecting to Cassandra took too long\n");
		goto error;
	}
	if (cass_future_error_code(conn_future) != CASS_OK) {
		CASS_PRINT_FUTURE_ERR(conn_future);
		goto error;
	}

	cass_future_free(conn_future);

	return 0;

error:
	cass_future_free(conn_future);
	return -1;
}

int cassandra_close(cassandra_con *cass_con)
{
	CassFuture *close_future = NULL;

	close_future = cass_session_close(cass_con->session);
	if (!close_future) {
		LM_ERR("Failed to get Cassandra Future object\n");
		return -1;	
	}

	if (cass_future_wait_timed(close_future, 1000*cassandra_conn_timeout) == 0) {
		LM_ERR("Closing connection to Cassandra took too long\n");
		goto error;
	}
	if (cass_future_error_code(close_future) != CASS_OK) {
		CASS_PRINT_FUTURE_ERR(close_future);
		goto error;
	}

	cass_future_free(close_future);

	return 0;

error:
	cass_future_free(close_future);
	return -1;
}

int cassandra_reopen(cassandra_con *cass_con)
{
	if (cassandra_close(cass_con) < 0) {
		LM_ERR("Failed to close connection to Cassandra\n");
		return -1;
	}

	if (cassandra_open(cass_con) < 0) {
		LM_ERR("Failed to open connection to Cassandra\n");
		return -1;
	}

	return 0;
}

int cassandra_new_connection(cassandra_con *con, char *host, int port)
{
	con->cluster = cass_cluster_new();
	if (!con->cluster) {
		LM_ERR("Failed to create Cassandra Cluster object\n");
		return -1;
	}

	if (cass_cluster_set_contact_points(con->cluster, host)
		!= CASS_OK) {
		LM_ERR("Failed to set the Cassandra contact points\n");
		goto error;
	}
	if (port && cass_cluster_set_port(con->cluster, port) != CASS_OK) {
		LM_ERR("Failed to set the port for the Cassandra contact points\n");
		goto error;
	}

	con->session = cass_session_new();
	if (!con->session) {
		LM_ERR("Failed to create Cassandra Session object\n");
		goto error;
	}

	if (cassandra_open(con) < 0) {
		LM_ERR("Failed to open connection to Cassandra\n");
		cass_session_free(con->session);
		goto error;
	}

	return 0;

error:
	cass_cluster_free(con->cluster);
	return -1;
}

void *cassandra_init_connection(struct cachedb_id *id)
{
	cassandra_con *con;
	str keyspace = {0,0};
	str table = {0,0};
	str cnt_table = {0,0};
	int db_len;
	char *p;

	if (id == NULL) {
		LM_ERR("null cachedb_id\n");
		return NULL;
	}

	if (id->database == NULL) {
		LM_ERR("no database supplied for cassandra\n");
		return NULL;
	}

	db_len = strlen(id->database);

	p = (char *)memchr(id->database, '.', db_len);
	if (!p) {
		LM_ERR("Invalid database. Should be 'Keyspace.Table[.CountersTable]'\n");
		return NULL;
	}

	keyspace.s = id->database;
	keyspace.len = p - keyspace.s;
	if (keyspace.len == 0) {
		LM_ERR("Empty Keyspace\n");
		return NULL;
	}

	table.s = p + 1;

	p = (char *)memchr(table.s, '.', id->database + db_len - p - 1);
	if (!p)
		table.len = db_len - keyspace.len - 1;
	else
		table.len = p - table.s;

	if (table.len == 0) {
		LM_ERR("Empty Table\n");
		return NULL;
	}

	if (p) {
		cnt_table.s = p + 1;
		cnt_table.len = db_len - keyspace.len - 1 - table.len - 1;
	}

	LM_INFO("Keyspace = [%.*s] Table = [%.*s] CountersTable = [%.*s]\n",
		keyspace.len, keyspace.s, table.len, table.s,
		cnt_table.len, cnt_table.s);

	con = (cassandra_con *)pkg_malloc(sizeof(cassandra_con));
	if (con == NULL) {
		LM_ERR("no more pkg \n");
		return 0;
	}

	memset(con, 0, sizeof(cassandra_con));
	con->id = id;
	con->ref = 1;

	if (cassandra_new_connection(con, id->host, id->port) < 0) {
		LM_ERR("failed to create new connection to Cassandra\n");
		pkg_free(con);
		return NULL;
	}

	con->keyspace = keyspace;
	con->table = table;
	con->cnt_table = cnt_table;

	return con;
}

void cassandra_free_connection(cachedb_pool_con *con)
{
	cassandra_con *cass_con = (cassandra_con*)con;

	if (!con)
		return;

	if (cassandra_close(cass_con) < 0) {
		LM_ERR("Failed to close connection to Cassandra\n");
		return;
	}

	if (cass_con->cluster)
		cass_cluster_free(cass_con->cluster);
	if (cass_con->session)
		cass_session_free(cass_con->session);

	pkg_free(cass_con);
}

cachedb_con *cassandra_init(str *url)
{
	return cachedb_do_init(url, cassandra_init_connection);
}

void cassandra_destroy(cachedb_con *con) {
	cachedb_do_close(con, cassandra_free_connection);
}

const CassResult *execute_query(CassSession* session, CassStatement *statement,
					char *op_name, int *reopen_conn)
{	
	CassFuture *query_future = NULL;
	const CassResult *result;
	int rc;
	struct timeval start;

	query_future = cass_session_execute(session, statement);
	if (!query_future) {
		LM_ERR("Failed to get Cassandra Future object\n");
		return NULL;
	}

	start_expire_timer(start, cassandra_exec_threshold);
	rc = cass_future_wait_timed(query_future, 1000*cassandra_query_timeout);
	stop_expire_timer(start, cassandra_exec_threshold, op_name,
	                  NULL, 0, 0);
	if (rc == 0) {
		LM_ERR("Cassandra query took too long\n");
		goto error;
	}

	if (cass_future_error_code(query_future) != CASS_OK) {
		CASS_PRINT_FUTURE_ERR(query_future);
		*reopen_conn = 1;
		goto error;
	}

	result = cass_future_get_result(query_future);
	if (!result) {
		LM_ERR("Failed to get Cassandra Result object\n");
		goto error;
	}

	cass_future_free(query_future);

	return result;

error:
	cass_future_free(query_future);
	return NULL;
}

#define cassandra_do_query(_op_name) \
do {  \
	int retries = cassandra_query_retries;  \
	int reopen_conn = 0;  \
	do {  \
		if (reopen_conn && cassandra_reopen(cass_con) < 0)  \
			goto error;  \
		reopen_conn = 0;  \
		LM_DBG("executing query: %.*s\n", cql_buf_len, cql_query_buf.s);  \
		result = execute_query(cass_con->session, statement, (_op_name),  \
			&reopen_conn);  \
		if (result)  \
			goto process_result;  \
	} while (retries--);  \
	goto error;  \
} while(0)

int cassandra_set(cachedb_con *con, str *attr, str *val, int expires)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	int cql_buf_len = 0;

	if (!attr || !val || !con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cass_con = (cassandra_con *)con->data;

	/* estimate the length of the query string */
	cql_buf_len = 13 + cass_con->keyspace.len + 3 + cass_con->table.len + 4 +
		CASS_OSS_KEY_COL_LEN + 4 + CASS_OSS_VAL_COL_LEN + 27 + 11;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	/* build insert query */
	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"INSERT INTO \"%.*s\".\"%.*s\" (\"%s\", \"%s\") VALUES (?, ?) USING "
		"TTL %d", cass_con->keyspace.len, cass_con->keyspace.s, cass_con->table.len,
		cass_con->table.s, CASS_OSS_KEY_COL_S, CASS_OSS_VAL_COL_S, expires);

	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'set'\n");
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, 2);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	if (cass_statement_set_consistency(statement, wr_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	if (cass_statement_bind_string_n(statement, 0, attr->s, attr->len) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}
	if (cass_statement_bind_string_n(statement, 1, val->s, val->len) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'set'");

process_result:
	cass_statement_free(statement);
	cass_result_free(result);
	return 0;

error:
	LM_ERR("Cassandra 'set' failed\n");
	cass_statement_free(statement);
	return -1;
}

int cassandra_get(cachedb_con *con, str *attr, str *val)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	const CassRow *row;
	const CassValue *cass_val;
	int cql_buf_len = 0;
	int rc;
	char *col_val;
	size_t len;

	if (!attr || !val || !con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cass_con = (cassandra_con *)con->data;

	/* estimate the length of the query string */
	cql_buf_len = 8 + CASS_OSS_VAL_COL_LEN + 8 + cass_con->keyspace.len + 3 +
		cass_con->table.len + 9 + CASS_OSS_KEY_COL_LEN + 5;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	/* build select query */
	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"SELECT \"%s\" FROM \"%.*s\".\"%.*s\" WHERE \"%s\" = ?", CASS_OSS_VAL_COL_S,
		cass_con->keyspace.len, cass_con->keyspace.s, cass_con->table.len,
		cass_con->table.s, CASS_OSS_KEY_COL_S);

	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'get'\n");
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, 1);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	if (cass_statement_set_consistency(statement, rd_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	if (cass_statement_bind_string_n(statement, 0, attr->s, attr->len) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'get'");

process_result:
	row = cass_result_first_row(result);
	if (!row) {
		LM_DBG("Key: %.*s not found\n", attr->len, attr->s);
		rc = -2;
		val->s = NULL;
		val->len = 0;
	} else {
		cass_val = cass_row_get_column(row, 0);
		if (!cass_val) {
			LM_ERR("Failed to get Cassandra Value object\n");
			cass_result_free(result);
			goto error;
		}

		if (cass_value_is_null(cass_val)) {
			LM_DBG("Null value for key: %.*s\n", attr->len, attr->s);
			val->s = NULL;
			val->len = 0;
		} else {
			if (cass_value_get_string(cass_val, (const char **)&col_val, &len)
				!= CASS_OK) {
				LM_ERR("Failed to get string value from Cassandra Value object\n");
				cass_result_free(result);
				goto error;
			}

			val->s = pkg_malloc(len);
			if (!val->s) {
				LM_ERR("no more pkg memory\n");
				cass_result_free(result);
				goto error;
			}

			val->len = len;
			memcpy(val->s, col_val, len);
		}

		rc = 0;
	}

	cass_statement_free(statement);
	cass_result_free(result);
	return rc;

error:
	LM_ERR("Cassandra 'get' failed\n");
	cass_statement_free(statement);
	return -1;
}

int _cassandra_remove(cachedb_con *con, str *attr, const str *key)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	int cql_buf_len = 0;

	if (!attr || !con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cass_con = (cassandra_con *)con->data;

	/* estimate the length of the query string */
	cql_buf_len = 13 + cass_con->keyspace.len + 3 + cass_con->table.len + 9 +
		key->len + 5;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	/* build delete query */
	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"DELETE FROM \"%.*s\".\"%.*s\" WHERE \"%s\" = ?",
		cass_con->keyspace.len, cass_con->keyspace.s,
		cass_con->table.len, cass_con->table.s, key->s);

	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'remove'\n");
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, 1);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	if (cass_statement_set_consistency(statement, wr_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	if (cass_statement_bind_string_n(statement, 0, attr->s, attr->len) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'remove'");

process_result:
	cass_statement_free(statement);
	cass_result_free(result);
	return 0;

error:
	LM_ERR("Cassandra 'remove' failed\n");
	cass_statement_free(statement);
	return -1;
}

int cassandra_remove(cachedb_con *con, str *attr)
{
	return _cassandra_remove(con, attr, _str(CASS_OSS_KEY_COL_S));
}

static int basic_get_counter(cachedb_con *con, str *attr, int *val)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	const CassRow *row;
	const CassValue *cass_val;
	int cql_buf_len;
	int rc;
	cass_int64_t cass_cnt;

	if (!attr || !val || !con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cass_con = (cassandra_con *)con->data;

	if (!cass_con->cnt_table.s) {
		LM_ERR("No counters table defined\n");
		return -1;
	}

	/* estimate the length of the query string */
	cql_buf_len = 8 + CASS_OSS_VAL_COL_LEN + 8 + cass_con->keyspace.len + 3 +
		cass_con->cnt_table.len + 9 + CASS_OSS_KEY_COL_LEN + 5;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	/* build select query */
	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"SELECT \"%s\" FROM \"%.*s\".\"%.*s\" WHERE \"%s\" = ?",
		CASS_OSS_VAL_COL_S, cass_con->keyspace.len, cass_con->keyspace.s,
		cass_con->cnt_table.len, cass_con->cnt_table.s, CASS_OSS_KEY_COL_S);

	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'get_counter'\n");
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, 1);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	if (cass_statement_set_consistency(statement, rd_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	if (cass_statement_bind_string_n(statement, 0, attr->s, attr->len) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'get_counter'");

process_result:
	row = cass_result_first_row(result);
	if (!row) {
		LM_DBG("Key: %.*s not found\n", attr->len, attr->s);
		rc = -2;
		*val = 0;
	} else {
		cass_val = cass_row_get_column(row, 0);
		if (!cass_val) {
			LM_ERR("Failed to get Cassandra Value object\n");
			cass_result_free(result);
			goto error;
		}

		if (cass_value_get_int64(cass_val, &cass_cnt) != CASS_OK) {
			LM_ERR("Failed to get integer value from Cassandra Value object\n");
			cass_result_free(result);
			goto error;
		}

		*val = (int)cass_cnt;

		rc = 0;
	}

	cass_statement_free(statement);
	cass_result_free(result);
	return rc;

error:
	LM_ERR("Cassandra 'get_counter' failed\n");
	cass_statement_free(statement);
	return -1;
}

int cassandra_get_counter(cachedb_con *con, str *attr, int *val)
{
	return basic_get_counter(con, attr, val);
}

static int basic_update_counter(cachedb_con *con, str *attr, int val, char op,
									char *op_name)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	int cql_buf_len;

	if (!attr || !val || !con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cass_con = (cassandra_con *)con->data;

	if (!cass_con->cnt_table.s) {
		LM_ERR("No counters table defined\n");
		return -1;
	}

	/* estimate the length of the query string */
	cql_buf_len = 8 + cass_con->keyspace.len + 3 + cass_con->cnt_table.len + 7 +
		CASS_OSS_VAL_COL_LEN + 5 + CASS_OSS_VAL_COL_LEN + 14 +
		CASS_OSS_KEY_COL_LEN + 5;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	/* build update query */
	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"UPDATE \"%.*s\".\"%.*s\" SET \"%s\" = \"%s\" %c ? WHERE \"%s\" = ?",
		cass_con->keyspace.len, cass_con->keyspace.s,
		cass_con->cnt_table.len, cass_con->cnt_table.s,
		CASS_OSS_VAL_COL_S, CASS_OSS_VAL_COL_S, op, CASS_OSS_KEY_COL_S);

	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for %s\n", op_name);
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, 2);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	if (cass_statement_set_consistency(statement, wr_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	if (cass_statement_bind_int64(statement, 0, (cass_int64_t)val) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}
	if (cass_statement_bind_string_n(statement, 1, attr->s, attr->len) != CASS_OK) {
		LM_ERR("Failed to bind value for Cassandra statement\n");
		goto error;
	}

	cassandra_do_query(op_name);

process_result:
	cass_statement_free(statement);
	cass_result_free(result);
	return 0;

error:
	LM_ERR("%s failed\n", op_name);
	cass_statement_free(statement);
	return -1;
}

int cassandra_add(cachedb_con *con, str *attr, int val, int expires, int *new_val)
{
	if (basic_update_counter(con, attr, val, '+', "Cassandra 'add'") < 0)
		return -1;
	else
		return basic_get_counter(con, attr, new_val);
}

int cassandra_sub(cachedb_con *con, str *attr, int val, int expires, int *new_val)
{
	if (basic_update_counter(con, attr, val, '-', "Cassandra 'sub'") < 0)
		return -1;
	else
		return basic_get_counter(con, attr, new_val);
}