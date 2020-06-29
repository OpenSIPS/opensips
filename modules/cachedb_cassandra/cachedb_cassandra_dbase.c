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
#include <inttypes.h>

#include <cassandra.h>
#include "cachedb_cassandra.h"
#include "cachedb_cassandra_dbase.h"
#include "../../lib/osips_malloc.h"

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
	const CassKeyspaceMeta *keyspace_meta;

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

	cass_con->schema_meta = cass_session_get_schema_meta(cass_con->session);
	if (!cass_con->schema_meta) {
		LM_ERR("Failed to get schema metadata\n");
		goto error;
	}

	keyspace_meta = cass_schema_meta_keyspace_by_name_n(cass_con->schema_meta,
		cass_con->keyspace.s, cass_con->keyspace.len);
	if (!keyspace_meta) {
		LM_ERR("Failed to get keyspace: %.*s metadata (might not exist)\n",
			cass_con->keyspace.len, cass_con->keyspace.s);
		cass_schema_meta_free(cass_con->schema_meta);
		goto error;
	}
	cass_con->table_meta = cass_keyspace_meta_table_by_name_n(keyspace_meta,
		cass_con->table.s, cass_con->table.len);
	if (!cass_con->table_meta) {
		LM_ERR("Failed to get table: %.*s metadata (might not exist)\n",
			cass_con->table.len, cass_con->table.s);
		cass_schema_meta_free(cass_con->schema_meta);
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

	cass_schema_meta_free(cass_con->schema_meta);

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

#if CASS_VERSION_MAJOR >= 2 && CASS_VERSION_MINOR >= 15
	/* since version 2.15, DSE support is available in the standard driver
	 * and the protocol version defaults to DSEV2; as such we force the
	 * protocol version to v4 */
	if (cass_cluster_set_protocol_version(con->cluster,
		CASS_PROTOCOL_VERSION_V4) != CASS_OK) {
		LM_ERR("Failed to set the protocol version\n");
		goto error;
	}
#endif

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

	con->keyspace = keyspace;
	con->table = table;
	con->cnt_table = cnt_table;

	if (cassandra_new_connection(con, id->host, id->port) < 0) {
		LM_ERR("failed to create new connection to Cassandra\n");
		pkg_free(con);
		return NULL;
	}

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
	_stop_expire_timer(start, cassandra_exec_threshold, op_name,
						NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
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

static int where_clause_from_filter(const cdb_filter_t *row_filter, str *buf,
									int *no_bind_params)
{
	char *p = buf->s;
	int cur;
	int clause_len = 0;
	str op;
	const cdb_filter_t *filter;
	int len;

	for (filter = row_filter; filter; filter = filter->next) {
		if (!filter->key.name.s )
			continue;

		(*no_bind_params)++;

		switch (filter->op) {
		case CDB_OP_EQ:
			init_str(&op, "=");
			break;
		case CDB_OP_LT:
			init_str(&op, "<");
			break;
		case CDB_OP_LTE:
			init_str(&op, "<=");
			break;
		case CDB_OP_GT:
			init_str(&op, ">");
			break;
		case CDB_OP_GTE:
			init_str(&op, ">=");
			break;
		default:
			LM_BUG("unsupported operator: %d\n", filter->op);
			return -1;
		}

		len = 1 + filter->key.name.len + 2 + op.len + 7;
		clause_len += len;

		cur = p - buf->s;
		if (pkg_str_extend(buf, clause_len+1) < 0) {
			LM_ERR("oom\n");
			return -1;
		}
		p = buf->s + cur;

		len = snprintf(p, len+1, "\"%.*s\" %.*s ? AND ", filter->key.name.len,
				filter->key.name.s, op.len, op.s);
		if (len < 0)
			return -1;

		p += len;
	}

	*(p-5) = 0;

	return clause_len;
}

static int bind_where_clause_params(CassStatement *statement,
								const cdb_filter_t *row_filter, int start_idx)
{
	const cdb_filter_t *filter;
	int idx = start_idx;

	for (filter = row_filter; filter; filter = filter->next) {
		if (!filter->key.name.s )
			continue;

		if (filter->val.is_str) {
			if (cass_statement_bind_string_n(statement, idx, filter->val.s.s,
				filter->val.s.len) != CASS_OK) {
				LM_ERR("Failed to bind string value to Cassandra statement\n");
				return -1;
			}
		} else {
			if (cass_statement_bind_int32(statement, idx, filter->val.i)
				!= CASS_OK) {
				LM_ERR("Failed to bind integer value to Cassandra statement\n");
				return -1;
			}
		}

		idx++;
	}

	return 0;
}

static int cdb_val_to_string(cdb_val_t *cdb_val, str *valbuf, int *val_len)
{
	char *i = NULL;
	static char ibuf[INT2STR_MAX_LEN+1];

	switch (cdb_val->type) {
	case CDB_NULL:
		*val_len = 0;
		break;
	case CDB_INT32:
		i = sint2str((long)cdb_val->val.i32, val_len);
		break;
	case CDB_INT64:
		*val_len = snprintf(ibuf, INT2STR_MAX_LEN, "%lld",
					(long long)cdb_val->val.i64);
		i = ibuf;
		if (*val_len < 0) {
			LM_ERR("Failed to covert int64 to string\n");
			return -1;
		}
		break;
	case CDB_STR:
		*val_len = cdb_val->val.st.len;
		break;
	default:
		LM_ERR("Bad cdb value type\n");
		return -1;
	}

	if (pkg_str_extend(valbuf, *val_len+1) < 0)
		return -1;

	switch (cdb_val->type) {
	case CDB_NULL:
		valbuf->s[0] = MAP_VAL_TYPE_NULL;
		(*val_len)++;
		break;
	case CDB_INT32:
		valbuf->s[0] = MAP_VAL_TYPE_INT32;
		memcpy(valbuf->s+1, i, *val_len);
		(*val_len)++;
		break;
	case CDB_INT64:
		valbuf->s[0] = MAP_VAL_TYPE_INT64;
		memcpy(valbuf->s+1, i, *val_len);
		(*val_len)++;
		break;
	case CDB_STR:
		valbuf->s[0] = MAP_VAL_TYPE_STR;
		memcpy(valbuf->s+1, cdb_val->val.st.s, *val_len);
		(*val_len)++;
		break;
	default:
		LM_ERR("Bad cdb value type\n");
		return -1;
	}

	return 0;
}

static int dict_to_cass_collection(cdb_dict_t *dict, CassCollection *collection)
{
	cdb_pair_t *pair;
	struct list_head *_;
	CassCollection *sub_collection;
	static str valbuf = {0,0};
	int val_len;

	list_for_each (_, dict) {
		pair = list_entry(_, cdb_pair_t, list);
		if (!pair->key.name.s)
			continue;

		if (pair->subkey.s) {
			LM_ERR("Updating a key for a nested map is not supported\n");
			return -1;
		}
		if (pair->unset) {
			LM_ERR("Unsetting a key when updating an entire map is not supported\n");
			return -1;
		}

		if (cass_collection_append_string_n(collection, pair->key.name.s,
			pair->key.name.len) != CASS_OK) {
			LM_ERR("Failed to append key to collection\n");
			return -1;
		}

		switch (pair->val.type) {
		case CDB_NULL:
		case CDB_INT32:
		case CDB_INT64:
		case CDB_STR:
			/* also store other types (null, integers) as strings in order to
			 * support heterogeneous types as map values */
			if (cdb_val_to_string(&pair->val, &valbuf, &val_len) < 0) {
				LM_ERR("Failed to encode map value as string\n");
				return -1;
			}

			if (cass_collection_append_string_n(collection, valbuf.s,
				val_len) != CASS_OK) {
				LM_ERR("Failed to append value to collection\n");
				return -1;
			}

			break;
		case CDB_DICT:
			sub_collection = cass_collection_new(CASS_COLLECTION_TYPE_MAP,
												CASS_COLL_APROX_COUNT);
			if (!sub_collection) {
				LM_ERR("Failed to create Cassandra Collection object\n");
				return -1;
			}

			if (dict_to_cass_collection(&pair->val.val.dict, sub_collection) < 0) {
				LM_ERR("Failed to build collection value\n");
				cass_collection_free(sub_collection);
				return -1;
			}

			if (cass_collection_append_collection(collection, sub_collection)
				!= CASS_OK) {
				LM_ERR("Failed to append collection value to collection\n");
				cass_collection_free(sub_collection);
				return -1;
			}

			cass_collection_free(sub_collection);

			break;
		default:
			LM_ERR("unsupported type %d for key %.*s\n", pair->val.type,
			       pair->key.name.len, pair->key.name.s);
			return -1;
		}
	}

	return 0;
}

static int bind_set_clause_params(CassStatement *statement,
								const cdb_dict_t *pairs, int *end_idx)
{
	struct list_head *_;
	cdb_pair_t *pair;
	CassCollection *collection;

	list_for_each (_, pairs) {
		pair = list_entry(_, cdb_pair_t, list);
		if (!pair->key.name.s)
			continue;

		if (pair->unset) {
			if (cass_statement_bind_null(statement, *end_idx) != CASS_OK) {
				LM_ERR("Failed to bind null value to Cassandra statement\n");
				return -1;
			}
			(*end_idx)++;
			continue;
		}

		switch (pair->val.type) {
		case CDB_NULL:
			if (cass_statement_bind_null(statement, *end_idx) != CASS_OK) {
				LM_ERR("Failed to bind null value to Cassandra statement\n");
				return -1;
			}
			(*end_idx)++;
			break;
		case CDB_INT32:
			if (cass_statement_bind_int32(statement, *end_idx, pair->val.val.i32)
				!= CASS_OK) {
				LM_ERR("Failed to bind integer value to Cassandra statement\n");
				return -1;
			}
			(*end_idx)++;
			break;
		case CDB_INT64:
			if (cass_statement_bind_int64(statement, *end_idx, pair->val.val.i64)
				!= CASS_OK) {
				LM_ERR("Failed to bind integer value to Cassandra statement\n");
				return -1;
			}
			(*end_idx)++;
			break;
		case CDB_STR:
			if (cass_statement_bind_string_n(statement, *end_idx,
				pair->val.val.st.s, pair->val.val.st.len) != CASS_OK) {
				LM_ERR("Failed to bind string value to Cassandra statement\n");
				return -1;
			}
			(*end_idx)++;
			break;
		case CDB_DICT:
			collection = cass_collection_new(CASS_COLLECTION_TYPE_MAP,
											CASS_COLL_APROX_COUNT);
			if (!collection) {
				LM_ERR("Failed to create Cassandra Collection object\n");
				return -1;
			}

			if (dict_to_cass_collection(&pair->val.val.dict, collection) < 0) {
				LM_ERR("Failed to build collection value\n");
				cass_collection_free(collection);
				return -1;
			}

			if (cass_statement_bind_collection(statement, *end_idx, collection)
				!= CASS_OK) {
				LM_ERR("Failed to bind collection value to Cassandra statement\n");
				cass_collection_free(collection);
				return -1;
			}
			cass_collection_free(collection);

			(*end_idx)++;
			break;
		default:
			LM_ERR("unsupported type %d for key %.*s\n", pair->val.type,
			       pair->key.name.len, pair->key.name.s);
			return -1;
		}
	}

	return 0;
}

int cassandra_col_update(cachedb_con *con, const cdb_filter_t *row_filter,
						const cdb_dict_t *pairs)
{
	cassandra_con *cass_con;
	CassStatement *statement = NULL;
	const CassResult *result;
	cdb_pair_t *pair;
	struct list_head *_;
	static str buf1 = {0,0}, buf2 = {0,0};
	char *p;
	int cur;
	int len;
	int cql_buf_len = 0, buf1_len = 0, buf2_len = 0;
	int bind_idx = 0, no_bind_params = 0;
	int max_ttl = 0;

	if (!row_filter) {
		LM_ERR("Updating all the rows at once is not supported\n");
		return -1;
	}

	if (!con) {
		LM_ERR("null parameter\n");
		return -1;
	}
	cass_con = (cassandra_con *)con->data;

	/* build update query's SET clause */
	p = buf1.s;

	list_for_each (_, pairs) {
		pair = list_entry(_, cdb_pair_t, list);
		if (!pair->key.name.s)
			continue;

		no_bind_params++;

		if (pair->ttl > max_ttl)
			max_ttl = pair->ttl;

		if (pair->subkey.s) {
			len = 1 + pair->key.name.len + 3 + pair->subkey.len + 8;
			buf1_len += len;

			cur = p - buf1.s;
			if (pkg_str_extend(&buf1, buf1_len+1) < 0) {
				LM_ERR("oom\n");
				return -1;
			}
			p = buf1.s + cur;

			len = snprintf(p, len+1, "\"%.*s\"['%.*s'] = ?, ", pair->key.name.len,
					pair->key.name.s, pair->subkey.len, pair->subkey.s);
		} else {
			len = 1 + pair->key.name.len + 7;
			buf1_len += len;

			cur = p - buf1.s;
			if (pkg_str_extend(&buf1, buf1_len+1) < 0) {
				LM_ERR("oom\n");
				return -1;
			}
			p = buf1.s + cur;

			len = snprintf(p, len+1, "\"%.*s\" = ?, ",
				pair->key.name.len, pair->key.name.s);
		}

		if (len < 0) {
			LM_ERR("Failed to build SET clause for query\n");
			goto error;
		}
		p += len;
	}

	if (no_bind_params == 0) {
		LM_DBG("No update to be done\n");
		return 0;
	}
	*(p-2) = 0;

	/* build update query's WHERE clause */
	if ((buf2_len = where_clause_from_filter(row_filter, &buf2,
		&no_bind_params)) < 0) {
		LM_ERR("Failed to build WHERE caluse for query\n");
		goto error;
	}

	/* estimate the length of the query string */
	cql_buf_len = 8 + cass_con->keyspace.len + 3 + cass_con->table.len + 12 +
		11 + 5 + buf1_len + 7 + buf2_len;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"UPDATE \"%.*s\".\"%.*s\" USING TTL %d SET %s WHERE %s",
		cass_con->keyspace.len, cass_con->keyspace.s,
		cass_con->table.len, cass_con->table.s, max_ttl, buf1.s, buf2.s);
	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'update'\n");
		goto error;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, no_bind_params);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		goto error;
	}

	if (cass_statement_set_consistency(statement, wr_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	/* bind values to statement */
	if (bind_set_clause_params(statement, pairs, &bind_idx) < 0) {
		LM_ERR("Failed to bind 'SET' clause parameters\n");
		goto error;
	}
	if (bind_where_clause_params(statement, row_filter, bind_idx) < 0) {
		LM_ERR("Failed to bind 'WHERE' clause parameters\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'update'");

process_result:
	cass_statement_free(statement);
	cass_result_free(result);
	return 0;

error:
	LM_ERR("Cassandra 'update' failed\n");
	if (statement)
		cass_statement_free(statement);
	return -1;
}

static int get_cdb_val_from_string(str *strval, cdb_val_t *cdb_val)
{
	switch (strval->s[0]) {
	case MAP_VAL_TYPE_NULL:
		cdb_val->type = CDB_NULL;
		break;
	case MAP_VAL_TYPE_INT32:
		cdb_val->type = CDB_INT32;
		strval->s = strval->s + 1;
		strval->len--;
		if (str2sint(strval, (int *)&cdb_val->val.i32) < 0) {
			LM_ERR("Failed to convert string to integer\n");
			return -1;
		}
		break;
	case MAP_VAL_TYPE_INT64:
		cdb_val->type = CDB_INT64;
		strval->s = strval->s + 1;
		if (sscanf(strval->s, "%lld", (long long *)&cdb_val->val.i64) < 0) {
			LM_ERR("Failed to convert string to integer\n");
			return -1;
		}
		break;
	case MAP_VAL_TYPE_STR:
		cdb_val->type = CDB_STR;
		strval->s = strval->s + 1;
		strval->len--;
		if (pkg_str_dup(&cdb_val->val.st, strval) < 0)
			return -1;
		break;
	default:
		/* maybe we can treat this as a regular string, in case the
		 * value was not stored by a col api update() */
		LM_ERR("Unknown type encoding\n");
		return -1;
	}

	return 0;
}

static int append_cass_val_to_dict(const CassValue *cass_val, cdb_dict_t *cdb_dict,
									cdb_key_t *cdb_key, int is_map_val)
{
	cdb_pair_t *pair;
	str strval;
	CassIterator *map_iter = NULL;
	cdb_key_t map_cdb_key;
	const CassValue *map_cass_val;

	pair = cdb_mk_pair(cdb_key, NULL);
	if (!pair) {
		LM_ERR("oom\n");
		return -1;
	}

	if (cass_value_is_null(cass_val)) {
		pair->val.type = CDB_NULL;
		cdb_dict_add(pair, cdb_dict);
		return 0;
	}

	switch (cass_value_type(cass_val)) {
	case CASS_VALUE_TYPE_ASCII:
	case CASS_VALUE_TYPE_TEXT:
	case CASS_VALUE_TYPE_VARCHAR:
		if (cass_value_get_string(cass_val, (const char **)&strval.s,
			(size_t *)&strval.len) != CASS_OK) {
			LM_ERR("Failed to get string from Cassandra Value object\n");
			goto error;
		}

		if (is_map_val) {
			/* for map values, we have encoded other types (null, integers)
			 * as string so we should decode them accordingly */
			if (get_cdb_val_from_string(&strval, &pair->val) < 0) {
				LM_ERR("Failed to decode map value from string\n");
				goto error;
			}
		} else {
			pair->val.type = CDB_STR;
			if (pkg_str_dup(&pair->val.val.st, &strval) < 0)
				goto error;
		}
		break;
	case CASS_VALUE_TYPE_TINY_INT:
	case CASS_VALUE_TYPE_SMALL_INT:
	case CASS_VALUE_TYPE_INT:
		pair->val.type = CDB_INT32;
		if (cass_value_get_int32(cass_val, &pair->val.val.i32) != CASS_OK) {
			LM_ERR("Failed to get integer from Cassandra Value object\n");
			goto error;
		}
		break;
	case CASS_VALUE_TYPE_BIGINT:
		pair->val.type = CDB_INT64;
		if (cass_value_get_int64(cass_val, &pair->val.val.i64) != CASS_OK) {
			LM_ERR("Failed to get integer from Cassandra Value object\n");
			goto error;
		}
		break;
	case CASS_VALUE_TYPE_MAP:
		pair->val.type = CDB_DICT;
		INIT_LIST_HEAD(&pair->val.val.dict);

		map_iter = cass_iterator_from_map(cass_val);
		while (cass_iterator_next(map_iter)) {
			map_cass_val = cass_iterator_get_map_key(map_iter);
			if (!map_cass_val) {
				LM_ERR("Failed to get Cassandra Value object\n");
				goto error;
			}
			switch (cass_value_type(map_cass_val)) {
				case CASS_VALUE_TYPE_ASCII:
				case CASS_VALUE_TYPE_TEXT:
				case CASS_VALUE_TYPE_VARCHAR:
					break;
				default:
					LM_ERR("Only string values are supported as map keys\n");
					goto error;
			}
			if (cass_value_get_string(map_cass_val,
				(const char **)&map_cdb_key.name.s,
				(size_t *)&map_cdb_key.name.len) != CASS_OK) {
				LM_ERR("Failed to get string from Cassandra Value object\n");
				goto error;
			}
			map_cdb_key.is_pk = 0;

			map_cass_val = cass_iterator_get_map_value(map_iter);
			if (!map_cass_val) {
				LM_ERR("Failed to get Cassandra Value object\n");
				goto error;
			}

			if (append_cass_val_to_dict(map_cass_val, &pair->val.val.dict,
				&map_cdb_key, 1) < 0) {
				LM_ERR("Failed to add map to cdb result\n");
				goto error;
			}
		}
		cass_iterator_free(map_iter);
		break;
	default:
		LM_ERR("Unsupported Cassandra data type: %d\n", cass_value_type(cass_val));
		return -1;
	}

	cdb_dict_add(pair, cdb_dict);

	return 0;

error:
	if (map_iter)
		cass_iterator_free(map_iter);
	pkg_free(pair);
	return -1;
}

int cass_result_to_cdb_res(const CassResult *cass_result, cdb_res_t *cdb_res,
							const CassTableMeta *table_meta)
{
	CassIterator *rows_iter;
	const CassRow *cass_row;
	const CassValue *cass_val;
	cdb_row_t *cdb_row = NULL;
	cdb_key_t cdb_key;
	const CassColumnMeta *col_meta;
	int col_idx, cols_count;

	cdb_res_init(cdb_res);

	cols_count = cass_result_column_count(cass_result);

	rows_iter = cass_iterator_from_result(cass_result);
	while (cass_iterator_next(rows_iter)) {
		cass_row = cass_iterator_get_row(rows_iter);
		if (!cass_row) {
			LM_ERR("Failed to get Cassandra Row object\n");
			goto error;
		}

		cdb_row = pkg_malloc(sizeof *cdb_row);
		if (!cdb_row) {
			LM_ERR("oom\n");
			goto error;
		}

		INIT_LIST_HEAD(&cdb_row->dict);

		for (col_idx = 0; col_idx < cols_count; col_idx++) {
			if (cass_result_column_name(cass_result, col_idx,
				(const char **)&cdb_key.name.s, (size_t *)&cdb_key.name.len)
				!= CASS_OK) {
				LM_ERR("Failed to get column name\n");
				goto error;
			}

			col_meta = cass_table_meta_column_by_name_n(table_meta,
						(const char *)cdb_key.name.s, (size_t)cdb_key.name.len);
			if (!col_meta) {
				LM_ERR("Failed to get column metadata\n");
				goto error;
			}
			if (cass_column_meta_type(col_meta) == CASS_COLUMN_TYPE_PARTITION_KEY)
				cdb_key.is_pk = 1;
			else
				cdb_key.is_pk = 0;

			cass_val = cass_row_get_column(cass_row, col_idx);
			if (!cass_val) {
				LM_ERR("Failed to get Cassandra Value object\n");
				goto error;
			}
			if (append_cass_val_to_dict(cass_val, &cdb_row->dict, &cdb_key, 0) < 0) {
				LM_ERR("Failed to add column to cdb result\n");
				cdb_free_entries(&cdb_row->dict, osips_pkg_free);
				goto error;
			}
		}

		cdb_res->count++;
		list_add_tail(&cdb_row->list, &cdb_res->rows);
	}

	cass_iterator_free(rows_iter);
	return 0;

error:
	if (cdb_row)
		pkg_free(cdb_row);
	cass_iterator_free(rows_iter);
	return -1;
}

int cassandra_col_query(cachedb_con *con, const cdb_filter_t *filter,
						cdb_res_t *res)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	static str buf = {0,0};
	int cql_buf_len;
	int buf_len = 0;
	int no_bind_params = 0;

	if (!con) {
		LM_ERR("null parameter\n");
		return -1;
	}
	cass_con = (cassandra_con *)con->data;

	/* build select query */
	if (filter) {
		/* build query's WHERE clause */
		if ((buf_len = where_clause_from_filter(filter, &buf,
			&no_bind_params)) < 0) {
			LM_ERR("Failed to build WHERE caluse for query\n");
			return -1;
		}

		/* estimate the length of the query string */
		cql_buf_len = 15 + cass_con->keyspace.len + 3 + cass_con->table.len + 8 +
			buf_len + 16;

		if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
			LM_ERR("oom\n");
			return -1;
		}

		cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
			"SELECT * FROM \"%.*s\".\"%.*s\" WHERE %s ALLOW FILTERING",
			cass_con->keyspace.len, cass_con->keyspace.s,
			cass_con->table.len, cass_con->table.s, buf.s);
	} else {
		/* estimate the length of the query string */
		cql_buf_len = 15 + cass_con->keyspace.len + 3 + cass_con->table.len + 1;

		if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
			LM_ERR("oom\n");
			return -1;
		}

		cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
			"SELECT * FROM \"%.*s\".\"%.*s\"",
			cass_con->keyspace.len, cass_con->keyspace.s,
			cass_con->table.len, cass_con->table.s);
	}
	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'query'\n");
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, no_bind_params);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	if (cass_statement_set_consistency(statement, rd_consistency) != CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	if (bind_where_clause_params(statement, filter, 0) < 0) {
		LM_ERR("Failed to bind where clause parameters\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'query'");

process_result:
	if (cass_result_to_cdb_res(result, res, cass_con->table_meta) < 0) {
		LM_ERR("Failed to process Cassandra result\n");
		cass_result_free(result);
		goto error;
	}

	cass_statement_free(statement);
	cass_result_free(result);
	return 0;

error:
	LM_ERR("Cassandra 'query' failed\n");
	cass_statement_free(statement);
	return -1;
}

int cassandra_truncate(cachedb_con *con)
{
	cassandra_con *cass_con;
	CassStatement *statement;
	const CassResult *result;
	int cql_buf_len;

	if (!con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cass_con = (cassandra_con *)con->data;

	/* estimate the length of the query string */
	cql_buf_len = 10 + cass_con->keyspace.len + 3 + cass_con->table.len + 1;

	if (pkg_str_extend(&cql_query_buf, cql_buf_len+1) < 0) {
		LM_ERR("oom\n");
		return -1;
	}

	cql_buf_len = snprintf(cql_query_buf.s, cql_buf_len+1,
		"TRUNCATE \"%.*s\".\"%.*s\"",
		cass_con->keyspace.len, cass_con->keyspace.s,
		cass_con->table.len, cass_con->table.s);

	if (cql_buf_len < 0) {
		LM_ERR("Failed to build query string for Cassandra 'truncate'\n");
		return -1;
	}

	statement = cass_statement_new_n(cql_query_buf.s, cql_buf_len, 0);
	if (!statement) {
		LM_ERR("Failed to create Cassandra Statement object\n");
		return -1;
	}

	/* "ALL" consistency is required by Cassandra for a truncate operation */
	if (cass_statement_set_consistency(statement, CASS_CONSISTENCY_ALL)
		!= CASS_OK) {
		LM_ERR("Failed to set statement's consistency level\n");
		goto error;
	}

	cassandra_do_query("Cassandra 'truncate'");

process_result:
	cass_statement_free(statement);
	cass_result_free(result);
	return 0;

error:
	LM_ERR("Cassandra 'truncate' failed\n");
	cass_statement_free(statement);
	return -1;
}
