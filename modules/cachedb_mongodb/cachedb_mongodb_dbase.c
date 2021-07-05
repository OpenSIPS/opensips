/*
 * Copyright (C) 2011-2019 OpenSIPS Project
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
 */

#include "../../dprint.h"
#include "cachedb_mongodb_dbase.h"
#include "cachedb_mongodb_json.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../cachedb/cachedb.h"
#include "../../lib/osips_malloc.h"

#include <string.h>

extern str mongo_write_concern_str;
extern str mongo_write_concern_b;
extern int mongo_slave_ok;
extern int mongo_exec_threshold;

extern int compat_mode_30;
extern int compat_mode_24;

#define HEX_OID_SIZE 25
char *hex_oid_id;

#define dbg_bson(_prepend_txt, __bson_ptr__) \
	do { \
		char *__bson_str__; \
		if (is_printable(L_DBG)) { \
			__bson_str__ = bson_as_json(__bson_ptr__, NULL); \
			LM_DBG("%s%s\n", _prepend_txt, __bson_str__); \
			bson_free(__bson_str__); \
		} \
	} while (0)

#define dump_mongo_err(_err_ptr) \
	do { \
		LM_ERR("last error: %d.%d: %s\n", (_err_ptr)->domain, \
		       (_err_ptr)->code, (_err_ptr)->message); \
	} while (0)

/**
 * Builds a MongoDB connect string URI of the form:
 *
 * mongodb://[username:password@]
 *	   host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
 *
 * See https://docs.mongodb.com/manual/reference/connection-string
 */
static char *build_mongodb_connect_string(struct cachedb_id *id)
{
	char *ret, *p;
	int len, db_len;

	len =
	      strlen(id->scheme) + 3 +
	      (id->username ? strlen(id->username) : 0) + 1 +
	      (id->password ? strlen(id->password) : 0) + 1 +
	      strlen(id->host) + 1 +
		  5 + 1 + /* port */
	      strlen(id->database) + 1 +
		  (id->extra_options ? strlen(id->extra_options) : 0) + 1 +
		  1;

	ret = pkg_malloc(len);
	if (!ret) {
		LM_ERR("oom\n");
		return NULL;
	}

	p = memchr(id->database, '.', strlen(id->database));
	if (p)
		db_len = p - id->database;
	else
		db_len = strlen(id->database);

	len = sprintf(ret, "mongodb://");

	if (id->username && id->password)
		len += sprintf(ret + len, "%s:%s@", id->username, id->password);

	len += sprintf(ret + len, "%s", id->host);

	if (id->port != 0)
		len += sprintf(ret + len, ":%d", id->port);

	len += sprintf(ret + len, "/%.*s", db_len, id->database);

	if (id->extra_options)
		sprintf(ret + len, "?%s", id->extra_options);

	return ret;
}

#ifndef MONGOC_HANDSHAKE_APPNAME_MAX
#define MONGOC_HANDSHAKE_APPNAME_MAX 128
#endif

char osips_appname[MONGOC_HANDSHAKE_APPNAME_MAX];
mongo_con* mongo_new_connection(struct cachedb_id* id)
{
	char *p, *conn_str;
	mongo_con *con;

	if (!id->database) {
		LM_ERR("bad MongoDB URL (missing \"/database\" part)\n");
		return NULL;
	}

	snprintf(osips_appname, MONGOC_HANDSHAKE_APPNAME_MAX, "opensips-%d", my_pid());

	LM_DBG("MongoDB conn for [%s]: %s:%s://%s:xxxxxx@%s:%u\n", osips_appname,
	       id->scheme, id->group_name, id->username, id->host, id->port);

	conn_str = build_mongodb_connect_string(id);

	LM_DBG("cstr: %s\n", _db_url_escape(conn_str));

	con = pkg_malloc(sizeof *con);
	if (!con) {
		LM_ERR("oom!\n");
		return NULL;
	}
	memset(con, 0, sizeof *con);
	con->id = id;
	con->ref = 1;

	con->client = mongoc_client_new(conn_str);
	if (!con->client) {
		LM_ERR("failed to connect to Mongo (%s)\n", _db_url_escape(conn_str));
		return NULL;
	}

	p = memchr(id->database, '.', strlen(id->database));
	if (!p) {
		LM_ERR("MongoDB URL is missing the '/DB.collection' construct, only "
		       "have '/DB' so far: /%s\n", id->database);
		return NULL;
	}

	*p = '\0';
	con->db = pkg_strdup(id->database);
	con->col = pkg_strdup(p + 1);
	if (!con->db || !con->col) {
		LM_ERR("oom\n");
		return NULL;
	}

	LM_DBG("db: '%s', col: '%s', options: '%s'\n",
	       con->db, con->col, id->extra_options);

	con->database = mongoc_client_get_database(con->client, id->database);
	con->collection = mongoc_client_get_collection(con->client, id->database, p+1);
	*p = '.';

	pkg_free(conn_str);
	return con;
}

cachedb_con *mongo_con_init(str *url)
{
	return cachedb_do_init(url,(void *)mongo_new_connection);
}

void mongo_free_connection(cachedb_pool_con *con)
{
	mongo_con *mcon = (mongo_con *)con;

	mongoc_collection_destroy(mcon->collection);
	mongoc_database_destroy(mcon->database);
	mongoc_client_destroy(mcon->client);
	pkg_free(mcon->db);
	pkg_free(mcon->col);
}

void mongo_con_destroy(cachedb_con *con)
{
	LM_DBG("in mongo_destroy\n");
	cachedb_do_close(con,mongo_free_connection);
}

int mongo_con_get(cachedb_con *con, str *attr, str *val)
{
	bson_t *filter;
	mongoc_cursor_t *cursor;
	const bson_t *doc;
	bson_iter_t iter;
	const bson_value_t *value;
	struct timeval start;
	unsigned long ival;
	char *p;
	int ret = 0;

	LM_DBG("find %.*s in %s\n", attr->len, attr->s,
	       MONGO_NAMESPACE(con));

	filter = bson_new();
#if MONGOC_CHECK_VERSION(1, 5, 0)
	bson_append_utf8(filter, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find_with_opts(
	                MONGO_COLLECTION(con), filter, NULL, NULL);
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB get",
	            attr->s, attr->len, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_next(cursor, &doc)) {
#else
	bson_t child;
	BSON_APPEND_DOCUMENT_BEGIN(filter, "$query", &child);
	bson_append_utf8(&child, MDB_PK, MDB_PKLEN, attr->s, attr->len);
	bson_append_document_end(filter, &child);

	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find(MONGO_COLLECTION(con), MONGOC_QUERY_NONE,
	                                0, 0, 0, filter, NULL, NULL);
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB get",
	            attr->s, attr->len, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_more(cursor) && mongoc_cursor_next(cursor, &doc)) {
#endif
		if (bson_iter_init_find(&iter, doc, "opensips")) {
			value = bson_iter_value(&iter);
			switch (value->value_type) {
			case BSON_TYPE_UTF8:
				val->len = value->value.v_utf8.len;
				val->s = pkg_malloc(val->len);
					if (!val->s) {
						LM_ERR("oom!\n");
					goto out_err;
				}
				memcpy(val->s, value->value.v_utf8.str, val->len);
				goto out_found;
			case BSON_TYPE_INT32:
				ival = (unsigned long)value->value.v_int32;
				break;
			case BSON_TYPE_INT64:
				ival = (unsigned long)value->value.v_int64;
				break;
			default:
				LM_ERR("unsupported type %d for key %.*s!\n",
				       value->value_type, attr->len, attr->s);
				goto out_err;
			}

			p = int2str(ival, &val->len);
			val->s = pkg_malloc(val->len);
			if (!val->s) {
				LM_ERR("oom!\n");
				goto out_err;
			}
			memcpy(val->s, p, val->len);
			goto out_found;
		}
	}

	ret = -2;
	memset(val, 0, sizeof *val);
	LM_DBG("key not found: %.*s\n", attr->len, attr->s);

out_found:
	bson_destroy(filter);
	mongoc_cursor_destroy(cursor);
	return ret;

out_err:
	bson_destroy(filter);
	mongoc_cursor_destroy(cursor);
	memset(val, 0, sizeof *val);
	return -1;
}

int mongo_con_set(cachedb_con *con, str *attr, str *val, int expires)
{
	bson_t *query, *update;
	bson_t child;
	bson_error_t error;
	struct timeval start;
	int ret = 0;

	query = bson_new();
	bson_append_utf8(query, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	update = bson_new();
	BSON_APPEND_DOCUMENT_BEGIN(update, "$set", &child);
	bson_append_utf8(&child, "opensips", 8, val->s, val->len);
	bson_append_document_end(update, &child);

	dbg_bson("query: ", query);
	dbg_bson("update: ", update);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_update(MONGO_COLLECTION(con), MONGOC_UPDATE_UPSERT,
	                              query, update, NULL, &error)) {
		LM_ERR("failed to store %.*s=%.*s\n",
		       attr->len, attr->s, val->len, val->s);
		ret = -1;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB set",
	            attr->s, attr->len, 0, cdb_slow_queries, cdb_total_queries);

	bson_destroy(query);
	bson_destroy(update);

	return ret;
}

int mongo_con_remove(cachedb_con *con, str *attr)
{
	bson_t *doc;
	bson_error_t error;
	struct timeval start;
	int ret = 0;

	doc = bson_new();
	bson_append_utf8(doc, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	dbg_bson("removing: ", doc);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_remove(MONGO_COLLECTION(con),
	                         MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error)) {
		LM_ERR("failed to remove key '%.*s'\n", attr->len, attr->s);
		ret = -1;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB remove",
	            attr->s, attr->len, 0, cdb_slow_queries, cdb_total_queries);

	bson_destroy(doc);

	return ret;
}

/* In MongoDB, we always use "_id" as the primary cache key */
int _mongo_con_remove(cachedb_con *con, str *attr, const str *key)
{
	return mongo_con_remove(con, attr);
}

int mongo_raw_find(cachedb_con *con, bson_t *raw_query, bson_iter_t *ns,
                   cdb_raw_entry ***reply, int expected_kv_no, int *reply_no)
{
	struct json_object *obj = NULL;
	mongoc_collection_t *col = NULL;
	bson_iter_t iter;
	bson_t _query, *query = NULL, *opts = NULL, proj;
	mongoc_cursor_t *cursor;
	struct timeval start;
	const bson_value_t *v;
	const bson_t *doc;
	int i, len, csz = 0, ret = -1;
	const char *p;

	if (bson_iter_type(ns) != BSON_TYPE_UTF8) {
		LM_ERR("collection name must be a string (%d)!\n", bson_iter_type(ns));
		return -1;
	}

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   bson_iter_utf8(ns, NULL));

#if MONGOC_CHECK_VERSION(1, 5, 0)
	if (bson_iter_init_find(&iter, raw_query, "filter") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter)) {
		v = bson_iter_value(&iter);
		bson_init_static(&_query, v->value.v_doc.data, v->value.v_doc.data_len);
	} else {
		bson_init(&_query);
	}
	query = &_query;
#else
	bson_t *fields = NULL, child;

	query = bson_new();
	BSON_APPEND_DOCUMENT_BEGIN(query, "$query", &child);
	if (bson_iter_init_find(&iter, raw_query, "filter") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter)) {
		v = bson_iter_value(&iter);
		bson_init_static(&child, v->value.v_doc.data, v->value.v_doc.data_len);
	}
	bson_append_document_end(query, &child);
#endif

	if (bson_iter_init_find(&iter, raw_query, "projection") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter)) {
#if MONGOC_CHECK_VERSION(1, 5, 0)
		opts = bson_new();
#endif
		v = bson_iter_value(&iter);
		bson_init_static(&proj, v->value.v_doc.data, v->value.v_doc.data_len);
#if MONGOC_CHECK_VERSION(1, 5, 0)
		bson_append_document(opts, "projection", 10, &proj);
#else
		fields = &proj;
#endif
	}

	if (!reply)
		goto ok_skip_result;
	*reply = NULL;

#if MONGOC_CHECK_VERSION(1, 5, 0)
	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find_with_opts(col, query, opts, NULL);
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw find",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_next(cursor, &doc)) {
#else
	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find(col, MONGOC_QUERY_NONE,
	                                0, 0, 0, query, fields, NULL);
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw find",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_more(cursor) && mongoc_cursor_next(cursor, &doc)) {
#endif

		*reply = pkg_realloc(*reply, (csz + 1) * sizeof **reply);
		if (!*reply) {
			LM_ERR("no more pkg\n");
			ret = -1;
			goto out_err;
		}
		(*reply)[csz] = pkg_malloc(expected_kv_no * sizeof ***reply);
		if (!(*reply)[csz]) {
			LM_ERR("no more pkg\n");
			ret = -1;
			goto out_err_free;
		}

		bson_iter_init(&iter, doc);
		obj = json_object_new_object();
		bson_to_json_generic(obj, &iter, BSON_TYPE_DOCUMENT);

		p = json_object_to_json_string(obj);
		if (!p) {
			LM_ERR("failed to translate json to string\n");
			ret = -1;
			goto out_err_free;
		}

		LM_DBG("got JSON: %s\n", p);

		len = strlen(p);
		(*reply)[csz][0].val.s.s = pkg_malloc(len);
		if (!(*reply)[csz][0].val.s.s ) {
			LM_ERR("No more pkg \n");
			ret = -1;
			goto out_err_free;
		}

		memcpy((*reply)[csz][0].val.s.s, p, len);
		(*reply)[csz][0].val.s.len = len;
		(*reply)[csz][0].type = CDB_STR;

		json_object_put(obj);

		csz++;
	}

	*reply_no = csz;

ok_skip_result:
	if (opts)
		bson_destroy(opts);
	if (query != &_query)
		bson_destroy(query);
	mongoc_cursor_destroy(cursor);
	mongoc_collection_destroy(col);
	return 0;

out_err_free:
	if (*reply) {
		for (i = 0; i < csz; i++) {
			pkg_free((*reply)[i][0].val.s.s);
			pkg_free((*reply)[i]);
		}

		pkg_free(*reply);
	}
out_err:
	*reply = NULL;
	*reply_no = 0;
	if (opts)
		bson_destroy(opts);
	if (query != &_query)
		bson_destroy(query);
	mongoc_cursor_destroy(cursor);
	mongoc_collection_destroy(col);
	return ret;
}

int mongo_raw_update(cachedb_con *con, bson_t *raw_query, bson_iter_t *ns)
{
	mongoc_collection_t *col = NULL;
	mongoc_bulk_operation_t *bulk = NULL;
	bson_iter_t iter, uiter, sub_iter;
	bson_error_t error;
	bson_t query, update, reply;
	struct timeval start;
	const bson_value_t *v;
	int ret, count = 0;

	if (bson_iter_type(ns) != BSON_TYPE_UTF8) {
		LM_ERR("collection name must be a string (%d)!\n", bson_iter_type(ns));
		return -1;
	}

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   bson_iter_utf8(ns, NULL));

	if (!bson_iter_init_find(&iter, raw_query, "updates") ||
	    !BSON_ITER_HOLDS_ARRAY(&iter)) {
		LM_ERR("missing or non-array 'updates' field in update command!\n");
		return -1;
	}

	if (bson_iter_recurse(&iter, &sub_iter)) {
		while (bson_iter_next(&sub_iter)) {
			count++;
		}
	}

	if (count == 0) {
		LM_DBG("nothing to update!\n");
		goto out;
	}

#if MONGOC_CHECK_VERSION(1,9,0)
	bulk = mongoc_collection_create_bulk_operation_with_opts(col, NULL);
#else
	bulk = mongoc_collection_create_bulk_operation(col, false, NULL);
#endif
	if (!bulk) {
		LM_ERR("failed to create bulk op!\n");
		goto out_err;
	}

	count = 0;
	if (bson_iter_init_find(&iter, raw_query, "updates") &&
	    bson_iter_recurse(&iter, &uiter)) {
		while (bson_iter_next(&uiter)) {
			bson_iter_recurse(&uiter, &sub_iter);
			if (!bson_iter_find(&sub_iter, "q")) {
				LM_ERR("ignoring 'updates' subdoc due to missing q field!\n");
				continue;
			}
			v = bson_iter_value(&sub_iter);
			bson_init_static(&query, v->value.v_doc.data, v->value.v_doc.data_len);

			bson_iter_recurse(&uiter, &sub_iter);
			if (!bson_iter_find(&sub_iter, "u")) {
				LM_ERR("ignoring 'updates' subdoc due to missing u field!\n");
				continue;
			}
			v = bson_iter_value(&sub_iter);
			bson_init_static(&update, v->value.v_doc.data, v->value.v_doc.data_len);

			count++;
			mongoc_bulk_operation_update(bulk, &query, &update, true);
		}
	}

	if (count == 0) {
		LM_DBG("nothing to update!\n");
		goto out;
	}

	start_expire_timer(start, mongo_exec_threshold);
	ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	if (!ret) {
		LM_ERR("failed bulk update\nerror: %d.%d: %s\n",
		       error.domain, error.code, error.message);
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw update",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw update",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	dbg_bson("reply received: ", &reply);

out:
	if (bulk) {
		mongoc_bulk_operation_destroy(bulk);
	}
	mongoc_collection_destroy(col);
	return 0;

out_err:
	if (bulk) {
		mongoc_bulk_operation_destroy(bulk);
	}
	mongoc_collection_destroy(col);
	return -1;
}

int mongo_raw_insert(cachedb_con *con, bson_t *raw_query, bson_iter_t *ns)
{
	mongoc_collection_t *col = NULL;
	mongoc_bulk_operation_t *bulk = NULL;
	bson_iter_t iter, sub_iter;
	bson_error_t error;
	bson_t doc, reply;
	struct timeval start;
	const bson_value_t *v;
	int ret, count = 0;

	if (bson_iter_type(ns) != BSON_TYPE_UTF8) {
		LM_ERR("collection name must be a string (%d)!\n", bson_iter_type(ns));
		return -1;
	}

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   bson_iter_utf8(ns, NULL));

	if (!bson_iter_init_find(&iter, raw_query, "documents") ||
	    !BSON_ITER_HOLDS_ARRAY(&iter)) {
		LM_ERR("missing or non-array 'documents' field in raw insert!\n");
		return -1;
	}

	if (bson_iter_recurse(&iter, &sub_iter)) {
		while (bson_iter_next(&sub_iter)) {
			count++;
		}
	}

	if (count == 0) {
		LM_DBG("nothing to insert!\n");
		goto out;
	}

#if MONGOC_CHECK_VERSION(1,9,0)
	bulk = mongoc_collection_create_bulk_operation_with_opts(col, NULL);
#else
	bulk = mongoc_collection_create_bulk_operation(col, false, NULL);
#endif
	if (!bulk) {
		LM_ERR("failed to create bulk op!\n");
		goto out_err;
	}

	if (bson_iter_init_find(&iter, raw_query, "documents") &&
	    bson_iter_recurse(&iter, &sub_iter)) {
		while (bson_iter_next(&sub_iter)) {
			v = bson_iter_value(&sub_iter);
			bson_init_static(&doc, v->value.v_doc.data, v->value.v_doc.data_len);
			mongoc_bulk_operation_insert(bulk, &doc);
		}
	}

	start_expire_timer(start, mongo_exec_threshold);
	ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	if (!ret) {
		LM_ERR("failed bulk insert\nerror: %d.%d: %s\n",
		       error.domain, error.code, error.message);
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw insert",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw insert",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	dbg_bson("reply received: ", &reply);

out:
	if (bulk) {
		mongoc_bulk_operation_destroy(bulk);
	}
	mongoc_collection_destroy(col);
	return 0;

out_err:
	if (bulk) {
		mongoc_bulk_operation_destroy(bulk);
	}
	mongoc_collection_destroy(col);
	return -1;
}

int mongo_raw_remove(cachedb_con *con, bson_t *raw_query, bson_iter_t *ns)
{
	mongoc_collection_t *col = NULL;
	mongoc_bulk_operation_t *bulk = NULL;
	bson_iter_t iter, qiter, sub_iter;
	bson_error_t error;
	bson_t doc, reply;
	struct timeval start;
	const bson_value_t *v;
	int ret, count = 0;

	if (bson_iter_type(ns) != BSON_TYPE_UTF8) {
		LM_ERR("collection name must be a string (%d)!\n", bson_iter_type(ns));
		return -1;
	}

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   bson_iter_utf8(ns, NULL));

	if (!bson_iter_init_find(&iter, raw_query, "deletes") ||
	    !BSON_ITER_HOLDS_ARRAY(&iter)) {
		LM_ERR("missing or non-array 'deletes' field in delete command!\n");
		return -1;
	}

	if (bson_iter_recurse(&iter, &sub_iter)) {
		while (bson_iter_next(&sub_iter)) {
			count++;
		}
	}

	if (count == 0) {
		LM_DBG("nothing to delete!\n");
		goto out;
	}

#if MONGOC_CHECK_VERSION(1,9,0)
	bulk = mongoc_collection_create_bulk_operation_with_opts(col, NULL);
#else
	bulk = mongoc_collection_create_bulk_operation(col, false, NULL);
#endif
	if (!bulk) {
		LM_ERR("failed to create bulk op!\n");
		goto out_err;
	}

	count = 0;
	if (bson_iter_init_find(&iter, raw_query, "deletes") &&
	    bson_iter_recurse(&iter, &qiter)) {
		while (bson_iter_next(&qiter)) {
			bson_iter_recurse(&qiter, &sub_iter);
			if (!bson_iter_find(&sub_iter, "q")) {
				LM_ERR("ignoring 'deletes' subdoc due to missing q field!\n");
				continue;
			}
			v = bson_iter_value(&sub_iter);
			bson_init_static(&doc, v->value.v_doc.data, v->value.v_doc.data_len);

			count++;
			mongoc_bulk_operation_remove(bulk, &doc);
		}
	}

	if (count == 0) {
		LM_DBG("nothing to update!\n");
		goto out;
	}

	start_expire_timer(start, mongo_exec_threshold);
	ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	if (!ret) {
		LM_ERR("failed bulk insert\nerror: %d.%d: %s\n",
		       error.domain, error.code, error.message);
		_stop_expire_timer(start, mongo_exec_threshold, "mongodb raw remove",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw remove",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	dbg_bson("reply received: ", &reply);

out:
	if (bulk) {
		mongoc_bulk_operation_destroy(bulk);
	}
	mongoc_collection_destroy(col);
	return 0;

out_err:
	if (bulk) {
		mongoc_bulk_operation_destroy(bulk);
	}
	mongoc_collection_destroy(col);
	return -1;
}

int mongo_con_raw_query(cachedb_con *con, str *qstr, cdb_raw_entry ***reply,
                        int expected_kv_no, int *reply_no)
{
	static str raw_query_buf;

	bson_t doc = BSON_INITIALIZER, rpl = BSON_INITIALIZER;
	bson_iter_t iter;
	bson_error_t error;
	struct timeval start;
	int ret = 0;
	const char *p;
	int csz = 0, i, len;

	LM_DBG("Get operation on namespace %s\n", MONGO_NAMESPACE(con));
	start_expire_timer(start,mongo_exec_threshold);

	if (pkg_str_extend(&raw_query_buf, qstr->len + 1)) {
		LM_ERR("oom!\n");
		return -1;
	}

	memcpy(raw_query_buf.s, qstr->s, qstr->len);
	raw_query_buf.s[qstr->len] = '\0';

	ret = json_to_bson(raw_query_buf.s, &doc);
	if (ret < 0) {
		LM_ERR("Failed to convert [%.*s] to BSON\n", qstr->len, qstr->s);
		ret = -1;
		goto out_err;
	}

	/* treat "find" differently on pre-3.2 MongoDB servers */
	if ((compat_mode_30 || compat_mode_24) &&
	    bson_iter_init_find(&iter, &doc, "find")) {
		if (mongo_raw_find(con, &doc, &iter, reply, expected_kv_no, reply_no) != 0)
			return -1;

		if (*reply_no == 0)
			return -2;

		return 0;
	} else if (compat_mode_24) {
		if (bson_iter_init_find(&iter, &doc, "insert"))
			return mongo_raw_insert(con, &doc, &iter);
		else if (bson_iter_init_find(&iter, &doc, "update"))
			return mongo_raw_update(con, &doc, &iter);
		else if (bson_iter_init_find(&iter, &doc, "delete"))
			return mongo_raw_remove(con, &doc, &iter);
	}

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_command_simple(MONGO_COLLECTION(con), &doc,
	                              NULL, &rpl, &error)) {
		LM_ERR("raw query:\n'%.*s'\nfailed with: %d.%d: %s\n", qstr->len, qstr->s,
		       error.domain, error.code, error.message);
		ret = -1;
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw query",
		            qstr->s, qstr->len, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB raw query",
	            qstr->s, qstr->len, 0, cdb_slow_queries, cdb_total_queries);

	if (!reply)
		goto ok_skip_result;

	/* start with a single returned document */
	*reply = pkg_malloc(1 * sizeof **reply);
	if (!*reply) {
		LM_ERR("no more PKG mem\n");
		goto out_err;
	}

	/* expected_kv_no is always 1 for MongoDB */
	**reply = pkg_malloc(expected_kv_no * sizeof ***reply);
	if (!**reply) {
		LM_ERR("No more pkg mem\n");
		pkg_free(*reply);
		goto out_err;
	}

	if (!bson_iter_init(&iter, &rpl)) {
		LM_ERR("failed to init!!!\n");
		ret = -1;
		goto out_err;
	}

	do {
		struct json_object *obj;

		if (csz > 0) {
			*reply = pkg_realloc(*reply, (csz + 1) * sizeof **reply);
			if (!*reply) {
				LM_ERR("No more pkg\n");
				ret = -1;
				goto out_err;
			}
			(*reply)[csz] = pkg_malloc(expected_kv_no * sizeof ***reply);
			if (!(*reply)[csz]) {
				LM_ERR("No more pkg\n");
				ret = -1;
				goto out_err;
			}
		}

		obj = json_object_new_object();
		bson_to_json_generic(obj, &iter, BSON_TYPE_DOCUMENT);

		p = json_object_to_json_string(obj);
		if (!p) {
			LM_ERR("failed to translate json to string\n");
			json_object_put(obj);
			ret = -1;
			goto out_err;
		}

		LM_DBG("got JSON: %s\n", p);

		len = strlen(p);
		(*reply)[csz][0].val.s.s = pkg_malloc(len);
		if (!(*reply)[csz][0].val.s.s ) {
			LM_ERR("No more pkg \n");
			json_object_put(obj);
			ret = -1;
			goto out_err;
		}

		memcpy((*reply)[csz][0].val.s.s,p,len);
		(*reply)[csz][0].val.s.len = len;
		(*reply)[csz][0].type = CDB_STR;

		json_object_put(obj);

		csz++;
	} while (bson_iter_next(&iter));

	*reply_no = csz;

ok_skip_result:
	bson_destroy(&doc);
	bson_destroy(&rpl);

	return csz == 0 ? -2 : 1;

out_err:
	bson_destroy(&doc);
	bson_destroy(&rpl);

	if (reply && *reply) {
		for (i = 0; i < csz; i++) {
			pkg_free((*reply)[i][0].val.s.s);
			pkg_free((*reply)[i]);
		}

		pkg_free(*reply);
		*reply = NULL;
		*reply_no = 0;
	}

	return ret;
}

int mongo_con_add(cachedb_con *con, str *attr, int val, int expires, int *new_val)
{
	bson_t *cmd;
	bson_t child, ichild, reply;
	bson_error_t error;
	bson_iter_t iter;
	bson_iter_t sub_iter;
	struct timeval start;
	int ret = 0;

	cmd = bson_new();
	bson_append_utf8(cmd, "findAndModify", 13,
	                 mongoc_collection_get_name(MONGO_COLLECTION(con)), -1);

	BSON_APPEND_DOCUMENT_BEGIN(cmd, "query", &child);
	bson_append_utf8(&child, MDB_PK, MDB_PKLEN, attr->s, attr->len);
	bson_append_document_end(cmd, &child);

	BSON_APPEND_DOCUMENT_BEGIN(cmd, "update", &child);
	BSON_APPEND_DOCUMENT_BEGIN(&child, "$inc", &ichild);
	bson_append_int32(&ichild, "opensips_counter", 16, val);
	bson_append_document_end(&child, &ichild);
	bson_append_document_end(cmd, &child);

	bson_append_bool(cmd, "upsert", 6, true);

	bson_append_bool(cmd, "new", 3, true);

	dbg_bson("upsert: ", cmd);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_command_simple(MONGO_COLLECTION(con), cmd,
	                              NULL, &reply, &error)) {
		LM_ERR("failed to %s: %.*s += %d\n", val > 0 ? "add" : "sub",
		       attr->len, attr->s, val);
		ret = -1;
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB counter add",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB counter add",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	if (!new_val)
		goto out;

	if (bson_iter_init_find(&iter, &reply, "value") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter) &&
	    bson_iter_recurse(&iter, &sub_iter)) {

		if (bson_iter_find(&sub_iter, "opensips_counter")) {
			*new_val = bson_iter_value(&sub_iter)->value.v_int32;
		}
	}

out:
	bson_destroy(&reply);
	bson_destroy(cmd);
	return ret;
}

int mongo_con_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	return mongo_con_add(connection,attr,-val,expires,new_val);
}

int mongo_con_get_counter(cachedb_con *con, str *attr, int *val)
{
	bson_t *query;
	const bson_t *doc;
	const bson_value_t *value;
	mongoc_cursor_t *cursor;
	bson_iter_t iter;
	struct timeval start;
	int ret = -2;

	query = bson_new();
#if MONGOC_CHECK_VERSION(1, 5, 0)
	bson_append_utf8(query, MDB_PK, MDB_PKLEN, attr->s, attr->len);
#else
	bson_t child;
	BSON_APPEND_DOCUMENT_BEGIN(query, "$query", &child);
	bson_append_utf8(&child, MDB_PK, MDB_PKLEN, attr->s, attr->len);
	bson_append_document_end(query, &child);
#endif

	dbg_bson("query: ", query);

#if MONGOC_CHECK_VERSION(1, 5, 0)
	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find_with_opts(
	                MONGO_COLLECTION(con), query, NULL, NULL);
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB counter get",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_next(cursor, &doc)) {
#else
	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find(MONGO_COLLECTION(con), MONGOC_QUERY_NONE,
	                                0, 0, 0, query, NULL, NULL);
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB counter get",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_more(cursor) && mongoc_cursor_next(cursor, &doc)) {
#endif

		if (bson_iter_init_find(&iter, doc, "opensips_counter")) {
			value = bson_iter_value(&iter);
			switch (value->value_type) {
			case BSON_TYPE_INT32:
				ret = 0;
				*val = value->value.v_int32;
				break;
			default:
				LM_ERR("unsupported type %d for key %.*s!\n", value->value_type, attr->len, attr->s);
				ret = -1;
				goto out;
			}
		}
	}

out:
	bson_destroy(query);
	mongoc_cursor_destroy(cursor);
	return ret;
}

int kvo_to_bson(const db_key_t *_k, const db_val_t *_v, const db_op_t *_op,
                 int _n, bson_t *doc)
{
	int i;
	bool ok = true;
	bson_t _child, *child;
	str key;
	bson_oid_t _id;
	bool has_oid = false;
	char *p, _old_char;

	for (i = 0; i < _n; i++) {
		if (!_op || strcmp(_op[i], OP_EQ) == 0) {
			child = doc;
			key = *_k[i];
		} else {
			child = &_child;
			bson_append_document_begin(doc, _k[i]->s, _k[i]->len, &_child);
			if (strcmp(_op[i], OP_LT) == 0) {
				key.s = "$lt";
				key.len = 3;
			} else if (strcmp(_op[i], OP_GT) == 0) {
				key.s = "$gt";
				key.len = 3;
			} else if (strcmp(_op[i], OP_LEQ) == 0) {
				key.s = "$lte";
				key.len = 4;
			} else if (strcmp(_op[i], OP_GEQ) == 0) {
				key.s = "$gte";
				key.len = 4;
			} else if (strcmp(_op[i], OP_NEQ) == 0) {
				key.s = "$ne";
				key.len = 3;
			} else {
				/* shouldn't get here, but let's make gcc happy */
				key.s = "";
				key.len = 0;
			}
		}

		if (VAL_NULL(&_v[i])) {
			if (!bson_append_null(child, key.s, key.len)) {
				LM_ERR("NULL NOT SUPPORTED X\n");
				return -1;
			}
			continue;
		}

		switch (VAL_TYPE(&_v[i])) {
			case DB_INT:
				ok = bson_append_int32(child, key.s, key.len, VAL_INT(&_v[i]));
				break;
			case DB_STRING:
				if (!has_oid && _k[i]->len == 3 &&
				    strncmp("_id", _k[i]->s, _k[i]->len) == 0) {
					LM_DBG("we got it [%.*s]\n", _k[i]->len, _k[i]->s);
					bson_oid_init_from_string(&_id, VAL_STRING(&_v[i]));
					ok = bson_append_oid(child, key.s, key.len, &_id);
					has_oid = true;
				} else {
					ok = bson_append_utf8(child, key.s, key.len, VAL_STRING(&_v[i]), -1);
				}
				break;
			case DB_STR:
				if (!has_oid && _k[i]->len == 3 &&
				    strncmp("_id", _k[i]->s, _k[i]->len) == 0) {
					p = VAL_STR(&_v[i]).s + VAL_STR(&_v[i]).len;
					_old_char = *p;
					*p = '\0';
					bson_oid_init_from_string(&_id, VAL_STR(&_v[i]).s);
					*p = _old_char;
					ok = bson_append_oid(child, key.s, key.len, &_id);
					has_oid = true;
				} else {
					ok = bson_append_utf8(child, key.s, key.len, VAL_STR(&_v[i]).s,
						VAL_STR(&_v[i]).len);
				}
				break;
			case DB_BLOB:
				ok = bson_append_utf8(child, key.s, key.len, VAL_BLOB(&_v[i]).s,
						VAL_BLOB(&_v[i]).len);
				break;
			case DB_DOUBLE:
				ok = bson_append_double(child, key.s, key.len, VAL_DOUBLE(&_v[i]));
				break;
			case DB_BIGINT:
				ok = bson_append_int64(child, key.s, key.len, VAL_BIGINT(&_v[i]));
				break;
			case DB_DATETIME:
				ok = bson_append_time_t(child, key.s, key.len, VAL_TIME(&_v[i]));
				break;
			case DB_BITMAP:
				ok = bson_append_int32(child, key.s, key.len, VAL_BITMAP(&_v[i]));
				break;
		}

		if (!ok) {
			LM_ERR("failed to append bson for key=%.*s, op=%s\n",
			       _k[i]->len, _k[i]->s, _op ? _op[i] : NULL);
			return -1;
		}

		if (_op && strcmp(_op[i], OP_EQ) != 0) {
			if (!bson_append_document_end(doc, child)) {
				LM_ERR("failed to append doc end!\n");
				return -1;
			}
		}
	}

	return 0;
}

int mongo_db_query_trans(cachedb_con *con, const str *table, const db_key_t *_k,
                         const db_op_t *_op, const db_val_t *_v,
                         const db_key_t *_c, const int _n, const int _nc,
                         const db_key_t _o, db_res_t **_r)
{
	char key_buff[32], namespace[MDB_MAX_NS_LEN], *p;
	char hex_oid[HEX_OID_SIZE];
	static str dummy_string = {"", 0};
	bson_t *filter, child;
	mongoc_cursor_t *cursor = NULL;
	const bson_t *doc;
	db_row_t *current;
	db_val_t *cur_val;
	bson_iter_t iter;
	struct timeval start;
	int ri, c, old_rows, rows = 0;
	unsigned int ts, _;
	mongoc_collection_t *col = NULL;
	char *strf, *stro;
	str st;

	*_r = NULL;

	filter = bson_new();

#if !MONGOC_CHECK_VERSION(1, 5, 0)
	bson_t *fields = NULL;
	BSON_APPEND_DOCUMENT_BEGIN(filter, "$query", &child);
	if (kvo_to_bson(_k, _v, _op, _n, &child) != 0) {
		LM_ERR("failed to build filter bson\n");
		goto out_err;
	}
	bson_append_document_end(filter, &child);
#else
	bson_t *opts = NULL;
	if (kvo_to_bson(_k, _v, _op, _n, filter) != 0) {
		LM_ERR("failed to build filter bson\n");
		goto out_err;
	}
#endif

#if MONGOC_CHECK_VERSION(1, 5, 0)
	opts = bson_new();
	if (_o) {
		bson_append_document_begin(opts, "sort", 4, &child);
		bson_append_int32(&child, _o->s, _o->len, 1);
		bson_append_document_end(opts, &child);
	}

	bson_append_document_begin(opts, "projection", 10, &child);
	for (c = 0; c < _nc; c++) {
		bson_append_int32(&child, _c[c]->s, _c[c]->len, 1);
	}
	bson_append_document_end(opts, &child);
#else
	if (_o) {
		BSON_APPEND_DOCUMENT_BEGIN(filter, "$orderby", &child);
		bson_append_int32(&child, _o->s, _o->len, 1);
		bson_append_document_end(filter, &child);
	}

	fields = bson_new();
	for (c = 0; c < _nc; c++) {
		bson_append_int32(fields, _c[c]->s, _c[c]->len, 1);
	}
#endif

	memcpy(namespace, table->s, table->len);
	namespace[table->len] = '\0';

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   namespace);

	if (is_printable(L_DBG)) {
		strf = bson_as_json(filter, NULL);
#if MONGOC_CHECK_VERSION(1, 5, 0)
		stro = bson_as_json(opts, NULL);
#else
		stro = bson_as_json(fields, NULL);
#endif
		LM_DBG("query doc:\n%s\n%s\n", strf, stro);
		bson_free(strf);
		bson_free(stro);
	}

	start_expire_timer(start, mongo_exec_threshold);
#if MONGOC_CHECK_VERSION(1, 5, 0)
	cursor = mongoc_collection_find_with_opts(col, filter, opts, NULL);
#else
	cursor = mongoc_collection_find(col, MONGOC_QUERY_NONE,
	                                0, 0, 0, filter, fields, NULL);
#endif
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB query trans",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	MONGO_CURSOR(con) = cursor;

	*_r = db_new_result();
	if (!*_r) {
		LM_ERR("Failed to init new result \n");
		goto out_err;
	}

	RES_COL_N(*_r) = _nc;

	/* on first iteration we allocate the result
	 * we always assume the query returns exactly the number
	 * of 'columns' as were requested */
	if (db_allocate_columns(*_r, _nc) != 0) {
		LM_ERR("failed to allocate columns\n");
		goto out_err;
	}

	/* and we initialize the names as if all are there */
	for (c = 0; c < _nc; c++) {
		/* since we don't have schema, the types will be allocated
		 * when we fetch the actual rows */
		RES_NAMES(*_r)[c]->s = _c[c]->s;
		RES_NAMES(*_r)[c]->len = _c[c]->len;
	}

#if MONGOC_CHECK_VERSION(1, 5, 0)
	for (ri = 0; mongoc_cursor_next(cursor, &doc); ri++) {
#else
	for (ri = 0; mongoc_cursor_more(cursor) &&
	             mongoc_cursor_next(cursor, &doc); ri++) {
#endif
		if (ri + 1 > rows) {
			old_rows = rows;
			rows = rows > 0 ? 2 * rows : 1;
			if (db_realloc_rows(*_r, old_rows, rows) != 0) {
				LM_ERR("failed to realloc rows\n");
				goto out_err;
			}

			hex_oid_id = pkg_realloc(hex_oid_id,
			                         sizeof *hex_oid_id * rows * (HEX_OID_SIZE + 1));
			if (!hex_oid_id) {
				LM_ERR("oom\n");
				goto out_err;
			}
		}

		RES_ROW_N(*_r) = ri + 1;

		current = &(RES_ROWS(*_r)[ri]);
		ROW_N(current) = RES_COL_N(*_r);
		for (c = 0; c < _nc; c++) {
			memcpy(key_buff, _c[c]->s, _c[c]->len);
			key_buff[_c[c]->len] = '\0';
			cur_val = &ROW_VALUES(current)[c];

			if (!bson_iter_init_find(&iter, doc, key_buff)) {
				memset(cur_val, 0, sizeof *cur_val);
				VAL_STRING(cur_val) = dummy_string.s;
				VAL_STR(cur_val) = dummy_string;
				VAL_BLOB(cur_val) = dummy_string;
				/* we treat null values as DB string */
				VAL_TYPE(cur_val) = DB_STRING;
				VAL_NULL(cur_val) = 1;
				LM_DBG("fixed missing col: '%.*s'\n", _c[c]->len, _c[c]->s);
			} else {
				switch (bson_iter_type(&iter)) {
					case BSON_TYPE_INT32:
						VAL_TYPE(cur_val) = DB_INT;
						VAL_INT(cur_val) = bson_iter_int32(&iter);
						LM_DBG("Found int [%.*s]=[%d]\n",
						       _c[c]->len, _c[c]->s, VAL_INT(cur_val));
						break;
					case BSON_TYPE_DOUBLE:
						VAL_TYPE(cur_val) = DB_DOUBLE;
						VAL_DOUBLE(cur_val) = bson_iter_double(&iter);
						LM_DBG("Found double [%.*s]=[%f]\n",
						       _c[c]->len, _c[c]->s, VAL_DOUBLE(cur_val));
						break;
					case BSON_TYPE_UTF8:
						st.s = (char *)bson_iter_utf8(&iter, (unsigned int *)&st.len);
						if (pkg_nt_str_dup(&st, &st) != 0) {
							LM_ERR("oom\n");
							goto out_err;
						}

						VAL_TYPE(cur_val) = DB_STRING;
						VAL_STRING(cur_val) = st.s;
						VAL_FREE(cur_val) = 1;
						LM_DBG("Found string [%.*s]=[%.*s]\n",
						       _c[c]->len, _c[c]->s, st.len, st.s);
						break;
					case BSON_TYPE_INT64:
						VAL_TYPE(cur_val) = DB_BIGINT;
						VAL_BIGINT(cur_val) = bson_iter_int64(&iter);
						LM_DBG("Found long [%.*s]=[%lld]\n",
						       _c[c]->len, _c[c]->s, VAL_BIGINT(cur_val));
						break;
					case BSON_TYPE_DATE_TIME:
						VAL_TYPE(cur_val) = DB_DATETIME;
						VAL_TIME(cur_val) = bson_iter_date_time(&iter)/(int64_t)1000;
						LM_DBG("Found time [%.*s]=[%d]\n",
						       _c[c]->len, _c[c]->s, (int)VAL_TIME(cur_val));
						break;
					case BSON_TYPE_OID:
						bson_oid_to_string(bson_iter_oid(&iter), hex_oid);
						p = &hex_oid_id[ri * (HEX_OID_SIZE + 1)];
						memcpy(p, hex_oid, HEX_OID_SIZE);
						p[HEX_OID_SIZE] = '\0';
						VAL_TYPE(cur_val) = DB_STRING;
						VAL_STRING(cur_val) = p;
						LM_DBG("Found oid [%.*s]=[%s]\n",
						       _c[c]->len, _c[c]->s, VAL_STRING(cur_val));
						break;
					case BSON_TYPE_NULL:
						VAL_TYPE(cur_val) = DB_STRING;
						VAL_NULL(cur_val) = 1;
						LM_DBG("Found null [%.*s]=[%d]\n",
						       _c[c]->len, _c[c]->s, VAL_NULL(cur_val));
						break;
					case BSON_TYPE_TIMESTAMP:
						bson_iter_timestamp(&iter, &ts, &_);
						VAL_TYPE(cur_val) = DB_INT;
						VAL_INT(cur_val) = (int)ts;
						LM_DBG("Found timestamp [%u]\n", ts);
						break;
					case BSON_TYPE_BINARY:
						bson_iter_binary(&iter, NULL, (unsigned int *)&st.len,
						                 (const unsigned char **)&st.s);
						VAL_TYPE(cur_val) = DB_STR;
						if (pkg_nt_str_dup(&VAL_STR(cur_val), &st) != 0) {
							LM_ERR("oom\n");
							goto out_err;
						}
						VAL_FREE(cur_val) = 1;
						LM_DBG("Found binary data: '%.*s'\n", st.len, st.s);
						break;
					default:
						LM_WARN("Unsupported type [%d] for [%.*s] - treating as NULL\n",
						        bson_iter_type(&iter), _c[c]->len, _c[c]->s);
						memset(cur_val, 0, sizeof *cur_val);
						VAL_STRING(cur_val) = dummy_string.s;
						VAL_STR(cur_val) = dummy_string;
						VAL_BLOB(cur_val) = dummy_string;
						/* we treat null values as DB string */
						VAL_TYPE(cur_val) = DB_STRING;
						VAL_NULL(cur_val) = 1;
						break;
				}
			}
		}
	}

	bson_destroy(filter);
#if MONGOC_CHECK_VERSION(1, 5, 0)
	bson_destroy(opts);
#else
	bson_destroy(fields);
#endif
	mongoc_collection_destroy(col);
	return 0;

out_err:
	bson_destroy(filter);
#if MONGOC_CHECK_VERSION(1, 5, 0)
	if (opts) {
		bson_destroy(opts);
	}
#else
	if (fields) {
		bson_destroy(fields);
	}
#endif
	if (cursor) {
		mongoc_cursor_destroy(cursor);
	}
	if (*_r) {
		db_free_result(*_r);
		*_r = NULL;

		if (hex_oid_id) {
			pkg_free(hex_oid_id);
			hex_oid_id = NULL;
		}
	}
	if (col) {
		mongoc_collection_destroy(col);
	}
	return -1;
}

int mongo_db_free_result_trans(cachedb_con *con, db_res_t *_r)
{
	if (!con || !_r) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	LM_DBG("freeing mongo query result \n");

	if (hex_oid_id) {
		pkg_free(hex_oid_id);
		hex_oid_id = NULL;
	}

	if (db_free_result(_r) < 0) {
		LM_ERR("unable to free result structure\n");
		return -1;
	}

	mongoc_cursor_destroy(MONGO_CURSOR(con));
	MONGO_CURSOR(con) = NULL;
	return 0;
}

int mongo_db_insert_trans(cachedb_con *con, const str *table,
                          const db_key_t *_k, const db_val_t *_v, const int _n)
{
	char namespace[MDB_MAX_NS_LEN];
	bson_t *doc;
	bson_error_t error;
	mongoc_collection_t *col = NULL;
	struct timeval start;

	doc = bson_new();
	if (kvo_to_bson(_k, _v, NULL, _n, doc) != 0) {
		LM_ERR("failed to build bson\n");
		goto out_err;
	}

	dbg_bson("insert doc: ", doc);

	memcpy(namespace, table->s, table->len);
	namespace[table->len] = '\0';

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   namespace);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_insert(col, MONGOC_INSERT_NONE, doc, NULL, &error)) {
	    LM_ERR("insert failed with:\nerror %d.%d: %s\n",
		       error.domain, error.code, error.message);
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB insert trans",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB insert trans",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	if (doc) {
		bson_destroy(doc);
	}
	mongoc_collection_destroy(col);
	return 0;

out_err:
	if (doc) {
		bson_destroy(doc);
	}
	if (col) mongoc_collection_destroy(col);
	return -1;
}

int mongo_db_delete_trans(cachedb_con *con, const str *table,
                          const db_key_t *_k, const db_op_t *_o,
                          const db_val_t *_v, const int _n)
{
	char namespace[MDB_MAX_NS_LEN];
	bson_t *doc;
	bson_error_t error;
	mongoc_collection_t *col = NULL;
	struct timeval start;

	doc = bson_new();
	if (kvo_to_bson(_k, _v, _o, _n, doc) != 0) {
		LM_ERR("failed to build bson\n");
		goto out_err;
	}

	memcpy(namespace, table->s, table->len);
	namespace[table->len] = '\0';

	dbg_bson("remove doc: ", doc);

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   namespace);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_remove(col, MONGOC_REMOVE_NONE, doc, NULL, &error)) {
	    LM_ERR("insert failed with:\nerror %d.%d: %s\n",
		       error.domain, error.code, error.message);
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB remove trans",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB remove trans",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	if (doc) {
		bson_destroy(doc);
	}
	mongoc_collection_destroy(col);
	return 0;

out_err:
	if (doc) {
		bson_destroy(doc);
	}
	if (col) mongoc_collection_destroy(col);
	return -1;
}

int mongo_db_update_trans(cachedb_con *con, const str *table,
                          const db_key_t *_k, const db_op_t *_o,
                          const db_val_t *_v, const db_key_t *_uk,
                          const db_val_t *_uv, const int _n, const int _un)
{
	char namespace[MDB_MAX_NS_LEN];
	bson_t *query, *update = NULL, child;
	bson_error_t error;
	mongoc_collection_t *col = NULL;
	struct timeval start;

	query = bson_new();
	if (kvo_to_bson(_k, _v, _o, _n, query) != 0) {
		LM_ERR("failed to build query bson\n");
		goto out_err;
	}

	update = bson_new();
	BSON_APPEND_DOCUMENT_BEGIN(update, "$set", &child);
	if (kvo_to_bson(_uk, _uv, NULL, _un, &child) != 0) {
		LM_ERR("failed to build update bson\n");
		goto out_err;
	}
	bson_append_document_end(update, &child);

	memcpy(namespace, table->s, table->len);
	namespace[table->len] = '\0';

	col = mongoc_client_get_collection(MONGO_CLIENT(con), MONGO_DB_STR(con),
	                                   namespace);

	dbg_bson("query doc: ", query);
	dbg_bson("update doc: ", update);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_update(col, MONGOC_UPDATE_MULTI_UPDATE,
	                              query, update, NULL, &error)) {
	    LM_ERR("insert failed with:\nerror %d.%d: %s\n",
		       error.domain, error.code, error.message);
		_stop_expire_timer(start, mongo_exec_threshold, "MongoDB update trans",
		            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);
		goto out_err;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB update trans",
	            NULL, 0, 0, cdb_slow_queries, cdb_total_queries);

	if (query) {
		bson_destroy(query);
	}
	if (update) {
		bson_destroy(update);
	}
	mongoc_collection_destroy(col);
	return 0;

out_err:
	if (query) {
		bson_destroy(query);
	}
	if (update) {
		bson_destroy(update);
	}
	if (col) mongoc_collection_destroy(col);
	return -1;
}

int mongo_truncate(cachedb_con *con)
{
	bson_t empty_doc = BSON_INITIALIZER;
	bson_error_t error;
	struct timeval start;
	int ret = 0;

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_remove(MONGO_COLLECTION(con),
	                         MONGOC_REMOVE_NONE, &empty_doc, NULL, &error)) {
		LM_ERR("failed to truncate collection '%s'!\n", MONGO_COL_STR(con));
		ret = -1;
	}
	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB truncate",
	            con->url.s, con->url.len, 0, cdb_slow_queries, cdb_total_queries);

	return ret;
}

int mongo_doc_to_dict(const bson_t *doc, cdb_dict_t *out_dict)
{
	bson_iter_t iter;
	bson_t subdoc;
	const bson_value_t *v;
	cdb_key_t key;
	cdb_pair_t *pair;
	union cdb_val_u *val;

	if (bson_iter_init(&iter, doc)) {
		while (bson_iter_next(&iter)) {
			init_str(&key.name, bson_iter_key(&iter));
			key.is_pk = !memcmp(key.name.s, "_id", 3);

			v = bson_iter_value(&iter);

			pair = cdb_mk_pair(&key, NULL);
			if (!pair) {
				LM_ERR("oom\n");
				goto out_err;
			}

			val = &pair->val.val;

			switch (v->value_type) {
			case BSON_TYPE_UTF8:
				pair->val.type = CDB_STR;
				val->st.len = v->value.v_utf8.len;
				val->st.s = pkg_malloc(val->st.len);
					if (!val->st.s) {
						LM_ERR("oom!\n");
					pkg_free(pair);
					goto out_err;
				}
				memcpy(val->st.s, v->value.v_utf8.str, val->st.len);
				break;
			case BSON_TYPE_INT32:
				pair->val.type = CDB_INT32;
				val->i32 = v->value.v_int32;
				break;
			case BSON_TYPE_INT64:
				pair->val.type = CDB_INT64;
				val->i64 = v->value.v_int64;
				break;
			case BSON_TYPE_DOCUMENT:
				pair->val.type = CDB_DICT;
				bson_init_static(&subdoc, v->value.v_doc.data,
				                 v->value.v_doc.data_len);
				INIT_LIST_HEAD(&val->dict);

				if (mongo_doc_to_dict(&subdoc, &val->dict) != 0) {
					LM_ERR("failed to parse subdoc\n");
					pkg_free(pair);
					goto out_err;
				}
				break;
			case BSON_TYPE_NULL:
				pair->val.type = CDB_NULL;
				break;
			case BSON_TYPE_TIMESTAMP:
				pair->val.type = CDB_INT32;
				val->i32 = v->value.v_timestamp.timestamp;
				break;
			case BSON_TYPE_BINARY:
				pair->val.type = CDB_STR;
				val->st.s = (char *)v->value.v_binary.data;
				val->st.len = v->value.v_binary.data_len;
				break;
			default:
				LM_ERR("unsupported MongoDB type %d!\n", v->value_type);
				pkg_free(pair);
				goto out_err;
			}

			cdb_dict_add(pair, out_dict);
		}
	}

	return 0;

out_err:
	cdb_free_entries(out_dict, osips_pkg_free);
	return -1;
}

cdb_row_t *mongo_mk_cdb_row(const bson_t *doc)
{
	cdb_row_t *row;

	row = pkg_malloc(sizeof *row);
	if (!row) {
		LM_ERR("oom\n");
		return NULL;
	}

	INIT_LIST_HEAD(&row->dict);

	if (mongo_doc_to_dict(doc, &row->dict) != 0) {
		LM_ERR("failed to convert bson to dict\n");
		goto out_err;
	}

	return row;

out_err:
	pkg_free(row);
	return NULL;
}

int mongo_cdb_filter_to_bson(const cdb_filter_t *filter, bson_t *cur)
{
	bson_t and_bson, *child, arr_doc, *subchild, _subchild;
	str text_op;
	str key;
	char prepend_and = filter ? !!filter->next : 0;
	int arr_idx = 0, arr_idx_len;
	char *arr_idx_str;

	if (!filter)
		return 0;

	if (prepend_and) {
		bson_append_array_begin(cur, "$and", 4, &and_bson);
		child = &and_bson;
	} else {
		child = cur;
	}

	for (; filter; filter = filter->next) {
		if (prepend_and) {
			arr_idx_str = int2str(arr_idx, &arr_idx_len);
			bson_append_document_begin(child, arr_idx_str, arr_idx_len, &arr_doc);
			arr_idx++;
			subchild = &arr_doc;
		} else {
			subchild = cur;
		}

		if (filter->key.is_pk)
			init_str(&key, "_id");
		else
			key = filter->key.name;

		/* TODO: clean this up when forcing MongoDB 3.0+, as only then
		 *       did they finally invent the $eq operator, doh!
		 */
		if (filter->op == CDB_OP_EQ) {
			if (filter->val.is_str)
				bson_append_utf8(subchild, key.s, key.len,
				                 filter->val.s.s, filter->val.s.len);
			else
				bson_append_int32(subchild, key.s, key.len,
				                  filter->val.i);
			goto next_filter;
		}

		bson_append_document_begin(subchild, key.s, key.len, &_subchild);

		switch (filter->op) {
		case CDB_OP_LT:
			init_str(&text_op, "$lt");
			break;
		case CDB_OP_LTE:
			init_str(&text_op, "$lte");
			break;
		case CDB_OP_GT:
			init_str(&text_op, "$gt");
			break;
		case CDB_OP_GTE:
			init_str(&text_op, "$gte");
			break;
		default:
			LM_BUG("unsupported operator: %d\n", filter->op);
			return -1;
		}

		if (filter->val.is_str)
			bson_append_utf8(&_subchild, text_op.s, text_op.len,
			                 filter->val.s.s, filter->val.s.len);
		else
			bson_append_int32(&_subchild, text_op.s, text_op.len,
			                  filter->val.i);

		bson_append_document_end(subchild, &_subchild);

	next_filter:
		if (prepend_and)
			bson_append_document_end(child, subchild);
	}

	if (prepend_and)
		bson_append_array_end(cur, child);

	return 0;
}

int mongo_con_query(cachedb_con *con, const cdb_filter_t *filter,
                       cdb_res_t *res)
{
	bson_t bson_filter = BSON_INITIALIZER;
	mongoc_cursor_t *cursor;
	cdb_row_t *row;
	const bson_t *doc;
	struct timeval start;

	LM_DBG("find all in %s\n", MONGO_NAMESPACE(con));

	cdb_res_init(res);

#if MONGOC_CHECK_VERSION(1, 5, 0)
	if (mongo_cdb_filter_to_bson(filter, &bson_filter) != 0) {
		LM_ERR("failed to build bson filter\n");
		return -1;
	}

	dbg_bson("using filter: ", &bson_filter);

	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find_with_opts(
	                MONGO_COLLECTION(con), &bson_filter, NULL, NULL);

	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB query rows",
	            con->url.s, con->url.len, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_next(cursor, &doc)) {
#else
	bson_t child;

	BSON_APPEND_DOCUMENT_BEGIN(&bson_filter, "$query", &child);
	if (mongo_cdb_filter_to_bson(filter, &child) != 0) {
		LM_ERR("failed to build bson filter\n");
		return -1;
	}
	bson_append_document_end(&bson_filter, &child);
	bson_destroy(&child);

	dbg_bson("using filter: ", &bson_filter);

	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find(MONGO_COLLECTION(con), MONGOC_QUERY_NONE,
	                                0, 0, 0, &bson_filter, NULL, NULL);

	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB query rows",
	            con->url.s, con->url.len, 0, cdb_slow_queries, cdb_total_queries);

	while (mongoc_cursor_more(cursor) && mongoc_cursor_next(cursor, &doc)) {
#endif
		row = mongo_mk_cdb_row(doc);
		if (!row) {
			LM_ERR("failed to create row\n");
			goto out_err;
		}

		res->count++;
		list_add_tail(&row->list, &res->rows);
	}

	LM_DBG("result count: %d\n", res->count);

	bson_destroy(&bson_filter);
	mongoc_cursor_destroy(cursor);
	return 0;

out_err:
	bson_destroy(&bson_filter);
	mongoc_cursor_destroy(cursor);
	cdb_free_rows(res);
	return -1;
}

int mongo_print_cdb_key(str *dest, const cdb_key_t *key, const str *subkey)
{
	static str static_pkg_buf;
	str main_key;
	int total_len;

	if (key->is_pk)
		init_str(&main_key, "_id");
	else
		main_key = key->name;

	if (ZSTR(*subkey)) {
		*dest = main_key;
		return 0;
	}

	total_len = main_key.len + 1 + subkey->len;

	if (pkg_str_extend(&static_pkg_buf, total_len + 1)) {
		LM_ERR("oom\n");
		return -1;
	}

	sprintf(static_pkg_buf.s, "%.*s.%.*s", main_key.len, main_key.s,
	        subkey->len, subkey->s);

	dest->s = static_pkg_buf.s;
	dest->len = total_len;

	return 0;
}

int mongo_cdb_dict_to_bson(const cdb_dict_t *dict, bson_t *out_doc)
{
	struct list_head *_;
	bson_t bson_val = BSON_INITIALIZER;
	cdb_pair_t *pair;
	str key;

	list_for_each (_, dict) {
		pair = list_entry(_, cdb_pair_t, list);
		key = pair->key.name;

		switch (pair->val.type) {
		case CDB_NULL:
			if (!bson_append_null(out_doc, key.s, key.len)) {
				LM_ERR("failed to append NULL doc\n");
				goto out_err;
			}
			break;
		case CDB_INT32:
			if (!bson_append_int32(out_doc, key.s, key.len,
			                       pair->val.val.i32)) {
				LM_ERR("failed to append %.*s: %d\n", key.len,
				       key.s, pair->val.val.i32);
				goto out_err;
			}
			break;
		case CDB_INT64:
			if (!bson_append_int64(out_doc, key.s, key.len,
			                       pair->val.val.i64)) {
				LM_ERR("failed to append %.*s: %lld\n", key.len,
				       key.s, (long long)pair->val.val.i64);
				goto out_err;
			}
			break;
		case CDB_STR:
			if (!bson_append_utf8(out_doc, key.s, key.len,
			                      pair->val.val.st.s, pair->val.val.st.len)) {
				LM_ERR("failed to append %.*s: %.*s\n", key.len,
				       key.s, pair->val.val.st.len, pair->val.val.st.s);
				goto out_err;
			}
			break;
		case CDB_DICT:
			if (mongo_cdb_dict_to_bson(&pair->val.val.dict, &bson_val) != 0) {
				LM_ERR("failed to convert dict to bson\n");
				goto out_err;
			}

			if (!bson_append_document(out_doc, key.s, key.len, &bson_val)) {
				LM_ERR("failed to append doc\n");
				goto out_err;
			}

			bson_reinit(&bson_val);
			break;
		default:
			LM_ERR("unsupported type %d for key %.*s\n", pair->val.type,
			       key.len, key.s);
			goto out_err;
		}
	}

	bson_destroy(&bson_val);
	return 0;
out_err:
	bson_destroy(&bson_val);
	return -1;
}

int mongo_con_update(cachedb_con *con, const cdb_filter_t *row_filter,
                     const cdb_dict_t *pairs)
{
	struct list_head *_;
	bson_t filter = BSON_INITIALIZER, update = BSON_INITIALIZER;
	bson_t bson_val = BSON_INITIALIZER;
	bson_t set_keys = BSON_INITIALIZER, unset_keys = BSON_INITIALIZER;
	bson_error_t error;
	struct timeval start;
	int ret = 0;
	char has_set = 0, has_unset = 0;
	cdb_pair_t *pair;
	str key;

	if (mongo_cdb_filter_to_bson(row_filter, &filter) != 0) {
		LM_ERR("failed to build bson filter\n");
		return -1;
	}

	list_for_each (_, pairs) {
		pair = list_entry(_, cdb_pair_t, list);

		/* we only support one level of subkey indirection --
		 * any subkeys present at deeper nesting levels will be ignored */
		if (mongo_print_cdb_key(&key, &pair->key, &pair->subkey) != 0) {
			LM_ERR("oom\n");
			ret = -1;
			goto out;
		}

		if (pair->unset) {
			if (!bson_append_null(&unset_keys, key.s, key.len)) {
				LM_ERR("failed to append NULL doc\n");
				ret = -1;
				goto out;
			}

			has_unset = 1;
			continue;
		}

		switch (pair->val.type) {
		case CDB_NULL:
			if (!bson_append_null(&set_keys, key.s, key.len)) {
				LM_ERR("failed to append NULL doc\n");
				ret = -1;
				goto out;
			}
			break;
		case CDB_INT32:
			if (!bson_append_int32(&set_keys, key.s, key.len,
			                       pair->val.val.i32)) {
				LM_ERR("failed to append i32 val: %d\n", pair->val.val.i32);
				ret = -1;
				goto out;
			}
			break;
		case CDB_INT64:
			if (!bson_append_int64(&set_keys, key.s, key.len,
			                       pair->val.val.i64)) {
				LM_ERR("failed to append i64 val: %lld\n", (long long)pair->val.val.i64);
				ret = -1;
				goto out;
			}
			break;
		case CDB_STR:
			if (!bson_append_utf8(&set_keys, key.s, key.len,
			                      pair->val.val.st.s, pair->val.val.st.len)) {
				LM_ERR("failed to append str val: %.*s\n",
				       pair->val.val.st.len, pair->val.val.st.s);
				ret = -1;
				goto out;
			}
			break;
		case CDB_DICT:
			if (mongo_cdb_dict_to_bson(&pair->val.val.dict, &bson_val) != 0) {
				LM_ERR("failed to convert dict to bson\n");
				ret = -1;
				goto out;
			}

			if (!bson_append_document(&set_keys, key.s, key.len, &bson_val)) {
				LM_ERR("failed to append key %.*s to doc\n", key.len, key.s);
				ret = -1;
				goto out;
			}
			bson_reinit(&bson_val);
			break;
		default:
			LM_ERR("unsupported val type: %d\n", pair->val.type);
			ret = -1;
			goto out;
		}

		has_set = 1;
	}

	dbg_bson("filter: ", &filter);
	dbg_bson("set: ", &set_keys);
	dbg_bson("unset: ", &unset_keys);

	if (!has_set && !has_unset) {
		LM_ERR("redundant update query\n");
		ret = -1;
		goto out;
	}

	if (has_set && !bson_append_document(&update, "$set", 4, &set_keys)) {
		LM_ERR("failed to append $set key\n");
		ret = -1;
		goto out;
	}

	if (has_unset && !bson_append_document(&update, "$unset", 6,
	                                       &unset_keys)) {
		LM_ERR("failed to append $set key\n");
		ret = -1;
		goto out;
	}

	dbg_bson("update: ", &update);

	start_expire_timer(start, mongo_exec_threshold);
	if (!mongoc_collection_update(MONGO_COLLECTION(con),
	                           MONGOC_UPDATE_UPSERT|MONGOC_UPDATE_MULTI_UPDATE,
	                           &filter, &update, NULL, &error)) {
		dump_mongo_err(&error);
		ret = -1;
	}

	_stop_expire_timer(start, mongo_exec_threshold, "MongoDB update",
	            con->url.s, con->url.len, 0, cdb_slow_queries, cdb_total_queries);

out:
	bson_destroy(&bson_val);
	bson_destroy(&filter);
	bson_destroy(&set_keys);
	bson_destroy(&unset_keys);
	bson_destroy(&update);
	return ret;
}
