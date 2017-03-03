/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 *
 * history:
 * ---------
 *  2011-09-xx  created (vlad-paiu)
 */

#include "../../dprint.h"
#include "cachedb_mongodb_dbase.h"
#include "cachedb_mongodb_json.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../cachedb/cachedb.h"

#include <string.h>

//extern mongo_write_concern mwc;
extern str mongo_write_concern_str;
extern str mongo_write_concern_b;
extern int mongo_slave_ok;
extern int mongo_exec_threshold;

extern int compat_mode_30;
extern int compat_mode_24;

#define HEX_OID_SIZE 25
char *hex_oid_id = NULL;

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
	int len;

	len =
	      strlen(id->scheme) + 3 +
	      (id->username ? strlen(id->username) : 0) + 1 +
	      (id->password ? strlen(id->password) : 0) + 1 +
	      strlen(id->host) + 1 +
		  5 + 1 + /* port */
	      strlen(id->database) + 1 +
		  1;

	ret = pkg_malloc(len);
	if (!ret) {
		LM_ERR("oom\n");
		return NULL;
	}

	p = memchr(id->database, '.', strlen(id->database));

	if (id->username && id->password) {
		if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
			sprintf(ret, "mongodb://%s:%s@%s/%s", id->username, id->password,
			        id->host, id->database);
		} else {
			sprintf(ret, "mongodb://%s:%s@%s:%d/%s", id->username, id->password,
			        id->host, id->port, id->database);
		}
	} else {
		if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
			sprintf(ret, "mongodb://%s/%.*s", id->host,
			        (int)(p ? p - id->database : strlen(id->database)), id->database);
		} else {
			sprintf(ret, "mongodb://%s:%d/%.*s", id->host, id->port,
			        (int)(p ? p - id->database : strlen(id->database)), id->database);
		}
	}

	return ret;
}

char osips_appname[MONGOC_HANDSHAKE_APPNAME_MAX];
mongo_con* mongo_new_connection(struct cachedb_id* id)
{
	char *p, *conn_str;
	mongo_con *con;

	snprintf(osips_appname, MONGOC_HANDSHAKE_APPNAME_MAX, "opensips-%d", my_pid());

	LM_DBG("MongoDB conn for [%s]: %s:%s %s:%s |%s|:%u\n", osips_appname,
	       id->scheme, id->group_name, id->username, id->password, id->host, id->port);

	conn_str = build_mongodb_connect_string(id);

	LM_DBG("cstr: %s\n", conn_str);

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
		LM_ERR("failed to connect to Mongo (%s)\n", conn_str);
		return NULL;
	}

	p = memchr(id->database, '.', strlen(id->database));
	if (!p) {
		LM_ERR("malformed Mongo database part in %s\n", id->database);
		return NULL;
	}

	*p = '\0';
	con->db = pkg_strdup(id->database);
	con->col = pkg_strdup(p + 1);
	if (!con->db || !con->col) {
		LM_ERR("oom\n");
		return NULL;
	}

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
	bson_t *query;
	mongoc_cursor_t *cursor;
	const bson_t *doc;
	bson_iter_t iter;
	const bson_value_t *value;
	struct timeval start;
	unsigned long ival;
	char *p;

	LM_DBG("find %.*s in %s\n", attr->len, attr->s,
	       MONGO_NAMESPACE(con));

	query = bson_new();
	bson_append_utf8(query, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	start_expire_timer(start, mongo_exec_threshold);
	cursor = mongoc_collection_find_with_opts(
	                MONGO_COLLECTION(con), query, NULL, NULL);
	stop_expire_timer(start, mongo_exec_threshold, "MongoDB find",
	                  attr->s, attr->len, 0);

	while (mongoc_cursor_next(cursor, &doc)) {
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
				goto out;
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
			goto out;
		}
	}

	LM_DBG("key not found: %.*s\n", attr->len, attr->s);

out:
	bson_destroy(query);
	mongoc_cursor_destroy(cursor);
	return 0;

out_err:
	bson_destroy(query);
	mongoc_cursor_destroy(cursor);
	memset(val, 0, sizeof *val);
	return -1;
}

int mongo_con_set(cachedb_con *con, str *attr, str *val, int expires)
{
	bson_t *query, *update;
	bson_t child;
	bson_error_t error;
	int ret = 0;

	query = bson_new();
	bson_append_utf8(query, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	update = bson_new();
	BSON_APPEND_DOCUMENT_BEGIN(update, "$set", &child);
	bson_append_utf8(&child, "opensips", 8, val->s, val->len);
	bson_append_document_end(update, &child);

	if (!mongoc_collection_update(MONGO_COLLECTION(con), MONGOC_UPDATE_UPSERT,
	                              query, update, NULL, &error)) {
		LM_ERR("failed to store %.*s=%.*s\n",
		       attr->len, attr->s, val->len, val->s);
		ret = -1;
	}

	bson_destroy(query);
	bson_destroy(update);

	return ret;
}

int mongo_con_remove(cachedb_con *con, str *attr)
{
	bson_t *doc;
	bson_error_t error;
	int ret = 0;

	doc = bson_new();
	bson_append_utf8(doc, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	if (!mongoc_collection_remove(MONGO_COLLECTION(con),
	                         MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error)) {
		LM_ERR("failed to remove key '%.*s'\n", attr->len, attr->s);
		ret = -1;
	}

	bson_destroy(doc);

	return ret;
}

void dbg_bson_print_raw( const char *data , int depth )
{
#if 0
	bson_iterator i;
	const char *key;
	int temp;
	bson_timestamp_t ts;
	char oidhex[HEX_OID_SIZE];
	bson_t scope;
	bson_iterator_from_buffer( &i, data );

	while ( bson_iterator_next( &i ) ) {
		bson_type t = bson_iterator_type( &i );
		if ( t == 0 )
			break;
		key = bson_iterator_key( &i );

		for ( temp=0; temp<=depth; temp++ )
			LM_INFO( "\t" );
			LM_INFO( "key [%s] : type [%d] \t " , key , t );
			switch ( t ) {
				case BSON_DOUBLE:
					LM_INFO( "double ---%f---" , bson_iterator_double( &i ) );
					break;
				case BSON_STRING:
					LM_INFO( "string ---%s---" , bson_iterator_string( &i ) );
					break;
				case BSON_SYMBOL:
					LM_INFO( "SYMBOL: ---%s---" , bson_iterator_string( &i ) );
					break;
				case BSON_OID:
					bson_oid_to_string( bson_iterator_oid( &i ), oidhex );
					LM_INFO( "oid ---%s---" , oidhex );
					break;
				case BSON_BOOL:
					LM_INFO( "bool ---%s---" , bson_iterator_bool( &i ) ? "true" : "false" );
					break;
				case BSON_DATE:
					LM_INFO( "date ---%ld---" , ( long int )bson_iterator_date( &i ) );
					break;
				case BSON_BINDATA:
					LM_INFO( "BSON_BINDATA" );
					break;
				case BSON_UNDEFINED:
					LM_INFO( "BSON_UNDEFINED" );
					break;
				case BSON_NULL:
					LM_INFO( "BSON_NULL" );
					break;
				case BSON_REGEX:
					LM_INFO( "BSON_REGEX: ---%s---", bson_iterator_regex( &i ) );
					break;
				case BSON_CODE:
					LM_INFO( "BSON_CODE: ---%s---", bson_iterator_code( &i ) );
					break;
				case BSON_CODEWSCOPE:
					LM_INFO( "BSON_CODE_W_SCOPE: %s", bson_iterator_code( &i ) );
					bson_init( &scope );
					bson_iterator_code_scope( &i, &scope );
					LM_INFO( "\n\t SCOPE: " );
					bson_print( &scope );
					break;
				case BSON_INT:
					LM_INFO( "int ---%d---" , bson_iterator_int( &i ) );
					break;
				case BSON_LONG:
					LM_INFO( "long ---%ld---" , bson_iterator_long( &i ) );
					break;
				case BSON_TIMESTAMP:
					ts = bson_iterator_timestamp( &i );
					LM_INFO( "i: %d, t: %d", ts.i, ts.t );
					break;
				case BSON_OBJECT:
				case BSON_ARRAY:
					LM_INFO( "--- array ---\n" );
					dbg_bson_print_raw( bson_iterator_value( &i ) , depth + 1 );
					break;
				default:
					bson_errprintf( "can't print type : %d\n" , t );
			}
		LM_INFO( "\n" );
	}
#endif
}

void dbg_print_bson(bson_t *b)
{
	//dbg_bson_print_raw(b->data,0);
}

int mongo_raw_find(cachedb_con *con, bson_t *raw_query, bson_iter_t *ns,
                   cdb_raw_entry ***reply, int expected_kv_no, int *reply_no)
{
	struct json_object *obj = NULL;
	mongoc_collection_t *col;
	bson_iter_t iter;
	bson_t _query, *query = NULL, *opts = NULL, proj;
	mongoc_cursor_t *cursor;
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

	if (bson_iter_init_find(&iter, raw_query, "filter") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter)) {
		v = bson_iter_value(&iter);
		bson_init_static(&_query, v->value.v_doc.data, v->value.v_doc.data_len);
		query = &_query;
	} else {
		query = bson_new();
	}

	if (bson_iter_init_find(&iter, raw_query, "projection") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter)) {
		opts = bson_new();
		v = bson_iter_value(&iter);
		bson_init_static(&proj, v->value.v_doc.data, v->value.v_doc.data_len);
		bson_append_document(opts, "projection", 10, &proj);
	}

	cursor = mongoc_collection_find_with_opts(col, query, opts, NULL);

	*reply = NULL;
	while (mongoc_cursor_next(cursor, &doc)) {
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

#if 0
	bson_iterator i;
	mongo_cursor *m_cursor;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson_t op_b,fields_b,err_b;
	int have_query=0,have_fields=0,j,ret;

	if (!reply || expected_kv_no != 1) {
		LM_ERR("A find op should expect document results\n");
		return -1;
	}

	bson_iterator_from_buffer( &i, raw_query->data );
	while ( bson_iterator_next( &i ) ) {
		bson_type t = bson_iterator_type( &i );
		if ( t == 0 )
			break;

		key = bson_iterator_key( &i );
		switch ( t ) {
			case BSON_STRING:
				if (strcmp(key,"op") == 0) {
					continue;
				}
				else if (strcmp(key,"ns") == 0) {
					ns = bson_iterator_string(&i);
					LM_DBG("found ns [%s] \n",ns);
				}
				break;
			case BSON_OBJECT:
			case BSON_ARRAY:
				if (strcmp(key,"query") == 0) {
					memset(&op_b,0,sizeof(bson_t));
					bson_init_finished_data(&op_b,(char *)bson_iterator_value(&i));
					have_query=1;
				} else if (strcmp(key,"fields") == 0) {
					memset(&fields_b,0,sizeof(bson_t));
					bson_init_finished_data(&fields_b,(char *)bson_iterator_value(&i));
					have_fields=1;
				}
				break;
			default:
				LM_DBG("Unusable type %d - ignoring \n",t);
		}
	}

	if (have_query == 0) {
		LM_ERR("Cannot proceed. Don't have the actual find query \n");
		return -1;
	}

	for (j=0;j<2;j++) {
		m_cursor = mongo_find(conn,ns?ns:MONGO_NAMESPACE(connection),
				&op_b,have_fields?&fields_b:0,0,0,mongo_slave_ok);
		if (m_cursor == NULL) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			ret = mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
			if (ret == MONGO_OK) {
				LM_ERR("We had error - can't tell what it was - we're really bogus - probably mongos down\n");
				return -1;
			}
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&i,&err_b);
			while( bson_iterator_next(&i)) {
				LM_ERR("Fetched ERR key [%s]. Val = ",bson_iterator_key(&i));
				switch( bson_iterator_type( &i ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&i));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&i));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&i));
						break;
					default:
						/* TODO - support more types here */
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&i));
						break;
				}
			}
			return -1;
		}
		break;
	}

	ret = mongo_cursor_to_json(m_cursor,reply,expected_kv_no,reply_no);

	mongo_cursor_destroy(m_cursor);
	return ret;
#endif
	return 0;
}

int mongo_raw_count(cachedb_con *connection,bson_t *raw_query,cdb_raw_entry ***reply,int expected_kv_no,int *reply_no)
{
#if 0
	bson_iterator i;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson_t op_b,err_b;
	int have_query=0,j,result=0,ns_len=0;
	char db[32],coll[32],*p;

	if (!reply || expected_kv_no != 1) {
		LM_ERR("A count op should expect a single result\n");
		return -1;
	}

	bson_iterator_from_buffer( &i, raw_query->data );
	while ( bson_iterator_next( &i ) ) {
		bson_type t = bson_iterator_type( &i );
		if ( t == 0 )
			break;

		key = bson_iterator_key( &i );
		switch ( t ) {
			case BSON_STRING:
				if (strcmp(key,"op") == 0) {
					continue;
				}
				else if (strcmp(key,"ns") == 0) {
					ns = bson_iterator_string(&i);
					LM_DBG("found ns [%s] \n",ns);
					ns_len = strlen(ns);
					p = memchr(ns,'.',ns_len);
					if (!p) {
						LM_ERR("Invalid provided namespace \n");
						return -1;
					}
					memcpy(db,ns,p-ns);
					db[p-ns]=0;
					memcpy(coll,p+1,ns+ns_len-p-1);
					coll[ns+ns_len-p-1]=0;
				}
				break;
			case BSON_OBJECT:
			case BSON_ARRAY:
				if (strcmp(key,"query") == 0) {
					memset(&op_b,0,sizeof(bson_t));
					bson_init_finished_data(&op_b,(char *)bson_iterator_value(&i));
					have_query=1;
				}
				break;
			default:
				LM_DBG("Unusable type %d - ignoring \n",t);
		}
	}

	if (have_query == 0) {
		LM_ERR("Cannot proceed. Don't have the actual count query \n");
		return -1;
	}

	for (j=0;j<2;j++) {
		result = (int)mongo_count(conn,ns?db:MONGO_DATABASE(connection),
				ns?coll:MONGO_COLLECTION(connection),&op_b);
		if (result == MONGO_ERROR) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&i,&err_b);
			while( bson_iterator_next(&i)) {
				LM_ERR("Fetched ERR key [%s]. Val = ",bson_iterator_key(&i));
				switch( bson_iterator_type( &i ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&i));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&i));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&i));
						break;
					default:
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&i));
						break;
				}
			}
			return -1;
		}
		break;
	}

	LM_DBG("The result is [%d]\n",result);

	*reply = pkg_malloc(1 * sizeof(cdb_raw_entry *));
	if (*reply == NULL) {
		LM_ERR("No more pkg mem\n");
		return -1;
	}

	**reply = pkg_malloc(1 * sizeof(cdb_raw_entry));
	if (**reply == NULL) {
		LM_ERR("No more pkg mem\n");
		pkg_free(*reply);
		return -1;
	}

	(**reply)->type = CDB_INT;
	(**reply)->val.n = result;

	*reply_no = 1;
	return 0;
#endif
	return 0;
}

int mongo_raw_update(cachedb_con *con, bson_t *raw_query, bson_iter_t *ns)
{
	mongoc_collection_t *col;
	mongoc_bulk_operation_t *bulk = NULL;
	bson_iter_t iter, uiter, sub_iter;
	bson_error_t error;
	bson_t query, update, reply;
	const bson_value_t *v;
	int ret, count = 0;
	char *str;

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

	bulk = mongoc_collection_create_bulk_operation(col, false, NULL);
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

	ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	if (!ret) {
		LM_ERR("failed bulk update\nerror: %d.%d: %s\n",
		       error.domain, error.code, error.message);
		goto out_err;
	}

	if (is_printable(L_DBG)) {
		str = bson_as_json(&reply, NULL);
		LM_DBG("reply received: %s\n", str);
		bson_free(str);
	}

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
	mongoc_collection_t *col;
	mongoc_bulk_operation_t *bulk = NULL;
	bson_iter_t iter, sub_iter;
	bson_error_t error;
	bson_t doc, reply;
	const bson_value_t *v;
	int ret, count = 0;
	char *str;

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

	bulk = mongoc_collection_create_bulk_operation(col, false, NULL);
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

	ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	if (!ret) {
		LM_ERR("failed bulk insert\nerror: %d.%d: %s\n",
		       error.domain, error.code, error.message);
		goto out_err;
	}

	if (is_printable(L_DBG)) {
		str = bson_as_json(&reply, NULL);
		LM_DBG("reply received: %s\n", str);
		bson_free(str);
	}

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
	mongoc_collection_t *col;
	mongoc_bulk_operation_t *bulk = NULL;
	bson_iter_t iter, qiter, sub_iter;
	bson_error_t error;
	bson_t doc, reply;
	const bson_value_t *v;
	int ret, count = 0;
	char *str;

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

	bulk = mongoc_collection_create_bulk_operation(col, false, NULL);
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

	ret = mongoc_bulk_operation_execute(bulk, &reply, &error);
	if (!ret) {
		LM_ERR("failed bulk insert\nerror: %d.%d: %s\n",
		       error.domain, error.code, error.message);
		goto out_err;
	}

	if (is_printable(L_DBG)) {
		str = bson_as_json(&reply, NULL);
		LM_DBG("reply received: %s\n", str);
		bson_free(str);
	}

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

#if 0
	bson_iterator i;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson_t op_b,err_b;
	int have_query=0,j,ret;

	bson_iterator_from_buffer( &i, raw_query->data );

	while ( bson_iterator_next( &i ) ) {
		bson_type t = bson_iterator_type( &i );
		if ( t == 0 )
			break;

		key = bson_iterator_key( &i );
		switch ( t ) {
			case BSON_STRING:
				if (strcmp(key,"op") == 0) {
					continue;
				}
				else if (strcmp(key,"ns") == 0) {
					ns = bson_iterator_string(&i);
					LM_DBG("found ns [%s] \n",ns);
				}
				break;
			case BSON_OBJECT:
			case BSON_ARRAY:
				if (strcmp(key,"query") == 0) {
					memset(&op_b,0,sizeof(bson_t));
					bson_init_finished_data(&op_b,(char *)bson_iterator_value(&i));
					have_query=1;
				}
				break;
			default:
				LM_DBG("Unusable type %d - ignoring \n",t);
		}
	}

	if (have_query == 0) {
		LM_ERR("Cannot proceed. Don't have the actual remove query \n");
		return -1;
	}

	for (j=0;j<2;j++) {
		ret = mongo_remove(conn,ns?ns:MONGO_NAMESPACE(connection),
				&op_b,0);
		if (ret == MONGO_ERROR) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&i,&err_b);
			while( bson_iterator_next(&i)) {
				LM_ERR("Fetched ERR key [%s]. Val = ",bson_iterator_key(&i));
				switch( bson_iterator_type( &i ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&i));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&i));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&i));
						break;
					default:
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&i));
						break;
				}

				return -1;
			}
		}
		break;
	}

	return 0;
#endif
	return 0;
}

static char *raw_query_buf;
static int raw_query_buf_len;

int mongo_con_raw_query(cachedb_con *con, str *qstr, cdb_raw_entry ***reply,
                        int expected_kv_no, int *reply_no)
{
	struct json_object *obj = NULL;
	bson_t doc, rpl;
	bson_iter_t iter;
	bson_error_t error;
	struct timeval start;
	int ret = 0;
	const char *p;
	int csz = 0, i, len;

	LM_DBG("Get operation on namespace %s\n", MONGO_NAMESPACE(con));
	start_expire_timer(start,mongo_exec_threshold);

	if (qstr->len > raw_query_buf_len) {
		raw_query_buf = pkg_realloc(raw_query_buf, qstr->len + 1);
		if (!raw_query_buf) {
			LM_ERR("oom!\n");
			return -1;
		}

		memcpy(raw_query_buf, qstr->s, qstr->len);
		raw_query_buf[qstr->len] = '\0';

		raw_query_buf_len = qstr->len;
	} else {
		memcpy(raw_query_buf, qstr->s, qstr->len);
		raw_query_buf[qstr->len] = '\0';
	}

	ret = json_to_bson(raw_query_buf, &doc);
	if (ret < 0) {
		LM_ERR("Failed to convert [%.*s] to BSON\n", qstr->len, qstr->s);
		ret = -1;
		goto out;
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

	if (!mongoc_collection_command_simple(MONGO_COLLECTION(con), &doc,
	                              NULL, &rpl, &error)) {
		LM_ERR("raw query:\n'%.*s'\nfailed with: %d.%d: %s\n", qstr->len, qstr->s,
		       error.domain, error.code, error.message);
		ret = -1;
		goto out_err;
	}

	/* start with a single returned document */
	*reply = pkg_malloc(1 * sizeof **reply);
	if (!*reply) {
		LM_ERR("no more PKG mem\n");
		return -1;
	}

	/* expected_kv_no is always 1 for MongoDB */
	**reply = pkg_malloc(expected_kv_no * sizeof ***reply);
	if (!**reply) {
		LM_ERR("No more pkg mem\n");
		pkg_free(*reply);
		return -1;
	}

	if (bson_iter_init(&iter, &rpl)) {
		while (bson_iter_next(&iter)) {
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
				ret = -1;
				goto out_err;
			}

			LM_DBG("got JSON: %s\n", p);

			len = strlen(p);
			(*reply)[csz][0].val.s.s = pkg_malloc(len);
			if (!(*reply)[csz][0].val.s.s ) {
				LM_ERR("No more pkg \n");
				ret = -1;
				goto out_err;
			}

			memcpy((*reply)[csz][0].val.s.s,p,len);
			(*reply)[csz][0].val.s.len = len;
			(*reply)[csz][0].type = CDB_STR;

			json_object_put(obj);

			csz++;
		}
	} else {
		LM_ERR("failed to init!!!\n");
		ret = -1;
		goto out_err;
	}

out:
	*reply_no = csz;
	if (csz == 0)
		return -2;

	return 1;

out_err:
	if (obj)
		json_object_put(obj);

	if (*reply) {
		for (i = 0; i < csz; i++) {
			pkg_free((*reply)[i][0].val.s.s);
			pkg_free((*reply)[i]);
		}

		pkg_free(*reply);
		*reply = NULL;
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

	if (!mongoc_collection_command_simple(MONGO_COLLECTION(con), cmd,
	                              NULL, &reply, &error)) {
		LM_ERR("failed to %s: %.*s += %d\n", val > 0 ? "add" : "sub",
		       attr->len, attr->s, val);
		ret = -1;
		goto out;
	}

	if (bson_iter_init_find(&iter, &reply, "value") &&
	    BSON_ITER_HOLDS_DOCUMENT(&iter) &&
	    bson_iter_recurse(&iter, &sub_iter)) {

		if (bson_iter_find(&sub_iter, "opensips_counter")) {
			*new_val = bson_iter_value(&sub_iter)->value.v_int32;
		}
	}

out:
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
	int ret = 0;

	query = bson_new();
	bson_append_utf8(query, MDB_PK, MDB_PKLEN, attr->s, attr->len);

	cursor = mongoc_collection_find_with_opts(
	                MONGO_COLLECTION(con), query, NULL, NULL);

	while (mongoc_cursor_next(cursor, &doc)) {
		if (bson_iter_init_find(&iter, doc, "opensips_counter")) {
			value = bson_iter_value(&iter);
			switch (value->value_type) {
			case BSON_TYPE_INT32:
				*val = value->value.v_int32;
				break;
			default:
				LM_ERR("unsupported type %d for key %.*s!\n", attr->len,
				       value->value_type, attr->s);
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

#if 0
#define MONGO_DB_KEY_TRANS(key,val,index,op,query)\
	do { \
		if (VAL_NULL(val+index) == 0) { \
			memcpy(key_buff,key[index]->s,key[index]->len); \
			key_buff[key[index]->len]=0; \
			if (op != NULL && strcmp(op[index],OP_EQ)) { \
				bson_append_start_object(&query,key_buff);\
				if (strcmp(op[index],OP_LT) == 0) \
					memcpy(key_buff,"$lt",4); \
				else if (strcmp(op[index],OP_GT) == 0) \
					memcpy(key_buff,"$gt",4); \
				else if (strcmp(op[index],OP_LEQ) == 0) \
					memcpy(key_buff,"$lte",5); \
				else if (strcmp(op[index],OP_GEQ) == 0) \
					memcpy(key_buff,"$gte",5); \
				else if (strcmp(op[index],OP_NEQ) == 0) \
					memcpy(key_buff,"$ne",4); \
			} \
			switch VAL_TYPE(val+index) { \
				case DB_INT: \
					bson_append_int(&query,key_buff,VAL_INT(val+index)); \
					break; \
				case DB_STRING: \
					if (appendOID && key[index]->len == 3 && strncmp("_id", key[index]->s,key[index]->len) == 0) { \
						LM_DBG("we got it [%.*s]\n", key[index]->len, key[index]->s); \
						bson_oid_from_string(&_id, VAL_STRING(val+index)); \
						bson_append_oid(&query,key_buff,&_id); \
						appendOID = 0; \
					} else { \
						bson_append_string(&query,key_buff,VAL_STRING(val+index)); \
					} \
					break; \
				case DB_STR: \
					if (appendOID && key[index]->len == 3 && strncmp("_id", key[index]->s,key[index]->len) == 0) { \
						p = VAL_STR(val+index).s + VAL_STR(val+index).len; \
						_old_char = *p; \
						*p = '\0'; \
						bson_oid_from_string(&_id, VAL_STR(val+index).s); \
						*p = _old_char; \
						bson_append_oid(&query,key_buff,&_id); \
						appendOID = 0; \
					} else { \
						bson_append_string_n(&query,key_buff,VAL_STR(val+index).s, \
							VAL_STR(val+index).len); \
					} \
					break; \
				case DB_BLOB: \
					bson_append_string_n(&query,key_buff,VAL_BLOB(val+index).s, \
							VAL_BLOB(val+index).len); \
					break; \
				case DB_DOUBLE: \
					bson_append_double(&query,key_buff,VAL_DOUBLE(val+index)); \
					break; \
				case DB_BIGINT: \
					bson_append_long(&query,key_buff,VAL_BIGINT(val+index)); \
					break; \
				case DB_DATETIME: \
					bson_append_time_t(&query,key_buff,VAL_TIME(val+index)); \
					break; \
				case DB_BITMAP: \
					bson_append_int(&query,key_buff,VAL_BITMAP(val+index)); \
					break; \
			} \
			if (op != NULL && strcmp(op[index],OP_EQ)) { \
				bson_append_finish_object(&query); \
			} \
		} \
	} while (0)
#endif

int mongo_db_query_trans(cachedb_con *con,const str *table,const db_key_t* _k, const db_op_t* _op,const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,const db_key_t _o, db_res_t** _r)
{
#if 0
	char key_buff[32],namespace_buff[64],*p;
	bson_t query;
	bson_t fields;
	bson_t err_b;
	int i,j,row_no;
	mongo *conn = &MONGO_CDB_CON(con);
	mongo_cursor *m_cursor;
	bson_iterator it;
	char hex_oid[HEX_OID_SIZE];
	db_row_t *current;
	db_val_t *cur_val;
	static str dummy_string = {"", 0};
	struct timeval start;
	char _old_char;
	bson_oid_t _id;
	int appendOID = 1;

	start_expire_timer(start,mongo_exec_threshold);

	if (!_c) {
		LM_ERR("The module does not support 'select *' SQL queries \n");
		return -1;
	}

	bson_init(&query);
	if (_n) {
		bson_append_start_object(&query, "$query");
		for (i=0;i<_n;i++) {
			MONGO_DB_KEY_TRANS(_k,_v,i,_op,query);
		}
		bson_append_finish_object(&query);
	}

	if (_o) {
		if (!_n) {
			bson_append_start_object(&query, "$query");
			bson_append_finish_object(&query);
		}
		memcpy(key_buff,_o->s,_o->len);
		key_buff[_o->len]=0;
		bson_append_start_object(&query, "$orderby");
		bson_append_int(&query,key_buff,1);
		bson_append_finish_object(&query);
	}

	bson_finish(&query);

	bson_init(&fields);
	for (i=0;i<_nc;i++) {
		 memcpy(key_buff,_c[i]->s,_c[i]->len);
		 key_buff[_c[i]->len]=0;
		 bson_append_bool(&fields,key_buff,1);
	}

	bson_finish(&fields);

	p=namespace_buff;
	i = strlen(MONGO_DATABASE(con));
	memcpy(p,MONGO_DATABASE(con),i);
	p +=i;
	*p++ = '.';
	memcpy(p,table->s,table->len);
	p+= table->len;
	*p = 0;

	LM_DBG("Running raw mongo query on table %s\n",namespace_buff);

	for (i=0;i<2;i++) {
		m_cursor = mongo_find(conn,namespace_buff,
				&query,&fields,0,0,mongo_slave_ok);
		if (m_cursor == NULL) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(con),&err_b);
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&it,&err_b);
			while( bson_iterator_next(&it)) {
				LM_DBG("Fetched key %s\n",bson_iterator_key(&it));
				switch( bson_iterator_type( &it ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&it));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&it));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&it));
						break;
					case BSON_OID:
						bson_oid_to_string(bson_iterator_oid(&it),hex_oid);
						LM_DBG("(oid) \"%s\"\n",hex_oid);
						break;
					default:
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
						break;

				}
			}
			goto error;
		}
		break;
	}

	MONGO_CDB_CURSOR(con) = m_cursor;

	*_r = db_new_result();
	if (*_r == NULL) {
		LM_ERR("Failed to init new result \n");
		goto error;
	}

	RES_COL_N(*_r) = _nc;

	row_no = m_cursor->reply->fields.num;
	LM_DBG("We have %d rows\n",row_no);
	if (row_no == 0) {
		LM_DBG("No rows returned from Mongo \n");
		bson_destroy(&fields);
		bson_destroy(&query);
		stop_expire_timer(start,mongo_exec_threshold,
		"cachedb_mongo sql_select",table->s,table->len,0);
		return 0;
	}

	/* on first iteration we allocate the result
	 * we always assume the query returns exactly the number
	 * of 'columns' as were requested */
	if (db_allocate_columns(*_r,_nc) != 0) {
		LM_ERR("Failed to allocate columns \n");
		goto error2;
	}

	/* and we initialize the names as if all are there */
	for (j=0;j<_nc;j++) {
		/* since we don't have schema, the types will be allocated
		 * when we fetch the actual rows */
		RES_NAMES(*_r)[j]->s = _c[j]->s;
		RES_NAMES(*_r)[j]->len = _c[j]->len;
	}

	if (db_allocate_rows(*_r,row_no) != 0) {
		LM_ERR("No more private memory for rows \n");
		goto error2;
	}

	RES_ROW_N(*_r) = row_no;

	hex_oid_id = pkg_malloc(sizeof(char) * row_no * HEX_OID_SIZE);
	if (hex_oid_id==NULL) {
		LM_ERR("oom\n");
		goto error2;
	}
	i=0;
	while( mongo_cursor_next(m_cursor) == MONGO_OK ) {
		bson_iterator_init(&it,mongo_cursor_bson(m_cursor));
		current = &(RES_ROWS(*_r)[i]);
		ROW_N(current) = RES_COL_N(*_r);
		for (j=0;j<_nc;j++) {
			memcpy(key_buff,_c[j]->s,_c[j]->len);
			key_buff[_c[j]->len]=0;
			cur_val = &ROW_VALUES(current)[j];
			if (bson_find(&it,mongo_cursor_bson(m_cursor),key_buff) == BSON_EOO) {
				memset(cur_val,0,sizeof(db_val_t));
				VAL_STRING(cur_val) = dummy_string.s;
				VAL_STR(cur_val) = dummy_string;
				VAL_BLOB(cur_val) = dummy_string;
				/* we treat null values as DB string */
				VAL_TYPE(cur_val) = DB_STRING;
				VAL_NULL(cur_val) = 1;
				LM_DBG("Found empty [%.*s]\n", _c[j]->len, _c[j]->s);
			} else {
				switch( bson_iterator_type( &it ) ) {
					case BSON_INT:
						VAL_TYPE(cur_val) = DB_INT;
						VAL_INT(cur_val) = bson_iterator_int(&it);
						LM_DBG("Found int [%.*s]=[%d]\n",
							_c[j]->len, _c[j]->s, VAL_INT(cur_val));
						break;
					case BSON_DOUBLE:
						VAL_TYPE(cur_val) = DB_DOUBLE;
						VAL_DOUBLE(cur_val) = bson_iterator_double(&it);
						LM_DBG("Found double [%.*s]=[%f]\n",
							_c[j]->len, _c[j]->s, VAL_DOUBLE(cur_val));
						break;
					case BSON_STRING:
						VAL_TYPE(cur_val) = DB_STRING;
						VAL_STRING(cur_val) = bson_iterator_string(&it);
						LM_DBG("Found string [%.*s]=[%s]\n",
							_c[j]->len, _c[j]->s, VAL_STRING(cur_val));
						break;
					case BSON_LONG:
						VAL_TYPE(cur_val) = DB_BIGINT;
						VAL_BIGINT(cur_val) = bson_iterator_long(&it);
						LM_DBG("Found long [%.*s]=[%lld]\n",
							_c[j]->len, _c[j]->s, VAL_BIGINT(cur_val));
						break;
					case BSON_DATE:
						VAL_TYPE(cur_val) = DB_DATETIME;
						VAL_TIME(cur_val) = bson_iterator_time_t(&it);
						LM_DBG("Found time [%.*s]=[%d]\n",
							_c[j]->len, _c[j]->s, (int)VAL_TIME(cur_val));
						break;
					case BSON_OID:
						bson_oid_to_string(bson_iterator_oid(&it), hex_oid);
						p = &hex_oid_id[i*HEX_OID_SIZE];
						memcpy(p, hex_oid, HEX_OID_SIZE);
						VAL_TYPE(cur_val) = DB_STRING;
						VAL_STRING(cur_val) = p;
						LM_DBG("Found oid [%.*s]=[%s]\n",
							_c[j]->len, _c[j]->s, VAL_STRING(cur_val));
						break;
					default:
						LM_WARN("Unsupported type [%d] for [%.*s] - treating as NULL\n",
							bson_iterator_type(&it), _c[j]->len, _c[j]->s);
						memset(cur_val,0,sizeof(db_val_t));
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
		i++;
	}

	LM_DBG("Successfully ran query\n");
	bson_destroy(&query);
	bson_destroy(&fields);
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo sql_select",table->s,table->len,0);
	return 0;

error2:
	db_free_result(*_r);
	mongo_cursor_destroy(m_cursor);
	*_r = NULL;
	MONGO_CDB_CURSOR(con) = NULL;
error:
	bson_destroy(&query);
	bson_destroy(&fields);
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo sql_select",table->s,table->len,0);
	return -1;
#endif
	return 0;
}

int mongo_db_free_result_trans(cachedb_con* con, db_res_t* _r)
{
#if 0
	if ((!con) || (!_r)) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	LM_DBG("freeing mongo query result \n");

	if (hex_oid_id) {
		pkg_free(hex_oid_id); hex_oid_id = NULL;
	}

	if (db_free_result(_r) < 0) {
		LM_ERR("unable to free result structure\n");
		return -1;
	}

	mongo_cursor_destroy(MONGO_CDB_CURSOR(con));
	MONGO_CDB_CURSOR(con) = NULL;
	return 0;
#endif
	return 0;
}

int mongo_db_insert_trans(cachedb_con *con,const str *table,const db_key_t* _k, const db_val_t* _v,const int _n)
{
#if 0
	int i,j,ret;
	bson_t query;
	bson_t err_b;
	char key_buff[32],namespace_buff[64],*p;
	mongo *conn = &MONGO_CDB_CON(con);
	bson_iterator it;
	struct timeval start;
	char _old_char;
	bson_oid_t _id;
	int appendOID = 1;

	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&query);
	for (i=0;i<_n;i++) {
		if (VAL_NULL(_v+i) == 0) {
			MONGO_DB_KEY_TRANS(_k,_v,i,((db_op_t*)0),query);
		}
	}
	bson_finish(&query);

	p=namespace_buff;
	i = strlen(MONGO_DATABASE(con));
	memcpy(p,MONGO_DATABASE(con),i);
	p +=i;
	*p++ = '.';
	memcpy(p,table->s,table->len);
	p+= table->len;
	*p = 0;

	LM_DBG("Running raw mongo insert on table %s\n",namespace_buff);

	for (j=0;j<2;j++) {
		ret = mongo_insert(conn,namespace_buff,&query,0);
		if (ret == MONGO_ERROR) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(con),&err_b);
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&it,&err_b);
			while( bson_iterator_next(&it)) {
				LM_ERR("Fetched ERR key [%s]. Val = ",bson_iterator_key(&it));
				switch( bson_iterator_type( &it ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&it));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&it));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&it));
						break;
					default:
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
						break;
				}
			}

			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			stop_expire_timer(start,mongo_exec_threshold,
			"cachedb_mongo sql_insert",table->s,table->len,0);
			return -1;
		}
		break;
	}

	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo sql_insert",table->s,table->len,0);
	return 0;
#endif
	return 0;
}

int mongo_db_delete_trans(cachedb_con *con,const str *table,const db_key_t* _k,const db_op_t *_o, const db_val_t* _v,const int _n)
{
#if 0
	int i,j,ret;
	bson_t query;
	bson_t err_b;
	char key_buff[32],namespace_buff[64],*p;
	mongo *conn = &MONGO_CDB_CON(con);
	bson_iterator it;
	struct timeval start;
	char _old_char;
	bson_oid_t _id;
	int appendOID = 1;

	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&query);
	for (i=0;i<_n;i++) {
			MONGO_DB_KEY_TRANS(_k,_v,i,_o,query);
	}
	bson_finish(&query);

	p=namespace_buff;
	i = strlen(MONGO_DATABASE(con));
	memcpy(p,MONGO_DATABASE(con),i);
	p +=i;
	*p++ = '.';
	memcpy(p,table->s,table->len);
	p+= table->len;
	*p = 0;

	LM_DBG("Running raw mongo delete on table %s\n",namespace_buff);

	for (j=0;j<2;j++) {
		ret = mongo_remove(conn,namespace_buff,&query,0);
		if (ret == MONGO_ERROR) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(con),&err_b);
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&it,&err_b);
			while( bson_iterator_next(&it)) {
				LM_ERR("Fetched ERR key [%s]. Val = ",bson_iterator_key(&it));
				switch( bson_iterator_type( &it ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&it));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&it));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&it));
						break;
					default:
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
						break;
				}
			}

			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			stop_expire_timer(start,mongo_exec_threshold,
			"cachedb_mongo sql_delete",table->s,table->len,0);
			return -1;
		}
		break;
	}

	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo sql_delete",table->s,table->len,0);
	return 0;
#endif
	return 0;
}

int mongo_db_update_trans(cachedb_con *con,const str *table,const db_key_t* _k,const db_op_t *_o, const db_val_t* _v,const db_key_t* _uk, const db_val_t* _uv, const int _n,const int _un)
{
#if 0
	int i,j,ret;
	bson_t query,op_query;
	bson_t err_b;
	char key_buff[32],namespace_buff[64],*p;
	mongo *conn = &MONGO_CDB_CON(con);
	bson_iterator it;
	struct timeval start;
	char _old_char;
	bson_oid_t _id;
	int appendOID = 1;

	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&query);
	for (i=0;i<_n;i++) {
			MONGO_DB_KEY_TRANS(_k,_v,i,_o,query);
	}
	bson_finish(&query);

	bson_init(&op_query);
	bson_append_start_object(&op_query, "$set");
	for (i=0;i<_un;i++) {
		MONGO_DB_KEY_TRANS(_uk,_uv,i,((db_op_t*)NULL),op_query);
	}
	bson_append_finish_object(&op_query);
	bson_finish(&op_query);

	p=namespace_buff;
	i = strlen(MONGO_DATABASE(con));
	memcpy(p,MONGO_DATABASE(con),i);
	p +=i;
	*p++ = '.';
	memcpy(p,table->s,table->len);
	p+= table->len;
	*p = '\0';

	LM_DBG("Running raw mongo update on table %s\n",namespace_buff);

	for (j=0;j<2;j++) {
		ret = mongo_update(conn,namespace_buff,
				&query,&op_query,MONGO_UPDATE_UPSERT|MONGO_UPDATE_MULTI,0);
		if (ret == MONGO_ERROR) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(con),&err_b);
			if (!bson_size(&err_b))
				return -1;

			bson_iterator_init(&it,&err_b);
			while( bson_iterator_next(&it)) {
				LM_ERR("Fetched ERR key [%s]. Val = ",bson_iterator_key(&it));
				switch( bson_iterator_type( &it ) ) {
					case BSON_DOUBLE:
						LM_DBG("(double) %e\n",bson_iterator_double(&it));
						break;
					case BSON_INT:
						LM_DBG("(int) %d\n",bson_iterator_int(&it));
						break;
					case BSON_STRING:
						LM_DBG("(string) \"%s\"\n",bson_iterator_string(&it));
						break;
					default:
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
						break;
				}
			}
			return -1;
			stop_expire_timer(start,mongo_exec_threshold,
			"cachedb_mongo sql_update",table->s,table->len,0);
		}
		break;
	}

	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo sql_update",table->s,table->len,0);
	return 0;
#endif
	return 0;
}
