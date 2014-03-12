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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include "../../cachedb/cachedb.h"

#include <string.h>

extern mongo_write_concern mwc;
extern str mongo_write_concern_str;
extern str mongo_write_concern_b;
extern int mongo_slave_ok;
extern int mongo_exec_threshold;

#define HEX_OID_SIZE 25
char *hex_oid_id = NULL;

mongo_con* mongo_new_connection(struct cachedb_id* id)
{
	mongo_con *con;
	bson version_cmd,version_out;
	bson_iterator it;
	const char *version;
	char *p,*p1;
	str database, collection,replset_name,host,port;
	int port_no,last=0;
	char hostname[64];

	if (id == NULL) {
		LM_ERR("null cachedb_id\n");
		return 0;
	}

	if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
		/* we are connecting to a replica set */
		replset_name.s = id->database;
		p = memchr(id->database,'.',strlen(id->database));
		if (!p) {
			LM_ERR("Malformed mongo database\n");
			return 0;
		}

		replset_name.len = p-replset_name.s;

		database.s = replset_name.s+replset_name.len+1;
		p = memchr(replset_name.s+replset_name.len+1,'.',
					strlen(id->database)-replset_name.len-1);
		if (!p) {
			LM_ERR("Malformed mongo database\n");
			return 0;
		}

		database.len = p-database.s;

		collection.s = p+1;
		collection.len = id->database+strlen(id->database) - collection.s;

		con = pkg_malloc(sizeof(mongo_con)+database.len+collection.len+
											replset_name.len+3);
		if (con == NULL) {
			LM_ERR("no more pkg \n");
			return 0;
		}

		memset(con,0,sizeof(mongo_con)+database.len+collection.len+replset_name.len+3);
		con->id = id;
		con->ref = 1;

		con->database = (char *)(con +1);
		memcpy(con->database,database.s,database.len);
		con->collection = con->database + database.len + 1;
		memcpy(con->collection,collection.s,collection.len);
		con->replset_name = con->database+database.len+collection.len+2;
		memcpy(con->replset_name,replset_name.s,replset_name.len);

		LM_INFO("Connecting to [%s.%s.%s]\n",
				con->replset_name,con->database,con->collection);

		if (mongo_set_op_timeout(&MONGO_CON(con),mongo_op_timeout) != MONGO_OK)
			LM_WARN("Failed to set timeout of %d millis\n",mongo_op_timeout);
		else
			LM_DBG("Set timeout to %d millis\n",mongo_op_timeout);

		mongo_replset_init(&MONGO_CON(con),con->replset_name);

		p = id->host;
		while (*p) {
			host.s = p;

			p1 = memchr(host.s,',',strlen(host.s));
			if (p1 == NULL) {
				p1 = id->host+strlen(id->host);
				last=1;
			}

			host.len = p1 - host.s;

			port.s = memchr(host.s,':',host.len);
			if (!port.s)
				port_no = 27017;
			else {
				port.s++;

				port.len = host.s + host.len - port.s;
				host.len = host.len - port.len - 1;

				if (str2int(&port,(unsigned int *)&port_no) != 0) {
					LM_ERR("Malformed mongo URL\n");
					return 0;
				}
			}

			memcpy(hostname,host.s,host.len);
			hostname[host.len] = 0;

			mongo_replset_add_seed(&MONGO_CON(con),hostname,port_no);

			if (last)
				break;
			else
				p = ++ p1;
		}

		if (mongo_replset_connect(&MONGO_CON(con)) != MONGO_OK) {
			LM_ERR("Failure to connect to mongo - %d\n",MONGO_CON(con).err);
			return 0;
		}
	} else {

		database.s = id->database;
		p = memchr(id->database,'.',strlen(id->database));
		if (!p) {
			LM_ERR("Malformed mongo database\n");
			return 0;
		}

		database.len = p-database.s;

		collection.s = p+1;
		collection.len = id->database+strlen(id->database) - collection.s;

		con = pkg_malloc(sizeof(mongo_con)+database.len+collection.len+2);
		if (con == NULL) {
			LM_ERR("no more pkg \n");
			return 0;
		}

		memset(con,0,sizeof(mongo_con)+database.len+collection.len+2);
		con->id = id;
		con->ref = 1;

		mongo_init(&MONGO_CON(con));

		con->database = (char *)(con +1);
		memcpy(con->database,database.s,database.len);
		con->collection = con->database + database.len + 1;
		memcpy(con->collection,collection.s,collection.len);

		if (mongo_set_op_timeout(&MONGO_CON(con),mongo_op_timeout) != MONGO_OK)
			LM_WARN("Failed to set timeout of %d millis\n",mongo_op_timeout);
		else
			LM_DBG("Set timeout to %d millis\n",mongo_op_timeout);

		if (mongo_connect(&MONGO_CON(con),id->host,id->port) != MONGO_OK) {
			LM_ERR("Failure to connect to mongo\n");
			return 0;
		}
	}

	if (mongo_write_concern_str.s != NULL) {
		mongo_set_write_concern(&MONGO_CON(con), &mwc);
	}

	bson_init(&version_cmd);
	bson_append_int(&version_cmd, "buildinfo", 1 );
	bson_finish(&version_cmd);

	if( mongo_run_command(&MONGO_CON(con), "admin", &version_cmd,
	 &version_out ) == MONGO_ERROR ) {
		LM_ERR("Failed to get version of server\n");
		return 0;
	}

	bson_iterator_init(&it, &version_out);
	version = bson_iterator_string(&it);

	LM_INFO("Connected at server %s with version %s , "
			"to db %s.%s\n",id->host,version,
			con->database,con->collection);
	bson_destroy(&version_cmd);
	bson_destroy(&version_out);

	return con;
}

cachedb_con *mongo_con_init(str *url)
{
	return cachedb_do_init(url,(void *)mongo_new_connection);
}

void mongo_free_connection(cachedb_pool_con *con)
{
}

void mongo_con_destroy(cachedb_con *con)
{
	LM_DBG("in mongo_destroy\n");
	cachedb_do_close(con,mongo_free_connection);
}

int mongo_con_get(cachedb_con *connection,str *attr,str *val)
{
	bson new_b,err_b;
	mongo_cursor *m_cursor;
	bson_iterator it;
	const char *rez;
	int rez_len,i;
	mongo *conn = &MONGO_CDB_CON(connection);
	char hex_oid[HEX_OID_SIZE];
	struct timeval start;

	LM_DBG("Get operation on namespace %s\n",MONGO_NAMESPACE(connection));
	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&new_b);
	if (bson_append_string_n(&new_b,"_id",attr->s,attr->len) != BSON_OK) {
		LM_ERR("Failed to append _id \n");
		bson_destroy(&new_b);
		goto error;
	}
	bson_finish(&new_b);

	for (i=0;i<2;i++) {
		m_cursor = mongo_find(conn,MONGO_NAMESPACE(connection),
				&new_b,0,0,0,mongo_slave_ok);
		if (m_cursor == NULL) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
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

				bson_destroy(&new_b);
			}
			goto error;
		}
		break;
	}

	while( mongo_cursor_next(m_cursor) == MONGO_OK ) {
		bson_iterator_init(&it,mongo_cursor_bson(m_cursor));

		if (bson_find(&it,mongo_cursor_bson(m_cursor),"opensips") == BSON_EOO)
			continue;

		switch( bson_iterator_type( &it ) ) {
			case BSON_INT:
				rez = int2str(bson_iterator_int(&it),&rez_len);
				if (rez == NULL) {
					LM_ERR("Failed to convert %d to str\n",
						bson_iterator_int(&it));
					mongo_cursor_destroy(m_cursor);
					goto error;
				}

				val->s = pkg_malloc(rez_len);
				if (val->s == NULL) {
					LM_ERR("No more pkg malloc\n");
					mongo_cursor_destroy(m_cursor);
					goto error;
				}
				memcpy(val->s,rez,rez_len);
				val->len = rez_len;
				mongo_cursor_destroy(m_cursor);
				stop_expire_timer(start,mongo_exec_threshold,
				"cachedb_mongo get",attr->s,attr->len,0);
				return 0;

				break;
			case BSON_STRING:
				rez = bson_iterator_string(&it);
				if (rez == NULL) {
					LM_ERR("Got null str for mongo\n");
					mongo_cursor_destroy(m_cursor);
					goto error;
				}
				rez_len=strlen(rez);
				val->s = pkg_malloc(rez_len);

				if (val->s == NULL) {
					LM_ERR("No more pkg malloc\n");
					mongo_cursor_destroy(m_cursor);
					goto error;
				}
				memcpy(val->s,rez,rez_len);
				val->len = rez_len;
				mongo_cursor_destroy(m_cursor);
				stop_expire_timer(start,mongo_exec_threshold,
				"cachedb_mongo get",attr->s,attr->len,0);
				return 0;

				break;
				default:
					LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
					break;
		}
	}

	LM_DBG("No suitable response found\n");
	mongo_cursor_destroy(m_cursor);
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo get",attr->s,attr->len,0);
	return -2;
error:
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo get",attr->s,attr->len,0);
	return -1;
}

int mongo_con_set(cachedb_con *connection,str *attr,str *val,int expires)
{
	bson new_b;
	int i;
	struct timeval start;
	mongo *conn = &MONGO_CDB_CON(connection);

	LM_DBG("Set operation on namespace %s\n",MONGO_NAMESPACE(connection));
	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&new_b);
	if (bson_append_string_n(&new_b,"_id",attr->s,attr->len) != BSON_OK) {
		LM_ERR("Failed to append _id \n");
		bson_destroy(&new_b);
		goto error;
	}

	if (bson_append_string_n(&new_b,"opensips",val->s,val->len) != BSON_OK) {
		LM_ERR("Failed to append _id \n");
		bson_destroy(&new_b);
		goto error;
	}

	bson_finish(&new_b);

	for (i=0;i<2;i++) {
		if (mongo_insert(conn,MONGO_NAMESPACE(connection),
				&new_b,NULL) != BSON_OK) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to do insert. Con err = %d\n",
				conn->err);
			bson_destroy(&new_b);
			goto error;
		}
	}

	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo set",attr->s,attr->len,0);
	bson_destroy(&new_b);
	return 0;
error:
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo set",attr->s,attr->len,0);
	return -1;
}

int mongo_con_remove(cachedb_con *connection,str *attr)
{
	bson new_b;
	int i;
	struct timeval start;
	mongo *conn = &MONGO_CDB_CON(connection);

	LM_DBG("Remove operation on namespace %s\n",MONGO_NAMESPACE(connection));
	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&new_b);
	if (bson_append_string_n(&new_b,"_id",attr->s,attr->len) != BSON_OK) {
		LM_ERR("Failed to append _id \n");
		bson_destroy(&new_b);
		goto error;
	}

	bson_finish(&new_b);

	for (i=0;i<2;i++) {
		if (mongo_remove(conn,MONGO_NAMESPACE(connection),
				&new_b,NULL) != BSON_OK) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to do insert. Con err = %d\n",
				conn->err);
			bson_destroy(&new_b);
			goto error;
		}
	}

	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo remove",attr->s,attr->len,0);
	bson_destroy(&new_b);
	return 0;
error:
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo remove",attr->s,attr->len,0);
	return -1;
}

void dbg_bson_print_raw( const char *data , int depth )
{
	bson_iterator i;
	const char *key;
	int temp;
	bson_timestamp_t ts;
	char oidhex[HEX_OID_SIZE];
	bson scope;
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
}

void dbg_print_bson(bson *b)
{
	dbg_bson_print_raw(b->data,0);
}

int mongo_raw_find(cachedb_con *connection,bson *raw_query,cdb_raw_entry ***reply,int expected_kv_no,int *reply_no)
{
	bson_iterator i;
	mongo_cursor *m_cursor;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson op_b,fields_b,err_b;
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
					memset(&op_b,0,sizeof(bson));
					bson_init_finished_data(&op_b,(char *)bson_iterator_value(&i));
					have_query=1;
				} else if (strcmp(key,"fields") == 0) {
					memset(&fields_b,0,sizeof(bson));
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
}

int mongo_raw_count(cachedb_con *connection,bson *raw_query,cdb_raw_entry ***reply,int expected_kv_no,int *reply_no)
{
	bson_iterator i;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson op_b,err_b;
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
					memset(&op_b,0,sizeof(bson));
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
}

int mongo_raw_update(cachedb_con *connection,bson *raw_query)
{
	bson_iterator i;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson op_b,match_b,err_b;
	int have_query=0,have_match=0,j,ret;

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
					memset(&op_b,0,sizeof(bson));
					bson_init_finished_data(&op_b,(char *)bson_iterator_value(&i));
					have_query=1;
				} else if (strcmp(key,"match") == 0) {
					memset(&match_b,0,sizeof(bson));
					bson_init_finished_data(&match_b,(char *)bson_iterator_value(&i));
					have_match=1;
				}
				break;
			default:
				LM_DBG("Unusable type %d - ignoring \n",t);
		}
	}

	if (have_query == 0) {
		LM_ERR("Cannot proceed. Don't have the actual update query \n");
		return -1;
	}

	for (j=0;j<2;j++) {
		/* TODO - various flags - upsert, multi etc */
		ret = mongo_update(conn,ns?ns:MONGO_NAMESPACE(connection),
				have_match?&match_b:0,&op_b,0,0);
		if (ret == MONGO_ERROR) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
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

	return 0;
}

int mongo_raw_insert(cachedb_con *connection,bson *raw_query)
{
	bson_iterator i;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson op_b,err_b;
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
					memset(&op_b,0,sizeof(bson));
					bson_init_finished_data(&op_b,(char *)bson_iterator_value(&i));
					have_query=1;
				}
				break;
			default:
				LM_DBG("Unusable type %d - ignoring \n",t);
		}
	}

	if (have_query == 0) {
		LM_ERR("Cannot proceed. Don't have the actual insert query \n");
		return -1;
	}

	for (j=0;j<2;j++) {
		ret = mongo_insert(conn,ns?ns:MONGO_NAMESPACE(connection),
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

			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			return -1;
		}
		break;
	}

	return 0;
}

int mongo_raw_remove(cachedb_con *connection,bson *raw_query)
{
	bson_iterator i;
	const char *key,*ns=NULL;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson op_b,err_b;
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
					memset(&op_b,0,sizeof(bson));
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
}

static char *raw_query_buf=NULL;
static int raw_query_buf_len=0;

int mongo_con_raw_query(cachedb_con *connection,str *attr,cdb_raw_entry ***reply,int expected_kv_no,int *reply_no)
{
	bson new_b;
	int ret;
	bson_iterator i;
	struct timeval start;
	const char *op=NULL;

	LM_DBG("Get operation on namespace %s\n",MONGO_NAMESPACE(connection));
	start_expire_timer(start,mongo_exec_threshold);

	if (attr->len > raw_query_buf_len) {
		raw_query_buf = pkg_realloc(raw_query_buf,attr->len+1);
		if (!raw_query_buf) {
			LM_ERR("No more pkg\n");
			goto error;
		}

		memcpy(raw_query_buf,attr->s,attr->len);
		raw_query_buf[attr->len]=0;

		raw_query_buf_len = attr->len;
	} else {
		memcpy(raw_query_buf,attr->s,attr->len);
		raw_query_buf[attr->len]=0;
	}

	ret = json_to_bson(raw_query_buf,&new_b);

	if (ret < 0) {
		LM_ERR("Failed to convert [%.*s] to BSON\n",attr->len,attr->s);
		goto error;
	}

	if (bson_find(&i,&new_b,"op") == BSON_EOO) {
		LM_ERR("No \"op\" specified \n");
		bson_destroy(&new_b);
		goto error;
	}

	if (bson_iterator_type( &i ) != BSON_STRING) {
		LM_ERR("The op must be a string \n");
		bson_destroy(&new_b);
		goto error;
	}

	op = bson_iterator_string( &i );

	if (strcmp(op,"find") == 0) {
		ret = mongo_raw_find(connection,&new_b,reply,expected_kv_no,reply_no);
	} else if (strcmp(op,"update") == 0) {
		ret = mongo_raw_update(connection,&new_b);
	} else if (strcmp(op,"insert") == 0) {
		ret = mongo_raw_insert(connection,&new_b);
	} else if (strcmp(op,"remove") == 0) {
		ret = mongo_raw_remove(connection,&new_b);
	} else if (strcmp(op,"count") == 0) {
		ret = mongo_raw_count(connection,&new_b,reply,expected_kv_no,reply_no);
	} else {
		LM_ERR("Unsupported op type [%s] \n",op);
		bson_destroy(&new_b);
		goto error;
	}

	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo raw",attr->s,attr->len,0);
	bson_destroy(&new_b);
	return ret;
error:
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo raw",attr->s,attr->len,0);
	return -1;
}

static char counter_q_buf[256];
int mongo_con_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	bson cmd,err_b,out;
	int j,ret;
	struct timeval start;
	mongo *conn = &MONGO_CDB_CON(connection);
	bson_iterator it,it2;
	const char *curr_key,*inner_key;

	start_expire_timer(start,mongo_exec_threshold);

	bson_init( &cmd );
	bson_append_string(&cmd,"findAndModify",MONGO_COLLECTION(connection));

	bson_append_start_object(&cmd,"query");
	memcpy(counter_q_buf,attr->s,attr->len);
	counter_q_buf[attr->len]=0;
	bson_append_string(&cmd,"_id",counter_q_buf);
	bson_append_finish_object(&cmd);

	bson_append_start_object(&cmd,"update");
	bson_append_start_object(&cmd,"$inc");
	bson_append_int(&cmd,"opensips_counter",val);
	bson_append_finish_object(&cmd);
	bson_append_finish_object(&cmd);

	bson_finish(&cmd);

	for (j=0;j<2;j++) {
		ret = mongo_run_command(conn,MONGO_DATABASE(connection),
				&cmd,&out);
		if (ret != MONGO_OK) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
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
						/* TODO - support more types here */
						LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
						break;
				}
			}
			bson_destroy(&cmd);
			stop_expire_timer(start,mongo_exec_threshold,
			"cachedb_mongo add",attr->s,attr->len,0);
			return -1;
		}
		break;
	}

	if (!new_val) {
		bson_destroy(&out);
		bson_destroy(&cmd);
		stop_expire_timer(start,mongo_exec_threshold,
		"cachedb_mongo add",attr->s,attr->len,0);
		return 0;
	}

	bson_iterator_init(&it,&out);
	while( bson_iterator_next(&it)) {
		curr_key=bson_iterator_key(&it);

		if (memcmp(curr_key,"retval",6) == 0) {
			if (bson_iterator_type(&it) != BSON_OBJECT) {
				LM_ERR("Unexpected value type %d\n",
					bson_iterator_type(&it));
				goto err;
			}
			bson_iterator_subiterator(&it,&it2);
			while (bson_iterator_next(&it2)) {
				inner_key=bson_iterator_key(&it2);
				if (memcmp(inner_key,"cval",4) == 0) {
					*new_val = bson_iterator_int(&it2) + val;
					bson_destroy(&out);
					bson_destroy(&cmd);
					stop_expire_timer(start,mongo_exec_threshold,
					"cachedb_mongo add",attr->s,attr->len,0);
					return 0;
				}
			}
		}
	}

err:
	bson_destroy(&out);
	bson_destroy(&cmd);
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo add",attr->s,attr->len,0);
	return -1;

}

int mongo_con_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	return mongo_con_add(connection,attr,-val,expires,new_val);
}

int mongo_con_get_counter(cachedb_con *connection,str *attr,int *val)
{
	bson new_b,err_b;
	mongo_cursor *m_cursor;
	bson_iterator it;
	int i;
	struct timeval start;
	mongo *conn = &MONGO_CDB_CON(connection);
	char hex_oid[HEX_OID_SIZE];

	LM_DBG("Get counter operation on namespace %s\n",MONGO_NAMESPACE(connection));
	start_expire_timer(start,mongo_exec_threshold);

	bson_init(&new_b);
	if (bson_append_string_n(&new_b,"_id",attr->s,attr->len) != BSON_OK) {
		LM_ERR("Failed to append _id \n");
		bson_destroy(&new_b);
		stop_expire_timer(start,mongo_exec_threshold,
		"cachedb_mongo get_counter",attr->s,attr->len,0);
		return -1;
	}
	bson_finish(&new_b);

	for (i=0;i<2;i++) {
		m_cursor = mongo_find(conn,MONGO_NAMESPACE(connection),
				&new_b,0,0,0,mongo_slave_ok);
		if (m_cursor == NULL) {
			if (mongo_check_connection(conn) == MONGO_ERROR &&
			mongo_reconnect(conn) == MONGO_OK &&
			mongo_check_connection(conn) == MONGO_OK) {
				LM_INFO("Lost connection to Mongo but reconnected. Re-Trying\n");
				continue;
			}
			LM_ERR("Failed to run query. Err = %d, %d , %d \n",conn->err,conn->errcode,conn->lasterrcode);
			mongo_cmd_get_last_error(conn,MONGO_DATABASE(connection),&err_b);
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
			bson_destroy(&new_b);
			stop_expire_timer(start,mongo_exec_threshold,
			"cachedb_mongo get_counter",attr->s,attr->len,0);
			return -1;
		}
		break;
	}

	while( mongo_cursor_next(m_cursor) == MONGO_OK ) {
		bson_iterator_init(&it,mongo_cursor_bson(m_cursor));

		if (bson_find(&it,mongo_cursor_bson(m_cursor),"opensips_counter") == BSON_EOO)
			continue;

		switch( bson_iterator_type( &it ) ) {
			case BSON_INT:
				if (val)
					*val = bson_iterator_int(&it);

				mongo_cursor_destroy(m_cursor);
				stop_expire_timer(start,mongo_exec_threshold,
				"cachedb_mongo get_counter",attr->s,attr->len,0);
				return 0;

				break;
			default:
					LM_DBG("(unknown type %d)\n",bson_iterator_type(&it));
					break;
		}
	}

	LM_DBG("No suitable response found\n");
	mongo_cursor_destroy(m_cursor);
	stop_expire_timer(start,mongo_exec_threshold,
	"cachedb_mongo get_counter",attr->s,attr->len,0);
	return -2;
}

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

int mongo_db_query_trans(cachedb_con *con,const str *table,const db_key_t* _k, const db_op_t* _op,const db_val_t* _v, const db_key_t* _c, const int _n, const int _nc,const db_key_t _o, db_res_t** _r)
{
	char key_buff[32],namespace_buff[64],*p;
	bson query;
	bson fields;
	bson err_b;
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

	LM_DBG("Succesfully ran query\n");
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
}

int mongo_db_free_result_trans(cachedb_con* con, db_res_t* _r)
{
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
}

int mongo_db_insert_trans(cachedb_con *con,const str *table,const db_key_t* _k, const db_val_t* _v,const int _n)
{
	int i,j,ret;
	bson query;
	bson err_b;
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
}

int mongo_db_delete_trans(cachedb_con *con,const str *table,const db_key_t* _k,const db_op_t *_o, const db_val_t* _v,const int _n)
{
	int i,j,ret;
	bson query;
	bson err_b;
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
}

int mongo_db_update_trans(cachedb_con *con,const str *table,const db_key_t* _k,const db_op_t *_o, const db_val_t* _v,const db_key_t* _uk, const db_val_t* _uv, const int _n,const int _un)
{
	int i,j,ret;
	bson query,op_query;
	bson err_b;
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
}
