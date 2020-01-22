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
#include "cachedb_redis_dbase.h"
#include "cachedb_redis_utils.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../cachedb/cachedb.h"

#include <string.h>
#include <hiredis/hiredis.h>

#define QUERY_ATTEMPTS 2

int redis_query_tout = CACHEDB_REDIS_DEFAULT_TIMEOUT;
int redis_connnection_tout = CACHEDB_REDIS_DEFAULT_TIMEOUT;
int shutdown_on_error = 0;

redisContext *redis_get_ctx(char *ip, int port)
{
	struct timeval tv;
	static char warned = 0;
	redisContext *ctx;

	if (!redis_connnection_tout) {
		if (!warned++)
			LM_WARN("Connecting to redis without timeout might block your server\n");
		ctx = redisConnect(ip,port);
	} else {
		tv.tv_sec = redis_connnection_tout / 1000;
		tv.tv_usec = (redis_connnection_tout * 1000) % 1000000;
		ctx = redisConnectWithTimeout(ip,port,tv);
	}
	if (ctx && ctx->err != REDIS_OK) {
		LM_ERR("failed to open redis connection %s:%hu - %s\n",ip,
				(unsigned short)port,ctx->errstr);
		return NULL;
	}

	if (redis_query_tout) {
		tv.tv_sec = redis_query_tout / 1000;
		tv.tv_usec = (redis_query_tout * 1000) % 1000000;
		if (redisSetTimeout(ctx, tv) != REDIS_OK) {
			LM_ERR("Cannot set query timeout to %dms\n", redis_query_tout);
			return NULL;
		}
	}
	return ctx;
}

int redis_connect_node(redis_con *con,cluster_node *node)
{
	redisReply *rpl;

	node->context = redis_get_ctx(node->ip,node->port);
	if (!node->context)
		return -1;

	if (con->id->password) {
		rpl = redisCommand(node->context,"AUTH %s",con->id->password);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to auth to redis - %.*s\n",
				rpl?(unsigned)rpl->len:7,rpl?rpl->str:"FAILURE");
			freeReplyObject(rpl);
			redisFree(node->context);
			return -1;
		}
		LM_DBG("AUTH [password] -  %.*s\n",(unsigned)rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	if ((con->flags & REDIS_SINGLE_INSTANCE) && con->id->database) {
		rpl = redisCommand(node->context,"SELECT %s",con->id->database);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to select database %s - %.*s\n",con->id->database,
				rpl?(unsigned)rpl->len:7,rpl?rpl->str:"FAILURE");
			freeReplyObject(rpl);
			redisFree(node->context);
			return -1;
		}

		LM_DBG("SELECT [%s] - %.*s\n",con->id->database,(unsigned)rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	return 0;
}

int redis_reconnect_node(redis_con *con,cluster_node *node)
{
	LM_DBG("reconnecting node %s:%d \n",node->ip,node->port);

	/* close the old connection */
	if(node->context)
		redisFree(node->context);

	return redis_connect_node(con,node);
}


int redis_connect(redis_con *con)
{
	redisContext *ctx;
	redisReply *rpl;
	cluster_node *it;
	int len;

	/* connect to redis DB */
	ctx = redis_get_ctx(con->id->host,con->id->port);
	if (!ctx)
		return -1;

	/* auth using password, if any */
	if (con->id->password) {
		rpl = redisCommand(ctx,"AUTH %s",con->id->password);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to auth to redis - %.*s\n",
				rpl?(unsigned)rpl->len:7,rpl?rpl->str:"FAILURE");
			if (rpl!=NULL)
				freeReplyObject(rpl);
			redisFree(ctx);
			return -1;
		}
		LM_DBG("AUTH [password] -  %.*s\n",(unsigned)rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	rpl = redisCommand(ctx,"CLUSTER NODES");
	if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
		/* single instace mode */
		con->flags |= REDIS_SINGLE_INSTANCE;
		len = strlen(con->id->host);
		con->nodes = pkg_malloc(sizeof(cluster_node) + len + 1);
		if (con->nodes == NULL) {
			LM_ERR("no more pkg\n");
			if (rpl!=NULL)
				freeReplyObject(rpl);
			redisFree(ctx);
			return -1;
		}
		con->nodes->ip = (char *)(con->nodes + 1);

		strcpy(con->nodes->ip,con->id->host);
		con->nodes->port = con->id->port;
		con->nodes->start_slot = 0;
		con->nodes->end_slot = 4096;
		con->nodes->context = NULL;
		con->nodes->next = NULL;
		LM_DBG("single instance mode\n");
	} else {
		/* cluster instance mode */
		con->flags |= REDIS_CLUSTER_INSTANCE;
		con->slots_assigned = 0;
		LM_DBG("cluster instance mode\n");
		if (build_cluster_nodes(con,rpl->str,rpl->len) < 0) {
			LM_ERR("failed to parse Redis cluster info\n");
			freeReplyObject(rpl);
			redisFree(ctx);
			return -1;
		}
	}

	if (rpl!=NULL)
		freeReplyObject(rpl);
	redisFree(ctx);

	con->flags |= REDIS_INIT_NODES;

	for (it=con->nodes;it;it=it->next) {

		if (it->end_slot > con->slots_assigned )
			con->slots_assigned = it->end_slot;

		if (redis_connect_node(con,it) < 0) {
			LM_ERR("failed to init connection \n");
			return -1;
		}
	}

	return 0;
}

redis_con* redis_new_connection(struct cachedb_id* id)
{
	redis_con *con;

	if (id == NULL) {
		LM_ERR("null cachedb_id\n");
		return 0;
	}

	if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS) {
		LM_ERR("multiple hosts are not supported for redis\n");
		return 0;
	}

	con = pkg_malloc(sizeof(redis_con));
	if (con == NULL) {
		LM_ERR("no more pkg \n");
		return 0;
	}

	memset(con,0,sizeof(redis_con));
	con->id = id;
	con->ref = 1;

	if (redis_connect(con) < 0) {
		LM_ERR("failed to connect to DB\n");
		if (shutdown_on_error) {
			pkg_free(con);
			return NULL;
		}
	}

	return con;
}

cachedb_con *redis_init(str *url)
{
	return cachedb_do_init(url,(void *)redis_new_connection);
}

void redis_free_connection(cachedb_pool_con *con)
{
	redis_con * c;

	LM_DBG("in redis_free_connection\n");

	if (!con) return;
	c = (redis_con *)con;
	destroy_cluster_nodes(c);
	pkg_free(c);
}

void redis_destroy(cachedb_con *con) {
	LM_DBG("in redis_destroy\n");
	cachedb_do_close(con,redis_free_connection);
}

#define redis_run_command(con,key,fmt,args...) \
	do {\
		con = (redis_con *)connection->data; \
		if (!(con->flags & REDIS_INIT_NODES) && redis_connect(con) < 0) { \
			LM_ERR("failed to connect to DB\n"); \
			return -9; \
		} \
		node = get_redis_connection(con,key); \
		if (node == NULL) { \
			LM_ERR("Bad cluster configuration\n"); \
			return -10; \
		} \
		if (node->context == NULL) { \
			if (redis_reconnect_node(con,node) < 0) { \
				return -1; \
			} \
		} \
		for (i = QUERY_ATTEMPTS; i; i--) { \
			reply = redisCommand(node->context,fmt,##args); \
			if (reply == NULL || reply->type == REDIS_REPLY_ERROR) { \
				LM_INFO("Redis query failed: %p %.*s\n",\
					reply,reply?(unsigned)reply->len:7,reply?reply->str:"FAILURE"); \
				if (reply) \
					freeReplyObject(reply); \
				if (node->context->err == REDIS_OK || redis_reconnect_node(con,node) < 0) { \
					i = 0; break; \
				}\
			} else break; \
		} \
		if (i==0) { \
			LM_ERR("giving up on query\n"); \
			return -1; \
		} \
		if (i != QUERY_ATTEMPTS) \
			LM_INFO("successfully ran query after %d failed attempt(s)\n", \
			        QUERY_ATTEMPTS - i); \
	} while (0)

int redis_get(cachedb_con *connection,str *attr,str *val)
{
	redis_con *con;
	cluster_node *node;
	redisReply *reply;
	int i;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	redis_run_command(con,attr,"GET %b",attr->s,attr->len);

	if (reply->type == REDIS_REPLY_NIL || reply->str == NULL
			|| reply->len == 0) {
		LM_DBG("no such key - %.*s\n",attr->len,attr->s);
		val->s = NULL;
		val->len = 0;
		freeReplyObject(reply);
		return -2;
	}

	LM_DBG("GET %.*s  - %.*s\n",attr->len,attr->s,(unsigned)reply->len,reply->str);

	val->s = pkg_malloc(reply->len);
	if (val->s == NULL) {
		LM_ERR("no more pkg\n");
		freeReplyObject(reply);
		return -1;
	}

	memcpy(val->s,reply->str,reply->len);
	val->len = reply->len;
	freeReplyObject(reply);
	return 0;
}

int redis_set(cachedb_con *connection,str *attr,str *val,int expires)
{
	redis_con *con;
	cluster_node *node;
	redisReply *reply;
	int i;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	redis_run_command(con,attr,"SET %b %b",attr->s,attr->len,val->s,val->len);

	LM_DBG("set %.*s to %.*s - status = %d - %.*s\n",attr->len,attr->s,val->len,
			val->s,reply->type,(unsigned)reply->len,reply->str);

	freeReplyObject(reply);

	if (expires) {
		redis_run_command(con,attr,"EXPIRE %b %d",attr->s,attr->len,expires);

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				(unsigned)reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;
}

/* returns 0 in case of successful remove
 * returns 1 in case of key not existent
 * return -1 in case of error */
int redis_remove(cachedb_con *connection,str *attr)
{
	redis_con *con;
	cluster_node *node;
	redisReply *reply;
	int ret=0,i;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	redis_run_command(con,attr,"DEL %b",attr->s,attr->len);

	if (reply->integer == 0) {
		LM_DBG("Key %.*s does not exist in DB\n",attr->len,attr->s);
		ret = 1;
	} else
		LM_DBG("Key %.*s successfully removed\n",attr->len,attr->s);

	freeReplyObject(reply);
	return ret;
}

/* returns the new value of the counter */
int redis_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	redis_con *con;
	cluster_node *node;
	redisReply *reply;
	int i;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	redis_run_command(con,attr,"INCRBY %b %d",attr->s,attr->len,val);

	if (new_val)
		*new_val = reply->integer;
	freeReplyObject(reply);

	if (expires) {
		redis_run_command(con,attr,"EXPIRE %b %d",attr->s,attr->len,expires);

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				(unsigned)reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;
}

int redis_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	redis_con *con;
	cluster_node *node;
	redisReply *reply;
	int i;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	redis_run_command(con,attr,"DECRBY %b %d",attr->s,attr->len,val);

	if (new_val)
		*new_val = reply->integer;
	freeReplyObject(reply);

	if (expires) {
		redis_run_command(con,attr,"EXPIRE %b %d",attr->s,attr->len,expires);

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				(unsigned)reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;
}

int redis_get_counter(cachedb_con *connection,str *attr,int *val)
{
	redis_con *con;
	cluster_node *node;
	redisReply *reply;
	int i,ret;
	str response;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	redis_run_command(con,attr,"GET %b",attr->s,attr->len);

	if (reply->type == REDIS_REPLY_NIL || reply->str == NULL
			|| reply->len == 0) {
		LM_DBG("no such key - %.*s\n",attr->len,attr->s);
		return -2;
	}

	LM_DBG("GET %.*s  - %.*s\n",attr->len,attr->s,(unsigned)reply->len,reply->str);

	response.s=reply->str;
	response.len=reply->len;

	if (str2sint(&response,&ret) != 0) {
		LM_ERR("Not a counter \n");
		freeReplyObject(reply);
		return -3;
	}

	if (val)
		*val = ret;

	freeReplyObject(reply);
	return 0;
}

int redis_raw_query_handle_reply(redisReply *reply,cdb_raw_entry ***ret,
		int expected_kv_no,int *reply_no)
{
	int current_size=0,len,i;

	/* start with a single returned document */
	*ret = pkg_malloc(1 * sizeof(cdb_raw_entry *));
	if (*ret == NULL) {
		LM_ERR("No more PKG mem\n");
		goto error;
	}

	**ret = pkg_malloc(expected_kv_no * sizeof(cdb_raw_entry));
	if (**ret == NULL) {
		LM_ERR("No more pkg mem\n");
		goto error;
	}

	switch (reply->type) {
		case REDIS_REPLY_STRING:
			(*ret)[current_size][0].val.s.s = pkg_malloc(reply->len);
			if (! (*ret)[current_size][0].val.s.s ) {
				LM_ERR("No more pkg \n");
				goto error;
			}

			memcpy((*ret)[current_size][0].val.s.s,reply->str,reply->len);
			(*ret)[current_size][0].val.s.len = reply->len;
			(*ret)[current_size][0].type = CDB_STR;

			current_size++;
			break;
		case REDIS_REPLY_INTEGER:
			(*ret)[current_size][0].val.n = reply->integer;
			(*ret)[current_size][0].type = CDB_INT32;
			current_size++;
			break;
		case REDIS_REPLY_NIL:
			(*ret)[current_size][0].type = CDB_NULL;
			(*ret)[current_size][0].val.s.s = NULL;
			(*ret)[current_size][0].val.s.len = 0;
			current_size++;
			break;
		case REDIS_REPLY_ARRAY:
			for (i=0;i<reply->elements;i++) {
				switch (reply->element[i]->type) {
					case REDIS_REPLY_STRING:
					case REDIS_REPLY_INTEGER:
					case REDIS_REPLY_NIL:
						if (current_size > 0) {
							*ret = pkg_realloc(*ret,(current_size + 1) * sizeof(cdb_raw_entry *));
							if (*ret == NULL) {
								LM_ERR("No more pkg\n");
								goto error;
							}
							(*ret)[current_size] = pkg_malloc(expected_kv_no * sizeof(cdb_raw_entry));
							if ((*ret)[current_size] == NULL) {
								LM_ERR("No more pkg\n");
								goto error;
							}
						}


						if (reply->element[i]->type == REDIS_REPLY_INTEGER) {
							(*ret)[current_size][0].val.n = reply->element[i]->integer;
							(*ret)[current_size][0].type = CDB_INT32;
						} else if (reply->element[i]->type == REDIS_REPLY_NIL) {
							(*ret)[current_size][0].val.s.s = NULL;
							(*ret)[current_size][0].val.s.len = 0;
							(*ret)[current_size][0].type = CDB_NULL;
						} else {
							(*ret)[current_size][0].val.s.s = pkg_malloc(reply->element[i]->len);
							if (! (*ret)[current_size][0].val.s.s ) {
								pkg_free((*ret)[current_size]);
								LM_ERR("No more pkg \n");
								goto error;
							}

							memcpy((*ret)[current_size][0].val.s.s,reply->element[i]->str,reply->element[i]->len);
							(*ret)[current_size][0].val.s.len = reply->element[i]->len;
							(*ret)[current_size][0].type = CDB_STR;
						}

						current_size++;
						break;
					default:
						LM_DBG("Unexpected data type %d found in array - skipping \n",reply->element[i]->type);
				}
			}
			break;
		default:
			LM_ERR("unhandled Redis datatype %d\n", reply->type);
			goto error;
	}

	if (current_size == 0)
		pkg_free((*ret)[0]);

	*reply_no = current_size;
	freeReplyObject(reply);
	return 1;

error:
	if (current_size == 0 && *ret)
		pkg_free((*ret)[0]);

	if (*ret) {
		for (len = 0;len<current_size;len++) {
			if ( (*ret)[len][0].type == CDB_STR)
				pkg_free((*ret)[len][0].val.s.s);
			pkg_free((*ret)[len]);
		}
		pkg_free(*ret);
	}

	*ret = NULL;
	*reply_no=0;

	freeReplyObject(reply);
	return -1;
}

/* TODO - altough in most of the cases the targetted key is the 2nd query string,
	that's not always the case ! - make this 100% */
int redis_raw_query_extract_key(str *attr,str *query_key)
{
	int len;
	char *p,*q,*r;

	if (!attr || attr->s == NULL || query_key == NULL)
		return -1;

	trim_len(len,p,*attr);
	q = memchr(p,' ',len);
	if (q == NULL) {
		LM_ERR("Malformed Redis RAW query \n");
		return -1;
	}

	query_key->s = q+1;
	r = memchr(query_key->s,' ',len - (query_key->s - p));
	if (r == NULL) {
		query_key->len = (p+len) - query_key->s;
	} else {
		query_key->len = r-query_key->s;
	}

	return 0;
}

int redis_raw_query_send(cachedb_con *connection,redisReply **reply,cdb_raw_entry ***rpl,int expected_kv_no,int *reply_no,str *attr, ...)
{
	redis_con *con;
	cluster_node *node;
	int i,end;
	va_list ap;
	str query_key;

	con = (redis_con *)connection->data;

	if (!(con->flags & REDIS_INIT_NODES) && redis_connect(con) < 0) {
		LM_ERR("failed to connect to DB\n");
		return -9;
	}

	if (redis_raw_query_extract_key(attr,&query_key) < 0) {
		LM_ERR("Failed to extra Redis raw query key \n");
		return -1;
	}

	node = get_redis_connection(con,&query_key);
	if (node == NULL) {
		LM_ERR("Bad cluster configuration\n");
		return -10;
	}

	if (node->context == NULL) {
		if (redis_reconnect_node(con,node) < 0) {
			return -1;
		}
	}

	va_start(ap,attr);
	end = attr->s[attr->len];
	attr->s[attr->len] = 0;

	for (i = QUERY_ATTEMPTS; i; i--) {
		*reply = redisvCommand(node->context,attr->s,ap);
		if (*reply == NULL || (*reply)->type == REDIS_REPLY_ERROR) {
			LM_INFO("Redis query failed: %.*s\n",
				*reply?(unsigned)((*reply)->len):7,*reply?(*reply)->str:"FAILURE");
			if (*reply)
				freeReplyObject(*reply);
			if (node->context->err == REDIS_OK || redis_reconnect_node(con,node) < 0) {
				i = 0; break;
			}
		} else break;
	}

	va_end(ap);
	attr->s[attr->len]=end;

	if (i==0) {
		LM_ERR("giving up on query\n");
		return -1;
	}

	if (i != QUERY_ATTEMPTS)
		LM_INFO("successfully ran query after %d failed attempt(s)\n",
		        QUERY_ATTEMPTS - i);

	return 0;
}

int redis_raw_query(cachedb_con *connection,str *attr,cdb_raw_entry ***rpl,int expected_kv_no,int *reply_no)
{
	redisReply *reply;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}


	if (redis_raw_query_send(connection,&reply,rpl,expected_kv_no,reply_no,attr) < 0) {
		LM_ERR("Failed to send query to server \n");
		return -1;
	}

	switch (reply->type) {
		case REDIS_REPLY_ERROR:
			LM_ERR("Error encountered when running Redis raw query [%.*s]\n",
			attr->len,attr->s);
			return -1;
		case REDIS_REPLY_NIL:
			LM_DBG("Redis raw query [%.*s] failed - no such key\n",attr->len,attr->s);
			freeReplyObject(reply);
			return -2;
		case REDIS_REPLY_STATUS:
			LM_DBG("Received a status of %.*s from Redis \n",(unsigned)reply->len,reply->str);
			if (reply_no)
				*reply_no = 0;
			freeReplyObject(reply);
			return 1;
		default:
			/* some data arrived - yay */

			if (rpl == NULL) {
				LM_DBG("Received reply type %d but script writer not interested in it \n",reply->type);
				freeReplyObject(reply);
				return 1;
			}
			return redis_raw_query_handle_reply(reply,rpl,expected_kv_no,reply_no);
	}

	return 1;
}
