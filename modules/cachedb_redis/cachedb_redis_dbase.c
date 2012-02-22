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
#include "cachedb_redis_dbase.h"
#include "cachedb_redis_utils.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../cachedb/cachedb.h"

#include <string.h>
#include <hiredis/hiredis.h>

int redis_connect_node(redis_con *con,cluster_node *node)
{
	redisReply *rpl;

	node->context = redisConnect(node->ip,node->port);
	if (node->context->err != REDIS_OK) {
		LM_ERR("failed to open redis connection %s:%hu - %s\n",node->ip,
				node->port,node->context->errstr);
		return -1;
	}

	if (con->id->password) {
		rpl = redisCommand(node->context,"AUTH %s",con->id->password);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to auth to redis - %.*s\n",
				rpl?rpl->len:7,rpl?rpl->str:"FAILURE");
			freeReplyObject(rpl);
			redisFree(node->context);
			return -1;
		}
		LM_DBG("AUTH [password] -  %.*s\n",rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	if ((con->type & REDIS_SINGLE_INSTANCE) && con->id->database) {
		rpl = redisCommand(node->context,"SELECT %s",con->id->database);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to select database %s - %.*s\n",con->id->database,
				rpl?rpl->len:7,rpl?rpl->str:"FAILURE");
			freeReplyObject(rpl);
			redisFree(node->context);
			return -1;
		}

		LM_DBG("SELECT [%s] - %.*s\n",con->id->database,rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	return 0;
}

int redis_connect(redis_con *con)
{
	redisContext *ctx;
	redisReply *rpl;
	cluster_node *it;

	/* connect to redis DB */
	ctx = redisConnect(con->id->host,con->id->port);
	if (ctx->err != REDIS_OK) {
		LM_ERR("failed to open redis connection - %s\n",ctx->errstr);
		return -1;
	}

	/* auth using password, if any */
	if (con->id->password) {
		rpl = redisCommand(ctx,"AUTH %s",con->id->password);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to auth to redis - %.*s\n",
				rpl?rpl->len:7,rpl?rpl->str:"FAILURE");
			freeReplyObject(rpl);
			redisFree(ctx);
			return -1;
		}
		LM_DBG("AUTH [password] -  %.*s\n",rpl->len,rpl->str);
		freeReplyObject(rpl);
	}
	
	rpl = redisCommand(ctx,"CLUSTER NODES");
	if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
		/* single instace mode */
		con->type |= REDIS_SINGLE_INSTANCE;
		con->nodes = pkg_malloc(sizeof(cluster_node));
		if (con->nodes == NULL) {
			LM_ERR("no more pkg\n");
			freeReplyObject(rpl);
			redisFree(ctx);
			return -1;
		}

		redisFree(ctx);
		strcpy(con->nodes->ip,con->id->host);
		con->nodes->port = con->id->port;
		con->nodes->start_slot = 0;
		con->nodes->end_slot = 4096;
		con->nodes->context = NULL;
		con->nodes->next = NULL;
		LM_DBG("single instance mode\n");
	} else {
		/* cluster instance mode */
		con->type |= REDIS_CLUSTER_INSTANCE;
		redisFree(ctx);
		LM_DBG("cluster instance mode\n");
		if (build_cluster_nodes(con,rpl->str,rpl->len) < 0) {
			LM_ERR("failed to parse Redis cluster info\n");
			return -1;
		}
	}

	freeReplyObject(rpl);
	for (it=con->nodes;it;it=it->next)
		if (redis_connect_node(con,it) < 0) {
			LM_ERR("failed to init connection \n");
			return -1;
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
		pkg_free(con);
		return 0;
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
		node = get_redis_connection(con,key); \
		if (node == NULL) { \
			LM_ERR("Bad cluster configuration\n"); \
			return -10; \
		} \
		for (i=2;i;i--) { \
			reply = redisCommand(node->context,fmt,##args); \
			if (reply == NULL || reply->type == REDIS_REPLY_ERROR) { \
				LM_ERR("Redis operation failure - %.*s\n",\
					reply?reply->len:7,reply?reply->str:"FAILURE"); \
				if (reply) \
					freeReplyObject(reply); \
				if (node->context->err == REDIS_OK || redis_connect_node(con,node) < 0) { \
					i = 0; break; \
				}\
			} else break; \
		} \
		if (i==0) { \
			LM_ERR("giving up on query\n"); \
			return -1; \
		} \
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
		return -2;
	}

	LM_DBG("GET %.*s  - %.*s\n",attr->len,attr->s,reply->len,reply->str);

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
			val->s,reply->type,reply->len,reply->str);

	freeReplyObject(reply);

	if (expires) {
		redis_run_command(con,attr,"EXPIRE %b %d",attr->s,attr->len,expires);

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;
}

/* returns 0 in case of succesful remove
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
		LM_DBG("Key %.*s succesfully removed\n",attr->len,attr->s);

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
				reply->len,reply->str);

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
				reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;
}
