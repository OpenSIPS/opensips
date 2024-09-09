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
#include "../../pt.h"
#include "../../cachedb/cachedb.h"
#include "../../lib/csv.h"

#include <string.h>
#include <hiredis/hiredis.h>

#define QUERY_ATTEMPTS 2
#define REDIS_DF_PORT  6379

int redis_query_tout = CACHEDB_REDIS_DEFAULT_TIMEOUT;
int redis_connnection_tout = CACHEDB_REDIS_DEFAULT_TIMEOUT;
int shutdown_on_error = 0;
int use_tls = 0;

struct tls_mgm_binds tls_api;

redisContext *redis_get_ctx(char *ip, int port)
{
	struct timeval tv;
	static char warned = 0;
	redisContext *ctx;

	if (!port)
		port = REDIS_DF_PORT;

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

#ifdef HAVE_REDIS_SSL
static void tls_print_errstack(void)
{
	int code;

	while ((code = ERR_get_error())) {
		LM_ERR("TLS errstack: %s\n", ERR_error_string(code, 0));
	}
}

static int redis_init_ssl(char *url_extra_opts, redisContext *ctx,
	struct tls_domain **tls_dom)
{
	str tls_dom_name;
	SSL *ssl;
	struct tls_domain *d;

	if (tls_dom == NULL) {
		if (strncmp(url_extra_opts, CACHEDB_TLS_DOM_PARAM,
				CACHEDB_TLS_DOM_PARAM_LEN)) {
			LM_ERR("Invalid Redis URL parameter: %s\n", url_extra_opts);
			return -1;
		}

		tls_dom_name.s = url_extra_opts + CACHEDB_TLS_DOM_PARAM_LEN;
		tls_dom_name.len = strlen(tls_dom_name.s);
		if (!tls_dom_name.len) {
			LM_ERR("Empty TLS domain name in Redis URL\n");
			return -1;
		}

		d = tls_api.find_client_domain_name(&tls_dom_name);
		if (d == NULL) {
			LM_ERR("TLS domain: %.*s not found\n",
				tls_dom_name.len, tls_dom_name.s);
			return -1;
		}

		*tls_dom = d;
	} else {
		d = *tls_dom;
	}

	ssl = SSL_new(((void**)d->ctx)[process_no]);
	if (!ssl) {
		LM_ERR("failed to create SSL structure (%d:%s)\n", errno, strerror(errno));
		tls_print_errstack();
		tls_api.release_domain(*tls_dom);
		return -1;
	}

	if (redisInitiateSSL(ctx, ssl) != REDIS_OK) {
		printf("Failed to init Redis SSL: %s\n", ctx->errstr);
		tls_api.release_domain(*tls_dom);
		return -1;
	}

	LM_DBG("TLS enabled for this connection\n");

	return 0;
}
#endif

int redis_connect_node(redis_con *con,cluster_node *node)
{
	redisReply *rpl;

	node->context = redis_get_ctx(node->ip,node->port);
	if (!node->context)
		return -1;

#ifdef HAVE_REDIS_SSL
	if (use_tls && con->id->extra_options &&
		redis_init_ssl(con->id->extra_options, node->context,
			&node->tls_dom) < 0) {
		redisFree(node->context);
		node->context = NULL;
		return -1;
	}
#endif

	if (con->id->password) {
		rpl = redisCommand(node->context,"AUTH %s",con->id->password);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to auth to redis - %.*s\n",
				rpl?(unsigned)rpl->len:7,rpl?rpl->str:"FAILURE");
			freeReplyObject(rpl);
			goto error;
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
			goto error;
		}

		LM_DBG("SELECT [%s] - %.*s\n",con->id->database,(unsigned)rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	return 0;

error:
	redisFree(node->context);
	node->context = NULL;
	if (use_tls && node->tls_dom) {
		tls_api.release_domain(node->tls_dom);
		node->tls_dom = NULL;
	}
	return -1;
}

int redis_reconnect_node(redis_con *con,cluster_node *node)
{
	LM_DBG("reconnecting node %s:%d \n",node->ip,node->port);

	/* close the old connection */
	if(node->context) {
		redisFree(node->context);
		node->context = NULL;
	}

	return redis_connect_node(con,node);
}

int redis_connect(redis_con *con)
{
	redisContext *ctx;
	redisReply *rpl;
	cluster_node *it;
	int len;
	struct tls_domain *tls_dom = NULL;

	/* connect to redis DB */
	ctx = redis_get_ctx(con->host,con->port);
	if (!ctx)
		return -1;

#ifdef HAVE_REDIS_SSL
	if (use_tls && con->id->extra_options &&
		redis_init_ssl(con->id->extra_options, ctx, &tls_dom) < 0) {
		redisFree(ctx);
		return -1;
	}
#endif

	/* auth using password, if any */
	if (con->id->password) {
		rpl = redisCommand(ctx,"AUTH %s",con->id->password);
		if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
			LM_ERR("failed to auth to redis - %.*s\n",
				rpl?(unsigned)rpl->len:7,rpl?rpl->str:"FAILURE");
			if (rpl!=NULL)
				freeReplyObject(rpl);
			goto error;
		}
		LM_DBG("AUTH [password] -  %.*s\n",(unsigned)rpl->len,rpl->str);
		freeReplyObject(rpl);
	}

	rpl = redisCommand(ctx,"CLUSTER NODES");
	if (rpl == NULL || rpl->type == REDIS_REPLY_ERROR) {
		/* single instace mode */
		con->flags |= REDIS_SINGLE_INSTANCE;
		len = strlen(con->host);
		con->nodes = pkg_malloc(sizeof(cluster_node) + len + 1);
		if (con->nodes == NULL) {
			LM_ERR("no more pkg\n");
			if (rpl!=NULL)
				freeReplyObject(rpl);
			goto error;
		}
		con->nodes->ip = (char *)(con->nodes + 1);

		strcpy(con->nodes->ip,con->host);
		con->nodes->port = con->port;
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
			goto error;
		}
	}

	if (rpl!=NULL)
		freeReplyObject(rpl);
	redisFree(ctx);

	if (use_tls && tls_dom)
		tls_api.release_domain(tls_dom);

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

error:
	redisFree(ctx);
	if (use_tls && tls_dom)
		tls_api.release_domain(tls_dom);
	return -1;
}

/* free a circular list of Redis connections */
void redis_free_conns(redis_con *con)
{
	redis_con *aux = NULL, *head = con;

	while (con && (con != head || !aux)) {
		aux = con;
		con = con->next_con;
		pkg_free(aux->host);
		pkg_free(aux);
	}
}

/* parse a string of: "host[:port]" */
int redis_get_hostport(const str *hostport, char **host, unsigned short *port)
{
	str in, out;

	char *p = q_memchr(hostport->s, ':', hostport->len);
	if (!p) {
		if (pkg_nt_str_dup(&out, hostport) != 0) {
			LM_ERR("oom\n");
			return -1;
		}

		*host = out.s;
		*port = REDIS_DF_PORT;
	} else {
		in.s = hostport->s;
		in.len = p - hostport->s;
		if (pkg_nt_str_dup(&out, &in) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
		*host = out.s;

		in.s = p + 1;
		in.len = hostport->s + hostport->len - (p + 1);
		if (in.len <= 0) {
			LM_ERR("bad/missing Redis port in URL\n");
			return -1;
		}

		unsigned int out_port;
		if (str2int(&in, &out_port) != 0) {
			LM_ERR("failed to parse Redis port in URL\n");
			return -1;
		}

		*port = out_port;
	}

	LM_DBG("extracted from '%.*s': '%s' and %d\n", hostport->len, hostport->s,
	       *host, *port);

	return 0;
}

redis_con* redis_new_connection(struct cachedb_id* id)
{
	redis_con *con, *cons = NULL;
	csv_record *r, *it;
	unsigned int multi_hosts;

	if (id == NULL) {
		LM_ERR("null cachedb_id\n");
		return NULL;
	}

	if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS)
		multi_hosts = REDIS_MULTIPLE_HOSTS;
	else
		multi_hosts = 0;

	r = parse_csv_record(_str(id->host));
	if (!r) {
		LM_ERR("failed to parse Redis host list: '%s'\n", id->host);
		return NULL;
	}

	for (it = r; it; it = it->next) {
		LM_DBG("parsed Redis host: '%.*s'\n", it->s.len, it->s.s);

		con = pkg_malloc(sizeof(redis_con));
		if (con == NULL) {
			LM_ERR("no more pkg\n");
			goto out_err;
		}

		memset(con,0,sizeof(redis_con));

		{
			unsigned short _, *port;

			/* if the DSN has a custom port, inherit it now & bypass parser */
			if (!(id->flags & CACHEDB_ID_MULTIPLE_HOSTS) && id->port) {
				con->port = id->port;
				port = &_;
			} else {
				port = &con->port;
			}

			if (redis_get_hostport(&it->s, &con->host, port) != 0) {
				LM_ERR("no more pkg\n");
				goto out_err;
			}

			LM_DBG("final hostport: %s:%u\n", con->host, con->port);
		}

		con->id = id;
		con->ref = 1;
		con->flags |= multi_hosts; /* if the case */

		/* if doing failover Redises, only connect the 1st one for now! */
		if (!cons && redis_connect(con) < 0) {
			LM_ERR("failed to connect to DB\n");
			if (shutdown_on_error)
				goto out_err;
		}

		_add_last(con, cons, next_con);
	}

	/* turn @cons into a circular list */
	con->next_con = cons;
	/* set the "last-known-to-work" connection */
	cons->current = cons;

	free_csv_record(r);
	return cons;

out_err:
	free_csv_record(r);
	redis_free_conns(cons);
	return NULL;
}

cachedb_con *redis_init(str *url)
{
	return cachedb_do_init(url,(void *)redis_new_connection);
}

void redis_free_connection(cachedb_pool_con *cpc)
{
	redis_con *con = (redis_con *)cpc, *aux = NULL, *head = con;

	LM_DBG("in redis_free_connection\n");

	if (!con)
		return;

	while (con && (con != head || !aux)) {
		aux = con;
		con = con->next_con;
		destroy_cluster_nodes(aux);
		pkg_free(aux->host);
		pkg_free(aux);
	}
}

void redis_destroy(cachedb_con *con) {
	LM_DBG("in redis_destroy\n");
	cachedb_do_close(con,redis_free_connection);
}

/*
 * Upon returning 0 (success), @rpl is guaranteed to be:
 *   - non-NULL
 *   - non-REDIS_REPLY_ERROR
 *
 * On error, a negative code is returned
 */
static int _redis_run_command(cachedb_con *connection, redisReply **rpl, str *key,
	int argc, const char **argv, const size_t *argvlen,
	char *cmd_fmt, va_list ap)
{
	redis_con *con = NULL, *first;
	cluster_node *node;
	redisReply *reply = NULL;
	int i, last_err = 0;
	va_list aq;

	first = ((redis_con *)connection->data)->current;
	while (((redis_con *)connection->data)->current != first || !con) {
		con = ((redis_con *)connection->data)->current;

		if (!(con->flags & REDIS_INIT_NODES) && redis_connect(con) < 0) {
			LM_ERR("failed to connect to DB\n");
			last_err = -9;
			goto try_next_con;
		}

		node = get_redis_connection(con,key);
		if (node == NULL) {
			LM_ERR("Bad cluster configuration\n");
			last_err = -10;
			goto try_next_con;
		}

		if (node->context == NULL) {
			if (redis_reconnect_node(con,node) < 0) {
				last_err = -1;
				goto try_next_con;
			}
		}

		for (i = QUERY_ATTEMPTS; i; i--) {
			if (argc) {
				reply = redisCommandArgv(node->context, argc, argv, argvlen);
			} else {
				va_copy(aq, ap);
				reply = redisvCommand(node->context, cmd_fmt, aq);
				va_end(aq);
			}

			if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
				LM_INFO("Redis query failed: %p %.*s (%s)\n",
					reply,reply?(unsigned)reply->len:7,reply?reply->str:"FAILURE",
					node->context->errstr);
				if (reply) {
					freeReplyObject(reply);
					reply = NULL;
				}
				if (node->context->err == REDIS_OK || redis_reconnect_node(con,node) < 0) {
					i = 0; break;
				}
			} else break;
		}

		if (i==0) {
			LM_ERR("giving up on query to %s:%d\n", con->host, con->port);
			last_err = -1;
			goto try_next_con;
		}

		if (i != QUERY_ATTEMPTS)
			LM_INFO("successfully ran query after %d failed attempt(s)\n",
			        QUERY_ATTEMPTS - i);

		last_err = 0;
		break;

try_next_con:
		((redis_con *)connection->data)->current = con->next_con;
		if (con->next_con != first)
			LM_INFO("failing over to next Redis host (%s:%d)\n",
			        con->next_con->host, con->next_con->port);
	}

	*rpl = reply;
	return last_err;
}

static int redis_run_command(cachedb_con *connection, redisReply **rpl,
              str *key, char *cmd_fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, cmd_fmt);
	rc = _redis_run_command(connection, rpl, key, 0, NULL, NULL, cmd_fmt, ap);
	va_end(ap);

	return rc;
}

static int redis_run_command_argv(cachedb_con *connection, redisReply **rpl,
              str *key, int argc, const char **argv, const size_t *argvlen)
{
	va_list _;

	return _redis_run_command(connection, rpl, key, argc, argv, argvlen, NULL, _);
}

int redis_get(cachedb_con *connection,str *attr,str *val)
{
	redisReply *reply;
	int rc;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	rc = redis_run_command(connection, &reply, attr, "GET %b",
		attr->s, (size_t)attr->len);
	if (rc != 0)
		goto out_err;

	if (reply->type == REDIS_REPLY_NIL) {
		LM_DBG("no such key - %.*s\n",attr->len,attr->s);
		val->s = NULL;
		val->len = 0;
		freeReplyObject(reply);
		return -2;
	}

	if (reply->str == NULL || reply->len == 0) {
		/* empty string key */
		val->s = NULL;
		val->len = 0;
		freeReplyObject(reply);
		return 0;
	}

	LM_DBG("GET %.*s  - %.*s\n",attr->len,attr->s,(unsigned)reply->len,reply->str);

	val->s = pkg_malloc(reply->len);
	if (val->s == NULL) {
		LM_ERR("no more pkg\n");
		goto out_err;
	}

	memcpy(val->s,reply->str,reply->len);
	val->len = reply->len;
	freeReplyObject(reply);
	return 0;

out_err:
	if (reply)
		freeReplyObject(reply);
	return rc;
}

int redis_set(cachedb_con *connection,str *attr,str *val,int expires)
{
	redisReply *reply;
	int rc;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	rc = redis_run_command(connection, &reply, attr, "SET %b %b",
			attr->s, (size_t)attr->len, val->s, (size_t)val->len);
	if (rc != 0)
		goto out_err;

	LM_DBG("set %.*s to %.*s - status = %d - %.*s\n",attr->len,attr->s,val->len,
			val->s,reply->type,(unsigned)reply->len,reply->str);

	freeReplyObject(reply);

	if (expires) {
		rc = redis_run_command(connection, &reply, attr, "EXPIRE %b %d",
		             attr->s, (size_t)attr->len, expires);
		if (rc != 0)
			goto out_err;

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				(unsigned)reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;

out_err:
	freeReplyObject(reply);
	return rc;
}

/* returns 0 in case of successful remove
 * returns 1 in case of key not existent
 * return -1 in case of error */
int redis_remove(cachedb_con *connection,str *attr)
{
	redisReply *reply;
	int rc;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	rc = redis_run_command(connection, &reply, attr, "DEL %b",
		attr->s, (size_t)attr->len);
	if (rc != 0)
		goto out_err;

	if (reply->integer == 0) {
		LM_DBG("Key %.*s does not exist in DB\n",attr->len,attr->s);
		rc = 1;
	} else
		LM_DBG("Key %.*s successfully removed\n",attr->len,attr->s);

	freeReplyObject(reply);
	return rc;

out_err:
	freeReplyObject(reply);
	return rc;
}

/* returns the new value of the counter */
int redis_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	redisReply *reply;
	int rc;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	rc = redis_run_command(connection, &reply, attr, "INCRBY %b %d",
			attr->s, (size_t)attr->len,val);
	if (rc != 0)
		goto out_err;

	if (new_val)
		*new_val = reply->integer;
	freeReplyObject(reply);

	if (expires) {
		rc = redis_run_command(connection, &reply, attr, "EXPIRE %b %d",
				attr->s, (size_t)attr->len,expires);
		if (rc != 0)
			goto out_err;

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				(unsigned)reply->len,reply->str);

		freeReplyObject(reply);
	}

	return rc;

out_err:
	freeReplyObject(reply);
	return rc;
}

int redis_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val)
{
	redisReply *reply;
	int rc;

	if (!attr || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	rc = redis_run_command(connection, &reply, attr, "DECRBY %b %d",
			attr->s, (size_t)attr->len, val);
	if (rc != 0)
		goto out_err;

	if (new_val)
		*new_val = reply->integer;
	freeReplyObject(reply);

	if (expires) {
		rc = redis_run_command(connection, &reply, attr, "EXPIRE %b %d",
				attr->s, (size_t)attr->len, expires);
		if (rc != 0)
			goto out_err;

		LM_DBG("set %.*s to expire in %d s - %.*s\n",attr->len,attr->s,expires,
				(unsigned)reply->len,reply->str);

		freeReplyObject(reply);
	}

	return 0;

out_err:
	freeReplyObject(reply);
	return rc;
}

int redis_get_counter(cachedb_con *connection,str *attr,int *val)
{
	redisReply *reply;
	int ret, rc;
	str response;

	if (!attr || !val || !connection) {
		LM_ERR("null parameter\n");
		return -1;
	}

	rc = redis_run_command(connection, &reply, attr, "GET %b",
			attr->s, (size_t)attr->len);
	if (rc != 0)
		goto out_err;

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

out_err:
	freeReplyObject(reply);
	return rc;
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

int redis_raw_query_send(cachedb_con *connection, redisReply **reply,
		cdb_raw_entry ***_, int __, int *___, str *attr, ...)
{
	int argc = 0, squoted = 0, dquoted = 0;
	const char *argv[MAP_SET_MAX_FIELDS+1];
	size_t argvlen[MAP_SET_MAX_FIELDS+1];
	str key, st;
	char *p, *lim, *arg = NULL;

	st = *attr;
	trim(&st);

	/* allow script developers to enclose swaths of text with single/double
	 * quotes, in case any of their raw query string arguments must include
	 * whitespace chars.  The enclosing quotes shall not be passed to Redis. */
	for (p = st.s, lim = p + st.len; p < lim; p++) {
		if ((dquoted && *p != '"') || (squoted && *p != '\''))
			continue;

		if (argc == MAP_SET_MAX_FIELDS) {
			LM_ERR("max raw query args exceeded (%d)\n", MAP_SET_MAX_FIELDS);
			goto bad_query;
		}

		if (dquoted || squoted) {
			if (p+1 < lim && !is_ws(*(p+1)))
				goto bad_query;

			argv[argc]++;
			argvlen[argc] = p - argv[argc];
			argc++;
			dquoted = squoted = 0;
		} else if (*p == '"') {
			dquoted = 1;
			argv[argc] = p;
		} else if (*p == '\'') {
			squoted = 1;
			argv[argc] = p;
		} else if (is_ws(*p)) {
			if (!arg)
				continue;

			argv[argc] = arg;
			argvlen[argc++] = p - arg;
			arg = NULL;
		} else if (!arg) {
			arg = p;
		}
	}

	if (squoted || dquoted) {
		LM_ERR("unterminated quoted query argument\n");
		goto bad_query;
	}

	if (arg) {
		argv[argc] = arg;
		argvlen[argc++] = st.s + st.len - arg;
	}

	if (argc < 2)
		goto bad_query;

	/* TODO - altough in most of the cases the targetted key is the 2nd query string,
		that's not always the case ! - make this 100% */
	key.s = (char *)argv[1];
	key.len = argvlen[1];

#ifdef EXTRA_DEBUG
	int i;
	LM_DBG("raw query key: %.*s\n", key.len, key.s);
	for (i = 0; i < argc; i++)
		LM_DBG("raw query arg %d: '%.*s' (%d)\n", i, (int)argvlen[i], argv[i],
		       (int)argvlen[i]);
#endif

	return redis_run_command_argv(connection, reply, &key, argc, argv, argvlen);

bad_query:
	LM_ERR("malformed Redis RAW query: '%.*s' (%d)\n",
	       attr->len, attr->s, attr->len);
	return -1;
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

int redis_map_get(cachedb_con *con, const str *key, cdb_res_t *res)
{
	redisReply *scan_reply = NULL, *get_reply = NULL;
	str null_key = {0,0};
	int rc;
	int scan_cursor = 0;
	str s;
	int i,j;
	cdb_row_t *cdb_row;
	cdb_key_t cdb_key;
	cdb_pair_t *hfield, *pair;

	if (!res || !con) {
		LM_ERR("null parameter\n");
		return -1;
	}

	cdb_res_init(res);

	/* iterate over all keys, return a cdb_pair_t for every key */
	do {
		rc = redis_run_command(con, &scan_reply, &null_key,
			"SCAN %d COUNT %d TYPE hash", scan_cursor, MAP_GET_SCAN_COUNT);
		if (rc != 0)
			goto err_free_reply;

		s.len = scan_reply->element[0]->len;
		s.s = scan_reply->element[0]->str;
		if (str2sint(&s, &scan_cursor) != 0) {
			LM_ERR("Cursor returned by SCAN command is not an integer\n");
			goto err_free_reply;
		}

		for (i = 0; i < scan_reply->element[1]->elements; i++) {
			/* get the all the map fields for this key */
			s.len = scan_reply->element[1]->element[i]->len;
			s.s = scan_reply->element[1]->element[i]->str;

			rc = redis_run_command(con, &get_reply, &s, "HGETALL %b",
				s.s, (size_t)s.len);
			if (rc != 0)
				goto err_free_reply;

			if (get_reply->elements == 0)
				continue;

			cdb_row = pkg_malloc(sizeof *cdb_row);
			if (!cdb_row) {
				LM_ERR("no more pkg memory\n");
				goto err_free_reply;
			}
			INIT_LIST_HEAD(&cdb_row->dict);

			cdb_key.name = s;
			cdb_key.is_pk = 1;
			pair = cdb_mk_pair(&cdb_key, NULL);
			if (!pair) {
				LM_ERR("no more pkg memory\n");
				goto err_free_row;
			}
			pair->val.type = CDB_DICT;
			INIT_LIST_HEAD(&pair->val.val.dict);

			for (j = 0; j < get_reply->elements; j+=2) {
				/* in the array returned by HGETALL every
				 * field name is followed by its' value */
				cdb_key.name.len = get_reply->element[j]->len;
				cdb_key.name.s = get_reply->element[j]->str;
				cdb_key.is_pk = 0;

				hfield = cdb_mk_pair(&cdb_key, NULL);
				if (!hfield) {
					LM_ERR("no more pkg memory\n");
					goto err_free_pair;
				}

				s.len = get_reply->element[j+1]->len;
				s.s = get_reply->element[j+1]->str;

				switch (s.s[0]) {
				case HASH_FIELD_VAL_NULL:
					hfield->val.type = CDB_NULL;
					break;
				case HASH_FIELD_VAL_STR:
					hfield->val.type = CDB_STR;
					s.s++;
					s.len--;
					if (pkg_str_dup(&hfield->val.val.st, &s) < 0) {
						LM_ERR("no more pkg memory\n");
						pkg_free(hfield);
						goto err_free_pair;
					}
					break;
				case HASH_FIELD_VAL_INT32:
					hfield->val.type = CDB_INT32;
					s.s++;
					s.len--;
					if (str2sint(&s, (int *)&hfield->val.val.i32) < 0) {
						LM_ERR("Expected hash field value to be an integer\n");
						pkg_free(hfield);
						goto err_free_pair;
					}
					break;
				default:
					LM_DBG("Unexpected type [%c] for hash field, skipping\n", s.s[0]);
					pkg_free(hfield);
					continue;
				}

				cdb_dict_add(hfield, &pair->val.val.dict);
			}

			if (!list_empty(&pair->val.val.dict)) {
				cdb_dict_add(pair, &cdb_row->dict);
				res->count++;
				list_add_tail(&cdb_row->list, &res->rows);
			}

			freeReplyObject(get_reply);
			get_reply = NULL;
		}

		freeReplyObject(scan_reply);
		scan_reply = NULL;
	} while (scan_cursor);

	return 0;

err_free_pair:
	pkg_free(pair);
err_free_row:
	cdb_free_entries(&cdb_row->dict, osips_pkg_free);
	pkg_free(cdb_row);
err_free_reply:
	if (get_reply)
		freeReplyObject(get_reply);
	if (scan_reply)
		freeReplyObject(scan_reply);
	return rc;
}

int redis_map_set(cachedb_con *con, const str *key, const str *subkey,
	const cdb_dict_t *pairs)
{
	int argc = 0;
	const char *argv[MAP_SET_MAX_FIELDS+2];
	size_t argvlen[MAP_SET_MAX_FIELDS+2];
	cdb_pair_t *pair;
	struct list_head *_;
	static str valbuf;
	int offset = 0;
	char *int_buf = NULL;
	int len;
	int rc;
	redisReply *reply;

	if (!con || !key) {
		LM_ERR("null parameter\n");
		return -1;
	}

	argv[0] = "HSET";
	argvlen[0] = sizeof("HSET")-1;
	argv[1] = key->s;
	argvlen[1] = key->len;
	argc = 2;

	list_for_each (_, pairs) {
		pair = list_entry(_, cdb_pair_t, list);

		argv[argc] = pair->key.name.s;
		argvlen[argc] = pair->key.name.len;
		argc++;

		if (argc > MAP_SET_MAX_FIELDS) {
			LM_ERR("Trying to set too many fields(%d)\n", argc);
			return -1;
		}

		switch (pair->val.type) {
		case CDB_NULL:
			len = 0;
			break;
		case CDB_INT32:
			int_buf = sint2str((long)pair->val.val.i32, &len);
			break;
		case CDB_STR:
			len = pair->val.val.st.len;
			break;
		default:
			LM_DBG("Unexpected type [%d] for hash field\n", pair->val.type);
			return -1;
		}

		if (pkg_str_extend(&valbuf, offset+len+1) < 0)
			return -1;

		switch (pair->val.type) {
		case CDB_NULL:
			valbuf.s[offset] = HASH_FIELD_VAL_NULL;
			break;
		case CDB_INT32:
			valbuf.s[offset] = HASH_FIELD_VAL_INT32;
			memcpy(valbuf.s+offset+1, int_buf, len);
			break;
		case CDB_STR:
			valbuf.s[offset] = HASH_FIELD_VAL_STR;
			memcpy(valbuf.s+offset+1, pair->val.val.st.s, len);
			break;
		default:
			LM_DBG("Unexpected type [%d] for hash field\n", pair->val.type);
			return -1;
		}

		argv[argc] = valbuf.s+offset;
		argvlen[argc] = len+1;
		argc++;

		offset += len+1;
	}

	rc = redis_run_command_argv(con, &reply, (str *)key,
		argc, argv, argvlen);
	if (rc != 0)
		return rc;

	freeReplyObject(reply);
	reply = NULL;

	if (subkey) {
		rc = redis_run_command(con, &reply, (str*)subkey, "SADD %b %b",
			subkey->s, (size_t)subkey->len, key->s, (size_t)key->len);
		if (rc != 0)
			return rc;

		freeReplyObject(reply);
	}

	return 0;
}

int redis_map_remove(cachedb_con *con, const str *key, const str *subkey)
{
	int rc;
	redisReply *reply;
	int i;
	str s;

	if (!con || (!key && !subkey)) {
		LM_ERR("null parameter\n");
		return -1;
	}

	if (!subkey)
		return redis_remove(con, (str*)key);

	if (key) {
		/* key based delete, but also remove the member "key"
		 * from the Set at "subkey" */
		rc = redis_run_command(con, &reply, (str*)subkey, "SREM %b %b",
			subkey->s, (size_t)subkey->len, key->s, (size_t)key->len);
		if (rc < 0)
			return rc;

		freeReplyObject(reply);

		return redis_remove(con, (str*)key);
	} else {
		/* subkey based delete - delete all the keys that are members
		 * of the Set at "subkey" */
		rc = redis_run_command(con, &reply, (str*)subkey, "SMEMBERS %b",
			subkey->s, (size_t)subkey->len);
		if (rc != 0)
			return rc;

		for (i = 0; i < reply->elements; i++) {
			s.s = reply->element[i]->str;
			s.len = reply->element[i]->len;

			rc = redis_remove(con, &s);
			if (rc < 0) {
				freeReplyObject(reply);
				return -1;
			}
		}

		freeReplyObject(reply);

		return redis_remove(con, (str*)subkey);
	}
}
