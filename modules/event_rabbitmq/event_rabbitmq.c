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
 *  2011-05-xx  created (razvancrainea)
 */

#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "../../lib/csv.h"
#include "event_rabbitmq.h"
#include "rabbitmq_send.h"
#include <string.h>
#include "../../mem/shm_mem.h"
#include "rmq_servers.h"
#include "../../db/db_id.h"
#include "../../mod_fix.h"
#include "../../dprint.h"

/**
 * module functions
 */
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

/**
 * module parameters
 */
static unsigned int heartbeat = 0;
static int rmq_connect_timeout = RMQ_DEFAULT_CONNECT_TIMEOUT;
static int rmq_timeout = 0;
struct timeval conn_timeout_tv;
#if defined AMQP_VERSION && AMQP_VERSION >= 0x00090000
struct timeval rpc_timeout_tv;
#endif
int use_tls;
struct tls_mgm_binds tls_api;
struct openssl_binds openssl_api;

#if AMQP_VERSION < AMQP_VERSION_CODE(0, 10, 0, 0)
gen_lock_t *ssl_lock;
#endif

/**
 * exported functions
 */
static evi_reply_sock* rmq_parse(str socket);
static int rmq_raise(struct sip_msg *msg, str* ev_name, evi_reply_sock *sock,
	evi_params_t *params, evi_async_ctx_t *async_ctx);
static int rmq_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void rmq_free(evi_reply_sock *sock);
static str rmq_print(evi_reply_sock *sock);

static int fixup_check_avp(void** param);
static int rmq_publish(struct sip_msg *msg, struct rmq_server *srv, str *srkey,
			str *sbody, str *sctype, pv_spec_t *hnames, pv_spec_t *hvals);


/* sending process */
static const proc_export_t procs[] = {
	{"RabbitMQ sender",  0,  0, rmq_process, 1, 0},
	{0,0,0,0,0,0}
};

/* module parameters */
static const param_export_t mod_params[] = {
	{"heartbeat",					INT_PARAM, &heartbeat},
	{"connect_timeout", INT_PARAM, &rmq_connect_timeout},
	{"timeout", INT_PARAM, &rmq_timeout},
	{"use_tls", INT_PARAM, &use_tls},
	{ "server_id",			STR_PARAM|USE_FUNC_PARAM,
		(void *)rmq_server_add},
	{0,0,0}
};

static module_dependency_t *get_deps_use_tls_mgm(const param_export_t *param)
{
	if (*(int *)param->param_pointer == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "tls_mgm", DEP_ABORT);
}

static module_dependency_t *get_deps_use_tls_openssl(const param_export_t *param)
{
	if (*(int *)param->param_pointer == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "tls_openssl", DEP_ABORT);
}

/* modules dependencies */
static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "use_tls", get_deps_use_tls_mgm },
		{ "use_tls", get_deps_use_tls_openssl },
		{ NULL, NULL },
	},
};

/* exported commands */
static const cmd_export_t cmds[] = {
	{"rabbitmq_publish",(cmd_function)rmq_publish, {
		{CMD_PARAM_STR, fixup_rmq_server, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR | CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/**
 * module exports
 */
struct module_exports exports= {
	"event_rabbitmq",				/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load function */
	&deps,							/* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	mod_params,						/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* exported transformations */
	procs,							/* extra processes */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	0,								/* response handling function */
	mod_destroy,					/* destroy function */
	child_init,						/* per-child init function */
	0								/* reload confirm function */
};


/**
 * exported functions for core event interface
 */
static const evi_export_t trans_export_rmq = {
	RMQ_STR,					/* transport module name */
	rmq_raise,					/* raise function */
	rmq_parse,					/* parse function */
	rmq_match,					/* sockets match function */
	rmq_free,					/* free function */
	rmq_print,					/* print socket */
	RMQ_FLAG					/* flags */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module ......\n");

	if (register_event_mod(&trans_export_rmq)) {
		LM_ERR("cannot register transport functions for RabbitMQ\n");
		return -1;
	}

	if (rmq_create_pipe() < 0) {
		LM_ERR("cannot create communication pipe\n");
		return -1;
	}

	if ( heartbeat <= 0 || heartbeat > 65535) {
		LM_WARN("heartbeat is disabled according to the modparam configuration\n");
		heartbeat = 0;
	} else {
		LM_NOTICE("heartbeat is enabled for [%d] seconds\n", heartbeat);
	}

	conn_timeout_tv.tv_sec = rmq_connect_timeout/1000;
	conn_timeout_tv.tv_usec = (rmq_connect_timeout%1000)*1000;

#if defined AMQP_VERSION && AMQP_VERSION >= 0x00090000
	if (rmq_timeout < 0) {
		LM_WARN("invalid value for 'timeout' %d; fallback to blocking mode\n", rmq_timeout);
		rmq_timeout = 0;
	}
	rpc_timeout_tv.tv_sec = rmq_timeout/1000;
	rpc_timeout_tv.tv_usec = (rmq_timeout%1000)*1000;
#else
	if (rmq_timeout != 0)
		LM_WARN("setting the timeout without support for it; fallback to blocking mode\n");
#endif

	if (use_tls) {
		#ifndef AMQP_VERSION_v04
		LM_ERR("TLS not supported for librabbitmq version lower than 0.4.0\n");
		return -1;
		#endif

		if (load_tls_openssl_api(&openssl_api)) {
			LM_DBG("Failed to load openssl API\n");
			return -1;
		}

		if (load_tls_mgm_api(&tls_api) != 0) {
			LM_ERR("failed to load tls_mgm API!\n");
			return -1;
		}

		#if AMQP_VERSION < AMQP_VERSION_CODE(0, 10, 0, 0)
		ssl_lock = lock_alloc();
		if (!ssl_lock) {
			LM_ERR("No more shm memory\n");
			return -1;
		}
		if (!lock_init(ssl_lock)) {
			LM_ERR("Failed to init lock\n");
			return -1;
		}
		#endif

		amqp_set_initialize_ssl_library(0);
	}

	return 0;
}

static int child_init(int rank)
{
	if (rmq_init_writer() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}

	rmq_connect_servers();

	return 0;
}

/*
 * destroy function
 */
static void mod_destroy(void)
{
	LM_NOTICE("destroy module ...\n");
	/* closing sockets */
	rmq_destroy_pipe();

	#if AMQP_VERSION < AMQP_VERSION_CODE(0, 10, 0, 0)
	lock_destroy(ssl_lock);
	lock_dealloc(ssl_lock);
	#endif
}


static int rmq_raise(struct sip_msg *msg, str* ev_name, evi_reply_sock *sock,
	evi_params_t *params, evi_async_ctx_t *async_ctx)
{
	rmq_send_t *rmqs;
	str buf;

	if (!sock || !(sock->flags & RMQ_FLAG)) {
		LM_ERR("invalid socket type\n");
		return -1;
	}
	/* sanity checks */
	if ((sock->flags & (EVI_ADDRESS|EVI_PORT|EVI_PARAMS)) !=
			(EVI_ADDRESS|EVI_PORT|EVI_PARAMS) ||
			!sock->port || !sock->address.len || !sock->address.s) {
		LM_ERR("socket doesn't have enough details\n");
		return -1;
	}

	buf.s = evi_build_payload(params, ev_name, 0, NULL, NULL);
	if (!buf.s) {
		LM_ERR("Failed to build event payload %.*s\n", ev_name->len, ev_name->s);
		return -1;
	}
	buf.len = strlen(buf.s);


	rmqs = shm_malloc(sizeof(rmq_send_t) + buf.len + 1);
	if (!rmqs) {
		LM_ERR("no more shm memory\n");
		evi_free_payload(buf.s);
		return -1;
	}
	memcpy(rmqs->msg, buf.s, buf.len + 1);
	evi_free_payload(buf.s);

	rmqs->sock = sock;
	rmqs->async_ctx = *async_ctx;

	if (rmq_send(rmqs) < 0) {
		LM_ERR("cannot send message\n");
		return -1;
	}

	LM_NOTICE("Sent message successfully: %s\n", rmqs->msg);

	return 0;
}

static inline int dupl_string(str* dst, const char* begin, const char* end)
{
	str tmp;
	if (dst->s)
		shm_free(dst->s);

	tmp.s = (char *)begin;
	tmp.len = end - begin;

	dst->s = shm_malloc(end - begin + 1);
	if (!dst->s) {
		LM_ERR("no more shm memory\n");
		return -1;
	}

	if (un_escape(&tmp, dst) < 0)
		return -1;

	/* NULL-terminate the string */
	dst->s[dst->len] = 0;
	dst->len++;

	return 0;
}

/*
 * This is the parsing function
 * The socket grammar should be:
 * 		 [user [':' password] '@'] ip [':' port] '/' [ exchange ?] routing_key
 */
static evi_reply_sock* rmq_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	rmq_params_t *param;
	unsigned int len, i;
	const char* begin;
	str s, tmp;
	csv_record *p_list = NULL, *it;
	str prev_token;

	enum state {
		ST_USER_HOST,	/* Username or hostname */
		ST_PASS_PORT,	/* Password or port part */
		ST_HOST,		/* Hostname part */
		ST_PORT,		/* Port part */
		ST_ROUTE_OR_PARAMS 	/* Routing key or extra params */
	} st;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	sock = shm_malloc(sizeof(evi_reply_sock) + sizeof(rmq_params_t));
	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}
	memset(sock, 0, sizeof(evi_reply_sock) + sizeof(rmq_params_t));
	param = (rmq_params_t*)(sock + 1);

	prev_token.s = 0;
	prev_token.len = 0;

	/* Initialize all attributes to 0 */
	st = ST_USER_HOST;
	begin = socket.s;
	len = socket.len;

	for(i = 0; i < len; i++) {
		switch(st) {
		case ST_USER_HOST:
			switch(socket.s[i]) {
			case '@':
				st = ST_HOST;
				if (dupl_string(&tmp, begin, socket.s + i)) goto err;
				memcpy(param->conn.uri.user, tmp.s, tmp.len);
				param->conn.uri.user[tmp.len] = '\0';
				begin = socket.s + i + 1;
				param->conn.flags |= RMQ_PARAM_USER;
				break;

			case ':':
				st = ST_PASS_PORT;
				if (dupl_string(&prev_token, begin, socket.s + i) < 0) goto err;
				begin = socket.s + i + 1;
				break;

			case '/':
				if (dupl_string(&sock->address, begin, socket.s + i) < 0)
					goto err;
				sock->flags |= EVI_ADDRESS;
				st = ST_ROUTE_OR_PARAMS;
				begin = socket.s + i + 1;
			}
			break;

		case ST_PASS_PORT:
			switch(socket.s[i]) {
			case '@':
				st = ST_HOST;
				memcpy(param->conn.uri.user, prev_token.s, prev_token.len);
				param->conn.flags |= RMQ_PARAM_USER;
				prev_token.s = 0;
				if (dupl_string(&tmp, begin, socket.s + i) < 0)
					goto err;
				memcpy(param->conn.uri.password, tmp.s, tmp.len);
				param->conn.flags |= RMQ_PARAM_PASS;
				begin = socket.s + i + 1;
				break;

			case '/':
				sock->address.len = prev_token.len;
				sock->address.s = prev_token.s;
				prev_token.s = 0;
				sock->flags |= EVI_ADDRESS;

				sock->port = str2s(begin, socket.s + i - begin, 0);
				if (!sock->port) {
					LM_DBG("malformed port: %.*s\n",
							(int)(socket.s + i - begin), begin);
					goto err;
				}
				sock->flags |= EVI_PORT;
				st = ST_ROUTE_OR_PARAMS;
				begin = socket.s + i + 1;
			}
			break;

		case ST_HOST:
			switch(socket.s[i]) {
			case ':':
				st = ST_PORT;
				if (dupl_string(&sock->address, begin, socket.s + i) < 0)
					goto err;
				sock->flags |= EVI_ADDRESS;
				begin = socket.s + i + 1;
				break;

			case '/':
				if (dupl_string(&sock->address, begin, socket.s + i) < 0)
					goto err;
				sock->flags |= EVI_ADDRESS;

				st = ST_ROUTE_OR_PARAMS;
				begin = socket.s + i + 1;
			}
			break;

		case ST_PORT:
			switch(socket.s[i]) {
			case '/':
				sock->port = str2s(begin, socket.s + i - begin, 0);
				if (!sock->port) {
					LM_DBG("malformed port: %.*s\n",
							(int)(socket.s + i - begin), begin);
					goto err;
				}
				sock->flags |= EVI_PORT;

				st = ST_ROUTE_OR_PARAMS;
				begin = socket.s + i + 1;
			}
			break;

		case ST_ROUTE_OR_PARAMS:
			switch(socket.s[i]) {
			case '?':
				s.s = (char*)begin;
				s.len = socket.s + i - begin;

				p_list = __parse_csv_record(&s, 0, ';');
				if (!p_list) {
					LM_ERR("bad extra parameters: %.*s\n", s.len, s.s);
					goto err;
				}
				for (it = p_list; it; it = it->next)
					if (it->s.len > RMQ_EXCHANGE_LEN &&
						!memcmp(it->s.s, RMQ_EXCHANGE_S, RMQ_EXCHANGE_LEN)) {
						if (dupl_string(&tmp, it->s.s+RMQ_EXCHANGE_LEN,
							it->s.s + it->s.len) < 0)
							goto err;
						memcpy((char *)param->conn.exchange.bytes, tmp.s, tmp.len);
						param->conn.exchange.len = tmp.len;
						param->conn.flags |= RMQ_PARAM_EKEY;
					} else if (it->s.len > RMQ_TLS_DOM_LEN &&
						!memcmp(it->s.s, RMQ_TLS_DOM_S, RMQ_TLS_DOM_LEN)) {
						if (dupl_string(&param->conn.tls_dom_name,
							it->s.s+RMQ_TLS_DOM_LEN, it->s.s + it->s.len) < 0)
							goto err;
						param->conn.tls_dom_name.len--;
						param->conn.flags |= RMQ_PARAM_TLS;
					} else if (it->s.len == RMQ_PERSISTENT_LEN &&
						!memcmp(it->s.s, RMQ_PERSISTENT_S, RMQ_PERSISTENT_LEN)) {
						param->conn.flags |= RMQF_NOPER;
					} else {
						LM_WARN("unknown extra parameter: '%.*s'\n", it->s.len, it->s.s);
						goto err;
					}

				free_csv_record(p_list);

				if (dupl_string(&param->routing_key, socket.s + i + 1, socket.s + len) < 0)
					goto err;
				param->conn.flags |= RMQF_MAND;


				goto success;
			}
			if(i == len - 1){
				if (dupl_string(&param->routing_key, begin, socket.s + len) < 0)
					goto err;

				param->conn.flags |= RMQF_MAND;
				goto success;
			}
			break;
				
		}
	}
	LM_WARN("not implemented %.*s\n", socket.len, socket.s);
	goto err;

success:
	if (!(sock->flags & EVI_PORT) || !sock->port) {
		if (param->conn.flags & RMQ_PARAM_TLS)
			sock->port = RMQ_DEFAULT_TLS_PORT;
		else
			sock->port = RMQ_DEFAULT_PORT;
		sock->flags |= EVI_PORT;
	}
	if (!(param->conn.flags & RMQ_PARAM_USER) || !param->conn.uri.user) {
		param->conn.uri.user = shm_malloc(rmq_static_holder.len);
		if (!param->conn.uri.user) {
			goto err;
		}
		memcpy(param->conn.uri.user, rmq_static_holder.s, rmq_static_holder.len);
		param->conn.uri.password = param->conn.uri.user;
		param->conn.flags |= RMQ_PARAM_USER|RMQ_PARAM_PASS;
	}

	if ((param->conn.flags & RMQ_PARAM_TLS) && !use_tls) {
		LM_ERR("'use_tls' module parameter required for TLS support\n");
		goto err;
	}

	param->conn.heartbeat = heartbeat;
	sock->params = param;
	sock->flags |= EVI_PARAMS | RMQ_FLAG | EVI_ASYNC_STATUS;

	return sock;
err:
	LM_ERR("error while parsing socket %.*s\n", socket.len, socket.s);
	if (prev_token.s)
		shm_free(prev_token.s);
	rmq_free_param(param);
	free_csv_record(p_list);
	if (sock->address.s)
		shm_free(sock->address.s);
	shm_free(sock);
	return NULL;
}


/* returns 0 if sockets don't match */
static int rmq_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	rmq_params_t *p1, *p2;
	/* sock flags */
	if (!sock1 || !sock2 ||
			!(sock1->flags & RMQ_FLAG) || !(sock2->flags & RMQ_FLAG) ||
			!(sock1->flags & EVI_PARAMS) || !(sock2->flags & EVI_PARAMS) ||
			!(sock1->flags & EVI_PORT) || !(sock2->flags & EVI_PORT) ||
			!(sock1->flags & EVI_ADDRESS) || !(sock2->flags & EVI_ADDRESS))
		return 0;

	p1 = (rmq_params_t *)sock1->params;
	p2 = (rmq_params_t *)sock2->params;
	if (!p1 || !p2 ||
		!(p1->conn.flags & RMQF_MAND) || !(p2->conn.flags & RMQF_MAND))

		return 0;

	if (sock1->port == sock2->port &&
			sock1->address.len == sock2->address.len &&
			p1->routing_key.len == p2->routing_key.len &&
			strlen(p1->conn.uri.user) == strlen(p2->conn.uri.user) && p1->conn.exchange.len == p2->conn.exchange.len &&
			(p1->conn.uri.user == p2->conn.uri.user || /* trying the static values */
			!memcmp(p1->conn.uri.user, p2->conn.uri.user, strlen(p1->conn.uri.user))) &&
			!memcmp(sock1->address.s, sock2->address.s, sock1->address.len) &&
			!memcmp(p1->routing_key.s, p2->routing_key.s, p1->routing_key.len) &&
			!memcmp(p1->conn.exchange.bytes, p2->conn.exchange.bytes, p1->conn.exchange.len)) {
		LM_DBG("socket matched: %s@%s:%hu/%s\n",
				p1->conn.uri.user, sock1->address.s, sock2->port, p1->routing_key.s);
		return 1;
	}
	return 0;
}

#define DO_PRINT(_s, _l) \
	do { \
		if (rmq_print_s.len + (_l) > rmq_print_len) { \
			int new_len = (rmq_print_s.len + (_l)) * 2; \
			char *new_s = pkg_realloc(rmq_print_s.s, new_len); \
			if (!new_s) { \
				LM_ERR("no more pkg mem to realloc\n"); \
				goto end; \
			} \
			rmq_print_s.s = new_s; \
			rmq_print_len = new_len; \
		} \
		memcpy(rmq_print_s.s + rmq_print_s.len, (_s), (_l)); \
		rmq_print_s.len += (_l); \
	} while (0)

static int rmq_print_len = 0;
static str rmq_print_s = { 0, 0 };

static str rmq_print(evi_reply_sock *sock)
{
	rmq_params_t * param;
	rmq_print_s.len = 0;

	if (!sock) {
		LM_DBG("Nothing to print\n");
		goto end;
	}

	if (!(sock->flags & EVI_PARAMS))
		goto end;

	param = sock->params;
	if (param->conn.flags & RMQ_PARAM_USER) {
		DO_PRINT(param->conn.uri.user, strlen(param->conn.uri.user) - 1 /* skip 0 */);
		DO_PRINT("@", 1);
	}
	if (sock->flags & EVI_ADDRESS)
		DO_PRINT(sock->address.s, sock->address.len - 1);

	DO_PRINT("/", 1); /* needs to be changed if it can print a key without RMQ_PARAM_RKEY */
	
	if (param->conn.flags & RMQ_PARAM_EKEY) {
		DO_PRINT(param->conn.exchange.bytes, param->conn.exchange.len - 1);
		DO_PRINT("?", 1);
	}

	if (param->conn.flags & RMQF_MAND) {
		DO_PRINT(param->routing_key.s, param->routing_key.len - 1);
	}
end:
	return rmq_print_s;
}
#undef DO_PRINT

static void rmq_free(evi_reply_sock *sock)
{
	rmq_send_t *rmqs = shm_malloc(sizeof(rmq_send_t) + 1);
	if (!rmqs) {
		LM_ERR("no more shm memory\n");
		goto destroy;
	}
	rmqs->sock = sock;
	rmqs->msg[0] = 0;

	if (rmq_send(rmqs) < 0) {
		LM_ERR("cannot send message\n");
		goto destroy;
	}
	return;
destroy:
	if (rmqs)
		shm_free(rmqs);
	rmq_destroy(sock);
}

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}

/*
 * function that simply prints the parameters passed
 */
static int rmq_publish(struct sip_msg *msg, struct rmq_server *srv, str *srkey,
			str *sbody, str *sctype, pv_spec_t *hnames, pv_spec_t *hvals)
{
	int aname, avals;
	unsigned short type;

	if (hnames && !hvals) {
		LM_ERR("header names without values!\n");
		return -1;
	}
	if (!hnames && hvals) {
		LM_ERR("header values without names!\n");
		return -1;
	}

	if (hnames &&
			pv_get_avp_name(msg, &hnames->pvp, &aname, &type) < 0) {
		LM_ERR("cannot resolve names AVP\n");
		return -1;
	}

	if (hvals &&
			pv_get_avp_name(msg, &hvals->pvp, &avals, &type) < 0) {
		LM_ERR("cannot resolve values AVP\n");
		return -1;
	}

	/* resolve the AVP */
	return rmq_send_rm(srv, srkey, sbody, sctype,
			(hnames ? &aname : NULL),
			(hvals ? &avals : NULL)) == 0 ? 1: -1;
}
