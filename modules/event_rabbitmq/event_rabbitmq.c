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
#include "event_rabbitmq.h"
#include "rabbitmq_send.h"
#include <string.h>



/**
 * module functions
 */
static int mod_init(void);
static int child_init(int);
static void destroy(void);

/**
 * module parameters
 */
static unsigned int heartbeat = 0;
extern unsigned rmq_sync_mode;
static int rmq_connect_timeout = RMQ_DEFAULT_CONNECT_TIMEOUT;
struct timeval conn_timeout_tv;

/**
 * exported functions
 */
static evi_reply_sock* rmq_parse(str socket);
static int rmq_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params);
static int rmq_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void rmq_free(evi_reply_sock *sock);
static str rmq_print(evi_reply_sock *sock);

/* sending process */
static proc_export_t procs[] = {
	{"RabbitMQ sender",  0,  0, rmq_process, 1, 0},
	{0,0,0,0,0,0}
};

/* module parameters */
static param_export_t mod_params[] = {
	{"heartbeat",					INT_PARAM, &heartbeat},
	{"sync_mode",		INT_PARAM, &rmq_sync_mode},
	{"connect_timeout", INT_PARAM, &rmq_connect_timeout},
	{0,0,0}
};

/**
 * module exports
 */
struct module_exports exports= {
	"event_rabbitmq",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,            /* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	mod_params,							/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,			 				/* exported transformations */
	procs,						/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};


/**
 * exported functions for core event interface
 */
static evi_export_t trans_export_rmq = {
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

	return 0;
}

static int child_init(int rank)
{
	if (rmq_init_writer() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}
	return 0;
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
			!(p1->flags & RMQ_PARAM_RKEY) || !(p2->flags & RMQ_PARAM_RKEY))
		return 0;

	if (sock1->port == sock2->port &&
			sock1->address.len == sock2->address.len &&
			p1->routing_key.len == p2->routing_key.len &&
			p1->user.len == p2->user.len && p1->exchange.len == p2->exchange.len &&
			(p1->user.s == p2->user.s || /* trying the static values */
			!memcmp(p1->user.s, p2->user.s, p1->user.len)) &&
			!memcmp(sock1->address.s, sock2->address.s, sock1->address.len) &&
			!memcmp(p1->routing_key.s, p2->routing_key.s, p1->routing_key.len) && 
			!memcmp(p1->exchange.s, p2->exchange.s, p1->exchange.len)) {
		LM_DBG("socket matched: %s@%s:%hu/%s\n",
				p1->user.s, sock1->address.s, sock2->port, p1->routing_key.s);
		return 1;
	}
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
	str prev_token;

	enum state {
		ST_USER_HOST,	/* Username or hostname */
		ST_PASS_PORT,	/* Password or port part */
		ST_HOST,		/* Hostname part */
		ST_PORT,		/* Port part */
		ST_ROUTE_OR_EXPORT 	/* Routing or export key */
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
				if (dupl_string(&param->user, begin, socket.s + i)) goto err;
				begin = socket.s + i + 1;
				param->flags |= RMQ_PARAM_USER;
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
				st = ST_ROUTE_OR_EXPORT;
				begin = socket.s + i + 1;
			}
			break;

		case ST_PASS_PORT:
			switch(socket.s[i]) {
			case '@':
				st = ST_HOST;
				param->user.len = prev_token.len;
				param->user.s = prev_token.s;
				param->flags |= RMQ_PARAM_USER;
				prev_token.s = 0;
				if (dupl_string(&param->pass, begin, socket.s + i) < 0)
					goto err;
				param->flags |= RMQ_PARAM_PASS;
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
				st = ST_ROUTE_OR_EXPORT;
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

				st = ST_ROUTE_OR_EXPORT;
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

				st = ST_ROUTE_OR_EXPORT;
				begin = socket.s + i + 1;
			}
			break;

		case ST_ROUTE_OR_EXPORT:
			switch(socket.s[i]) {
			case '?':

				if (dupl_string(&param->exchange, begin, socket.s + i) < 0)
					goto err;
				param->flags |= RMQ_PARAM_EKEY;

				if (dupl_string(&param->routing_key, socket.s + i + 1, socket.s + len) < 0)
					goto err;
				param->flags |= RMQ_PARAM_RKEY;

				goto success;
			}
			if(i == len - 1){
				if (dupl_string(&param->routing_key, begin, socket.s + len) < 0)
					goto err;

				param->flags |= RMQ_PARAM_RKEY;
				goto success;
			}
			break;
				
		}
	}
	LM_WARN("not implemented %.*s\n", socket.len, socket.s);
	goto err;

success:
	if (!(sock->flags & EVI_PORT) || !sock->port) {
		sock->port = RMQ_DEFAULT_PORT;
		sock->flags |= EVI_PORT;
	}
	if (!(param->flags & RMQ_PARAM_USER) || !param->user.s) {
		param->user = param->pass = rmq_static_holder;
		param->flags |= RMQ_PARAM_USER|RMQ_PARAM_PASS;
	}

	param->heartbeat = heartbeat;
	sock->params = param;
	sock->flags |= EVI_PARAMS | RMQ_FLAG;

	return sock;
err:
	LM_ERR("error while parsing socket %.*s\n", socket.len, socket.s);
	if (prev_token.s)
		shm_free(prev_token.s);
	rmq_free_param(param);
	if (sock->address.s)
		shm_free(sock->address.s);
	shm_free(sock);
	return NULL;
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
	if (param->flags & RMQ_PARAM_USER) {
		DO_PRINT(param->user.s, param->user.len - 1 /* skip 0 */);
		DO_PRINT("@", 1);
	}
	if (sock->flags & EVI_ADDRESS)
		DO_PRINT(sock->address.s, sock->address.len - 1);

	DO_PRINT("/", 1); /* needs to be changed if it can print a key without RMQ_PARAM_RKEY */
	
	if (param->flags & RMQ_PARAM_EKEY) {
		DO_PRINT(param->exchange.s, param->exchange.len - 1);
		DO_PRINT("?", 1);
	}

	if (param->flags & RMQ_PARAM_RKEY) {
		DO_PRINT(param->routing_key.s, param->routing_key.len - 1);
	}
end:
	return rmq_print_s;
}
#undef DO_PRINT

static int rmq_raise(struct sip_msg *msg, str* ev_name,
					 evi_reply_sock *sock, evi_params_t * params)
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

	if (rmq_send(rmqs) < 0) {
		LM_ERR("cannot send message\n");
		return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module ...\n");
	/* closing sockets */
	rmq_destroy_pipe();
}

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


