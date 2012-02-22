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
 *  2011-05-xx  created (razvancrainea)
 */

#include "../../sr_module.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "event_rabbitmq.h"
#include "rabbitmq_send.h"
#include <string.h>



/* send buffer */
static char rmq_buffer[RMQ_BUFFER_SIZE];
static int rmq_buffer_len;

/**
 * module functions
 */
static int mod_init(void);
static int child_init(int);
static void destroy(void);

/**
 * exported functions
 */
static evi_reply_sock* rmq_parse(str socket);
static int rmq_raise(str* ev_name, evi_reply_sock *sock,
		evi_params_t * params);
static int rmq_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void rmq_free(evi_reply_sock *sock);

/* sending process */
static proc_export_t procs[] = {
	{"RabbitMQ sender",  0,  0, rmq_process, 1, 0},
	{0,0,0,0,0,0}
};
/**
 * module exports
 */
struct module_exports exports= {
	"event_rabbitmq",			/* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* exported functions */
	0,							/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	procs,						/* extra processes */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init					/* per-child init function */
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
	RMQ_FLAG					/* flags */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_rmq)) {
		LM_ERR("cannot register transport functions for RabbitMQ\n");
		return -1;
	}

	if (rmq_create_pipe() < 0) {
		LM_ERR("cannot create communication pipe\n");
		return -1;
	}

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
			!(p1->flags & RMQ_PARAM_EXCH) || !(p2->flags & RMQ_PARAM_EXCH) ||
			!(p1->flags & RMQ_PARAM_USER) || !(p2->flags & RMQ_PARAM_USER))
		return 0;

	if (sock1->port == sock2->port &&
			sock1->address.len == sock2->address.len &&
			p1->exchange.len == p2->exchange.len &&
			p1->user.len == p2->user.len &&
			(p1->user.s == p2->user.s || /* trying the static values */
			 !memcmp(p1->user.s, p2->user.s, p1->user.len)) &&
			!memcmp(sock1->address.s, sock2->address.s, sock1->address.len) &&
			!memcmp(p1->exchange.s, p2->exchange.s, p1->exchange.len)) {
		LM_DBG("socket matched: %s@%s:%hu/%s\n",
				p1->user.s, sock1->address.s, sock2->port, p1->exchange.s);
		return 1;
	}
	return 0;
}

static inline int dupl_string(str* dst, const char* begin, const char* end)
{
	dst->s = shm_malloc(end - begin + 1);
	if (!dst->s) {
		LM_ERR("no more shm memory\n");
		return -1;
	}

	memcpy(dst->s, begin, end - begin);
	dst->s[end - begin] = 0;
	dst->len = end - begin + 1;
	return 0;
}

/*
 * This is the parsing function
 * The socket grammar should be:
 * 		 [user [':' password '@']] ip [':' port] '/' exchange
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
				if (dupl_string(&param->exchange, socket.s + i + 1, 
							socket.s + len) < 0)
					goto err;
				param->flags |= RMQ_PARAM_EXCH;
				goto success;
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
				if (dupl_string(&param->exchange, socket.s + i + 1, 
							socket.s + len) < 0)
					goto err;
				param->flags |= RMQ_PARAM_EXCH;
				goto success;
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

				if (dupl_string(&param->exchange, socket.s + i + 1, 
							socket.s + len) < 0)
					goto err;
				param->flags |= RMQ_PARAM_EXCH;
				goto success;
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

				if (dupl_string(&param->exchange, socket.s + i + 1, 
							socket.s + len) < 0)
					goto err;
				param->flags |= RMQ_PARAM_EXCH;
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
		param->user.s = param->pass.s = RMQ_DEFAULT_UP;
		param->user.len = param->pass.len = RMQ_DEFAULT_UP_LEN;
		param->flags |= RMQ_PARAM_USER|RMQ_PARAM_PASS;
	}

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

#define DO_COPY(buff, str, len) \
	do { \
		if ((buff) - rmq_buffer + (len) > RMQ_BUFFER_SIZE) { \
			LM_ERR("buffer too small\n"); \
			goto end; \
		} \
		memcpy((buff), (str), (len)); \
		buff += (len); \
	} while (0)

/* builds parameters list */
static int rmq_build_params(str* ev_name, evi_params_p ev_params)
{
	evi_param_p node;
	int len;
	char *buff, *int_s, *p, *end, *old;
	char quote = QUOTE_C, esc = ESC_C;

	if (ev_params && ev_params->flags & RMQ_FLAG) {
		LM_DBG("buffer already built\n");
		return rmq_buffer_len;
	}

	rmq_buffer_len = 0;
	
	/* first is event name - cannot be larger than the buffer size */
	memcpy(rmq_buffer, ev_name->s, ev_name->len);
	rmq_buffer_len = ev_name->len;
	buff = rmq_buffer + ev_name->len;

	if (!ev_params)
		goto end;

	for (node = ev_params->first; node; node = node->next) {
		*buff = PARAM_SEP;
		buff++;

		/* parameter name */
		if (node->name.len && node->name.s) {
			DO_COPY(buff, node->name.s, node->name.len);
			DO_COPY(buff, ATTR_SEP_S, ATTR_SEP_LEN);
		}

		if (node->flags & EVI_STR_VAL) {
			/* it is a string value */
			if (node->val.s.len && node->val.s.s) {
				len++;
				/* check to see if enclose is needed */
				end = node->val.s.s + node->val.s.len;
				for (p = node->val.s.s; p < end; p++)
					if (*p == PARAM_SEP)
						break;
				if (p == end) {
					/* copy the whole buffer */
					DO_COPY(buff, node->val.s.s, node->val.s.len);
				} else {
					DO_COPY(buff, &quote, 1);
					old = node->val.s.s;
					/* search for '"' to escape */
					for (p = node->val.s.s; p < end; p++)
						if (*p == QUOTE_C) {
							DO_COPY(buff, old, p - old);
							DO_COPY(buff, &esc, 1);
							old = p;
						}
					/* copy the rest of the string */
					DO_COPY(buff, old, p - old);
					DO_COPY(buff, &quote, 1);
				}
			}
		} else if (node->flags & EVI_INT_VAL) {
			int_s = int2str(node->val.n, &len);
			DO_COPY(buff, int_s, len);
		} else {
			LM_DBG("unknown parameter type [%x]\n", node->flags);
		}
	}

end:
	/* set buffer end */
	*buff = 0;
	rmq_buffer_len = buff - rmq_buffer + 1;
	if (ev_params)
		ev_params->flags |= RMQ_FLAG;

	return rmq_buffer_len;
}


static int rmq_raise(str* ev_name, evi_reply_sock *sock,
		evi_params_t * params)
{
	rmq_send_t *rmqs;
	int len;

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

	/* check connection */
	/* build the params list */
	if ((len = rmq_build_params(ev_name, params)) < 0) {
		LM_ERR("error while building parameters list\n");
		return -1;
	}
	rmqs = shm_malloc(sizeof(rmq_send_t *) + len);
	if (!rmqs) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memcpy(rmqs->msg, rmq_buffer, len);
	rmqs->sock = sock;

	if (rmq_send(rmqs) < 0) {
		LM_ERR("cannot send message\n");
		shm_free(rmqs);
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
	rmq_send_t *rmqs = shm_malloc(sizeof(rmq_send_t *) + 1);
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
	rmq_destroy(sock);
}

