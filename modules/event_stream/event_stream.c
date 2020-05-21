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

#include "../../sr_module.h"
#include "../../resolve.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "event_stream.h"
#include "stream_send.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * module functions
 */
static int mod_init(void);
static void destroy(void);
static int child_init(int);

/**
 * exported functions
 */
static evi_reply_sock* stream_parse(str socket);
static int stream_raise(struct sip_msg *msg, str* ev_name,
						evi_reply_sock *sock, evi_params_t * params);
static int stream_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void stream_free(evi_reply_sock *sock);
static str stream_print(evi_reply_sock *sock);

/**
 * module process
 */
static proc_export_t procs[] = {
	{"event_stream Sender",  0,  0, stream_process, 1, 0},
	{0,0,0,0,0,0}
};

/* module parameters */
static param_export_t mod_params[] = {
	{"sync_mode",		INT_PARAM, &stream_sync_mode},
	{"event_param",		STR_PARAM, &stream_event_param},
	{"timeout",			INT_PARAM, &stream_timeout},
	{0,0,0}
};

/**
 * module exports
 */
struct module_exports exports = {
	"event_stream",				/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,                       /* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	mod_params,					/* exported parameters */
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
static evi_export_t trans_export_stream = {
	TCP_STR,					/* transport module name */
	stream_raise,				/* raise function */
	stream_parse,				/* parse function */
	stream_match,				/* sockets match function */
	stream_free,				/* free function */
	stream_print,				/* print function */
	STREAM_FLAG					/* flags */
};

static int child_init(int rank) {
	if (stream_init_writer() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}
	return 0;
}

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_stream)) {
		LM_ERR("cannot register transport functions for event_stream\n");
		return -1;
	}

	if (stream_init_process() < 0) {
		LM_ERR("cannot initialize external process\n");
		return -1;
	}

	return 0;
}

/* returns 0 if sockets match */
static int stream_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	str *m1, *m2;
	unsigned needed_flags = STREAM_FLAG|EVI_PORT|EVI_ADDRESS;
	if (!sock1 || !sock2)
		return 0;
	/* check for similar flags */
	if ((sock1->flags & needed_flags) != needed_flags ||
			(sock2->flags & needed_flags) != needed_flags) {
		return 0;
	}

	if ((sock1->flags & EVI_PARAMS) != (sock2->flags & EVI_PARAMS))
		return 0;

	if (sock1->port != sock2->port ||
			sock1->address.len != sock2->address.len ||
			memcmp(sock1->address.s, sock2->address.s, sock1->address.len)) {
		return 0;
	}
	if (!sock1->params)
		return 1;
	m1 = (str *)&sock1->params;
	m2 = (str *)&sock2->params;
	if (m1->len != m2->len || memcmp(m1->s, m2->s, m1->len))
		return 0;
	return 1;
}


/*
 * This is the parsing function
 * The socket grammar should be:
 * 		 ip ':' port ['/'method]
 */
static evi_reply_sock* stream_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	unsigned short port = 0;
	char *p = NULL;
	str *method;
	str host;
	struct hostent *hentity;
	int len, err;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	/* extract host */
	host.s = socket.s;
	p = memchr(socket.s, COLON_C, socket.len);
	if (!p || p == socket.s) {
		LM_ERR("port not specified <%.*s>\n", socket.len, socket.s);
		return NULL;
	}
	host.len = p - socket.s;

	/* used to resolve host */
	*p = '\0';
	/* skip colon */
	socket.s += host.len + 1;
	socket.len -= host.len + 1;

	LM_DBG("host is %.*s - remaining <%.*s>[%d]\n", host.len, host.s,
			socket.len, socket.s, socket.len);

	if (!socket.len || *socket.s == '\0') {
		LM_ERR("invalid port number\n");
		return NULL;
	}

	p = memchr(socket.s, SLASH_C, socket.len);
	if (!p) {
		/* if we do not have a method, we use the event's name */
		p = socket.s + socket.len;
	}

	port = str2s(socket.s, p - socket.s, &err);
	if (port == 0 || err != 0) {
		LM_ERR("malformed port: %.*s\n",(int)(p - socket.s), socket.s);
		return NULL;
	}

	/* jump over ':' */
	socket.len = socket.len - (p - socket.s);
	socket.s = p;

	LM_DBG("port is %hu - remains <%.*s>[%d]\n",
			port, socket.len, socket.s, socket.len);

	if (socket.len) {
		/* jump over slash */
		socket.len--;
		socket.s++;
	}

	len = sizeof(evi_reply_sock) + host.len
		+ (socket.len ? sizeof(str) + socket.len /* this is method */: 0);
	sock = shm_malloc(len);
	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}

	memset(sock, 0, len);
	/* only UDP has port */
	sock->flags = EVI_PORT;
	sock->port = port;

	/* also build sockaddr */
	hentity = resolvehost(host.s, 0);
	if (!hentity) {
		LM_ERR("cannot resolve host %s\n", host.s);
		goto error;
	}
	if(hostent2su(&sock->src_addr.udp_addr, hentity, 0, port)){
		LM_ERR("failed to resolve %s\n", host.s);
		goto error;
	}
	sock->flags |= EVI_SOCKET;

	/* address */
	sock->address.s = (char*)(sock+1);
	sock->address.len = host.len;
	memcpy(sock->address.s, host.s, host.len);
	sock->flags |= EVI_ADDRESS;

	if (socket.len) {
		/* copy method, if it exists */
		method = (str *)(sock->address.s + host.len);
		method->s = (char*)(method+1);

		method->len = socket.len;
		memcpy(method->s, socket.s, socket.len);

		sock->params = method;

		sock->flags |= EVI_PARAMS;
	}

	/* needs expire */
	sock->flags |= EVI_EXPIRE|STREAM_FLAG;

	return sock;
error:
	if (sock)
		shm_free(sock);
	return NULL;
}

#define DO_PRINT(_s, _l) \
	do { \
		if (stream_print_s.len + (_l) > stream_print_len) { \
			int new_len = (stream_print_s.len + (_l)) * 2; \
			char *new_s = pkg_realloc(stream_print_s.s, new_len); \
			if (!new_s) { \
				LM_ERR("no more pkg mem to realloc\n"); \
				goto end; \
			} \
			stream_print_s.s = new_s; \
			stream_print_len = new_len; \
		} \
		memcpy(stream_print_s.s + stream_print_s.len, (_s), (_l)); \
		stream_print_s.len += (_l); \
	} while (0)

static int stream_print_len = 0;
static str stream_print_s = { 0, 0 };

static str stream_print(evi_reply_sock *sock)
{
	str aux;
	str *method;

	stream_print_s.len = 0;

	if (!sock) {
		LM_DBG("Nothing to print\n");
		goto end;
	}
	method = (str *)sock->params;

	if (sock->flags & EVI_ADDRESS)
		DO_PRINT(sock->address.s, sock->address.len);

	if (sock->flags & EVI_PORT) {
		DO_PRINT(":", 1);
		aux.s = int2str(sock->port, &aux.len);
		DO_PRINT(aux.s, aux.len);
	}

	if (sock->flags & EVI_PARAMS) {
		DO_PRINT("/", 1);
		DO_PRINT(method->s, method->len);
	}

end:
	return stream_print_s;
}
#undef DO_PRINT


static int stream_raise(struct sip_msg *dummy_msg, str* ev_name,
						evi_reply_sock *sock, evi_params_t * params)
{
	stream_send_t *msg = NULL;
	str socket;
	const char *err_msg;

	if (!sock) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & STREAM_FLAG)) {
		LM_ERR("invalid socket type %x\n", sock->flags);
		return -1;
	}

	/* check to see if a socket was specified */
	if (!(sock->flags & EVI_SOCKET)) {
		LM_ERR("not a valid socket\n");
		return -1;
	}
	if (!(sock->flags & EVI_ADDRESS)) {
		LM_ERR("cannot find destination address\n");
		return -1;
	}

	if (stream_build_buffer(ev_name, sock, params, &msg) < 0) {
		err_msg = "creating send buffer";
		goto error;
	}

	if (stream_send(msg) < 0) {
		err_msg = "raising event";
		goto error;
	}

	return 0;
error:
	socket = stream_print(sock);
	LM_ERR("%s %.*s to %.*s failed!\n", err_msg,
			ev_name->len, ev_name->s, socket.len, socket.s);
	return -1;
}

static void stream_free(evi_reply_sock *sock)
{
	/* nothing special here */
	shm_free(sock);
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module ...\n");
	/* closing sockets */
	stream_destroy_pipe();
}
