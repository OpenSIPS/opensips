/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 *  2012-05-xx  created (razvancrainea)
 */

#include "../../sr_module.h"
#include "../../resolve.h"
#include "../../evi/evi_transport.h"
#include "../../ut.h"
#include "event_xmlrpc.h"
#include "xmlrpc_send.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern unsigned xmlrpc_struct_on;
extern unsigned xmlrpc_sync_mode;

/**
 * module functions
 */
static int mod_init(void);
static void destroy(void);
static int child_init(int);

/**
 * exported functions
 */
static evi_reply_sock* xmlrpc_parse(str socket);
static int xmlrpc_raise(struct sip_msg *msg, str* ev_name,
						evi_reply_sock *sock, evi_params_t * params);
static int xmlrpc_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static void xmlrpc_free(evi_reply_sock *sock);
static str xmlrpc_print(evi_reply_sock *sock);

/**
 * module process
 */
static proc_export_t procs[] = {
	{"XML-RPC sender",  0,  0, xmlrpc_process, 1, 0},
	{0,0,0,0,0,0}
};

/* module parameters */
static param_export_t mod_params[] = {
	{"use_struct_param",		INT_PARAM, &xmlrpc_struct_on},
	{"sync_mode",		INT_PARAM, &xmlrpc_sync_mode},
	{0,0,0}
};

/**
 * module exports
 */
struct module_exports exports = {
	"event_xmlrpc",				/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,						/* OpenSIPS module dependencies */
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
static evi_export_t trans_export_xmlrpc = {
	XMLRPC_STR,					/* transport module name */
	xmlrpc_raise,				/* raise function */
	xmlrpc_parse,				/* parse function */
	xmlrpc_match,				/* sockets match function */
	xmlrpc_free,				/* free function */
	xmlrpc_print,				/* print function */
	XMLRPC_FLAG					/* flags */
};

static int child_init(int rank) {
	if (xmlrpc_init_writer() < 0) {
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

	if (register_event_mod(&trans_export_xmlrpc)) {
		LM_ERR("cannot register transport functions for XMLRPC\n");
		return -1;
	}

	if (xmlrpc_create_pipe() < 0) {
		LM_ERR("cannot create communication pipe\n");
		return -1;
	}

	if (xmlrpc_init_buffers() < 0) {
		LM_ERR("cannot initiate buffer\n");
		return -1;
	}

	return 0;
}

/* returns 0 if sockets match */
static int xmlrpc_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	str *m1, *m2;
	unsigned needed_flags = XMLRPC_FLAG|EVI_PORT|EVI_PARAMS|EVI_ADDRESS;
	if (!sock1 || !sock2)
		return 0;
	/* check for similar flags */
	if ((sock1->flags & needed_flags) != needed_flags ||
			(sock2->flags & needed_flags) != needed_flags) {
		return 0;
	}
	m1 = (str *)&sock1->params;
	m2 = (str *)&sock2->params;
	if (sock1->port != sock2->port ||
			m1->len != m2->len ||
			sock1->address.len != sock2->address.len ||
			memcmp(m1->s, m2->s, m1->len) ||
			memcmp(sock1->address.s, sock2->address.s, sock1->address.len)) {
		return 0;
	}
	return 1;
}


/*
 * This is the parsing function
 * The socket grammar should be:
 * 		 ip ':' port '/optional/path' ':' method
 */
static evi_reply_sock* xmlrpc_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	unsigned short port = 0;
	char *p = NULL;
	str host, path=str_init(NULL);
	struct hostent *hentity;
	int len;
	struct xmlrpc_sock_param *params;

	int http_buf_len=0;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	if (!(params=shm_malloc(sizeof(struct xmlrpc_sock_param)))) {
		LM_ERR("no more pkg mem!\n");
		return NULL;
	}
	memset(params, 0, sizeof(struct xmlrpc_sock_param));

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

	LM_DBG("host is %.*s - remains <%.*s>[%d]\n", host.len, host.s,
			socket.len, socket.s, socket.len);

	if (!socket.len || *socket.s == '\0') {
		LM_ERR("invalid port number\n");
		return NULL;
	}

	p = memchr(socket.s, COLON_C, socket.len);
	if (!p || p == socket.s) {
		LM_ERR("method not specified <%.*s>\n", socket.len, socket.s);
		return NULL;
	}

	port = str2s(socket.s, p - socket.s, 0);
	if (port == 0) {
		/* most probably we've got path */
		if ((path.s=(q_memchr(socket.s, SLASH_C, p-socket.s)))==NULL) {
			LM_ERR("malformed port: %.*s\n",(int)(p - socket.s), socket.s);
			return NULL;
		} else {
			port=str2s(socket.s, path.s-socket.s, 0);
			if (port == 0) {
				LM_ERR("malformed port: %.*s\n",(int)(p - socket.s), socket.s);
				return NULL;
			}

			path.len = p - path.s;

			socket.len -= ((path.s+path.len)-socket.s);
			socket.s = path.s+path.len;
		}

		/* will use this later for allocation */
		http_buf_len=LENOF(XMLRPC_HTTP_METHOD) +  path.len +
			LENOF(XMLRPC_HTTP_PROTO_HOST);
	}

	/* jump over ':' */
	socket.len = socket.len - (p - socket.s + 1);
	socket.s = p + 1;

	LM_DBG("port is %hu - remains <%.*s>[%d]\n",
			port, socket.len, socket.s, socket.len);

	if (socket.len <= 0 || *socket.s == '\0') {
		LM_ERR("invalid method name\n");
		return NULL;
	}

	len = sizeof(evi_reply_sock) + host.len
		+ sizeof(struct xmlrpc_sock_param)
		+ socket.len /* this is method */+ http_buf_len;
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



	/* copy parameters: path and method */
	params = (struct xmlrpc_sock_param*)(sock->address.s + host.len);
	params->method.s = (char*)(params+1);

	memcpy(params->method.s, socket.s, socket.len);
	params->method.len = socket.len;

	if (http_buf_len) {
		/* build only once; not for every message */
		params->first_line.s = (char*)(params->method.s+socket.len);

		memcpy(params->method.s, socket.s, socket.len);

		params->first_line.len = 0;

		memcpy(params->first_line.s,
				XMLRPC_HTTP_METHOD, LENOF(XMLRPC_HTTP_METHOD));
		params->first_line.len = LENOF(XMLRPC_HTTP_METHOD);

		memcpy(params->first_line.s+params->first_line.len, path.s, path.len);
		params->first_line.len += path.len;

		memcpy(params->first_line.s+params->first_line.len, XMLRPC_HTTP_PROTO_HOST,
				LENOF(XMLRPC_HTTP_PROTO_HOST));
		params->first_line.len += LENOF(XMLRPC_HTTP_PROTO_HOST);
	} else {
		params->first_line.s = XMLRPC_HTTP_CONST;
		params->first_line.len = LENOF(XMLRPC_HTTP_CONST);
	}



	sock->flags |= EVI_PARAMS;

	/* needs expire */
	sock->flags |= EVI_EXPIRE|XMLRPC_FLAG;

	sock->params= params;

	return sock;
error:
	if (sock)
		shm_free(sock);
	return NULL;
}

#define DO_PRINT(_s, _l) \
	do { \
		if (xmlrpc_print_s.len + (_l) > xmlrpc_print_len) { \
			int new_len = (xmlrpc_print_s.len + (_l)) * 2; \
			char *new_s = pkg_realloc(xmlrpc_print_s.s, new_len); \
			if (!new_s) { \
				LM_ERR("no more pkg mem to realloc\n"); \
				goto end; \
			} \
			xmlrpc_print_s.s = new_s; \
			xmlrpc_print_len = new_len; \
		} \
		memcpy(xmlrpc_print_s.s + xmlrpc_print_s.len, (_s), (_l)); \
		xmlrpc_print_s.len += (_l); \
	} while (0)

static int xmlrpc_print_len = 0;
static str xmlrpc_print_s = { 0, 0 };

static str xmlrpc_print(evi_reply_sock *sock)
{
	str aux;
	struct xmlrpc_sock_param *params;

	xmlrpc_print_s.len = 0;

	if (!sock) {
		LM_DBG("Nothing to print\n");
		goto end;
	}
	params = sock->params;

	if (sock->flags & EVI_ADDRESS)
		DO_PRINT(sock->address.s, sock->address.len);

	if (sock->flags & EVI_PORT) {
		DO_PRINT(":", 1);
		aux.s = int2str(sock->port, &aux.len);
		DO_PRINT(aux.s, aux.len);
	}

	if (sock->flags & EVI_PARAMS) {
		DO_PRINT(":", 1);
		DO_PRINT(params->method.s, params->method.len);
	}

end:
	return xmlrpc_print_s;
}
#undef DO_PRINT


static int xmlrpc_raise(struct sip_msg *dummy_msg, str* ev_name,
						evi_reply_sock *sock, evi_params_t * params)
{
	xmlrpc_send_t * msg = NULL;

	if (!sock) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & XMLRPC_FLAG)) {
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
	if (!(sock->flags & EVI_PARAMS)) {
		LM_ERR("no method found\n");
		return -1;
	}

	if (xmlrpc_build_buffer(ev_name, sock, params, &msg) ) {
		LM_ERR("cannot create send buffer\n");
		return -1;
	}

	if (xmlrpc_send(msg) < 0) {
		LM_ERR("cannot send message\n");
		return -1;
	}

	return 0;
}

static void xmlrpc_free(evi_reply_sock *sock)
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
	xmlrpc_destroy_pipe();
}
