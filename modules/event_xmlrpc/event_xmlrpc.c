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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

/**
 * module functions
 */
static int mod_init(void);
static void destroy(void);

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
	{0,0,0}
};


/**
 * module exports
 */
struct module_exports exports= {
	"event_xmlrpc",				/* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* exported functions */
	mod_params,					/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	procs,						/* extra processes */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	0							/* per-child init function */
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
 * 		 ip ':' port ':' method
 */
static evi_reply_sock* xmlrpc_parse(str socket)
{
	evi_reply_sock *sock = NULL;
	unsigned short port = 0;
	char *p = NULL;
	str host, *method;
	struct hostent *hentity;
	int len;

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
		LM_DBG("malformed port: %.*s\n",(int)(p - socket.s), socket.s);
		return NULL;
	}

	/* skip colon */
	socket.len = socket.len - (p - socket.s + 1);
	socket.s = p + 1;

	LM_DBG("port is %hu - remains <%.*s>[%d]\n",
			port, socket.len, socket.s, socket.len);

	if (socket.len <= 0 || *socket.s == '\0') {
		LM_ERR("invalid method name\n");
		return NULL;
	}

	LM_DBG("method is %.*s[%d]\n", socket.len, socket.s, socket.len);

	len = sizeof(evi_reply_sock) - sizeof(void*) + sizeof(str) +
		host.len + socket.len;
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

	/* copy method  - this should point to same address as params*/
	method = (str *) &sock->params;
	method->s = (char *) (method + 1);
	method->len = socket.len;
	memcpy(method->s, socket.s, socket.len);
	sock->flags |= EVI_PARAMS;

	/* address should point below method name */
	sock->address.s = method->s + method->len;
	sock->address.len = host.len;
	memcpy(sock->address.s, host.s, host.len);
	sock->flags |= EVI_ADDRESS;

	/* needs expire */
	sock->flags |= EVI_EXPIRE|XMLRPC_FLAG;

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
	str aux, *method;

	xmlrpc_print_s.len = 0;

	if (!sock) {
		LM_DBG("Nothing to print");
		goto end;
	}

	if (sock->flags & EVI_ADDRESS)
		DO_PRINT(sock->address.s, sock->address.len);

	if (sock->flags & EVI_PORT) {
		DO_PRINT(":", 1);
		aux.s = int2str(sock->port, &aux.len);
		DO_PRINT(aux.s, aux.len);
	}

	if (sock->flags & EVI_PARAMS) {
		DO_PRINT(":", 1);
		method = (str *) &sock->params;
		DO_PRINT(method->s, method->len);
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
		shm_free(msg);
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
