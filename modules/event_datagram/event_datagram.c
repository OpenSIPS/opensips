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
#include "../../resolve.h"
#include "../../ut.h"
#include "event_datagram.h"
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>


#if !defined(AF_LOCAL)
 #define AF_LOCAL AF_UNIX
#endif
#if !defined(PF_LOCAL)
 #define PF_LOCAL PF_UNIX
#endif


/* unix and udp sockets */
static struct dgram_socks sockets;

/**
 * module functions
 */
static int mod_init(void);
static void destroy(void);
static int child_init(int);

/**
 * exported functions
 */
static evi_reply_sock* datagram_parse_udp(str socket);
static evi_reply_sock* datagram_parse_unix(str socket);
static int datagram_raise(struct sip_msg *msg, str* ev_name,
						  evi_reply_sock *sock, evi_params_t * params);
static int datagram_match(evi_reply_sock *sock1, evi_reply_sock *sock2);
static str datagram_print(evi_reply_sock *sock);

/**
 * module exports
 */
struct module_exports exports= {
	"event_datagram",				/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	NULL,            /* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported asyn functions */
	0,							/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,			 				/* exported transformations */
	0,							/* extra processes */
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
static evi_export_t trans_export_udp = {
	UDP_STR,					/* transport module name */
	datagram_raise,				/* raise function */
	datagram_parse_udp,			/* parse function */
	datagram_match,				/* sockets match function */
	0,							/* no free function */
	datagram_print,				/* socket print function */
	DGRAM_UDP_FLAG				/* flags */
};

static evi_export_t trans_export_unix = {
	UNIX_STR,					/* transport module name */
	datagram_raise,				/* raise function */
	datagram_parse_unix,		/* parse function */
	datagram_match,				/* sockets match function */
	0,							/* no free function */
	datagram_print,				/* socket print function */
	DGRAM_UNIX_FLAG				/* flags */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module ...\n");

	if (register_event_mod(&trans_export_udp)) {
		LM_ERR("cannot register transport functions for UDP\n");
		return -1;
	}

	if (register_event_mod(&trans_export_unix)) {
		LM_ERR("cannot register transport functions for UNIX\n");
		return -1;
	}
	return 0;
}


/* returns 0 if sockets match */
static int datagram_match(evi_reply_sock *sock1, evi_reply_sock *sock2)
{
	if (!sock1 || !sock2)
		return 0;
	/* if the sockets have different types */
	if ((sock1->flags & (DGRAM_UDP_FLAG|DGRAM_UNIX_FLAG)) !=
			(sock2->flags & (DGRAM_UDP_FLAG|DGRAM_UNIX_FLAG)))
		return 0;
	if (((sock1->flags & EVI_PORT) != (sock2->flags & EVI_PORT)) ||
			((sock1->flags & EVI_PORT) && (sock1->port != sock2->port)))
		return 0;

	if (sock1->flags & EVI_ADDRESS && sock2->flags & EVI_ADDRESS) {
		if (!memcmp(sock1->address.s, sock2->address.s,
					sock1->address.len)) {
			LM_DBG("socket matched %.*s:%hu\n", sock1->address.len,
					sock1->address.s, sock1->port);
			return 1;
		}
	}
	return 0;
}


static evi_reply_sock* datagram_parse(str socket, int is_unix)
{
	evi_reply_sock *sock = NULL;
	unsigned short port = 0;
	char *p = NULL, *host = 0;
	int len = 0;
	struct hostent *hentity;

	if (!socket.len || !socket.s) {
		LM_ERR("no socket specified\n");
		return NULL;
	}

	len = socket.len;
	host = socket.s;
	if (!is_unix) {
		p = memchr(host, COLON_C, len);
		if (!p || p == host) {
			LM_ERR("port not specified <%.*s>\n", len, host);
			return NULL;
		}
		port = str2s(p + 1, host + len - p - 1, 0);
		if (port == 0) {
			LM_DBG("malformed port: %.*s\n",
					(int)(host + len - p - 1), p + 1);
			return NULL;
		}
		LM_DBG("port is %d\n", port);
		len = p - host;
	}

	/* host */
	if (!host || len <= 0) {
		LM_ERR("malformed address %s\n", host);
		goto error;
	}
	sock = shm_malloc(sizeof(evi_reply_sock) + len);
	if (!sock) {
		LM_ERR("no more memory for socket\n");
		return NULL;
	}

	memset(sock, 0, sizeof(evi_reply_sock));

	/* only UDP has port */
	if (port) {
		sock->flags = EVI_PORT;
		sock->port = port;

		/* also build sockaddr */
		*p = 0;
		hentity = resolvehost(host, 0);
		if (!hentity) {
			LM_ERR("cannot resolve host %s\n", host);
			goto error;
		}
		if(hostent2su(&sock->src_addr.udp_addr, hentity, 0, port)){
			LM_ERR("failed to resolve %s\n", host);
			goto error;
		}
		/* restore colon */
		*p = COLON_C;
		sock->flags |= EVI_SOCKET | DGRAM_UDP_FLAG;
	} else {
		sock->src_addr.unix_addr.sun_family = AF_LOCAL;
		memcpy(sock->src_addr.unix_addr.sun_path, host, len);
		sock->src_addr.unix_addr.sun_path[len] = 0;
		sock->flags |= EVI_SOCKET | DGRAM_UNIX_FLAG;
	}

	LM_DBG("address is <%.*s>\n", len, host);
	sock->address.s = (char *) (sock + 1);
	sock->address.len = len;
	memcpy(sock->address.s, host, len);
	sock->flags |= EVI_ADDRESS;

	/* needs expire */
	sock->flags |= EVI_EXPIRE;

	return sock;
error:
	if (sock)
		shm_free(sock);
	return NULL;
}

static evi_reply_sock* datagram_parse_udp(str socket)
{
	return datagram_parse(socket, 0);
}

static evi_reply_sock* datagram_parse_unix(str socket)
{
	return datagram_parse(socket, 1);
}

#define DO_PRINT(_s, _l) \
	do { \
		if (datagram_print_s.len + (_l) > datagram_print_len) { \
			int new_len = (datagram_print_s.len + (_l)) * 2; \
			char *new_s = pkg_realloc(datagram_print_s.s, new_len); \
			if (!new_s) { \
				LM_ERR("no more pkg mem to realloc\n"); \
				goto end; \
			} \
			datagram_print_s.s = new_s; \
			datagram_print_len = new_len; \
		} \
		memcpy(datagram_print_s.s + datagram_print_s.len, (_s), (_l)); \
		datagram_print_s.len += (_l); \
	} while (0)

static int datagram_print_len = 0;
static str datagram_print_s = { 0, 0 };

static str datagram_print(evi_reply_sock *sock)
{
	str aux;
	datagram_print_s.len = 0;

	if (!sock) {
		LM_DBG("Nothing to print\n");
		goto end;
	}

	if (sock->flags & EVI_ADDRESS)
		DO_PRINT(sock->address.s, sock->address.len);

	if (sock->flags & EVI_PORT) {
		DO_PRINT(":", 1);
		aux.s = int2str(sock->port, &aux.len);
		DO_PRINT(aux.s, aux.len);
	}

end:
	return datagram_print_s;
}
#undef DO_PRINT

static int datagram_raise(struct sip_msg *msg, str* ev_name,
						  evi_reply_sock *sock, evi_params_t *params)
{
	int ret;
	str buf;

	if (!sock || !(sock->flags & EVI_SOCKET)) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & (DGRAM_UDP_FLAG | DGRAM_UNIX_FLAG))) {
		LM_ERR("invalid socket type\n");
		return -1;
	}

	buf.s = evi_build_payload(params, ev_name, 0, NULL, NULL);
	if (!buf.s) {
		LM_ERR("Failed to build event payload %.*s\n", ev_name->len, ev_name->s);
		return -1;
	}
	buf.len = strlen(buf.s);

	/* send data */
	if (sock->flags & DGRAM_UDP_FLAG) {
		ret = sendto(sockets.udp_sock, buf.s, buf.len, 0,
			&sock->src_addr.udp_addr.s, sizeof(struct sockaddr_in));
	} else {
		ret = sendto(sockets.unix_sock, buf.s, buf.len, 0,
			&sock->src_addr.udp_addr.s, sizeof(struct sockaddr_un));
	}

	evi_free_payload(buf.s);

	if (ret < 0) {
		LM_ERR("Cannot raise datagram event due to %d:%s\n", errno, strerror(errno));
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
	close(sockets.unix_sock);
	close(sockets.udp_sock);
}

static int create_socket(int family)
{
	int flags, sock = socket(family, SOCK_DGRAM, 0);
	if (sock == -1)
		goto error;

	/* Turn non-blocking mode on for sending*/
	flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto close_error;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto close_error;
	}
	return sock;

close_error:
	close(sock);
error:
	return -1;
}

static int child_init(int rank)
{
	LM_DBG("init_child [%d]  pid [%d]\n", rank, getpid());

	/* initialize the unix socket */
	sockets.unix_sock = create_socket(AF_LOCAL);
	if (sockets.unix_sock == -1) {
		LM_ERR("cannot create unix socket: %s\n", strerror(errno));
		return -1;
	}

	/* initilize the udp socket */
	sockets.udp_sock = create_socket(AF_INET);
	if (sockets.udp_sock == -1) {
		LM_ERR("cannot create udp socket: %s\n", strerror(errno));
		goto error;
	}
	return 0;

error:
	close(sockets.unix_sock);
	return -1;
}

