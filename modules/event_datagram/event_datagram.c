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
/* send buffer */
static char dgram_buffer[DGRAM_BUFFER_SIZE];
static int dgram_buffer_len;

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
static int datagram_raise(str* ev_name, evi_reply_sock *sock,
		evi_params_t * params);
static int datagram_match(evi_reply_sock *sock1, evi_reply_sock *sock2);

/**
 * module exports
 */
struct module_exports exports= {
	"event_datagram",				/* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* exported functions */
	0,							/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init					/* per-child init function */
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
	DGRAM_UDP_FLAG				/* flags */
};

static evi_export_t trans_export_unix = {
	UNIX_STR,					/* transport module name */
	datagram_raise,				/* raise function */
	datagram_parse_unix,		/* parse function */
	datagram_match,				/* sockets match function */
	0,							/* no free function */
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

#define DO_COPY(buff, str, len) \
	do { \
		if ((buff) - dgram_buffer + 1 > DGRAM_BUFFER_SIZE) { \
			LM_ERR("buffer too small\n"); \
			return -1; \
		} \
		memcpy((buff), (str), (len)); \
		buff += (len); \
	} while (0)

/* builds parameters list */
static int datagram_build_params(str* ev_name, evi_params_p ev_params)
{
	evi_param_p node;
	int len;
	char *buff, *int_s, *p, *end, *old;
	char quote = QUOTE_C, esc = ESC_C;

	if (ev_params && ev_params->flags & (DGRAM_UDP_FLAG | DGRAM_UNIX_FLAG)) {
		LM_DBG("buffer already built\n");
		return dgram_buffer_len;
	}

	dgram_buffer_len = 0;
	
	/* first is event name - cannot be larger than the buffer size */
	memcpy(dgram_buffer, ev_name->s, ev_name->len);
	dgram_buffer[ev_name->len] = PARAM_SEP;
	buff = dgram_buffer + ev_name->len + 1;
	dgram_buffer_len = ev_name->len + 1;

	if (!ev_params)
		goto end;

	for (node = ev_params->first; node; node = node->next) {
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
		*buff = PARAM_SEP;
		buff++;
	}

end:
	*buff = PARAM_SEP;
	buff++;

	/* set buffer len */
	dgram_buffer_len = buff - dgram_buffer;
	if (ev_params)
		ev_params->flags |= (DGRAM_UDP_FLAG | DGRAM_UNIX_FLAG);

	return dgram_buffer_len;
}


static int datagram_raise(str* ev_name, evi_reply_sock *sock,
		evi_params_t *params)
{
	if (!sock || !(sock->flags & EVI_SOCKET)) {
		LM_ERR("no socket found\n");
		return -1;
	}

	/* check the socket type */
	if (!(sock->flags & (DGRAM_UDP_FLAG | DGRAM_UNIX_FLAG))) {
		LM_ERR("invalid socket type\n");
		return -1;
	}

	/* build the params list */
	if (datagram_build_params(ev_name, params) < 0) {
		LM_ERR("error while building parameters list\n");
		return -1;
	}

	/* send data */
	if (sock->flags & DGRAM_UDP_FLAG) {
		sendto(sockets.udp_sock, dgram_buffer, dgram_buffer_len, 0,
			&sock->src_addr.udp_addr.s, sizeof(struct sockaddr_in));
	} else {
		sendto(sockets.unix_sock, dgram_buffer, dgram_buffer_len, 0,
			&sock->src_addr.udp_addr.s, sizeof(struct sockaddr_un));
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

