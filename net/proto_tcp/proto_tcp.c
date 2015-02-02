/*
 * Copyright (C) 2015 - OpenSIPS Foundation
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2015-01-09  first version (razvanc)
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../tcp_utils.h"
#include "proto_tcp_handler.h"

static int mod_init(void);
static int net_tcp_init(void);
static int net_tcp_api_bind(struct api_proto *proto_binds,
		struct api_proto_net *net_binds);
static int net_tcp_add_listener(struct socket_info *si);
static int net_tcp_bind(struct socket_info *si);
static int net_tcp_recv(void *handler);

#ifdef DISABLE_NAGLE
static int tcp_proto_no=-1; /*!< tcp protocol number as returned by getprotobyname */
#endif

static cmd_export_t cmds[] = {
	{"proto_bind_api", (cmd_function)net_tcp_api_bind, 0, 0, 0, 0},
	{0,0,0,0,0,0}
};


#ifndef DISABLE_AUTO_TCP
struct module_exports proto_tcp_exports = {
#else
struct module_exports exports = {
#endif
	PROTO_PREFIX "tcp",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	0,          /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
};

static int net_tcp_init(void)
{
	LM_INFO("initializing TCP\n");

#ifdef DISABLE_NAGLE
	struct protoent* pe;

	pe=getprotobyname("tcp");
	if (pe==0){
		LM_ERR("could not get TCP protocol number\n");
		tcp_proto_no=-1;
	}else{
		tcp_proto_no=pe->p_proto;
	}
#endif

	return 0;
}


static int mod_init(void)
{
	LM_INFO("initializing...\n");
	return 0;
}

static struct api_proto tcp_proto_binds = {
	.name			= "tcp",
	.default_port	= SIP_PORT,
	.init			= net_tcp_init,
	.add_listener	= net_tcp_add_listener,
};

static struct api_proto_net tcp_proto_net_binds = {
	.id				= PROTO_TCP,
	.flags			= PROTO_NET_USE_TCP,
	.bind			= net_tcp_bind,
	.recv			= net_tcp_recv,
};


static int net_tcp_api_bind(struct api_proto *proto_api,
	struct api_proto_net *proto_net_api)
{
	if (!proto_api || !proto_net_api)
		return -1;
/*
 * TODO: memset + set or simply copy the structures?
	memset(funcs, 0, sizeof(struct proto_funcs));
	funcs.init = net_tcp_init;
 */
	memcpy(proto_api, &tcp_proto_binds, sizeof(struct api_proto));
	memcpy(proto_net_api, &tcp_proto_net_binds,
			sizeof(struct api_proto_net));

	return 0;
}

static int net_tcp_add_listener(struct socket_info *si)
{
	/* there is not that mutch to do for the TCP interface */
	if (tcp_add_listener(si->name.s, si->port_no, PROTO_TCP, NULL) < 0) {
		LM_ERR("cannot add TCP listener\n");
		return -1;
	}
	return 0;
}


static inline int init_sock_keepalive(int s)
{
/* TODO: skip this for now until we solve the parameters problem */
#if 0
	int optval;

	if (tcp_keepinterval || tcp_keepidle || tcp_keepcount) {
		tcp_keepalive = 1; /* force on */
	}

#ifdef HAVE_SO_KEEPALIVE
	if ((optval = tcp_keepalive)) {
		if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
			LM_WARN("init_sock_keepalive: failed to enable SO_KEEPALIVE: %s\n", strerror(errno));
			return -1;
		}
		LM_INFO("-- TCP keepalive enabled on socket\n");
	}
#endif
#ifdef HAVE_TCP_KEEPINTVL
	if ((optval = tcp_keepinterval)) {
		if (setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) < 0) {
			LM_WARN("init_sock_keepalive: failed to set keepalive probes interval: %s\n", strerror(errno));
		}
	}
#endif
#ifdef HAVE_TCP_KEEPIDLE
	if ((optval = tcp_keepidle)) {
		if (setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) < 0) {
			LM_WARN("init_sock_keepalive: failed to set keepalive idle interval: %s\n", strerror(errno));
		}
	}
#endif
#ifdef HAVE_TCP_KEEPCNT
	if ((optval = tcp_keepcount)) {
		if (setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) < 0) {
			LM_WARN("init_sock_keepalive: failed to set maximum keepalive count: %s\n", strerror(errno));
		}
	}
#endif
#endif
	return 0;
}

static int net_tcp_bind(struct socket_info *sock_info)
{
	union sockaddr_union* addr;
	int optval;
#ifdef DISABLE_NAGLE
	int flag;
	struct protoent* pe;

	if (tcp_proto_no==-1){ /* if not already set */
		pe=getprotobyname("tcp");
		if (pe==0){
			LM_ERR("could not get TCP protocol number\n");
			tcp_proto_no=-1;
		}else{
			tcp_proto_no=pe->p_proto;
		}
	}
#endif

	addr=&sock_info->su;
	/* sock_info->proto=PROTO_TCP; */
	if (init_su(addr, &sock_info->address, sock_info->port_no)<0){
		LM_ERR("could no init sockaddr_union\n");
		goto error;
	}
	sock_info->socket=socket(AF2PF(addr->s.sa_family), SOCK_STREAM, 0);
	if (sock_info->socket==-1){
		LM_ERR("socket: %s\n", strerror(errno));
		goto error;
	}
#ifdef DISABLE_NAGLE
	flag=1;
	if ( (tcp_proto_no!=-1) &&
		 (setsockopt(sock_info->socket, tcp_proto_no , TCP_NODELAY,
					 &flag, sizeof(flag))<0) ){
		LM_ERR("could not disable Nagle: %s\n",	strerror(errno));
	}
#endif


#if  !defined(TCP_DONT_REUSEADDR)
	/* Stevens, "Network Programming", Section 7.5, "Generic Socket
	 * Options": "...server started,..a child continues..on existing
	 * connection..listening server is restarted...call to bind fails
	 * ... ALL TCP servers should specify the SO_REUSEADDRE option
	 * to allow the server to be restarted in this situation
	 *
	 * Indeed, without this option, the server can't restart.
	 *   -jiri
	 */
	optval=1;
	if (setsockopt(sock_info->socket, SOL_SOCKET, SO_REUSEADDR,
				(void*)&optval, sizeof(optval))==-1) {
		LM_ERR("setsockopt %s\n", strerror(errno));
		goto error;
	}
#endif
	/* tos */
	optval = tos;
	if (setsockopt(sock_info->socket, IPPROTO_IP, IP_TOS, (void*)&optval,
				sizeof(optval)) ==-1){
		LM_WARN("setsockopt tos: %s\n", strerror(errno));
		/* continue since this is not critical */
	}

	if (probe_max_sock_buff(sock_info->socket,1,MAX_SEND_BUFFER_SIZE,
				BUFFER_INCREMENT))
	{
		LM_WARN("setsockopt tcp snd buff: %s\n",	strerror(errno));
		/* continue since this is not critical */
	}

	init_sock_keepalive(sock_info->socket);
	if (bind(sock_info->socket, &addr->s, sockaddru_len(*addr))==-1){
		LM_ERR("bind(%x, %p, %d) on %s:%d : %s\n",
 				sock_info->socket, &addr->s,
 				(unsigned)sockaddru_len(*addr),
 				sock_info->address_str.s,
				sock_info->port_no,
 				strerror(errno));
		goto error;
	}
	if (listen(sock_info->socket, tcp_listen_backlog)==-1){
		LM_ERR("listen(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s,
				(unsigned)sockaddru_len(*addr),
				sock_info->address_str.s,
				strerror(errno));
		goto error;
	}

	return 0;
error:
	if (sock_info->socket!=-1){
		close(sock_info->socket);
		sock_info->socket=-1;
	}
	return -1;
}

/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also r->error
 */
int proto_tcp_read(struct tcp_connection *c,struct tcp_req *r)
{
	int bytes_free, bytes_read;
	int fd;

	fd=c->fd;
	bytes_free=TCP_BUF_SIZE- (int)(r->pos - r->buf);

	if (bytes_free==0){
		LM_ERR("buffer overrun, dropping\n");
		r->error=TCP_REQ_OVERRUN;
		return -1;
	}
again:
	bytes_read=read(fd, r->pos, bytes_free);

	if(bytes_read==-1){
		if (errno == EWOULDBLOCK || errno == EAGAIN){
			return 0; /* nothing has been read */
		}else if (errno == EINTR) goto again;
		else{
			LM_ERR("error reading: %s\n",strerror(errno));
			r->error=TCP_READ_ERROR;
			return -1;
		}
	}else if (bytes_read==0){
		c->state=S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
	}
#ifdef EXTRA_DEBUG
	LM_DBG("read %d bytes:\n%.*s\n", bytes_read, bytes_read, r->pos);
#endif
	r->pos+=bytes_read;
	return bytes_read;
}

static int net_tcp_recv(void *handler)
{
	return tcp_utils_read_req(handler, proto_tcp_read);
}

