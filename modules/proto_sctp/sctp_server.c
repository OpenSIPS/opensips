/*
 * Copyright (C) 2015 OpenSIPS Solutions
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * --------
 *  2007-06-22	sctp_server.c created, using udp_server.c as template -gmarmon
 *  2015-02-19 migrated to the new proto interfaces (bogdan)
 */

/*!
 * \file
 * \brief SCTP support
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/sctp.h>
#include <errno.h>
#include <arpa/inet.h>
#ifdef __linux__
	#include <linux/types.h>
	#include <linux/errqueue.h>
#endif

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../net/net_udp.h"
#include "../../socket_info.h"
#include "../../receive.h"
#include "sctp_server.h"

#define LISTEN_BACKLOG 5

int proto_sctp_init_listener(struct socket_info* sock_info)
{
	union sockaddr_union* addr;
	int optval;

	addr=&sock_info->su;
	sock_info->proto=PROTO_SCTP;
	if (init_su(addr, &sock_info->address, sock_info->port_no)<0){
		LM_ERR("could not init sockaddr_union\n");
		goto error;
	}

	sock_info->socket = socket(AF2PF(addr->s.sa_family), SOCK_SEQPACKET,
		IPPROTO_SCTP);
	if (sock_info->socket==-1){
		LM_ERR("socket failed with %s [%d]\n", strerror(errno), errno);
		goto error;
	}

	optval=1;
	if (setsockopt(sock_info->socket, SOL_SOCKET, SO_REUSEADDR ,
					(void*)&optval, sizeof(optval)) ==-1){
		LM_ERR("setsockopt: %s\n", strerror(errno));
		goto error;
	}

#ifdef DISABLE_NAGLE
	/* turns of Nagle-like algorithm/chunk-bundling.*/
	optval=1;
	if (setsockopt(sock_info->socket, IPPROTO_SCTP, SCTP_NODELAY,
				(void*)&optval, sizeof(optval))==-1){
		LM_WARN("setsockopt %s\n", strerror(errno));
	/* continues since this is not critical */
	}
#endif

	/* this sockopt causes a kernel panic in some sctp implementations.
	 * commenting it out. -gmarmon */

	/* tos
	optval=tos;
	if (setsockopt(sock_info->socket, IPPROTO_IP, IP_TOS, (void*)&optval,
			sizeof(optval)) ==-1){
		LM_WARN("setsockopt tos: %s\n", strerror(errno));
	}
    */

#if defined (__linux__) && defined(SCTP_ERRORS)
	/* will SCTP_ERRORS ever be defined? -gmarmon */
	optval=1;
	/* enable error receiving on unconnected sockets */
	if(setsockopt(sock_info->socket, SOL_IP, IP_RECVERR,
		      (void*)&optval, sizeof(optval)) ==-1){
		LM_ERR("setsockopt: %s\n", strerror(errno));
		goto error;
	}
#endif

	/*if ( probe_max_receive_buffer(sock_info->socket)==-1) goto error;
	 */

	if (bind(sock_info->socket, &addr->s, sockaddru_len(*addr))==-1){
		LM_ERR("bind(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s,
				(unsigned)sockaddru_len(*addr),
				sock_info->address_str.s,
				strerror(errno));
		if (addr->s.sa_family==AF_INET6)
			LM_ERR("might be caused by using a link "
					" local address, try site local or global\n");
		goto error;
	}
	if(listen(sock_info->socket, LISTEN_BACKLOG)<0){
		LM_ERR("listen(%x, %d) on %s: %s\n",
				sock_info->socket,
				LISTEN_BACKLOG,
				sock_info->address_str.s,
				strerror(errno));
		goto error;
	}
	return 0;

error:
	return -1;
}


int proto_sctp_read(struct socket_info *si, int* bytes_read)
{
	struct receive_info ri;
	int len;
	static char buf [BUF_SIZE+1];
	char *tmp;
	unsigned int fromlen;
	struct sctp_sndrcvinfo sinfo;

	fromlen=sockaddru_len(si->su);
	len = sctp_recvmsg(si->socket, buf, BUF_SIZE, &ri.src_su.s, &fromlen,
		&sinfo, 0);
	if (len==-1){
		if (errno==EAGAIN){
			LM_DBG("packet with bad checksum received\n");
			return 0;
		}
		if ((errno==EINTR)||(errno==EWOULDBLOCK)|| (errno==ECONNREFUSED))
			return -1;
		LM_ERR("sctp_recvmsg:[%d] %s\n", errno, strerror(errno));
		return -2;
	}

	/* we must 0-term the messages, receive_msg expects it */
	buf[len]=0; /* no need to save the previous char */

	ri.bind_address = si;
	ri.dst_port = si->port_no;
	ri.dst_ip = si->address;
	ri.proto = si->proto;
	ri.proto_reserved1 = ri.proto_reserved2 = 0;

	su2ip_addr(&ri.src_ip, &ri.src_su);
	ri.src_port=su_getport(&ri.src_su);

	if (ri.src_port==0){
		tmp=ip_addr2a(&ri.src_ip);
		LM_INFO("dropping 0 port packet from %s\n", tmp);
		return 0;
	}

	/* receive_msg must free buf too!*/
	receive_msg(buf, len, &ri, NULL, 0);

	return 0;
}


/*! \brief which socket to use? main socket or new one? */
int proto_sctp_send(struct socket_info *source, char *buf, unsigned len,
									union sockaddr_union* to, unsigned int id)
{
	int n;
	int tolen;

	tolen=sockaddru_len(*to);
again:
	n=sctp_sendmsg(source->socket, buf, len, &to->s, tolen, 0, 0, 0, 0, 0);
#ifdef XL_DEBUG
	LM_INFO("send status: %d\n", n);
#endif
	if (n==-1){
		LM_ERR("sctp_sendmsg(sock,%p,%d,%p,%d,0,0,0,0,0): %s(%d)\n",
				buf,len,&to->s,tolen, strerror(errno),errno);

		if (errno==EINTR) goto again;
		if (errno==EINVAL) {
			LM_CRIT("invalid sendtoparameters\n"
			"one possible reason is the server is bound to localhost and\n"
			"attempts to send to the net\n");
		}
	}
	return n;
}

