/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 *
 * History:
 * -------
 *  2015-02-11  first version (bogdan)
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>

#include "../../pt.h"
#include "../../timer.h"
#include "../../socket_info.h"
#include "../../receive.h"
#include "../api_proto.h"
#include "../api_proto_net.h"
#include "../net_udp.h"
#include "proto_udp.h"


static int mod_init(void);
static int proto_udp_init(struct proto_info *pi);
static int proto_udp_init_listener(struct socket_info *si);
static int proto_udp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id);

static int udp_read_req(struct socket_info *src, int* bytes_read);

static callback_list* cb_list = NULL;

static int udp_port = SIP_PORT;


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_udp_init, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};


static param_export_t params[] = {
	{ "udp_port",    INT_PARAM,   &udp_port   },
	{0, 0, 0}
};


struct module_exports proto_udp_exports = {
	PROTO_PREFIX "udp",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};


static int mod_init(void)
{
	LM_INFO("initializing UDP-plain protocol\n");
	return 0;
}


static int proto_udp_init(struct proto_info *pi)
{
	pi->id					= PROTO_UDP;
	pi->name				= "udp";
	pi->default_port		= udp_port;

	pi->tran.init_listener	= proto_udp_init_listener;
	pi->tran.send			= proto_udp_send;

	pi->net.flags			= PROTO_NET_USE_UDP;
	pi->net.read			= (proto_net_read_f)udp_read_req;

	return 0;
}


static int proto_udp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to UDP plain here, so
	 * transparently use the generic listener init from net UDP layer */
	return udp_init_listener(si, O_NONBLOCK);
}


static int udp_read_req(struct socket_info *si, int* bytes_read)
{
	struct receive_info ri;
	int len;
	static char buf [BUF_SIZE+1];
	char *tmp;
	unsigned int fromlen;
	callback_list* p;
	str msg;

	fromlen=sockaddru_len(si->su);
	/* coverity[overrun-buffer-arg: FALSE] - union has 28 bytes, CID #200029 */
	len=recvfrom(bind_address->socket, buf, BUF_SIZE,0,&ri.src_su.s,&fromlen);
	if (len==-1){
		if (errno==EAGAIN)
			return 0;
		if ((errno==EINTR)||(errno==EWOULDBLOCK)|| (errno==ECONNREFUSED))
			return -1;
		LM_ERR("recvfrom:[%d] %s\n", errno, strerror(errno));
		return -2;
	}

	if (len<MIN_UDP_PACKET) {
		LM_DBG("probing packet received len = %d\n", len);
		return 0;
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

	msg.s = buf;
	msg.len = len;

	/* run callbacks if looks like non-SIP message*/
	if( !isalpha(msg.s[0]) ){    /* not-SIP related */
		for(p = cb_list; p; p = p->next){
			if(p->b == msg.s[1]){
				if (p->func(bind_address->socket, &ri, &msg, p->param)==0){
					/* buffer consumed by callback */
					break;
				}
			}
		}
		if (p) return 0;
	}

	if (ri.src_port==0){
		tmp=ip_addr2a(&ri.src_ip);
		LM_INFO("dropping 0 port packet from %s\n", tmp);
		return 0;
	}

	/* receive_msg must free buf too!*/
	receive_msg( msg.s, msg.len, &ri, NULL, 0);

	return 0;
}


/**
 * Main UDP send function, called from msg_send.
 * \see msg_send
 * \param source send socket
 * \param buf sent data
 * \param len data length in bytes
 * \param to destination address
 * \return -1 on error, the return value from sento on success
 */
static int proto_udp_send(struct socket_info* source,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id)
{
	int n, tolen;

	tolen=sockaddru_len(*to);
again:
	n=sendto(source->socket, buf, len, 0, &to->s, tolen);
	if (n==-1){
		if (errno==EINTR || errno==EAGAIN) goto again;
		LM_ERR("sendto(sock,%p,%d,0,%p,%d): %s(%d) [%s:%hu]\n", buf,len,to,
				tolen,strerror(errno),errno,inet_ntoa(to->sin.sin_addr),
				ntohs(to->sin.sin_port));
		if (errno==EINVAL) {
			LM_CRIT("invalid sendtoparameters\n"
			"one possible reason is the server is bound to localhost and\n"
			"attempts to send to the net\n");
		}
	}
	return n;
}


int register_udprecv_cb(udp_rcv_cb_f* func, void* param, char a, char b)
{
	callback_list* new;

	new = (callback_list*) pkg_malloc(sizeof(callback_list));
	if(!new){
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memset(new, 0, sizeof(callback_list));

	new->func = func;
	new->param = param;
	new->a = a;
	new->b = b;
	new->next = NULL;

	if(!cb_list){
		cb_list = new;
	}else{
		new->next = cb_list;
		cb_list = new;
	}

	return 0;
}




