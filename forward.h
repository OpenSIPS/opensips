/*
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
 * History:
 * -------
 *  2001-??-?? created by andrei
 *  ????-??-?? lots of changes by a lot of people
 *  2003-02-11 added inline msg_send (andrei)
 *  2003-04-07 changed all ports to host byte order (andrei)
 *  2003-04-12  FORCE_RPORT_T added (andrei)
 *  2003-04-15  added tcp_disable support (andrei)
 */

/*!
 * \file
 * \brief OpenSIPS Stateless forward support
 */


#ifndef forward_h
#define forward_h

#include "globals.h"
#include "mem/mem.h"
#include "parser/msg_parser.h"
#include "route.h"
#include "proxy.h"
#include "ip_addr.h"
#include "script_cb.h"
#include "sl_cb.h"
#include "net/trans.h"
#include "socket_info.h"

struct socket_info* get_send_socket(struct sip_msg* msg,
									union sockaddr_union* su, int proto);
struct socket_info* get_out_socket(union sockaddr_union* to, int proto);
int check_self(str* host, unsigned short port, unsigned short proto);
int forward_request( struct sip_msg* msg,  struct proxy_l* p);
int update_sock_struct_from_via( union sockaddr_union* to,
								 struct sip_msg* msg,
								 struct via_body* via );

/*! \brief use src_ip, port=src_port if rport, via port if via port, 5060 otherwise */
#define update_sock_struct_from_ip(  to, msg ) \
	init_su((to), &(msg)->rcv.src_ip, \
			((!msg->via1)||((msg)->via1->rport)||((msg)->msg_flags&FL_FORCE_RPORT))? \
							(msg)->rcv.src_port: \
							((msg)->via1->port)?(msg)->via1->port: SIP_PORT )

int forward_reply( struct sip_msg* msg);



/*! \brief
 *
 *  \param send_sock = 0 if already known (e.g. for udp in some cases),
 *        non-0 otherwise
 *  \param proto =TCP|UDP
 *  \param to = sockaddr-like description of the destination
 *  \param id - only used on tcp, it will force sending on connection "id"
 *       if id!=0 and the connection exists, else it will send to "to"
 *       (useful for sending replies on  the same connection as the request
 *       that generated them; use 0 if you don't want this)
 * \param buf - the buffer containing the message to be sent
 * \param len - the length of the message to be sent
 * \return 0 if ok, -1 on error
 */
static inline int msg_send( struct socket_info* send_sock, int proto,
							union sockaddr_union* to, unsigned int id,
							char* buf, int len, struct sip_msg* msg)
{
	str out_buff;
	unsigned short port;
	char *ip;

	if (proto<=PROTO_NONE || proto>=PROTO_OTHER) {
		LM_BUG("bogus proto %s/%d received!\n",proto2a(proto),proto);
		return -1;
	}
	if (protos[proto].id==PROTO_NONE) {
		LM_ERR("trying to using proto %s/%d which is not initialized!\n",
			proto2a(proto),proto);
		return -1;
	}

	out_buff.len = len;
	out_buff.s = buf;

	/* determin the send socket */
	if (send_sock==0)
		send_sock=get_send_socket(0, to, proto);
	if (send_sock==0){
		LM_ERR("no sending socket found for proto %s/%d\n",
			proto2a(proto), proto);
		goto error;
	}

	/* the raw processing callbacks are free to change whatever inside
	 * the buffer further use out_buff.s and at the end try to free out_buff.s
	 * if changed by callbacks */
	if ( is_sip_proto(proto) )
		run_post_raw_processing_cb(POST_RAW_PROCESSING,&out_buff, msg);

	/* update the length for further processing */
	len = out_buff.len;

	if (protos[proto].tran.send(send_sock, out_buff.s, out_buff.len, to,id)<0){
		get_su_info(to, ip, port);
		LM_ERR("send() to %s:%hu for proto %s/%d failed\n",
				ip, port, proto2a(proto),proto);
		goto error;
	}

	/* potentially allocated by the out raw processing */
	if (out_buff.s != buf)
		pkg_free(out_buff.s);

	return 0;
error:
	if (out_buff.s != buf)
		pkg_free(out_buff.s);
	return -1;
}


#endif
