/*
 *  $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "parser/msg_parser.h"
#include "route.h"
#include "proxy.h"
#include "ip_addr.h"

#include "udp_server.h"
#ifdef USE_TCP
#include "tcp_server.h"
#endif

#ifdef USE_SCTP
#include "sctp_server.h"
#endif


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
			(((msg)->via1->rport)||((msg)->msg_flags&FL_FORCE_RPORT))? \
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
							union sockaddr_union* to, int id,
							char* buf, int len)
{
	if (send_sock==0)
		send_sock=get_send_socket(0, to, proto);
	if (send_sock==0){
		LM_ERR("no sending socket found for proto %d\n", proto);
		goto error;
	}

	if (proto==PROTO_UDP){
		if (udp_send(send_sock, buf, len, to)==-1){
			LM_ERR("udp_send failed\n");
			goto error;
		}
	}
#ifdef USE_TCP
	else if (proto==PROTO_TCP){
		if (tcp_disable){
			LM_WARN("attempt to send on tcp and tcp"
					" support is disabled\n");
			goto error;
		}else{
			if (tcp_send(send_sock, proto, buf, len, to, id)<0){
				LM_ERR("tcp_send failed\n");
				goto error;
			}
		}
	}
#ifdef USE_TLS
	else if (proto==PROTO_TLS){
		if (tls_disable){
			LM_WARN("attempt to send on tls and tls"
					" support is disabled\n");
			goto error;
		}else{
			if (tcp_send(send_sock, proto, buf, len, to, id)<0){
				LM_ERR("tcp_send failed\n");
				goto error;
			}
		}
	}
#endif /* USE_TLS */
#endif /* USE_TCP */
#ifdef USE_SCTP
	else if (proto==PROTO_SCTP){
		if (sctp_disable){
			LM_WARN("attempt to send on sctp and sctp"
					" support is disabled\n");
			goto error;
		}else{
			if (sctp_server_send(send_sock, buf, len, to)<0){
				LM_ERR("sctp_send failed\n");
				goto error;
			}
		}
	}
#endif /* USE_SCTP */
	else{
			LM_CRIT("unknown proto %d\n", proto);
			goto error;
	}
	return 0;
error:
	return -1;
}


/***** forward callbacks *****/

/* callback function prototype */
typedef void (fwd_cb_t) (struct sip_msg* req, str  *buffer,
		struct socket_info* send_sock, int proto, union sockaddr_union *to);

/* register a FWD callback */
int register_fwdcb(fwd_cb_t f);

#endif
