/*
 * $Id$
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
 */

/*! 
 * \brief TCP server 
 */


#ifndef tcp_server_h
#define tcp_server_h

extern int tcp_no_new_conn_bflag;
extern int tcp_no_new_conn;


/* "public" functions*/

struct tcp_connection* tcpconn_get(int id, struct ip_addr* ip, int port, 
									int timeout);
void tcpconn_put(struct tcp_connection* c);
int tcp_send(struct socket_info* send_sock, int type, char* buf, unsigned len,
									union sockaddr_union* to, int id);

int tcpconn_add_alias(int id, int port, int proto);

void force_tcp_conn_lifetime(struct receive_info *rcv, unsigned int timeout);



#endif
