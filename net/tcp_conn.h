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
 *
 * History:
 * --------
 *  2003-01-29  tcp buffer size ++-ed to allow for 0-terminator
 *  2003-06-30  added tcp_connection flags & state (andrei)
 *  2003-10-27  tcp port aliases support added (andrei)
 *  2012-01-19  added TCP keepalive support
 */

/*!
 * \file
 * \brief TCP protocol support
 */



#ifndef _NET_tcp_conn_h
#define _NET_tcp_conn_h

#include "../locking.h"
#include "tcp_conn_defs.h"


/*!< TCP connection lifetime, in seconds */
#define DEFAULT_TCP_CONNECTION_LIFETIME 120
/*!< TCP listen backlog count */
#define DEFAULT_TCP_LISTEN_BACKLOG 10
/*!< If a connect doesn't complete in more than 100ms, timeout */
#define DEFAULT_TCP_CONNECT_TIMEOUT 100
/*!< Maximum number of connections */
#define DEFAULT_TCP_MAX_CONNECTIONS 2048
/*!< After 5 seconds, the child "returns"
  the connection to the tcp master process */
#define TCP_CHILD_TIMEOUT 5
/*!< how often "tcp main" checks for timeout*/
#define TCP_MAIN_SELECT_TIMEOUT 5
/*!< the same as above but for children */
#define TCP_CHILD_SELECT_TIMEOUT 2


/* fd communication commands - internal usage ONLY */
enum conn_cmds { CONN_DESTROY=-3, CONN_ERROR=-2, CONN_EOF=-1, CONN_RELEASE,
		CONN_GET_FD, CONN_NEW, ASYNC_CONNECT, ASYNC_WRITE };
/* CONN_RELEASE, EOF, ERROR, DESTROY can be used by "reader" processes
 * CONN_GET_FD, NEW, ERROR only by writers */


/*! \brief add a tcpconn to a list
 * list head, new element, next member, prev member */
#define tcpconn_listadd(head, c, next, prev) \
	do{ \
		/* add it at the beginning of the list*/ \
		(c)->next=(head); \
		(c)->prev=0; \
		if ((head)) (head)->prev=(c); \
		(head)=(c); \
	} while(0)


/*! \brief remove a tcpconn from a list*/
#define tcpconn_listrm(head, c, next, prev) \
	do{ \
		if ((head)==(c)) (head)=(c)->next; \
		if ((c)->next) (c)->next->prev=(c)->prev; \
		if ((c)->prev) (c)->prev->next=(c)->next; \
	}while(0)

#define TCPCONN_GET_PART(_id)  (_id%TCP_PARTITION_SIZE)
#define TCP_PART(_id)  (tcp_parts[TCPCONN_GET_PART(_id)])

#define TCPCONN_LOCK(_id) \
	lock_get(tcp_parts[TCPCONN_GET_PART(_id)].tcpconn_lock);
#define TCPCONN_UNLOCK(_id) \
	lock_release(tcp_parts[TCPCONN_GET_PART(_id)].tcpconn_lock);

#define TCP_ALIAS_HASH_SIZE 1024
#define TCP_ID_HASH_SIZE 1024

static inline unsigned tcp_addr_hash(struct ip_addr* ip, unsigned short port)
{
	if(ip->len==4) return (ip->u.addr32[0]^port)&(TCP_ALIAS_HASH_SIZE-1);
	else if (ip->len==16)
			return (ip->u.addr32[0]^ip->u.addr32[1]^ip->u.addr32[2]^
					ip->u.addr32[3]^port) & (TCP_ALIAS_HASH_SIZE-1);
	else{
		LM_CRIT("bad len %d for an ip address\n", ip->len);
		return 0;
	}
}

#define tcp_id_hash(id) (id&(TCP_ID_HASH_SIZE-1))

void tcpconn_put(struct tcp_connection* c);


#endif

