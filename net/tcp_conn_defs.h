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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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



#ifndef _NET_tcp_conn_defs_h
#define _NET_tcp_conn_defs_h

#include "../ip_addr.h"

/*!< Maximum number of port aliases */
#define TCP_CON_MAX_ALIASES  4

/*!< the max number of chunks that a child accepts until the message
 * is read completely - anything above will lead to the connection being
 * closed - considered an attack */
#define TCP_CHILD_MAX_MSG_CHUNK  4

/*!< the max number of seconds that a child waits  until the message is 
 * ead completely - anything above will lead to the connection being closed
 * and considered an attack */
#define TCP_CHILD_MAX_MSG_TIME  4


/* tcp connection flags */
#define F_CONN_NON_BLOCKING   1
#define F_CONN_REMOVED        2 /*!< no longer in "main" listen fd list */
#define F_CONN_NOT_CONNECTED  4 /*!< a connection in pending state,
								  waiting to be connected */

enum tcp_conn_states { S_CONN_ERROR=-2, S_CONN_BAD=-1, S_CONN_OK=0,
		S_CONN_INIT, S_CONN_EOF, S_CONN_ACCEPT, S_CONN_CONNECT };

struct tcp_connection;

/*! \brief TCP port alias structure */
struct tcp_conn_alias{
	struct tcp_connection* parent;
	struct tcp_conn_alias* next;
	struct tcp_conn_alias* prev;
	unsigned short port;			/*!< alias port */
	unsigned short hash;			/*!< hash index in the address hash */
};


struct tcp_send_chunk{
	char *buf; /* buffer that needs to be sent out */
	char *pos; /* the position that we should be writing next */
	int len;   /* length of the buffer */
	int ticks; /* time at which this chunk was initially
				  attempted to be written */
};

/*! \brief TCP connection structure */
struct tcp_connection{
	int s;					/*!< socket, used by "tcp main" */
	int fd;					/*!< used only by "children", don't modify it! private data! */
	gen_lock_t write_lock;
	int id;					/*!< id (unique!) used to retrieve a specific connection when reply-ing*/
	struct receive_info rcv;		/*!< src & dst ip, ports, proto a.s.o*/
	volatile int refcnt;
	enum sip_protos type;			/*!< PROTO_TCP or a protocol over it, e.g. TLS */
	int flags;				/*!< connection related flags */
	enum tcp_conn_states state;		/*!< connection state */
	void* extra_data;			/*!< extra data associated to the connection, 0 for tcp*/
	unsigned int timeout;			/*!< connection timeout, after this it will be removed*/
	unsigned int lifetime;			/*!< lifetime to be set for the connection */
	unsigned id_hash;			/*!< hash index in the id_hash */
	struct tcp_connection* id_next;		/*!< next in id hash table */
	struct tcp_connection* id_prev;		/*!< prev in id hash table */
	struct tcp_connection* c_next;		/*!< Child next (use locally) */
	struct tcp_connection* c_prev;		/*!< Child prev (use locally */
	struct tcp_conn_alias con_aliases[TCP_CON_MAX_ALIASES];	/*!< Aliases for this connection */
	int aliases;				/*!< Number of aliases, at least 1 */
	struct tcp_req *con_req;	/*!< Per connection req buffer */
	unsigned int msg_attempts;	/*!< how many read attempts we have done for the last request */
	struct tcp_send_chunk **async_chunks; /*!< the chunks that need to be written on this
										   connection when it will become writable */
	int async_chunks_no; /* the total number of chunks pending to be written */
	int oldest_chunk; /* the oldest chunk in our write list */
};


/*! \brief add port as an alias for the "id" connection
 * \return 0 on success,-1 on failure */
int tcpconn_add_alias(int id, int port, int proto);

#endif

