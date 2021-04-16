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



#ifndef _NET_tcp_conn_defs_h
#define _NET_tcp_conn_defs_h

#include "../locking.h"
#include "../ip_addr.h"

/* keepalive */
#ifndef NO_TCP_KEEPALIVE
    #define HAVE_SO_KEEPALIVE
#endif

/* keepintvl */
#ifndef NO_TCP_KEEPINTVL
    #ifdef __OS_linux
        #define HAVE_TCP_KEEPINTVL
    #endif
#endif

/* keepidle */
#ifndef NO_TCP_KEEPIDLE
    #ifdef __OS_linux
        #define HAVE_TCP_KEEPIDLE
    #endif
#endif

/* keepcnt */
#ifndef NO_TCP_KEEPCNT
    #ifdef __OS_linux
        #define HAVE_TCP_KEEPCNT
    #endif
#endif


/*!< Maximum number of port aliases */
#define TCP_CON_MAX_ALIASES  4

/*!< the max number of seconds that a child waits  until the message is
 * read completely - anything above will lead to the connection being closed
 * and considered an attack */
#define TCP_CHILD_MAX_MSG_TIME  4

/* tcp connection flags */
#define F_CONN_NON_BLOCKING		(1<<0)
#define F_CONN_TRACE_DROPPED	(1<<1) /*!< tracing dropped on this connection */
#define F_CONN_ACCEPTED			(1<<2) /*!< created after a connect event */
#define F_CONN_REMOVED_READ		(1<<3) /*!< no longer in "main" reactor for read */
#define F_CONN_REMOVED_WRITE	(1<<4) /*!< no longer in "main" reactor for write */
/*!< no longer in "main" reactor for read or write */
#define F_CONN_REMOVED			(F_CONN_REMOVED_READ|F_CONN_REMOVED_WRITE)
#define F_CONN_INIT				(1<<5) /*!< the connection was initialized */

enum tcp_conn_states { S_CONN_ERROR=-2, S_CONN_BAD=-1, S_CONN_OK=0,
		S_CONN_CONNECTING, S_CONN_EOF };

struct tcp_connection;

/*! \brief TCP port alias structure */
struct tcp_conn_alias{
	struct tcp_connection* parent;
	struct tcp_conn_alias* next;
	struct tcp_conn_alias* prev;
	unsigned short port;			/*!< alias port */
	unsigned short hash;			/*!< hash index in the address hash */
};


/*! \brief TCP connection structure */
struct tcp_connection{
	int s;					/*!< socket, used by "tcp main" */
	int fd;					/*!< used only by "children", don't modify it! private data! */
	int proc_id;				/*!< used only by "children", contains the pt table ID of the TCP worker currently holding the connection, or -1 if in TCP main */
	gen_lock_t write_lock;
	unsigned int id;				/*!< id (unique!) used to retrieve a specific connection when reply-ing*/
	unsigned long long cid;					/*!< connection id (unique!) used to uniquely identify connections across space and time */
	struct receive_info rcv;		/*!< src & dst ip, ports, proto a.s.o*/
	volatile int refcnt;
	enum sip_protos type;			/*!< PROTO_TCP or a protocol over it, e.g. TLS */
	enum tcp_conn_states state;		/*!< connection state */
	void* extra_data;			/*!< extra data associated to the connection, 0 for tcp*/
	/*!< connection timeout, to be used by worker only; after this
	 * it will be released (with success or not) */
	unsigned int timeout;
	/*!< the lifetime of the connection - watched by TCP main process
	 * in order to close un-used connections */
	unsigned int lifetime;
	unsigned id_hash;			/*!< hash index in the id_hash */
	struct tcp_connection* id_next;		/*!< next in id hash table */
	struct tcp_connection* id_prev;		/*!< prev in id hash table */
	struct tcp_connection* c_next;		/*!< Child next (use locally) */
	struct tcp_connection* c_prev;		/*!< Child prev (use locally */
	struct tcp_conn_alias con_aliases[TCP_CON_MAX_ALIASES];	/*!< Aliases for this connection */
	int aliases;				/*!< Number of aliases, at least 1 */
	struct tcp_req *con_req;	/*!< Per connection req buffer */
	unsigned int msg_attempts;	/*!< how many read attempts we have done for the last request */
	/*!< connection related flags */
	unsigned short flags;
	/*!< protocol related & reserved flags */
	unsigned short proto_flags;
	struct struct_hist *hist;
	/* protocol specific data attached to this connection */
	void *proto_data;
};


/*! \brief add port as an alias for the "id" connection
 * \return 0 on success,-1 on failure */
int tcpconn_add_alias(unsigned int id, int port, int proto);


#define tcp_conn_set_lifetime( _c, _lt) \
	do { \
		unsigned int _timeout = get_ticks() + _lt;\
		if (_timeout > (_c)->lifetime ) \
			(_c)->lifetime = _timeout;\
	}while(0)


#endif

