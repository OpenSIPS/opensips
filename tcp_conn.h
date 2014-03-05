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



#ifndef _tcp_conn_h
#define _tcp_conn_h

#include "ip_addr.h"
#include "locking.h"


#define TCP_CON_MAX_ALIASES 4 			/*!< Maximum number of port aliases */

#define TCP_BUF_SIZE 65535			/*!< TCP buffer size */
#define DEFAULT_TCP_CONNECTION_LIFETIME 120 	/*!< TCP connection lifetime, in seconds */
#define DEFAULT_TCP_LISTEN_BACKLOG 10          /*!< TCP listen backlog count */
#define DEFAULT_TCP_SEND_TIMEOUT 10 		/*!< If a send can't write for more then 10s, timeout */
#define DEFAULT_TCP_CONNECT_TIMEOUT 10		/*!< If a connect doesn't complete in this time, timeout */
#define DEFAULT_TCP_MAX_CONNECTIONS 2048	/*!< Maximum number of connections */
#define TCP_CHILD_TIMEOUT 5 			/*!< After 5 seconds, the child "returns"
							 the connection to the tcp master process */
#define TCP_MAIN_SELECT_TIMEOUT 5		/*!< how often "tcp main" checks for timeout*/
#define TCP_CHILD_SELECT_TIMEOUT 2		/*!< the same as above but for children */

#define TCP_CHILD_MAX_MSG_CHUNK	4		/*!< the max number of chunks that a child accepts
										  until the message is read completely - anything
										  above will lead to the connection being closed -
										  considered an attack */
#define TCP_CHILD_MAX_MSG_TIME	4		/*!< the max number of seconds that a child waits
										  until the message is read completely - anything
										  above will lead to the connection being closed -
										  considered an attack */


/* tcp connection flags */
#define F_CONN_NON_BLOCKING   1
#define F_CONN_REMOVED        2 /*!< no longer in "main" listen fd list */
#define F_CONN_NOT_CONNECTED  4 /*!< a connection in pending state,
								  waiting to be connected */


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


enum tcp_req_errors {	TCP_REQ_INIT, TCP_REQ_OK, TCP_READ_ERROR,
		TCP_REQ_OVERRUN, TCP_REQ_BAD_LEN };
enum tcp_req_states {	H_SKIP_EMPTY, H_SKIP, H_LF, H_LFCR,  H_BODY, H_STARTWS,
		H_CONT_LEN1, H_CONT_LEN2, H_CONT_LEN3, H_CONT_LEN4, H_CONT_LEN5,
		H_CONT_LEN6, H_CONT_LEN7, H_CONT_LEN8, H_CONT_LEN9, H_CONT_LEN10,
		H_CONT_LEN11, H_CONT_LEN12, H_CONT_LEN13, H_L_COLON,
		H_CONT_LEN_BODY, H_CONT_LEN_BODY_PARSE , H_PING_CRLFCRLF,
		H_SKIP_EMPTY_CR_FOUND, H_SKIP_EMPTY_CRLF_FOUND, H_SKIP_EMPTY_CRLFCR_FOUND
	};

enum tcp_conn_states { S_CONN_ERROR=-2, S_CONN_BAD=-1, S_CONN_OK=0,
		S_CONN_INIT, S_CONN_EOF, S_CONN_ACCEPT, S_CONN_CONNECT };


/* fd communication commands */
enum conn_cmds { CONN_DESTROY=-3, CONN_ERROR=-2, CONN_EOF=-1, CONN_RELEASE,
		CONN_GET_FD, CONN_NEW, ASYNC_CONNECT, ASYNC_WRITE };
/* CONN_RELEASE, EOF, ERROR, DESTROY can be used by "reader" processes
 * CONN_GET_FD, NEW, ERROR only by writers */

struct tcp_req{
	struct tcp_req* next;
	/* sockaddr ? */
	char buf[TCP_BUF_SIZE+1];		/*!< bytes read so far (+0-terminator)*/
	char* start;					/*!< where the message starts, after all the empty lines are skipped*/
	char* pos;						/*!< current position in buf */
	char* parsed;					/*!< last parsed position */
	char* body;						/*!< body position */
	unsigned int   content_len;
	unsigned short has_content_len;	/*!< 1 if content_length was parsed ok*/
	unsigned short complete;		/*!< 1 if one req has been fully read, 0 otherwise*/
	unsigned int   bytes_to_go;		/*!< how many bytes we have still to read from the body*/
	enum tcp_req_errors error;
	enum tcp_req_states state;
};



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



#define init_tcp_req( r) \
	do{ \
		(r)->parsed=(r)->pos=(r)->start=(r)->buf; \
		(r)->error=TCP_REQ_OK;\
		(r)->state=H_SKIP_EMPTY; \
		(r)->body=0; \
		(r)->complete=(r)->content_len=(r)->has_content_len=0; \
		(r)->bytes_to_go=0; \
	}while(0)


/*! \brief add a tcpconn to a list
 * list head, new element, next member, prev member */
#define tcpconn_listadd(head, c, next, prev) \
	do{ \
		/* add it at the begining of the list*/ \
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


#define TCPCONN_LOCK lock_get(tcpconn_lock);
#define TCPCONN_UNLOCK lock_release(tcpconn_lock);

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


#endif

