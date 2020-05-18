/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#ifndef _EVI_TRANSPORT_H_
#define _EVI_TRANSPORT_H_

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "../mi/mi.h"
#include "../str.h"
#include "../ip_addr.h"
#include "../parser/msg_parser.h"
#include "evi_params.h"

#define		EVI_ADDRESS		(1 << 1)
#define		EVI_PORT		(1 << 2)
#define		EVI_SOCKET		(1 << 3)
#define		EVI_PARAMS		(1 << 4)
#define		EVI_EXPIRE		(1 << 8) // indicates that the socket may expire
#define		EVI_PENDING		(1 << 9) // indicates that the socket is in use

/* sockets */
typedef union {
	union sockaddr_union udp_addr;
	struct sockaddr_un unix_addr;
} sockaddr_reply;

/* reply socket */
typedef struct ev_reply_sock_ {
	unsigned int flags;
	unsigned short port;
	str address;
	unsigned int expire;
	long subscription_time;
	sockaddr_reply src_addr;
	void *params;
} evi_reply_sock;

/* event raise function */
typedef int (raise_f)(struct sip_msg *msg, str *ev_name,
					  evi_reply_sock *sock, evi_params_t * params);
/* socket parse function */
typedef evi_reply_sock* (parse_f)(str);
/* tries to match two sockets */
typedef int (match_f)(evi_reply_sock *sock1, evi_reply_sock *sock2);
/* free a socket */
typedef void (evi_free_f)(evi_reply_sock *sock);
/* prints a given socket */
typedef str (print_f)(evi_reply_sock *sock);

typedef struct evi_export_ {
	str proto;			/* protocol name */
	raise_f *raise;		/* raise function */
	parse_f *parse;		/* parse function */
	match_f *match;		/* sockets match function */
	evi_free_f *free;	/* free a socket */
	print_f *print;		/* prints a socket */
	unsigned int flags;
} evi_export_t;


/* transport list */
typedef struct evi_trans_ {
	evi_export_t *module;
	struct evi_trans_ *next;
} evi_trans_t;

/* functions used by the transport modules */
/*
 * Used to register a transport module
 * Parameters:
 *  + export functions
 *
 * Returns:
 *  - 0 if successful or negative on error
 */
int register_event_mod(evi_export_t *ev);

/*
 * Used to build the payload of an event
 * Parameters:
 *  + event parameters
 *  + jsonrpc method (usually this should be the event name)
 *  + jsonrpc id, if 0 the field will be NULL
 *  + key of an extra string parameter (ignored if the event has array params)
 *  + value of an extra string parameter
 *
 * Returns:
 *  - the new event payload or NULL on error
 */
char *evi_build_payload(evi_params_t *params, str *method, int id,
	str *extra_param_k, str *extra_param_v);

/*
 * Used to free an event payload built with evi_build_payload()
 * Parameters:
 *  + event payload
 */
void evi_free_payload(char *payload);

#endif /* _EVI_TRANSPORT_H_ */
