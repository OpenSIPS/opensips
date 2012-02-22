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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include "evi_params.h"

#define		EVI_ADDRESS		(1 << 1)
#define		EVI_PORT		(1 << 2)
#define		EVI_SOCKET		(1 << 3)
#define		EVI_PARAMS		(1 << 4)
#define		EVI_EXPIRE		(1 << 8)

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
typedef int (raise_f)(str* ev_name, evi_reply_sock *sock, evi_params_t * params);
/* socket parse function */
typedef evi_reply_sock* (parse_f)(str);
/* tries to match two sockets */
typedef int (match_f)(evi_reply_sock *sock1, evi_reply_sock *sock2);
/* free a socket */
typedef void (free_f)(evi_reply_sock *sock);

typedef struct evi_export_ {
	str proto;			/* protocol name */
	raise_f *raise;		/* raise function */
	parse_f *parse;		/* parse function */
	match_f *match;		/* sockets match function */
	free_f *free;		/* free a socket */
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
 *  - 0 if successfull or negative on error
 */
int register_event_mod(evi_export_t *ev);

#endif /* _EVI_TRANSPORT_H_ */
