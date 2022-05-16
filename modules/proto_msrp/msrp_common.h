/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


/* here we have "network layer"-specific functions that are
 * shared both by msrp "plain" and "tls"
 */

#ifndef _PROTO_MSRP_MSRP_COMMON_H_
#define _PROTO_MSRP_MSRP_COMMON_H_

#include "../../str.h"
#include "../../socket_info.h"
#include "../../net/net_tcp.h"
#include "../../trace_api.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../tls_mgm/api.h"
#include "msrp_parser.h"

enum msrp_req_states { MSRP_START, MSRP_FIRSTLINE_IDENT,
		MSRP_FIRSTLINE_METHOD,
		MSRP_HEADERS, MSRP_BODY, MSRP_EOM
	};

struct msrp_req{
	/* reading indicators */
	struct tcp_req tcp;

	/* parsing fields*/
	struct msrp_firstline fl;
	str body; /* the MSRP body payload, without the EOM */

	/* control fields */
	/* 1 if one req has been fully read, 0 otherwise*/
	unsigned short complete;
	enum msrp_req_states state;
};

extern int msrp_send_timeout;
extern int msrp_tls_handshake_timeout;
extern int msrp_max_msg_chunks;
extern int *msrp_trace_is_on;
extern int  msrp_trace_filter_route_id;
extern trace_dest msrp_t_dst;
extern struct msrp_req msrp_current_req;

extern struct tls_mgm_binds tls_mgm_api;


#define init_msrp_req( r, _size) \
	do{ \
		(r)->tcp.parsed=(r)->tcp.start=(r)->tcp.buf; \
		(r)->tcp.pos=(r)->tcp.buf + (_size); \
		(r)->tcp.error=TCP_REQ_OK;\
		(r)->state=MSRP_START; \
		(r)->complete=0; \
		(r)->body.len=0;(r)->body.s=NULL; \
		memset( &(r)->fl, 0, sizeof(struct msrp_firstline) ); \
	}while(0)


#define F_TCP_CONN_TRACED ( 1 << 0 )
#define TRACE_ON(flags) (msrp_t_dst && (*msrp_trace_is_on) && \
						!(flags & F_CONN_TRACE_DROPPED))


void msrp_brief_parse_msg(struct msrp_req *r);

int proto_msrp_send(struct socket_info* send_sock,
		char* buf, unsigned int len,
		union sockaddr_union* to, unsigned int id);

int msrp_read_req(struct tcp_connection* con, int* bytes_read);

#endif

