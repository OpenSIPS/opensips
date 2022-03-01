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
#include "../../net/net_tcp.h"
#include "msrp_parser.h"

enum msrp_req_errors { MSRP_REQ_INIT, MSRP_REQ_OK, MSRP_READ_ERROR,
		MSRP_REQ_OVERRUN, MSRP_REQ_BAD };
enum msrp_req_states { MSRP_START, MSRP_FIRSTLINE_IDENT,
		MSRP_FIRSTLINE_METHOD,
		MSRP_HEADERS, MSRP_BODY, MSRP_EOM
	};

#define MSRP_BUF_SIZE 65536

struct msrp_req{
	/* reading indicators */
	char buf[MSRP_BUF_SIZE+1];		/*!< bytes read so far (+0-terminator)*/
	char* start;					/*!< where the message starts, after all the empty lines are skipped*/
	char* pos;						/*!< current position in buf */
	char* parsed;					/*!< last parsed position */

	/* parsing fields*/
	struct msrp_firstline fl;
	str body; /* the MSRP body payload, without the EOM */

	/* control fields */
	/* 1 if one req has been fully read, 0 otherwise*/
	unsigned short complete;
	enum msrp_req_errors error;
	enum msrp_req_states state;
};


#define init_msrp_req( r, _size) \
	do{ \
		(r)->parsed=(r)->start=(r)->buf; \
		(r)->pos=(r)->buf + (_size); \
		(r)->error=MSRP_REQ_OK;\
		(r)->state=MSRP_START; \
		(r)->complete=0; \
		(r)->body.len=0;(r)->body.s=NULL; \
		memset( &(r)->fl, 0, sizeof(struct msrp_firstline) ); \
	}while(0)

extern struct msrp_req msrp_current_req;


void msrp_brief_parse_msg(struct msrp_req *r);

int msrp_handle_req(struct msrp_req *req,
		struct tcp_connection *con, int _max_msg_chunks);

#endif

