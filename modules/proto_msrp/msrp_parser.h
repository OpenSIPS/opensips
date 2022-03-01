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

#ifndef _PROTO_MSRP_MSRP_PARSER_H_
#define _PROTO_MSRP_MSRP_PARSER_H_

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../parser/hf.h"


enum msrp_msg_type { MSRP_UNKNOWN=0, MSRP_REQUEST=1, MSRP_REPLY=2};

enum msrp_method {
	MSRP_METHOD_UNDEF=0,
	MSRP_METHOD_SEND,
	MSRP_METHOD_REPORT,
	MSRP_METHOD_AUTH,
	MSRP_METHOD_OTHER
};


struct msrp_firstline {
	enum msrp_msg_type type;
	str ident;
	union {
		struct {
			str method;
			int method_id;
		} request;
		struct {
			str status;
			str reason;
			unsigned short status_no;
		} reply;
	}u;
	/* pointer to the last char of this line (including the CFLF) */
	char *eol;
};

struct msrp_msg {
	struct msrp_firstline fl;

	struct hdr_field* headers;     /* All the parsed headers*/
	struct hdr_field* last_header; /* Pointer to the last header*/

	struct hdr_field* to_path;
	struct hdr_field* from_path;
	struct hdr_field* message_id;
	struct hdr_field* byte_range;
	struct hdr_field* failure_report;
	struct hdr_field* success_report;
	struct hdr_field* status;
	struct hdr_field* use_path;
	struct hdr_field* content_type;

	str body;

	struct receive_info rcv; /* source & dest ip, ports, proto a.s.o */

	char* buf;        /* unmodified, original (as received) buffer */
	unsigned int len; /* message len (orig) */
};


struct msrp_url {
	str whole;
	unsigned short secured;
	unsigned short port_no;
	str host;
	str port;
	str session;
	str params;
	struct msrp_url *next;
};


struct msrp_url* parse_msrp_path(str *path);

char* parse_msrp_url( char* start, char *end, struct msrp_url* url);

int parse_msrp_msg( char* buf, int len, struct msrp_msg *msg);

void free_msrp_msg( struct msrp_msg *msg);

#endif
