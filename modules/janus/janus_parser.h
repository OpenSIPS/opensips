/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
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
 * History:
 * --------
 * 2024-12-03 initial release (vlad)
 */

#ifndef _PROTO_JANUS_JANUS_PARSER_H_
#define _PROTO_JANUS_JANUS_PARSER_H_

#include "../../str.h"
#include "../../ip_addr.h"
#include "../../parser/hf.h"
#include "../../ut.h"
#include "../../lib/osips_malloc.h"

/* janus protocol is a bit strange in differentiating between requests / replies
 * janus : ack & janus : event are ways of signaling a reply */
enum janus_msg_type { JANUS_UNKNOWN=0, JANUS_REQUEST=1, JANUS_REPLY=2};

struct janus_url {
	str whole;
	int proto;
	unsigned short port_no;
	str host;
	str port;
	str resource;
	struct janus_url *next;
};

enum janus_method {
	JANUS_METHOD_UNDEF=0,
	JANUS_METHOD_CREATE,
	JANUS_METHOD_ATTACH,
	JANUS_METHOD_MESSAGE,
	JANUS_METHOD_TRICKLE,
	JANUS_METHOD_EVENT,
	JANUS_METHOD_ACK,
	JANUS_METHOD_OTHER
};

struct janus_msg {
	/* JSON driven protocol */
	cJSON *body;

	enum janus_method method;

	struct receive_info rcv; /* source & dest ip, ports, proto a.s.o */

	char* buf;        /* unmodified, original (as received) buffer */
	unsigned int len; /* message len (orig) */
};

char * parse_janus_url(char *start,char *end,struct janus_url *url);

#endif
