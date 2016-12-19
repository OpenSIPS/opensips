/*
 * Copyright (C) 2016 - OpenSIPS Foundation
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
 * -------
 *  2016-08-30  first version (Ionut Ionita)
 */
#include "ut.h"

/* INADDR_LOOPBACK is internally stored in network byte order;
 * we need little endian so we'll define our own loopback address */
#define TRACE_INADDR_LOOPBACK	((in_addr_t) 0x0100007f) /* Inet 127.0.0.1.  */

enum TRACE_DATA_TYPES {
	TRACE_TYPE_GENERIC=0, /* for data fields/chunks that can have only one type */
	TRACE_TYPE_STR=1,
	TRACE_TYPE_UINT8,
	TRACE_TYPE_UINT16,
	TRACE_TYPE_UINT32,
	TRACE_INET_ADDR,
	TRACE_INET6_ADDR
};


typedef void * trace_message;
typedef void * data_id_t;
typedef void * trace_dest;

/*
 * creates a message for tracing
 * @param1 sender network info
 * @param2 receiver network info
 * @param3 network level protocol
 * @param4 traced message payload
 * @param5 payload message protocol type
 * @param6 tracing protocol version
 *
 * @return pointer to the tracing message
 */
typedef trace_message (create_trace_message_f)(union sockaddr_union* from_su,
		union sockaddr_union* to_su, int net_proto, str* payload, int pld_proto,
		trace_dest dest);



/*
 * add data to trace_message(chunks, fields etc.)
 * @param1 message used for tracing data
 * @param2 data to be added to the message
 * @param3 length of the data
 * @param4 TRACE_DATA_TYPES defines the type of data to be added
 *
 */
typedef int (add_trace_data_f)(trace_message message, void* data, int len,
		int type, int data_id, int vendor);

/*
 * send traced message to the desired destination
 * @param1 message to send(function should contain packing functionality and also free it)
 * @param2 destination to which the message is sent
 * @param3 send socket
 *         can be NULL case in which will be sent on any of the sockets available
 *
 */
typedef int (trace_send_message_f)(trace_message message,
		trace_dest dest, struct socket_info* send_sock);

/*
 * fetch a trace destination by its name
 * @param1 name of the destination
 * @return trace destination if found or null otherwise
 */
typedef trace_dest (get_trace_dest_by_name_f)(str *);

/*
 * free function
 * @param1 trace message to be freed
 *
 */
typedef void (free_trace_message_f)(trace_message message);


typedef struct _trace_prot {
	create_trace_message_f*   create_trace_message;
	add_trace_data_f*         add_trace_data;
	trace_send_message_f*     send_message;
	get_trace_dest_by_name_f* get_trace_dest_by_name;
	free_trace_message_f*     free_message;
} trace_proto_t;

/*
	Type definition for a bind function.
 */
typedef int (*trace_bind_api_f)(trace_proto_t*);

int trace_prot_bind(char* module_name, trace_proto_t* prot);


