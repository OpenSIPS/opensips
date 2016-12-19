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


/*
 * get an unique identifier for each type of message traced
 * current types of messages that should be returned an id for
 * "sip"
 * "rest" (not implemented)
 * "xlog"
 * "mi"   (not implemented)
 *
 * @param1 the name of the protocol requesting an id(should be one of the above)
 * @return integer value uniquely identifying a certain type of packet
 *
 */
typedef int (get_message_id_f)(char* proto);

/*
 * get identifier for some data as is the correlation id or specific
 * vendor data
 *
 * @param1 string identifier for data
 * @param2 {out} vendor identifier for data
 * @param3 {out} data identifier
 * @return positive value if found 0 else
 */
typedef int (get_data_id_f)(const char* data_name, int* vendor, int* data_id);


typedef struct _trace_prot {
	create_trace_message_f*   create_trace_message;
	add_trace_data_f*         add_trace_data;
	trace_send_message_f*     send_message;
	get_trace_dest_by_name_f* get_trace_dest_by_name;
	free_trace_message_f*     free_message;
	get_message_id_f*         get_message_id;
	get_data_id_f*            get_data_id;
} trace_proto_t;

/**
 * message scope tracing functions
 * currently only siptrace module populates these functions
 */
/**
 * the function registers a name for certain type of messages to be traced
 *
 * @param {name} string trace type identifier; shall be used by the module
 *               implementing the function as a traced type identifier from
 *               the script (for exmaple xlog message tracing shall be
 *               identified with "xlog" name)
 *
 * @return {id} integer identifier for this type of tracing; shall be used
 *              at runtime to check whether or not {name} messages are being
 *              traced
 */
typedef int(*register_trace_type_f)(char* id_name);

/**
 * the function checks whether certain types of messages are being traced;
 * it shall return
 *
 * @param {id}  identifier returned by register_trace_type_f function;
 * @return {destination_id} an id that shall be passed to get_next_destination
 *                          function in order to return a trace_dest structure
 *                          to which we shall send the traced packet
 */
typedef int(*check_is_traced_f)(int id);

/**
 * this shall be used along with check_is_traced; it returns a trace_dest
 * structure that shall be used for sending the message using the trace protocol
 * @param {last_dest} if null the first destiantion corresponding to that id_hash
 *                    shall be returned, else it shall be returned the next after
 *                    last_dest
 * @param {id_hash} an id which will identify the set of destinations to which
 *                  the traced message shall be sent
 * @return {trace_destination} the destination to which we shall send the packet
 */
typedef trace_dest(*get_next_destination_f)(trace_dest last_dest, int id_hash);


/**
 * generic tracing function in sip context(currently dirrectly related
 * to siptrace module); if custom message needs to be send
 * (with custom chunks for example for proto_hep module)
 * one can choose to use the trace api function along with check_is_traced_f
 * and get_next_destination_f
 * @param {id} id returned by register_trace_type function
 * @param {from_su} data sender
 * @param {to_su} data receiver
 * @param {payload} packet payload
 * @param {net_proto} the protocol that was used for this message
 * @param {correlation_id} string identifier to link this message to the
 *                         sip message; it can be for example the callid
 *
 */
typedef int(*sip_context_trace_f)(int id, union sockaddr_union* from_su,
		union sockaddr_union* to_su, str* payload, int net_proto,
		str* correlation_id);


extern register_trace_type_f register_trace_type;
extern check_is_traced_f check_is_traced;
extern get_next_destination_f get_next_destination;
extern sip_context_trace_f sip_context_trace;


/*
	Type definition for a bind function.
 */
typedef int (*trace_bind_api_f)(trace_proto_t*);

int trace_prot_bind(char* module_name, trace_proto_t* prot);


