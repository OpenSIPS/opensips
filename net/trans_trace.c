/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include "../trace_api.h"
#include "trans_trace.h"

str trans_trace_str_status[] = {
	str_init("SUCCESS"),
	str_init("FAILURE")
};

str trans_trace_str_event[] = {
	str_init("ACCEPTED"),
	str_init("CONNECT_START"),
	str_init("CONNECTED"),
	str_init("CLOSED"),
	str_init("STATS")
};

static str TCP_PROTO_ID = str_init("TCP");
static str TLS_PROTO_ID = str_init("TLS");
static str WS_PROTO_ID = str_init("WS");
static str WSS_PROTO_ID = str_init("WSS");

/* error reasons */
str AS_CONNECT_INIT = str_init("Async connect in progress...");
str CONNECT_OK = str_init("Successfully connected...");
str ASYNC_CONNECT_OK = str_init("Successfully connected asynchronously...");
str ACCEPT_OK = str_init("Connection accepted...");
str ACCEPT_FAIL = str_init("Failed to accept connection...");
str CONNECT_FAIL = str_init("Failed to connect...");



static void add_proto( trace_message message, int proto);

int net_trace_proto_id=-1;
trace_proto_t* net_trace_api=0;

trace_message create_trace_message( unsigned long long id, union sockaddr_union* src,
						union sockaddr_union* dst, int proto, void* dest)
{
	int net_proto;
	static int correlation_id = -1, correlation_vendor = -1;

	str str_id;

	if ( !net_trace_api ) {
		LM_BUG("trace api not loaded! should have been loaded!\n");
		return 0;
	}

	trace_message message;
	switch ( proto ) {
		case PROTO_TCP:
			net_proto = IPPROTO_TCP;
			break;
		case PROTO_TLS:
			net_proto = IPPROTO_IDP;
			break;
		case PROTO_WS:
			net_proto = IPPROTO_ESP;
			break;
		case PROTO_WSS:
			net_proto = IPPROTO_ESP;
			break;
		default:
			return 0;
	}

	message = net_trace_api->create_trace_message( src, dst,
			net_proto, 0, net_trace_proto_id, dest);

	str_id.s = int2str( id, &str_id.len );
	if ( correlation_vendor == -1 || correlation_id == - 1) {
		if ( net_trace_api->get_data_id("correlation_id", &correlation_vendor, &correlation_id ) < 0 ) {
			LM_ERR("can't find correlation id chunk!\n");
			return 0;
		}
	}

	if ( net_trace_api->add_chunk( message, str_id.s, str_id.len, TRACE_TYPE_STR,
			correlation_id, correlation_vendor) < 0) {
		LM_ERR("failed to add correlation id! aborting trace...!\n");
		return 0;
	}
	add_proto( message, proto);

	return message;
}


void add_trace_data( void* message, char* key, str* value)
{
	if ( !message || !key || !value || !value->len || !value->s ) {
		LM_ERR("invalid input data!\n");
		return;
	}

	net_trace_api->add_payload_part( message, key, value);

	return;
}

int send_trace_message( void* message, void* destination)
{
	if ( net_trace_api->send_message( message, destination, 0) < 0 ) {
		LM_ERR("failed to trace message!\n");
		net_trace_api->free_message( message );
		return -1;
	}

	net_trace_api->free_message( message );

	return 0;
}

static void add_proto( trace_message message, int proto)
{
	switch ( proto ) {
		case PROTO_TCP:
			add_trace_data( message, "Protocol", &TCP_PROTO_ID );
			break;
		case PROTO_TLS:
			add_trace_data( message, "Protocol", &TLS_PROTO_ID );
			break;
		case PROTO_WS:
			add_trace_data( message, "Protocol", &WS_PROTO_ID );
			break;
		case PROTO_WSS:
			add_trace_data( message, "Protocol", &WSS_PROTO_ID );
			break;
		default:
			break;
	}
}

int trace_message_atonce( int proto, unsigned long long id, union sockaddr_union* src,
						union sockaddr_union* dst,trans_trace_event event,
						trans_trace_status status, str* data, void* destination)
{
	trace_message message;

	message = create_trace_message( id, src, dst, proto, destination);
	if ( !message ) {
		LM_ERR("failed to create the message!\n");
		return -1;
	}

	add_trace_data( message, "Event", &trans_trace_str_event[event]);
	add_trace_data( message, "Status", &trans_trace_str_status[status]);

	if ( data && data->s && data->len) {
		add_trace_data( message, "Message", data);
	}


	if ( send_trace_message( message, destination) < 0 ) {
		LM_ERR("failed to send message!\n");
		return -1;
	}


	return 0;
}


int tcpconn2su( struct tcp_connection* c, union sockaddr_union* src_su,
		union sockaddr_union* dst_su)
{

	if ( !c || !src_su || !dst_su ) {
		LM_ERR("bad input!\n");
		return -1;
	}

	if ( init_su( src_su, &c->rcv.src_ip, c->rcv.src_port) < 0 ) {
		LM_ERR("failed to create source su!\n");
		return -1;
	}

	if ( init_su( dst_su, &c->rcv.dst_ip, c->rcv.dst_port) < 0 ) {
		LM_ERR("failed to create destination su!\n");
		return -1;
	}

	return 0;
}


int check_trace_route( int route_id, struct tcp_connection* conn)
{
	struct sip_msg *req;

	/* route not set */
	if ( route_id == -1 )
		return 1;

	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("No more memory\n");
		return -1;
	}

	/* set request route type */
	set_route_type( REQUEST_ROUTE );

	memcpy( &req->rcv, &conn->rcv, sizeof( struct receive_info ));

	/* run given hep route */
	if (run_top_route(sroutes->request[route_id].a, req) & ACT_FL_DROP){
		conn->flags |= F_CONN_TRACE_DROPPED;
		release_dummy_sip_msg(req);
		return 0;
	}

	release_dummy_sip_msg(req);
	return 1;
}
