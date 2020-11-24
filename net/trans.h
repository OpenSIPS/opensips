/*
 * Copyright (C) 2015 OpenSIPS Project
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
 *  2015-01-xx  created (razvanc)
 */

#ifndef _TRANS_TI_H_
#define _TRANS_TI_H_

#include "../ip_addr.h"
#include "api_proto.h"
#include "api_proto_net.h"

struct proto_info {
	/* the name of the protocol */
	char *name;

	/* the default port according to RFC */
	unsigned short default_rfc_port;

	/* proto as ID */
	enum sip_protos id;

	/* the default port, in case it is missing in the listener */
	unsigned short default_port;

	/* bindings for the transport interface */
	struct api_proto tran;

	/* bindings for the net interface */
	struct api_proto_net net;

	/* listeners on this proto */
	struct socket_info *listeners;

	/* default sending interfaces */
	struct socket_info *sendipv4;
	struct socket_info *sendipv6;
};

/* XXX: here it would be nice to have a separate structure that only populates
 * the necessary info, without having access to "private" fields like
 * listeners */
typedef int (*api_proto_init)(struct proto_info *pi);

extern struct proto_info protos[];

#define is_tcp_based_proto(_p) \
	((_p==PROTO_WS)||(protos[_p].net.flags&PROTO_NET_USE_TCP))
/* XXX: this ^ is an ugly hack to detect that WebSocket connections
 * are TCP based, even though the module is not loaded. We need this
 * in scenarios where a WSS client sends transport=ws in the URI's
 * params according to RFC 7118 - razvanc
 */

/* NOTE: make sure trans_load() is called, or you will get false negatives! */
#define is_udp_based_proto(_p) \
	(protos[_p].net.flags&PROTO_NET_USE_UDP)

#define proto_has_listeners(_p) \
	(protos[_p].listeners != NULL)

#define DST_FCNTL_SET_LIFETIME 1

#define trans_set_dst_attr( _rcv, _attr, _val) \
	do { \
		if (protos[(_rcv)->proto].tran.dst_attr) \
			protos[(_rcv)->proto].tran.dst_attr(_rcv,_attr,_val);\
	}while(0)

/*
 * loads the transport protocol
 */
int trans_load(void);

/*
 * adds a new listening socket
 */
int add_listening_socket(struct socket_id *sock);

/*
 * adds a temporary listening socket
 */
int add_cmd_listening_socket(char *name, int port, int proto);

/*
 * fixes temporary listening sockets
 */
int fix_cmd_listening_sockets(void);

/*
 * fixes all socket lists
 */
int fix_all_socket_lists(void);

/*
 * init all registered listening sockets
 */
int trans_init_all_listeners(void);

void print_all_socket_lists(void);

static inline char* get_proto_name(unsigned short proto)
{
	if (proto == PROTO_NONE)
		return "*";
	if (proto >= PROTO_LAST || protos[proto].id == PROTO_NONE)
		return "unknown";
	return protos[proto].name;
}

#endif /* _TRANS_TI_H_ */
