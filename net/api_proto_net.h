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

#ifndef _API_PROTO_NET_H_
#define _API_PROTO_NET_H_

#include "tcp_conn_defs.h"

/* api_proto_net flags */
#define PROTO_NET_USE_TCP	(1<<0) /* set by proto's that are based on TCP */
#define PROTO_NET_USE_UDP	(1<<1) /* set by proto's that are based on UDP */


typedef int  (*proto_net_dgram_read_f)(const struct socket_info *si, int *len);

typedef int  (*proto_net_stream_write_f)(struct tcp_connection *c, int fd);

/**
 * Read a complete SIP message from the network, including its body/payload and
 * also fully process it, through receive_msg() and opensips.cfg routing logic.
 *
 * The function must include sufficient parsing logic in order to overcome
 * the streaming protocol's inherent limitation of not having the data "split"
 * into individual application-layer messages.  For example, implementors may
 * want to block-READ until "Content-Length: " to obtain payload size, then
 * continue READ'ing until EOH, then a final READ for the full body.
 *
 * Possible return values:
 *   -1 :: error during reading, the @c connection is still valid and must be
 *         released by caller
 *    0 :: a complete request was read and processed; check @c->state for
 *         S_CONN_EOF and release @c connection if condition is true
 *    1 :: a complete request was read and processed; the @c ptr is *invalid*
 *         as the connection has already been released, to achieve parallelism
 */
typedef int  (*proto_net_stream_read_f)(struct tcp_connection *c, int *len);
typedef int  (*proto_net_stream_conn_init_f)(struct tcp_connection *c);
typedef void (*proto_net_stream_conn_clean_f)(struct tcp_connection *c);
typedef int  (*proto_net_stream_extra_match_f)(struct tcp_connection *c, void *id);

typedef void (*proto_net_report_f)( int type, unsigned long long conn_id,
		int conn_flags, void *extra);

struct api_proto_net {
	int						flags;
	union {
		struct {
			proto_net_dgram_read_f		read;
		} dgram;
		struct {
			unsigned			async_chunks;
			proto_net_stream_read_f		read;
			proto_net_stream_write_f	write;
			struct {
				proto_net_stream_conn_init_f   init;
				proto_net_stream_conn_clean_f  clean;
				proto_net_stream_extra_match_f match;
			} conn;
		} stream;
	};
	proto_net_report_f		report;
};

#endif /*_API_PROTO_NET_H_ */
