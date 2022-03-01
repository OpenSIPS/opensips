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

#ifndef _PROTO_MSRP_MSRP_PLAIN_H_
#define _PROTO_MSRP_MSRP_PLAIN_H_

extern int msrp_send_timeout;
extern int msrp_max_msg_chunks;
extern int *msrp_trace_is_on;
extern int  msrp_trace_filter_route_id;


int proto_msrp_init_listener(struct socket_info *si);

void msrp_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);

int msrp_write_on_socket(struct tcp_connection *c, int fd,
		char *buf, int len);

int proto_msrp_send(struct socket_info* send_sock,
		char* buf, unsigned int len,
		union sockaddr_union* to, unsigned int id);

int msrp_read_req(struct tcp_connection* con, int* bytes_read);

#endif
