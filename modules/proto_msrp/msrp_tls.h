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

#ifndef _PROTO_MSRP_MSRP_TLS_H_
#define _PROTO_MSRP_MSRP_TLS_H_


int msrps_conn_extra_match(struct tcp_connection *c, void *id);

int proto_msrps_conn_init(struct tcp_connection* c);

void proto_msrps_conn_clean(struct tcp_connection* c);

void msrps_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);

int msrps_write_on_socket(struct tcp_connection *c, int fd,
		char *buf, int len, int handshake_timeout, int send_timeout);

#endif
