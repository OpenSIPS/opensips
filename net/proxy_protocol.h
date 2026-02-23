/*
 * Copyright (C) 2025 OpenSIPS Solutions
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
 */

#ifndef NET_PROXY_PROTOCOL_H
#define NET_PROXY_PROTOCOL_H

struct tcp_connection;
struct receive_info;
struct ip_addr;

/* Maximum length of a v1 PROXY header ("PROXY UNKNOWN\\r\\n" bound from spec). */
#define PROXY_PROTOCOL_BUF_MAX 107

int check_tcp_proxy_protocol(struct tcp_connection *c);
int check_udp_proxy_protocol(char **buf, int *size, struct receive_info *ri);
int build_outbound_proxy_protocol_v1_hdr(const struct receive_info *ri,
		const struct ip_addr *fallback_src_ip,
		unsigned short fallback_src_port,
		const struct ip_addr *fallback_dst_ip,
		unsigned short fallback_dst_port,
		char *buf, int size);
int send_stream_proxy_protocol_v1(struct tcp_connection *c, int fd,
		int write_timeout, int lock,
		const struct receive_info *ri, const char *proto_name);

#endif /* NET_PROXY_PROTOCOL_H */
