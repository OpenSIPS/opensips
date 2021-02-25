/*
 * Copyright (C) 2021 - OpenSIPS Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 *
 */

#ifndef TLS_OPS_API_H
#define TLS_OPS_API_H

#include "../../net/tcp_conn_defs.h"

typedef int (*tls_conn_init_f)(struct tcp_connection *c);
typedef void (*tls_conn_clean_f)(struct tcp_connection* c);
typedef int (*tls_update_fd_f)(struct tcp_connection* c, int fd);
typedef int (*tls_async_connect_f)(struct tcp_connection *con, int fd,
	int timeout);
typedef int (*tls_write_f)(struct tcp_connection *c, int fd, const void *buf,
	size_t len, short *poll_events);
typedef int (*tls_blocking_write_f)(struct tcp_connection *c, int fd,
	const char *buf, size_t len, int handshake_timeout, int send_timeout);
typedef int (*tls_fix_read_conn_f)(struct tcp_connection *c, int fd,
	int async_timeout, int lock);
typedef int (*tls_read_f)(struct tcp_connection * c,struct tcp_req *r);

#define TLS_OPS_API_BINDS \
	tls_conn_init_f tls_conn_init; \
	tls_conn_clean_f tls_conn_clean; \
	tls_update_fd_f tls_update_fd; \
	tls_async_connect_f tls_async_connect; \
	tls_write_f tls_write; \
	tls_blocking_write_f tls_blocking_write; \
	tls_fix_read_conn_f tls_fix_read_conn; \
	tls_read_f tls_read; \

#endif	/* TLS_OPS_API_H */