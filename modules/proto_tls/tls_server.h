/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
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
 */

#ifndef tls_server_h
#define tls_server_h

#include <stdio.h>
#include "../../net/tcp_conn.h"


#define F_TLS_DO_ACCEPT  (1<<0)
#define F_TLS_DO_CONNECT (1<<1)

size_t tls_blocking_write(struct tcp_connection *c, int fd,
		const char *buf, size_t len);

size_t tls_read(struct tcp_connection *c,struct tcp_req *r);

int tls_fix_read_conn(struct tcp_connection *c);

int tls_conn_shutdown(struct tcp_connection *c);

int tls_update_fd(struct tcp_connection *c, int fd);

#endif
