/*
 *  $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef tls_server_h
#define tls_server_h

#include <stdio.h>
#include "../tcp_conn.h"

/*
 * dump ssl error stack 
 */
void            tls_print_errstack(void);

/*
 * Called when new tcp connection is accepted 
 */
int             tls_tcpconn_init(struct tcp_connection *c, int sock);

/*
 * clean the extra data upon connection shut down 
 */
void            tls_tcpconn_clean(struct tcp_connection *c);

/*
 * shut down the TLS connection 
 */
void            tls_close(struct tcp_connection *c, int fd);

size_t          tls_blocking_write(struct tcp_connection *c, int fd,
				   const char *buf, size_t len);

size_t          tls_read(struct tcp_connection *c);

int             tls_fix_read_conn(struct tcp_connection *c);

#endif
