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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#ifndef _NET_TCP_H_
#define _NET_TCP_H_

#include "tcp_conn.h"

// initializes the TCP structures
int tcp_init(void);

// destroys the TCP data
void tcp_destroy(void);

// looks for the transport protocol that knows how to handle the
// proto and calls the corresponding add_listener() function
int tcp_add_listener(char* host, int port, int type, void *ctx);

// used to return a listener
struct socket_info* tcp_find_listener(union sockaddr_union* to, int proto);

// initializes the TCP listeners
int tcp_init_listeners(void);

// returns the connection identified by either the id or the destination to
struct tcp_connection* tcp_conn_get(int id, union sockaddr_union* to);

// used to tune the connection attributes
int tcp_conn_fcntl(struct tcp_connection *conn, int attr, void *value);

#endif /* _NET_TCP_H_ */
