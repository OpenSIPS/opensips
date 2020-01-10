/*
 * Copyright (C) 2019 - OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or * (at your option) any later version
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
 */

#ifndef _NET_TCP_COMMON_H_
#define _NET_TCP_COMMON_H_

/* blocking connect on a non-blocking socket */
int tcp_connect_blocking(int s, const struct sockaddr *servaddr,
		socklen_t addrlen);

/* blocking connect on a non-blocking socket with timeout */
int tcp_connect_blocking_timeout(int s, const struct sockaddr *servaddr,
		socklen_t addrlen, int timeout);

int tcp_sync_connect_fd(union sockaddr_union* src, union sockaddr_union* dst);

struct tcp_connection* tcp_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server, int *fd, int send2main);

/* Attempts do a connect to the given destination. It returns:
 *   1 - connect was done local (completed)
 *   0 - connect launched as async (in progress)
 *  -1 - error
 */
int tcp_async_connect(struct socket_info* send_sock,
					union sockaddr_union* server, int timeout,
					struct tcp_connection** c, int *ret_fd, int send2main);

/* Responsible for writing the TCP send chunks - called under con write lock
 *	* if returns = 1 : the connection will be released for more writting
 *	* if returns = 0 : the connection will be released
 *	* if returns < 0 : the connection will be released as BAD /  broken
 */
int tcp_async_write(struct tcp_connection* con,int fd);

int tcp_write_on_socket(struct tcp_connection* con, int fd,
		char *buf, int len, int write_timeout, int async_write_timeout);

/* adds an async chunk to the connection pending list */
int tcp_async_add_chunk(struct tcp_connection *con, char *buf,
		int len, int lock);

/* returns the first chunk to be written */
struct tcp_async_chunk *tcp_async_get_chunk(struct tcp_connection *con);

void tcp_async_update_write(struct tcp_connection *con, int len);

#endif /* _NET_TCP_COMMON_H_ */
