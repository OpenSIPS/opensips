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

#ifndef _NET_TCP_H_
#define _NET_TCP_H_

#include "../mi/mi.h"
#include "tcp_conn_defs.h"

#define TCP_PARTITION_SIZE 32

/**************************** Control functions ******************************/

/* initializes the TCP structures */
int tcp_init(void);

/* destroys the TCP data */
void tcp_destroy(void);

/* checks if the TCP layer may provide async write support */
int tcp_has_async_write(void);

/* creates the communication channel between a generic OpenSIPS process
   and the TCP MAIN process - TO BE called before forking */
int tcp_pre_connect_proc_to_tcp_main( int proc_no );

/* same as above, but to be called after forking, both in child and parent */
void tcp_connect_proc_to_tcp_main( int proc_no, int chid );

/* tells how many processes the TCP layer will create */
int tcp_count_processes(void);

/* starts all TCP related processes */
int tcp_start_processes(int *chd_rank, int *startup_done);

/* MI function to list all existing TCP connections */
struct mi_root *mi_tcp_list_conns(struct mi_root *cmd, void *param);


/************************* TCP net helper functions **************************/

/* initializes an already defined TCP listener */
int tcp_init_listener(struct socket_info *si);

/* helper function to set all TCP related options to a socket */
int tcp_init_sock_opt(int s);

/* blocking connect on a non-blocking socket */
int tcp_connect_blocking(int s, const struct sockaddr *servaddr,
		socklen_t addrlen);

/********************** TCP conn management functions ************************/

/* returns the connection identified by either the id or the destination to */
int tcp_conn_get(int id, struct ip_addr* ip, int port, enum sip_protos proto,
		struct tcp_connection** conn, int* conn_fd);

/* creates a new tcp conn around a newly connected socket
 * and sends it to the master */
struct tcp_connection* tcp_conn_create(int sock, union sockaddr_union* su,
		struct socket_info* si, int state);

/* creates a new tcp conn around a newly connected socket */
struct tcp_connection* tcp_conn_new(int sock, union sockaddr_union* su,
		struct socket_info* si, int state);

/* sends a connected connection to the master */
int tcp_conn_send(struct tcp_connection *con);

/* release a connection aquired via tcp_conn_get() or tcp_conn_create() */
void tcp_conn_release(struct tcp_connection* c, int pending_data);

/* destroys a connection before sending it to main */
void tcp_conn_destroy(struct tcp_connection* tcpconn);

/* used to tune the connection attributes */
int tcp_conn_fcntl(struct receive_info *rcv, int attr, void *value);

#endif /* _NET_TCP_H_ */
