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
#include "tcp_conn_profile.h"

#define TCP_PARTITION_SIZE 32

extern int tcp_workers_max_no;

typedef int (*tcp_thread_job_f)(void *data);

/**************************** Control functions ******************************/

/* initializes the TCP structures */
int tcp_init(void);

/* destroys the TCP data */
void tcp_destroy(void);

/* checks if the TCP layer may provide async write support */
int tcp_has_async_write(void);


/* tells how many processes the TCP layer will create */
int tcp_count_processes(unsigned int *extra);

/* starts all TCP worker processes */
int tcp_start_processes(int *chd_rank, int *startup_done);

/* starts the TCP listening process */
int tcp_start_listener(void);

void tcp_reset_worker_slot(void);

/* MI function to list all existing TCP connections */
mi_response_t *mi_tcp_list_conns(const mi_params_t *params,
							struct mi_handler *async_hdl);

/* MI function to close a given TCP connections */
mi_response_t *mi_tcp_close_conn(const mi_params_t *params,
						struct mi_handler *async_hdl);

/* close a TCP-based connection identified by remote ip:port */
int tcp_close_connection(str *ipport);


/************************* TCP net helper functions **************************/

/* initializes an already defined TCP listener */
int tcp_init_listener(struct socket_info *si);
int tcp_bind_listener(struct socket_info *si);

struct tcp_req *tcp_conn_get_req(struct tcp_connection *c);
void tcp_conn_destroy_req(struct tcp_connection *c);

/* helper function to set all TCP related options to a socket */
int tcp_init_sock_opt(int s, const struct tcp_conn_profile *prof, enum si_flags socketflags, int sock_tos);

/********************** TCP conn management functions ************************/

/* returns the shared connection identified by either the id or destination */
int tcp_conn_get(int unsigned id, struct ip_addr* ip, int port,
		enum sip_protos proto, void *proto_extra_id,
		struct tcp_connection** conn, const struct socket_info* send_sock);

/* creates a new tcp conn around a newly connected socket */
struct tcp_connection* tcp_conn_create(const union sockaddr_union* su,
		const struct socket_info* si, struct tcp_conn_profile *prof,
		int state);

/* true when TCP main owns the write path and IO threads handle flushing */
int tcp_write_in_main(void);

/* release a connection acquired via tcp_conn_get() or tcp_conn_create() */
void tcp_conn_release(struct tcp_connection* c, int pending_data);

/* destroys a connection before sending it to main */
void tcp_conn_destroy(struct tcp_connection* tcpconn);

/* used to tune the connection attributes */
int tcp_conn_fcntl(struct receive_info *rcv, int attr, void *value);

/* returns the correlation ID of a TCP connection */
int tcp_get_correlation_id( unsigned int id, unsigned long long *cid);

/* returns the receive_info of a TCP connection */
int tcp_get_rcv(unsigned int id, struct receive_info *ri);

/* returns the process-table slot of TCP main */
int tcp_get_main_proc_no(void);

int tcp_run_task(tcp_thread_job_f run, void *data);
int tcp_async_write_job(struct tcp_connection *tcpconn);

/* either process locally or dispatch to an OpenSIPS worker via IPC */
int tcp_dispatch_msg(char *msg, int len,
		struct receive_info *rcv, const void *data, int data_len);

extern unsigned int last_outgoing_tcp_id;

#endif /* _NET_TCP_H_ */
