/*
 * Copyright (C) 2017 OpenSIPS Project
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
 * History:
 * ---------
 *  2017-01-24  created (razvanc)
 */

#ifndef _RMQ_SERVERS_H_
#define _RMQ_SERVERS_H_

#define RMQ_DEFAULT_HEARTBEAT		0 /* 0 seconds - disabled */
#define RMQ_DEFAULT_RETRIES			0 /* 0 times - do not retry */
#define RMQ_MIN_FRAMES				4096
#define RMQ_DEFAULT_FRAMES			131072

#include <amqp.h>

/* AMQP_VERSION was only added in v0.4.0 - there is no way to check the
 * version of the library before this, so we consider everything beyond v0.4.0
 * as old and inneficient */
#if defined AMQP_VERSION && AMQP_VERSION >= 0x00040000
  #define AMQP_VERSION_v04
#include <amqp_tcp_socket.h>
#define rmq_uri struct amqp_connection_info
#define RMQ_EMPTY amqp_empty_bytes
#else
/* although struct amqp_connection_info was added in v0.2.0, there is no way
 * to check against that version, so we assume it does not exist until v0.4.0
 */
typedef struct _rmq_uri {
	char *user;
	char *password;
	char *host;
	char *vhost;
	int port;
	int ssl;
} rmq_uri;
#define RMQ_EMPTY AMQP_EMPTY_BYTES
#endif


enum rmq_server_state { RMQS_OFF, RMQS_INIT, RMQS_CONN, RMQS_ON };

#define RMQF_IMM	(1<<0) /* message MUST be delivered to a consumer immediately. */
#define RMQF_MAND	(1<<1) /* message MUST be routed to a queue */
#define RMQF_NOPER	(1<<2) /* message must not be persistent */

struct rmq_server {
	enum rmq_server_state state;
	str cid; /* connection id */
	struct list_head list;

	rmq_uri uri;
	unsigned flags;
	int retries;
	int heartbeat;
	int max_frames;
	amqp_bytes_t exchange;
	amqp_connection_state_t conn;
};

int rmq_server_add(modparam_t type, void * val);
int rmq_reconnect(struct rmq_server *srv);
int fixup_rmq_server(void **param);
struct rmq_server *rmq_get_server(str *cid);
void rmq_connect_servers(void);

int rmq_send(struct rmq_server *srv, str *rkey, str *body, str *ctype,
		int *names, int *values);

#endif /* _RMQ_SERVERS_H_ */
