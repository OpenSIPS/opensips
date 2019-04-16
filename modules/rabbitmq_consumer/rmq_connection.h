/*
 * Copyright (C) 2019 OpenSIPS Project
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

#ifndef _RMQ_CONNECTION_H_
#define _RMQ_CONNECTION_H_

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include "../../lib/list.h"
#include "../../evi/evi_params.h"
#include "../../evi/evi.h"

#define CONN_PARAMS_SEP ';'
#define NO_CONN_PARAMS 7

#define RMQ_DEFAULT_HEARTBEAT		0 /* 0 - disabled */
#define RMQ_MIN_FRAME_MAX			4096
#define RMQ_DEFAULT_FRAME_MAX		131072

#define RMQ_FLAG_ACK		(1<<0)  /* server will expect message ACK's */
#define RMQ_FLAG_EXCLUSIVE	(1<<1)  /* request exclusive consumer access */

#define RMQ_MAX_CONNS 32
#define RMQ_DEFAULT_CONNECT_TIMEOUT 500 /* ms */
#define RMQ_DEFAULT_RETRY_TIMEOUT 5000 /* ms */
#define RMQ_POLL_TIMEOUT 250  /* ms */


enum rmq_conn_state {RMQ_CONN_NONE, RMQ_CONN_SOCK, RMQ_CONN_LOGIN, RMQ_CONN_CHAN};

enum rmq_rpc_err_type {RMQ_ERR=-1, RMQ_ERR_CLOSE_CONN=-2, RMQ_ERR_CLOSE_CHAN=-3};

struct rmq_connection {
	struct amqp_connection_info uri;
	amqp_bytes_t queue;
	str event_name;
	int heartbeat;
	int frame_max;
	int flags;

	enum rmq_conn_state state;
	int pfds_idx;
	struct timeval timeout_start;
	amqp_connection_state_t amqp_conn;
	event_id_t evi_id;
	evi_params_p evi_params;
	evi_param_p evi_body_param;

	struct list_head list;
};

extern int rmq_connect_timeout;
extern int rmq_retry_timeout;

void rmq_cons_process(int proc_no);
int rmq_conn_add(modparam_t type, void *val);

#endif /* _RMQ_CONNECTION_H_ */
