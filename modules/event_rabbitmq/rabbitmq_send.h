/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 *  2011-05-xx  created (razvancrainea)
 */


#ifndef _RMQ_SEND_H_
#define _RMQ_SEND_H_

#include "event_rabbitmq.h"

#define RMQ_SEND_RETRY 3

typedef struct _rmq_send {
	evi_reply_sock *sock;
	evi_async_ctx_t async_ctx;
	char msg[0];
} rmq_send_t;

struct rmq_cb_ipc_param {
	evi_async_ctx_t async_ctx;
	enum evi_status status;
};

void rmq_process(int rank);
int rmq_create_pipe(void);
void rmq_destroy_pipe(void);
int rmq_init_writer(void);
int rmq_send(rmq_send_t * rmqs);
void rmq_free_param(rmq_params_t *rmqp);
void rmq_destroy(evi_reply_sock *sock);

extern struct timeval conn_timeout_tv;
extern str rmq_static_holder;

#endif
