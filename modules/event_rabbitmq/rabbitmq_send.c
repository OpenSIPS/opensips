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

#include "../../evi/evi_transport.h"
#include "../../mem/shm_mem.h"
#include "../../pt.h"
#include "rabbitmq_send.h"
#include "rmq_servers.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define RMQ_SIZE (sizeof(rmq_send_t *))
#define IS_ERR(_err) (errno == _err)

/* used to communicate with the sending process */
static int rmq_pipe[2];

str rmq_static_holder = str_init(RMQ_DEFAULT_UP);

/* creates communication pipe */
int rmq_create_pipe(void)
{
	int rc;

	rmq_pipe[0] = rmq_pipe[1] = -1;
	/* create pipe */
	do {
		rc = pipe(rmq_pipe);
	} while (rc < 0 && IS_ERR(EINTR));

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}
	return 0;
}

void rmq_destroy_pipe(void)
{
	if (rmq_pipe[0] != -1)
		close(rmq_pipe[0]);
	if (rmq_pipe[1] != -1)
		close(rmq_pipe[1]);
}

int rmq_send(rmq_send_t* rmqs)
{
	int rc;
	int retries = RMQ_SEND_RETRY;

	do {
		rc = write(rmq_pipe[1], &rmqs, RMQ_SIZE);
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("unable to send rmq send struct to worker\n");
		shm_free(rmqs);
		return -1;
	}

	return 0;
}

static rmq_send_t * rmq_receive(void)
{
	int rc;
	int retries = RMQ_SEND_RETRY;
	rmq_send_t * recv;

	if (rmq_pipe[0] == -1)
		return NULL;

	do {
		rc = read(rmq_pipe[0], &recv, RMQ_SIZE);
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("cannot receive send param\n");
		return NULL;
	}
	return recv;
}

int rmq_init_writer(void)
{
	int flags;

	if (rmq_pipe[0] != -1) {
		close(rmq_pipe[0]);
		rmq_pipe[0] = -1;
	}

	/* Turn non-blocking mode on for sending*/
	flags = fcntl(rmq_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(rmq_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(rmq_pipe[1]);
	rmq_pipe[1] = -1;
	return -1;
}

static void rmq_init_reader(void)
{
	if (rmq_pipe[1] != -1) {
		close(rmq_pipe[1]);
		rmq_pipe[1] = -1;
	}
}

void rmq_free_param(rmq_params_t *rmqp)
{
	if ((rmqp->conn.flags & RMQ_PARAM_USER) && rmqp->conn.uri.user &&
			rmqp->conn.uri.user != rmq_static_holder.s)
		shm_free(rmqp->conn.uri.user);
	if ((rmqp->conn.flags & RMQ_PARAM_PASS) && rmqp->conn.uri.password &&
			rmqp->conn.uri.password != rmq_static_holder.s)
		shm_free(rmqp->conn.uri.password);
	if ((rmqp->conn.flags & RMQF_MAND) && rmqp->routing_key.s)
		shm_free(rmqp->routing_key.s);
}

void rmq_destroy_connection(rmq_connection_t *conn)
{
	switch (conn->state)
	{
	case RMQS_ON:
	case RMQS_CONN:
		rmq_error("closing channel",
				amqp_channel_close(conn->conn, RMQ_DEFAULT_CHANNEL, AMQP_REPLY_SUCCESS));
	case RMQS_INIT:
		rmq_error("closing connection",
				amqp_connection_close(conn->conn, AMQP_REPLY_SUCCESS));
		if (amqp_destroy_connection(conn->conn) < 0)
			LM_ERR("cannot destroy connection\n");
	case RMQS_OFF:
		break;
	default:
		LM_WARN("Unknown rmq server state %d\n", conn->state);
	}

	conn->state = RMQS_OFF;

	if (conn->tls_dom) {
		tls_api.release_domain(conn->tls_dom);
		conn->tls_dom = NULL;
	}
}

void rmq_destroy(evi_reply_sock *sock)
{
	if (!sock)
		return;
	if ((sock->flags & EVI_ADDRESS) && sock->address.s)
		shm_free(sock->address.s);
	if ((sock->flags & EVI_PARAMS) && sock->params) {
		rmq_free_param((rmq_params_t *)sock->params);
		rmq_params_t *rmqp = (rmq_params_t *)sock->params;
		rmq_destroy_connection(&rmqp->conn);
	}
	shm_free(sock);
}

/* sends the buffer */
static int rmq_sendmsg(rmq_send_t *rmqs)
{
	rmq_params_t * rmqp = (rmq_params_t *)rmqs->sock->params;
	int ret;
	int re_publish = 0;
	amqp_basic_properties_t props;

	if (!rmqp || !(rmqp->conn.flags & RMQF_MAND)) {
		LM_ERR("not enough socket info\n");
		return -1;;
	}

	if (rmqp->conn.state == RMQS_OFF)
		return 0;

	rmqp->conn.uri.host = rmqs->sock->address.s;

	rmqp->conn.uri.port = rmqs->sock->port;

	ret = rmq_basic_publish(&rmqp->conn,
			RMQ_DEFAULT_FRAMES,
			&rmqs->sock->address,
			amqp_cstring_bytes(rmqp->routing_key.s),
			amqp_cstring_bytes(rmqs->msg),
			((rmqp->conn.flags & RMQF_NOPER)?&props:0),
			re_publish);

	return ret;
}

void rmq_run_status_cb(int sender, void *param)
{
	struct rmq_cb_ipc_param *cb_ipc_param =
		(struct rmq_cb_ipc_param *)param;

	cb_ipc_param->async_ctx.status_cb(cb_ipc_param->async_ctx.cb_param,
		cb_ipc_param->status);

	shm_free(cb_ipc_param);
}

static void rmq_dispatch_status_cb(evi_async_ctx_t *async_ctx,
	enum evi_status status)
{
	struct rmq_cb_ipc_param *cb_ipc_param;

	cb_ipc_param = shm_malloc(sizeof *cb_ipc_param);
	if (!cb_ipc_param) {
		LM_ERR("oom!\n");
		return;
	}

	cb_ipc_param->async_ctx = *async_ctx;
	cb_ipc_param->status = status;

	ipc_dispatch_rpc(rmq_run_status_cb, cb_ipc_param);
}

void rmq_process(int rank)
{
	enum evi_status status;

	/* init blocking reader */
	rmq_init_reader();
	rmq_send_t * rmqs;

	/* suppress the E_CORE_LOG event for new logs while handling
	 * the event itself */
	suppress_proc_log_event();

	/* waiting for commands */
	for (;;) {
		rmqs = rmq_receive();
		if (!rmqs || !rmqs->sock) {
			LM_ERR("invalid receive sock info received\n");
			goto end;
		}
		/* check if we should disconnect it */
		if (!rmqs->msg[0]) {
			rmq_destroy(rmqs->sock);
			goto end;
		}
		/* send msg */
		if (rmq_sendmsg(rmqs)) {
			LM_ERR("cannot send message\n");
			status = EVI_STATUS_FAIL;
		} else {
			status = EVI_STATUS_SUCCESS;
		}

		if (rmqs->async_ctx.status_cb)
			rmq_dispatch_status_cb(&rmqs->async_ctx, status);
end:
		if (rmqs)
			shm_free(rmqs);
	}

	reset_proc_log_event();
}
