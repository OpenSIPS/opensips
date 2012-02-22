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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */

#include "../../evi/evi_transport.h"
#include "../../mem/shm_mem.h"
#include "rabbitmq_send.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define RMQ_SIZE (sizeof(rmq_send_t *))
#define IS_ERR(_err) (errno == _err)


/* used to communicate with the sending process */
static int rmq_pipe[2];

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
	} while ((rc < 0 && (IS_ERR(EINTR)||IS_ERR(EAGAIN)||IS_ERR(EWOULDBLOCK)))
			|| retries-- > 0);

	if (rc < 0) {
		LM_ERR("unable to send rmq send struct to worker\n");
		return -1;
	}
	/* give a change to the writer :) */
	sched_yield();
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
	} while ((rc < 0 && IS_ERR(EINTR)) || retries-- > 0);

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

/* function that checks for error */
static int rmq_error(char const *context, amqp_rpc_reply_t x)
{
	amqp_connection_close_t *mconn;
	amqp_channel_close_t *mchan;

	switch (x.reply_type) {
		case AMQP_RESPONSE_NORMAL:
			return 0;

		case AMQP_RESPONSE_NONE:
			LM_ERR("%s: missing RPC reply type!", context);
			break;

		case AMQP_RESPONSE_LIBRARY_EXCEPTION:
			LM_ERR("%s: %s\n", context,  "(end-of-stream)");
			break;

		case AMQP_RESPONSE_SERVER_EXCEPTION:
			switch (x.reply.id) {
				case AMQP_CONNECTION_CLOSE_METHOD:
					mconn = (amqp_connection_close_t *)x.reply.decoded;
					LM_ERR("%s: server connection error %d, message: %.*s",
							context, mconn->reply_code,
							(int)mconn->reply_text.len,
							(char *)mconn->reply_text.bytes);
					break;
				case AMQP_CHANNEL_CLOSE_METHOD:
						mchan = (amqp_channel_close_t *)x.reply.decoded;
					LM_ERR("%s: server channel error %d, message: %.*s",
							context, mchan->reply_code,
							(int)mchan->reply_text.len,
							(char *)mchan->reply_text.bytes);
					break;
				default:
					LM_ERR("%s: unknown server error, method id 0x%08X",
							context, x.reply.id);
					break;
			}
			break;
	}
	return -1;
}


void rmq_print(evi_reply_sock *sock)
{
	rmq_params_t *rmqp;
	if (!sock) {
		LM_DBG("null sock\n");
		return;
	}
	if (sock->flags & EVI_ADDRESS && sock->address.s)
		LM_DBG("XXX Address: %s\n", sock->address.s);
	else
		LM_DBG("XXX Address not found\n");
	if (sock->flags & EVI_PORT && sock->port)
		LM_DBG("XXX Port: %d\n", sock->port);
	else
		LM_DBG("XXX Port not found\n");
	if (!(sock->flags & EVI_PARAMS)) {
		LM_DBG("XXX Params not found\n");
		return;
	}
	rmqp = (rmq_params_t *)sock->params;
	LM_DBG("XXX Flags %X : %X\n", sock->flags, rmqp->flags);
	if (rmqp->flags & RMQ_PARAM_EXCH && rmqp->exchange.s)
		LM_DBG("XXX Exchange: %s\n", rmqp->exchange.s);
	else
		LM_DBG("XXX Exchange not found\n");
	if (rmqp->flags & RMQ_PARAM_USER && rmqp->user.s)
		LM_DBG("XXX User: %s\n", rmqp->user.s);
	else
		LM_DBG("XXX User not found\n");
	if (rmqp->flags & RMQ_PARAM_PASS && rmqp->pass.s)
		LM_DBG("XXX Pass: %s\n", rmqp->pass.s);
	else
		LM_DBG("XXX Pass not found\n");
	if (rmqp->flags & RMQ_PARAM_CONN && rmqp->conn)
		LM_DBG("XXX Conn: %p\n", rmqp->conn);
	else
		LM_DBG("XXX Conn not found\n");
	LM_DBG("XXX Sock: %d\n", rmqp->sock);
}

void rmq_free_param(rmq_params_t *rmqp)
{
	if ((rmqp->flags & RMQ_PARAM_USER) && rmqp->user.s &&
			rmqp->user.s != (char *)RMQ_DEFAULT_UP)
		shm_free(rmqp->user.s);
	if ((rmqp->flags & RMQ_PARAM_PASS) && rmqp->pass.s &&
			rmqp->pass.s != (char *)RMQ_DEFAULT_UP)
		shm_free(rmqp->pass.s);
	if ((rmqp->flags & RMQ_PARAM_EXCH) && rmqp->exchange.s)
		shm_free(rmqp->exchange.s);
}


void rmq_destroy_param(rmq_params_t *rmqp)
{
	if (!rmqp)
		return;
	if (rmqp->conn && rmqp->flags & RMQ_PARAM_CONN) {
		if (rmqp->flags & RMQ_PARAM_CHAN) {
			rmq_error("closing channel",
					amqp_channel_close(rmqp->conn, rmqp->channel,
						AMQP_REPLY_SUCCESS));
		}
		rmq_error("closing connection",
				amqp_connection_close(rmqp->conn, AMQP_REPLY_SUCCESS));
		if (amqp_destroy_connection(rmqp->conn) < 0)
			LM_ERR("cannot destroy connection\n");
	}

	rmqp->flags &= ~(RMQ_PARAM_CONN|RMQ_PARAM_CHAN);
}

void rmq_destroy(evi_reply_sock *sock)
{
	if (!sock)
		return;
	if ((sock->flags & EVI_ADDRESS) && sock->address.s)
		shm_free(sock->address.s);
	if ((sock->flags & EVI_PARAMS) && sock->params) {
		rmq_free_param((rmq_params_t *)sock->params);
		rmq_destroy_param((rmq_params_t *)sock->params);
	}
	shm_free(sock);
}


static int rmq_reconnect(evi_reply_sock *sock)
{
	rmq_params_t * rmqp = (rmq_params_t *)sock->params;

	if (!rmqp || !(rmqp->flags & RMQ_PARAM_EXCH)) {
		LM_ERR("not enough socket info\n");
		return -1;
	}
//	rmq_print(sock);
	if (!(rmqp->flags & RMQ_PARAM_CONN) || !rmqp->conn) {
		/* init new connection */
		if (!(rmqp->conn = amqp_new_connection())) {
			LM_ERR("cannot create new connection\n");
			return -1;
		}
		rmqp->flags |= RMQ_PARAM_CONN;
		rmqp->sock = amqp_open_socket(sock->address.s, sock->port);
		if (rmqp->sock < 0) {
			LM_ERR("cannot opens socket\n");
			goto destroy_rmqp;
		}
		amqp_set_sockfd(rmqp->conn, rmqp->sock);

		if (rmq_error("Logging in", amqp_login(rmqp->conn,
				RMQ_DEFAULT_VHOST,
				0,
				RMQ_DEFAULT_MAX,
				0,
				AMQP_SASL_METHOD_PLAIN,
				rmqp->flags & RMQ_PARAM_USER ? rmqp->user.s : RMQ_DEFAULT_UP,
				rmqp->flags & RMQ_PARAM_PASS ? rmqp->pass.s : RMQ_DEFAULT_UP)))
			goto destroy_rmqp;
	}
	if (!(rmqp->flags & RMQ_PARAM_CHAN)) {
		rmqp->channel = 1;
		amqp_channel_open(rmqp->conn, rmqp->channel);
		rmqp->flags |= RMQ_PARAM_CHAN;
		if (rmq_error("Opening channel", amqp_get_rpc_reply(rmqp->conn)))
			goto destroy_rmqp;
	}
	return 0;
destroy_rmqp:
	rmq_destroy_param(rmqp);
	return -1;
}

/* sends the buffer */
static int rmq_sendmsg(rmq_send_t *rmqs)
{
	rmq_params_t * rmqp = (rmq_params_t *)rmqs->sock->params;

	/* all checks should be already done */
	return amqp_basic_publish(rmqp->conn,
			rmqp->channel,
			AMQP_EMPTY_BYTES,
			amqp_cstring_bytes(rmqp->exchange.s),
			0,
			0,
			0,
			amqp_cstring_bytes(rmqs->msg));
}

void rmq_process(int rank)
{
	/* init blocking reader */
	rmq_init_reader();
	rmq_send_t * rmqs;

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

		/* check if we should reconnect */
		if (rmq_reconnect(rmqs->sock) < 0) {
			LM_ERR("cannot reconnect socket\n");
			goto end;
		}

		/* send msg */
		if (rmq_sendmsg(rmqs))
			LM_ERR("cannot send message\n");
end:
		if (rmqs)
			shm_free(rmqs);
	}
}
