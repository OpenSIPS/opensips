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

/* function that checks for error */
static int rmq_error(char const *context, amqp_rpc_reply_t x)
{
	amqp_connection_close_t *mconn;
	amqp_channel_close_t *mchan;
#ifndef AMQP_VERSION_v04
	char *errorstr;
#endif

	switch (x.reply_type) {
		case AMQP_RESPONSE_NORMAL:
			return 0;

		case AMQP_RESPONSE_NONE:
			LM_ERR("%s: missing RPC reply type!", context);
			break;

		case AMQP_RESPONSE_LIBRARY_EXCEPTION:
#ifndef AMQP_VERSION_v04
			errorstr = amqp_error_string(x.library_error);
			LM_ERR("%s: %s\n", context, errorstr);
			free(errorstr);
#else
			LM_ERR("%s: %s\n", context, amqp_error_string2(x.library_error));
#endif
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


void rmq_free_param(rmq_params_t *rmqp)
{
	if ((rmqp->flags & RMQ_PARAM_USER) && rmqp->user.s &&
			rmqp->user.s != rmq_static_holder.s)
		shm_free(rmqp->user.s);
	if ((rmqp->flags & RMQ_PARAM_PASS) && rmqp->pass.s &&
			rmqp->pass.s != rmq_static_holder.s)
		shm_free(rmqp->pass.s);
	if ((rmqp->flags & RMQ_PARAM_RKEY) && rmqp->routing_key.s)
		shm_free(rmqp->routing_key.s);
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

	if (rmqp->tls_dom) {
		tls_api.release_domain(rmqp->tls_dom);
		rmqp->tls_dom = NULL;
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
#if defined AMQP_VERSION_v04
	amqp_socket_t *amqp_sock;
#endif
	int socket;

	if (!rmqp || !(rmqp->flags & RMQ_PARAM_RKEY)) {
		LM_ERR("not enough socket info\n");
		return -1;
	}
	if (!(rmqp->flags & RMQ_PARAM_CONN) || !rmqp->conn) {
		/* init new connection */
		if (!(rmqp->conn = amqp_new_connection())) {
			LM_ERR("cannot create new connection\n");
			return -1;
		}
#if defined AMQP_VERSION_v04
		if (use_tls && (rmqp->flags&RMQ_PARAM_TLS)) {
			if (!rmqp->tls_dom) {
				rmqp->tls_dom = tls_api.find_client_domain_name(&rmqp->tls_dom_name);
				if (!rmqp->tls_dom) {
					LM_ERR("TLS domain: '%.*s' not found\n",
						rmqp->tls_dom_name.len, rmqp->tls_dom_name.s);
					goto destroy_rmqp;
				}
			}

			amqp_sock = amqp_ssl_socket_new(rmqp->conn);
			if (!amqp_sock) {
				LM_ERR("cannot create AMQP TLS socket\n");
				goto destroy_rmqp;
			}

			if (amqp_ssl_socket_set_cacert(amqp_sock, rmqp->tls_dom->ca.s) !=
				AMQP_STATUS_OK) {
				LM_ERR("Failed to set CA certificate\n");
				goto destroy_rmqp;
			}

			if (amqp_ssl_socket_set_key(amqp_sock, rmqp->tls_dom->cert.s,
				rmqp->tls_dom->pkey.s) != AMQP_STATUS_OK) {
				LM_ERR("Failed to set certificate and private key\n");
				goto destroy_rmqp;
			}

			#if AMQP_VERSION >= 0x00080000
			amqp_ssl_socket_set_verify_peer(amqp_sock, rmqp->tls_dom->verify_cert);
			amqp_ssl_socket_set_verify_hostname(amqp_sock, 0);
			#else
			amqp_ssl_socket_set_verify(amqp_sock, rmqp->tls_dom->verify_cert);
			#endif

			#if AMQP_VERSION >= 0x00080000
			amqp_tls_version_t method_min, method_max;

			if (rmqp->tls_dom->method != TLS_METHOD_UNSPEC) {
				switch (rmqp->tls_dom->method) {
				case TLS_USE_TLSv1:
					method_min = AMQP_TLSv1;
					break;
				case TLS_USE_TLSv1_2:
					method_min = AMQP_TLSv1_2;
					break;
				default:
					LM_NOTICE("Unsupported TLS minimum method for AMQP, using TLSv1\n");
					method_min = AMQP_TLSv1;
				}
			} else {
				LM_DBG("Minimum TLS method unspecified, using TLSv1\n");
				method_min = AMQP_TLSv1;
			}

			if (rmqp->tls_dom->method_max != TLS_METHOD_UNSPEC) {
				switch (rmqp->tls_dom->method_max) {
				case TLS_USE_TLSv1:
					method_max = AMQP_TLSv1;
					break;
				case TLS_USE_TLSv1_2:
					method_max = AMQP_TLSv1_2;
					break;
				default:
					LM_NOTICE("Unsupported TLS maximum method for AMQP, using latest"
						" supported by librabbitmq\n");
					method_max = AMQP_TLSvLATEST;
				}
			} else {
				method_max = AMQP_TLSvLATEST;
				LM_DBG("Maximum TLS method unspecified, using latest supported by"
					" librabbitmq\n");
			}

			if (amqp_ssl_socket_set_ssl_versions(amqp_sock, method_min, method_max) !=
				AMQP_STATUS_OK) {
				LM_ERR("Failed to set TLS method range\n");
				goto destroy_rmqp;
			}
			#endif
		} else {
			amqp_sock = amqp_tcp_socket_new(rmqp->conn);
			if (!amqp_sock) {
				LM_ERR("cannot create AMQP socket\n");
				goto destroy_rmqp;
			}
		}

		socket = amqp_socket_open_noblock(amqp_sock, sock->address.s,
			sock->port, &conn_timeout_tv);
		if (socket < 0) {
			amqp_connection_close(rmqp->conn, AMQP_REPLY_SUCCESS);
			LM_ERR("cannot open AMQP socket: %d\n", socket);
			goto destroy_rmqp;
		}
#else
		socket = amqp_open_socket_noblock(sock->address.s, sock->port,
			&conn_timeout_tv);
		if (socket < 0) {
			LM_ERR("cannot open AMQP socket\n");
			goto destroy_rmqp;
		}
		amqp_set_sockfd(rmqp->conn, socket);
#endif

		rmqp->flags |= RMQ_PARAM_CONN;
		if (rmq_error("Logging in", amqp_login(
				rmqp->conn,
				RMQ_DEFAULT_VHOST,
				0,
				RMQ_DEFAULT_MAX,
				rmqp->heartbeat,
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

#ifdef AMQP_VERSION_v04
static inline int amqp_check_status(rmq_params_t *rmqp, int r, int* re_publish)
{
	switch (r) {
		case AMQP_STATUS_OK:
			return 0;

		case AMQP_STATUS_NO_MEMORY:
			LM_ERR("no more memory\n");
			goto no_close;

		case AMQP_STATUS_TABLE_TOO_BIG:
			LM_ERR("A table in the properties was too large to fit in a single frame\n");
			goto no_close;

		case AMQP_STATUS_HEARTBEAT_TIMEOUT:
			LM_ERR("heartbeat timeout\n");
			break;

		case AMQP_STATUS_CONNECTION_CLOSED:
			LM_ERR("Connection closed\n");
			break;

		/* this should not happened since we do not use ssl */
		case AMQP_STATUS_SSL_ERROR:
			LM_ERR("SSL error\n");
			break;

		case AMQP_STATUS_TCP_ERROR:
			LM_ERR("TCP error: %s(%d)\n", strerror(errno), errno);
			break;

		/* This is happening on rabbitmq server restart */
		case AMQP_STATUS_SOCKET_ERROR:
			LM_WARN("Socket error\n");
			if (*re_publish == 0) *re_publish = 1;
			break;

		default:
			LM_ERR("Unknown AMQP error[%d]: %s(%d)\n", r, strerror(errno), errno);
			break;
	}
	/* we close the connection here to be able to re-connect later */
	rmq_destroy_param(rmqp);
no_close:
	return r;
}
#else
static inline int amqp_check_status(rmq_params_t *rmqp, int r, int* re_publish)
{
	if (r != 0) {
		LM_ERR("Unknown AMQP error [%d] while sending\n", r);
		/* we close the connection here to be able to re-connect later */
		rmq_destroy_param(rmqp);
		return -1;
	}
	return 0;
}
#endif

/* sends the buffer */
static int rmq_sendmsg(rmq_send_t *rmqs)
{
	rmq_params_t * rmqp = (rmq_params_t *)rmqs->sock->params;
	int ret,rtrn;
	int re_publish = 0;
	amqp_basic_properties_t props;

	if (!(rmqp->flags & RMQ_PARAM_CONN))
		return 0;

	if (rmqp->flags & RMQ_PARAM_PERS) {
		memset(&props, 0, sizeof props);
		props.delivery_mode = 2;
		props._flags |= AMQP_BASIC_DELIVERY_MODE_FLAG;
	}
	
	/* all checks should be already done */
	ret = amqp_basic_publish(rmqp->conn,
			rmqp->channel,
			rmqp->flags&RMQ_PARAM_EKEY?
		 		amqp_cstring_bytes(rmqp->exchange.s) :
				AMQP_EMPTY_BYTES ,
			amqp_cstring_bytes(rmqp->routing_key.s),
			0,
			0,
			((rmqp->flags & RMQ_PARAM_PERS)?&props:0),
			amqp_cstring_bytes(rmqs->msg));

	rtrn = amqp_check_status(rmqp, ret, &re_publish);

	if (rtrn != 0 && re_publish != 0) {
		if (rmq_reconnect(rmqs->sock) < 0) {
			LM_ERR("cannot reconnect socket\n");
			return rtrn;
		}
		/* all checks should be already done */
		ret = amqp_basic_publish(rmqp->conn,
				rmqp->channel,
				rmqp->flags&RMQ_PARAM_EKEY?
					amqp_cstring_bytes(rmqp->exchange.s) :
					AMQP_EMPTY_BYTES ,
				amqp_cstring_bytes(rmqp->routing_key.s),
				0,
				0,
				((rmqp->flags & RMQ_PARAM_PERS)?&props:0),
				amqp_cstring_bytes(rmqs->msg));
		rtrn = amqp_check_status(rmqp, ret, &re_publish);
	}

	return rtrn;
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
			if (rmqs->async_ctx.status_cb)
				rmq_dispatch_status_cb(&rmqs->async_ctx, EVI_STATUS_FAIL);
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
}
