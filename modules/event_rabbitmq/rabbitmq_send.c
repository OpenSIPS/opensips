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

void rmq_destroy_connection(rmq_connection_t *conn, int temporarely)
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
	case RMQS_PREINIT:
		break;
	default:
		LM_WARN("Unknown rmq server state %d\n", conn->state);
	}

	if (temporarely)
		conn->state = RMQS_PREINIT;
	else
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
		rmq_destroy_connection(&rmqp->conn, 0);
	}
	shm_free(sock);
}

static int rmq_reconnect(evi_reply_sock *sock)
{
	rmq_params_t * rmqp = (rmq_params_t *)sock->params;
	rmq_connection_t *conn;
#if defined AMQP_VERSION_v04
	amqp_socket_t *amqp_sock;
#endif
	int socket;

	if (!rmqp) {
		LM_ERR("not enough socket info\n");
		return -1;
	}

	conn = &rmqp->conn;

	switch (conn->state) {
	case RMQS_OFF:
	case RMQS_PREINIT:
		if (!(conn->conn = amqp_new_connection())) {
			LM_ERR("cannot create amqp connection!\n");
			return -1;
		}
#if defined AMQP_VERSION_v04
		if (use_tls && (conn->uri.ssl || (conn->flags&RMQ_PARAM_TLS))) {
			if (!conn->tls_dom) {
				conn->tls_dom = tls_api.find_client_domain_name(&conn->tls_dom_name);
				if (!conn->tls_dom) {
					LM_ERR("TLS domain: %.*s not found\n",
						conn->tls_dom_name.len, conn->tls_dom_name.s);
					return -1;
				}
			}

			amqp_sock = amqp_ssl_socket_new(conn->conn);
			if (!amqp_sock) {
				LM_ERR("cannot create AMQP TLS socket\n");
				return -1;
			}

			#if AMQP_VERSION < AMQP_VERSION_CODE(0, 10, 0, 0)
			/* if amqp_ssl_socket_get_context() is not available, serialize the CA,
			 * cert and key loading in order to prevent openssl multiprocess issues */
			lock_get(ssl_lock);
			if (amqp_ssl_socket_set_cacert(amqp_sock, conn->tls_dom->ca.s) !=
				AMQP_STATUS_OK) {
				LM_ERR("Failed to set CA certificate\n");
				lock_release(ssl_lock);
				return -1;
			}

			if (amqp_ssl_socket_set_key(amqp_sock, conn->tls_dom->cert.s,
				conn->tls_dom->pkey.s) != AMQP_STATUS_OK) {
				LM_ERR("Failed to set certificate and private key\n");
				lock_release(ssl_lock);
				return -1;
			}
			lock_release(ssl_lock);
			#else
			/* point the CA, cert and key from librabbitmq's SSL_CTX to
			 * the info loaded through the tls_mgm's SSL_CTX, in order to
			 * prevent openssl multiprocess issues */
			void *ssl_ctx;
			ssl_ctx = amqp_ssl_socket_get_context(amqp_sock);

			/* set CA in AMQP's SSL_CTX  */
			openssl_api.ctx_set_cert_store(ssl_ctx,
				((void**)conn->tls_dom->ctx)[process_no]);

			/* set certificate in AMQP's SSL_CTX */
			if (openssl_api.ctx_set_cert_chain(ssl_ctx,
				((void**)conn->tls_dom->ctx)[process_no]) < 0) {
				LM_ERR("Failed to set certificate\n");
				return -1;
			}

			/* set private key in AMQP's SSL_CTX */
			if (openssl_api.ctx_set_pkey_file(ssl_ctx, conn->tls_dom->pkey.s) < 0) {
				LM_ERR("Failed to set private key\n");
				return -1;
			}
			#endif

			#if AMQP_VERSION >= AMQP_VERSION_CODE(0, 8, 0, 0)
			amqp_ssl_socket_set_verify_peer(amqp_sock, conn->tls_dom->verify_cert);
			amqp_ssl_socket_set_verify_hostname(amqp_sock, 0);
			#else
			amqp_ssl_socket_set_verify(amqp_sock, conn->tls_dom->verify_cert);
			#endif

			#if AMQP_VERSION >= AMQP_VERSION_CODE(0, 8, 0, 0)
			amqp_tls_version_t method_min, method_max;

			if (conn->tls_dom->method != TLS_METHOD_UNSPEC) {
				switch (conn->tls_dom->method) {
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
				LM_INFO("Minimum TLS method unspecified, using TLSv1\n");
				method_min = AMQP_TLSv1;
			}

			if (conn->tls_dom->method_max != TLS_METHOD_UNSPEC) {
				switch (conn->tls_dom->method_max) {
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
				LM_INFO("Maximum TLS method unspecified, using latest supported by"
					" librabbitmq\n");
			}

			if (amqp_ssl_socket_set_ssl_versions(amqp_sock, method_min, method_max) !=
				AMQP_STATUS_OK) {
				LM_ERR("Failed to set TLS method range\n");
				return -1;
			}
			#endif
		} else {
			amqp_sock = amqp_tcp_socket_new(conn->conn);
			if (!amqp_sock) {
				LM_ERR("cannot create AMQP socket\n");
				return -1;
			}
		}

		socket = amqp_socket_open_noblock(amqp_sock, sock->address.s,
			sock->port, &conn_timeout_tv);
		if (socket < 0) {
			amqp_connection_close(conn->conn, AMQP_REPLY_SUCCESS);
			LM_ERR("cannot open AMQP socket\n");
			return -1;
		}
#if defined AMQP_VERSION && AMQP_VERSION >= 0x00090000
		if (rpc_timeout_tv.tv_sec > 0 &&
				amqp_set_rpc_timeout(conn->conn, &rpc_timeout_tv) < 0)
			LM_ERR("setting RPC timeout - going blocking\n");
#endif

#else
		socket = amqp_open_socket_noblock(sock->address.s, sock->port,
				&conn_timeout_tv);
		if (socket < 0) {
			LM_ERR("cannot open AMQP socket\n");
			return -1;
		}
		amqp_set_sockfd(conn->conn, socket);
#endif
		conn->state = RMQS_INIT;
		/* fall through */
	case RMQS_INIT:
		if (rmq_error("Logging in", amqp_login(
				conn->conn,
				RMQ_DEFAULT_VHOST,
				0,
				RMQ_DEFAULT_FRAMES,
				conn->heartbeat,
				AMQP_SASL_METHOD_PLAIN,
				conn->uri.user ? conn->uri.user : RMQ_DEFAULT_UP,
				conn->uri.password ? conn->uri.password : RMQ_DEFAULT_UP)))
			return -2;
		/* all good - return success */
		conn->state = RMQS_CONN;
		/* fall through */
	case RMQS_CONN:
		/* don't use more than 1 channel */
		amqp_channel_open(conn->conn, RMQ_DEFAULT_CHANNEL);
		if (rmq_error("Opening channel", amqp_get_rpc_reply(conn->conn)))
			return -2;
		LM_INFO("[] successfully connected!\n");
		conn->state = RMQS_ON;
		/* fall through */
	case RMQS_ON:
		return 0;
	default:
		LM_WARN("Unknown rmq server state %d\n", conn->state);
		return -1;
	}

}

static int rmq_basic_publish(rmq_connection_t *conn, int max_frames,
						str *cid, amqp_bytes_t akey, amqp_bytes_t abody,
						amqp_basic_properties_t *props, int retries, rmq_send_t *rmqs)
{
	int ret;
	evi_reply_sock *sock;

	if (conn->flags & RMQF_NOPER) {
		props->delivery_mode = 2;
		props->_flags |= AMQP_BASIC_DELIVERY_MODE_FLAG;
	}

	do {
		sock = rmqs->sock;
		LM_INFO("rmq_reconnect()\n");
		ret = rmq_reconnect(sock);

		if (ret == -1) {
			if (amqp_destroy_connection(conn->conn) < 0)
				LM_ERR("cannot destroy connection\n");
			if (conn->tls_dom) {
				tls_api.release_domain(conn->tls_dom);
				conn->tls_dom = NULL;
			}
			LM_ERR("cannot connect to RabbitMQ server %s:%u\n",
				conn->uri.host, conn->uri.port);
			return ret;
		}
		if (ret == -2) {
			rmq_destroy_connection(conn, 1);
			LM_ERR("cannot connect to RabbitMQ server %s:%u\n",
				conn->uri.host, conn->uri.port);
				return ret;
		}

		ret = amqp_basic_publish(conn->conn, RMQ_DEFAULT_CHANNEL, conn->exchange, akey, \
				(conn->flags & RMQF_MAND), (conn->flags & RMQF_IMM),
				props, abody);
		ret = amqp_check_status(conn, ret, &retries, *cid);
	} while (ret > 0);

	return ret;
}

/* sends the buffer */
static int rmq_sendmsg(rmq_send_t *rmqs)
{
	rmq_params_t * rmqp = (rmq_params_t *)rmqs->sock->params;
	int ret;
	int re_publish = 2;
	amqp_basic_properties_t props;

	if (!rmqp || !(rmqp->conn.flags & RMQF_MAND)) {
		LM_ERR("not enough socket info\n");
		return -1;;
	}

	/* FIXME:
	 * We need a new state for un-initialised connections
	 * Unlike server connections, this ones are not initialised at startup
	 */
	if (rmqp->conn.state == RMQS_OFF) {
		LM_INFO("server disconnected\n");
		return 0;
	}

	rmqp->conn.uri.host = rmqs->sock->address.s;

	rmqp->conn.uri.port = rmqs->sock->port;

	ret = rmq_basic_publish(&rmqp->conn,
			RMQ_DEFAULT_FRAMES,
			&rmqs->sock->address,
			amqp_cstring_bytes(rmqp->routing_key.s),
			amqp_cstring_bytes(rmqs->msg),
			((rmqp->conn.flags & RMQF_NOPER)?&props:0),
			re_publish,
			rmqs);

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
