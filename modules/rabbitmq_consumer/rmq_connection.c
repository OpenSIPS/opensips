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

#include <poll.h>

#include "../../ut.h"
#include "../../lib/csv.h"
#include "../../mem/shm_mem.h"

#include "rmq_connection.h"
#include "rmq_event.h"


int rmq_connect_timeout = RMQ_DEFAULT_CONNECT_TIMEOUT;
int rmq_retry_timeout = RMQ_DEFAULT_RETRY_TIMEOUT;

static OSIPS_LIST_HEAD(rmq_connections);

static struct pollfd pfds[RMQ_MAX_CONNS];
static int nfds = 0;

#define IS_WS(_c) ((_c) == ' ' || (_c) == '\t' || (_c) == '\r' || (_c) == '\n')

int rmq_conn_add(modparam_t mtype, void *val)
{
	str s;
	csv_record *p_list, *it;
	str params[NO_CONN_PARAMS];
	str p;
	enum rmq_conn_param {RMQP_URI, RMQP_QUEUE, RMQP_EV, RMQP_ACK, RMQP_EX,
		RMQP_HBEAT, RMQP_FRAME} param_type;
	char *uri_s;
	struct rmq_connection *rmq_conn;

	if (mtype != STR_PARAM) {
		LM_ERR("invalid parameter type %d\n", mtype);
		return -1;
	}
	s.s = (char *)val;
	s.len = strlen(s.s);

	p_list = __parse_csv_record(&s, 0, CONN_PARAMS_SEP);
	if (!p_list) {
		LM_ERR("Failed to parse connection parameters\n");
		return -1;
	}

	memset(params, 0, sizeof params);

	for (it = p_list; it; it = it->next) {
		p.s = it->s.s;
		p.len = 0;
		for (; it->s.len > 0 && !IS_WS(*it->s.s) && *it->s.s != '=';
			it->s.s++, it->s.len--)
			p.len++;
		if (p.len == 0) {
			if (it->next) {
				LM_ERR("Empty connection parameter\n");
				free_csv_record(p_list);
				return -1;
			} else {
				break;
			}
		}

		if (!strncasecmp(p.s, "uri", 3))
			param_type = RMQP_URI;
		else if (!strncasecmp(p.s, "queue", 5))
			param_type = RMQP_QUEUE;
		else if (!strncasecmp(p.s, "event", 5))
			param_type = RMQP_EV;
		else if (!strncasecmp(p.s, "ack", 3))
			param_type = RMQP_ACK;
		else if (!strncasecmp(p.s, "exclusive", 9))
			param_type = RMQP_EX;
		else if (!strncasecmp(p.s, "frame_max", 9))
			param_type = RMQP_FRAME;
		else if (!strncasecmp(p.s, "heartbeat", 9))
			param_type = RMQP_HBEAT;
		else {
			LM_ERR("Unknown connection parameter: %.*s\n", p.len, p.s);
			free_csv_record(p_list);
			return -1;
		}

		/* parameters without value */
		if (param_type == RMQP_ACK || param_type == RMQP_EX) {
			params[param_type] = p;
			continue;
		}

		for (; it->s.len > 0 && *it->s.s != '='; it->s.s++, it->s.len--) ;
		if (it->s.len == 0) {
			LM_ERR("cannot find '=' for connection parameter: %.*s\n", p.len, p.s);
			free_csv_record(p_list);
			return -1;
		}

		it->s.s++; it->s.len--;
		for (; it->s.len > 0 && IS_WS(*it->s.s); it->s.s++, it->s.len--) ;
		if (it->s.len == 0) {
			LM_ERR("Empty value for connection parameter: %.*s\n", p.len, p.s);
			free_csv_record(p_list);
			return -1;
		}
		params[param_type] = it->s;
	}

	free_csv_record(p_list);

	if (!params[RMQP_URI].s) {
		LM_ERR("Missing 'uri' connection parameter\n");
		return -1;
	}

	rmq_conn = shm_malloc(sizeof *rmq_conn + params[RMQP_URI].len + 1);
	if (!rmq_conn) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(rmq_conn, 0, sizeof *rmq_conn);

	uri_s = ((char *)rmq_conn) + sizeof *rmq_conn;
	memcpy(uri_s, params[RMQP_URI].s, params[RMQP_URI].len);
	uri_s[params[RMQP_URI].len] = 0;

	amqp_default_connection_info(&rmq_conn->uri);
	if (amqp_parse_url(uri_s, &rmq_conn->uri) != AMQP_STATUS_OK) {
		LM_ERR("Failed to parse amqp uri: %s\n", uri_s);
		goto err_free;
	}

	if (rmq_conn->uri.ssl) {
		LM_WARN("SSL connections are not currently supported!\n");
		goto err_free;
	}

	if (!params[RMQP_QUEUE].s) {
		LM_ERR("Missing 'queue' connection parameter\n");
		goto err_free;
	}

	rmq_conn->queue = amqp_bytes_malloc(params[RMQP_QUEUE].len);
	if (!rmq_conn->queue.bytes) {
		LM_ERR("Failed to allocate buffer\n");
		goto err_free;
	}
	memcpy(rmq_conn->queue.bytes, params[RMQP_QUEUE].s, params[RMQP_QUEUE].len);

	if (!params[RMQP_EV].s) {
		LM_ERR("Missing 'event' connection parameter\n");
		goto err_free;
	}

	if (shm_nt_str_dup(&rmq_conn->event_name, &params[RMQP_EV]) < 0) {
		LM_ERR("oom\n");
		goto err_free;
	}

	rmq_conn->heartbeat = RMQ_DEFAULT_HEARTBEAT;
	if (params[RMQP_HBEAT].s) {
		if (str2int(&params[RMQP_HBEAT],
			(unsigned int *)&rmq_conn->heartbeat) < 0) {
			LM_ERR("heartbeat must be the number of seconds, not %.*s\n",
				params[RMQP_HBEAT].len, params[RMQP_HBEAT].s);
			goto err_free;
		}
		if (rmq_conn->heartbeat < 0) {
			LM_WARN("invalid number of heartbeat seconds %d! Using default!\n",
				rmq_conn->heartbeat);
			rmq_conn->heartbeat = RMQ_DEFAULT_HEARTBEAT;
		} else {
			LM_DBG("setting heartbeat to %d\n", rmq_conn->heartbeat);
		}	
	}

	rmq_conn->frame_max = RMQ_DEFAULT_FRAME_MAX;
	if (params[RMQP_FRAME].s) {
		if (str2int(&params[RMQP_FRAME],
			(unsigned int *)&rmq_conn->frame_max) < 0) {
			LM_ERR("maximum frame must be a number, not %.*s\n",
				params[RMQP_FRAME].len, params[RMQP_FRAME].s);
			goto err_free;
		}
		if (rmq_conn->frame_max < RMQ_MIN_FRAME_MAX) {
			LM_WARN("maximum frame is %d - less than minimum supported %d! "
					"setting to minimum\n", rmq_conn->frame_max, RMQ_MIN_FRAME_MAX);
			rmq_conn->frame_max = RMQ_MIN_FRAME_MAX;
		} else {
			LM_DBG("setting maximum frame to %d\n", rmq_conn->frame_max);
		}
	}

	if (params[RMQP_ACK].s)
		rmq_conn->flags |= RMQ_FLAG_ACK;
	if (params[RMQP_EX].s)
		rmq_conn->flags |= RMQ_FLAG_EXCLUSIVE;

	rmq_conn->state = RMQ_CONN_NONE;

	rmq_conn->pfds_idx = nfds;
	pfds[nfds].events = POLLIN;
	pfds[nfds].fd = -1;
	nfds++;

	if (rmq_evi_init(rmq_conn) < 0) {
		LM_ERR("Failed to init script event\n");
		goto err_free;
	}

	list_add(&rmq_conn->list, &rmq_connections);
	LM_DBG("new RabbitMQ connection to %s:%u\n",
		rmq_conn->uri.host, rmq_conn->uri.port);

	return 0;

err_free:
	shm_free(rmq_conn);
	return -1;
}

static inline int rmq_rpc_error(struct rmq_connection *conn,
				char const *context, amqp_rpc_reply_t x)
{
	amqp_connection_close_t *mconn;
	amqp_channel_close_t *mchan;
	amqp_channel_close_ok_t mchan_close_ok;
	amqp_connection_close_ok_t mconn_close_ok;

	switch (x.reply_type) {
	case AMQP_RESPONSE_NORMAL:
		return 0;

	case AMQP_RESPONSE_NONE:
		LM_ERR("%s: missing RPC reply type!\n", context);
		break;

	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
		LM_ERR("%s: %s\n", context, amqp_error_string2(x.library_error));
		if (x.library_error == AMQP_STATUS_CONNECTION_CLOSED)
			return RMQ_ERR_CLOSE_CONN;
		break;

	case AMQP_RESPONSE_SERVER_EXCEPTION:
		switch (x.reply.id) {
		case AMQP_CONNECTION_CLOSE_METHOD:
			mconn = (amqp_connection_close_t *)x.reply.decoded;
			LM_ERR("%s: server connection error %d, message: %.*s\n",
					context, mconn->reply_code, (int)mconn->reply_text.len,
					(char *)mconn->reply_text.bytes);

			if (amqp_send_method(conn->amqp_conn, 1, AMQP_CONNECTION_CLOSE_OK_METHOD,
				&mconn_close_ok) != AMQP_STATUS_OK)
				LM_ERR("%s: Failed to send channel close ok reply\n", context);
			break;
		case AMQP_CHANNEL_CLOSE_METHOD:
				mchan = (amqp_channel_close_t *)x.reply.decoded;
			LM_ERR("%s: server channel error %d, message: %.*s\n",
					context, mchan->reply_code, (int)mchan->reply_text.len,
					(char *)mchan->reply_text.bytes);

			if (amqp_send_method(conn->amqp_conn, 1, AMQP_CHANNEL_CLOSE_OK_METHOD,
				&mchan_close_ok) != AMQP_STATUS_OK)
				LM_ERR("%s: Failed to send connection close ok reply\n", context);

			return RMQ_ERR_CLOSE_CHAN;
		default:
			LM_ERR("%s: unknown server error, method id 0x%08X\n",
					context, x.reply.id);
			break;
		}

		return RMQ_ERR_CLOSE_CONN;
	default:
		LM_ERR("%s: bad RPC reply type!\n", context);
	}

	return RMQ_ERR;
}

static void rmq_close_conn(struct rmq_connection *conn, int channel_only)
{
	switch (conn->state) {
	case RMQ_CONN_CHAN:
		if (channel_only && (rmq_rpc_error(conn, "closing channel",
			amqp_channel_close(conn->amqp_conn, 1, AMQP_REPLY_SUCCESS)) == 0)) {
			conn->state = RMQ_CONN_LOGIN;
			return;
		}
	case RMQ_CONN_LOGIN:
	case RMQ_CONN_SOCK:
		/* coverity[check_return: FALSE] */
		rmq_rpc_error(conn, "closing connection",
			amqp_connection_close(conn->amqp_conn, AMQP_REPLY_SUCCESS));
		if (amqp_destroy_connection(conn->amqp_conn) < 0)
			LM_ERR("cannot destroy connection\n");
	case RMQ_CONN_NONE:
		break;
	default:
		LM_WARN("Bad connection state %d\n", conn->state);
	}

	gettimeofday(&conn->timeout_start, NULL);
	pfds[conn->pfds_idx].fd = -1;

	conn->state = RMQ_CONN_NONE;
}

static int rmq_connect(struct rmq_connection *conn)
{
	amqp_socket_t *amqp_sock;
	struct timeval timeout = {rmq_connect_timeout/1000,
							 (rmq_connect_timeout%1000)*1000};

	switch (conn->state) {
	case RMQ_CONN_NONE:
		conn->amqp_conn = amqp_new_connection();
		if (!conn->amqp_conn) {
			LM_ERR("cannot create amqp connection!\n");
			gettimeofday(&conn->timeout_start, NULL);
			return -1;
		}

		amqp_sock = amqp_tcp_socket_new(conn->amqp_conn);
		if (!amqp_sock) {
			LM_ERR("cannot create AMQP socket\n");
			goto err_clean_amqp_conn;
		}
		if (amqp_socket_open_noblock(amqp_sock,
			conn->uri.host, conn->uri.port, &timeout) != AMQP_STATUS_OK) {
			LM_ERR("cannot open AMQP socket\n");
			goto err_clean_amqp_conn;
		}

		pfds[conn->pfds_idx].fd = amqp_get_sockfd(conn->amqp_conn);
		if (pfds[conn->pfds_idx].fd < 0) {
			LM_ERR("cannot fetch amqp socket descriptor\n");
			goto err_clean_amqp_conn;
		}

		conn->state = RMQ_CONN_SOCK;
		/* fall through */
	case RMQ_CONN_SOCK:
		if (rmq_rpc_error(conn, "Logging in", amqp_login(
			conn->amqp_conn,
			(conn->uri.vhost ? conn->uri.vhost: "/"),
			0,
			conn->frame_max,
			conn->heartbeat,
			AMQP_SASL_METHOD_PLAIN,
			conn->uri.user,
			conn->uri.password)))
			goto err_close_rmq_conn;

		conn->state = RMQ_CONN_LOGIN;
		/* fall through */
	case RMQ_CONN_LOGIN:
		/* use only 1 channel */
		amqp_channel_open(conn->amqp_conn, 1);
		if (rmq_rpc_error(conn, "Opening channel",
				amqp_get_rpc_reply(conn->amqp_conn)))
			goto err_close_rmq_conn;

		LM_DBG("successfully connected to: %s:%u\n", conn->uri.host, conn->uri.port);
		conn->state = RMQ_CONN_CHAN;
		/* fall through */
	case RMQ_CONN_CHAN:
		return 0;
	default:
		LM_WARN("Bad connection state\n");
		return -1;
}

err_close_rmq_conn:
	rmq_close_conn(conn, 0);
	return -1;
err_clean_amqp_conn:
	gettimeofday(&conn->timeout_start, NULL);
	if (amqp_destroy_connection(conn->amqp_conn) != AMQP_STATUS_OK)
		LM_ERR("cannot destroy connection\n");
	return -1;
}

static inline int rmq_register_consumer(struct rmq_connection *conn) {
	if (!amqp_basic_consume(conn->amqp_conn, 1, conn->queue,
		amqp_empty_bytes, 0, !(conn->flags&RMQ_FLAG_ACK),
		conn->flags&RMQ_FLAG_EXCLUSIVE, amqp_empty_table))
		return -1;

	return 0;
}

static inline int rmq_close_chan_retry(struct rmq_connection *conn)
{
	rmq_close_conn(conn, 1);

	if (conn->state == RMQ_CONN_NONE)
		/* failed to only close the channel, whole connection was closed */
		return -1;

	if (rmq_connect(conn) < 0) {
		LM_ERR("Failed to re-open channel to server: %s:%u\n",
			conn->uri.host, conn->uri.port);
		return -1;
	}

	if (rmq_register_consumer(conn) < 0) {
		LM_ERR("Failed to re-register consumer to server: %s:%u\n",
			conn->uri.host, conn->uri.port);
		rmq_close_conn(conn, 0);
		return -1;
	}

	return 0;
}

static inline int rmq_rpc_err_close(struct rmq_connection *conn,
				char const *context, amqp_rpc_reply_t x, int close_any_error)
{
	int rc;

	rc = rmq_rpc_error(conn, context, x);
	if (rc == RMQ_ERR_CLOSE_CHAN) {
		/* close the channel and try to open it again and
		 * re-register the consumer */
		rmq_close_chan_retry(conn);

		/* even if channel reopened, the RPC was still erroneous */
		return -1;
	} else if (rc == RMQ_ERR_CLOSE_CONN) {
		rmq_close_conn(conn, 0);
		return -1;
	} else if (rc == RMQ_ERR && close_any_error) {
		rmq_close_conn(conn, 0);
		return -1;
	}

	return rc; /* 0 or -1 */
}

static void rmq_initial_connect_all(void)
{
	struct list_head *it;
	struct rmq_connection *conn;

	list_for_each(it, &rmq_connections) {
		conn = container_of(it, struct rmq_connection, list);
		if (rmq_connect(conn) < 0)
			LM_ERR("cannot connect to RabbitMQ server: %s:%u\n",
					conn->uri.host, conn->uri.port);
	}
}

static int rmq_consume(struct rmq_connection *conn)
{
	static struct timeval zero_tv = {0, 0};
	amqp_envelope_t envelope;
	amqp_rpc_reply_t rpl;
	amqp_frame_t frame;
	str msg_body;
	int rc;

	amqp_maybe_release_buffers(conn->amqp_conn);

	rpl = amqp_consume_message(conn->amqp_conn, &envelope, &zero_tv, 0);
	if (rpl.reply_type != AMQP_RESPONSE_NORMAL) {
		if (rpl.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
			rpl.library_error == AMQP_STATUS_TIMEOUT) {
			/* frame not ready yet */
			return 0;
		} else if (rpl.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
			rpl.library_error == AMQP_STATUS_UNEXPECTED_STATE) {
			if (amqp_simple_wait_frame(conn->amqp_conn, &frame) != AMQP_STATUS_OK) {
				LM_ERR("Failed to get the unexpected received method\n");
				return -1;
			}

			if (frame.frame_type != AMQP_FRAME_METHOD) {
				LM_ERR("Expected a method frame\n");
				return -1;
			}
			if (frame.payload.method.id == AMQP_CHANNEL_CLOSE_METHOD) {
				LM_ERR("Received a channel.close method, closing channel\n");
				rmq_close_chan_retry(conn);
			} else if (frame.payload.method.id == AMQP_CONNECTION_CLOSE_METHOD) {
				LM_ERR("Received a connection.close method, closing connection\n");
				rmq_close_conn(conn, 0);
			} else
				LM_ERR("Received an unexpected method\n");

			return -1;
		} else
			rmq_rpc_err_close(conn, "Consuming message", rpl, 0);

		return -1;
	} else {
		msg_body.s = envelope.message.body.bytes;
		msg_body.len = envelope.message.body.len;

		if ((rc = rmq_ipc_dispatch_event(conn, &msg_body)) < 0) {
			LM_ERR("Failed to dispatch event\n");
			goto out_free;
		}

		if ((conn->flags&RMQ_FLAG_ACK) && amqp_basic_ack(conn->amqp_conn,
			1, envelope.delivery_tag, 0) > 0)
			LM_ERR("Failed to acknowledge consumed message\n");

out_free:
		amqp_destroy_envelope(&envelope);
		return rc;
	}
}

void rmq_cons_process(int proc_no)
{
	struct list_head *it;
	struct rmq_connection *conn;
	int r;
	struct timeval now;

	/* connect to brokers */
	rmq_initial_connect_all();

	/* register consumers */
	list_for_each(it, &rmq_connections) {
		conn = container_of(it, struct rmq_connection, list);
		if (conn->state != RMQ_CONN_CHAN)
			continue;

		if (rmq_register_consumer(conn) &&
			rmq_rpc_err_close(conn, "Registering consumer",
			amqp_get_rpc_reply(conn->amqp_conn), 1))
			LM_ERR("Failed to register consumer to server: %s:%u\n",
					conn->uri.host, conn->uri.port);
	}

	while (1) {
		r = poll(pfds, nfds, RMQ_POLL_TIMEOUT);
		if (r < 0) {
			if (errno != EINTR)
				LM_ERR("poll failed: %s [%d]\n", strerror(errno), errno);
			continue;
		}

		list_for_each(it, &rmq_connections) {
			conn = container_of(it, struct rmq_connection, list);
			if (conn->state != RMQ_CONN_CHAN) {
				/* reconnect if timeout passed */
				gettimeofday(&now, NULL);
				if ((now.tv_sec - conn->timeout_start.tv_sec)*1000 +
					(now.tv_usec - conn->timeout_start.tv_usec)/1000 >
					rmq_retry_timeout) {
					if (rmq_connect(conn) < 0) {
						LM_ERR("cannot connect to RabbitMQ server: %s:%u\n",
							conn->uri.host, conn->uri.port);
						continue;
					}

					if (rmq_register_consumer(conn) &&
						rmq_rpc_err_close(conn, "Registering consumer",
						amqp_get_rpc_reply(conn->amqp_conn), 1))
						LM_ERR("Failed to register consumer to server: %s:%u\n",
								conn->uri.host, conn->uri.port);
				}
				continue;
			}

			if (pfds[conn->pfds_idx].revents & POLLIN) {
				if (rmq_consume(conn) < 0) {
					LM_ERR("Failed to consume message\n");
				}
			} else if (pfds[conn->pfds_idx].revents & POLLHUP) {
				LM_INFO("Server: %s:%u closed the TCP connection\n",
					conn->uri.host, conn->uri.port);
				rmq_close_conn(conn, 0);
			} else if (pfds[conn->pfds_idx].revents & POLLERR) {
				LM_ERR("connection error with server: %s:%u - %s:%d\n",
					conn->uri.host , conn->uri.port, strerror(errno), errno);
				rmq_close_conn(conn, 0);
			} else if (pfds[conn->pfds_idx].revents != 0)
				LM_WARN("Unexpected poll event: %d\n",
					pfds[conn->pfds_idx].revents);
		}
	}
}
