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

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../db/db_id.h"
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../dprint.h"
#include "../../ut.h"

#include "rmq_servers.h"

#if defined AMQP_VERSION && AMQP_VERSION >= 0x00040000
  #define AMQP_VERSION_v04
#include <amqp_tcp_socket.h>
#endif

static LIST_HEAD(rmq_servers);

enum rmq_func_param_type { RMQT_SERVER, RMQT_PVAR };
struct rmq_func_param {
	enum rmq_func_param_type type;
	void *value;
};

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

/* function used to get a rmq_server based on a cid */
struct rmq_server *rmq_get_server(str *cid)
{
	struct list_head *it;
	struct rmq_server *srv;

	list_for_each(it, &rmq_servers) {
		srv = container_of(it, struct rmq_server, list);
		if (srv->cid.len == cid->len && memcmp(srv->cid.s, cid->s, cid->len) == 0)
			return srv;
	}
	return NULL;
}

struct rmq_server *rmq_resolve_server(struct sip_msg *msg, char *param)
{
	struct rmq_func_param *p = (struct rmq_func_param *)param;
	str cid;

	if (p->type == RMQT_SERVER)
		return p->value;

	if (fixup_get_svalue(msg, (gparam_p)param, &cid) < 0) {
		LM_ERR("cannot get the connection id!\n");
		return NULL;
	}
	return rmq_get_server(&cid);
}

static void rmq_clean_server(struct rmq_server *srv)
{
	switch (srv->state) {
	case RMQS_CONN:
	case RMQS_INIT:
		rmq_error("closing connection",
				amqp_connection_close(srv->conn, AMQP_REPLY_SUCCESS));
		if (amqp_destroy_connection(srv->conn) < 0)
			LM_ERR("cannot destroy connection\n");
	case RMQS_NONE:
		break;
	default:
		LM_WARN("Unknown rmq server state %d\n", srv->state);
	}
}

#if 0
static void rmq_destroy_server(struct rmq_server *srv)
{
	rmq_clean_server(srv);
	pkg_free(srv);
}
#endif

/*
 * function used to reconnect a RabbitMQ server
 */
int rmq_reconnect(struct rmq_server *srv)
{
#if defined AMQP_VERSION_v04
	amqp_socket_t *amqp_sock;
#endif
	int socket;

	switch (srv->state) {
	case RMQS_NONE:
		srv->conn = amqp_new_connection();
		if (!srv) {
			LM_ERR("cannot create amqp connection!\n");
			return -1;
		}
#if defined AMQP_VERSION_v04
		amqp_sock = amqp_tcp_socket_new(srv->conn);
		if (!amqp_sock) {
			LM_ERR("cannot create AMQP socket\n");
			goto clean_rmq_conn;
		}
		socket = amqp_socket_open(amqp_sock, srv->uri.host, srv->uri.port);
		if (socket < 0) {
			LM_ERR("cannot open AMQP socket\n");
			goto clean_rmq_conn;
		}
#else
		socket = amqp_open_socket(srv->uri.host, srv->uri.port);
		if (socket < 0) {
			LM_ERR("cannot open AMQP socket\n");
			goto clean_rmq_conn;
		}
		amqp_set_sockfd(srv->conn, socket);
#endif
		srv->state = RMQS_INIT;
	case RMQS_INIT:
		if (rmq_error("Logging in", amqp_login(
				srv->conn,
				srv->uri.vhost,
				srv->max_channels,
				srv->max_frames,
				srv->heartbeat,
				AMQP_SASL_METHOD_PLAIN,
				srv->uri.user,
				srv->uri.password)))
			goto clean_rmq_server;
		/* all good - return success */
		srv->state = RMQS_CONN;
	case RMQS_CONN:
		amqp_channel_open(srv->conn, 1);
		if (rmq_error("Opening channel", amqp_get_rpc_reply(srv->conn)))
			goto clean_rmq_server;
		return 0;
	default:
		LM_WARN("Unknown rmq server state %d\n", srv->state);
		return -1;
	}
clean_rmq_server:
	rmq_clean_server(srv);
	return -2;
clean_rmq_conn:
	if (amqp_destroy_connection(srv->conn) < 0)
		LM_ERR("cannot destroy connection\n");
	return -1;
}

#define IS_WS(_c) ((_c) == ' ' || (_c) == '\t' || (_c) == '\r' || (_c) == '\n')

/*
 * function used to add a RabbitMQ server
 */
int rmq_server_add(modparam_t type, void * val)
{
	struct rmq_server *srv;
	str s;
	str cid;
	str suri = {0, 0};
	char uri_pending = 0;
	char *uri;
	int max_channels = RMQ_DEFAULT_MAX_CHANNELS;
	int max_frames = RMQ_DEFAULT_MAX_FRAMES;
	int heartbeat = RMQ_DEFAULT_HEARTBEAT;

	if (type != STR_PARAM) {
		LM_ERR("invalid parameter type %d\n", type);
		return -1;
	}
	s.s = (char *)val;
	s.len = strlen(s.s);

	for (; s.len > 0; s.s++, s.len--)
		if (!IS_WS(*s.s))
			break;
	if (s.len <= 0 || *s.s != '[') {
		LM_ERR("cannot find connection id start: %.*s\n", s.len, s.s);
		return -1;
	}
	cid.s = s.s + 1;
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--)
		if (*s.s == ']')
			break;
	if (s.len <= 0 || *s.s != ']') {
		LM_ERR("cannot find connection id end: %.*s\n", s.len, s.s);
		return -1;
	}
	cid.len = s.s - cid.s;

	/* check if the server was already defined */
	if (rmq_get_server(&cid)) {
		LM_ERR("Connection ID %.*s already defined! Please use different "
				"names for different connections!\n", cid.len, cid.s);
		return -1;
	}

	/* server not found - parse this one */
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--) {
		if (IS_WS(*s.s))
			continue;
		if (s.len > 4 && strncasecmp(s.s, "uri", 3) == 0) {
			/* skip spaces before = */
			for (s.len -= 3, s.s += 3; s.len > 0; s.s++, s.len--)
				if (!IS_WS(*s.s))
					break;
			if (s.len <= 0 || *s.s != '=') {
				LM_ERR("cannot find uri equal: %.*s\n", s.len, s.s);
				return -1;
			}
			s.s++;
			s.len--;

			/* remember where the uri starts */
			suri = s;
			uri_pending = 1;
		} else {
			/* we eneded up in a place that has ';' - if we haven't found
			 * the end of the uri, this is also part of the uri. otherwise it
			 * is an error and we shall report it */
			if (!uri_pending) {
				LM_ERR("Unknown parameter: %.*s\n", s.len, s.s);
				return -1;
			}
		}
		/* search for the next ';' */
		for (; s.len > 0; s.s++, s.len--)
			if (*s.s == ';')
				break;
	}
	/* if we don't have an uri, we forfeit */
	if (!suri.s) {
		LM_ERR("cannot find an uri!");
		return -1;
	}
	/* if still pending, remove the last ';' */
	trim_spaces_lr(suri);
	if (uri_pending && suri.s[suri.len - 1] == ';')
		suri.len--;
	trim_spaces_lr(suri);

	if ((srv = pkg_malloc(sizeof *srv + suri.len + 1)) == NULL) {
		LM_ERR("cannot alloc memory for rabbitmq server\n");
		return -1;
	}
	uri = ((char *)srv) + sizeof *srv;
	memcpy(uri, suri.s, suri.len);
	uri[suri.len] = 0;

	if (amqp_parse_url(uri, &srv->uri) != 0) {
		LM_ERR("cannot parse rabbitmq uri: %s\n", uri);
		goto free;
	}

	if (srv->uri.ssl) {
		LM_WARN("we currently do not support ssl connections!\n");
		goto free;
	}

	srv->state = RMQS_NONE;
	srv->cid = cid;

	srv->max_frames = max_frames;
	srv->max_channels = max_channels;
	srv->heartbeat = heartbeat;

	list_add(&srv->list, &rmq_servers);
	LM_DBG("new AMQP host=%s:%u with cid=%.*s\n",
			srv->uri.host, srv->uri.port, srv->cid.len, srv->cid.s);

	/* parse the url */
	return 0;
free:
	pkg_free(srv);
	return -1;
}
#undef IS_WS

/*
 * fixup function for rmq_server
 */
int fixup_rmq_server(void **param)
{
	str tmp;
	struct rmq_func_param *p;
	tmp.s = (char *)*param;
	tmp.len = strlen(tmp.s);
	trim_spaces_lr(tmp);
	if (tmp.len <= 0) {
		LM_ERR("invalid connection id!\n");
		return E_CFG;
	}
	p = pkg_malloc(sizeof(*p));
	if (!p) {
		LM_ERR("out of pkg memory!\n");
		return E_OUT_OF_MEM;
	}

	if (tmp.s[0] == PV_MARKER) {
		if (fixup_pvar(param) < 0) {
			LM_ERR("cannot parse cid\n");
			return E_UNSPEC;
		}
		p->value = *param;
		p->type = RMQT_PVAR;
	} else {
		p->value = rmq_get_server(&tmp);
		if (!p->value) {
			LM_ERR("unknown connection id=%.*s\n",
					tmp.len, tmp.s);
			return E_CFG;
		}
		p->type = RMQT_SERVER;
	}
	*param = p;
	return 0;
}

/*
 * function to connect all rmq servers
 */
void rmq_connect_servers(void)
{
	struct list_head *it;
	struct rmq_server *srv;

	list_for_each(it, &rmq_servers) {
		srv = container_of(it, struct rmq_server, list);
		if (rmq_reconnect(srv) < 0)
			LM_ERR("cannot connect to RabbitMQ server %s:%u\n",
					srv->uri.host, srv->uri.port);
	}
	
}
