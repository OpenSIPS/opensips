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
#include "../../lib/list.h"
#include "../../mod_fix.h"
#include "../../dprint.h"
#include "../../ut.h"

#include "rmq_servers.h"
#include <amqp_framing.h>

#if defined AMQP_VERSION && AMQP_VERSION >= 0x00040000
#define rmq_parse amqp_parse_url
#else
#include "../../db/db_id.h"
#warning "You are using an old, unsupported RabbitMQ library version - compile on your own risk!"
/* ugly hack to move ptr from id to rmq_uri */
#define PTR_MOVE(_from, _to) \
	do { \
		(_to) = (_from); \
		(_from) = NULL; \
	} while(0)
static inline int rmq_parse(char *url, rmq_uri *uri)
{
	str surl;
	struct db_id *id;

	surl.s = url;
	surl.len = strlen(url);

	if ((id = new_db_id(&surl)) == NULL)
		return -1;

	if (strcmp(id->scheme, "amqps") == 0)
		uri->ssl = 1;

	/* there might me a pkg leak compared to the newer version, but parsing
	 * only happends at startup, so we should not worry about this now */
	if (id->username)
		PTR_MOVE(id->username, uri->user);
	else
		uri->user = "guest";
	if (id->password)
		PTR_MOVE(id->password, uri->password);
	else
		uri->password = "guest";
	if (id->host)
		PTR_MOVE(id->host, uri->host);
	else
		uri->host = "localhost";
	if (id->database)
		PTR_MOVE(id->database, uri->vhost);
	else
		uri->vhost = "/";
	if (id->port)
		uri->port = id->port;
	else if (uri->ssl)
		uri->port = 5671;
	else
		uri->port = 5672;
	free_db_id(id);
	return 0;
}
#endif

static OSIPS_LIST_HEAD(rmq_servers);

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
#ifndef AMQP_VERSION_v04
	char *errorstr;
#endif

	switch (x.reply_type) {
		case AMQP_RESPONSE_NORMAL:
			return 0;

		case AMQP_RESPONSE_NONE:
			LM_ERR("%s: missing RPC reply type!\n", context);
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
					LM_ERR("%s: server connection error %d, message: %.*s\n",
							context, mconn->reply_code,
							(int)mconn->reply_text.len,
							(char *)mconn->reply_text.bytes);
					break;
				case AMQP_CHANNEL_CLOSE_METHOD:
						mchan = (amqp_channel_close_t *)x.reply.decoded;
					LM_ERR("%s: server channel error %d, message: %.*s\n",
							context, mchan->reply_code,
							(int)mchan->reply_text.len,
							(char *)mchan->reply_text.bytes);
					break;
				default:
					LM_ERR("%s: unknown server error, method id 0x%08X\n",
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

static void rmq_close_server(struct rmq_server *srv)
{
	switch (srv->state) {
	case RMQS_ON:
	case RMQS_CONN:
		rmq_error("closing channel",
				amqp_channel_close(srv->conn, 1, AMQP_REPLY_SUCCESS));
	case RMQS_INIT:
		rmq_error("closing connection",
				amqp_connection_close(srv->conn, AMQP_REPLY_SUCCESS));
		if (amqp_destroy_connection(srv->conn) < 0)
			LM_ERR("cannot destroy connection\n");
	case RMQS_OFF:
		break;
	default:
		LM_WARN("Unknown rmq server state %d\n", srv->state);
	}
	srv->state = RMQS_OFF;
}

#if 0
static void rmq_destroy_server(struct rmq_server *srv)
{
	rmq_close_server(srv);
	if (srv->exchange.bytes)
		amqp_bytes_free(srv->exchange);
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
	case RMQS_OFF:
		srv->conn = amqp_new_connection();
		if (!srv->conn) {
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
		/* fall through */
	case RMQS_INIT:
		if (rmq_error("Logging in", amqp_login(
				srv->conn,
				(srv->uri.vhost ? srv->uri.vhost: "/"),
				0,
				srv->max_frames,
				srv->heartbeat,
				AMQP_SASL_METHOD_PLAIN,
				srv->uri.user,
				srv->uri.password)))
			goto clean_rmq_server;
		/* all good - return success */
		srv->state = RMQS_CONN;
		/* fall through */
	case RMQS_CONN:
		/* don't use more than 1 channel */
		amqp_channel_open(srv->conn, 1);
		if (rmq_error("Opening channel", amqp_get_rpc_reply(srv->conn)))
			goto clean_rmq_server;
		LM_DBG("[%.*s] successfully connected!\n", srv->cid.len, srv->cid.s);
		srv->state = RMQS_ON;
		/* fall through */
	case RMQS_ON:
		return 0;
	default:
		LM_WARN("Unknown rmq server state %d\n", srv->state);
		return -1;
	}
clean_rmq_server:
	rmq_close_server(srv);
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
	str param, s, cid;
	str suri = {0, 0};
	char uri_pending = 0;
	unsigned flags = 0;
	char *uri;
	int retries = 0;
	int max_frames = RMQ_DEFAULT_FRAMES;
	int heartbeat = RMQ_DEFAULT_HEARTBEAT;
	str exchange = {0, 0};
	enum rmq_parse_param { RMQP_NONE, RMQP_URI, RMQP_FRAME, RMQP_HBEAT, RMQP_IMM,
		RMQP_MAND, RMQP_EXCH, RMQP_RETRY, RMQP_NOPER } state;

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
#define IF_IS_PARAM(_p, _s, _l) \
	do { \
		if (s.len >= (sizeof(_p) - 1) && strncasecmp(s.s, (_p), sizeof(_p) - 1) == 0) { \
			LM_DBG("[%.*s] found parameter %s\n", cid.len, cid.s, (_p)); \
			s.s += (sizeof(_p) - 1); \
			s.len -= (sizeof(_p) - 1); \
			state = _s; \
			goto _l; \
		} \
	} while (0)

	/* server not found - parse this one */
	for (s.s++, s.len--; s.len > 0; s.s++, s.len--) {
		if (IS_WS(*s.s))
			continue;
		param = s;
		state = RMQP_NONE;
		IF_IS_PARAM("uri", RMQP_URI, value);
		IF_IS_PARAM("frames", RMQP_FRAME, value);
		IF_IS_PARAM("retries", RMQP_RETRY, value);
		IF_IS_PARAM("exchange", RMQP_EXCH, value);
		IF_IS_PARAM("heartbeat", RMQP_HBEAT, value);
		IF_IS_PARAM("immediate", RMQP_IMM, no_value);
		IF_IS_PARAM("mandatory", RMQP_MAND, no_value);
		IF_IS_PARAM("non-persistent", RMQP_NOPER, no_value);

		/* there is no known parameter here */
		goto no_value;

#undef IF_IS_PARAM

value:
		/* found a valid parameter - if uri has started, it should be ended */
		if (uri_pending) {
			suri.len -= param.len;
			uri_pending = 0;
		}
		/* skip spaces before = */
		for (; s.len > 0; s.s++, s.len--)
			if (!IS_WS(*s.s))
				break;
		if (s.len <= 0 || *s.s != '=') {
			LM_ERR("[%.*s] cannot find uri equal: %.*s\n", cid.len, cid.s,
					param.len, param.s);
			return -1;
		}
		s.s++;
		s.len--;
		param = s; /* start of the parameter */

no_value:
		/* search for the next ';' */
		for (; s.len > 0; s.s++, s.len--)
			if (*s.s == ';')
				break;
		if (state != RMQP_URI)
			param.len -= s.len;
		trim_len(param.len, param.s, param);

		/* here is the end of parameter  - handle it */
		switch (state) {
		case RMQP_URI:
			/* remember where the uri starts */
			suri = param;
			uri_pending = 1;
			break;
		case RMQP_NONE:
			/* we eneded up in a place that has ';' - if we haven't found
			 * the end of the uri, this is also part of the uri. otherwise it
			 * is an error and we shall report it */
			if (!uri_pending) {
				LM_ERR("[%.*s] Unknown parameter: %.*s\n", cid.len, cid.s,
						param.len, param.s);
				return -1;
			}
			break;
		case RMQP_FRAME:
			if (str2int(&param, (unsigned int *)&max_frames) < 0) {
				LM_ERR("[%.*s] frames must be a number: %.*s\n",
						cid.len, cid.s, param.len, param.s);
				return -1;
			}
			if (max_frames < RMQ_MIN_FRAMES) {
				LM_WARN("[%.*s] number of frames is %d - less than expected %d! "
						"setting to expected\n", cid.len, cid.s, max_frames, RMQ_MIN_FRAMES);
				max_frames = RMQ_MIN_FRAMES;
			} else {
				LM_DBG("[%.*s] setting frames to %d\n", cid.len, cid.s, max_frames);
			}
			break;
		case RMQP_HBEAT:
			if (str2int(&param, (unsigned int *)&heartbeat) < 0) {
				LM_ERR("[%.*s] heartbeat must be the number of seconds, not %.*s\n",
						cid.len, cid.s, param.len, param.s);
				return -1;
			}
			if (heartbeat < 0) {
				LM_WARN("[%.*s] invalid number of heartbeat seconds %d! Using default!\n",
						cid.len, cid.s, heartbeat);
				heartbeat = RMQ_DEFAULT_HEARTBEAT;
			} else {
				LM_DBG("[%.*s] setting heartbeat to %d\n", cid.len, cid.s, heartbeat);
			}
			break;
		case RMQP_RETRY:
			if (str2int(&param, (unsigned int *)&retries) < 0) {
				LM_ERR("[%.*s] retries must be a number, not %.*s\n",
						cid.len, cid.s, param.len, param.s);
				return -1;
			}
			if (retries < 0) {
				LM_WARN("[%.*s] invalid number of retries %d! Using default!\n",
						cid.len, cid.s, retries);
				retries = RMQ_DEFAULT_RETRIES;
			} else {
				LM_DBG("[%.*s] %d number of retries in case of error\n",
						cid.len, cid.s, heartbeat);
			}
			break;
		case RMQP_IMM:
			flags |= RMQF_IMM;
			break;
		case RMQP_MAND:
			flags |= RMQF_MAND;
			break;
		case RMQP_NOPER:
			flags |= RMQF_NOPER;
			break;
		case RMQP_EXCH:
			exchange = param;
			LM_DBG("[%.*s] setting exchange '%.*s'\n", cid.len, cid.s,
					exchange.len, exchange.s);
			break;
		}
	}
	/* if we don't have an uri, we forfeit */
	if (!suri.s) {
		LM_ERR("[%.*s] cannot find an uri!", cid.len, cid.s);
		return -1;
	}
	/* trim the last spaces and ';' of the uri */
	trim_len(suri.len, suri.s, suri);
	if (suri.s[suri.len - 1] == ';')
		suri.len--;
	trim_len(suri.len, suri.s, suri);

	if ((srv = pkg_malloc(sizeof *srv + suri.len + 1)) == NULL) {
		LM_ERR("cannot alloc memory for rabbitmq server\n");
		return -1;
	}
	memset(srv, 0, sizeof *srv);
	uri = ((char *)srv) + sizeof *srv;
	memcpy(uri, suri.s, suri.len);
	uri[suri.len] = 0;

	if (rmq_parse(uri, &srv->uri) != 0) {
		LM_ERR("[%.*s] cannot parse rabbitmq uri: %s\n", cid.len, cid.s, uri);
		goto free;
	}

	if (srv->uri.ssl) {
		LM_WARN("[%.*s] we currently do not support ssl connections!\n", cid.len, cid.s);
		goto free;
	}

	if (exchange.len) {
		srv->exchange = amqp_bytes_malloc(exchange.len);
		if (!srv->exchange.bytes) {
			LM_ERR("[%.*s] cannot allocate echange buffer!\n", cid.len, cid.s);
			goto free;
		}
		memcpy(srv->exchange.bytes, exchange.s, exchange.len);
	} else
		srv->exchange = RMQ_EMPTY;

	srv->state = RMQS_OFF;
	srv->cid = cid;

	srv->flags = flags;
	srv->retries = retries;
	srv->max_frames = max_frames;
	srv->heartbeat = heartbeat;

	list_add(&srv->list, &rmq_servers);
	LM_DBG("[%.*s] new AMQP host=%s:%u\n", srv->cid.len, srv->cid.s,
			srv->uri.host, srv->uri.port);

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
	void *srv = rmq_get_server((str*)*param);

	if (!srv) {
		LM_ERR("unknown connection id=%.*s\n",
			((str*)*param)->len, ((str*)*param)->s);
		return E_CFG;
	}

	*param = srv;

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

static inline int amqp_check_status(struct rmq_server *srv, int r, int* retry)
{
#ifndef AMQP_VERSION_v04
	if (r != 0) {
		LM_ERR("[%.*s] unknown AMQP error [%d] while sending\n",
				srv->cid.len, srv->cid.s, r);
		/* we close the connection here to be able to re-connect later */
		/* TODO: close the connection */
		return r;
	}
	return 0;
#else
	switch (r) {
		case AMQP_STATUS_OK:
			return 0;

		case AMQP_STATUS_TIMER_FAILURE:
			LM_ERR("[%.*s] timer failure\n", srv->cid.len, srv->cid.s);
			goto no_close;

		case AMQP_STATUS_NO_MEMORY:
			LM_ERR("[%.*s] no more memory\n", srv->cid.len, srv->cid.s);
			goto no_close;

		case AMQP_STATUS_TABLE_TOO_BIG:
			LM_ERR("[%.*s] a table in the properties was too large to fit in "
					"a single frame\n", srv->cid.len, srv->cid.s);
			goto no_close;

		case AMQP_STATUS_HEARTBEAT_TIMEOUT:
			LM_ERR("[%.*s] heartbeat timeout\n", srv->cid.len, srv->cid.s);
			break;

		case AMQP_STATUS_CONNECTION_CLOSED:
			LM_ERR("[%.*s] connection closed\n", srv->cid.len, srv->cid.s);
			break;

		/* this should not happened since we do not use ssl */
		case AMQP_STATUS_SSL_ERROR:
			LM_ERR("[%.*s] SSL error\n", srv->cid.len, srv->cid.s);
			break;

		case AMQP_STATUS_TCP_ERROR:
			LM_ERR("[%.*s] TCP error: %s(%d)\n", srv->cid.len, srv->cid.s,
					strerror(errno), errno);
			break;

		/* This is happening on rabbitmq server restart */
		case AMQP_STATUS_SOCKET_ERROR:
			LM_WARN("[%.*s] socket error: %s(%d)\n",
					srv->cid.len, srv->cid.s, strerror(errno), errno);
			break;

		default:
			LM_ERR("[%.*s] unknown AMQP error[%d]: %s(%d)\n",
					srv->cid.len, srv->cid.s, r, strerror(errno), errno);
			break;
	}
	/* we close the connection here to be able to re-connect later */
	rmq_close_server(srv);
no_close:
	if (retry && *retry > 0) {
		(*retry)--;
		return 1;
	}
	return r;
#endif
}

#define RMQ_ALLOC_STEP 2

int rmq_send(struct rmq_server *srv, str *rkey, str *body, str *ctype,
		int *names, int *values)
{
	int nr;
	int_str v;
	int ret = -1;
	amqp_bytes_t akey;
	amqp_bytes_t abody;
	amqp_basic_properties_t props;
	int retries = srv->retries;
	static int htable_allocated = 0;
	static amqp_table_entry_t *htable = NULL;
	struct usr_avp *aname = NULL, *aval = NULL;
	amqp_table_entry_t *htmp = NULL;

	akey.len = rkey->len;
	akey.bytes = rkey->s;
	abody.len = body->len;
	abody.bytes = body->s;
	memset(&props, 0, sizeof props);

	/* populates props based on the names and values */
	if (names && values) {
		/* count the number of avps */
		nr = 0;
		for (;;) {
			aname = search_first_avp(0, *names, &v, aname);
			if (!aname)
				break;
			if (nr >= htable_allocated) {
				htmp = pkg_realloc(htable, (htable_allocated + RMQ_ALLOC_STEP) *
						sizeof(amqp_table_entry_t));
				if (!htmp) {
					LM_ERR("out of pkg memory for headers!\n");
					return -1;
				}
				htable_allocated += RMQ_ALLOC_STEP;
				htable = htmp;
			}
			if (aname->flags & AVP_VAL_STR) {
				htable[nr].key.len = v.s.len;
				htable[nr].key.bytes = v.s.s;
			} else {
				htable[nr].key.bytes = int2str(v.n, (int *)&htable[nr].key.len);
			}
			aval = search_first_avp(0, *values, &v, aval);
			if (!aval) {
				LM_ERR("names and values number mismatch!\n");
				break;
			}
			if (aval->flags & AVP_VAL_STR) {
				htable[nr].value.kind = AMQP_FIELD_KIND_UTF8;
				htable[nr].value.value.bytes.bytes = v.s.s;
				htable[nr].value.value.bytes.len = v.s.len;
			} else {
				htable[nr].value.kind = AMQP_FIELD_KIND_I32;
				htable[nr].value.value.i32 = v.n;
			}
			LM_DBG("added key no. %d %.*s type %s\n", nr + 1,
					(int)htable[nr].key.len, (char *)htable[nr].key.bytes,
					(htable[nr].value.kind == AMQP_FIELD_KIND_UTF8 ? "string":"int"));
			nr++;
		}
		LM_DBG("doing a rabbitmq query with %d headers\n", nr);
		props.headers.entries = htable;
		props.headers.num_entries = nr;
		props._flags |= AMQP_BASIC_HEADERS_FLAG;
	}

	if (ctype) {
		props._flags |= AMQP_BASIC_CONTENT_TYPE_FLAG;
		props.content_type.len = ctype->len;
		props.content_type.bytes = ctype->s;
	}
	if (!(srv->flags & RMQF_NOPER)) {
		props.delivery_mode = 2;
		props._flags |= AMQP_BASIC_DELIVERY_MODE_FLAG;
	}

	do {
		if (rmq_reconnect(srv) < 0) {
			LM_ERR("[%.*s] cannot send RabbitMQ message\n",
					srv->cid.len, srv->cid.s);
			return ret;
		}

		ret = amqp_basic_publish(srv->conn, 1, srv->exchange, akey, \
				(srv->flags & RMQF_MAND), (srv->flags & RMQF_IMM),
				&props, abody);
		ret = amqp_check_status(srv, ret, &retries);
	} while (ret > 0);

	return ret;
}
