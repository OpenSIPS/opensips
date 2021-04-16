/*
 * Copyright (C) 2019 - OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../forward.h"
#include "../../ipc.h"
#include "../../db/db.h"
#include "../../receive.h"
#include "../tm/tm_load.h"
#include "../../parser/parse_from.h"

#include "proto_smpp.h"
#include "utils.h"
#include "db.h"

/*
 * TODO:
 *  - implement reload
 *  - reconnect when connection is down
 */

extern int proto_tcp_read(struct tcp_connection* ,struct tcp_req* );

static int mod_init(void);
static int child_init(int rank);
static int smpp_init(struct proto_info *pi);
static int smpp_init_listener(struct socket_info *si);
static int smpp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id);
static int smpp_read_req(struct tcp_connection* conn, int* bytes_read);
static int smpp_write_async_req(struct tcp_connection* con,int fd);
static int smpp_conn_init(struct tcp_connection* c);
static void smpp_conn_clean(struct tcp_connection* c);
static int send_smpp_msg(struct sip_msg* msg, str *name, str *from,
		str *to, str *body, int *utf16, int *delivery_confirmation);

static unsigned smpp_port = 2775;
static int smpp_max_msg_chunks = 8;
extern int smpp_send_timeout;

str db_url = {NULL, 0};

static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)smpp_init, {{0,0,0}},
		REQUEST_ROUTE},
	{"send_smpp_message", (cmd_function)send_smpp_msg, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0},{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[] = {
	{"smpp_port", INT_PARAM, &smpp_port},
	{"smpp_max_msg_chunks", INT_PARAM, &smpp_max_msg_chunks},
	{"smpp_send_timeout", INT_PARAM, &smpp_send_timeout},
	{"db_url", STR_PARAM, &db_url.s},
	{"outbound_uri", STR_PARAM, &smpp_outbound_uri},
	{"smpp_table", STR_PARAM, &smpp_table},
	{"name_col", STR_PARAM, &smpp_name_col.s},
	{"ip_col", STR_PARAM, &smpp_ip_col.s},
	{"port_col", STR_PARAM, &smpp_port_col.s},
	{"system_id_col", STR_PARAM, &smpp_system_id_col.s},
	{"password_col", STR_PARAM, &smpp_password_col.s},
	{"system_type_col", STR_PARAM, &smpp_system_type_col.s},
	{"src_ton_col", STR_PARAM, &smpp_src_ton_col.s},
	{"src_npi_col", STR_PARAM, &smpp_src_npi_col.s},
	{"dst_ton_col", STR_PARAM, &smpp_dst_ton_col.s},
	{"dst_npi_col", STR_PARAM, &smpp_dst_npi_col.s},
	{"session_type_col", STR_PARAM, &smpp_session_type_col.s},
	{0, 0, 0}
};

struct module_exports exports = {
	PROTO_PREFIX "smpp",	/* module name*/
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,					/* load function */
	NULL,			/* OpenSIPS module dependencies */
	cmds,			/* exported functions */
	0,			/* exported async functions */
	params,			/* module parameters */
	0,			/* exported statistics */
	0,			/* exported MI functions */
	0,			/* exported pseudo-variables */
	0,			/* exported transformations */
	0,			/* extra processes */
	0,			/* module pre-initialization function */
	mod_init,	/* module initialization function */
	0,			/* response function */
	0,			/* destroy function */
	child_init,		/* per-child init function */
	0			/* reload confirm function */
};

static int smpp_init(struct proto_info *pi)
{
	pi->id			= PROTO_SMPP;
	pi->name		= "smpp";
	pi->default_port	= smpp_port;

	pi->tran.init_listener	= smpp_init_listener;
	pi->tran.send		= smpp_send;
	pi->tran.dst_attr	= tcp_conn_fcntl;

	pi->net.flags		= PROTO_NET_USE_TCP;
	pi->net.read		= (proto_net_read_f)smpp_read_req;
	pi->net.write		= (proto_net_write_f)smpp_write_async_req;

	pi->net.conn_init	= smpp_conn_init;
	pi->net.conn_clean	= smpp_conn_clean;

	return 0;
}

static int mod_init(void)
{
	LM_INFO("initializing SMPP protocol\n");

	init_db_url(db_url, 0 /* cannot be null */);

	if (!smpp_outbound_uri.s) {
		LM_ERR("missing modparam: 'smpp_outbound_uri'\n");
		return -1;
	}

	smpp_outbound_uri.len = strlen(smpp_outbound_uri.s);

	/* if we don't have a listener, we won't be able to connect, or send
	 * enquiries, therefore it's mandatory to have at least one */
	if (!proto_has_listeners(PROTO_SMPP)) {
		LM_ERR("at least one listener is mandatory for using the SMPP module!\n");
		return -1;
	}

	if (smpp_db_init(&db_url) < 0)
		return -1;

	if (smpp_sessions_init() < 0)
		return -1;

	smpp_db_close();

	if (register_timer("enquire-link-timer", enquire_link, NULL, 5,
			TIMER_FLAG_DELAY_ON_DELAY)<0 )
		return -1;

	/* load the TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}


	return 0;
}


struct tcp_connection* smpp_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server, int *fd)
{
	int s;
	union sockaddr_union my_name;
	socklen_t my_name_len;
	struct tcp_connection* con;

	s=socket(AF2PF(server->s.sa_family), SOCK_STREAM, 0);
	if (s==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	if (tcp_init_sock_opt(s)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}
	my_name_len = sockaddru_len(send_sock->su);
	memcpy( &my_name, &send_sock->su, my_name_len);
	su_setport( &my_name, 0);
	if (bind(s, &my_name.s, my_name_len )!=0) {
		LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
		goto error;
	}

	if (tcp_connect_blocking(s, &server->s, sockaddru_len(*server))<0){
		LM_ERR("tcp_blocking_connect failed\n");
		goto error;
	}
	con = tcp_conn_create(s, server, send_sock, S_CONN_OK);
	if (con==NULL){
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	*fd = s;
	return con;
	/*FIXME: set sock idx! */
error:
	/* close the opened socket */
	if (s!=-1) close(s);
	return 0;
}

static int child_init(int rank)
{
	LM_INFO("initializing child #%d\n", rank);

	if (smpp_db_connect(&db_url) < 0)
		return -1;

	if ((rank == 1) && ipc_dispatch_rpc(rpc_bind_sessions, NULL) < 0) {
		LM_CRIT("failed to RPC the data loading\n");
		return -1;
	}

	return 0;
}

static int smpp_conn_init(struct tcp_connection* c)
{
	LM_INFO("smpp_conn_init called\n");
	return 0;
}

static void smpp_conn_clean(struct tcp_connection* c)
{
	LM_INFO("smpp_conn_clean called\n");
}

static int smpp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}

static int smpp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id)
{
	LM_INFO("smpp_send called\n");

	return 0;
}

static struct tcp_req smpp_current_req;
static int smpp_handle_req(struct tcp_req *req, struct tcp_connection *con)
{
	long size;
	struct receive_info local_rcv;

	if (req->complete){
		/* update the timeout - we successfully read the request */
		tcp_conn_set_lifetime( con, tcp_con_lifetime);
		con->timeout = con->lifetime;

		LM_DBG("completely received a message\n");
		/* rcv.bind_address should always be !=0 */
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */

		/* prepare for next request */
		size=req->pos - req->parsed;

		if (!size) {
			/* did not read any more things -  we can release
			 * the connection */
			LM_DBG("Nothing more to read on TCP conn %p, currently in state %d \n",
				con,con->state);
			if (req != &smpp_current_req) {
				/* we have the buffer in the connection tied buff -
				 *	detach it , release the conn and free it afterwards */
				con->con_req = NULL;
			}
		} else {
			LM_DBG("We still have things on the pipe - "
				"keeping connection \n");
		}
		local_rcv = con->rcv;

		/* give the message to the registered functions */
		handle_smpp_msg(req->buf, (smpp_session_t *)con->proto_data, &local_rcv);

		if (!size && req != &smpp_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			pkg_free(req);
		}

		con->msg_attempts = 0;

		if (size) {
			memmove(req->buf, req->parsed, size);

			init_tcp_req(req, size);

			/* if we still have some unparsed bytes, try to  parse them too*/
			return 1;
		}
	} else {

		con->msg_attempts ++;
		if (con->msg_attempts == smpp_max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			return -1;
		}

		if (req == &smpp_current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request\n");
			con->con_req = pkg_malloc(sizeof(struct tcp_req));
			if (con->con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				return -1;
			}

			if (req->pos != req->buf) {
				/* we have read some bytes */
				memcpy(con->con_req->buf,req->buf,req->pos-req->buf);
				con->con_req->pos = con->con_req->buf + (req->pos-req->buf);
			} else {
				con->con_req->pos = con->con_req->buf;
			}

			if (req->parsed != req->buf)
				con->con_req->parsed =con->con_req->buf+(req->parsed-req->buf);
			else
				con->con_req->parsed = con->con_req->buf;

			con->con_req->complete=req->complete;
			con->con_req->content_len=req->content_len;
			con->con_req->error = req->error;
		}
	}

	return 0;
}

static inline void smpp_parse_headers(struct tcp_req *req)
{
	uint32_t *px = (uint32_t*)req->buf;

	if (req->content_len == 0 && req->pos - req->buf < HEADER_SZ){
		req->parsed = req->pos;
		return;
	}

	req->content_len = ntohl(*px);
	if (req->pos - req->buf == req->content_len) {
		LM_DBG("received a complete message\n");
		req->complete = 1;
		req->parsed = req->buf +req->content_len;
	} else if (req->pos - req->buf > req->content_len) {
		LM_DBG("received more then a message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else {
		LM_DBG("received only part of a message\n");
		req->parsed = req->pos;
	}
}

static int smpp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	struct tcp_req *req;

	bytes = -1;
	total_bytes = 0;

	if (con->con_req) {
		req = con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&smpp_current_req, 0);
		req = &smpp_current_req;
	}

	again:
	if(req->error == TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed < req->pos){
			bytes=0;
		} else {
			bytes=proto_tcp_read(con,req);
			if (bytes < 0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		smpp_parse_headers(req);

		total_bytes+=bytes;
		/* eof check:
		 * is EOF if eof on fd and req.  not complete yet,
		 * if req. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->error!=TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
				  (int)(req->pos-req->buf), req->buf,
				  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		goto error;
	}

	switch (smpp_handle_req(req, con) ) {
		case 1:
			goto again;
		case -1:
			goto error;
	}

	LM_DBG("tcp_read_req end\n");
done:
	if (bytes_read) *bytes_read=total_bytes;
	/* connection will be released */
		return 0;
error:
	/* connection will be released as ERROR */
		return -1;
}

static int smpp_write_async_req(struct tcp_connection* con,int fd)
{
	LM_INFO("smpp_write_async_req called\n");
	return 0;
}

static int send_smpp_msg(struct sip_msg* msg, str *name, str *from,
		str *to, str *body, int *utf16, int *delivery_confirmation)
{
	str sbody;
	struct sip_uri *uri;
	content_t *msg_content_type;
	int body_type;
	param_t *p;
	smpp_session_t *session = NULL;

	session = smpp_session_get(name);
	if (!session) {
		LM_INFO("SMSc %.*s not found!\n", name->len, name->s);
		return -2;
	}

	if (!from) {
		uri = parse_from_uri(msg);
		if (!uri) {
			LM_ERR("could not parse from uri!\n");
			return -1;
		}
		from = &uri->user;
	}

	if (!to) {
		if(msg->parsed_uri_ok==0 && (parse_sip_msg_uri(msg)) < 0) {
			LM_ERR("Failed to parse URI \n");
			return -1;
		}
		to = &msg->parsed_uri.user;
	}

	if (!body) {
		if (get_body(msg, &sbody) < 0) {
			LM_ERR("Failed to fetch SIP body \n");
			return -1;
		}
	} else
		sbody = *body;

	if (!utf16) {
		if (!body) {
			body_type = parse_content_type_hdr(msg);
			if (body_type < 0) {
				LM_ERR("Failed to parse content type header \n");
				return -1;
			} else if (body_type > 0) {

				if (body_type != (TYPE_TEXT << 16 | SUBTYPE_PLAIN))
					LM_WARN("Don't know how to parse body type %d(%s). "
							"Treating as text/plain\n", body_type,
							convert_mime2string_CT(body_type));
				body_type = SMPP_CODING_DEFAULT;
				/* Expecting Content-Type:text/plain; charset=UTF-16 */

				/* check the charset */
				msg_content_type = msg->content_type->parsed;

				for (p = msg_content_type->params; p; p=p->next) {
					if (p->name.len == 7 && memcmp(p->name.s,"charset",7) == 0) {
						if (p->body.len == 6 &&
						memcmp(p->body.s,"UTF-16",6) == 0) {
							body_type = SMPP_CODING_UCS2;
							break;
						}
					}
				}
			}
		} else
			body_type = SMPP_CODING_DEFAULT;
	} else if (*utf16)
		body_type = SMPP_CODING_UCS2;
	else
		body_type = SMPP_CODING_DEFAULT;

	return send_submit_or_deliver_request(&sbody, body_type,
			from, to, session, delivery_confirmation);
}
