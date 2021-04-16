 /*
 * Copyright (C) 2015 OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
 *
 */

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <dirent.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../timer.h"
#include "../../receive.h"
#include "../../pt.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"

#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../tls_mgm/api.h"
#include "../tls_mgm/tls_conn_ops.h"
#include "../tls_mgm/tls_conn_server.h"

#include "../../net/trans_trace.h"

/*
 * Open questions:
 *
 * - what would happen when select exits, connection is passed
 *   to reader to perform read, but another process would acquire
 *   the same connection meanwhile, performs a write and finishes
 *   accept/connect on behalf of the reader process, thus the
 *   reader process would have nothing to read ? (resolved)
 *
 * - What happens if SSL_accept or SSL_connect gets called on
 *   already established connection (c->S_CONN_OK) ? We could
 *   save some locking provided that the functions do not screw
 *   up the connection (in tcp_fix_read_conn we would not have
 *   to lock before the switch).
 *
 * - tls_blocking_write needs fixing..
 *
 * - we need to protect ctx by a lock -- it is in shared memory
 *   and may be accessed simultaneously
 */
struct tls_mgm_binds tls_mgm_api;

static int tls_port_no = SIPS_PORT;

static int tls_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;

/* 0: send CRLF pong to incoming CRLFCRLF ping */
static int tls_crlf_pingpong = 1;

/* 0: do not drop single CRLF messages */
static int tls_crlf_drop = 0;

/* check the SSL certificate when comes to TCP conn reusage */
static int cert_check_on_conn_reusage = 0;

static int tls_handshake_tout = 100;
static int tls_send_tout = 100;

static int  mod_init(void);
static void mod_destroy(void);
static int proto_tls_init(struct proto_info *pi);
static int proto_tls_init_listener(struct socket_info *si);
static int proto_tls_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id);
static void tls_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);
static mi_response_t *tls_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *tls_trace_mi_1(const mi_params_t *params,
								struct mi_handler *async_hdl);


trace_dest t_dst;

static int w_tls_blocking_write(struct tcp_connection *c, int fd, const char *buf,
																	size_t len)
{
	int ret;

	lock_get(&c->write_lock);
	ret = tls_blocking_write(c, fd, buf, len,
			tls_handshake_tout, tls_send_tout, t_dst, &tls_mgm_api);
	lock_release(&c->write_lock);
	return ret;
}

/* buffer to be used for reading all TCP SIP messages
   detached from the actual con - in order to improve
   paralelism ( process the SIP message while the con
   can be sent back to main to do more stuff */
static struct tcp_req tls_current_req;

/* re-use similar and existing functions from the TCP-plain protocol */
#define _tcp_common_write        w_tls_blocking_write
#define _tcp_common_current_req  tls_current_req
#include "../../net/proto_tcp/tcp_common.h"

#define TLS_TRACE_PROTO "proto_hep"

static str trace_destination_name = {NULL, 0};
trace_proto_t tprot;

/* module  tracing parameters */
static int trace_is_on_tmp=0, *trace_is_on;
static char* trace_filter_route;
static int trace_filter_route_id = -1;

/**/

static int tls_read_req(struct tcp_connection* con, int* bytes_read);
static int proto_tls_conn_init(struct tcp_connection* c);
static void proto_tls_conn_clean(struct tcp_connection* c);

static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_tls_init, {{0, 0, 0}}, 0},
	{ 0, 0, {{0, 0, 0}}, 0}
};


static param_export_t params[] = {
	{ "tls_port",              INT_PARAM,         &tls_port_no               },
	{ "tls_crlf_pingpong",     INT_PARAM,         &tls_crlf_pingpong         },
	{ "tls_crlf_drop",         INT_PARAM,         &tls_crlf_drop             },
	{ "tls_max_msg_chunks",    INT_PARAM,         &tls_max_msg_chunks        },
	{ "tls_send_timeout",      INT_PARAM,         &tls_send_tout             },
	{ "tls_handshake_timeout", INT_PARAM,         &tls_handshake_tout        },
	{ "trace_destination",     STR_PARAM,         &trace_destination_name.s  },
	{ "trace_on",					INT_PARAM, &trace_is_on_tmp           },
	{ "trace_filter_route",			STR_PARAM, &trace_filter_route        },
	{ "cert_check_on_conn_reusage",	INT_PARAM, &cert_check_on_conn_reusage},
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tls_mgm"  , DEP_ABORT  },
		{ MOD_TYPE_DEFAULT, "proto_hep", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static mi_export_t mi_cmds[] = {
	{ "tls_trace", 0, 0, 0, {
		{tls_trace_mi, {0}},
		{tls_trace_mi_1, {"trace_mode", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};

struct module_exports exports = {
	PROTO_PREFIX "tls",  /* module name*/
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	NULL,       /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};


static int mod_init(void)
{

	LM_INFO("initializing TLS protocol\n");

	if(load_tls_mgm_api(&tls_mgm_api) != 0){
		LM_DBG("failed to find tls API - is tls_mgm module loaded?\n");
		return -1;
	}

	if (trace_destination_name.s) {
		if ( !net_trace_api ) {
			if ( trace_prot_bind( TLS_TRACE_PROTO, &tprot) < 0 ) {
				LM_ERR( "can't bind trace protocol <%s>\n", TLS_TRACE_PROTO );
				return -1;
			}
			net_trace_api = &tprot;
		} else {
			tprot = *net_trace_api;
		}

		trace_destination_name.len = strlen( trace_destination_name.s );

		if ( net_trace_proto_id == -1 )
			net_trace_proto_id = tprot.get_message_id( TRANS_TRACE_PROTO_ID );

		t_dst = tprot.get_trace_dest_by_name( &trace_destination_name );
	}

	/* fix route name */
	if ( !(trace_is_on = shm_malloc(sizeof(int))) ) {
		LM_ERR("no more shared memory!\n");
		return -1;
	}

	*trace_is_on = trace_is_on_tmp;
	if ( trace_filter_route ) {
		trace_filter_route_id =
			get_script_route_ID_by_name( trace_filter_route,
				sroutes->request, RT_NO);
	}

	return 0;
}


/*
 * called from main.c when opensips exits (main process)
 */
static void mod_destroy(void)
{
	/* library destroy */
	ERR_free_strings();
	/*SSL_free_comp_methods(); - this function is not on std. openssl*/
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return;
}


static int proto_tls_init(struct proto_info *pi)
{
	pi->id					= PROTO_TLS;
	pi->name				= "tls";
	pi->default_port		= tls_port_no;

	pi->tran.init_listener	= proto_tls_init_listener;
	pi->tran.send			= proto_tls_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)tls_read_req;
	pi->net.conn_init		= proto_tls_conn_init;
	pi->net.conn_clean		= proto_tls_conn_clean;
	if (cert_check_on_conn_reusage)
		pi->net.conn_match		= tls_conn_extra_match;
	else
		pi->net.conn_match		= NULL;
	pi->net.report			= tls_report;

	return 0;
}



static int proto_tls_init_listener(struct socket_info *si)
{
	/*
	 * reuse tcp initialization
	 */
	if (tcp_init_listener(si) < 0) {
		LM_ERR("failed to initialize TCP part\n");
		goto error;
	}

	return 0;

error:
	if (si->socket != -1) {
		close(si->socket);
		si->socket = -1;
	}
	return -1;
}


static int proto_tls_conn_init(struct tcp_connection* c)
{
	struct tls_data* data;

	if ( t_dst && tprot.create_trace_message ) {
		/* this message shall be used in first send function */
		data = shm_malloc( sizeof(struct tls_data) );
		if ( !data ) {
			LM_ERR("no more pkg mem!\n");
			goto out;
		}
		memset( data, 0, sizeof(struct tls_data) );

		if ( t_dst && tprot.create_trace_message) {
			data->tprot = &tprot;
			data->dest  = t_dst;
			data->net_trace_proto_id = net_trace_proto_id;
			data->trace_is_on = trace_is_on;
			data->trace_route_id = trace_filter_route_id;
		}

		c->proto_data = data;
	} else {
		c->proto_data = 0;
	}

out:
	return tls_conn_init(c, &tls_mgm_api);
}


static void proto_tls_conn_clean(struct tcp_connection* c)
{
	if (c->proto_data) {
		shm_free(c->proto_data);
		c->proto_data = NULL;
	}

	tls_conn_clean(c, &tls_mgm_api);
}


static void tls_report(int type, unsigned long long conn_id, int conn_flags,
																void *extra)
{
	str s;

	if (type==TCP_REPORT_CLOSE) {
		if ( !*trace_is_on || !t_dst || (conn_flags & F_CONN_TRACE_DROPPED) )
			return;

		/* grab reason text */
		if (extra) {
			s.s = (char*)extra;
			s.len = strlen (s.s);
		}

		trace_message_atonce( PROTO_TLS, conn_id, NULL/*src*/, NULL/*dst*/,
			TRANS_TRACE_CLOSED, TRANS_TRACE_SUCCESS, extra?&s:NULL, t_dst );
	}

	return;
}

static struct tcp_connection* tls_sync_connect(struct socket_info* send_sock,
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
	con=tcp_conn_create(s, server, send_sock, S_CONN_OK);
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


static int proto_tls_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id)
{
	struct tcp_connection *c;
	struct tls_domain *dom;
	struct ip_addr ip;
	int port;
	int fd, n;

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		dom = (cert_check_on_conn_reusage==0)?
			NULL : tls_mgm_api.find_client_domain( &ip, port);
		n = tcp_conn_get(id, &ip, port, PROTO_TLS, dom, &c, &fd);
		if (dom)
			tls_mgm_api.release_domain(dom);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd);
	}else{
		LM_CRIT("prot_tls_send called with null id & to\n");
		return -1;
	}

	if (n<0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to acquire connection\n");
		return -1;
	}

	/* was connection found ?? */
	if (c==0) {
		if (tcp_no_new_conn) {
			return -1;
		}
		if (!to) {
			LM_ERR("Unknown destination - cannot open new ws connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one\n");
		/* create tcp connection */
		if ((c=tls_sync_connect(send_sock, to, &fd))==0) {
			LM_ERR("connect failed\n");
			return -1;
		}
		goto send_it;
	}

	/* now we have a connection, let's what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd==-1) {
		/* connection is not writable because of its state */
		/* return error, nothing to do about it */
		tcp_conn_release(c, 0);
		return -1;
	}

send_it:
	LM_DBG("sending via fd %d...\n",fd);

	lock_get(&c->write_lock);
	n = tls_blocking_write(c, fd, buf, len,
			tls_handshake_tout, tls_send_tout, t_dst, &tls_mgm_api);
	lock_release(&c->write_lock);
	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n=%d fd=%d\n",c, n, fd);
	LM_DBG("buf=\n%.*s\n", (int)len, buf);
	if (n<0){
		LM_ERR("failed to send\n");
		c->state=S_CONN_BAD;
		if (c->proc_id != process_no)
			close(fd);
		tcp_conn_release(c, 0);
		return -1;
	}

	/* only close the FD if not already in the context of our process
	either we just connected, or main sent us the FD */
	if (c->proc_id != process_no)
		close(fd);

	/* mark the ID of the used connection (tracing purposes) */
	last_outgoing_tcp_id = c->id;
	send_sock->last_local_real_port = c->rcv.dst_port;
	send_sock->last_remote_real_port = c->rcv.src_port;

	tcp_conn_release(c, 0);
	return n;
}

static int tls_read_req(struct tcp_connection* con, int* bytes_read)
{
	int ret;
	int bytes;
	int total_bytes;
	struct tcp_req* req;

	struct tls_data* data;

	bytes=-1;
	total_bytes=0;

	if (con->con_req) {
		req=con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&tls_current_req, 0);
		req=&tls_current_req;
	}

	/* do this trick in order to trace whether if it's an error or not */
	ret=tls_fix_read_conn(con, t_dst, &tls_mgm_api);

	/* if there is pending tracing data on an accepted connection, flush it
	 * As this is a read op, we look only for accepted conns, not to conflict
	 * with connected conns (flushed on write op) */
	if ( con->flags&F_CONN_ACCEPTED && con->proto_flags & F_TLS_TRACE_READY ) {
		data = con->proto_data;
		/* send the message if set from tls_mgm */
		if ( data->message ) {
			send_trace_message( data->message, t_dst);
			data->message = NULL;
		}

		/* don't allow future traces for this connection */
		data->tprot = 0;
		data->dest  = 0;

		con->proto_flags &= ~( F_TLS_TRACE_READY );
	}

	if ( ret != 0 ) {
		LM_ERR("failed to do pre-tls reading\n");
		goto error;
	}

	if(con->state!=S_CONN_OK)
		goto done; /* not enough data */

again:
	if(req->error==TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed<req->pos){
			bytes=0;
		}else{
			bytes=tls_read(con,req, &tls_mgm_api);
			if (bytes<0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		tcp_parse_headers(req, tls_crlf_pingpong, tls_crlf_drop);
#ifdef EXTRA_DEBUG
					/* if timeout state=0; goto end__req; */
		LM_DBG("read= %d bytes, parsed=%d, state=%d, error=%d\n",
				bytes, (int)(req->parsed-req->start), req->state,
				req->error );
		LM_DBG("last char=0x%02X, parsed msg=\n%.*s\n",
				*(req->parsed-1), (int)(req->parsed-req->start),
				req->start);
#endif
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

	switch (tcp_handle_req(req, con, tls_max_msg_chunks) ) {
		case 1:
			goto again;
		case -1:
			goto error;
	}

	LM_DBG("tls_read_req end\n");
done:
	if (bytes_read) *bytes_read=total_bytes;
	/* connection will be released */
	return 0;
error:
	/* connection will be released as ERROR */
	return -1;
}

static mi_response_t *tls_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if ( *trace_is_on ) {
		if (add_mi_string(resp_obj, MI_SSTR("TLS tracing"), MI_SSTR("on")) < 0) {
			free_mi_response(resp);
			return 0;
		}
	} else {
		if (add_mi_string(resp_obj, MI_SSTR("TLS tracing"), MI_SSTR("off")) < 0) {
			free_mi_response(resp);
			return 0;
		}
	}

	return resp;
}

static mi_response_t *tls_trace_mi_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str new_mode;

	if (get_mi_string_param(params, "trace_mode", &new_mode.s, &new_mode.len) < 0)
		return init_mi_param_error();

	if ( (new_mode.s[0] | 0x20) == 'o' &&
			(new_mode.s[1] | 0x20) == 'n' ) {
		*trace_is_on = 1;
		return init_mi_result_ok();
	} else
	if ( (new_mode.s[0] | 0x20) == 'o' &&
			(new_mode.s[1] | 0x20) == 'f' &&
			(new_mode.s[2] | 0x20) == 'f' ) {
		*trace_is_on = 0;
		return init_mi_result_ok();
	} else {
		return init_mi_error_extra(500, MI_SSTR("Bad parameter value"),
			MI_SSTR("trace_mode should be 'on' or 'off'"));
	}
}
