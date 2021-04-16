/*
 * Copyright (C) 2015 - OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
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
 *
 * History:
 * -------
 *  2015-02-11  first version (razvanc)
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <poll.h>

#include "../../pt.h"
#include "../../sr_module.h"
#include "../../net/net_tcp.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp_report.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../receive.h"
#include "../../timer.h"
#include "../../net/trans_trace.h"
#include "proto_ws.h"
#include "ws_tcp.h"
#include "ws_common_defs.h"

/* parameters*/
int ws_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;

static struct tcp_req tcp_current_req;

static struct ws_req ws_current_req;

/* in milliseconds */
int ws_send_timeout = 100;

/* in milliseconds */
int ws_hs_read_tout = 100;

/* XXX: this information should be dynamically provided */
static str ws_resource = str_init("/");

#define _ws_common_module "ws"
#define _ws_common_tcp_current_req tcp_current_req
#define _ws_common_current_req ws_current_req
#define _ws_common_max_msg_chunks ws_max_msg_chunks
#define _ws_common_read ws_raw_read
#define _ws_common_writev ws_raw_writev
#define _ws_common_read_tout ws_hs_read_tout
#define _ws_common_write_tout ws_send_timeout
#define _ws_common_resource ws_resource
#include "ws_handshake_common.h"
#include "ws_common.h"

#define WS_TRACE_PROTO "proto_hep"
#define WS_TRANS_TRACE_PROTO_ID "net"
static str trace_destination_name = {NULL, 0};
trace_dest t_dst;
trace_proto_t tprot;

extern int is_tcp_main;

/* module  tracing parameters */
static int trace_is_on_tmp=0, *trace_is_on;
static char* trace_filter_route;
static int trace_filter_route_id = -1;
/**/

static int mod_init(void);
static int proto_ws_init(struct proto_info *pi);
static int proto_ws_init_listener(struct socket_info *si);
static int proto_ws_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id);
static int ws_read_req(struct tcp_connection* con, int* bytes_read);
static int ws_conn_init(struct tcp_connection* c);
static void ws_conn_clean(struct tcp_connection* c);
static void ws_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);
static mi_response_t *ws_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *ws_trace_mi_1(const mi_params_t *params,
								struct mi_handler *async_hdl);


static int ws_port = WS_DEFAULT_PORT;


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_ws_init, {{0,0,0}},0},
};

static param_export_t params[] = {
	/* XXX: should we drop the ws prefix? */
	{ "ws_port",           INT_PARAM, &ws_port           },
	{ "ws_max_msg_chunks", INT_PARAM, &ws_max_msg_chunks },
	{ "ws_send_timeout",   INT_PARAM, &ws_send_timeout   },
	{ "ws_resource",       STR_PARAM, &ws_resource.s     },
	{ "ws_handshake_timeout", INT_PARAM, &ws_hs_read_tout },
	{ "trace_destination",     STR_PARAM,         &trace_destination_name.s  },
	{ "trace_on",						 INT_PARAM, &trace_is_on_tmp        },
	{ "trace_filter_route",				 STR_PARAM, &trace_filter_route     },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "proto_hep", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static mi_export_t mi_cmds[] = {
	{ "ws_trace", 0, 0, 0, {
		{ws_trace_mi, {0}},
		{ws_trace_mi_1, {"trace_mode", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};

struct module_exports exports = {
	PROTO_PREFIX "ws",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};



static int proto_ws_init(struct proto_info *pi)
{
	pi->id					= PROTO_WS;
	pi->name				= "ws";
	pi->default_port		= ws_port;

	pi->tran.init_listener	= proto_ws_init_listener;
	pi->tran.send			= proto_ws_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)ws_read_req;

	pi->net.conn_init		= ws_conn_init;
	pi->net.conn_clean		= ws_conn_clean;
	pi->net.report			= ws_report;

	return 0;
}


static int mod_init(void)
{
	LM_INFO("initializing WebSocket protocol\n");

	ws_resource.len = strlen(ws_resource.s);

	if (trace_destination_name.s) {
		if ( !net_trace_api ) {
			if ( trace_prot_bind( WS_TRACE_PROTO, &tprot) < 0 ) {
				LM_ERR( "can't bind trace protocol <%s>\n", WS_TRACE_PROTO );
				return -1;
			}

			net_trace_api = &tprot;
		} else {
			tprot = *net_trace_api;
		}

		trace_destination_name.len = strlen( trace_destination_name.s );

		if ( net_trace_proto_id == -1 )
			net_trace_proto_id = tprot.get_message_id( WS_TRANS_TRACE_PROTO_ID );

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


static int ws_conn_init(struct tcp_connection* c)
{
	struct ws_data *d;

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct ws_data *)shm_malloc(sizeof(*d));
	if (d==NULL) {
		LM_ERR("failed to create ws states in shm mem\n");
		return -1;
	}
	memset( d, 0, sizeof( struct ws_data ) );

	if ( t_dst && tprot.create_trace_message ) {
		d->tprot = &tprot;
		d->dest = t_dst;
		d->net_trace_proto_id = net_trace_proto_id;
		d->trace_is_on = trace_is_on;
		d->trace_route_id = trace_filter_route_id;
	}

	d->state = WS_CON_INIT;
	d->type = WS_NONE;
	d->code = WS_ERR_NONE;

	c->proto_data = (void*)d;
	return 0;
}

static void ws_conn_clean(struct tcp_connection* c)
{
	struct ws_data *d = (struct ws_data*)c->proto_data;
	if (!d)
		return;

	if (c->state == S_CONN_OK && !is_tcp_main) {
		switch (d->code) {
		case WS_ERR_NOSEND:
			break;
		case WS_ERR_NONE:
			WS_CODE(c) = WS_ERR_NORMAL;
			/* fall through */
		default:
			ws_close(c);
			break;
		}
	}

	shm_free(d);
	c->proto_data = NULL;
}


static int proto_ws_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}

static void ws_report(int type, unsigned long long conn_id, int conn_flags,
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

		trace_message_atonce( PROTO_WS, conn_id, NULL/*src*/, NULL/*dst*/,
			TRANS_TRACE_CLOSED, TRANS_TRACE_SUCCESS, extra?&s:NULL, t_dst );
	}

	return;
}



/**************  WRITE related functions ***************/



/*! \brief Finds a tcpconn & sends on it */
static int proto_ws_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id)
{
	struct tcp_connection *c;
	struct timeval get;
	struct ip_addr ip;
	int port = 0;
	int fd, n;

	struct ws_data* d;

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get,tcpthreshold);

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, PROTO_WS, NULL, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd);
	}else{
		LM_CRIT("prot_tls_send called with null id & to\n");
		get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
		return -1;
	}

	if (n<0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to acquire connection\n");
		get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
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
		if ((c=ws_connect(send_sock, to, &fd))==0) {
			LM_ERR("connect failed\n");
			return -1;
		}

		d = c->proto_data;

		if ( d && d->dest && d->tprot ) {
			if ( d->message ) {
				send_trace_message( d->message, t_dst);
				d->message = NULL;
			}

			/* don't allow future traces for this cnection */
			d->tprot = 0;
			d->dest  = 0;
		}

		goto send_it;
	}
	get_time_difference(get, tcpthreshold, tcp_timeout_con_get);

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

	n = ws_req_write(c, fd, buf, len);
	stop_expire_timer(get, tcpthreshold, "WS ops",buf,(int)len,1);
	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n=%d fd=%d\n",c, n, fd);
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




/**************  READ related functions ***************/




/* Responsible for reading the request
 *	* if returns >= 0 : the connection will be released
 *	* if returns <  0 : the connection will be released as BAD / broken
 */
static int ws_read_req(struct tcp_connection* con, int* bytes_read)
{
	int size;
	struct ws_data* d;

	if (WS_STATE(con) != WS_CON_HANDSHAKE_DONE) {
		size = ws_server_handshake(con);
		if (size < 0) {
			LM_ERR("cannot complete WebSocket handshake\n");
			goto error;
		}

		d = con->proto_data;
		if ( d && d->dest && d->tprot ) {
			if ( d->message ) {
				send_trace_message( d->message, t_dst);
				d->message = NULL;
			}

			/* don't allow future traces for this connection */
			d->tprot = 0;
			d->dest  = 0;
		}

		if (size == 0)
			goto done;
	}
	if (WS_STATE(con) == WS_CON_HANDSHAKE_DONE && ws_process(con) < 0)
		goto error;

done:
	return 0;
error:
	/* connection will be released as ERROR */
	return -1;
}

static mi_response_t *ws_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if ( *trace_is_on ) {
		if (add_mi_string(resp_obj, MI_SSTR("WS tracing"), MI_SSTR("on")) < 0) {
			free_mi_response(resp);
			return 0;
		}
	} else {
		if (add_mi_string(resp_obj, MI_SSTR("WS tracing"), MI_SSTR("off")) < 0) {
			free_mi_response(resp);
			return 0;
		}
	}

	return resp;
}

static mi_response_t *ws_trace_mi_1(const mi_params_t *params,
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
