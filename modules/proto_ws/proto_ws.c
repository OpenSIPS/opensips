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
#include <poll.h>

#include "../../pt.h"
#include "../../sr_module.h"
#include "../../net/net_tcp.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../receive.h"
#include "../../timer.h"
#include "proto_ws.h"
#include "ws.h"

static int mod_init(void);
static int proto_ws_init(struct proto_info *pi);
static int proto_ws_init_listener(struct socket_info *si);
static int proto_ws_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id);
static int ws_read_req(struct tcp_connection* con, int* bytes_read);

/* parameters*/
int ws_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;

/* in milliseconds */
int ws_send_timeout = 100;

static int ws_port = WS_DEFAULT_PORT;


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_ws_init, 0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};


static param_export_t params[] = {
	/* XXX: should we drop the ws prefix? */
	{ "ws_port",           INT_PARAM, &ws_port           },
	{ "ws_max_msg_chunks", INT_PARAM, &ws_max_msg_chunks },
	{ "ws_send_timeout",   INT_PARAM, &ws_send_timeout   },
	{0, 0, 0}
};


struct module_exports exports = {
	PROTO_PREFIX "ws",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
};



static int proto_ws_init(struct proto_info *pi)
{
	pi->default_port		= ws_port;

	pi->tran.init_listener	= proto_ws_init_listener;
	pi->tran.send			= proto_ws_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)ws_read_req;

	return 0;
}


static int mod_init(void)
{
	LM_INFO("initializing WebSocket protocol\n");
	return 0;
}



static int proto_ws_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}





/**************  WRITE related functions ***************/



/*! \brief Finds a tcpconn & sends on it */
static int proto_ws_send(struct socket_info* send_sock,
											char* buf, unsigned int len,
											union sockaddr_union* to, int id)
{
	struct tcp_connection *c;
	struct timeval get;
	struct ip_addr ip;
	int port = 0;
	int fd, n;

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get,tcpthreshold);

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, &c, &fd);
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
		/* XXX: currently cannot work as a WebSocket client */
		LM_ERR("no open tcp connection found. "
				"WebSocket connect is not supported!\n");
		get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
		return -1;
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

	LM_DBG("sending via fd %d...\n",fd);

	n = ws_req_write(c, fd, buf, len);
	stop_expire_timer(get, tcpthreshold, "WS ops",buf,(int)len,1);
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

	if (WS_STATE(con) != WS_CON_HANDSHAKE_DONE) {

		size = ws_handshake(con);
		if (size < 0) {
			LM_ERR("cannot complete WebSocket handshake\n");
			goto error;
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




