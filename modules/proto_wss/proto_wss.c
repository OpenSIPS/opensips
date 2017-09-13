/*
 * Copyright (C) 2016 - OpenSIPS Foundation
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
 *  2015-12-xx  first version (razvanc)
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
#include "../../net/tcp_conn_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../proto_ws/proto_ws.h"
#include "proto_wss.h"
#include "../proto_ws/ws_common_defs.h"
#include "../tls_mgm/api.h"
#include "../tls_mgm/tls_conn_ops.h"
#include "../tls_mgm/tls_conn_server.h"

struct tls_mgm_binds tls_mgm_api;

/* parameters*/
int wss_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;

static struct tcp_req tcp_current_req;

static struct ws_req wss_current_req;

int wss_hs_read_tout = 100;

/* XXX: this information should be dynamically provided */
static str wss_resource = str_init("/");

static int wss_raw_writev(struct tcp_connection *c, int fd,
		const struct iovec *iov, int iovcnt, int tout);

#define _ws_common_module "wss"
#define _ws_common_tcp_current_req tcp_current_req
#define _ws_common_current_req wss_current_req
#define _ws_common_max_msg_chunks wss_max_msg_chunks
#define _ws_common_read tls_read
#define _ws_common_writev wss_raw_writev
#define _ws_common_read_tout wss_hs_read_tout
/*
 * the timeout is only used by the _ws_common_writev function
 * but in our case, the timeout specified in the TLS MGM
 * module is used, so we no longer need this here
 */
#define _ws_common_write_tout 0
#define _ws_common_resource wss_resource
#include "../proto_ws/ws_handshake_common.h"
#include "../proto_ws/ws_common.h"

extern int is_tcp_main;

static int mod_init(void);
static int proto_wss_init(struct proto_info *pi);
static int proto_wss_init_listener(struct socket_info *si);
static int proto_wss_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id);
static int wss_read_req(struct tcp_connection* con, int* bytes_read);
static int wss_conn_init(struct tcp_connection* c);
static void ws_conn_clean(struct tcp_connection* c);

static int wss_port = WSS_DEFAULT_PORT;


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_wss_init, 0, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};


static param_export_t params[] = {
	/* XXX: should we drop the ws prefix? */
	{ "wss_port",           INT_PARAM, &wss_port           },
	{ "wss_max_msg_chunks", INT_PARAM, &wss_max_msg_chunks },
	{ "wss_resource",       STR_PARAM, &wss_resource       },
	{ "wss_handshake_timeout", INT_PARAM, &wss_hs_read_tout},
	{0, 0, 0}
};


struct module_exports exports = {
	PROTO_PREFIX "wss",  /* module name*/
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



static int proto_wss_init(struct proto_info *pi)
{
	pi->id					= PROTO_WSS;
	pi->name				= "wss";
	pi->default_port		= wss_port;

	pi->tran.init_listener	= proto_wss_init_listener;
	pi->tran.send			= proto_wss_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)wss_read_req;

	pi->net.conn_init		= wss_conn_init;
	pi->net.conn_clean		= ws_conn_clean;

	return 0;
}


static int mod_init(void)
{
	LM_INFO("initializing Secure WebSocket protocol\n");

	if(load_tls_mgm_api(&tls_mgm_api) != 0){
		LM_DBG("failed to find tls API - is tls_mgm module loaded?\n");
		return -1;
	}

	return 0;
}


static int wss_conn_init(struct tcp_connection* c)
{
	struct ws_data *d;
	int ret;

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct ws_data *)shm_malloc(sizeof(*d));
	if (d==NULL) {
		LM_ERR("failed to create ws states in shm mem\n");
		return -1;
	}
	d->state = WS_CON_INIT;
	d->type = WS_NONE;
	d->code = WS_ERR_NONE;

	c->proto_data = (void*)d;

	ret = tls_conn_init(c, &tls_mgm_api);
	if (ret < 0) {
		LM_ERR("Cannot initiate the conn\n");
		shm_free(d);
	}

	return ret;
}

static void ws_conn_clean(struct tcp_connection* c)
{
	struct ws_data *d = (struct ws_data*)c->proto_data;

	if (d) {

		if (c->state == S_CONN_OK && !is_tcp_main) {
			switch (d->code) {
			case WS_ERR_NOSEND:
				break;
			case WS_ERR_NONE:
				WS_CODE(c) = WS_ERR_NORMAL;
			default:
				ws_close(c);
				break;
			}
		}

		shm_free(d);
		c->proto_data = NULL;

	}

	tls_conn_clean(c);
}


static int proto_wss_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}

static struct tcp_connection* ws_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server)
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
	con=tcp_conn_new(s, server, send_sock, S_CONN_OK);
	if (con==NULL){
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	/* it is safe to move this here and clear it after we complete the
	 * handshake, just before sending the fd to main */
	con->fd = s;
	return con;
error:
	/* close the opened socket */
	if (s!=-1) close(s);
	return 0;
}

static struct tcp_connection* ws_connect(struct socket_info* send_sock,
		union sockaddr_union* to, int *fd)
{
	struct tcp_connection *c;

	if ((c=ws_sync_connect(send_sock, to))==0) {
		LM_ERR("connect failed\n");
		return NULL;
	}
	/* the state of the connection should be NONE, otherwise something is
	 * wrong */
	if (WS_TYPE(c) != WS_NONE) {
		LM_BUG("invalid type for connection %d\n", WS_TYPE(c));
		goto error;
	}
	WS_TYPE(c) = WS_CLIENT;

	if (ws_client_handshake(c) < 0) {
		LM_ERR("cannot complete WebSocket handshake\n");
		goto error;
	}

	*fd = c->fd;
	/* clear the fd, just in case */
	c->fd = -1;
	/* handshake done - send the socket to main */
	if (tcp_conn_send(c) < 0) {
		LM_ERR("cannot send socket to main\n");
		goto error;
	}

	return c;
error:
	tcp_conn_destroy(c);
	return NULL;
}


/**************  WRITE related functions ***************/



/*! \brief Finds a tcpconn & sends on it */
static int proto_wss_send(struct socket_info* send_sock,
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
		n = tcp_conn_get(id, &ip, port, PROTO_WSS, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, &c, &fd);
	}else{
		LM_CRIT("prot_tls_send called with null id & to\n");
		get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
		return -1;
	}

	if (n<0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to aquire connection\n");
		get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
		return -1;
	}

	/* was connection found ?? */
	if (c==0) {
		if (tcp_no_new_conn) {
			return -1;
		}
		if (!to) {
			LM_ERR("Unknown destination - cannot open new tcp connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one\n");
		/* create tcp connection */
		if ((c=ws_connect(send_sock, to, &fd))==0) {
			LM_ERR("connect failed\n");
			return -1;
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
	stop_expire_timer(get, tcpthreshold, "WSS ops",buf,(int)len,1);
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

	tcp_conn_release(c, 0);
	return n;
}




/**************  READ related functions ***************/




/* Responsible for reading the request
 *	* if returns >= 0 : the connection will be released
 *	* if returns <  0 : the connection will be released as BAD / broken
 */
static int wss_read_req(struct tcp_connection* con, int* bytes_read)
{
	int size;

	/* we need to fix the SSL connection before doing anything */
	if (tls_fix_read_conn(con) < 0) {
		LM_ERR("cannot fix read connection\n");
		goto error;
	}

	if (WS_STATE(con) != WS_CON_HANDSHAKE_DONE) {

		size = ws_server_handshake(con);
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



static int wss_raw_writev(struct tcp_connection *c, int fd,
		const struct iovec *iov, int iovcnt, int tout)
{
	int i, n, ret = 0;
#ifdef TLS_DONT_WRITE_FRAGMENTS
	static char *buf = NULL;
#endif

#ifndef TLS_DONT_WRITE_FRAGMENTS
	lock_get(&c->write_lock);
	for (i = 0; i < iovcnt; i++) {
		n = tls_blocking_write(c, fd, iov[i].iov_base, iov[i].iov_len, &tls_mgm_api);
		if (n < 0) {
			ret = -1;
			goto end;
		}
		ret += n;
	}
#else
	n = 0;
	for (i = 0; i < iovcnt; i++)
		n += iov[i].iov_len;
	buf = pkg_realloc(buf, n);
	if (!buf) {
		ret = -2;
		goto end;
	}
	n = 0;
	for (i = 0; i < iovcnt; i++) {
		memcpy(buf + n, iov[i].iov_base, iov[i].iov_len);
		n += iov[i].iov_len;
	}
	lock_get(&c->write_lock);
	n = tls_blocking_write(c, fd, buf, n, &tls_mgm_api);
#endif /* TLS_DONT_WRITE_FRAGMENTS */

end:
	lock_release(&c->write_lock);
	return ret;
}
