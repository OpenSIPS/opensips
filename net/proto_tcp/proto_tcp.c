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
 *  2015-01-09  first version (razvanc)
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../net/trans_trace.h"
#include "../../net/tcp_common.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../trace_api.h"

#include "tcp_common_defs.h"
#include "proto_tcp_handler.h"

#define F_TCP_CONN_TRACED ( 1 << 0 )
#define TRACE_ON(flags) (t_dst && (*trace_is_on) && \
						!(flags & F_CONN_TRACE_DROPPED))

static int mod_init(void);
static int proto_tcp_init(struct proto_info *pi);
static int proto_tcp_init_listener(struct socket_info *si);
static int proto_tcp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id);
inline static int _tcp_write_on_socket(struct tcp_connection *c, int fd,
		char *buf, int len);

/* buffer to be used for reading all TCP SIP messages
   detached from the actual con - in order to improve
   paralelism ( process the SIP message while the con
   can be sent back to main to do more stuff */
static struct tcp_req tcp_current_req;

#define _tcp_common_write _tcp_write_on_socket
#define _tcp_common_current_req tcp_current_req
#include "tcp_common.h"

static int tcp_read_req(struct tcp_connection* con, int* bytes_read);
static void tcp_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);
static mi_response_t *w_tcp_trace_mi(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *w_tcp_trace_mi_1(const mi_params_t *params,
								struct mi_handler *async_hdl);

#define TRACE_PROTO "proto_hep"

static str trace_destination_name = {NULL, 0};
trace_dest t_dst;
trace_proto_t tprot;

/* module  tracing parameters */
static int trace_is_on_tmp=0, *trace_is_on;
static char* trace_filter_route;
static int trace_filter_route_id = -1;
/**/

extern int unix_tcp_sock;

/* default port for TCP protocol */
static int tcp_port = SIP_PORT;

/* in milliseconds */
static int tcp_send_timeout = 100;

/* 1 if TCP connect & write should be async */
static int tcp_async = 1;

/* Number of milliseconds that a worker will block waiting for a local
 * connect - if connect op exceeds this, it will get passed to TCP main*/
static int tcp_async_local_connect_timeout = 100;

/* Number of milliseconds that a worker will block waiting for a local
 * write - if write op exceeds this, it will get passed to TCP main*/
static int tcp_async_local_write_timeout = 10;

/* maximum number of write chunks that will be queued per TCP connection -
  if we exceed this number, we just drop the connection */
static int tcp_async_max_postponed_chunks = 32;

static int tcp_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;

/* 0: send CRLF pong to incoming CRLFCRLF ping */
static int tcp_crlf_pingpong = 1;

/* 0: do not drop single CRLF messages */
static int tcp_crlf_drop = 0;


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_tcp_init, {{0, 0, 0}}, 0},
	{0,0,{{0,0,0}},0}
};


static param_export_t params[] = {
	{ "tcp_port",                        INT_PARAM, &tcp_port               },
	{ "tcp_send_timeout",                INT_PARAM, &tcp_send_timeout       },
	{ "tcp_max_msg_chunks",              INT_PARAM, &tcp_max_msg_chunks     },
	{ "tcp_crlf_pingpong",               INT_PARAM, &tcp_crlf_pingpong      },
	{ "tcp_crlf_drop",                   INT_PARAM, &tcp_crlf_drop          },
	{ "tcp_async",                       INT_PARAM, &tcp_async              },
	{ "tcp_async_max_postponed_chunks",  INT_PARAM,
											&tcp_async_max_postponed_chunks },
	{ "tcp_async_local_connect_timeout", INT_PARAM,
											&tcp_async_local_connect_timeout},
	{ "tcp_async_local_write_timeout",   INT_PARAM,
											&tcp_async_local_write_timeout  },
	{ "trace_destination",               STR_PARAM, &trace_destination_name.s},
	{ "trace_on",						 INT_PARAM, &trace_is_on_tmp        },
	{ "trace_filter_route",				 STR_PARAM, &trace_filter_route     },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "tcp_trace", 0, 0, 0, {
		{w_tcp_trace_mi, {0}},
		{w_tcp_trace_mi_1, {"trace_mode", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};

/* module dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "proto_hep", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 }
	},
	{ /* modparam dependencies */
		{ NULL, NULL}
	}
};

struct module_exports proto_tcp_exports = {
	PROTO_PREFIX "tcp",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,          /* exported MI functions */
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

static int proto_tcp_init(struct proto_info *pi)
{
	pi->id					= PROTO_TCP;
	pi->name				= "tcp";
	pi->default_port		= tcp_port;

	pi->tran.init_listener	= proto_tcp_init_listener;
	pi->tran.send			= proto_tcp_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)tcp_read_req;
	pi->net.write			= (proto_net_write_f)tcp_async_write;
	pi->net.report			= tcp_report;

	if (tcp_async && !tcp_has_async_write()) {
		LM_WARN("TCP network layer does not have support for ASYNC write, "
			"disabling it for TCP plain\n");
		tcp_async = 0;
	}

	/* without async support, there is nothing to init/clean per conn */
	if (tcp_async!=0)
		pi->net.async_chunks= tcp_async_max_postponed_chunks;

	return 0;
}


static int mod_init(void)
{
	LM_INFO("initializing TCP-plain protocol\n");
	if (trace_destination_name.s) {
		if ( !net_trace_api ) {
			if ( trace_prot_bind( TRACE_PROTO, &tprot) < 0 ) {
				LM_ERR( "can't bind trace protocol <%s>\n", TRACE_PROTO );
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
			get_script_route_ID_by_name( trace_filter_route, sroutes->request,
				RT_NO);
	}

	return 0;
}


static int proto_tcp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}


/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also r->error
 */
int proto_tcp_read(struct tcp_connection *c,struct tcp_req *r)
{
	int bytes_free, bytes_read;
	int fd;

	fd=c->fd;
	bytes_free=TCP_BUF_SIZE- (int)(r->pos - r->buf);

	if (bytes_free==0){
		LM_ERR("buffer overrun, dropping\n");
		r->error=TCP_REQ_OVERRUN;
		return -1;
	}
again:
	bytes_read=read(fd, r->pos, bytes_free);

	if(bytes_read==-1){
		if (errno == EWOULDBLOCK || errno == EAGAIN){
			return 0; /* nothing has been read */
		} else if (errno == EINTR) {
			goto again;
		} else if (errno == ECONNRESET) {
			c->state=S_CONN_EOF;
			LM_DBG("CONN RESET on %p, FD %d\n", c, fd);
			bytes_read = 0;
		} else {
			LM_ERR("error reading: %s\n",strerror(errno));
			r->error=TCP_READ_ERROR;
			return -1;
		}
	}else if (bytes_read==0){
		c->state=S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
	}
#ifdef EXTRA_DEBUG
	LM_DBG("read %d bytes:\n%.*s\n", bytes_read, bytes_read, r->pos);
#endif
	r->pos+=bytes_read;
	return bytes_read;
}


static void tcp_report(int type, unsigned long long conn_id, int conn_flags,
																void *extra)
{
	str s;

	if (type==TCP_REPORT_CLOSE) {
		/* grab reason text */
		if (extra) {
			s.s = (char*)extra;
			s.len = strlen (s.s);
		}

		if ( TRACE_ON( conn_flags ) ) {
			trace_message_atonce( PROTO_TCP, conn_id, NULL/*src*/, NULL/*dst*/,
				TRANS_TRACE_CLOSED, TRANS_TRACE_SUCCESS, extra?&s:NULL, t_dst );
		}
	}

	return;
}


/**************  WRITE related functions ***************/
/* This is just a wrapper around the writing function, so we can use them
 * internally, but also export them to the "tcp_common" funcs */
inline static int _tcp_write_on_socket(struct tcp_connection *c, int fd,
															char *buf, int len)
{
	return tcp_write_on_socket(c, fd, buf, len,
			tcp_send_timeout, tcp_async_local_write_timeout);
}


/*! \brief Finds a tcpconn & sends on it */
static int proto_tcp_send(struct socket_info* send_sock,
									char* buf, unsigned int len,
									union sockaddr_union* to, unsigned int id)
{
	struct tcp_connection *c;
	struct ip_addr ip;
	int port;
	struct timeval get,snd;
	int fd, n;

	union sockaddr_union src_su, dst_su;

	port=0;

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get,tcpthreshold);

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, PROTO_TCP, NULL, &c, &fd, send_sock);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd, NULL);
	}else{
		LM_CRIT("tcp_send called with null id & to\n");
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
			LM_ERR("Unknown destination - cannot open new tcp connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one, async = %d\n",
			tcp_async);
		/* create tcp connection */
		if (tcp_async) {
			n = tcp_async_connect(send_sock, to,
					tcp_async_local_connect_timeout, &c, &fd, 1);
			if ( n<0 ) {
				LM_ERR("async TCP connect failed\n");
				get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
				return -1;
			}
			/* connect succeeded, we have a connection */
			LM_DBG( "Successfully connected from interface %s:%d to %s:%d!\n",
				ip_addr2a( &c->rcv.src_ip ), c->rcv.src_port,
				ip_addr2a( &c->rcv.dst_ip ), c->rcv.dst_port );

			if (n==0) {
				/* attach the write buffer to it */
				if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
					LM_ERR("Failed to add the initial write chunk\n");
					len = -1; /* report an error - let the caller decide what to do */
				}

				/* trace the message */
				if ( TRACE_ON( c->flags ) &&
						check_trace_route( trace_filter_route_id, c) ) {
					if ( tcpconn2su( c, &src_su, &dst_su) < 0 ) {
						LM_ERR("can't create su structures for tracing!\n");
					} else {
						trace_message_atonce( PROTO_TCP, c->cid,
							&src_su, &dst_su,
							TRANS_TRACE_CONNECT_START, TRANS_TRACE_SUCCESS,
							&AS_CONNECT_INIT, t_dst );
					}
				}

				/* mark the ID of the used connection (tracing purposes) */
				last_outgoing_tcp_id = c->id;
				send_sock->last_local_real_port = c->rcv.dst_port;
				send_sock->last_remote_real_port = c->rcv.src_port;

				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when
				 * connect will be completed */
				LM_DBG("Successfully started async connection \n");
				sh_log(c->hist, TCP_SEND2MAIN, "send 1, (%d)", c->refcnt);
				tcp_conn_release(c, 0);
				return len;
			}

			LM_DBG("First connect attempt succeeded in less than %d ms, "
				"proceed to writing \n",tcp_async_local_connect_timeout);
			/* our first connect attempt succeeded - go ahead as normal */
			/* trace the attempt */
			if (  TRACE_ON( c->flags ) &&
					check_trace_route( trace_filter_route_id, c) ) {
				c->proto_flags |= F_TCP_CONN_TRACED;
				if ( tcpconn2su( c, &src_su, &dst_su) < 0 ) {
					LM_ERR("can't create su structures for tracing!\n");
				} else {
					trace_message_atonce( PROTO_TCP, c->cid, &src_su, &dst_su,
						TRANS_TRACE_CONNECTED, TRANS_TRACE_SUCCESS,
						&ASYNC_CONNECT_OK, t_dst );
				}
			}
		} else {
			if ((c=tcp_sync_connect(send_sock, to, &fd, 1))==0) {
				LM_ERR("connect failed\n");
				get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
				return -1;
			}

			if ( TRACE_ON( c->flags ) &&
					check_trace_route( trace_filter_route_id, c) ) {
				c->proto_flags |= F_TCP_CONN_TRACED;
				if ( tcpconn2su( c, &src_su, &dst_su) < 0 ) {
					LM_ERR("can't create su structures for tracing!\n");
				} else {
					trace_message_atonce( PROTO_TCP, c->cid, &src_su, &dst_su,
						TRANS_TRACE_CONNECTED, TRANS_TRACE_SUCCESS,
						&CONNECT_OK, t_dst );
				}
			}

			LM_DBG( "Successfully connected from interface %s:%d to %s:%d!\n",
				ip_addr2a( &c->rcv.src_ip ), c->rcv.src_port,
				ip_addr2a( &c->rcv.dst_ip ), c->rcv.dst_port );
		}

		goto send_it;
	}

	if ( !(c->proto_flags & F_TCP_CONN_TRACED) ) {
		/* most probably it's an async connect */
		if ( TRACE_ON( c->flags ) ) {
			trace_message_atonce( PROTO_TCP, c->cid, 0, 0,
				TRANS_TRACE_CONNECTED, TRANS_TRACE_SUCCESS,
				&CONNECT_OK, t_dst );
		}

		c->proto_flags |= F_TCP_CONN_TRACED;
	}

	get_time_difference(get,tcpthreshold,tcp_timeout_con_get);

	/* now we have a connection, let's see what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd==-1) {
		/* connection is not writable because of its state - can we append
		 * data to it for later writting (async writting)? */
		if (c->state==S_CONN_CONNECTING) {
			/* the connection is currently in the process of getting
			 * connected - let's append our send chunk as well - just in
			 * case we ever manage to get through */
			LM_DBG("We have acquired a TCP connection which is still "
				"pending to connect - delaying write \n");
			n = tcp_async_add_chunk(c,buf,len,1);
			if (n < 0) {
				LM_ERR("Failed to add another write chunk to %p\n",c);
				/* we failed due to internal errors - put the
				 * connection back */
				sh_log(c->hist, TCP_SEND2MAIN, "send 2, (%d)", c->refcnt);
				tcp_conn_release(c, 0);
				return -1;
			}

			/* mark the ID of the used connection (tracing purposes) */
			last_outgoing_tcp_id = c->id;
			send_sock->last_local_real_port = c->rcv.dst_port;
			send_sock->last_remote_real_port = c->rcv.src_port;

			/* we successfully added our write chunk - success */
			sh_log(c->hist, TCP_SEND2MAIN, "send 3, (%d)", c->refcnt);
			tcp_conn_release(c, 0);
			return len;
		} else {
			/* return error, nothing to do about it */
			sh_log(c->hist, TCP_SEND2MAIN, "send 4, (%d)", c->refcnt);
			tcp_conn_release(c, 0);
			return -1;
		}
	}


send_it:
	LM_DBG("sending via fd %d...\n",fd);

	start_expire_timer(snd,tcpthreshold);

	n = tcp_write_on_socket(c, fd, buf, len,
			tcp_send_timeout, tcp_async_local_write_timeout);

	get_time_difference(snd,tcpthreshold,tcp_timeout_send);
	stop_expire_timer(get,tcpthreshold,"tcp ops",buf,(int)len,1);

	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n/len=%d/%d fd=%d\n",c, n, len, fd);
	/* LM_DBG("buf=\n%.*s\n", (int)len, buf); */
	if (n<0){
		LM_ERR("failed to send\n");
		c->state=S_CONN_BAD;
		if (c->proc_id != process_no)
			close(fd);

		sh_log(c->hist, TCP_SEND2MAIN, "send 5, (%d)", c->refcnt);
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

	sh_log(c->hist, TCP_SEND2MAIN, "send 6, (%d, async: %d)", c->refcnt, n < len);
	tcp_conn_release(c, (n<len)?1:0/*pending data in async mode?*/ );
	return n;
}



/**************  READ related functions ***************/

/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also r->error
 */
int tcp_read(struct tcp_connection *c,struct tcp_req *r)
{
	int bytes_free, bytes_read;
	int fd;

	fd=c->fd;
	bytes_free=TCP_BUF_SIZE- (int)(r->pos - r->buf);

	if (bytes_free==0){
		LM_ERR("buffer overrun, dropping\n");
		r->error=TCP_REQ_OVERRUN;
		return -1;
	}
again:
	bytes_read=read(fd, r->pos, bytes_free);

	if(bytes_read==-1){
		if (errno == EWOULDBLOCK || errno == EAGAIN){
			return 0; /* nothing has been read */
		} else if (errno == EINTR) {
			goto again;
		} else if (errno == ECONNRESET) {
			c->state=S_CONN_EOF;
			LM_DBG("CONN RESET on %p, FD %d\n", c, fd);
			bytes_read = 0;
		} else {
			LM_ERR("error reading: %s\n",strerror(errno));
			r->error=TCP_READ_ERROR;
			return -1;
		}
	}else if (bytes_read==0){
		c->state=S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
	}
#ifdef EXTRA_DEBUG
	LM_DBG("read %d bytes:\n%.*s\n", bytes_read, bytes_read, r->pos);
#endif
	r->pos+=bytes_read;
	return bytes_read;
}


/* Responsible for reading the request
 *	* if returns >= 0 : the connection will be released
 *	* if returns <  0 : the connection will be released as BAD / broken
 */
static int tcp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	struct tcp_req* req;

	union sockaddr_union src_su, dst_su;

	if ( !(con->proto_flags & F_TCP_CONN_TRACED)) {
		con->proto_flags |= F_TCP_CONN_TRACED;

		LM_DBG("Accepted connection from %s:%d on interface %s:%d!\n",
			ip_addr2a( &con->rcv.src_ip ), con->rcv.src_port,
			ip_addr2a( &con->rcv.dst_ip ), con->rcv.dst_port );

		if ( TRACE_ON( con->flags ) &&
					check_trace_route( trace_filter_route_id, con) ) {
			if ( tcpconn2su( con, &src_su, &dst_su) < 0 ) {
				LM_ERR("can't create su structures for tracing!\n");
			} else {
				trace_message_atonce( PROTO_TCP, con->cid, &src_su, &dst_su,
					TRANS_TRACE_ACCEPTED, TRANS_TRACE_SUCCESS,
					&ACCEPT_OK, t_dst );
			}
		}
	}

	bytes=-1;
	total_bytes=0;

	if (con->con_req) {
		req=con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&tcp_current_req, 0);
		req=&tcp_current_req;
	}

again:
	if(req->error==TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed<req->pos){
			bytes=0;
		}else{
			bytes=tcp_read(con,req);
			if (bytes<0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		tcp_parse_headers(req, tcp_crlf_pingpong, tcp_crlf_drop);
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

	switch (tcp_handle_req(req, con, tcp_max_msg_chunks) ) {
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

static mi_response_t *w_tcp_trace_mi(const mi_params_t *mi_params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("TCP tracing"), "%s",
		*trace_is_on ? "on" : "off") < 0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}

static mi_response_t *w_tcp_trace_mi_1(const mi_params_t *mi_params,
								struct mi_handler *async_hdl)
{
	str new_mode;

	if (get_mi_string_param(mi_params, "trace_mode", &new_mode.s, &new_mode.len) < 0)
		return init_mi_param_error();

	if ((new_mode.s[0] | 0x20) == 'o' &&
		(new_mode.s[1] | 0x20) == 'n' ) {
		*trace_is_on = 1;
		return init_mi_result_ok();
	} else if ((new_mode.s[0] | 0x20) == 'o' &&
			  (new_mode.s[1] | 0x20) == 'f' &&
			  (new_mode.s[2] | 0x20) == 'f') {
		*trace_is_on = 0;
		return init_mi_result_ok();
	} else {
		return init_mi_error_extra(JSONRPC_INVAL_PARAMS_CODE,
			MI_SSTR(JSONRPC_INVAL_PARAMS_MSG),
			MI_SSTR("trace_mode should be 'on' or 'off'"));
	}
}
