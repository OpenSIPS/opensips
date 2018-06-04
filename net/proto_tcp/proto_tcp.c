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
		char* buf, unsigned int len, union sockaddr_union* to, int id);
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

static int tcp_write_async_req(struct tcp_connection* con,int fd);
static int tcp_read_req(struct tcp_connection* con, int* bytes_read);
static int tcp_conn_init(struct tcp_connection* c);
static void tcp_conn_clean(struct tcp_connection* c);
static void tcp_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra);
static struct mi_root* tcp_trace_mi(struct mi_root* cmd, void* param );

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



struct tcp_send_chunk {
	char *buf; /* buffer that needs to be sent out */
	char *pos; /* the position that we should be writing next */
	int len;   /* length of the buffer */
	int ticks; /* time at which this chunk was initially
				  attempted to be written */
};

struct tcp_data {
	/* the chunks that need to be written on this
	 * connection when it will become writable */
	struct tcp_send_chunk **async_chunks;
	/* the total number of chunks pending to be written */
	int async_chunks_no;
	/* the oldest chunk in our write list */
	int oldest_chunk;
};


static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_tcp_init, 0, 0, 0, 0},
	{0,0,0,0,0,0}
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
	{ "tcp_trace", 0, tcp_trace_mi,   0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0}
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
	&deps,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
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
	pi->net.write			= (proto_net_write_f)tcp_write_async_req;
	pi->net.report			= tcp_report;

	if (tcp_async && !tcp_has_async_write()) {
		LM_WARN("TCP network layer does not have support for ASYNC write, "
			"disabling it for TCP plain\n");
		tcp_async = 0;
	}

	/* without async support, there is nothing to init/clean per conn */
	if (tcp_async!=0) {
		pi->net.conn_init	= tcp_conn_init;
		pi->net.conn_clean	= tcp_conn_clean;
	}

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
			get_script_route_ID_by_name( trace_filter_route, rlist, RT_NO);
	}

	return 0;
}


static int proto_tcp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}


static int tcp_conn_init(struct tcp_connection* c)
{
	struct tcp_data *d;

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct tcp_data*)shm_malloc( sizeof(*d) +
		sizeof(struct tcp_send_chunk *) * tcp_async_max_postponed_chunks );
	if (d==NULL) {
		LM_ERR("failed to create tcp chunks in shm mem\n");
		return -1;
	}

	d->async_chunks = (struct tcp_send_chunk **)(d+1);
	d->async_chunks_no = 0;
	d->oldest_chunk = 0;

	c->proto_data = (void*)d;

	return 0;
}


static void tcp_conn_clean(struct tcp_connection* c)
{
	struct tcp_data *d = (struct tcp_data*)c->proto_data;
	int r;

	for (r=0;r<d->async_chunks_no;r++) {
		shm_free(d->async_chunks[r]);
	}

	shm_free(d);

	c->proto_data = NULL;
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


/**************  CONNECT related functions ***************/

/* returns :
 * 0  - in case of success
 * -1 - in case there was an internal error
 * -2 - in case our chunks buffer is full
 *		and we need to let the connection go
 */
static inline int add_write_chunk(struct tcp_connection *con,char *buf,int len,
					int lock)
{
	struct tcp_send_chunk *c;
	struct tcp_data *d = (struct tcp_data*)con->proto_data;

	c = shm_malloc(sizeof(struct tcp_send_chunk) + len);
	if (!c) {
		LM_ERR("No more SHM\n");
		return -1;
	}

	c->len = len;
	c->ticks = get_ticks();
	c->buf = (char *)(c+1);
	memcpy(c->buf,buf,len);
	c->pos = c->buf;

	if (lock)
		lock_get(&con->write_lock);

	if (d->async_chunks_no == tcp_async_max_postponed_chunks) {
		LM_ERR("We have reached the limit of max async postponed chunks\n");
		if (lock)
			lock_release(&con->write_lock);
		shm_free(c);
		return -2;
	}

	d->async_chunks[d->async_chunks_no++] = c;
	if (d->async_chunks_no == 1)
		d->oldest_chunk = c->ticks;

	if (lock)
		lock_release(&con->write_lock);

	return 0;
}


/* Attempts do a connect to the given destination. It returns:
 *   1 - connect was done local (completed)
 *   0 - connect launched as async (in progress)
 *  -1 - error
 */
static int tcpconn_async_connect(struct socket_info* send_sock,
					union sockaddr_union* server, char *buf, unsigned len,
					struct tcp_connection** c, int *ret_fd)
{
	int fd, n;
	union sockaddr_union my_name;
	socklen_t my_name_len;
	struct tcp_connection* con;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout;
#else
	struct pollfd pf;
#endif
	unsigned int elapsed,to;
	int err;
	unsigned int err_len;
	int poll_err;
	char *ip;
	unsigned short port;
	struct timeval begin;

	/* create the socket */
	fd=socket(AF2PF(server->s.sa_family), SOCK_STREAM, 0);
	if (fd==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		return -1;
	}
	if (tcp_init_sock_opt(fd)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}
	my_name_len = sockaddru_len(send_sock->su);
	memcpy( &my_name, &send_sock->su, my_name_len);
	su_setport( &my_name, 0);
	if (bind(fd, &my_name.s, my_name_len )!=0) {
		LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
		goto error;
	}

	/* attempt to do connect and see if we do block or not */
	poll_err=0;
	elapsed = 0;
	to = tcp_async_local_connect_timeout*1000;

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}

again:
	n=connect(fd, &server->s, sockaddru_len(*server));
	if (n==-1) {
		if (errno==EINTR){
			elapsed=get_time_diff(&begin);
			if (elapsed<to) goto again;
			else {
				LM_DBG("Local connect attempt failed \n");
				goto async_connect;
			}
		}
		if (errno!=EINPROGRESS && errno!=EALREADY){
			get_su_info(&server->s, ip, port);
			LM_ERR("[server=%s:%d] (%d) %s\n",ip, port, errno,strerror(errno));
			goto error;
		}
	} else goto local_connect;

	/* let's poll for a little */
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	FD_ZERO(&orig_set);
	FD_SET(fd, &orig_set);
#else
	pf.fd=fd;
	pf.events=POLLOUT;
#endif

	while(1){
		elapsed=get_time_diff(&begin);
		if (elapsed<to)
			to-=elapsed;
		else {
			LM_DBG("Polling is overdue \n");
			goto async_connect;
		}
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		sel_set=orig_set;
		timeout.tv_sec=to/1000000;
		timeout.tv_usec=to%1000000;
		n=select(fd+1, 0, &sel_set, 0, &timeout);
#else
		n=poll(&pf, 1, to/1000);
#endif
		if (n<0){
			if (errno==EINTR) continue;
			get_su_info(&server->s, ip, port);
			LM_ERR("poll/select failed:[server=%s:%d] (%d) %s\n",
				ip, port, errno, strerror(errno));
			goto error;
		}else if (n==0) /* timeout */ continue;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		if (FD_ISSET(fd, &sel_set))
#else
		if (pf.revents&(POLLERR|POLLHUP|POLLNVAL)){
			LM_ERR("poll error: flags %x\n", pf.revents);
			poll_err=1;
		}
#endif
		{
			err_len=sizeof(err);
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if ((err==0) && (poll_err==0)) goto local_connect;
			if (err!=EINPROGRESS && err!=EALREADY){
				get_su_info(&server->s, ip, port);
				LM_ERR("failed to retrieve SO_ERROR [server=%s:%d] (%d) %s\n",
					ip, port, err, strerror(err));
				goto error;
			}
		}
	}

async_connect:
	LM_DBG("Create connection for async connect\n");
	/* create a new dummy connection */
	con=tcp_conn_create(fd, server, send_sock, S_CONN_CONNECTING);
	if (con==NULL) {
		LM_ERR("tcp_conn_create failed\n");
		goto error;
	}
	/* attach the write buffer to it */
	lock_get(&con->write_lock);
	if (add_write_chunk(con,buf,len,0) < 0) {
		LM_ERR("Failed to add the initial write chunk\n");
		/* FIXME - seems no more SHM now ...
		 * continue the async connect process ? */
	}
	lock_release(&con->write_lock);
	/* report an async, in progress connect */
	*c = con;
	return 0;

local_connect:
	con=tcp_conn_create(fd, server, send_sock, S_CONN_OK);
	if (con==NULL) {
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	*c = con;
	*ret_fd = fd;
	/* report a local connect */
	return 1;

error:
	close(fd);
	*c = NULL;
	return -1;
}


static struct tcp_connection* tcp_sync_connect(struct socket_info* send_sock,
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




/**************  WRITE related functions ***************/

/* called under the TCP connection write lock, timeout is in milliseconds */
static int async_tsend_stream(struct tcp_connection *c,
		int fd, char* buf, unsigned int len, int timeout)
{
	int written;
	int n;
	struct pollfd pf;

	pf.fd=fd;
	pf.events=POLLOUT;
	written=0;

again:
	n=send(fd, buf, len,
#ifdef HAVE_MSG_NOSIGNAL
			MSG_NOSIGNAL
#else
			0
#endif
		);

	if (n<0){
		if (errno==EINTR) goto again;
		else if (errno!=EAGAIN && errno!=EWOULDBLOCK) {
			LM_ERR("Failed first TCP async send : (%d) %s\n",
					errno, strerror(errno));
			return -1;
		} else
			goto poll_loop;
	}

	written+=n;
	if (n<len) {
		/* partial write */
		buf+=n;
		len-=n;
	} else {
		/* successful write from the first try */
		LM_DBG("Async successful write from first try on %p\n",c);
		return len;
	}

poll_loop:
	n=poll(&pf,1,timeout);
	if (n<0) {
		if (errno==EINTR)
			goto poll_loop;
		LM_ERR("Polling while trying to async send failed %s [%d]\n",
				strerror(errno), errno);
		return -1;
	} else if (n==0) {
		LM_DBG("timeout -> do an async write (add it to conn)\n");
		/* timeout - let's just pass to main */
		if (add_write_chunk(c,buf,len,0) < 0) {
			LM_ERR("Failed to add write chunk to connection \n");
			return -1;
		} else {
			/* we have successfully added async write chunk
			 * tell MAIN to poll out for us */
			LM_DBG("Data still pending for write on conn %p\n",c);
			return 0;
		}
	}

	if (pf.revents&POLLOUT)
		goto again;

	/* some other events triggered by poll - treat as errors */
	return -1;
}


/* This is just a wrapper around the writing function, so we can use them
 * internally, but also export them to the "tcp_common" funcs */
inline static int _tcp_write_on_socket(struct tcp_connection *c, int fd,
															char *buf, int len)
{
	int n;

	lock_get(&c->write_lock);
	if (tcp_async) {
		/*
		 * if there is any data pending to write, we have to wait for those chunks
		 * to be sent, otherwise we will completely break the messages' order
		 */
		if (((struct tcp_data*)c->proto_data)->async_chunks_no)
			return add_write_chunk(c, buf, len, 0);
		n=async_tsend_stream(c,fd,buf,len,tcp_async_local_write_timeout);
	} else {
		n=tsend_stream(fd, buf, len, tcp_send_timeout);
	}
	lock_release(&c->write_lock);

	return n;
}


/*! \brief Finds a tcpconn & sends on it */
static int proto_tcp_send(struct socket_info* send_sock,
											char* buf, unsigned int len,
											union sockaddr_union* to, int id)
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
		n = tcp_conn_get(id, &ip, port, PROTO_TCP, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, &c, &fd);
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
		LM_DBG("no open tcp connection found, opening new one, async = %d\n",tcp_async);
		/* create tcp connection */
		if (tcp_async) {
			n = tcpconn_async_connect(send_sock, to, buf, len, &c, &fd);
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
				/* trace the message */
				if ( TRACE_ON( c->flags ) &&
						check_trace_route( trace_filter_route_id, c) ) {
					if ( tcpconn2su( c, &src_su, &dst_su) < 0 ) {
						LM_ERR("can't create su structures for tracing!\n");
					} else {
						trace_message_atonce( PROTO_TCP, c->cid, &src_su, &dst_su,
							TRANS_TRACE_CONNECT_START, TRANS_TRACE_SUCCESS,
							&AS_CONNECT_INIT, t_dst );
					}
				}

				/* mark the ID of the used connection (tracing purposes) */
				last_outgoing_tcp_id = c->id;

				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when
				 * connect will be completed */
				LM_DBG("Successfully started async connection \n");
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
			if ((c=tcp_sync_connect(send_sock, to, &fd))==0) {
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
			n = add_write_chunk(c,buf,len,1);
			if (n < 0) {
				LM_ERR("Failed to add another write chunk to %p\n",c);
				/* we failed due to internal errors - put the
				 * connection back */
				tcp_conn_release(c, 0);
				return -1;
			}

			/* mark the ID of the used connection (tracing purposes) */
			last_outgoing_tcp_id = c->id;

			/* we successfully added our write chunk - success */
			tcp_conn_release(c, 0);
			return len;
		} else {
			/* return error, nothing to do about it */
			tcp_conn_release(c, 0);
			return -1;
		}
	}


send_it:
	LM_DBG("sending via fd %d...\n",fd);

	start_expire_timer(snd,tcpthreshold);

	n = _tcp_write_on_socket(c, fd, buf, len);

	get_time_difference(snd,tcpthreshold,tcp_timeout_send);
	stop_expire_timer(get,tcpthreshold,"tcp ops",buf,(int)len,1);

	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n=%d fd=%d\n",c, n, fd);
	/* LM_DBG("buf=\n%.*s\n", (int)len, buf); */
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

	tcp_conn_release(c, (n<len)?1:0/*pending data in async mode?*/ );
	return n;
}


/* Responsible for writing the TCP send chunks - called under con write lock
 *	* if returns = 1 : the connection will be released for more writting
 *	* if returns = 0 : the connection will be released
 *	* if returns < 0 : the connection will be released as BAD /  broken
 */
static int tcp_write_async_req(struct tcp_connection* con,int fd)
{
	int n,left;
	struct tcp_send_chunk *chunk;
	struct tcp_data *d = (struct tcp_data*)con->proto_data;

	if (d->async_chunks_no == 0) {
		LM_DBG("The connection has been triggered "
		" for a write event - but we have no pending write chunks\n");
		return 0;
	}

next_chunk:
	chunk=d->async_chunks[0];
again:
	left = (int)((chunk->buf+chunk->len)-chunk->pos);
	LM_DBG("Trying to send %d bytes from chunk %p in conn %p - %d %d \n",
		   left,chunk,con,chunk->ticks,get_ticks());
	n=send(fd, chunk->pos, left,
#ifdef HAVE_MSG_NOSIGNAL
			MSG_NOSIGNAL
#else
			0
#endif
	);

	if (n<0) {
		if (errno==EINTR)
			goto again;
		else if (errno==EAGAIN || errno==EWOULDBLOCK) {
			LM_DBG("Can't finish to write chunk %p on conn %p\n",
				   chunk,con);
			/* report back we have more writting to be done */
			return 1;
		} else {
			LM_ERR("Error occurred while sending async chunk %d (%s)\n",
				   errno,strerror(errno));
			/* report the conn as broken */
			return -1;
		}
	}

	if (n < left) {
		/* partial write */
		chunk->pos+=n;
		goto again;
	} else {
		/* written a full chunk - move to the next one, if any */
		shm_free(chunk);
		d->async_chunks_no--;
		if (d->async_chunks_no == 0) {
			LM_DBG("We have finished writing all our async chunks in %p\n",con);
			d->oldest_chunk=0;
			/*  report back everything ok */
			return 0;
		} else {
			LM_DBG("We still have %d chunks pending on %p\n",
					d->async_chunks_no,con);
			memmove(&d->async_chunks[0],&d->async_chunks[1],
					d->async_chunks_no * sizeof(struct tcp_send_chunk*));
			d->oldest_chunk = d->async_chunks[0]->ticks;
			goto next_chunk;
		}
	}
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


static struct mi_root* tcp_trace_mi(struct mi_root* cmd_tree, void* param )
{
	struct mi_node* node;

	struct mi_node *rpl;
	struct mi_root *rpl_tree ;

	node = cmd_tree->node.kids;
	if(node == NULL) {
		/* display status on or off */
		rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
		if (rpl_tree == 0)
			return 0;
		rpl = &rpl_tree->node;

		if ( *trace_is_on ) {
			node = add_mi_node_child(rpl,0,MI_SSTR("TCP tracing"),MI_SSTR("on"));
		} else {
			node = add_mi_node_child(rpl,0,MI_SSTR("TCP tracing"),MI_SSTR("off"));
		}

		return rpl_tree ;
	} else if ( node && !node->next ) {
		if ( (node->value.s[0] | 0x20) == 'o' &&
				(node->value.s[1] | 0x20) == 'n' ) {
			*trace_is_on = 1;
			return init_mi_tree( 200, MI_SSTR(MI_OK));
		} else
		if ( (node->value.s[0] | 0x20) == 'o' &&
				(node->value.s[1] | 0x20) == 'f' &&
				(node->value.s[2] | 0x20) == 'f' ) {
			*trace_is_on = 0;
			return init_mi_tree( 200, MI_SSTR(MI_OK));
		} else {
			return init_mi_tree( 500, MI_SSTR(MI_INTERNAL_ERR));
		}
	} else {
		return init_mi_tree( 500, MI_SSTR(MI_INTERNAL_ERR));
	}

	return NULL;
}
