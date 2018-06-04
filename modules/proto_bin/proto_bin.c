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
#include <poll.h>
#include <errno.h>
 #include <unistd.h>
#include <netinet/tcp.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../bin_interface.h"
#include "proto_bin.h"
#include "../../ut.h"


static int mod_init(void);
static int proto_bin_init(struct proto_info *pi);
static int proto_bin_init_listener(struct socket_info *si);
static int proto_bin_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id);
static int bin_read_req(struct tcp_connection* con, int* bytes_read);
static int bin_write_async_req(struct tcp_connection* con,int fd);
static int bin_conn_init(struct tcp_connection* c);
static void bin_conn_clean(struct tcp_connection* c);


static int bin_port = 5555;
static int bin_send_timeout = 100;
static struct tcp_req bin_current_req;
static int bin_max_msg_chunks = 32;
static int bin_async = 1;
static int bin_async_max_postponed_chunks = 32;
static int bin_async_local_connect_timeout = 100;
static int bin_async_local_write_timeout = 10;

struct bin_send_chunk {
	char *buf; /* buffer that needs to be sent out */
	char *pos; /* the position that we should be writing next */
	int len;   /* length of the buffer */
	int ticks; /* time at which this chunk was initially
				  attempted to be written */
};

struct bin_data {
	/* the chunks that need to be written on this
	 * connection when it will become writable */
	struct bin_send_chunk **async_chunks;
	/* the total number of chunks pending to be written */
	int async_chunks_no;
	/* the oldest chunk in our write list */
	int oldest_chunk;
};

static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_bin_init, 0, 0, 0, 0},
	{0,0,0,0,0,0}
};

static param_export_t params[] = {
	{ "bin_port",                        INT_PARAM, &bin_port               },
	{ "bin_send_timeout",                INT_PARAM, &bin_send_timeout       },
	{ "bin_max_msg_chunks",              INT_PARAM, &bin_max_msg_chunks     },
	{ "bin_async",                       INT_PARAM, &bin_async              },
	{ "bin_async_max_postponed_chunks",  INT_PARAM,
											&bin_async_max_postponed_chunks },
	{ "bin_async_local_connect_timeout", INT_PARAM,
											&bin_async_local_connect_timeout},
	{ "bin_async_local_write_timeout",   INT_PARAM,
											&bin_async_local_write_timeout  },
	{0, 0, 0}
};

struct module_exports exports = {
	PROTO_PREFIX "bin",  /* module name*/
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

static int proto_bin_init(struct proto_info *pi)
{
	pi->id					= PROTO_BIN;
	pi->name				= "bin";
	pi->default_port		= bin_port;

	pi->tran.init_listener	= proto_bin_init_listener;
	pi->tran.send			= proto_bin_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)bin_read_req;
	pi->net.write			= (proto_net_write_f)bin_write_async_req;

	if (bin_async != 0) {
		pi->net.conn_init	= bin_conn_init;
		pi->net.conn_clean	= bin_conn_clean;
	}

	return 0;
}


static int mod_init(void)
{
	LM_INFO("initializing BIN protocol\n");

	return 0;
}


static int bin_conn_init(struct tcp_connection* c)
{
	struct bin_data *d;

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct bin_data*)shm_malloc( sizeof(struct bin_data) +
		sizeof(struct bin_send_chunk *) * bin_async_max_postponed_chunks );
	if (d == NULL) {
		LM_ERR("failed to create tcp chunks in shm mem\n");
		return -1;
	}

	d->async_chunks = (struct bin_send_chunk **)(d+1);
	d->async_chunks_no = 0;
	d->oldest_chunk = 0;

	c->proto_data = (void*)d;
	return 0;
}

static void bin_conn_clean(struct tcp_connection* c)
{
	struct bin_data *d = (struct bin_data*)c->proto_data;
	int r;

	for (r = 0; r < d->async_chunks_no; r++) {
		shm_free(d->async_chunks[r]);
	}

	shm_free(d);

	c->proto_data = NULL;
}

static int proto_bin_init_listener(struct socket_info *si)
{
	/* we do not do anything particular, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}





static int add_write_chunk(struct tcp_connection *con,char *buf,int len,
					int lock)
{
	struct bin_send_chunk *c;
	struct bin_data *d = (struct bin_data*)con->proto_data;

	c = shm_malloc(sizeof(struct bin_send_chunk) + len);
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

	if (d->async_chunks_no == bin_async_max_postponed_chunks) {
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
	n=send(fd, buf, len,0);

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
	if (n < len) {
		/* partial write */
		buf += n;
		len -= n;
	} else {
		/* successful write from the first try */
		LM_DBG("Async successful write from first try on %p\n",c);
		return len;
	}

poll_loop:
	n = poll(&pf,1,timeout);
	if (n<0) {
		if (errno==EINTR)
			goto poll_loop;
		LM_ERR("Polling while trying to async send failed %s [%d]\n",
				strerror(errno), errno);
		return -1;
	} else if (n == 0) {
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

static struct tcp_connection* bin_sync_connect(struct socket_info* send_sock,
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

static int tcpconn_async_connect(struct socket_info* send_sock,
					union sockaddr_union* server, char *buf, unsigned len,
					struct tcp_connection** c, int *ret_fd)
{
	int fd, n;
	union sockaddr_union my_name;
	socklen_t my_name_len;
	struct tcp_connection* con;

	struct pollfd pf;

	unsigned int elapsed,to;
	int err;
	unsigned int err_len;
	int poll_err;
	char *ip;
	unsigned short port;
	struct timeval begin;

	/* create the socket */
	fd = socket(AF2PF(server->s.sa_family), SOCK_STREAM, 0);
	if (fd == -1){
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
	poll_err = 0;
	elapsed = 0;
	to = bin_async_local_connect_timeout*1000;

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}

again:
	n = connect(fd, &server->s, sockaddru_len(*server));
	if (n == -1) {
		if (errno == EINTR){
			elapsed=get_time_diff(&begin);
			if (elapsed < to) goto again;
			else {
				LM_DBG("Local connect attempt failed \n");
				goto async_connect;
			}
		}
		if (errno != EINPROGRESS && errno!=EALREADY) {
			get_su_info(&server->s, ip, port);
			LM_ERR("[server=%s:%d] (%d) %s\n",ip, port, errno,strerror(errno));
			goto error;
		}
	} else goto local_connect;

	/* let's poll for a little */

	pf.fd = fd;
	pf.events = POLLOUT;

	while(1){
		elapsed = get_time_diff(&begin);
		if (elapsed < to)
			to -= elapsed;
		else {
			LM_DBG("Polling is overdue \n");
			goto async_connect;
		}

		n = poll(&pf, 1, to/1000);

		if (n < 0){
			if (errno == EINTR) continue;
			get_su_info(&server->s, ip, port);
			LM_ERR("poll/select failed:[server=%s:%d] (%d) %s\n",
				ip, port, errno, strerror(errno));
			goto error;
		} else if (n==0) /* timeout */ continue;

		if (pf.revents & (POLLERR|POLLHUP|POLLNVAL)){
			LM_ERR("poll error: flags %x\n", pf.revents);
			poll_err=1;
		}


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

async_connect:
	LM_DBG("Create connection for async connect\n");
	/* create a new dummy connection */
	con = tcp_conn_create(fd, server, send_sock, S_CONN_CONNECTING);
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
	con = tcp_conn_create(fd, server, send_sock, S_CONN_OK);
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

inline static int _bin_write_on_socket(struct tcp_connection *c, int fd,
												char *buf, int len){
	int n;

	lock_get(&c->write_lock);
	if (bin_async) {
		/*
		 * if there is any data pending to write, we have to wait for those chunks
		 * to be sent, otherwise we will completely break the messages' order
		 */
		if (((struct bin_data*)c->proto_data)->async_chunks_no)
			return add_write_chunk(c, buf, len, 0);
		n=async_tsend_stream(c,fd,buf,len, bin_async_local_write_timeout);
	} else {
		n = tsend_stream(fd, buf, len, bin_send_timeout);
	}
	lock_release(&c->write_lock);

	return n;
}

static int proto_bin_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id)
{
	struct tcp_connection *c;
	struct ip_addr ip;
	int port;
	int fd, n;

	port=0;

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, PROTO_BIN, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, &c, &fd);
	}else{
		LM_CRIT("tcp_send called with null id & to\n");
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
			LM_ERR("Unknown destination - cannot open new tcp connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one, async = %d\n",bin_async);
		/* create tcp connection */
		if (bin_async) {
			n = tcpconn_async_connect(send_sock, to, buf, len, &c, &fd);
			if ( n<0 ) {
				LM_ERR("async TCP connect failed\n");
				return -1;
			}
			/* connect succeeded, we have a connection */
			if (n==0) {
				/* mark the ID of the used connection (tracing purposes) */
				last_outgoing_tcp_id = c->id;
				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when 
				 * connect will be completed */
				LM_DBG("Successfully started async connection \n");
				tcp_conn_release(c, 0);
				return len;
			}
			/* our first connect attempt succeeded - go ahead as normal */
		} else if ((c=bin_sync_connect(send_sock, to, &fd))==0) {
			LM_ERR("connect failed\n");
			return -1;
		}
	
		goto send_it;
	}

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

	n = _bin_write_on_socket(c, fd, buf, len);

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

static int bin_handle_req(struct tcp_req *req,
							struct tcp_connection *con, int _max_msg_chunks)
{
	long size;

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
			if (req != &bin_current_req) {
				/* we have the buffer in the connection tied buff -
				 *	detach it , release the conn and free it afterwards */
				con->con_req = NULL;
			}
		} else {
			LM_DBG("We still have things on the pipe - "
				"keeping connection \n");
		}
		
		/* give the message to the registered functions */
		call_callbacks(req->buf, &con->rcv);


		if (!size && req != &bin_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			pkg_free(req);
		}

		if (size)
			memmove(req->buf, req->parsed, size);

		init_tcp_req(req, size);
		con->msg_attempts = 0;

		/* if we still have some unparsed bytes, try to  parse them too*/
		if (size) 
			return 1;
	} else {  
		/* request not complete - check the if the thresholds are exceeded */
		if (con->msg_attempts==0)
			/* if first iteration, set a short timeout for reading
			 * a whole SIP message */
			con->timeout = get_ticks() + tcp_max_msg_time;

		con->msg_attempts ++;
		if (con->msg_attempts == _max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}

		if (req == &bin_current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request\n");
			con->con_req = pkg_malloc(sizeof(struct tcp_req));
			if (con->con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				goto error;
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

	/* everything ok */
	return 0;
error:
	/* report error */
	return -1;
}

static void bin_parse_headers(struct tcp_req *req){
	unsigned int  *px;
	if(req->content_len == 0 && req->pos - req->buf < HEADER_SIZE){
		req->parsed = req->pos;
		return;
	}

	if (!is_valid_bin_packet(req->buf)) {
		LM_ERR("Invalid packet marker, got %.4s\n", req->buf);
		req->error = TCP_REQ_BAD_LEN;
		return;
	}

	px = (unsigned int*)(req->buf + MARKER_SIZE);
	req->content_len = (*px);
	if(req->pos - req->buf == req->content_len){
		LM_DBG("received a COMPLETE message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else if(req->pos - req->buf > req->content_len){
		LM_DBG("received MORE then a message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else {
		LM_DBG("received only PART of a message\n");
		req->parsed = req->pos;
	}
}

static int bin_read_req(struct tcp_connection* con, int* bytes_read){

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
		init_tcp_req(&bin_current_req, 0);
		req = &bin_current_req;
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

		bin_parse_headers(req);

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

	switch (bin_handle_req(req, con, bin_max_msg_chunks) ) {
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

static int bin_write_async_req(struct tcp_connection* con,int fd)
{
	int n,left;
	struct bin_send_chunk *chunk;
	struct bin_data *d = (struct bin_data*)con->proto_data;

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
	n = send(fd, chunk->pos, left, 0);
	if (n<0) {
		if (errno == EINTR)
			goto again;
		else if (errno == EAGAIN || errno == EWOULDBLOCK) {
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
					d->async_chunks_no * sizeof(struct bin_send_chunk*));
			d->oldest_chunk = d->async_chunks[0]->ticks;
			goto next_chunk;
		}
	}
}

