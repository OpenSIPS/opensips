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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2015-08-14  first version (Ionut Ionita)
 */

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_udp.h"
#include "../../socket_info.h"
#include "../../receive.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../ut.h"
#include "../compression/compression_api.h"
#include "hep.h"
#include "hep_cb.h"

#define HEP_FIRST 1
#define HEP_LAST  3


static int mod_init(void);
static void destroy(void);                          /*!< Module destroy function */
static int proto_hep_init_udp(struct proto_info *pi);
static int proto_hep_init_tcp(struct proto_info *pi);
static int proto_hep_init_udp_listener(struct socket_info *si);
static int hep_conn_init(struct tcp_connection* c);
static void hep_conn_clean(struct tcp_connection* c);
static int hep_write_async_req(struct tcp_connection* con,int fd);
static int hep_tcp_read_req(struct tcp_connection* con, int* bytes_read);
static int hep_udp_read_req(struct socket_info *si, int* bytes_read);
static int hep_udp_send (struct socket_info* send_sock,
		char *buf, unsigned int len, union sockaddr_union *to, int id);
static int hep_tcp_send (struct socket_info* send_sock,
		char *buf, unsigned int len, union sockaddr_union *to, int id);
static void update_recv_info(struct receive_info *ri, struct hep_desc *h);

void free_hep_context(void* ptr);

static int hep_port = 5656;
static int hep_async = 1;
static int hep_send_timeout = 100;
static int hep_async_max_postponed_chunks = 32;
static int hep_max_msg_chunks = 32;
static int hep_async_local_connect_timeout = 100;
static int hep_async_local_write_timeout = 10;

int hep_ctx_idx=0;

int hep_capture_id = 1;
int payload_compression=0;

compression_api_t compression_api;
load_compression_f load_compression;

static struct tcp_req hep_current_req;
/* we consider that different messages may contain different versions of hep
 * so we need to know what is the current version of hep */
static int hep_current_proto;

struct hep_send_chunk {
	char *buf; /* buffer that needs to be sent out */
	char *pos; /* the position that we should be writing next */
	int len;   /* length of the buffer */
	int ticks; /* time at which this chunk was initially
				  attempted to be written */
};

struct hep_data {
	/* the chunks that need to be written on this
	 * connection when it will become writable */
	struct hep_send_chunk **async_chunks;
	/* the total number of chunks pending to be written */
	int async_chunks_no;
	/* the oldest chunk in our write list */
	int oldest_chunk;
};


static cmd_export_t cmds[] = {
	{"proto_init",            (cmd_function)proto_hep_init_udp,        0, 0, 0, 0},
	{"proto_init",            (cmd_function)proto_hep_init_tcp,        0, 0, 0, 0},
	{"load_hep",			  (cmd_function)bind_proto_hep,        1, 0, 0, 0},
	{0,0,0,0,0,0}
};

static param_export_t params[] = {
	{ "hep_port",                        INT_PARAM, &hep_port				},
	{ "hep_send_timeout",                INT_PARAM, &hep_send_timeout		},
	{ "hep_max_msg_chunks",              INT_PARAM, &hep_max_msg_chunks     },
	{ "hep_async",                       INT_PARAM, &hep_async				},
	{ "hep_async_max_postponed_chunks",  INT_PARAM,
											&hep_async_max_postponed_chunks },
	/* what protocol shall be used: 1, 2 or 3 */
	{ "hep_capture_id",					 INT_PARAM, &hep_capture_id			},
	{ "hep_async_local_connect_timeout", INT_PARAM,
											&hep_async_local_connect_timeout},
	{ "hep_async_local_write_timeout",   INT_PARAM,
											&hep_async_local_write_timeout  },
	{ "compressed_payload",				 INT_PARAM, &payload_compression},
	{0, 0, 0}
};


static module_dependency_t *get_deps_compression(param_export_t *param)
{
	int do_compression= *(int *)param->param_pointer;

	if (do_compression == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "compression", DEP_ABORT);

}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{"compressed_payload", get_deps_compression},
		{ NULL, NULL },
	},
};



struct module_exports exports = {
	PROTO_PREFIX "hep",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,	/* destroy function */
	0,          /* per-child init function */
};

static int mod_init(void)
{
	/* check if any listeners defined for this proto */
	if ( !protos[PROTO_HEP_UDP].listeners && !protos[PROTO_HEP_TCP].listeners ) {
		LM_ERR("No HEP listener defined, neither TCP nor UDP!\n");
		return -1;
	}


	if (payload_compression) {
		load_compression =
			(load_compression_f)find_export("load_compression", 1, 0);
		if (!load_compression) {
			LM_ERR("can't bind compression module!\n");
			return -1;
		}

		if (load_compression(&compression_api)) {
			LM_ERR("failed to load compression api!\n");
			return -1;
		}
	}

	hep_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, 0);

	return 0;
}

static void destroy(void)
{
	free_hep_cbs();
}

void free_hep_context(void *ptr)
{
	struct hep_desc* h;
	struct hep_context* ctx = (struct hep_context*)ptr;

	generic_chunk_t* it;
	generic_chunk_t* foo=NULL;

	h = &ctx->h;

	/* for version 3 we may have custom chunks which are in shm so we
	 * need to free them */
	if (h->version == 3) {
		it = h->u.hepv3.chunk_list;
		while (it) {
			if (foo) {
				shm_free(foo->data);
				shm_free(foo);
			}
			foo=it;
			it=it->next;
		}

		if (foo) {
			shm_free(foo->data);
			shm_free(foo);
		}
	}

	shm_free(ctx);
}


static int proto_hep_init_udp(struct proto_info *pi)
{

	pi->id					= PROTO_HEP_UDP;
	pi->name				= "hep_udp";
	pi->default_port		= hep_port;
	pi->tran.init_listener	= proto_hep_init_udp_listener;

	pi->tran.send	= hep_udp_send;

	pi->net.flags	= PROTO_NET_USE_UDP;
	pi->net.read	= (proto_net_read_f)hep_udp_read_req;


	return 0;
}

static int proto_hep_init_tcp(struct proto_info *pi)
{

	pi->id					= PROTO_HEP_TCP;
	pi->name				= "hep_tcp";
	pi->default_port		= hep_port;
	pi->tran.init_listener	= tcp_init_listener;

	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;

	pi->net.read			= (proto_net_read_f)hep_tcp_read_req;
	pi->net.write			= (proto_net_write_f)hep_write_async_req;

	pi->tran.send			= hep_tcp_send;


	if (hep_async) {
		pi->net.conn_init	= hep_conn_init;
		pi->net.conn_clean	= hep_conn_clean;
	}

	return 0;
}



static int hep_conn_init(struct tcp_connection* c)
{
	struct hep_data *d;

	/* allocate the tcp_data and the array of chunks as a single mem chunk */
	d = (struct hep_data*)shm_malloc( sizeof(struct hep_data) +
		sizeof(struct hep_send_chunk *) * hep_async_max_postponed_chunks );
	if (d == NULL) {
		LM_ERR("failed to create tcp chunks in shm mem\n");
		return -1;
	}

	d->async_chunks = (struct hep_send_chunk **)(d+1);
	d->async_chunks_no = 0;
	d->oldest_chunk = 0;

	c->proto_data = (void*)d;
	return 0;
}

static void hep_conn_clean(struct tcp_connection* c)
{
	struct hep_data *d = (struct hep_data*)c->proto_data;
	int r;

	for (r = 0; r < d->async_chunks_no; r++) {
		shm_free(d->async_chunks[r]);
	}

	shm_free(d);

	c->proto_data = NULL;
}


static int proto_hep_init_udp_listener(struct socket_info *si)
{
	return udp_init_listener(si, hep_async?O_NONBLOCK:0);
}

static int add_write_chunk(struct tcp_connection *con,char *buf,int len,
					int lock)
{
	struct hep_send_chunk *c;
	struct hep_data *d = (struct hep_data*)con->proto_data;

	c = shm_malloc(sizeof(struct hep_send_chunk) + len);
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

	if (d->async_chunks_no == hep_async_max_postponed_chunks) {
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
		/* succesful write from the first try */
		LM_DBG("Async succesful write from first try on %p\n",c);
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
			/* we have succesfully added async write chunk
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



static struct tcp_connection* hep_sync_connect(struct socket_info* send_sock,
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
	to = hep_async_local_connect_timeout*1000;

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

inline static int _hep_write_on_socket(struct tcp_connection *c, int fd,
												char *buf, int len){
	int n;

	lock_get(&c->write_lock);
	if (hep_async) {
		/*
		 * if there is any data pending to write, we have to wait for those chunks
		 * to be sent, otherwise we will completely break the messages' order
		 */
		if (((struct hep_data*)c->proto_data)->async_chunks_no)
			return add_write_chunk(c, buf, len, 0);
		n=async_tsend_stream(c,fd,buf,len, hep_async_local_write_timeout);
	} else {
		n = tsend_stream(fd, buf, len, hep_send_timeout);
	}
	lock_release(&c->write_lock);

	return n;
}

static int hep_udp_send (struct socket_info* send_sock,
		char *buf, unsigned int len, union sockaddr_union *to, int id)
{
	int n, tolen;

	tolen=sockaddru_len(*to);
again:
	n=sendto(send_sock->socket, buf, len, 0, &to->s, tolen);
	if (n==-1){
		LM_ERR("sendto(sock,%p,%d,0,%p,%d): %s(%d)\n", buf,len,to,tolen,
				strerror(errno),errno);
		if (errno==EINTR || errno==EAGAIN) goto again;
		if (errno==EINVAL) {
			LM_CRIT("invalid sendtoparameters\n"
			"one possible reason is the server is bound to localhost and\n"
			"attempts to send to the net\n");
		}
	}
	return n;

}

static int hep_tcp_send (struct socket_info* send_sock,
		char *buf, unsigned int len, union sockaddr_union *to, int id)
{
	struct tcp_connection *c;
	int port=0;
	struct ip_addr ip;
	int fd, n;


	if (to) {
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id,&ip, port, PROTO_HEP_TCP, &c, &fd);
	} else if (id) {
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, &c, &fd);
	} else {
		LM_CRIT("tcp_send called with null id & to\n");
		return -1;
	}

	if (n < 0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to aquire connection\n");
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
		LM_DBG("no open tcp connection found, opening new one, async = %d\n",hep_async);
		/* create tcp connection */
		if (hep_async) {
			n = tcpconn_async_connect(send_sock, to, buf, len, &c, &fd);
			if ( n<0 ) {
				LM_ERR("async TCP connect failed\n");
				return -1;
			}
			/* connect succeeded, we have a connection */
			if (n==0) {
				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when
				 * connect will be completed */
				LM_DBG("Succesfully started async connection \n");
				tcp_conn_release(c, 0);
				return len;
			}
			/* our first connect attempt succeeded - go ahead as normal */
		} else if ((c=hep_sync_connect(send_sock, to, &fd))==0) {
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

			/* we succesfully added our write chunk - success */
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

	n = _hep_write_on_socket(c, fd, buf, len);

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

	tcp_conn_release(c, (n<len)?1:0/*pending data in async mode?*/ );

	return n;
}

static void hep_parse_headers(struct tcp_req *req){
	/* message length */
	u_int16_t length=0;
	hep_ctrl_t *ctrl;

	if(req->content_len == 0 &&
			req->pos - req->buf < sizeof(hep_ctrl_t)){
		/* not enough intel; keep watching son */
		return;
	}

	/* check for hepV3 header id; if tcp it's hepv3 */
	if (memcmp(req->buf, HEP_HEADER_ID, HEP_HEADER_ID_LEN)) {
		/* version 3*/
		LM_ERR("not a hepV3 message\n");
		return;
	}

	hep_current_proto = 3;
	ctrl = (hep_ctrl_t *)req->buf;
	length = ntohs(ctrl->length);
	req->content_len = (unsigned short)length;

	if(req->pos - req->buf == req->content_len){
		LM_DBG("received a COMPLETE message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else if(req->pos - req->buf > req->content_len){
		LM_DBG("received MORE than a message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else {
		LM_DBG("received only PART of a message\n");
		/* FIXME should we update parsed? we didn't receive the
		 * full message; we wait for the full mesage and only
		 * after that we update parsed */
		req->parsed = req->pos;
	}
}

int tcp_read(struct tcp_connection *c,struct tcp_req *r) {
	int bytes_free, bytes_read;
	int fd;

	fd = c->fd;
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
			LM_DBG("EOF on %p, FD %d\n", c, fd);
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


static inline int hep_handle_req(struct tcp_req *req,
							struct tcp_connection *con, int _max_msg_chunks)
{
	struct receive_info local_rcv;
	char *msg_buf;
	int msg_len;
	long size;

	int ret=0;

	struct hep_context *hep_ctx=NULL;
	context_p ctx=NULL;

	if (req->complete){
		/* update the timeout - we successfully read the request */
		tcp_conn_set_lifetime( con, tcp_con_lifetime);
		con->timeout=con->lifetime;

		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */

		/* prepare for next request */
		size=req->pos-req->parsed;

		msg_buf = req->buf;
		msg_len = req->parsed-req->start;
		local_rcv = con->rcv;

		if (!size) {
			/* did not read any more things -  we can release
			 * the connection */
			LM_DBG("Nothing more to read on TCP conn %p, currently in state %d \n",
				con,con->state);
			if (req != &hep_current_req) {
				/* we have the buffer in the connection tied buff -
				 *	detach it , release the conn and free it afterwards */
				con->con_req = NULL;
			}
			/* TODO - we could indicate to the TCP net layer to release
			 * the connection -> other worker may read the next available
			 * message on the pipe */
		} else {
			LM_DBG("We still have things on the pipe - "
				"keeping connection \n");
		}

		if( msg_buf[0] == 'H' && msg_buf[1] == 'E' && msg_buf[2] == 'P' ) {
			if ((hep_ctx = shm_malloc(sizeof(struct hep_context))) == NULL) {
				LM_ERR("no more shared memory!\n");
				return -1;
			}
			memset(hep_ctx, 0, sizeof(struct hep_context));
			memcpy(&hep_ctx->ri, &local_rcv, sizeof(struct receive_info));

			/* HEP related */
			if (unpack_hepv3(msg_buf, msg_len, &hep_ctx->h)) {
				LM_ERR("failed to unpack hepV3\n");
				goto error_free_hep;
			}
			update_recv_info(&local_rcv, &hep_ctx->h);

			/* set context for receive_msg */
			if ((ctx=context_alloc(CONTEXT_GLOBAL)) == NULL) {
				LM_ERR("failed to allocate new context! skipping...\n");
				goto error_free_hep;
			}

			memset(ctx, 0, context_size(CONTEXT_GLOBAL));

			context_put_ptr(CONTEXT_GLOBAL, ctx, hep_ctx_idx, hep_ctx);
			/* run hep callbacks; set the current processing context
			 * to hep context; this way callbacks will have all the data
			 * needed */
			current_processing_ctx = ctx;
			ret=run_hep_cbs();
			if (ret < 0) {
				LM_ERR("failed to run hep callbacks\n");
				goto error_free_hep;
			}
			current_processing_ctx = NULL;

			msg_len = hep_ctx->h.u.hepv3.payload_chunk.chunk.length-
											sizeof(hep_chunk_t);
			/* remove the hep header; leave only the payload */
			msg_buf = hep_ctx->h.u.hepv3.payload_chunk.data;
		}

		/* skip receive msg if we were told so from at least one callback */
		if ( ret != HEP_SCRIPT_SKIP ) {
			if ( receive_msg(msg_buf, msg_len, &local_rcv, ctx) <0 ) {
				LM_ERR("receive_msg failed \n");
			}
		} else {
			if ( ctx ) {
				context_free( ctx );
			}
		}

		if (hep_ctx)
			free_hep_context(hep_ctx);

		if (!size && req != &hep_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			pkg_free(req);
		}

		if (size) {
			memmove(req->buf, req->parsed, size);
			init_tcp_req( req, size);

			return 1;
		}
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

		if (req == &hep_current_req) {
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
			/* req will be reset on the next usage */
		}
	}

	/* everything ok */
	return 0;
error_free_hep:
	shm_free(hep_ctx);
error:
	/* report error */
	return -1;

}





static int hep_tcp_read_req(struct tcp_connection* con, int* bytes_read)
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
		init_tcp_req(&hep_current_req, 0);
		req = &hep_current_req;
	}

	again:
	if(req->error == TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed < req->pos){
			bytes=0;
		} else {
			bytes=tcp_read(con,req);
			if (bytes < 0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		hep_parse_headers(req);

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

	switch (hep_handle_req(req, con, hep_max_msg_chunks) ) {
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



static int hep_write_async_req(struct tcp_connection* con,int fd)
{
	int n,left;
	struct hep_send_chunk *chunk;
	struct hep_data *d = (struct hep_data*)con->proto_data;

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
			LM_ERR("Error occured while sending async chunk %d (%s)\n",
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
					d->async_chunks_no * sizeof(struct hep_send_chunk*));
			d->oldest_chunk = d->async_chunks[0]->ticks;
			goto next_chunk;
		}
	}
}


static int hep_udp_read_req(struct socket_info *si, int* bytes_read)
{
	struct receive_info ri;
	int len;
#ifdef DYN_BUF
	char* buf;
#else
	static char buf [BUF_SIZE+1];
#endif
	unsigned int fromlen;
	str msg;

	struct hep_context *hep_ctx;

	int ret = 0;

	context_p ctx=NULL;

#ifdef DYN_BUF
	buf=pkg_malloc(BUF_SIZE+1);
	if (buf==0){
		LM_ERR("could not allocate receive buffer\n");
		goto error;
	}
#endif

	fromlen=sockaddru_len(si->su);
	len=recvfrom(bind_address->socket, buf, BUF_SIZE,0,&ri.src_su.s,&fromlen);
	if (len==-1){
		if (errno==EAGAIN)
			return 0;
		if ((errno==EINTR)||(errno==EWOULDBLOCK)|| (errno==ECONNREFUSED))
			return -1;
		LM_ERR("recvfrom:[%d] %s\n", errno, strerror(errno));
		return -2;
	}


	if (len<MIN_UDP_PACKET) {
		LM_DBG("probing packet received len = %d\n", len);
		return 0;
	}

	/* we must 0-term the messages, receive_msg expects it */
	buf[len]=0; /* no need to save the previous char */

	ri.bind_address = si;
	ri.dst_port = si->port_no;
	ri.dst_ip = si->address;
	ri.proto = si->proto;
	ri.proto_reserved1 = ri.proto_reserved2 = 0;

	su2ip_addr(&ri.src_ip, &ri.src_su);
	ri.src_port=su_getport(&ri.src_su);

	/* if udp we are sure that version 1 or 2 of the
	 * protocol is used */
	if ((hep_ctx = shm_malloc(sizeof(struct hep_context))) == NULL) {
		LM_ERR("no more shared memory!\n");
		return -1;
	}

	memset(hep_ctx, 0, sizeof(struct hep_context));
	memcpy(&hep_ctx->ri, &ri, sizeof(struct receive_info));


	if (len < 4) {
		LM_ERR("invalid message! too short!\n");
		return -1;
	}

	if (!memcmp(buf, HEP_HEADER_ID, HEP_HEADER_ID_LEN)) {
		/* HEPv3 */
		if (unpack_hepv3(buf, len, &hep_ctx->h)) {
			LM_ERR("hepv3 unpacking failed\n");
			return -1;
		}
	} else {
		/* HEPv2 */
		if (unpack_hepv12(buf, len, &hep_ctx->h)) {
			LM_ERR("hepv12 unpacking failed\n");
			return -1;
		}
	}

	/* set context for receive_msg */
	if ((ctx=context_alloc(CONTEXT_GLOBAL)) == NULL) {
		LM_ERR("failed to allocate new context! skipping...\n");
		goto error_free_hep;
	}

	memset(ctx, 0, context_size(CONTEXT_GLOBAL));

	context_put_ptr(CONTEXT_GLOBAL, ctx, hep_ctx_idx, hep_ctx);

	update_recv_info(&ri, &hep_ctx->h);

	/* run hep callbacks; set the current processing context
	 * to hep context; this way callbacks will have all the data
	 * needed */
	current_processing_ctx = ctx;
	ret=run_hep_cbs();
	if (ret < 0) {
		LM_ERR("failed to run hep callbacks\n");
		return -1;
	}
	current_processing_ctx = NULL;

	if (hep_ctx->h.version == 3) {
		/* HEPv3 */
		msg.len =
			hep_ctx->h.u.hepv3.payload_chunk.chunk.length- sizeof(hep_chunk_t);
		msg.s = hep_ctx->h.u.hepv3.payload_chunk.data;
	} else {
		/* HEPv12 */
		msg.len = len - hep_ctx->h.u.hepv12.hdr.hp_l;
		msg.s = buf + hep_ctx->h.u.hepv12.hdr.hp_l;

		if (hep_ctx->h.u.hepv12.hdr.hp_v == 2) {
			msg.s += sizeof(struct hep_timehdr);
			msg.len -= sizeof(struct hep_timehdr);
		}
	}

	if (ret != HEP_SCRIPT_SKIP) {
		/* receive_msg must free buf too!*/
		receive_msg( msg.s, msg.len, &ri, ctx);
	} else {
		if ( ctx ) {
			context_free( ctx );
		}
	}

	free_hep_context(hep_ctx);

	return 0;

error_free_hep:
	shm_free(hep_ctx);
	return -1;

}



static void update_recv_info(struct receive_info *ri, struct hep_desc *h)
{
	unsigned proto;
	unsigned ip_family;
	unsigned sport, dport;

	struct ip_addr dst_ip, src_ip;

	switch (h->version) {
		case 1:
		case 2:
			ip_family = h->u.hepv12.hdr.hp_f;
			proto = h->u.hepv12.hdr.hp_p;
			sport	  = h->u.hepv12.hdr.hp_sport;
			dport	  = h->u.hepv12.hdr.hp_dport;
			switch (ip_family) {
				case AF_INET:
					dst_ip.af  = src_ip.af  = AF_INET;
					dst_ip.len = src_ip.len = 4;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv12.addr.hep_ipheader.hp_dst, 4);
					memcpy(&src_ip.u.addr,
								&h->u.hepv12.addr.hep_ipheader.hp_src, 4);

					break;

				case AF_INET6:
					dst_ip.af  = src_ip.af  = AF_INET6;
					dst_ip.len = src_ip.len = 16;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv12.addr.hep_ip6header.hp6_dst, 16);
					memcpy(&src_ip.u.addr,
								&h->u.hepv12.addr.hep_ip6header.hp6_src, 16);

					break;
			}

			break;
		case 3:
			ip_family = h->u.hepv3.hg.ip_family.data;
			proto	  = h->u.hepv3.hg.ip_proto.data;
			sport     = h->u.hepv3.hg.src_port.data;
			dport	  = h->u.hepv3.hg.dst_port.data;
			switch (ip_family) {
				case AF_INET:
					dst_ip.af  = src_ip.af  = AF_INET;
					dst_ip.len = src_ip.len = 4;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv3.addr.ip4_addr.dst_ip4.data, 4);
					memcpy(&src_ip.u.addr,
								&h->u.hepv3.addr.ip4_addr.src_ip4.data, 4);

					break;

				case AF_INET6:
					dst_ip.af  = src_ip.af  = AF_INET6;
					dst_ip.len = src_ip.len = 16;

					memcpy(&dst_ip.u.addr,
								&h->u.hepv3.addr.ip6_addr.dst_ip6.data, 16);
					memcpy(&src_ip.u.addr,
								&h->u.hepv3.addr.ip6_addr.src_ip6.data, 16);

					break;
			}

			break;
		default:
			LM_ERR("invalid hep version!\n");
			return;
	}

	if(proto == IPPROTO_UDP) ri->proto=PROTO_UDP;
	else if(proto == IPPROTO_TCP) ri->proto=PROTO_TCP;
	else if(proto == IPPROTO_IDP) ri->proto=PROTO_TLS;
											/* fake protocol */
	else if(proto == IPPROTO_SCTP) ri->proto=PROTO_SCTP;
	else if(proto == IPPROTO_ESP) ri->proto=PROTO_WS;
                                            /* fake protocol */
	else {
		LM_ERR("unknown protocol [%d]\n",proto);
		proto = PROTO_NONE;
	}


	if (h->version == 3)
		h->u.hepv3.hg.ip_proto.data = ri->proto;


	ri->src_ip = src_ip;
	ri->src_port = sport;

	ri->dst_ip = dst_ip;
	ri->dst_port = dport;
}
