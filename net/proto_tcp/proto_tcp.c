/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 *  2015-01-09  first version (razvanc)
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>

#include "../../pt.h"
#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../receive.h"
#include "proto_tcp_handler.h"

static int mod_init(void);
static int proto_tcp_init(void);
static int proto_tcp_api_bind(struct api_proto *proto_binds,
		struct api_proto_net *net_binds);
static int proto_tcp_init_listener(struct socket_info *si);
static int proto_tcp_bind(struct socket_info *si);
static int proto_tcp_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id);

static int tcp_write_async_req(struct tcp_connection* con);
static int tcp_read_req(struct tcp_connection* con, int* bytes_read);
static int tcp_conn_init(struct tcp_connection* c);
static void tcp_conn_clean(struct tcp_connection* c);


#define TCP_BUF_SIZE 65535			/*!< TCP buffer size */

/*!< the max number of chunks that a child accepts until the message
 * is read completely - anything above will lead to the connection being
 * closed - considered an attack */
#define TCP_CHILD_MAX_MSG_CHUNK  4

enum tcp_req_errors {	TCP_REQ_INIT, TCP_REQ_OK, TCP_READ_ERROR,
		TCP_REQ_OVERRUN, TCP_REQ_BAD_LEN };
enum tcp_req_states {	H_SKIP_EMPTY, H_SKIP, H_LF, H_LFCR,  H_BODY, H_STARTWS,
		H_CONT_LEN1, H_CONT_LEN2, H_CONT_LEN3, H_CONT_LEN4, H_CONT_LEN5,
		H_CONT_LEN6, H_CONT_LEN7, H_CONT_LEN8, H_CONT_LEN9, H_CONT_LEN10,
		H_CONT_LEN11, H_CONT_LEN12, H_CONT_LEN13, H_L_COLON,
		H_CONT_LEN_BODY, H_CONT_LEN_BODY_PARSE , H_PING_CRLFCRLF,
		H_SKIP_EMPTY_CR_FOUND, H_SKIP_EMPTY_CRLF_FOUND,
		H_SKIP_EMPTY_CRLFCR_FOUND
	};


struct tcp_req{
	struct tcp_req* next;
	/* sockaddr ? */
	char buf[TCP_BUF_SIZE+1];		/*!< bytes read so far (+0-terminator)*/
	char* start;					/*!< where the message starts, after all the empty lines are skipped*/
	char* pos;						/*!< current position in buf */
	char* parsed;					/*!< last parsed position */
	char* body;						/*!< body position */
	unsigned int   content_len;
	unsigned short has_content_len;	/*!< 1 if content_length was parsed ok*/
	unsigned short complete;		/*!< 1 if one req has been fully read, 0 otherwise*/
	unsigned int   bytes_to_go;		/*!< how many bytes we have still to read from the body*/
	enum tcp_req_errors error;
	enum tcp_req_states state;
};


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


//FIXME - expose below as module param
/*!< should a new TCP conn be open if needed? - branch flag to be set in
 * the SIP messages - configuration option */
int tcp_no_new_conn_bflag = 0;
/*!< should a new TCP conn be open if needed? - variable used to used for
 * signalizing between SIP layer (branch flag) and TCP layer (tcp_send func)*/
int tcp_no_new_conn = 0;
int tcp_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;


/* buffer to be used for reading all TCP SIP messages
   detached from the actual con - in order to improve
   paralelism ( process the SIP message while the con
   can be sent back to main to do more stuff */
struct tcp_req current_req;


static cmd_export_t cmds[] = {
	{"proto_bind_api", (cmd_function)proto_tcp_api_bind, 0, 0, 0, 0},
	{0,0,0,0,0,0}
};


#ifndef DISABLE_AUTO_TCP
struct module_exports proto_tcp_exports = {
#else
struct module_exports exports = {
#endif
	PROTO_PREFIX "tcp",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	0,          /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
};

static struct api_proto tcp_proto_binds = {
	.name			= "tcp",
	.default_port	= SIP_PORT,
	.init			= proto_tcp_init,
	.init_listener	= proto_tcp_init_listener,
	.send			= proto_tcp_send,
};

static struct api_proto_net tcp_proto_net_binds = {
	.id				= PROTO_TCP,
	.flags			= PROTO_NET_USE_TCP,
	.bind			= proto_tcp_bind,
	.read			= (proto_net_read_f)tcp_read_req,
	.write			= (proto_net_write_f)tcp_write_async_req,
	.conn_init		= tcp_conn_init,
	.conn_clean		= tcp_conn_clean,
};


static int proto_tcp_init(void)
{
	LM_INFO("initializing TCP-plain protocol\n");
	return 0;
}


static int mod_init(void)
{
	/* without async support, there is nothing to init/clean per conn */
	if (tcp_async==0) {
		tcp_proto_net_binds.conn_init = NULL;
		tcp_proto_net_binds.conn_clean = NULL;
	}
	return 0;
}

static int proto_tcp_api_bind(struct api_proto *proto_api,
										struct api_proto_net *proto_net_api)
{
	if (!proto_api || !proto_net_api)
		return -1;
/*
 * TODO: memset + set or simply copy the structures?
	memset(funcs, 0, sizeof(struct proto_funcs));
	funcs.init = net_tcp_init;
 */
	memcpy(proto_api, &tcp_proto_binds, sizeof(struct api_proto));
	memcpy(proto_net_api, &tcp_proto_net_binds,
			sizeof(struct api_proto_net));

	return 0;
}


static int proto_tcp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}


static int proto_tcp_bind(struct socket_info *sock_info)
{
	/* FIXME  - for TCP plain, there is nothing extra to do
	 * but to call the underlaying networking function */
	return -1;
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


#define init_tcp_req( r, _size) \
	do{ \
		(r)->parsed=(r)->start=(r)->buf; \
		(r)->pos=(r)->buf + (_size); \
		(r)->error=TCP_REQ_OK;\
		(r)->state=H_SKIP_EMPTY; \
		(r)->body=0; \
		(r)->complete=(r)->content_len=(r)->has_content_len=0; \
		(r)->bytes_to_go=0; \
	}while(0)


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
		}else if (errno == EINTR) goto again;
		else{
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



/**************  CONNECT related functions ***************/

#define get_su_info(_su, _ip_char, _port_no) \
	do { \
		struct ip_addr __ip; \
		sockaddr2ip_addr( &__ip, (struct sockaddr*)_su ); \
		_ip_char = ip_addr2a(&__ip); \
		_port_no = su_getport( (union sockaddr_union*)_su); \
	} while(0)


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





/*! \brief blocking connect on a non-blocking fd; it will timeout after
 * tcp_connect_timeout
 * if BLOCKING_USE_SELECT and HAVE_SELECT are defined it will internally
 * use select() instead of poll (bad if fd > FD_SET_SIZE, poll is preferred)
 */
static int tcp_blocking_connect(int fd, const struct sockaddr *servaddr,
			socklen_t addrlen)
{
	int n;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
	fd_set sel_set;
	fd_set orig_set;
	struct timeval timeout;
#else
	struct pollfd pf;
#endif
	int elapsed;
	int to;
	int ticks;
	int err;
	unsigned int err_len;
	int poll_err;
	char *ip;
	unsigned short port;

	poll_err=0;
	to=tcp_connect_timeout;
	ticks=get_ticks();
again:
	n=connect(fd, servaddr, addrlen);
	if (n==-1){
		if (errno==EINTR){
			elapsed=(get_ticks()-ticks)*TIMER_TICK;
			if (elapsed<to)		goto again;
			else goto error_timeout;
		}
		if (errno!=EINPROGRESS && errno!=EALREADY){
			get_su_info( servaddr, ip, port);
			LM_ERR("[server=%s:%d] (%d) %s\n",ip, port, errno, strerror(errno));
			goto error;
		}
	}else goto end;

	/* poll/select loop */
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		FD_ZERO(&orig_set);
		FD_SET(fd, &orig_set);
#else
		pf.fd=fd;
		pf.events=POLLOUT;
#endif
	while(1){
		elapsed=(get_ticks()-ticks)*TIMER_TICK;
		if (elapsed<to)
			to-=elapsed;
		else
			goto error_timeout;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		sel_set=orig_set;
		timeout.tv_sec=to;
		timeout.tv_usec=0;
		n=select(fd+1, 0, &sel_set, 0, &timeout);
#else
		n=poll(&pf, 1, to*1000);
#endif
		if (n<0){
			if (errno==EINTR) continue;
			get_su_info( servaddr, ip, port);
			LM_ERR("poll/select failed:[server=%s:%d] (%d) %s\n",
				ip, port, errno, strerror(errno));
			goto error;
		}else if (n==0) /* timeout */ continue;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		if (FD_ISSET(fd, &sel_set))
#else
		if (pf.revents&(POLLERR|POLLHUP|POLLNVAL)){
			LM_ERR("poll error: flags %d - %d %d %d %d \n", pf.revents,
				   POLLOUT,POLLERR,POLLHUP,POLLNVAL);
			poll_err=1;
		}
#endif
		{
			err_len=sizeof(err);
			getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if ((err==0) && (poll_err==0)) goto end;
			if (err!=EINPROGRESS && err!=EALREADY){
				get_su_info( servaddr, ip, port);
				LM_ERR("failed to retrieve SO_ERROR [server=%s:%d] (%d) %s\n",
					ip, port, err, strerror(err));
				goto error;
			}
		}
	}
error_timeout:
	/* timeout */
	LM_ERR("timeout %d s elapsed from %d s\n", elapsed, tcp_connect_timeout);
error:
	return -1;
end:
	return 0;
}


/* Attempts do a connect to the given destination. It returns:
 *   1 - connect was done local (completed)
 *   0 - connect launched as async (in progress)
 *  -1 - error
 */
static int tcpconn_async_connect(struct socket_info* send_sock,
					union sockaddr_union* server, char *buf, unsigned len,
					struct tcp_connection** c)
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
	to = tcp_async_local_connect_timeout;

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}

again:
	n=connect(fd, &server->s, sockaddru_len(*server));
	if (n==-1) {
		if (errno==EINTR){
			elapsed=get_time_diff(&begin);
			if (elapsed<tcp_async_local_connect_timeout)
				goto again;
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
	con=tcp_conn_create(fd, server, send_sock, PROTO_TCP, S_CONN_INIT);
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
	con=tcp_conn_create(fd, server, send_sock, PROTO_TCP, S_CONN_CONNECT);
	if (con==NULL) {
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	*c = con;
	/* report a local connect */
	return 1;

error:
	close(fd);
	*c = NULL;
	return -1;
}


static struct tcp_connection* tcp_sync_connect(struct socket_info* send_sock,
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

	if (tcp_blocking_connect(s, &server->s, sockaddru_len(*server))<0){
		LM_ERR("tcp_blocking_connect failed\n");
		goto error;
	}
	con=tcp_conn_create(s, server, send_sock, PROTO_TCP, S_CONN_CONNECT);
	if (con==NULL){
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	return con;
	/*FIXME: set sock idx! */
error:
	/* close the opened socket */
	if (s!=-1) close(s);
	return 0;
}




/**************  WRITE related functions ***************/

/* called under the TCP connection write lock */
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
		/* succesful write from the first try */
		LM_DBG("Async succesful write from first try on %p\n",c);
		return len;
	}

poll_loop:
	n=poll(&pf,1,timeout/1000);
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
			/* we have succesfully added async write chunk
			 * tell MAIN to poll out for us */
			LM_DBG("Data still pending for write on conn %p\n",c);
			return len;
		}
	}

	if (pf.events&POLLOUT)
		goto again;

	/* some other events triggered by poll - treat as errors */
	return -1;
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

	port=0;

	reset_tcp_vars(tcpthreshold);
	start_expire_timer(get,tcpthreshold);

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, tcp_con_lifetime, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, tcp_con_lifetime, &c, &fd);
	}else{
		LM_CRIT("tcp_send called with null id & to\n");
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
		LM_DBG("no open tcp connection found, opening new one\n");
		/* create tcp connection */
		if (tcp_async) {
			n = tcpconn_async_connect(send_sock, to, buf, len, &c );
			if ( n<0 ) {
				LM_ERR("async TCP connect failed\n");
				get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
				return -1;
			}
			/* connect succeded, we have a connection */
			if (n==0) {
				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when 
				 * connect will be completed */
				LM_DBG("Succesfully started async connection \n");
				tcp_conn_release(c, 0);
				return len;
			}

			LM_DBG("First connect attempt succeded in less than %d us, "
				"proceed to writing \n",tcp_async_local_connect_timeout);
			/* our first connect attempt succeeded - go ahead as normal */
		} else if ((c=tcp_sync_connect(send_sock, to))==0) {
			LM_ERR("connect failed\n");
			get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
			return -1;
		}

		fd=c->s;
		goto send_it;
	}
	get_time_difference(get,tcpthreshold,tcp_timeout_con_get);

	/* now we have a connection, let's what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd==-1) {
		/* connection is not writable because of its state - can we append
		 * data to it for later writting (async writting)? */
		if (c->flags & F_CONN_NOT_CONNECTED) {
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
		}
	} else {
		/* return error, nothing to do about it */
		tcp_conn_release(c, 0);
		return -1;
	}


send_it:
	LM_DBG("sending...\n");
	lock_get(&c->write_lock);
#ifdef USE_TLS
	// FIXME TCP
	if (c->type==PROTO_TLS)
		n=tls_blocking_write(c, fd, buf, len);
	else
#endif
	{
		start_expire_timer(snd,tcpthreshold);
		if (tcp_async) {
			n=async_tsend_stream(c,fd,buf,len,tcp_async_local_write_timeout);
		} else {
			n=tsend_stream(fd, buf, len, tcp_send_timeout*1000);
		}
		get_time_difference(snd,tcpthreshold,tcp_timeout_send);
		stop_expire_timer(get,tcpthreshold,"tcp ops",buf,(int)len,1);
	}
	lock_release(&c->write_lock);
	LM_DBG("after write: c= %p n=%d fd=%d\n",c, n, fd);
	LM_DBG("buf=\n%.*s\n", (int)len, buf);
	if (n<0){
		LM_ERR("failed to send\n");
		c->state=S_CONN_BAD;
		tcp_conn_release(c, 0);
		close(fd);
		return -1;
	}
	close(fd);
	tcp_conn_release(c, (n<len)?1:0/*pending data in async mode?*/ );
	return n;
}


/* Responsible for writing the TCP send chunks - called under con write lock
 *	* if returns = 1 : the connection will be released for more writting
 *	* if returns = 0 : the connection will be released
 *	* if returns < 0 : the connection will be released as BAD /  broken
 */
static int tcp_write_async_req(struct tcp_connection* con)
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
	n=send(con->fd, chunk->pos, left,
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
		}else if (errno == EINTR) goto again;
		else{
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



/*! \brief
 * reads all headers (until double crlf), & parses the content-length header
 *
 * \note (WARNING: inefficient, tries to reuse receive_msg but will go through
 * the headers twice [once here looking for Content-Length and for the end
 * of the headers and once in receive_msg]; a more speed efficient version will
 * result in either major code duplication or major changes to the receive code)
 *
 * \return number of bytes read & sets r->state & r->body
 * when either r->body!=0 or r->state==H_BODY =>
 * all headers have been read. It should be called in a while loop.
 * returns < 0 if error or 0 if EOF */
int tcp_read_headers(struct tcp_connection *c,struct tcp_req *r)
{
	unsigned int remaining;
	int bytes;
	char *p;

	#define crlf_default_skip_case \
					case '\n': \
						r->state=H_LF; \
						break; \
					default: \
						r->state=H_SKIP

	#define content_len_beg_case \
					case ' ': \
					case '\t': \
						if (!r->has_content_len) r->state=H_STARTWS; \
						else r->state=H_SKIP; \
							/* not interested if we already found one */ \
						break; \
					case 'C': \
					case 'c': \
						if(!r->has_content_len) r->state=H_CONT_LEN1; \
						else r->state=H_SKIP; \
						break; \
					case 'l': \
					case 'L': \
						/* short form for Content-Length */ \
						if (!r->has_content_len) r->state=H_L_COLON; \
						else r->state=H_SKIP; \
						break

	#define change_state(upper, lower, newstate)\
					switch(*p){ \
						case upper: \
						case lower: \
							r->state=(newstate); break; \
						crlf_default_skip_case; \
					}

	#define change_state_case(state0, upper, lower, newstate)\
					case state0: \
							  change_state(upper, lower, newstate); \
							  p++; \
							  break


	/* if we still have some unparsed part, parse it first, don't do the read*/
	if (r->parsed<r->pos){
		bytes=0;
	}else{
#ifdef USE_TLS
		if (c->type==PROTO_TLS)
			bytes=tls_read(c,r);
		else
#endif
			bytes=tcp_read(c,r);
		if (bytes<=0) return bytes;
	}
	p=r->parsed;

	while(p<r->pos && r->error==TCP_REQ_OK){
		switch((unsigned char)r->state){
			case H_BODY: /* read the body*/
				remaining=r->pos-p;
				if (remaining>r->bytes_to_go) remaining=r->bytes_to_go;
				r->bytes_to_go-=remaining;
				p+=remaining;
				if (r->bytes_to_go==0){
					r->complete=1;
					goto skip;
				}
				break;

			case H_SKIP:
				/* find lf, we are in this state if we are not interested
				 * in anything till end of line*/
				p=q_memchr(p, '\n', r->pos-p);
				if (p){
					p++;
					r->state=H_LF;
				}else{
					p=r->pos;
				}
				break;

			case H_LF:
				/* terminate on LF CR LF or LF LF */
				switch (*p){
					case '\r':
						r->state=H_LFCR;
						break;
					case '\n':
						/* found LF LF */
						r->state=H_BODY;
						if (r->has_content_len){
							r->body=p+1;
							r->bytes_to_go=r->content_len;
							if (r->bytes_to_go==0){
								r->complete=1;
								p++;
								goto skip;
							}
						}else{
							LM_DBG("no clen, p=%X\n", *p);
							r->error=TCP_REQ_BAD_LEN;
						}
						break;
					content_len_beg_case;
					default:
						r->state=H_SKIP;
				}
				p++;
				break;
			case H_LFCR:
				if (*p=='\n'){
					/* found LF CR LF */
					r->state=H_BODY;
					if (r->has_content_len){
						r->body=p+1;
						r->bytes_to_go=r->content_len;
						if (r->bytes_to_go==0){
							r->complete=1;
							p++;
							goto skip;
						}
					}else{
						LM_DBG("no clen, p=%X\n", *p);
						r->error=TCP_REQ_BAD_LEN;
					}
				}else r->state=H_SKIP;
				p++;
				break;

			case H_STARTWS:
				switch (*p){
					content_len_beg_case;
					crlf_default_skip_case;
				}
				p++;
				break;
			case H_SKIP_EMPTY:
				switch (*p){
					case '\n':
						break;
					case '\r':
						if (tcp_crlf_pingpong) {
							r->state=H_SKIP_EMPTY_CR_FOUND;
							r->start=p;
						}
						break;
					case ' ':
					case '\t':
						/* skip empty lines */
						break;
					case 'C':
					case 'c':
						r->state=H_CONT_LEN1;
						r->start=p;
						break;
					case 'l':
					case 'L':
						/* short form for Content-Length */
						r->state=H_L_COLON;
						r->start=p;
						break;
					default:
						r->state=H_SKIP;
						r->start=p;
				};
				p++;
				break;
			case H_SKIP_EMPTY_CR_FOUND:
				if (*p=='\n'){
					r->state=H_SKIP_EMPTY_CRLF_FOUND;
					p++;
				}else{
					r->state=H_SKIP_EMPTY;
				}
				break;

			case H_SKIP_EMPTY_CRLF_FOUND:
				if (*p=='\r'){
					r->state = H_SKIP_EMPTY_CRLFCR_FOUND;
					p++;
				}else{
					r->state = H_SKIP_EMPTY;
				}
				break;

			case H_SKIP_EMPTY_CRLFCR_FOUND:
				if (*p=='\n'){
					r->state = H_PING_CRLFCRLF;
					r->complete = 1;
					r->has_content_len = 1; /* hack to avoid error check */
					p++;
					goto skip;
				}else{
					r->state = H_SKIP_EMPTY;
				}
				break;
			change_state_case(H_CONT_LEN1,  'O', 'o', H_CONT_LEN2);
			change_state_case(H_CONT_LEN2,  'N', 'n', H_CONT_LEN3);
			change_state_case(H_CONT_LEN3,  'T', 't', H_CONT_LEN4);
			change_state_case(H_CONT_LEN4,  'E', 'e', H_CONT_LEN5);
			change_state_case(H_CONT_LEN5,  'N', 'n', H_CONT_LEN6);
			change_state_case(H_CONT_LEN6,  'T', 't', H_CONT_LEN7);
			change_state_case(H_CONT_LEN7,  '-', '_', H_CONT_LEN8);
			change_state_case(H_CONT_LEN8,  'L', 'l', H_CONT_LEN9);
			change_state_case(H_CONT_LEN9,  'E', 'e', H_CONT_LEN10);
			change_state_case(H_CONT_LEN10, 'N', 'n', H_CONT_LEN11);
			change_state_case(H_CONT_LEN11, 'G', 'g', H_CONT_LEN12);
			change_state_case(H_CONT_LEN12, 'T', 't', H_CONT_LEN13);
			change_state_case(H_CONT_LEN13, 'H', 'h', H_L_COLON);

			case H_L_COLON:
				switch(*p){
					case ' ':
					case '\t':
						break; /* skip space */
					case ':':
						r->state=H_CONT_LEN_BODY;
						break;
					crlf_default_skip_case;
				};
				p++;
				break;

			case  H_CONT_LEN_BODY:
				switch(*p){
					case ' ':
					case '\t':
						break; /* eat space */
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						r->state=H_CONT_LEN_BODY_PARSE;
						r->content_len=(*p-'0');
						break;
					/*FIXME: content length on different lines ! */
					crlf_default_skip_case;
				}
				p++;
				break;

			case H_CONT_LEN_BODY_PARSE:
				switch(*p){
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						r->content_len=r->content_len*10+(*p-'0');
						break;
					case '\r':
					case ' ':
					case '\t': /* FIXME: check if line contains only WS */
						r->state=H_SKIP;
						r->has_content_len=1;
						break;
					case '\n':
						/* end of line, parse successful */
						r->state=H_LF;
						r->has_content_len=1;
						break;
					default:
						LM_ERR("bad Content-Length header value, unexpected "
								"char %c in state %d\n", *p, r->state);
						r->state=H_SKIP; /* try to find another?*/
				}
				p++;
				break;

			default:
				LM_CRIT("unexpected state %d\n", r->state);
				abort();
		}
	}
	if (r->state == H_SKIP_EMPTY_CRLF_FOUND && tcp_crlf_drop) {
		r->state = H_SKIP_EMPTY;
		r->complete = 1;
		r->has_content_len = 1; /* hack to avoid error check */
	}
skip:
	r->parsed=p;
	return bytes;
}


/* Responsible for reading the request
 *	* if returns >= 0 : the connection will be released
 *	* if returns <  0 : the connection will be released as BAD / broken
 */
static int tcp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	long size;
	struct tcp_req* req;
	char c;
	struct receive_info local_rcv;
	char *msg_buf;
	int msg_len;

	bytes=-1;
	total_bytes=0;

	if (con->con_req) {
		req=con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&current_req, 0);
		req=&current_req;
	}

#ifdef USE_TLS
	if (con->type==PROTO_TLS){
		if (tls_fix_read_conn(con)!=0){
			goto error;
		}
		if(con->state!=S_CONN_OK) goto done; /* not enough data */
	}
#endif

again:
	if(req->error==TCP_REQ_OK){
		bytes=tcp_read_headers(con,req);
//#ifdef EXTRA_DEBUG
					/* if timeout state=0; goto end__req; */
		LM_DBG("read= %d bytes, parsed=%d, state=%d, error=%d\n",
				bytes, (int)(req->parsed-req->start), req->state,
				req->error );
		LM_DBG("last char=0x%02X, parsed msg=\n%.*s\n",
				*(req->parsed-1), (int)(req->parsed-req->start),
				req->start);
//#endif
		if (bytes==-1){
			LM_ERR("failed to read \n");
			goto error;
		}
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
	if (req->complete){
#ifdef EXTRA_DEBUG
		LM_DBG("end of header part\n");
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ", &con->rcv.src_ip, "\n");
		LM_DBG("headers:\n%.*s.\n",(int)(req->body-req->start), req->start);
#endif
		if (req->has_content_len){
			LM_DBG("content-length= %d\n", req->content_len);
#ifdef EXTRA_DEBUG
			LM_DBG("body:\n%.*s\n", req->content_len,req->body);
#endif
		}else{
			req->error=TCP_REQ_BAD_LEN;
			LM_ERR("content length not present or unparsable\n");
			goto error;
		}

		/* update the timeout - we succesfully read the request */
		con->timeout=get_ticks()+tcp_max_msg_time;

		/* if we are here everything is nice and ok*/
		update_stat( pt[process_no].load, +1 );
#ifdef EXTRA_DEBUG
		LM_DBG("calling receive_msg(%p, %d, )\n",
				req->start, (int)(req->parsed-req->start));
#endif
		/* rcv.bind_address should always be !=0 */
		bind_address=con->rcv.bind_address;
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */
		c=*req->parsed; /* ugly hack: zero term the msg & save the
						   previous char, req->parsed should be ok
						   because we always alloc BUF_SIZE+1 */
		*req->parsed=0;

		/* prepare for next request */
		size=req->pos-req->parsed;

		if (req->state==H_PING_CRLFCRLF) {
			/* we send the reply */
			if (proto_tcp_send( con->rcv.bind_address, CRLF, CRLF_LEN,
			&(con->rcv.src_su), con->rcv.proto_reserved1) < 0) {
				LM_ERR("CRLF pong - tcp_send() failed\n");
			}
			if (!size)
				goto done;
		} else {
			msg_buf = req->start;
			msg_len = req->parsed-req->start;
			local_rcv = con->rcv;

			if (!size) {
				/* did not read any more things -  we can release
				 * the connection */
				LM_DBG("We're releasing the connection in state %d \n",
					con->state);
				if (req != &current_req) {
					/* we have the buffer in the connection tied buff -
					 *	detach it , release the conn and free it afterwards */
					con->con_req = NULL;
				}
				goto done;
			} else {
				LM_DBG("We still have things on the pipe - "
					"keeping connection \n");
			}

			if (receive_msg(msg_buf, msg_len,
				&local_rcv) <0)
					LM_ERR("receive_msg failed \n");

			if (!size && req != &current_req) {
				/* if we no longer need this tcp_req
				 * we can free it now */
				pkg_free(req);
			}
		}

		*req->parsed=c;

		update_stat( pt[process_no].load, -1 );

		if (size) memmove(req->buf, req->parsed, size);
#ifdef EXTRA_DEBUG
		LM_DBG("preparing for new request, kept %ld bytes\n", size);
#endif
		init_tcp_req(&current_req, size);
		con->msg_attempts = 0;

		/* if we still have some unparsed bytes, try to  parse them too*/
		if (size) goto again;
	} else {
		/* request not complete - check the if the thresholds are exceeded */

		con->msg_attempts ++;
		if (con->msg_attempts == tcp_max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			goto error;
		}

		if (req == &current_req) {
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

			if (req->start != req->buf)
				con->con_req->start = con->con_req->buf +(req->start-req->buf);
			else
				con->con_req->start = con->con_req->buf;

			if (req->parsed != req->buf)
				con->con_req->parsed =con->con_req->buf+(req->parsed-req->buf);
			else
				con->con_req->parsed = con->con_req->buf;

			if (req->body != 0) {
				con->con_req->body = con->con_req->buf + (req->body-req->buf);
			} else
				con->con_req->body = 0;

			con->con_req->complete=req->complete;
			con->con_req->has_content_len=req->has_content_len;
			con->con_req->content_len=req->content_len;
			con->con_req->bytes_to_go=req->bytes_to_go;
			con->con_req->error = req->error;
			con->con_req->state = req->state;
			/* req will be reset on the next usage */
		}
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




