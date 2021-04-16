/*
 * Copyright (C) 2014-2015 OpenSIPS Project
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/uio.h>  /* writev*/
#include <netdb.h>
#include <stdlib.h> /*exit() */
#include <time.h>   /*time() */
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../globals.h"
#include "../locking.h"
#include "../socket_info.h"
#include "../ut.h"
#include "../pt.h"
#include "../pt_load.h"
#include "../daemonize.h"
#include "../reactor.h"
#include "../timer.h"
#include "../ipc.h"

#include "tcp_passfd.h"
#include "net_tcp_proc.h"
#include "net_tcp_report.h"
#include "net_tcp.h"
#include "tcp_conn.h"
#include "trans.h"

struct struct_hist_list *con_hist;

enum tcp_worker_state { STATE_INACTIVE=0, STATE_ACTIVE, STATE_DRAINING};

/* definition of a TCP worker */
struct tcp_worker {
	pid_t pid;
	int unix_sock;		/*!< Main-Worker comm, worker end */
	int main_unix_sock;	/*!< Main-Worker comm, TCP Main end */
	int busy;
	enum tcp_worker_state state;
	int n_reqs;		/*!< number of requests serviced so far */
};

/* definition of a TCP partition */
struct tcp_partition {
	/*! \brief connection hash table (after ip&port), includes also aliases */
	struct tcp_conn_alias** tcpconn_aliases_hash;
	/*! \brief connection hash table (after connection id) */
	struct tcp_connection** tcpconn_id_hash;
	gen_lock_t* tcpconn_lock;
};


/* array of TCP workers - to be used only by TCP MAIN */
struct tcp_worker *tcp_workers=0;

/* unique for each connection, used for
 * quickly finding the corresponding connection for a reply */
static unsigned int* connection_id=0;

/* array of TCP partitions */
static struct tcp_partition tcp_parts[TCP_PARTITION_SIZE];

/*!< tcp protocol number as returned by getprotobyname */
static int tcp_proto_no=-1;

/* communication socket from generic proc to TCP main */
int unix_tcp_sock = -1;

/*!< current number of open connections */
static int tcp_connections_no = 0;

/*!< by default don't accept aliases */
int tcp_accept_aliases=0;
int tcp_connect_timeout=DEFAULT_TCP_CONNECT_TIMEOUT;
int tcp_con_lifetime=DEFAULT_TCP_CONNECTION_LIFETIME;
int tcp_socket_backlog=DEFAULT_TCP_SOCKET_BACKLOG;
/*!< by default choose the best method */
enum poll_types tcp_poll_method=0;
int tcp_max_connections=DEFAULT_TCP_MAX_CONNECTIONS;
/* the configured/starting number of TCP workers */
int tcp_workers_no = UDP_WORKERS_NO;
/* the maximum numbers of TCP workers */
int tcp_workers_max_no;
/* the name of the auto-scaling profile (optional) */
char* tcp_auto_scaling_profile = NULL;
/* Max number of seconds that we except a full SIP message
 * to arrive in - anything above will lead to the connection to closed */
int tcp_max_msg_time = TCP_CHILD_MAX_MSG_TIME;


#ifdef HAVE_SO_KEEPALIVE
    int tcp_keepalive = 1;
#else
    int tcp_keepalive = 0;
#endif
int tcp_keepcount = 0;
int tcp_keepidle = 0;
int tcp_keepinterval = 0;

/*!< should we allow opening a new TCP conn when sending data 
 * over UAC branches? - branch flag to be set in the SIP messages */
int tcp_no_new_conn_bflag = 0;
/*!< should we allow opening a new TCP conn when sending data 
 * back to UAS (replies)? - msg flag to be set in the SIP messages */
int tcp_no_new_conn_rplflag = 0;
/*!< should a new TCP conn be open if needed? - variable used to used for
 * signalizing between SIP layer (branch flag) and TCP layer (tcp_send func)*/
int tcp_no_new_conn = 0;

/* if the TCP net layer is on or off (if no TCP based protos are loaded) */
static int tcp_disabled = 1;

/* is the process TCP MAIN ? */
int is_tcp_main = 0;

/* the ID of the TCP conn used for the last send operation in the
 * current process - attention, this is a really ugly HACK here */
unsigned int last_outgoing_tcp_id = 0;

static struct scaling_profile *s_profile = NULL;

/****************************** helper functions *****************************/
extern void handle_sigs(void);

static inline int init_sock_keepalive(int s)
{
	int optval;

	if (tcp_keepinterval || tcp_keepidle || tcp_keepcount) {
		tcp_keepalive = 1; /* force on */
	}

#ifdef HAVE_SO_KEEPALIVE
	if ((optval = tcp_keepalive)) {
		if (setsockopt(s,SOL_SOCKET,SO_KEEPALIVE,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to enable SO_KEEPALIVE: %s\n",
				strerror(errno));
			return -1;
		}
		LM_DBG("TCP keepalive enabled on socket %d\n",s);
	}
#endif
#ifdef HAVE_TCP_KEEPINTVL
	if ((optval = tcp_keepinterval)) {
		if (setsockopt(s,IPPROTO_TCP,TCP_KEEPINTVL,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to set keepalive probes interval: %s\n",
				strerror(errno));
		}
	}
#endif
#ifdef HAVE_TCP_KEEPIDLE
	if ((optval = tcp_keepidle)) {
		if (setsockopt(s,IPPROTO_TCP,TCP_KEEPIDLE,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to set keepalive idle interval: %s\n",
				strerror(errno));
		}
	}
#endif
#ifdef HAVE_TCP_KEEPCNT
	if ((optval = tcp_keepcount)) {
		if (setsockopt(s,IPPROTO_TCP,TCP_KEEPCNT,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to set maximum keepalive count: %s\n",
				strerror(errno));
		}
	}
#endif
	return 0;
}


/*! \brief Set all socket/fd options:  disable nagle, tos lowdelay,
 * non-blocking
 * \return -1 on error */
int tcp_init_sock_opt(int s)
{
	int flags;
	int optval;

#ifdef DISABLE_NAGLE
	flags=1;
	if ( (tcp_proto_no!=-1) && (setsockopt(s, tcp_proto_no , TCP_NODELAY,
					&flags, sizeof(flags))<0) ){
		LM_WARN("could not disable Nagle: %s\n", strerror(errno));
	}
#endif
	/* tos*/
	optval = tos;
	if (setsockopt(s, IPPROTO_IP, IP_TOS, (void*)&optval,sizeof(optval)) ==-1){
		LM_WARN("setsockopt tos: %s\n",	strerror(errno));
		/* continue since this is not critical */
	}

	if (probe_max_sock_buff(s,1,MAX_SEND_BUFFER_SIZE,BUFFER_INCREMENT)) {
		LM_WARN("setsockopt tcp snd buff: %s\n",	strerror(errno));
		/* continue since this is not critical */
	}

	init_sock_keepalive(s);

	/* non-blocking */
	flags=fcntl(s, F_GETFL);
	if (flags==-1){
		LM_ERR("fcntl failed: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	if (fcntl(s, F_SETFL, flags|O_NONBLOCK)==-1){
		LM_ERR("set non-blocking failed: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	return 0;
error:
	return -1;
}


/*! \brief blocking connect on a non-blocking fd; it will timeout after
 * tcp_connect_timeout
 * if BLOCKING_USE_SELECT and HAVE_SELECT are defined it will internally
 * use select() instead of poll (bad if fd > FD_SET_SIZE, poll is preferred)
 */
int tcp_connect_blocking_timeout(int fd, const struct sockaddr *servaddr,
											socklen_t addrlen, int timeout)
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
	int err;
	struct timeval begin;
	unsigned int err_len;
	int poll_err;
	char *ip;
	unsigned short port;

	poll_err=0;
	to = timeout*1000;

	if (gettimeofday(&(begin), NULL)) {
		LM_ERR("Failed to get TCP connect start time\n");
		goto error;
	}

again:
	n=connect(fd, servaddr, addrlen);
	if (n==-1){
		if (errno==EINTR){
			elapsed=get_time_diff(&begin);
			if (elapsed<to) goto again;
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
		elapsed = get_time_diff(&begin);
		if (elapsed<to)
			to-=elapsed;
		else
			goto error_timeout;
#if defined(HAVE_SELECT) && defined(BLOCKING_USE_SELECT)
		sel_set=orig_set;
		timeout.tv_sec = to/1000000;
		timeout.tv_usec = to%1000000;
		n=select(fd+1, 0, &sel_set, 0, &timeout);
#else
		n=poll(&pf, 1, to/1000);
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
	LM_ERR("connect timed out, %d us elapsed out of %d us\n", elapsed,
		timeout*1000);
error:
	return -1;
end:
	return 0;
}

int tcp_connect_blocking(int fd, const struct sockaddr *servaddr,
															socklen_t addrlen)
{
	return tcp_connect_blocking_timeout(fd, servaddr, addrlen,
			tcp_connect_timeout);
}



static int send2worker(struct tcp_connection* tcpconn,int rw)
{
	int i;
	int min_busy;
	int idx;
	long response[2];

	min_busy=INT_MAX;
	idx=0;
	for (i=0; i<tcp_workers_max_no; i++){
		if (tcp_workers[i].state==STATE_ACTIVE) {
			if (!tcp_workers[i].busy){
				idx=i;
				min_busy=0;
				break;
			}else if (min_busy>tcp_workers[i].busy){
				min_busy=tcp_workers[i].busy;
				idx=i;
			}
		}
	}

	tcp_workers[idx].busy++;
	tcp_workers[idx].n_reqs++;
	if (min_busy) {
		LM_DBG("no free tcp receiver, connection passed to the least "
		       "busy one (proc #%d, %d con)\n", idx, min_busy);
	}
	LM_DBG("to tcp worker %d (%d), %p rw %d\n", idx,
		tcp_workers[idx].pid, tcpconn,rw);
	response[0]=(long)tcpconn;
	response[1]=rw;
	if (send_fd(tcp_workers[idx].unix_sock, response, sizeof(response),
			tcpconn->s)<=0){
		LM_ERR("send_fd failed\n");
		return -1;
	}

	return 0;
}



/********************** TCP conn management functions ************************/

/* initializes an already defined TCP listener */
int tcp_init_listener(struct socket_info *si)
{
	union sockaddr_union* addr;
	int optval;
#ifdef DISABLE_NAGLE
	int flag;
	struct protoent* pe;

	if (tcp_proto_no==-1){ /* if not already set */
		pe=getprotobyname("tcp");
		if (pe==0){
			LM_ERR("could not get TCP protocol number\n");
			tcp_proto_no=-1;
		}else{
			tcp_proto_no=pe->p_proto;
		}
	}
#endif

	addr = &si->su;
	if (init_su(addr, &si->address, si->port_no)<0){
		LM_ERR("could no init sockaddr_union\n");
		goto error;
	}
	si->socket = socket(AF2PF(addr->s.sa_family), SOCK_STREAM, 0);
	if (si->socket==-1){
		LM_ERR("socket failed with [%s]\n", strerror(errno));
		goto error;
	}
#ifdef DISABLE_NAGLE
	flag=1;
	if ( (tcp_proto_no!=-1) &&
		 (setsockopt(si->socket, tcp_proto_no , TCP_NODELAY,
					 &flag, sizeof(flag))<0) ){
		LM_ERR("could not disable Nagle: %s\n",strerror(errno));
	}
#endif

#if  !defined(TCP_DONT_REUSEADDR)
	/* Stevens, "Network Programming", Section 7.5, "Generic Socket
	 * Options": "...server started,..a child continues..on existing
	 * connection..listening server is restarted...call to bind fails
	 * ... ALL TCP servers should specify the SO_REUSEADDRE option
	 * to allow the server to be restarted in this situation
	 */
	optval=1;
	if (setsockopt(si->socket, SOL_SOCKET, SO_REUSEADDR,
	(void*)&optval, sizeof(optval))==-1) {
		LM_ERR("setsockopt failed with [%s]\n", strerror(errno));
		goto error;
	}
#endif
	/* tos */
	optval = tos;
	if (setsockopt(si->socket, IPPROTO_IP, IP_TOS, (void*)&optval,
	sizeof(optval)) ==-1){
		LM_WARN("setsockopt tos: %s\n", strerror(errno));
		/* continue since this is not critical */
	}

	if (probe_max_sock_buff(si->socket,1,MAX_SEND_BUFFER_SIZE,
	BUFFER_INCREMENT)) {
		LM_WARN("setsockopt tcp snd buff: %s\n",strerror(errno));
		/* continue since this is not critical */
	}

	init_sock_keepalive(si->socket);
	if (bind(si->socket, &addr->s, sockaddru_len(*addr))==-1){
		LM_ERR("bind(%x, %p, %d) on %s:%d : %s\n",
 				si->socket, &addr->s,
 				(unsigned)sockaddru_len(*addr),
 				si->address_str.s,
				si->port_no,
 				strerror(errno));
		goto error;
	}
	if (listen(si->socket, tcp_socket_backlog)==-1){
		LM_ERR("listen(%x, %p, %d) on %s: %s\n",
				si->socket, &addr->s,
				(unsigned)sockaddru_len(*addr),
				si->address_str.s,
				strerror(errno));
		goto error;
	}

	return 0;
error:
	if (si->socket!=-1){
		close(si->socket);
		si->socket=-1;
	}
	return -1;
}


/*! \brief finds a connection, if id=0 return NULL
 * \note WARNING: unprotected (locks) use tcpconn_get unless you really
 * know what you are doing */
static struct tcp_connection* _tcpconn_find(unsigned int id)
{
	struct tcp_connection *c;
	unsigned hash;

	if (id){
		hash=tcp_id_hash(id);
		for (c=TCP_PART(id).tcpconn_id_hash[hash]; c; c=c->id_next){
#ifdef EXTRA_DEBUG
			LM_DBG("c=%p, c->id=%u, port=%d\n",c, c->id, c->rcv.src_port);
			print_ip("ip=", &c->rcv.src_ip, "\n");
#endif
			if ((id==c->id)&&(c->state!=S_CONN_BAD)) return c;
		}
	}
	return 0;
}


/* returns the correlation ID of a TCP connection */
int tcp_get_correlation_id( unsigned int id, unsigned long long *cid)
{
	struct tcp_connection* c;

	TCPCONN_LOCK(id);
	if ( (c=_tcpconn_find(id))!=NULL ) {
		*cid = c->cid;
		TCPCONN_UNLOCK(id);
		return 0;
	}
	*cid = 0;
	TCPCONN_UNLOCK(id);
	return -1;
}


/*! \brief _tcpconn_find with locks and acquire fd */
int tcp_conn_get(unsigned int id, struct ip_addr* ip, int port,
		enum sip_protos proto, void *proto_extra_id,
		struct tcp_connection** conn, int* conn_fd)
{
	struct tcp_connection* c;
	struct tcp_connection* tmp;
	struct tcp_conn_alias* a;
	unsigned hash;
	long response[2];
	unsigned int part;
	int n;
	int fd;

	if (id) {
		part = id;
		TCPCONN_LOCK(part);
		if ( (c=_tcpconn_find(part))!=NULL )
			goto found;
		TCPCONN_UNLOCK(part);
	}

	/* continue search based on IP address + port + transport */
#ifdef EXTRA_DEBUG
	LM_DBG("%d  port %u\n",id, port);
	if (ip) print_ip("tcpconn_find: ip ", ip, "\n");
#endif
	if (ip){
		hash=tcp_addr_hash(ip, port);
		for( part=0 ; part<TCP_PARTITION_SIZE ; part++ ) {
			TCPCONN_LOCK(part);
			for (a=TCP_PART(part).tcpconn_aliases_hash[hash]; a; a=a->next) {
#ifdef EXTRA_DEBUG
				LM_DBG("a=%p, c=%p, c->id=%u, alias port= %d port=%d\n",
					a, a->parent, a->parent->id, a->port,
					a->parent->rcv.src_port);
				print_ip("ip=",&a->parent->rcv.src_ip,"\n");
#endif
				c = a->parent;
				if (c->state != S_CONN_BAD &&
				    c->flags&F_CONN_INIT &&
				    port == a->port &&
				    proto == c->type &&
				    ip_addr_cmp(ip, &c->rcv.src_ip) &&
				    (proto_extra_id==NULL ||
				    protos[proto].net.conn_match==NULL ||
				    protos[proto].net.conn_match( c, proto_extra_id)) )
					goto found;
			}
			TCPCONN_UNLOCK(part);
		}
	}

	/* not found */
	*conn = NULL;
	if (conn_fd) *conn_fd = -1;
	return 0;

found:
	c->refcnt++;
	TCPCONN_UNLOCK(part);
	sh_log(c->hist, TCP_REF, "tcp_conn_get, (%d)", c->refcnt);

	LM_DBG("con found in state %d\n",c->state);

	if (c->state!=S_CONN_OK || conn_fd==NULL) {
		/* no need to acquired, just return the conn with an invalid fd */
		*conn = c;
		if (conn_fd) *conn_fd = -1;
		return 1;
	}

	if (c->proc_id == process_no) {
		LM_DBG("tcp connection found (%p) already in this process ( %d ) ,"
			" fd = %d\n", c, c->proc_id, c->fd);
		/* we already have the connection in this worker's reactor, */
		/* no need to acquire FD */
		*conn = c;
		*conn_fd = c->fd;
		return 1;
	}

	/* acquire the fd for this connection too */
	LM_DBG("tcp connection found (%p), acquiring fd\n", c);
	/* get the fd */
	response[0]=(long)c;
	response[1]=CONN_GET_FD;
	n=send_all(unix_tcp_sock, response, sizeof(response));
	if (n<=0){
		LM_ERR("failed to get fd(write):%s (%d)\n",
				strerror(errno), errno);
		n=-1;
		goto error;
	}
	LM_DBG("c= %p, n=%d, Usock=%d\n", c, n, unix_tcp_sock);
	tmp = c;
	n=receive_fd(unix_tcp_sock, &c, sizeof(c), &fd, MSG_WAITALL);
	if (n<=0){
		LM_ERR("failed to get fd(receive_fd):"
			" %s (%d)\n", strerror(errno), errno);
		n=-1;
		goto error;
	}
	if (c!=tmp){
		LM_CRIT("got different connection:"
			"  %p (id= %u, refcnt=%d state=%d != "
			"  %p (id= %u, refcnt=%d state=%d (n=%d)\n",
			  c,   c->id,   c->refcnt,   c->state,
			  tmp, tmp->id, tmp->refcnt, tmp->state, n
		   );
		n=-1; /* fail */
		close(fd);
		goto error;
	}
	LM_DBG("after receive_fd: c= %p n=%d fd=%d\n",c, n, fd);

	*conn = c;
	*conn_fd = fd;

	return 1;
error:
	tcpconn_put(c);
	sh_log(c->hist, TCP_UNREF, "tcp_conn_get, (%d)", c->refcnt);
	*conn = NULL;
	*conn_fd = -1;
	return -1;
}


/* used to tune the tcp_connection attributes - not to be used inside the
   network layer, but onlu from the above layer (otherwise we may end up
   in strange deadlocks!) */
int tcp_conn_fcntl(struct receive_info *rcv, int attr, void *value)
{
	struct tcp_connection *con;

	switch (attr) {
	case DST_FCNTL_SET_LIFETIME:
		/* set connection timeout */
		TCPCONN_LOCK(rcv->proto_reserved1);
		con =_tcpconn_find(rcv->proto_reserved1);
		if (!con) {
			LM_ERR("Strange, tcp conn not found (id=%u)\n",
				rcv->proto_reserved1);
		} else {
			tcp_conn_set_lifetime( con, (int)(long)(value));
		}
		TCPCONN_UNLOCK(rcv->proto_reserved1);
		return 0;
	default:
		LM_ERR("unsupported operation %d on conn\n",attr);
		return -1;
	}
	return -1;
}


static struct tcp_connection* tcpconn_add(struct tcp_connection *c)
{
	unsigned hash;

	if (c){
		TCPCONN_LOCK(c->id);
		/* add it at the beginning of the list*/
		hash=tcp_id_hash(c->id);
		c->id_hash=hash;
		tcpconn_listadd(TCP_PART(c->id).tcpconn_id_hash[hash], c, id_next,
			id_prev);

		hash=tcp_addr_hash(&c->rcv.src_ip, c->rcv.src_port);
		/* set the first alias */
		c->con_aliases[0].port=c->rcv.src_port;
		c->con_aliases[0].hash=hash;
		c->con_aliases[0].parent=c;
		tcpconn_listadd(TCP_PART(c->id).tcpconn_aliases_hash[hash],
			&c->con_aliases[0], next, prev);
		c->aliases++;
		TCPCONN_UNLOCK(c->id);
		LM_DBG("hashes: %d, %d\n", hash, c->id_hash);
		return c;
	}else{
		LM_CRIT("null connection pointer\n");
		return 0;
	}
}

/*! \brief unsafe tcpconn_rm version (nolocks) */
static void _tcpconn_rm(struct tcp_connection* c)
{
	int r;

	tcpconn_listrm(TCP_PART(c->id).tcpconn_id_hash[c->id_hash], c,
		id_next, id_prev);
	/* remove all the aliases */
	for (r=0; r<c->aliases; r++)
		tcpconn_listrm(TCP_PART(c->id).tcpconn_aliases_hash[c->con_aliases[r].hash],
			&c->con_aliases[r], next, prev);
	lock_destroy(&c->write_lock);

	if (protos[c->type].net.conn_clean)
		protos[c->type].net.conn_clean(c);

#ifdef DBG_TCPCON
	sh_log(c->hist, TCP_DESTROY, "type=%d", c->type);
	sh_unref(c->hist);
	c->hist = NULL;
#endif

	shm_free(c);
}


#if 0
static void tcpconn_rm(struct tcp_connection* c)
{
	int r;

	TCPCONN_LOCK(c->id);
	tcpconn_listrm(TCP_PART(c->id).tcpconn_id_hash[c->id_hash], c,
		id_next, id_prev);
	/* remove all the aliases */
	for (r=0; r<c->aliases; r++)
		tcpconn_listrm(TCP_PART(c->id).tcpconn_aliases_hash
			[c->con_aliases[r].hash],
			&c->con_aliases[r], next, prev);
	TCPCONN_UNLOCK(c->id);
	lock_destroy(&c->write_lock);

	if (protos[c->type].net.conn_clean)
		protos[c->type].net.conn_clean(c);

	shm_free(c);
}
#endif


/*! \brief add port as an alias for the "id" connection
 * \return 0 on success,-1 on failure */
int tcpconn_add_alias(unsigned int id, int port, int proto)
{
	struct tcp_connection* c;
	unsigned hash;
	struct tcp_conn_alias* a;

	a=0;
	/* fix the port */
	port=port ? port : protos[proto].default_port ;
	TCPCONN_LOCK(id);
	/* check if alias already exists */
	c=_tcpconn_find(id);
	if (c){
		hash=tcp_addr_hash(&c->rcv.src_ip, port);
		/* search the aliases for an already existing one */
		for (a=TCP_PART(id).tcpconn_aliases_hash[hash]; a; a=a->next) {
			if (a->parent->state != S_CONN_BAD &&
			    port == a->port &&
			    proto == a->parent->type &&
			    ip_addr_cmp(&c->rcv.src_ip, &a->parent->rcv.src_ip)) {
				/* found */
				if (a->parent!=c) goto error_sec;
				else goto ok;
			}
		}
		if (c->aliases>=TCP_CON_MAX_ALIASES) goto error_aliases;
		c->con_aliases[c->aliases].parent=c;
		c->con_aliases[c->aliases].port=port;
		c->con_aliases[c->aliases].hash=hash;
		tcpconn_listadd(TCP_PART(id).tcpconn_aliases_hash[hash],
								&c->con_aliases[c->aliases], next, prev);
		c->aliases++;
	}else goto error_not_found;
ok:
	TCPCONN_UNLOCK(id);
#ifdef EXTRA_DEBUG
	if (a) LM_DBG("alias already present\n");
	else   LM_DBG("alias port %d for hash %d, id %u\n", port, hash, id);
#endif
	return 0;
error_aliases:
	TCPCONN_UNLOCK(id);
	LM_ERR("too many aliases for connection %p (%u)\n", c, id);
	return -1;
error_not_found:
	TCPCONN_UNLOCK(id);
	LM_ERR("no connection found for id %u\n",id);
	return -1;
error_sec:
	LM_WARN("possible port hijack attempt\n");
	LM_WARN("alias already present and points to another connection "
			"(%d : %d and %u : %d)\n", a->parent->id,  port, id, port);
	TCPCONN_UNLOCK(id);
	return -1;
}


void tcpconn_put(struct tcp_connection* c)
{
	TCPCONN_LOCK(c->id);
	c->refcnt--;
	TCPCONN_UNLOCK(c->id);
}


static inline void tcpconn_ref(struct tcp_connection* c)
{
	TCPCONN_LOCK(c->id);
	c->refcnt++;
	TCPCONN_UNLOCK(c->id);
}


static struct tcp_connection* tcpconn_new(int sock, union sockaddr_union* su,
							struct socket_info* si, int state, int flags)
{
	struct tcp_connection *c;
	union sockaddr_union local_su;
	unsigned int su_size;

	c=(struct tcp_connection*)shm_malloc(sizeof(struct tcp_connection));
	if (c==0){
		LM_ERR("shared memory allocation failure\n");
		return 0;
	}
	memset(c, 0, sizeof(struct tcp_connection)); /* zero init */
	c->s=sock;
	c->fd=-1; /* not initialized */
	if (lock_init(&c->write_lock)==0){
		LM_ERR("init lock failed\n");
		goto error0;
	}

	c->rcv.src_su=*su;

	c->refcnt=0;
	su2ip_addr(&c->rcv.src_ip, su);
	c->rcv.src_port=su_getport(su);
	c->rcv.bind_address = si;
	c->rcv.dst_ip = si->address;
	su_size = sockaddru_len(local_su);
	if (getsockname(sock, (struct sockaddr *)&local_su, &su_size)<0) {
		LM_ERR("failed to get info on received interface/IP %d/%s\n",
			errno, strerror(errno));
		goto error;
	}
	c->rcv.dst_port = su_getport(&local_su);
	print_ip("tcpconn_new: new tcp connection to: ", &c->rcv.src_ip, "\n");
	LM_DBG("on port %d, proto %d\n", c->rcv.src_port, si->proto);
	c->id=(*connection_id)++;
	c->cid = (unsigned long long)c->id
				| ( (unsigned long long)(startup_time&0xFFFFFF) << 32 )
					| ( (unsigned long long)(rand()&0xFF) << 56 );

	c->rcv.proto_reserved1=0; /* this will be filled before receive_message*/
	c->rcv.proto_reserved2=0;
	c->state=state;
	c->extra_data=0;
	c->type = si->proto;
	c->rcv.proto = si->proto;
	/* start with the default conn lifetime */
	c->lifetime = get_ticks()+tcp_con_lifetime;
	c->flags|=F_CONN_REMOVED|flags;
#ifdef DBG_TCPCON
	c->hist = sh_push(c, con_hist);
#endif

	tcp_connections_no++;
	return c;

error:
	lock_destroy(&c->write_lock);
error0:
	shm_free(c);
	return 0;
}


/* creates a new tcp connection structure and informs the TCP Main on that
 * a +1 ref is set for the new conn !
 * IMPORTANT - the function assumes you want to create a new TCP conn as
 * a result of a connect operation - the conn will be set as connect !!
 * Accepted connection are triggered internally only */
struct tcp_connection* tcp_conn_create(int sock, union sockaddr_union* su,
											struct socket_info* si, int state)
{
	struct tcp_connection *c;

	/* create the connection structure */
	c = tcp_conn_new(sock, su, si, state);
	if (c==NULL)
		return NULL;

	return (tcp_conn_send(c) == 0 ? c : NULL);
}

struct tcp_connection* tcp_conn_new(int sock, union sockaddr_union* su,
		struct socket_info* si, int state)
{
	struct tcp_connection *c;

	/* create the connection structure */
	c = tcpconn_new(sock, su, si, state, 0);
	if (c==NULL) {
		LM_ERR("tcpconn_new failed\n");
		return NULL;
	}
	c->refcnt++; /* safe to do it w/o locking, it's not yet
					available to the rest of the world */
	sh_log(c->hist, TCP_REF, "connect, (%d)", c->refcnt);

	if (protos[c->type].net.conn_init &&
			protos[c->type].net.conn_init(c) < 0) {
		LM_ERR("failed to do proto %d specific init for conn %p\n",
				c->type, c);
		tcp_conn_destroy(c);
		return NULL;
	}
	c->flags |= F_CONN_INIT;

	return c;
}


/* sends a new connection from a worker to main */
int tcp_conn_send(struct tcp_connection *c)
{
	long response[2];
	int n, fd;

	/* inform TCP main about this new connection */
	if (c->state==S_CONN_CONNECTING) {
		/* store the local fd now, before TCP main overwrites it */
		fd = c->s;
		response[0]=(long)c;
		response[1]=ASYNC_CONNECT;
		n=send_fd(unix_tcp_sock, response, sizeof(response), fd);
		if (n<=0) {
			LM_ERR("Failed to send the socket to main for async connection\n");
			goto error;
		}
		close(fd);
	} else {
		response[0]=(long)c;
		response[1]=CONN_NEW;
		n=send_fd(unix_tcp_sock, response, sizeof(response), c->s);
		if (n<=0){
			LM_ERR("failed send_fd: %s (%d)\n", strerror(errno), errno);
			goto error;
		}
	}

	return 0;
error:
	/* no reporting as closed, as PROTO layer did not reporte it as
	 * OPEN yet */
	_tcpconn_rm(c);
	tcp_connections_no--;
	return -1;
}


static inline void tcpconn_destroy(struct tcp_connection* tcpconn)
{
	int fd;
	int unsigned id = tcpconn->id;

	TCPCONN_LOCK(id); /*avoid races w/ tcp_send*/
	tcpconn->refcnt--;
	if (tcpconn->refcnt==0){
		LM_DBG("destroying connection %p, flags %04x\n",
				tcpconn, tcpconn->flags);
		fd=tcpconn->s;
		/* no reporting here - the tcpconn_destroy() function is called
		 * from the TCP_MAIN reactor when handling connectioned received
		 * from a worker; and we generate the CLOSE reports from WORKERs */
		_tcpconn_rm(tcpconn);
		if (fd >= 0)
			close(fd);
		tcp_connections_no--;
	}else{
		/* force timeout */
		tcpconn->lifetime=0;
		tcpconn->state=S_CONN_BAD;
		LM_DBG("delaying (%p, flags %04x) ref = %d ...\n",
				tcpconn, tcpconn->flags, tcpconn->refcnt);

	}
	TCPCONN_UNLOCK(id);
}

/* wrapper to the internally used function */
void tcp_conn_destroy(struct tcp_connection* tcpconn)
{
	tcp_trigger_report(tcpconn, TCP_REPORT_CLOSE,
				"Closed by Proto layer");
	sh_log(tcpconn->hist, TCP_UNREF, "tcp_conn_destroy, (%d)", tcpconn->refcnt);
	return tcpconn_destroy(tcpconn);
}


/************************ TCP MAIN process functions ************************/

/*! \brief
 * handles a new connection, called internally by tcp_main_loop/handle_io.
 * \param si - pointer to one of the tcp socket_info structures on which
 *              an io event was detected (connection attempt)
 * \return  handle_* return convention: -1 on error, 0 on EAGAIN (no more
 *           io events queued), >0 on success. success/error refer only to
 *           the accept.
 */
static inline int handle_new_connect(struct socket_info* si)
{
	union sockaddr_union su;
	struct tcp_connection* tcpconn;
	socklen_t su_len = sizeof(su);
	int new_sock;
	unsigned int id;

	/* coverity[overrun-buffer-arg: FALSE] - union has 28 bytes, CID #200070 */
	new_sock=accept(si->socket, &(su.s), &su_len);
	if (new_sock==-1){
		if ((errno==EAGAIN)||(errno==EWOULDBLOCK))
			return 0;
		LM_ERR("failed to accept connection(%d): %s\n", errno, strerror(errno));
		return -1;
	}
	if (tcp_connections_no>=tcp_max_connections){
		LM_ERR("maximum number of connections exceeded: %d/%d\n",
					tcp_connections_no, tcp_max_connections);
		close(new_sock);
		return 1; /* success, because the accept was successful */
	}
	if (tcp_init_sock_opt(new_sock)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		close(new_sock);
		return 1; /* success, because the accept was successful */
	}

	/* add socket to list */
	tcpconn=tcpconn_new(new_sock, &su, si, S_CONN_OK, F_CONN_ACCEPTED);
	if (tcpconn){
		tcpconn->refcnt++; /* safe, not yet available to the
							  outside world */
		sh_log(tcpconn->hist, TCP_REF, "accept, (%d)", tcpconn->refcnt);
		tcpconn_add(tcpconn);
		LM_DBG("new connection: %p %d flags: %04x\n",
				tcpconn, tcpconn->s, tcpconn->flags);
		/* pass it to a workerr */
		sh_log(tcpconn->hist, TCP_SEND2CHILD, "accept");
		if(send2worker(tcpconn,IO_WATCH_READ)<0){
			LM_ERR("no TCP workers available\n");
			id = tcpconn->id;
			sh_log(tcpconn->hist, TCP_UNREF, "accept, (%d)", tcpconn->refcnt);
			TCPCONN_LOCK(id);
			tcpconn->refcnt--;
			if (tcpconn->refcnt==0){
				/* no close to report here as the connection was not yet
				 * reported as OPEN by the proto layer...this sucks a bit */
				_tcpconn_rm(tcpconn);
				close(new_sock/*same as tcpconn->s*/);
			}else tcpconn->lifetime=0; /* force expire */
			TCPCONN_UNLOCK(id);
		}
	}else{ /*tcpconn==0 */
		LM_ERR("tcpconn_new failed, closing socket\n");
		close(new_sock);
	}
	return 1; /* accept() was successful */
}


/*! \brief
 * handles an io event on one of the watched tcp connections
 *
 * \param    tcpconn - pointer to the tcp_connection for which we have an io ev.
 * \param    fd_i    - index in the fd_array table (needed for delete)
 * \return   handle_* return convention, but on success it always returns 0
 *           (because it's one-shot, after a successful execution the fd is
 *            removed from tcp_main's watch fd list and passed to a worker =>
 *            tcp_main is not interested in further io events that might be
 *            queued for this fd)
 */
inline static int handle_tcpconn_ev(struct tcp_connection* tcpconn, int fd_i,
																int event_type)
{
	int fd;
	int err;
	unsigned int id;
	unsigned int err_len;

	if (event_type == IO_WATCH_READ) {
		/* pass it to worker, so remove it from the io watch list */
		LM_DBG("data available on %p %d\n", tcpconn, tcpconn->s);
		if (reactor_del_reader(tcpconn->s, fd_i, 0)==-1)
			return -1;
		tcpconn->flags|=F_CONN_REMOVED_READ;
		tcpconn_ref(tcpconn); /* refcnt ++ */
		sh_log(tcpconn->hist, TCP_REF, "tcpconn read, (%d)", tcpconn->refcnt);
		sh_log(tcpconn->hist, TCP_SEND2CHILD, "read");
		if (send2worker(tcpconn,IO_WATCH_READ)<0){
			LM_ERR("no TCP workers available\n");
			id = tcpconn->id;
			TCPCONN_LOCK(id);
			tcpconn->refcnt--;
			sh_log(tcpconn->hist, TCP_UNREF, "tcpconn read, (%d)", tcpconn->refcnt);
			if (tcpconn->refcnt==0){
				fd=tcpconn->s;
				tcp_trigger_report(tcpconn, TCP_REPORT_CLOSE,
					"No worker for read");
				_tcpconn_rm(tcpconn);
				close(fd);
			}else tcpconn->lifetime=0; /* force expire*/
			TCPCONN_UNLOCK(id);
		}
		return 0; /* we are not interested in possibly queued io events,
					 the fd was either passed to a worker, or closed */
	} else {
		LM_DBG("connection %p fd %d is now writable\n", tcpconn, tcpconn->s);
		/* we received a write event */
		if (tcpconn->state==S_CONN_CONNECTING) {
			/* we're coming from an async connect & write
			 * let's see if we connected successfully */
			err_len=sizeof(err);
			if (getsockopt(tcpconn->s, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || \
					err != 0) {
				LM_DBG("Failed connection attempt\n");
				tcpconn_ref(tcpconn);
				sh_log(tcpconn->hist, TCP_REF, "tcpconn connect, (%d)", tcpconn->refcnt);
				reactor_del_all(tcpconn->s, fd_i, IO_FD_CLOSING);
				tcpconn->flags|=F_CONN_REMOVED;
				tcp_trigger_report(tcpconn, TCP_REPORT_CLOSE,
					"Async connect failed");
				tcpconn_destroy(tcpconn);
				sh_log(tcpconn->hist, TCP_UNREF, "tcpconn connect, (%d)", tcpconn->refcnt);
				return 0;
			}

			/* we successfully connected - further treat this case as if we
			 * were coming from an async write */
			tcpconn->state = S_CONN_OK;
			LM_DBG("Successfully completed previous async connect\n");

			/* now that we completed the async connection, we also need to
			 * listen for READ events, otherwise these will get lost */
			if (tcpconn->flags & F_CONN_REMOVED_READ) {
				reactor_add_reader( tcpconn->s, F_TCPCONN, RCT_PRIO_NET, tcpconn);
				tcpconn->flags&=~F_CONN_REMOVED_READ;
			}

			goto async_write;
		} else {
			/* we're coming from an async write -
			 * just pass to worker and have it write
			 * our TCP chunks */
async_write:
			/* no more write events for now */
			if (reactor_del_writer( tcpconn->s, fd_i, 0)==-1)
				return -1;
			tcpconn->flags|=F_CONN_REMOVED_WRITE;
			tcpconn_ref(tcpconn); /* refcnt ++ */
			sh_log(tcpconn->hist, TCP_REF, "tcpconn write, (%d)",
				tcpconn->refcnt);
			sh_log(tcpconn->hist, TCP_SEND2CHILD, "write");
			if (send2worker(tcpconn,IO_WATCH_WRITE)<0){
				LM_ERR("no TCP worker available\n");
				id = tcpconn->id;
				TCPCONN_LOCK(id);
				tcpconn->refcnt--;
				sh_log(tcpconn->hist, TCP_UNREF, "tcpconn write, (%d)",
					tcpconn->refcnt);
				if (tcpconn->refcnt==0){
					fd=tcpconn->s;
					tcp_trigger_report(tcpconn, TCP_REPORT_CLOSE,
						"No worker for write");
					_tcpconn_rm(tcpconn);
					close(fd);
				}else tcpconn->lifetime=0; /* force expire*/
				TCPCONN_UNLOCK(id);
			}
			return 0;
		}
	}
}


/*! \brief handles io from a tcp worker process
 * \param  tcp_c - pointer in the tcp_workers array, to the entry for
 *                 which an io event was detected
 * \param  fd_i  - fd index in the fd_array (useful for optimizing
 *                 io_watch_deletes)
 * \return handle_* return convention: -1 on error, 0 on EAGAIN (no more
 *           io events queued), >0 on success. success/error refer only to
 *           the reads from the fd.
 */
inline static int handle_tcp_worker(struct tcp_worker* tcp_c, int fd_i)
{
	struct tcp_connection* tcpconn;
	long response[2];
	int cmd;
	int bytes;

	if (tcp_c->unix_sock<=0){
		/* (we can't have a fd==0, 0 is never closed )*/
		LM_CRIT("fd %d for %d (pid %d)\n", tcp_c->unix_sock,
				(int)(tcp_c-&tcp_workers[0]), tcp_c->pid);
		goto error;
	}
	/* read until sizeof(response)
	 * (this is a SOCK_STREAM so read is not atomic) */
	bytes=recv_all(tcp_c->unix_sock, response, sizeof(response), MSG_DONTWAIT);
	if (bytes<(int)sizeof(response)){
		if (bytes==0){
			/* EOF -> bad, worker has died */
			if (get_osips_state()!=STATE_TERMINATING)
				LM_CRIT("dead tcp worker %d (EOF received), pid %d\n",
					(int)(tcp_c-&tcp_workers[0]), tcp_c->pid );
			/* don't listen on it any more */
			reactor_del_reader( tcp_c->unix_sock, fd_i, 0/*flags*/);
			/* eof. so no more io here, it's ok to return error */
			goto error;
		}else if (bytes<0){
			/* EAGAIN is ok if we try to empty the buffer
			 * e.g.: SIGIO_RT overflow mode or EPOLL ET */
			if ((errno!=EAGAIN) && (errno!=EWOULDBLOCK)){
				LM_CRIT("read from tcp worker %ld (pid %d) %s [%d]\n",
						(long)(tcp_c-&tcp_workers[0]), tcp_c->pid,
						strerror(errno), errno );
			}else{
				bytes=0;
			}
			/* try to ignore ? */
			goto end;
		}else{
			/* should never happen */
			LM_CRIT("too few bytes received (%d)\n", bytes );
			bytes=0; /* something was read so there is no error; otoh if
					  receive_fd returned less then requested => the receive
					  buffer is empty => no more io queued on this fd */
			goto end;
		}
	}

	LM_DBG("response= %lx, %ld from tcp worker %d (%d)\n",
		response[0], response[1], tcp_c->pid, (int)(tcp_c-&tcp_workers[0]));

	cmd=response[1];
	tcpconn=(struct tcp_connection*)response[0];
	if (tcpconn==0){
		/* should never happen */
		LM_CRIT("null tcpconn pointer received from tcp worker %d (pid %d):"
			"%lx, %lx\n", (int)(tcp_c-&tcp_workers[0]), tcp_c->pid,
			response[0], response[1]) ;
		goto end;
	}
	switch(cmd){
		case CONN_RELEASE:
			tcp_c->busy--;
			if (tcpconn->state==S_CONN_BAD){
				sh_log(tcpconn->hist, TCP_UNREF, "tcpworker release bad, (%d)", tcpconn->refcnt);
				tcpconn_destroy(tcpconn);
				break;
			}
			sh_log(tcpconn->hist, TCP_UNREF, "tcpworker release, (%d)", tcpconn->refcnt);
			tcpconn_put(tcpconn);
			/* must be after the de-ref*/
			reactor_add_reader( tcpconn->s, F_TCPCONN, RCT_PRIO_NET, tcpconn);
			tcpconn->flags&=~F_CONN_REMOVED_READ;
			break;
		case CONN_RELEASE_WRITE:
			tcp_c->busy--;
			if (tcpconn->state==S_CONN_BAD){
				sh_log(tcpconn->hist, TCP_UNREF, "tcpworker release write bad, (%d)", tcpconn->refcnt);
				tcpconn_destroy(tcpconn);
				break;
			}
			sh_log(tcpconn->hist, TCP_UNREF, "tcpworker release write, (%d)", tcpconn->refcnt);
			tcpconn_put(tcpconn);
			break;
		case ASYNC_WRITE:
			tcp_c->busy--;
			/* fall through*/
		case ASYNC_WRITE2:
			if (tcpconn->state==S_CONN_BAD){
				sh_log(tcpconn->hist, TCP_UNREF, "tcpworker async write bad, (%d)", tcpconn->refcnt);
				tcpconn_destroy(tcpconn);
				break;
			}
			sh_log(tcpconn->hist, TCP_UNREF, "tcpworker async write, (%d)", tcpconn->refcnt);
			tcpconn_put(tcpconn);
			/* must be after the de-ref*/
			reactor_add_writer( tcpconn->s, F_TCPCONN, RCT_PRIO_NET, tcpconn);
			tcpconn->flags&=~F_CONN_REMOVED_WRITE;
			break;
		case CONN_ERROR:
		case CONN_DESTROY:
		case CONN_EOF:
			/* WARNING: this will auto-dec. refcnt! */
			tcp_c->busy--;
			/* fall through*/
		case CONN_ERROR2:
			if ((tcpconn->flags & F_CONN_REMOVED) != F_CONN_REMOVED &&
				(tcpconn->s!=-1)){
				reactor_del_all( tcpconn->s, -1, IO_FD_CLOSING);
				tcpconn->flags|=F_CONN_REMOVED;
			}
			sh_log(tcpconn->hist, TCP_UNREF, "tcpworker destroy, (%d)", tcpconn->refcnt);
			tcpconn_destroy(tcpconn); /* closes also the fd */
			break;
		default:
			LM_CRIT("unknown cmd %d from tcp worker %d (%d)\n",
				cmd, tcp_c->pid, (int)(tcp_c-&tcp_workers[0]));
	}
end:
	return bytes;
error:
	return -1;
}


/*! \brief handles io from a "generic" ser process (get fd or new_fd from a tcp_send)
 *
 * \param p     - pointer in the ser processes array (pt[]), to the entry for
 *                 which an io event was detected
 * \param fd_i  - fd index in the fd_array (useful for optimizing
 *                 io_watch_deletes)
 * \return  handle_* return convention:
 *          - -1 on error reading from the fd,
 *          -  0 on EAGAIN  or when no  more io events are queued
 *             (receive buffer empty),
 *          -  >0 on successful reads from the fd (the receive buffer might
 *             be non-empty).
 */
inline static int handle_worker(struct process_table* p, int fd_i)
{
	struct tcp_connection* tcpconn;
	long response[2];
	int cmd;
	int bytes;
	int ret;
	int fd;

	ret=-1;
	if (p->unix_sock<=0){
		/* (we can't have a fd==0, 0 is never closed )*/
		LM_CRIT("fd %d for %d (pid %d)\n",
				p->unix_sock, (int)(p-&pt[0]), p->pid);
		goto error;
	}

	/* get all bytes and the fd (if transmitted)
	 * (this is a SOCK_STREAM so read is not atomic) */
	bytes=receive_fd(p->unix_sock, response, sizeof(response), &fd,
						MSG_DONTWAIT);
	if (bytes<(int)sizeof(response)){
		/* too few bytes read */
		if (bytes==0){
			/* EOF -> bad, worker has died */
			if (get_osips_state()!=STATE_TERMINATING)
				LM_CRIT("dead tcp worker %d (EOF received), pid %d\n",
					(int)(p-&pt[0]), p->pid);
			/* don't listen on it any more */
			reactor_del_reader( p->unix_sock, fd_i, 0/*flags*/);
			goto error; /* worker dead => no further io events from it */
		}else if (bytes<0){
			/* EAGAIN is ok if we try to empty the buffer
			 * e.g: SIGIO_RT overflow mode or EPOLL ET */
			if ((errno!=EAGAIN) && (errno!=EWOULDBLOCK)){
				LM_CRIT("read from worker %d (pid %d):  %s [%d]\n",
						(int)(p-&pt[0]), p->pid, strerror(errno), errno);
				ret=-1;
			}else{
				ret=0;
			}
			/* try to ignore ? */
			goto end;
		}else{
			/* should never happen */
			LM_CRIT("too few bytes received (%d)\n", bytes );
			ret=0; /* something was read so there is no error; otoh if
					  receive_fd returned less then requested => the receive
					  buffer is empty => no more io queued on this fd */
			goto end;
		}
	}
	ret=1; /* something was received, there might be more queued */
	LM_DBG("read response= %lx, %ld, fd %d from %d (%d)\n",
					response[0], response[1], fd, (int)(p-&pt[0]), p->pid);
	cmd=response[1];
	tcpconn=(struct tcp_connection*)response[0];
	if (tcpconn==0){
		LM_CRIT("null tcpconn pointer received from worker %d (pid %d)"
			"%lx, %lx\n", (int)(p-&pt[0]), p->pid, response[0], response[1]) ;
		goto end;
	}
	switch(cmd){
		case CONN_ERROR:
		case CONN_ERROR2:
			/* remove from reactor only if the fd exists, and it wasn't
			 * removed before */
			if ((tcpconn->flags & F_CONN_REMOVED) != F_CONN_REMOVED &&
					(tcpconn->s!=-1)){
				reactor_del_all( tcpconn->s, -1, IO_FD_CLOSING);
				tcpconn->flags|=F_CONN_REMOVED;
			}
			sh_log(tcpconn->hist, TCP_UNREF, "worker error, (%d)", tcpconn->refcnt);
			tcpconn_destroy(tcpconn); /* will close also the fd */
			break;
		case CONN_GET_FD:
			/* send the requested FD  */
			/* WARNING: take care of setting refcnt properly to
			 * avoid race condition */
			if (send_fd(p->unix_sock, &tcpconn, sizeof(tcpconn),
							tcpconn->s)<=0){
				LM_ERR("send_fd failed\n");
			}
			break;
		case CONN_NEW:
			/* update the fd in the requested tcpconn*/
			/* WARNING: take care of setting refcnt properly to
			 * avoid race condition */
			if (fd==-1){
				LM_CRIT(" cmd CONN_NEW: no fd received\n");
				break;
			}
			tcpconn->s=fd;
			/* add tcpconn to the list*/
			tcpconn_add(tcpconn);
			reactor_add_reader( tcpconn->s, F_TCPCONN, RCT_PRIO_NET, tcpconn);
			tcpconn->flags&=~F_CONN_REMOVED_READ;
			break;
		case ASYNC_CONNECT:
			/* connection is not yet linked to hash = not yet
			 * available to the outside world */
			if (fd==-1){
				LM_CRIT(" cmd CONN_NEW: no fd received\n");
				break;
			}
			tcpconn->s=fd;
			/* add tcpconn to the list*/
			tcpconn_add(tcpconn);
			/* FIXME - now we have lifetime==default_lifetime - should we
			 * set a shorter one when waiting for a connect ??? */
			/* only maintain the socket in the IO_WATCH_WRITE watcher
			 * while we have stuff to write - otherwise we're going to get
			 * useless events */
			reactor_add_writer( tcpconn->s, F_TCPCONN, RCT_PRIO_NET, tcpconn);
			tcpconn->flags&=~F_CONN_REMOVED_WRITE;
			break;
		case ASYNC_WRITE:
		case ASYNC_WRITE2:
			if (tcpconn->state==S_CONN_BAD){
				tcpconn->lifetime=0;
				break;
			}
			tcpconn_put(tcpconn);
			/* must be after the de-ref*/
			reactor_add_writer( tcpconn->s, F_TCPCONN, RCT_PRIO_NET, tcpconn);
			tcpconn->flags&=~F_CONN_REMOVED_WRITE;
			break;
		default:
			LM_CRIT("unknown cmd %d from worker %d (pid %d)\n", cmd,
				(int)(p-&pt[0]), p->pid);
	}
end:
	return ret;
error:
	return -1;
}


/*! \brief generic handle io routine, it will call the appropiate
 *  handle_xxx() based on the fd_map type
 *
 * \param  fm  - pointer to a fd hash entry
 * \param  idx - index in the fd_array (or -1 if not known)
 * \return -1 on error
 *          0 on EAGAIN or when by some other way it is known that no more
 *            io events are queued on the fd (the receive buffer is empty).
 *            Usefull to detect when there are no more io events queued for
 *            sigio_rt, epoll_et, kqueue.
 *         >0 on successful read from the fd (when there might be more io
 *            queued -- the receive buffer might still be non-empty)
 */
inline static int handle_io(struct fd_map* fm, int idx,int event_type)
{
	int ret = 0;

	pt_become_active();
	switch(fm->type){
		case F_TCP_LISTENER:
			ret = handle_new_connect((struct socket_info*)fm->data);
			break;
		case F_TCPCONN:
			ret = handle_tcpconn_ev((struct tcp_connection*)fm->data, idx,
				event_type);
			break;
		case F_TCP_TCPWORKER:
			ret = handle_tcp_worker((struct tcp_worker*)fm->data, idx);
			break;
		case F_TCP_WORKER:
			ret = handle_worker((struct process_table*)fm->data, idx);
			break;
		case F_IPC:
			ipc_handle_job(fm->fd);
			break;
		case F_NONE:
			LM_CRIT("empty fd map\n");
			goto error;
		default:
			LM_CRIT("unknown fd type %d\n", fm->type);
			goto error;
	}
	pt_become_idle();
	return ret;
error:
	pt_become_idle();
	return -1;
}


/*
 * iterates through all TCP connections and closes expired ones
 * Note: runs once per second at most
 */
#define tcpconn_lifetime(last_sec, close_all) \
	do { \
		int now; \
		now = get_ticks(); \
		if (last_sec != now) { \
			last_sec = now; \
			__tcpconn_lifetime(close_all); \
		} \
	} while (0)


/*! \brief very inefficient for now - FIXME
 * keep in sync with tcpconn_destroy, the "delete" part should be
 * the same except for io_watch_del..
 * \todo FIXME (very inefficient for now)
 */
static inline void __tcpconn_lifetime(int force)
{
	struct tcp_connection *c, *next;
	unsigned int ticks,part;
	unsigned h;
	int fd;

	if (have_ticks())
		ticks=get_ticks();
	else
		ticks=0;

	for( part=0 ; part<TCP_PARTITION_SIZE ; part++ ) {
		TCPCONN_LOCK(part); /* fixme: we can lock only on delete IMO */
		for(h=0; h<TCP_ID_HASH_SIZE; h++){
			c=TCP_PART(part).tcpconn_id_hash[h];
			while(c){
				next=c->id_next;
				if (force ||((c->refcnt==0) && (ticks>c->lifetime))) {
					if (!force)
						LM_DBG("timeout for hash=%d - %p"
								" (%d > %d)\n", h, c, ticks, c->lifetime);
					fd=c->s;
					/* report the closing of the connection . Note that
					 * there are connectioned that use an foced expire to 0
					 * as a way to be deleted - we are not interested in */
					/* Also, do not trigger reporting when shutdown (force=1)
					 * is done */
					if (c->lifetime>0 && !force)
						tcp_trigger_report(c, TCP_REPORT_CLOSE,
							"Timeout on no traffic");
					if ((!force)&&(fd>0)&&(c->refcnt==0)) {
						/* if any of read or write are set, we need to remove
						 * the fd from the reactor */
						if ((c->flags & F_CONN_REMOVED) != F_CONN_REMOVED){
							reactor_del_all( fd, -1, IO_FD_CLOSING);
							c->flags|=F_CONN_REMOVED;
						}
						close(fd);
					}
					_tcpconn_rm(c);
					tcp_connections_no--;
				}
				c=next;
			}
		}
		TCPCONN_UNLOCK(part);
	}
}


static void tcp_main_server(void)
{
	static unsigned int last_sec = 0;
	int flags;
	struct socket_info* si;
	int n;

	/* we run in a separate, dedicated process, with its own reactor
	 * (reactors are per process) */
	if (init_worker_reactor("TCP_main", RCT_PRIO_MAX)<0)
		goto error;

	/* now start watching all the fds */

	/* add all the sockets we listens on for connections */
	for( n=PROTO_FIRST ; n<PROTO_LAST ; n++ )
		if ( is_tcp_based_proto(n) )
			for( si=protos[n].listeners ; si ; si=si->next ) {
				if ( (si->socket!=-1) &&
				reactor_add_reader( si->socket, F_TCP_LISTENER,
				RCT_PRIO_NET, si)<0 ) {
					LM_ERR("failed to add listen socket to reactor\n");
					goto error;
				}
			}
	/* add all the unix sockets used for communcation with other opensips
	 * processes (get fd, new connection a.s.o)
	 * NOTE: we add even the socks for the inactive/unfork processes - the
	 *       socks are already created, but the triggering is from proc to
	 *       main, having them into reactor is harmless - thye will never
	 *       trigger as there is no proc on the other end to write us */
	for (n=1; n<counted_max_processes; n++) {
		/* skip myslef (as process) and -1 socks (disabled)
		   (we can't have 0, we never close it!) */
		if (n!=process_no && pt[n].unix_sock>0)
			if (reactor_add_reader( pt[n].unix_sock, F_TCP_WORKER,
			RCT_PRIO_PROC, &pt[n])<0){
				LM_ERR("failed to add process %d (%s) unix socket "
					"to the fd list\n", n, pt[n].desc);
				goto error;
			}
	}
	/* add all the unix sokets used for communication with the tcp workers */
	for (n=0; n<tcp_workers_max_no; n++) {
		/*we can't have 0, we never close it!*/
		if (tcp_workers[n].unix_sock>0) {
			/* make socket non-blocking */
			flags=fcntl(tcp_workers[n].unix_sock, F_GETFL);
			if (flags==-1){
				LM_ERR("fcntl failed: (%d) %s\n", errno, strerror(errno));
				goto error;
			}
			if (fcntl(tcp_workers[n].unix_sock,F_SETFL,flags|O_NONBLOCK)==-1){
				LM_ERR("set non-blocking failed: (%d) %s\n",
					errno, strerror(errno));
				goto error;
			}
			/* add socket for listening */
			if (reactor_add_reader( tcp_workers[n].unix_sock,
			F_TCP_TCPWORKER, RCT_PRIO_PROC, &tcp_workers[n])<0) {
				LM_ERR("failed to add tcp worker %d unix socket to "
						"the fd list\n", n);
				goto error;
			}
		}
	}

	/* init: start watching for the IPC jobs */
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor\n");
		goto error;
	}

	is_tcp_main = 1;

	/* main loop (requires "handle_io()" implementation) */
	reactor_main_loop( TCP_MAIN_SELECT_TIMEOUT, error,
			tcpconn_lifetime(last_sec, 0) );

error:
	destroy_worker_reactor();
	LM_CRIT("exiting...");
	exit(-1);
}



/**************************** Control functions ******************************/


/* initializes the TCP network level in terms of data structures */
int tcp_init(void)
{
	unsigned int i;

	/* first we do auto-detection to see if there are any TCP based
	 * protocols loaded */
	for ( i=PROTO_FIRST ; i<PROTO_LAST ; i++ )
		if (is_tcp_based_proto(i) && proto_has_listeners(i)) {
			tcp_disabled=0;
			break;
		}

	if (tcp_disabled)
		return 0;

#ifdef DBG_TCPCON
	con_hist = shl_init("TCP con", 10000, 1);
	if (!con_hist) {
		LM_ERR("oom con hist\n");
		goto error;
	}
#endif

	if (tcp_auto_scaling_profile) {
		s_profile = get_scaling_profile(tcp_auto_scaling_profile);
		if (s_profile==NULL) {
			LM_WARN("TCP scaling profile <%s> not defined "
				"-> ignoring it...\n", tcp_auto_scaling_profile);
		} else {
			auto_scaling_enabled = 1;
		}
	}

	tcp_workers_max_no = (s_profile && (tcp_workers_no<s_profile->max_procs)) ?
		s_profile->max_procs : tcp_workers_no ;

	/* init tcp workers array */
	tcp_workers = (struct tcp_worker*)pkg_malloc
		( tcp_workers_max_no*sizeof(struct tcp_worker) );
	if (tcp_workers==0) {
		LM_CRIT("could not alloc tcp_workers array in pkg memory\n");
		goto error;
	}
	memset( tcp_workers, 0, tcp_workers_max_no*sizeof(struct tcp_worker));
	/* init globals */
	connection_id=(unsigned int*)shm_malloc(sizeof(unsigned int));
	if (connection_id==0){
		LM_CRIT("could not alloc globals in shm memory\n");
		goto error;
	}
	// The  rand()  function returns a pseudo-random integer in the range 0 to
	// RAND_MAX inclusive (i.e., the mathematical range [0, RAND_MAX]).
	*connection_id=(unsigned int)rand();
	memset( &tcp_parts, 0, TCP_PARTITION_SIZE*sizeof(struct tcp_partition));
	/* init partitions */
	for( i=0 ; i<TCP_PARTITION_SIZE ; i++ ) {
		/* init lock */
		tcp_parts[i].tcpconn_lock=lock_alloc();
		if (tcp_parts[i].tcpconn_lock==0){
			LM_CRIT("could not alloc lock\n");
			goto error;
		}
		if (lock_init(tcp_parts[i].tcpconn_lock)==0){
			LM_CRIT("could not init lock\n");
			lock_dealloc((void*)tcp_parts[i].tcpconn_lock);
			tcp_parts[i].tcpconn_lock=0;
			goto error;
		}
		/* alloc hashtables*/
		tcp_parts[i].tcpconn_aliases_hash=(struct tcp_conn_alias**)
			shm_malloc(TCP_ALIAS_HASH_SIZE* sizeof(struct tcp_conn_alias*));
		if (tcp_parts[i].tcpconn_aliases_hash==0){
			LM_CRIT("could not alloc address hashtable in shm memory\n");
			goto error;
		}
		tcp_parts[i].tcpconn_id_hash=(struct tcp_connection**)
			shm_malloc(TCP_ID_HASH_SIZE*sizeof(struct tcp_connection*));
		if (tcp_parts[i].tcpconn_id_hash==0){
			LM_CRIT("could not alloc id hashtable in shm memory\n");
			goto error;
		}
		/* init hashtables*/
		memset((void*)tcp_parts[i].tcpconn_aliases_hash, 0,
			TCP_ALIAS_HASH_SIZE * sizeof(struct tcp_conn_alias*));
		memset((void*)tcp_parts[i].tcpconn_id_hash, 0,
			TCP_ID_HASH_SIZE * sizeof(struct tcp_connection*));
	}

	return 0;
error:
	/* clean-up */
	tcp_destroy();
	return -1;
}


/* destroys the TCP data */
void tcp_destroy(void)
{
	int part;

	if (tcp_parts[0].tcpconn_id_hash)
			/* force close/expire for all active tcpconns*/
			__tcpconn_lifetime(1);

	if (connection_id){
		shm_free(connection_id);
		connection_id=0;
	}

	for ( part=0 ; part<TCP_PARTITION_SIZE ; part++ ) {
		if (tcp_parts[part].tcpconn_id_hash){
			shm_free(tcp_parts[part].tcpconn_id_hash);
			tcp_parts[part].tcpconn_id_hash=0;
		}
		if (tcp_parts[part].tcpconn_aliases_hash){
			shm_free(tcp_parts[part].tcpconn_aliases_hash);
			tcp_parts[part].tcpconn_aliases_hash=0;
		}
		if (tcp_parts[part].tcpconn_lock){
			lock_destroy(tcp_parts[part].tcpconn_lock);
			lock_dealloc((void*)tcp_parts[part].tcpconn_lock);
			tcp_parts[part].tcpconn_lock=0;
		}
	}
}


int tcp_create_comm_proc_socks( int proc_no)
{
	int i;

	if (tcp_disabled)
		return 0;

	for( i=0 ; i<proc_no ; i++ ) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pt[i].tcp_socks_holder)<0){
			LM_ERR("socketpair failed for process %d: %d/%s\n",
				i, errno, strerror(errno));
			return -1;
		}
	}

	return 0;
}


int tcp_activate_comm_proc_socks( int proc_no)
{
	if (tcp_disabled)
		return 0;

	unix_tcp_sock = pt[proc_no].tcp_socks_holder[1];
	pt[proc_no].unix_sock = pt[proc_no].tcp_socks_holder[0];

	return 0;
}


void tcp_connect_proc_to_tcp_main( int proc_no, int worker )
{
	if (tcp_disabled)
		return;

	if (worker) {
		close( pt[proc_no].unix_sock );
	} else {
		unix_tcp_sock = -1;
	}
}


int _get_own_tcp_worker_id(void)
{
	pid_t pid;
	int i;

	pid = getpid();
	for( i=0 ; i<tcp_workers_max_no ; i++)
		if(tcp_workers[i].pid==pid)
			return i;

	return -1;
}


void tcp_reset_worker_slot(void)
{
	int i;

	if ((i=_get_own_tcp_worker_id())>=0) {
		tcp_workers[i].state=STATE_INACTIVE;
		tcp_workers[i].pid=0;
		tcp_workers[i].busy=0;
	}
}


static int fork_dynamic_tcp_process(void *foo)
{
	int p_id;
	int r;

	/* search for free slot in the TCP workers table */
	for( r=0 ; r<tcp_workers_max_no ; r++ )
		if (tcp_workers[r].state==STATE_INACTIVE)
			break;

	if (r==tcp_workers_max_no) {
		LM_BUG("trying to fork one more TCP worker but no free slots in "
			"the TCP table (size=%d)\n",tcp_workers_max_no);
		return -1;
	}

	if((p_id=internal_fork("SIP receiver TCP",
	OSS_PROC_DYNAMIC|OSS_PROC_NEEDS_SCRIPT, TYPE_TCP))<0){
		LM_ERR("cannot fork dynamic TCP worker process\n");
		return(-1);
	}else if (p_id==0){
		/* new TCP process */
		set_proc_attrs("TCP receiver");
		tcp_workers[r].pid = getpid();

		if (tcp_worker_proc_reactor_init(tcp_workers[r].main_unix_sock)<0||
		init_child(20000) < 0) {
			goto error;
		}

		report_conditional_status( 1, 0);/*report success*/
		/* the child proc is done read&write) dealing with the status pipe */
		clean_read_pipeend();

		tcp_worker_proc_loop();
		destroy_worker_reactor();

error:
		report_failure_status();
		LM_ERR("Initializing new process failed, exiting with error \n");
		pt[process_no].flags |= OSS_PROC_SELFEXIT;
		exit( -1);
	} else {
		/*parent/main*/
		tcp_workers[r].state=STATE_ACTIVE;
		tcp_workers[r].busy=0;
		tcp_workers[r].n_reqs=0;
		return p_id;
	}

	return 0;
}


static void tcp_process_graceful_terminate(int sender, void *param)
{
	int i;

	/* we accept this only from the main proccess */
	if (sender!=0) {
		LM_BUG("graceful terminate received from a non-main process!!\n");
		return;
	}
	LM_NOTICE("process %d received RPC to terminate from Main\n",process_no);

	/* going into "draining" state will avoid:
	 *  - getting jobs from TCP MAIN (active state required for that)
	 *  - having othe worker slot re-used (inactive state required for that) */
	if ((i=_get_own_tcp_worker_id())>=0)
		tcp_workers[i].state=STATE_DRAINING;

	tcp_terminate_worker();

	return;
}


/* counts the number of TPC processes to start with; this number may 
 * change during runtime due auto-scaling */
int tcp_count_processes(unsigned int *extra)
{
	if (extra) *extra = 0;

	if (tcp_disabled)
		return 0;


	if (s_profile && extra) {
		/* how many can be forked over th number of procs to start with ?*/
		if (s_profile->max_procs > tcp_workers_no)
			*extra = s_profile->max_procs - tcp_workers_no;
	}

	return 1/* tcp main */ + tcp_workers_no /*workers to start with*/;
}


int tcp_start_processes(int *chd_rank, int *startup_done)
{
	int r, n, p_id;
	int reader_fd[2]; /* for comm. with the tcp workers read  */
	struct socket_info *si;

	if (tcp_disabled)
		return 0;

	/* estimate max fd. no:
	 * 1 tcp send unix socket/all_proc,
	 *  + 1 udp sock/udp proc + 1 tcp_worker sock/tcp worker*
	 *  + no_listen_tcp */
	for( r=0,n=PROTO_FIRST ; n<PROTO_LAST ; n++ )
		if ( is_tcp_based_proto(n) )
			for(si=protos[n].listeners; si ; si=si->next,r++ );

	/* create the socket pairs for ALL potential processes */
	for(r=0; r<tcp_workers_max_no; r++){
		/* create sock to communicate from TCP main to worker */
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, reader_fd)<0){
			LM_ERR("socketpair failed: %s\n", strerror(errno));
			goto error;
		}
		tcp_workers[r].unix_sock = reader_fd[0]; /* worker's end */
		tcp_workers[r].main_unix_sock = reader_fd[1]; /* main's end */
	}

	if ( auto_scaling_enabled && s_profile &&
	create_process_group( TYPE_TCP, NULL, s_profile,
	fork_dynamic_tcp_process, tcp_process_graceful_terminate)!=0)
		LM_ERR("failed to create group of TCP processes for, "
			"auto forking will not be possible\n");

	/* start the TCP workers */
	for(r=0; r<tcp_workers_no; r++){
		(*chd_rank)++;
		p_id=internal_fork("SIP receiver TCP", OSS_PROC_NEEDS_SCRIPT,TYPE_TCP);
		if (p_id<0){
			LM_ERR("fork failed\n");
			goto error;
		}else if (p_id>0){
			/* parent */
			tcp_workers[r].state=STATE_ACTIVE;
			tcp_workers[r].busy=0;
			tcp_workers[r].n_reqs=0;
		}else{
			/* child */
			set_proc_attrs("TCP receiver");
			tcp_workers[r].pid = getpid();
			if (tcp_worker_proc_reactor_init(tcp_workers[r].main_unix_sock)<0||
					init_child(*chd_rank) < 0) {
				LM_ERR("init_children failed\n");
				report_failure_status();
				if (startup_done)
					*startup_done = -1;
				exit(-1);
			}

			/* was startup route executed so far ? */
			if (startup_done!=NULL && *startup_done==0 && r==0) {
				LM_DBG("running startup for first TCP\n");
				if(run_startup_route()< 0) {
					LM_ERR("Startup route processing failed\n");
					report_failure_status();
					*startup_done = -1;
					exit(-1);
				}
				*startup_done = 1;
			}

			report_conditional_status( (!no_daemon_mode), 0);

			tcp_worker_proc_loop();
		}
	}

	/* wait for the startup route to be executed */
	if (startup_done)
		while (!(*startup_done)) {
			usleep(5);
			handle_sigs();
		}

	return 0;
error:
	return -1;
}


int tcp_start_listener(void)
{
	int p_id;

	if (tcp_disabled)
		return 0;

	/* start the TCP manager process */
	if ( (p_id=internal_fork( "TCP main", 0, TYPE_NONE))<0 ) {
		LM_CRIT("cannot fork tcp main process\n");
		goto error;
	}else if (p_id==0){
			/* child */
		/* close the TCP inter-process sockets */
		close(unix_tcp_sock);
		unix_tcp_sock = -1;
		close(pt[process_no].unix_sock);
		pt[process_no].unix_sock = -1;

		report_conditional_status( (!no_daemon_mode), 0);

		tcp_main_server();
		exit(-1);
	}

	return 0;
error:
	return -1;
}

int tcp_has_async_write(void)
{
	return reactor_has_async();
}


/***************************** MI functions **********************************/

mi_response_t *mi_tcp_list_conns(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *conns_arr, *conn_item;
	struct tcp_connection *conn;
	time_t _ts;
	char date_buf[MI_DATE_BUF_LEN];
	int date_buf_len;
	unsigned int i,j,part;
	char proto[PROTO_NAME_MAX_SIZE];
	struct tm ltime;
	char *p;

	if (tcp_disabled)
		return init_mi_result_null();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	conns_arr = add_mi_array(resp_obj, MI_SSTR("Connections"));
	if (!conns_arr) {
		free_mi_response(resp);
		return 0;
	}

	for( part=0 ; part<TCP_PARTITION_SIZE ; part++) {
		TCPCONN_LOCK(part);
		for( i=0; i<TCP_ID_HASH_SIZE ; i++ ) {
			for(conn=TCP_PART(part).tcpconn_id_hash[i];conn;conn=conn->id_next){
				/* add one object fo each conn */
				conn_item = add_mi_object(conns_arr, 0, 0);
				if (!conn_item)
					goto error;

				/* add ID */
				if (add_mi_number(conn_item, MI_SSTR("ID"), conn->id) < 0)
					goto error;

				/* add type/proto */
				p = proto2str(conn->type, proto);
				if (add_mi_string(conn_item, MI_SSTR("Type"), proto,
					(int)(long)(p-proto)) > 0)
					goto error;

				/* add state */
				if (add_mi_number(conn_item, MI_SSTR("State"), conn->state) < 0)
					goto error;

				/* add Remote IP:Port */
				if (add_mi_string_fmt(conn_item, MI_SSTR("Remote"), "%s:%d",
					ip_addr2a(&conn->rcv.src_ip), conn->rcv.src_port) < 0)
					goto error;

				/* add Local IP:Port */
				if (add_mi_string_fmt(conn_item, MI_SSTR("Local"), "%s:%d",
					ip_addr2a(&conn->rcv.dst_ip), conn->rcv.dst_port) < 0)
					goto error;

				/* add lifetime */
				_ts = (time_t)conn->lifetime + startup_time;
				localtime_r(&_ts, &ltime);
				date_buf_len = strftime(date_buf, MI_DATE_BUF_LEN - 1,
										"%Y-%m-%d %H:%M:%S", &ltime);
				if (date_buf_len != 0) {
					if (add_mi_string(conn_item, MI_SSTR("Lifetime"),
						date_buf, date_buf_len) < 0)
						goto error;
				} else {
					if (add_mi_number(conn_item, MI_SSTR("Lifetime"), _ts) < 0)
						goto error;
				}

				/* add the port-aliases */
				for( j=0 ; j<conn->aliases ; j++ )
					/* add one node for each conn */
					add_mi_number( conn_item, MI_SSTR("Alias port"),
						conn->con_aliases[j].port );
			}
		}

		TCPCONN_UNLOCK(part);
	}

	return resp;

error:
	TCPCONN_UNLOCK(part);
	LM_ERR("failed to add MI item\n");
	free_mi_response(resp);
	return 0;
}



