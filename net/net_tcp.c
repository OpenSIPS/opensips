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
#include <pthread.h>
#include <stdint.h>

#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../globals.h"
#include "../locking.h"
#include "../socket_info.h"
#include "../ut.h"
#include "../pt.h"
#include "../pt_load.h"
#include "../daemonize.h"
#include "../status_report.h"
#include "../reactor.h"
#include "../timer.h"
#include "../ipc.h"
#include "../receive.h"
#include "../lib/cond.h"

#include "tcp_passfd.h"
#include "net_tcp_proc.h"
#include "net_tcp_report.h"
#include "net_tcp.h"
#include "tcp_common.h"
#include "tcp_conn.h"
#include "tcp_conn_profile.h"
#include "trans.h"
#include "net_tcp_dbg.h"

struct struct_hist_list *con_hist;

enum tcp_worker_state { STATE_INACTIVE=0, STATE_ACTIVE, STATE_DRAINING};

static int tcpconn_prepare_write(struct tcp_connection *tcpconn);

/* definition of a TCP worker - the array of these TCP workers is
 * mainly intended to be used by the TCP main, to keep track of the
 * workers, about their load and so. Nevertheless, since the addition
 * of the process auto-scaling, other processes may need access to this
 * data, thus it's relocation in SHM (versus initial PKG). For example,
 * the attendant process is the one forking new TCP workers (scaling up),
 * so it must be able to set the ENABLE state for the TCP worker (and being
 * (seen by the TCP main proc). Similar, when a TCP worker shuts down, it has
 * to mark itself as DISABLED and the TCP main must see that.
 * Again, 99% this array is intended for TCP Main ops, it is not lock
 * protected, so be very careful with any ops from other procs.
 */
struct tcp_worker {
	pid_t pid;
	int pt_idx;			/*!< Index in the main Process Table */
	enum tcp_worker_state state;
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
static int tcp_dispatch_sock[2] = { -1, -1 };

/* unique for each connection, used for
 * quickly finding the corresponding connection for a reply */
static unsigned int* connection_id=0;
static int *tcp_main_proc_no = 0;

/* array of TCP partitions */
static struct tcp_partition tcp_parts[TCP_PARTITION_SIZE];

/*!< tcp protocol number as returned by getprotobyname */
static int tcp_proto_no=-1;

/*!< current number of open connections */
static unsigned int *tcp_connections_no = 0;
static gen_lock_t *tcp_connections_lock = 0;

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
/* Max number of seconds that we expect a full SIP message
 * to arrive in. Anything above will close the connection. */
int tcp_max_msg_time = TCP_CHILD_MAX_MSG_TIME;
/* If the data reading may be performed across different workers (still
 * serial) or by a single worker (the TCP conns sticks to one worker) */
int tcp_parallel_read_on_workers = 0;

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
int tcp_threads = 0;

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

static inline int init_sock_keepalive(int s, const struct tcp_conn_profile *prof)
{
	int ka;
#if defined(HAVE_TCP_KEEPINTVL) || defined(HAVE_TCP_KEEPIDLE) || defined(HAVE_TCP_KEEPCNT)
	int optval;
#endif

	if (prof->keepinterval || prof->keepidle || prof->keepcount)
		ka = 1; /* force on */
	else
		ka = prof->keepalive;

#ifdef HAVE_SO_KEEPALIVE
	if (setsockopt(s,SOL_SOCKET,SO_KEEPALIVE,&ka,sizeof(ka))<0){
		LM_WARN("setsockopt failed to enable SO_KEEPALIVE: %s\n",
			strerror(errno));
		return -1;
	}
	LM_DBG("TCP keepalive enabled on socket %d\n",s);
#endif
#ifdef HAVE_TCP_KEEPINTVL
	if ((optval = prof->keepinterval)) {
		if (setsockopt(s,IPPROTO_TCP,TCP_KEEPINTVL,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to set keepalive probes interval: %s\n",
				strerror(errno));
		}
	}
#endif
#ifdef HAVE_TCP_KEEPIDLE
	if ((optval = prof->keepidle)) {
		if (setsockopt(s,IPPROTO_TCP,TCP_KEEPIDLE,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to set keepalive idle interval: %s\n",
				strerror(errno));
		}
	}
#endif
#ifdef HAVE_TCP_KEEPCNT
	if ((optval = prof->keepcount)) {
		if (setsockopt(s,IPPROTO_TCP,TCP_KEEPCNT,&optval,sizeof(optval))<0){
			LM_WARN("setsockopt failed to set maximum keepalive count: %s\n",
				strerror(errno));
		}
	}
#endif
	return 0;
}

static inline void set_sock_reuseport(int s)
{
	int yes = 1;

	if (setsockopt(s,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof(yes))<0){
		LM_WARN("setsockopt failed to set SO_REUSEPORT: %s\n",
			strerror(errno));
	}
	if (setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes))<0){
		LM_WARN("setsockopt failed to set SO_REUSEADDR: %s\n",
			strerror(errno));
	}
}

/*! \brief Set all socket/fd options:  disable nagle, tos lowdelay,
 * non-blocking
 * \return -1 on error */
int tcp_init_sock_opt(int s, const struct tcp_conn_profile *prof, enum si_flags socketflags, int sock_tos)
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
	optval = (sock_tos > 0) ? sock_tos : tos;
	if (optval > 0) {
		if (setsockopt(s, IPPROTO_IP, IP_TOS, (void*)&optval,sizeof(optval)) ==-1){
			LM_WARN("setsockopt tos: %s\n",	strerror(errno));
			/* continue since this is not critical */
		}
	}

	if (probe_max_sock_buff(s,1,MAX_SEND_BUFFER_SIZE,BUFFER_INCREMENT)) {
		LM_WARN("setsockopt tcp snd buff: %s\n",	strerror(errno));
		/* continue since this is not critical */
	}

	init_sock_keepalive(s, prof);
	if (socketflags & SI_REUSEPORT)
		set_sock_reuseport(s);

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

struct tcp_ipc_payload {
	struct receive_info rcv;
	struct tcp_connection *conn;
	int msg_len;
	int data_len;
	char msg_buf[0];
};

int tcp_dispatch_msg(char *msg, int len,
		struct receive_info *rcv, const void *data, int data_len)
{
	struct tcp_ipc_payload *payload;
	struct tcp_connection *conn = NULL;
	unsigned int alloc_len;
	int n;
	uintptr_t payload_ptr;

	if (len < 0) {
		LM_BUG("negative TCP message length: %d\n", len);
		return -1;
	}
	if (data_len < 0) {
		LM_BUG("negative TCP dispatch data length: %d\n", data_len);
		return -1;
	}
	if (data_len && !data) {
		LM_BUG("missing TCP dispatch data buffer for %d bytes\n", data_len);
		return -1;
	}

	alloc_len = sizeof(*payload) + len + 1 + data_len;
	payload = shm_malloc(alloc_len);
	if (!payload) {
		LM_ERR("oom while allocating TCP IPC payload (%u bytes)\n", alloc_len);
		return -1;
	}

	memcpy(&payload->rcv, rcv, sizeof(payload->rcv));
	payload->conn = NULL;
	payload->msg_len = len;
	payload->data_len = data_len;
	memcpy(payload->msg_buf, msg, len);
	payload->msg_buf[len] = '\0';
	if (data_len)
		memcpy(payload->msg_buf + len + 1, data, data_len);

	if (rcv->proto_reserved1 &&
			tcp_conn_get(rcv->proto_reserved1, NULL, 0, PROTO_NONE,
				NULL, &conn, NULL) > 0) {
		payload->conn = conn;
	}

	payload_ptr = (uintptr_t)payload;
	n = send(tcp_dispatch_sock[1], &payload_ptr, sizeof(payload_ptr), 0);
	if (n != (int)sizeof(payload_ptr)) {
		LM_ERR("failed to dispatch TCP message to worker socket: %s\n",
			(n < 0) ? strerror(errno) : "short write");
		if (payload->conn)
			tcpconn_put(payload->conn);
		shm_free(payload);
		return -1;
	}

	return 0;
}

enum tcp_job_op {
	TCP_READ_JOB = 1,
	TCP_WRITE_JOB = 2,
	TCP_RUN_JOB = 3,
};

struct tcp_job {
	struct tcp_connection *conn;
	int op;
	tcp_thread_job_f run;
	void *data;
	long resp;
	int ret;
	struct tcp_job *next;
};

static struct tcp_pool {
	pthread_t *threads;
	int threads_no;
	int stop;
	struct tcp_job *task_head;
	struct tcp_job *task_tail;

	pthread_mutex_t done_lock;
	struct tcp_job *done_head;
	struct tcp_job *done_tail;

	int notify_pipe[2];
} tcp_pool = {
	.threads = NULL,
	.threads_no = 0,
	.stop = 0,
	.task_head = NULL,
	.task_tail = NULL,
	.done_lock = PTHREAD_MUTEX_INITIALIZER,
	.done_head = NULL,
	.done_tail = NULL,
	.notify_pipe = {-1, -1},
};

struct tcp_shared_write_queue {
	gen_cond_t cond;
	struct tcp_connection *head;
	struct tcp_connection *tail;
};

static struct tcp_shared_write_queue *tcp_write_queue = NULL;

static inline int tcp_threads_active(void)
{
	return tcp_pool.threads_no > 0;
}

int tcp_write_in_main(void)
{
	/* This is a process-independent policy: TCP writes are handled by the
	 * dedicated TCP main process, regardless of the caller process. */
	return !tcp_disabled;
}



/********************** TCP conn management functions ************************/

/* initializes an already defined TCP listener */
int tcp_init_listener(struct socket_info *si)
{
	union sockaddr_union* addr = &si->su;
	if (init_su(addr, &si->address, si->port_no)<0){
		LM_ERR("could no init sockaddr_union\n");
		return -1;
	}
	return 0;
}

/* binding an defined TCP listener */
int tcp_bind_listener(struct socket_info *si)
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
	optval = (si->tos > 0) ? si->tos : tos;
	if (optval > 0) {
		if (setsockopt(si->socket, IPPROTO_IP, IP_TOS, (void*)&optval,
		sizeof(optval)) ==-1){
			LM_WARN("setsockopt tos: %s\n", strerror(errno));
			/* continue since this is not critical */
		}
	}

	if (probe_max_sock_buff(si->socket,1,MAX_SEND_BUFFER_SIZE,
	BUFFER_INCREMENT)) {
		LM_WARN("setsockopt tcp snd buff: %s\n",strerror(errno));
		/* continue since this is not critical */
	}

	init_sock_keepalive(si->socket, &tcp_con_df_profile);
	if (si->flags & SI_REUSEPORT)
		set_sock_reuseport(si->socket);
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

/* returns the correlation ID of a TCP connection */
int tcp_get_rcv( unsigned int id, struct receive_info *ri)
{
	struct tcp_connection* c;

	TCPCONN_LOCK(id);
	if ( (c=_tcpconn_find(id))!=NULL ) {
		memcpy(ri, &c->rcv, sizeof *ri);
		TCPCONN_UNLOCK(id);
		return 0;
	}
	TCPCONN_UNLOCK(id);
	return -1;
}

int tcp_get_main_proc_no(void)
{
	return tcp_main_proc_no ? *tcp_main_proc_no : -1;
}


/*! \brief _tcpconn_find with locks and acquire a shared connection reference */
int tcp_conn_get(unsigned int id, struct ip_addr* ip, int port,
		enum sip_protos proto, void *proto_extra_id,
		struct tcp_connection** conn, const struct socket_info* send_sock)
{
	struct tcp_connection* c;
	struct tcp_conn_alias* a;
	unsigned hash;
	unsigned int part;

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
				if (send_sock && a->parent->rcv.bind_address) {
					print_ip("requested send_sock ip=", &send_sock->address,"\n");
					print_ip("found send_sock ip=", &a->parent->rcv.bind_address->address,"\n");
				}
#endif
				c = a->parent;
				if (c->state != S_CONN_BAD &&
				    ((c->flags & F_CONN_INIT) ||
				     (c->state == S_CONN_CONNECTING && c->fd == -1)) &&
				    (send_sock==NULL || send_sock == a->parent->rcv.bind_address) &&
				    port == a->port &&
				    proto == c->type &&
				    ip_addr_cmp(ip, &c->rcv.src_ip) &&
				    (proto_extra_id == NULL ||
				     ((c->flags & F_CONN_INIT) &&
				      (protos[proto].net.stream.conn.match == NULL ||
				       protos[proto].net.stream.conn.match(c, proto_extra_id)))) )
						goto found;
				}
			TCPCONN_UNLOCK(part);
		}
	}

	/* not found */
	*conn = NULL;
	return 0;

found:
	c->refcnt++;
	TCPCONN_UNLOCK(part);
	sh_log(c->hist, TCP_REF, "tcp_conn_get, (%d)", c->refcnt);

	LM_DBG("con found in state %d\n",c->state);

	*conn = c;
	return 1;
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
		c->flags |= F_CONN_HASHED;
		TCPCONN_UNLOCK(c->id);
		LM_DBG("hashes: %d, %d\n", hash, c->id_hash);
		return c;
	}else{
		LM_CRIT("null connection pointer\n");
		return 0;
	}
}

static str e_tcp_src_ip = str_init("src_ip");
static str e_tcp_src_port = str_init("src_port");
static str e_tcp_dst_ip = str_init("dst_ip");
static str e_tcp_dst_port = str_init("dst_port");
static str e_tcp_c_proto = str_init("proto");

static void tcp_disconnect_event_raise(struct tcp_connection* c)
{
	evi_params_p list = 0;
	str src_ip,dst_ip, proto;
	int src_port,dst_port;
	char src_ip_buf[IP_ADDR_MAX_STR_SIZE],dst_ip_buf[IP_ADDR_MAX_STR_SIZE];

	// event has to be triggered - check for subscribers
	if (!evi_probe_event(EVI_TCP_DISCONNECT)) {
		goto end;
	}

	if (!(list = evi_get_params()))
		goto end;

	src_ip.s = ip_addr2a( &c->rcv.src_ip );
	memcpy(src_ip_buf,src_ip.s,IP_ADDR_MAX_STR_SIZE);
	src_ip.s = src_ip_buf;
	src_ip.len = strlen(src_ip.s);

	if (evi_param_add_str(list, &e_tcp_src_ip, &src_ip)) {
		LM_ERR("unable to add parameter\n");
		goto end;
	}

	src_port = c->rcv.src_port;

	if (evi_param_add_int(list, &e_tcp_src_port, &src_port)) {
		LM_ERR("unable to add parameter\n");
		goto end;
	}

	dst_ip.s = ip_addr2a( &c->rcv.dst_ip );
	memcpy(dst_ip_buf,dst_ip.s,IP_ADDR_MAX_STR_SIZE);
	dst_ip.s = dst_ip_buf;
	dst_ip.len = strlen(dst_ip.s);

	if (evi_param_add_str(list, &e_tcp_dst_ip, &dst_ip)) {
		LM_ERR("unable to add parameter\n");
		goto end;
	}

	dst_port = c->rcv.dst_port;

	if (evi_param_add_int(list, &e_tcp_dst_port, &dst_port)) {
		LM_ERR("unable to add parameter\n");
		goto end;
	}

	proto.s = protos[c->rcv.proto].name;
	proto.len = strlen(proto.s);

	if (evi_param_add_str(list, &e_tcp_c_proto, &proto)) {
		LM_ERR("unable to add parameter\n");
		goto end;
	}

	if (is_tcp_main) {
		if (evi_dispatch_event(EVI_TCP_DISCONNECT, list)) {
			LM_ERR("unable to dispatch tcp disconnect event\n");
		}
	} else {
		if (evi_raise_event(EVI_TCP_DISCONNECT, list)) {
			LM_ERR("unable to send tcp disconnect event\n");
		}
	}
	list = 0;

end:
	if (list)
		evi_free_params(list);
}

/* convenience macro to aid in shm_free() debugging */
#define _tcpconn_rm(c, ne) \
	do {\
		__tcpconn_rm(c, ne);\
		shm_free(c);\
	} while (0)

struct tcp_req *tcp_conn_get_req(struct tcp_connection *c)
{
	if (!c)
		return NULL;

	if (c->con_req)
		return c->con_req;

	c->con_req = thread_malloc(sizeof(*c->con_req));
	if (!c->con_req) {
		LM_ERR("failed to allocate TCP request buffer for connection %u\n",
			c->id);
		return NULL;
	}
	memset(c->con_req, 0, sizeof(*c->con_req));

	return c->con_req;
}

void tcp_conn_destroy_req(struct tcp_connection *c)
{
	if (!c || !c->con_req)
		return;

	thread_free(c->con_req);
	c->con_req = NULL;
}

/*! \brief unsafe tcpconn_rm version (nolocks) */
static void __tcpconn_rm(struct tcp_connection* c, int no_event)
{
	int r;

	if (c->flags & F_CONN_HASHED) {
		tcpconn_listrm(TCP_PART(c->id).tcpconn_id_hash[c->id_hash], c,
			id_next, id_prev);
		/* remove all the aliases */
		for (r=0; r<c->aliases; r++)
			tcpconn_listrm(TCP_PART(c->id).tcpconn_aliases_hash[
				c->con_aliases[r].hash], &c->con_aliases[r], next, prev);
		c->flags &= ~F_CONN_HASHED;
	}
	lock_destroy(&c->write_lock);

	if (c->async) {
		for (r = 0; r<c->async->pending; r++)
			shm_free(c->async->chunks[r]);
		shm_free(c->async);
		c->async = NULL;
	}

	lock_get(tcp_connections_lock);
	(*tcp_connections_no)--;
	lock_release(tcp_connections_lock);

	if (c->proto_req)
		thread_free(c->proto_req);
	c->proto_req = NULL;
	tcp_conn_destroy_req(c);

	if (protos[c->type].net.stream.conn.clean)
		protos[c->type].net.stream.conn.clean(c);

	if (!no_event) tcp_disconnect_event_raise(c);

#ifdef DBG_TCPCON
	sh_log(c->hist, TCP_DESTROY, "type=%d", c->type);
	sh_unref(c->hist);
	c->hist = NULL;
#endif

	/* shm_free(c); -- freed by _tcpconn_rm() */
}

/*! \brief add port as an alias for the "id" connection
 * \return 0 on success,-1 on failure */
int tcpconn_add_alias(struct sip_msg *msg, unsigned int id, int port, int proto)
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
	if (c) {
		if (msg && !(c->profile.alias_mode == TCP_ALIAS_ALWAYS
		               || (c->profile.alias_mode == TCP_ALIAS_RFC_5923
		                   && msg->via1->alias))) {
			LM_DBG("refusing to add alias (alias_mode: %u, via 'alias': %u)\n",
			        c->profile.alias_mode, !!msg->via1->alias);
			TCPCONN_UNLOCK(id);
			return 0;
		}

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
	int destroy = 0;

	TCPCONN_LOCK(c->id);
	c->refcnt--;
	if (c->refcnt == 0 && (c->flags & F_CONN_HASHED) == 0)
		destroy = 1;
	TCPCONN_UNLOCK(c->id);

	if (destroy)
		_tcpconn_rm(c, 1);
}


static inline void tcpconn_ref(struct tcp_connection* c)
{
	TCPCONN_LOCK(c->id);
	c->refcnt++;
	TCPCONN_UNLOCK(c->id);
}


static struct tcp_connection* tcpconn_new(int sock, const union sockaddr_union* su,
                    const struct socket_info* si, const struct tcp_conn_profile *prof,
                    int state, int flags)
{
	struct tcp_connection *c;
	union sockaddr_union local_su;
	unsigned int su_size;
	int counted = 0;

	lock_get(tcp_connections_lock);
	if (*tcp_connections_no >= (unsigned int)tcp_max_connections) {
		lock_release(tcp_connections_lock);
		LM_ERR("maximum number of connections exceeded: %u/%d\n",
			*tcp_connections_no, tcp_max_connections);
		return 0;
	}
	(*tcp_connections_no)++;
	lock_release(tcp_connections_lock);
	counted = 1;

	c=(struct tcp_connection*)shm_malloc(sizeof(struct tcp_connection));
	if (c==0){
		LM_ERR("shared memory allocation failure\n");
		goto error_count;
	}
	memset(c, 0, sizeof(struct tcp_connection)); /* zero init */
	c->fd=sock;
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
	if (sock >= 0) {
		su_size = sockaddru_len(*su);
		if (getsockname(sock, (struct sockaddr *)&local_su, &su_size)<0) {
			LM_ERR("failed to get info on received interface/IP %d/%s\n",
				errno, strerror(errno));
			goto error;
		}
		c->rcv.dst_port = su_getport(&local_su);
	} else {
		c->rcv.dst_port = (si->flags & SI_REUSEPORT) ? su_getport(&si->su) : 0;
	}
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
	c->lifetime = get_ticks() + prof->con_lifetime;
	c->timeout = c->lifetime;
	c->profile = *prof;
	c->flags|=F_CONN_REMOVED|flags;
#ifdef DBG_TCPCON
	c->hist = sh_push(c, con_hist);
#endif

	if (protos[si->proto].net.stream.async_chunks) {
		c->async = shm_malloc(sizeof(struct tcp_async_data) +
				protos[si->proto].net.stream.async_chunks *
				sizeof(struct tcp_async_chunk));
		if (c->async) {
			c->async->allocated = protos[si->proto].net.stream.async_chunks;
			c->async->oldest = 0;
			c->async->pending = 0;
		} else {
			LM_ERR("could not allocate async data for con!\n");
			goto error;
		}
	}
	if (sock >= 0 && protos[si->proto].net.stream.conn.init) {
		if (protos[si->proto].net.stream.conn.init(c) < 0) {
			LM_ERR("failed to do proto %d specific init for conn %p\n",
					c->type, c);
			goto error;
		}
		c->flags |= F_CONN_INIT;
	}
	return c;

error:
	lock_destroy(&c->write_lock);
error0:
	shm_free(c);
error_count:
	if (counted) {
		lock_get(tcp_connections_lock);
		(*tcp_connections_no)--;
		lock_release(tcp_connections_lock);
	}
	return 0;
}


/* creates a new tcp connection structure
 * for an outgoing connection request; local private state is initialized later
 * a +1 ref is set for the new conn !
 * IMPORTANT - the function assumes you want to create a new TCP conn as
 * a result of a connect operation - the conn will be set as connect !!
 * Accepted connection are triggered internally only */
struct tcp_connection* tcp_conn_create(const union sockaddr_union* su,
		const struct socket_info* si, struct tcp_conn_profile *prof,
		int state)
{
	struct tcp_connection *c;

	if (!prof)
		tcp_con_get_profile(su, &si->su, si->proto, prof);

	/* create the connection structure */
	c = tcpconn_new(-1, su, si, prof, state, 0);
	if (c==NULL) {
		LM_ERR("tcpconn_new failed\n");
		return NULL;
	}

	c->refcnt++; /* safe to do it w/o locking, it's not yet
					available to the rest of the world */
	sh_log(c->hist, TCP_REF, "connect, (%d)", c->refcnt);
	return c;
}


static inline void tcpconn_destroy(struct tcp_connection* tcpconn)
{
	int fd;
	int unsigned id = tcpconn->id;
	int hashed;

	TCPCONN_LOCK(id); /*avoid races w/ tcp_send*/
	tcpconn->refcnt--;
	if (tcpconn->refcnt==0){
		LM_DBG("destroying connection %p, flags %04x\n",
				tcpconn, tcpconn->flags);
		fd=tcpconn->fd;
		/* no reporting here - the tcpconn_destroy() function is called
		 * from the TCP_MAIN reactor when handling connectioned received
		 * from a worker; and we generate the CLOSE reports from WORKERs */
		hashed = (tcpconn->flags & F_CONN_HASHED);
		_tcpconn_rm(tcpconn, hashed ? 0 : 1);
		if (fd >= 0)
			close(fd);
	}else{
		/* force timeout */
		tcpconn->lifetime=0;
		tcpconn->timeout=0;
		tcpconn->state=S_CONN_BAD;
		sh_log(tcpconn->hist, TCP_DEL_DELAY, "tcpconn_destroy delayed, (%d)",
			tcpconn->refcnt);
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

static inline int tcp_set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl(F_GETFL) failed for %d: %s\n", fd, strerror(errno));
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl(F_SETFL) failed for %d: %s\n", fd, strerror(errno));
		return -1;
	}

	return 0;
}

static void tcp_push_done_job(struct tcp_job *job)
{
	pthread_mutex_lock(&tcp_pool.done_lock);
	if (tcp_pool.done_tail)
		tcp_pool.done_tail->next = job;
	else
		tcp_pool.done_head = job;
	tcp_pool.done_tail = job;
	pthread_mutex_unlock(&tcp_pool.done_lock);
}

static struct tcp_job *tcp_pop_done_job(void)
{
	struct tcp_job *job;

	pthread_mutex_lock(&tcp_pool.done_lock);
	job = tcp_pool.done_head;
	if (job) {
		tcp_pool.done_head = job->next;
		if (tcp_pool.done_head == NULL)
			tcp_pool.done_tail = NULL;
	}
	pthread_mutex_unlock(&tcp_pool.done_lock);

	return job;
}

static inline struct tcp_connection *tcp_pop_shared_write_conn_locked(void)
{
	struct tcp_connection *conn;

	conn = tcp_write_queue->head;
	if (conn) {
		tcp_write_queue->head = conn->wq_next;
		if (tcp_write_queue->head == NULL)
			tcp_write_queue->tail = NULL;
		conn->wq_next = NULL;
	}

	return conn;
}

static void *tcp_thread_routine(void *arg)
{
	struct tcp_job *job;
	struct tcp_connection *conn;
	char wake = 'x';
	int rc;

	(void)arg;

	/* Reactor operations stay in TCP main; IO threads only run read/write
	 * callbacks and notify completion back to the main thread. */
	while (1) {
		cond_lock(&tcp_write_queue->cond);
		while (!tcp_pool.stop && tcp_pool.task_head == NULL &&
				tcp_write_queue->head == NULL)
			cond_wait(&tcp_write_queue->cond);

		if (tcp_pool.stop && tcp_pool.task_head == NULL &&
				tcp_write_queue->head == NULL) {
			cond_unlock(&tcp_write_queue->cond);
			break;
		}

		job = tcp_pool.task_head;
		if (job) {
			tcp_pool.task_head = job->next;
			if (tcp_pool.task_head == NULL)
				tcp_pool.task_tail = NULL;
		} else if ((conn = tcp_pop_shared_write_conn_locked()) != NULL) {
			job = thread_malloc(sizeof(*job));
			if (!job) {
				LM_ERR("oom while building shared TCP write job\n");
				conn->flags &= ~F_CONN_WRITE_QUEUED;
				tcpconn_put(conn);
				cond_unlock(&tcp_write_queue->cond);
				continue;
			}
			job->conn = conn;
			job->op = TCP_WRITE_JOB;
			job->run = NULL;
			job->data = NULL;
			job->resp = 0;
			job->ret = 0;
			job->next = NULL;
		}
		cond_unlock(&tcp_write_queue->cond);

		conn = job->conn;
		if (job->op == TCP_READ_JOB) {
			if (conn->msg_attempts && get_ticks() > conn->timeout) {
				job->ret = -1;
				job->resp = -2;
			} else if (protos[conn->type].net.stream.read) {
				job->resp = protos[conn->type].net.stream.read(conn, &job->ret);
			} else {
				LM_ERR("missing stream.read callback for proto %d\n", conn->type);
				job->ret = -1;
				job->resp = -1;
			}
		} else if (job->op == TCP_WRITE_JOB) {
			if (protos[conn->type].net.stream.write) {
				if (tcpconn_prepare_write(conn) < 0) {
					job->ret = -1;
					job->resp = -1;
					goto done_job;
				}
				lock_get(&conn->write_lock);
				job->resp = protos[conn->type].net.stream.write(conn, conn->fd);
				lock_release(&conn->write_lock);
				job->ret = (job->resp < 0) ? -1 : 0;
			} else {
				LM_ERR("missing stream.write callback for proto %d\n", conn->type);
				job->ret = -1;
				job->resp = -1;
			}
		} else if (job->op == TCP_RUN_JOB) {
			job->ret = job->run ? job->run(job->data) : -1;
			thread_free(job);
			continue;
		} else {
			LM_ERR("unknown TCP job op %d\n", job->op);
			job->ret = -1;
			job->resp = -1;
		}

done_job:
		job->next = NULL;
		tcp_push_done_job(job);

		rc = write(tcp_pool.notify_pipe[1], &wake, 1);
		if (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
			LM_ERR("failed to notify TCP IO completion: %s\n", strerror(errno));
	}

	return NULL;
}

static int tcp_pool_init(void)
{
	int i;
	int started = 0;
	int threads_no;
	long cpu_no;

	if (tcp_threads > 0)
		threads_no = tcp_threads;
	else {
		cpu_no = sysconf(_SC_NPROCESSORS_ONLN);
		if (cpu_no > 0)
			threads_no = (int)cpu_no;
		else if (tcp_workers_no > 0)
			threads_no = tcp_workers_no;
		else
			threads_no = 1;
	}

	if (pipe(tcp_pool.notify_pipe) < 0) {
		LM_ERR("failed to create TCP IO notification pipe: %s\n", strerror(errno));
		goto error;
	}

	if (tcp_set_nonblock(tcp_pool.notify_pipe[0]) < 0 ||
	    tcp_set_nonblock(tcp_pool.notify_pipe[1]) < 0)
		goto error;

	if (reactor_add_reader(tcp_pool.notify_pipe[0],
		F_TCP_NOTIFY, RCT_PRIO_PROC, NULL) < 0) {
		LM_ERR("failed to add TCP IO notify pipe to reactor\n");
		goto error;
	}

	tcp_pool.threads = pkg_malloc(sizeof(*tcp_pool.threads) * threads_no);
	if (!tcp_pool.threads) {
		LM_ERR("oom while allocating TCP IO threads array\n");
		goto error;
	}

	tcp_pool.stop = 0;
	tcp_pool.threads_no = threads_no;

	for (i = 0; i < threads_no; i++) {
		if (pthread_create(&tcp_pool.threads[i], NULL,
				tcp_thread_routine, NULL) != 0) {
			LM_ERR("failed to start TCP IO thread %d/%d\n", i + 1, threads_no);
			goto error;
		}
		started++;
	}

	LM_NOTICE("TCP single IO mode started with %d threads\n", threads_no);
	return 0;

error:
	cond_lock(&tcp_write_queue->cond);
	tcp_pool.stop = 1;
	cond_broadcast(&tcp_write_queue->cond);
	cond_unlock(&tcp_write_queue->cond);

	if (tcp_pool.threads) {
		for (i = 0; i < started; i++)
			pthread_join(tcp_pool.threads[i], NULL);
		pkg_free(tcp_pool.threads);
		tcp_pool.threads = NULL;
	}
	tcp_pool.threads_no = 0;

	if (tcp_pool.notify_pipe[0] >= 0) {
		reactor_del_reader(tcp_pool.notify_pipe[0], -1, 0);
		close(tcp_pool.notify_pipe[0]);
		tcp_pool.notify_pipe[0] = -1;
	}
	if (tcp_pool.notify_pipe[1] >= 0) {
		close(tcp_pool.notify_pipe[1]);
		tcp_pool.notify_pipe[1] = -1;
	}

	return -1;
}

static void tcp_pool_destroy(void)
{
	int i;
	struct tcp_job *job;
	struct tcp_job *next;
	struct tcp_connection *conn;

	if (!tcp_threads_active() && tcp_pool.notify_pipe[0] < 0)
		return;

	cond_lock(&tcp_write_queue->cond);
	tcp_pool.stop = 1;
	cond_broadcast(&tcp_write_queue->cond);
	cond_unlock(&tcp_write_queue->cond);

	for (i = 0; i < tcp_pool.threads_no; i++)
		pthread_join(tcp_pool.threads[i], NULL);

	if (tcp_pool.threads) {
		pkg_free(tcp_pool.threads);
		tcp_pool.threads = NULL;
	}
	tcp_pool.threads_no = 0;

	if (tcp_pool.notify_pipe[0] >= 0) {
		reactor_del_reader(tcp_pool.notify_pipe[0], -1, 0);
		close(tcp_pool.notify_pipe[0]);
		tcp_pool.notify_pipe[0] = -1;
	}
	if (tcp_pool.notify_pipe[1] >= 0) {
		close(tcp_pool.notify_pipe[1]);
		tcp_pool.notify_pipe[1] = -1;
	}

	cond_lock(&tcp_write_queue->cond);
	for (job = tcp_pool.task_head; job; job = next) {
		next = job->next;
		if (job->conn)
			tcpconn_put(job->conn);
		thread_free(job);
	}
	tcp_pool.task_head = tcp_pool.task_tail = NULL;
	while ((conn = tcp_pop_shared_write_conn_locked()) != NULL) {
		conn->flags &= ~F_CONN_WRITE_QUEUED;
		tcpconn_put(conn);
	}
	cond_unlock(&tcp_write_queue->cond);

	pthread_mutex_lock(&tcp_pool.done_lock);
	for (job = tcp_pool.done_head; job; job = next) {
		next = job->next;
		if (job->conn)
			tcpconn_put(job->conn);
		thread_free(job);
	}
	tcp_pool.done_head = tcp_pool.done_tail = NULL;
	pthread_mutex_unlock(&tcp_pool.done_lock);
}

static int tcp_queue_job(struct tcp_connection *tcpconn, int op)
{
	struct tcp_job *job;

	if (!tcp_threads_active())
		return -1;

	job = thread_malloc(sizeof(*job));
	if (!job) {
		LM_ERR("oom while queuing TCP IO job\n");
		return -1;
	}

	job->conn = tcpconn;
	job->op = op;
	job->run = NULL;
	job->data = NULL;
	job->resp = 0;
	job->ret = 0;
	job->next = NULL;

	cond_lock(&tcp_write_queue->cond);
	if (tcp_pool.task_tail)
		tcp_pool.task_tail->next = job;
	else
		tcp_pool.task_head = job;
	tcp_pool.task_tail = job;
	cond_signal(&tcp_write_queue->cond);
	cond_unlock(&tcp_write_queue->cond);

	return 0;
}

int tcp_async_write_job(struct tcp_connection *tcpconn)
{
	if (!tcp_write_queue)
		return -1;
	if ((tcpconn->flags & F_CONN_HASHED) == 0)
		tcpconn_add(tcpconn);

	cond_lock(&tcp_write_queue->cond);
	if (tcpconn->flags & F_CONN_WRITE_QUEUED) {
		cond_unlock(&tcp_write_queue->cond);
		return 0;
	}

	tcpconn->flags |= F_CONN_WRITE_QUEUED;
	tcpconn->wq_next = NULL;
	if (tcp_write_queue->tail)
		tcp_write_queue->tail->wq_next = tcpconn;
	else
		tcp_write_queue->head = tcpconn;
	tcp_write_queue->tail = tcpconn;
	cond_signal(&tcp_write_queue->cond);
	cond_unlock(&tcp_write_queue->cond);
	return 0;
}

int tcp_run_task(tcp_thread_job_f run, void *data)
{
	struct tcp_job *job;

	if (!run)
		return -1;

	if (!tcp_threads_active()) {
		run(data);
		return 0;
	}

	job = thread_malloc(sizeof(*job));
	if (!job) {
		LM_ERR("oom while queuing TCP run job\n");
		return -1;
	}

	job->conn = NULL;
	job->op = TCP_RUN_JOB;
	job->run = run;
	job->data = data;
	job->resp = 0;
	job->ret = -1;
	job->next = NULL;

	cond_lock(&tcp_write_queue->cond);
	if (tcp_pool.task_tail)
		tcp_pool.task_tail->next = job;
	else
		tcp_pool.task_head = job;
	tcp_pool.task_tail = job;
	cond_signal(&tcp_write_queue->cond);
	cond_unlock(&tcp_write_queue->cond);

	return 0;
}

static inline int tcp_queue_write_job(struct tcp_connection *tcpconn)
{
	if (!(tcpconn->flags & F_CONN_REMOVED_READ) && tcpconn->fd != -1) {
		if (reactor_del_reader(tcpconn->fd, -1, 0) == -1)
			return -1;
		tcpconn->flags |= F_CONN_REMOVED_READ;
	}

	if (tcp_async_write_job(tcpconn) < 0)
		return -1;

	return 0;
}

static inline void tcp_fail_conn(struct tcp_connection *tcpconn,
		const char *reason, int report)
{
	if ((tcpconn->flags & F_CONN_REMOVED) != F_CONN_REMOVED &&
	    tcpconn->fd != -1) {
		reactor_del_all(tcpconn->fd, -1, IO_FD_CLOSING);
		tcpconn->flags |= F_CONN_REMOVED;
	}

	if (report)
		tcp_trigger_report(tcpconn, TCP_REPORT_CLOSE, (void *)reason);

	tcpconn_destroy(tcpconn);
}

static inline void tcp_complete_read(struct tcp_job *job)
{
	struct tcp_connection *tcpconn;

	tcpconn = job->conn;

	if (job->resp == -2) {
		tcp_fail_conn(tcpconn, "Timeout waiting for a complete message", 1);
		return;
	}

	if (job->resp < 0 || tcpconn->state == S_CONN_BAD) {
		tcp_fail_conn(tcpconn, "Read error", 1);
		return;
	}

	if (tcpconn->state == S_CONN_EOF) {
		tcp_fail_conn(tcpconn, "EOF received", 1);
		return;
	}

	if (tcpconn->flags & F_CONN_REMOVED_READ) {
		if (reactor_add_reader(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET, tcpconn) < 0) {
			LM_ERR("failed to re-add TCP conn %p for read events\n", tcpconn);
			tcp_fail_conn(tcpconn, "Failed to re-arm read", 0);
			return;
		}
		tcpconn->flags &= ~F_CONN_REMOVED_READ;
	}

	tcpconn_put(tcpconn);
}

static inline void tcp_complete_write(struct tcp_job *job)
{
	struct tcp_connection *tcpconn;
	int pending_chunks;

	tcpconn = job->conn;

	if (job->resp < 0 || tcpconn->state == S_CONN_BAD) {
		tcp_fail_conn(tcpconn, "Write error", 1);
		return;
	}

	lock_get(&tcpconn->write_lock);
	pending_chunks = (tcpconn->async && tcpconn->async->pending);
	lock_release(&tcpconn->write_lock);

	if ((tcpconn->flags & F_CONN_REMOVED_READ) && tcpconn->fd != -1) {
		if (reactor_add_reader(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET,
				tcpconn) < 0) {
			LM_ERR("failed to add TCP conn %p for read events\n", tcpconn);
			tcp_fail_conn(tcpconn, "Failed to arm read", 0);
			return;
		}
		tcpconn->flags &= ~F_CONN_REMOVED_READ;
	}

	if (job->resp == 1) {
		if (reactor_add_writer(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET, tcpconn) < 0) {
			LM_ERR("failed to re-add TCP conn %p for write events\n", tcpconn);
			tcp_fail_conn(tcpconn, "Failed to re-arm write", 0);
			return;
		}
		tcpconn->flags &= ~F_CONN_REMOVED_WRITE;
		tcpconn->flags &= ~F_CONN_WRITE_QUEUED;
		tcpconn_put(tcpconn);
		return;
	}

	if (pending_chunks) {
		tcpconn->flags &= ~F_CONN_WRITE_QUEUED;
		if (tcp_async_write_job(tcpconn) < 0) {
			LM_ERR("failed queuing follow-up TCP write job\n");
			tcpconn->flags &= ~F_CONN_WRITE_QUEUED;
			if (reactor_add_writer(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET, tcpconn) < 0) {
				tcp_fail_conn(tcpconn, "Failed queueing follow-up write", 0);
				return;
			}
			tcpconn->flags &= ~F_CONN_REMOVED_WRITE;
			tcpconn_put(tcpconn);
		}
		return;
	}

	tcpconn->flags &= ~F_CONN_WRITE_QUEUED;
	tcpconn_put(tcpconn);
}

static inline int handle_tcp_notify(int fd)
{
	char buf[64];
	int n;
	struct tcp_job *job;

	while ((n = read(fd, buf, sizeof(buf))) > 0)
		;
	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		LM_ERR("failed to read TCP IO notify fd: %s\n", strerror(errno));

	while ((job = tcp_pop_done_job()) != NULL) {
		if (job->op == TCP_READ_JOB)
			tcp_complete_read(job);
		else
			tcp_complete_write(job);
		thread_free(job);
	}

	return 0;
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
static inline int handle_new_connect(const struct socket_info* si)
{
	union sockaddr_union su;
	struct tcp_connection* tcpconn;
	struct tcp_conn_profile prof;
	socklen_t su_len = sizeof(su);
	int new_sock;
	unsigned int id;

	/* coverity[overrun-buffer-arg: FALSE] - union has 28 bytes, CID #200070 */
	new_sock = accept(si->socket, &(su.s), &su_len);
	if (new_sock == -1) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			return 0;
		LM_ERR("failed to accept connection(%d): %s\n", errno, strerror(errno));
		return -1;
	}

	tcp_con_get_profile(&su, &si->su, si->proto, &prof);
	if (tcp_init_sock_opt(new_sock, &prof, si->flags, si->tos) < 0) {
		LM_ERR("tcp_init_sock_opt failed\n");
		close(new_sock);
		return 1; /* success, because the accept was successful */
	}

	/* add socket to list */
	tcpconn = tcpconn_new(new_sock, &su, si, &prof, S_CONN_OK,
		F_CONN_ACCEPTED);
	if (tcpconn) {
		/* Safe: the connection is not yet visible outside TCP main. */
		tcpconn->refcnt++;
		sh_log(tcpconn->hist, TCP_REF, "accept, (%d)", tcpconn->refcnt);
		tcpconn_add(tcpconn);
		LM_DBG("new connection: %p %d flags: %04x\n",
			tcpconn, tcpconn->fd, tcpconn->flags);
		if (reactor_add_reader(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET,
				tcpconn) < 0) {
			LM_ERR("failed to add accepted TCP conn to reactor\n");
			id = tcpconn->id;
			TCPCONN_LOCK(id);
			tcpconn->refcnt--;
			if (tcpconn->refcnt == 0) {
				_tcpconn_rm(tcpconn, 1);
				close(new_sock);
			} else {
				tcpconn->lifetime = 0;
				tcpconn->timeout = 0;
			}
			TCPCONN_UNLOCK(id);
		} else {
			tcpconn->flags &= ~F_CONN_REMOVED_READ;
			tcpconn_put(tcpconn);
		}
	} else {
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
 */
inline static int handle_tcpconn_ev(struct tcp_connection* tcpconn, int fd_i,
		int event_type)
{
	int err;
	unsigned int err_len;

	if (event_type == IO_WATCH_READ) {
		LM_DBG("data available on %p %d\n", tcpconn, tcpconn->fd);
		if (reactor_del_reader(tcpconn->fd, fd_i, 0) == -1)
			return -1;
		tcpconn->flags |= F_CONN_REMOVED_READ;
		tcpconn_ref(tcpconn); /* refcnt ++ */
		sh_log(tcpconn->hist, TCP_REF, "tcp-main read queued, (%d)",
			tcpconn->refcnt);
		if (tcp_queue_job(tcpconn, TCP_READ_JOB) < 0) {
			LM_ERR("failed queuing TCP read job\n");
			if (reactor_add_reader(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET,
					tcpconn) < 0) {
				tcp_fail_conn(tcpconn, "Failed queueing read", 0);
				return 0;
			}
			tcpconn->flags &= ~F_CONN_REMOVED_READ;
			tcpconn_put(tcpconn);
		}
		return 0;
	} else {
		LM_DBG("connection %p fd %d is now writable\n", tcpconn, tcpconn->fd);
		/* we received a write event */
		if (tcpconn->state == S_CONN_CONNECTING) {
			/* we're coming from an async connect & write
			 * let's see if we connected successfully */
			err_len = sizeof(err);
			if (getsockopt(tcpconn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 ||
					err != 0) {
				LM_DBG("Failed connection attempt\n");
				tcpconn_ref(tcpconn);
				sh_log(tcpconn->hist, TCP_REF, "tcpconn connect, (%d)", tcpconn->refcnt);
				reactor_del_all(tcpconn->fd, fd_i, IO_FD_CLOSING);
				tcpconn->flags|=F_CONN_REMOVED;
				tcp_trigger_report(tcpconn, TCP_REPORT_CLOSE,
					"Async connect failed");
				sh_log(tcpconn->hist, TCP_UNREF, "tcpconn connect, (%d)", tcpconn->refcnt);
				tcpconn_destroy(tcpconn);
				return 0;
			}

			/* we successfully connected - further treat this case as if we
			 * were coming from an async write */
			tcpconn->state = S_CONN_OK;
			LM_DBG("Successfully completed previous async connect\n");

			/* now that we completed the async connection, we also need to
			 * listen for READ events, otherwise these will get lost */
			if (tcpconn->flags & F_CONN_REMOVED_READ) {
					reactor_add_reader(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET,
						tcpconn);
					tcpconn->flags &= ~F_CONN_REMOVED_READ;
				}

			goto async_write;
		} else {
async_write:
			/* no more write events for now */
				if (reactor_del_writer(tcpconn->fd, fd_i, 0) == -1)
					return -1;
			tcpconn->flags |= F_CONN_REMOVED_WRITE;
			tcpconn_ref(tcpconn); /* refcnt ++ */
			sh_log(tcpconn->hist, TCP_REF, "tcpconn write, (%d)",
				tcpconn->refcnt);
			if (tcp_queue_write_job(tcpconn) < 0) {
				LM_ERR("failed queuing TCP write job\n");
				if (reactor_add_writer(tcpconn->fd, F_TCPCONN, RCT_PRIO_NET,
						tcpconn) < 0) {
					tcp_fail_conn(tcpconn, "Failed queueing write", 0);
					return 0;
				}
				tcpconn->flags &= ~F_CONN_REMOVED_WRITE;
				tcpconn_put(tcpconn);
			}
			return 0;
		}
	}
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
			ret = handle_new_connect((const struct socket_info*)fm->data);
			break;
		case F_TCPCONN:
			ret = handle_tcpconn_ev((struct tcp_connection*)fm->data, idx,
				event_type);
			break;
		case F_TCP_NOTIFY:
			ret = handle_tcp_notify(fm->fd);
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
#define tcpconn_lifetime(last_sec) \
	do { \
		int now; \
		now = get_ticks(); \
		if (last_sec != now) { \
			last_sec = now; \
			__tcpconn_lifetime(0); \
		} \
	} while (0)


/*! \brief very inefficient for now - FIXME
 * keep in sync with tcpconn_destroy, the "delete" part should be
 * the same except for io_watch_del..
 * \todo FIXME (very inefficient for now)
 */
static inline void __tcpconn_lifetime(int shutdown)
{
	struct tcp_connection *c, *next;
	unsigned int ticks,part;
	unsigned h;
	int fd;
	void *reason;

	if (have_ticks())
		ticks=get_ticks();
	else
		ticks=0;

	for( part=0 ; part<TCP_PARTITION_SIZE ; part++ ) {
		if (!shutdown) TCPCONN_LOCK(part); /* fixme: we can lock only on delete IMO */
		for(h=0; h<TCP_ID_HASH_SIZE; h++){
			c=TCP_PART(part).tcpconn_id_hash[h];
			while(c){
				next=c->id_next;
				if (shutdown || ((c->refcnt == 0) &&
				((ticks > c->lifetime) ||
				(c->msg_attempts && ticks > c->timeout)))) {
					if (!shutdown)
						LM_DBG("timeout for hash=%d - %p"
								" (%d > %d)\n", h, c, ticks, c->lifetime);
					fd=c->fd;
					/* report the closing of the connection . Note that
					 * there are connectioned that use an foced expire to 0
					 * as a way to be deleted - we are not interested in */
					/* Also, do not trigger reporting when shutdown
					 * is done */
					if (c->lifetime>0 && !shutdown) {
						reason = (c->msg_attempts && ticks > c->timeout) ?
							"Timeout waiting for a complete message" :
							"Timeout on no traffic";
						tcp_trigger_report(c, TCP_REPORT_CLOSE, reason);
					}
					if ((!shutdown)&&(fd>0)&&(c->refcnt==0)) {
						/* if any of read or write are set, we need to remove
						 * the fd from the reactor */
						if ((c->flags & F_CONN_REMOVED) != F_CONN_REMOVED){
							reactor_del_all( fd, -1, IO_FD_CLOSING);
							c->flags|=F_CONN_REMOVED;
						}
						close(fd);
						c->fd = -1;
						}
						_tcpconn_rm(c, shutdown?1:0);
					}
					c=next;
				}
		}
		if (!shutdown) TCPCONN_UNLOCK(part);
	}
}


static void tcp_main_server(void)
{
	static unsigned int last_sec = 0;
	struct socket_info_full* sif;
	struct sr_module *m;
	int n;

	/* instruct tls_mgm to initialize all TLS domains */
	for (m=modules; m; m = m->next) {
		if (strcmp(m->exports->name, "tls_mgm") == 0)
			if (init_child(PROC_TCP_MAIN) < 0) {
				LM_ERR("error in init_child for PROC_TCP_MAIN\n");
				goto error;
			}
	}

	/* we run in a separate, dedicated process, with its own reactor
	 * (reactors are per process) */
	if (init_worker_reactor("TCP_main", RCT_PRIO_MAX)<0)
		goto error;

	/* now start watching all the fds */

	/* add all the sockets we listens on for connections */
	for (n = PROTO_FIRST; n < PROTO_LAST; n++)
		if (is_tcp_based_proto(n))
			for (sif = protos[n].listeners; sif; sif = sif->next) {
				struct socket_info* si = &sif->socket_info;
				if (protos[n].tran.bind_listener &&
						protos[n].tran.bind_listener(si) < 0) {
					LM_ERR("failed to bind listener [%.*s], proto %s\n",
						si->name.len, si->name.s, protos[n].name);
					goto error;
				}
				if (si->socket != -1 &&
						reactor_add_reader(si->socket, F_TCP_LISTENER,
							RCT_PRIO_NET, si) < 0) {
					LM_ERR("failed to add listen socket to reactor\n");
					goto error;
				}
			}
	/* init: start watching for the IPC jobs */
	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to reactor\n");
		goto error;
	}

	if (tcp_pool_init() < 0)
		goto error;

	is_tcp_main = 1;

	/* main loop (requires "handle_io()" implementation) */
	reactor_main_loop( TCP_MAIN_SELECT_TIMEOUT, error,
			tcpconn_lifetime(last_sec) );

error:
	tcp_pool_destroy();
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

	tcp_init_con_profiles();

	if (tcp_disabled)
		return 0;

#ifdef DBG_TCPCON
	con_hist = shl_init("TCP con", 10000, 0);
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
			LM_WARN("ignoring TCP auto-scaling profile in single IO mode\n");
			s_profile = NULL;
		}
	}

	tcp_workers_max_no = (s_profile && (tcp_workers_no<s_profile->max_procs)) ?
		s_profile->max_procs : tcp_workers_no ;

	/* init tcp workers array */
	tcp_workers = (struct tcp_worker*)shm_malloc
		( tcp_workers_max_no*sizeof(struct tcp_worker) );
	if (tcp_workers==0) {
		LM_CRIT("could not alloc tcp_workers array in shm memory\n");
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
	tcp_connections_no = (unsigned int *)shm_malloc(sizeof(*tcp_connections_no));
	if (tcp_connections_no == 0) {
		LM_CRIT("could not alloc tcp connection counter in shm memory\n");
		goto error;
	}
	*tcp_connections_no = 0;
	tcp_main_proc_no = (int *)shm_malloc(sizeof(*tcp_main_proc_no));
	if (tcp_main_proc_no == 0) {
		LM_CRIT("could not alloc tcp main proc slot in shm memory\n");
		goto error;
	}
	*tcp_main_proc_no = -1;
	tcp_write_queue = shm_malloc(sizeof(*tcp_write_queue));
	if (tcp_write_queue == 0) {
		LM_CRIT("could not alloc tcp shared write queue in shm memory\n");
		goto error;
	}
	memset(tcp_write_queue, 0, sizeof(*tcp_write_queue));
	if (cond_init(&tcp_write_queue->cond) != 0) {
		LM_CRIT("could not init tcp shared write queue cond\n");
		shm_free(tcp_write_queue);
		tcp_write_queue = 0;
		goto error;
	}
	tcp_connections_lock = lock_alloc();
	if (tcp_connections_lock == 0) {
		LM_CRIT("could not alloc tcp connection counter lock\n");
		goto error;
	}
	if (lock_init(tcp_connections_lock) == 0) {
		LM_CRIT("could not init tcp connection counter lock\n");
		lock_dealloc((void *)tcp_connections_lock);
		tcp_connections_lock = 0;
		goto error;
	}
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

	if (tcp_connections_no) {
		shm_free(tcp_connections_no);
		tcp_connections_no = 0;
	}

	if (tcp_main_proc_no) {
		shm_free(tcp_main_proc_no);
		tcp_main_proc_no = 0;
	}

	if (tcp_dispatch_sock[0] >= 0) {
		close(tcp_dispatch_sock[0]);
		tcp_dispatch_sock[0] = -1;
	}
	if (tcp_dispatch_sock[1] >= 0) {
		close(tcp_dispatch_sock[1]);
		tcp_dispatch_sock[1] = -1;
	}

	if (tcp_write_queue) {
		cond_destroy(&tcp_write_queue->cond);
		shm_free(tcp_write_queue);
		tcp_write_queue = 0;
	}

	if (tcp_connections_lock) {
		lock_destroy(tcp_connections_lock);
		lock_dealloc((void *)tcp_connections_lock);
		tcp_connections_lock = 0;
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


static int _get_own_tcp_worker_id(void)
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
		tcp_workers[i].pt_idx=0;
	}
}


/* counts the number of TCP processes to start with; this number may
 * change during runtime due auto-scaling */
int tcp_count_processes(unsigned int *extra)
{
	if (extra) *extra = 0;

	if (tcp_disabled)
		return 0;

	return 1 /* tcp main / IO process */ + tcp_workers_no /* dispatch workers */;
}


int tcp_start_processes(int *chd_rank, int *startup_done)
{
	int r, p_id, flags;
	const struct internal_fork_params ifp_sr_tcp = {
		.proc_desc = "SIP receiver TCP",
		.flags = OSS_PROC_NEEDS_SCRIPT,
		.type = TYPE_TCP,
	};

	if (tcp_disabled)
		return 0;

	/* create the shared dispatch socket from TCP main to TCP workers */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tcp_dispatch_sock) < 0) {
		LM_ERR("socketpair failed for TCP worker dispatch: %s\n",
			strerror(errno));
		goto error;
	}
	flags = fcntl(tcp_dispatch_sock[0], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed for TCP worker dispatch socket: %s\n",
			strerror(errno));
		goto error;
	}
	if (fcntl(tcp_dispatch_sock[0], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("failed to set non-blocking on TCP worker dispatch socket: %s\n",
			strerror(errno));
		goto error;
	}
	flags = fcntl(tcp_dispatch_sock[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed for TCP worker dispatch socket: %s\n",
			strerror(errno));
		goto error;
	}
	if (fcntl(tcp_dispatch_sock[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("failed to set non-blocking on TCP worker dispatch socket: %s\n",
			strerror(errno));
		goto error;
	}

	for (r = 0; r < tcp_workers_no; r++) {
		(*chd_rank)++;
		p_id = internal_fork(&ifp_sr_tcp);
		if (p_id < 0) {
			LM_ERR("cannot fork TCP worker process %d\n", r);
			goto error;
		} else if (p_id > 0) {
			/* parent */
			tcp_workers[r].state = STATE_ACTIVE;
			tcp_workers[r].pt_idx = p_id;
			continue;
		}

		/* child */
		if (tcp_dispatch_sock[1] >= 0)
			close(tcp_dispatch_sock[1]);
		tcp_dispatch_sock[1] = -1;

		set_proc_attrs("TCP receiver");
		tcp_workers[r].pid = getpid();

		if (tcp_worker_proc_reactor_init(tcp_dispatch_sock[0]) < 0 ||
				init_child(*chd_rank) < 0) {
			LM_ERR("init_child failed for TCP worker %d\n", r);
			report_failure_status();
			if (startup_done)
				*startup_done = -1;
			exit(-1);
		}

		/* first TCP worker runs startup_route if not already run */
		if (startup_done && *startup_done == 0 && r == 0) {
			LM_DBG("running startup route for first TCP worker\n");
			if (run_startup_route() < 0) {
				LM_ERR("startup route processing failed in TCP worker\n");
				report_failure_status();
				*startup_done = -1;
				exit(-1);
			}
			*startup_done = 1;
		}

		report_conditional_status((!no_daemon_mode), 0);
		tcp_worker_proc_loop();
	}

	if (tcp_dispatch_sock[0] >= 0) {
		close(tcp_dispatch_sock[0]);
		tcp_dispatch_sock[0] = -1;
	}

	if (startup_done && tcp_workers_no > 0)
		while (!(*startup_done)) {
			usleep(5);
			handle_sigs();
		}

	return 0;
error:
	if (tcp_dispatch_sock[0] >= 0) {
		close(tcp_dispatch_sock[0]);
		tcp_dispatch_sock[0] = -1;
	}
	if (tcp_dispatch_sock[1] >= 0) {
		close(tcp_dispatch_sock[1]);
		tcp_dispatch_sock[1] = -1;
	}
	return -1;
}

static int tcpconn_update_local_port(struct tcp_connection *tcpconn)
{
	union sockaddr_union local_su;
	socklen_t su_size;

	su_size = sockaddru_len(tcpconn->rcv.src_su);
	if (getsockname(tcpconn->fd, (struct sockaddr *)&local_su, &su_size) < 0) {
		LM_ERR("failed to get local socket info on conn %u: %s\n",
			tcpconn->id, strerror(errno));
		return -1;
	}

	tcpconn->rcv.dst_port = su_getport(&local_su);
	return 0;
}

static int tcpconn_prepare_write(struct tcp_connection *tcpconn)
{
	int fd;
	int connected = 0;

	if ((tcpconn->flags & F_CONN_INIT) == 0 &&
			protos[tcpconn->type].net.stream.conn.init) {
		if (protos[tcpconn->type].net.stream.conn.init(tcpconn) < 0) {
			LM_ERR("failed to init proto %d conn %p in TCP main\n",
				tcpconn->type, tcpconn);
			return -1;
		}
		tcpconn->flags |= F_CONN_INIT;
	}

	if (tcpconn->fd < 0) {
		if (!tcpconn->rcv.bind_address) {
			LM_ERR("missing bind_address for outbound conn %u\n", tcpconn->id);
			return -1;
		}

		fd = tcp_sync_connect_fd(&tcpconn->rcv.bind_address->su,
				&tcpconn->rcv.src_su, tcpconn->type, &tcpconn->profile,
				tcpconn->rcv.bind_address->flags,
				tcpconn->rcv.bind_address->tos);
		if (fd < 0)
			return -1;

		tcpconn->fd = fd;
		if (tcpconn_update_local_port(tcpconn) < 0) {
			close(fd);
			tcpconn->fd = -1;
			return -1;
		}

		tcpconn->state = S_CONN_OK;
		connected = 1;
	}

	if (connected && protos[tcpconn->type].net.stream.conn.connect) {
		if (protos[tcpconn->type].net.stream.conn.connect(tcpconn) < 0) {
			LM_ERR("failed to finish proto %d connect on conn %u\n",
				tcpconn->type, tcpconn->id);
			return -1;
		}
	}

	return 0;
}


int tcp_start_listener(void)
{
	int p_id;
	const struct internal_fork_params ifp_tcp_main = {
		.proc_desc = "TCP main",
		.flags = 0,
		.type = TYPE_NONE,
	};

	if (tcp_disabled)
		return 0;

	/* start the TCP manager process */
	if ( (p_id=internal_fork(&ifp_tcp_main))<0 ) {
		LM_CRIT("cannot fork tcp main process\n");
		goto error;
	}else if (p_id==0){
			/* child */
		report_conditional_status( (!no_daemon_mode), 0);

		tcp_main_server();
		exit(-1);
	}
	*tcp_main_proc_no = p_id;

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
