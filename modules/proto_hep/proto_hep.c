/*
 * Copyright (C) 2015-2023 - OpenSIPS Solutions
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
 *  2023-07-13  Add TLS transport support (Bence Szigeti <bence.szigeti@gohyda.com>)
 */

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <time.h>
#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/tcp_common.h"
#include "../../net/net_tcp.h"
#include "../../net/net_udp.h"
#include "../../socket_info.h"
#include "../../receive.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../ut.h"
#include "../../reactor_proc.h"
#include "../compression/compression_api.h"
#include "../tls_mgm/api.h"
#include "hep.h"
#include "hep_cb.h"
#include "signal.h"
#include "../../lib/list.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"


static int mod_init(void);
static void destroy(void);
static int proto_hep_init_udp(struct proto_info* pi);
static int proto_hep_init_tcp(struct proto_info* pi);
static int proto_hep_init_tls(struct proto_info* pi);
static int proto_hep_init_udp_listener(struct socket_info* si);
static int hep_tls_async_write(struct tcp_connection* con, int fd);
static int hep_tcp_read_req(struct tcp_connection* con, int* bytes_read);
static int hep_tls_read_req(struct tcp_connection* con, int* bytes_read);
static int hep_tcp_or_tls_read_req(struct tcp_connection* con, int* bytes_read,
		unsigned int is_tls);
static int hep_udp_read_req(const struct socket_info* si, int* bytes_read);
static int hep_udp_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id);
static int hep_tcp_or_tls_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id, unsigned int is_tls);
static int hep_tcp_or_tls_send_single(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id, unsigned int is_tls);
static int hep_tcp_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id);
static int hep_tls_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id);
static void update_recv_info(struct receive_info* ri, struct hep_desc* h);
void free_hep_context(void* ptr);
static int proto_hep_tls_conn_init(struct tcp_connection* c);
static void proto_hep_tls_conn_clean(struct tcp_connection* c);
static int hep_tls_write_on_socket(struct tcp_connection* c, int fd, char* buf, int len);
void hep_process(int rank);
static int use_single_process();


static int hep_port = HEP_PORT;
static int hep_async = 1;
static int hep_send_timeout = 100;
static int hep_async_max_postponed_chunks = 32;
static int hep_max_msg_chunks = 32;
static int hep_async_local_connect_timeout = 100;
static int hep_async_local_write_timeout = 10;
static int hep_tls_handshake_timeout = 100;
static int hep_tls_async_handshake_connect_timeout = 10;

int hep_ctx_idx = 0;
int hep_capture_id = 1;
int payload_compression = 0;

int homer5_on = 1;
str homer5_delim = {":", 0};

int *hep_process_no;
struct list_head *hep_job_list;
gen_lock_t *job_list_lock;
int *job_count;

compression_api_t compression_api;
load_compression_f load_compression;

static struct tcp_req hep_current_req;
/* we consider that different messages may contain different versions of hep
 * so we need to know what is the current version of hep */
static int hep_current_proto;

union sockaddr_union local_su;

struct tls_mgm_binds tls_mgm_api;

typedef struct hep_job {
	struct socket_info* send_sock;
	char *buf;
	unsigned int len;
	union sockaddr_union to;
	unsigned int id;
	unsigned int is_tls;
	time_t timestamp;
	struct list_head list;
} hep_job_t;

static const proc_export_t procs[] = {
	{"HEP worker",  0,  0, hep_process, 1, PROC_FLAG_HAS_IPC},
	{0,0,0,0,0,0}
};

static const cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_hep_init_udp, {{0,0,0}}, 0},
	{"proto_init", (cmd_function)proto_hep_init_tcp, {{0,0,0}}, 0},
	{"proto_init", (cmd_function)proto_hep_init_tls, {{0,0,0}}, 0},
	{"load_hep", (cmd_function)bind_proto_hep, {{0,0,0}}, 0},
	{"trace_bind_api", (cmd_function)hep_bind_trace_api, {{0,0,0}}, 0},
	{"correlate", (cmd_function)correlate_w, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

static const param_export_t params[] = {
	{ "hep_port",                        INT_PARAM, &hep_port                       },
	{ "hep_send_timeout",                INT_PARAM, &hep_send_timeout               },
	{ "hep_max_msg_chunks",              INT_PARAM, &hep_max_msg_chunks             },
	{ "hep_async",                       INT_PARAM, &hep_async                      },
	{ "hep_async_max_postponed_chunks",  INT_PARAM, &hep_async_max_postponed_chunks },
	/* what protocol shall be used: 1, 2 or 3 */
	{ "hep_capture_id",                  INT_PARAM, &hep_capture_id                 },
	{ "hep_async_local_connect_timeout", INT_PARAM, &hep_async_local_connect_timeout},
	{ "hep_async_local_write_timeout",   INT_PARAM, &hep_async_local_write_timeout  },
	{ "compressed_payload",              INT_PARAM, &payload_compression            },
	{ "hep_id",                          STR_PARAM|USE_FUNC_PARAM, parse_hep_id     },
	{ "homer5_on",                       INT_PARAM, &homer5_on                      },
	{ "homer5_delim",                    STR_PARAM, &homer5_delim.s                 },
	{ "use_single_process",				 INT_PARAM|USE_FUNC_PARAM,
													(void *)use_single_process		},
	{0, 0, 0}
};

static module_dependency_t* get_deps_compression(const param_export_t* param)
{
	int do_compression = *(int *)param->param_pointer;

	if (do_compression == 0) {
		return NULL;
	}

	return alloc_module_dep(MOD_TYPE_DEFAULT, "compression", DEP_ABORT);

}

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{"compressed_payload", get_deps_compression},
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	PROTO_PREFIX "hep",  /* module name                        */
	MOD_TYPE_DEFAULT,    /* class of this module               */
	MODULE_VERSION,      /* module version                     */
	DEFAULT_DLFLAGS,     /* dlopen flags                       */
	0,                   /* load function                      */
	&deps,               /* OpenSIPS module dependencies       */
	cmds,                /* exported functions                 */
	0,                   /* exported async functions           */
	params,              /* module parameters                  */
	0,                   /* exported statistics                */
	0,                   /* exported MI functions              */
	0,                   /* exported pseudo-variables          */
	0,                   /* exported transformations           */
	0,                   /* extra processes                    */
	0,                   /* module pre-initialization function */
	mod_init,            /* module initialization function     */
	0,                   /* response function                  */
	destroy,             /* destroy function                   */
	0,                   /* per-child init function            */
	0                    /* reload confirm function            */
};

static int mod_init(void)
{
	/* check if any listeners defined for this proto */
	if (!protos[PROTO_HEP_UDP].listeners && !protos[PROTO_HEP_TCP].listeners
		&& !protos[PROTO_HEP_TLS].listeners) {
		LM_ERR("No HEP listener defined!\n");
		return -1;
	}

	if (init_hep_id() < 0) {
		LM_ERR("could not initialize HEP id list!\n");
		return -1;
	}
	if (protos[PROTO_HEP_TLS].listeners && load_tls_mgm_api(&tls_mgm_api)!=0) {
		LM_DBG("failed to find TLS API - is tls_mgm module loaded?\n");
		return -1;
	}

	hep_process_no = (int*)shm_malloc(sizeof(int));
	if (!hep_process_no) {
		LM_ERR("Failed to allocate shared memory for current_process_no\n");
		return -1;
	}

	*hep_process_no = process_no;
	hep_job_list = (struct list_head *)shm_malloc(sizeof(struct list_head));
	if (!hep_job_list) {
		LM_ERR("Failed to allocate shared memory for hep_job_list\n");
		return -1;
	}
	INIT_LIST_HEAD(hep_job_list);

	job_list_lock = lock_alloc();
	if (job_list_lock == NULL) {
		LM_CRIT("ERROR\n");
		return -1;
	}

	if (lock_init(job_list_lock) < 0) {
		LM_CRIT("ERROR\n");
		lock_dealloc(job_list_lock);
		return -1;
	}

	job_count = (int *)shm_malloc(sizeof(int));
	if (!job_count) {
		LM_ERR("Failed to allocate shared memory for job_count\n");
		return -1;
	}
	*job_count = 0;

	if (payload_compression) {
		load_compression =
			(load_compression_f)find_export("load_compression", 0);
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
	homer5_delim.len = strlen(homer5_delim.s);

	local_su.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
	local_su.sin.sin_port = 0;
	local_su.sin.sin_family = AF_INET;

	return 0;
}

static void destroy(void)
{
	free_hep_cbs();
	destroy_hep_id();
}

static int use_single_process(modparam_t type, void * val)
{
	int p;

	p = (int)(unsigned long)val;

	if(p == 0) {
		return 0;
	}
	exports.procs = procs;
	return 0;
}

void hep_process(int rank) {

	*hep_process_no = process_no;
	suppress_proc_log_event();

	LM_DBG("Starting HEP worker process...\n");
	if (reactor_proc_init("HEP worker") != 0) {
		LM_CRIT("Failed to init HEP worker reactor\n");
		abort();
	}

	reactor_proc_loop();
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
			foo = it;
			it = it->next;
		}

		if (foo) {
			shm_free(foo->data);
			shm_free(foo);
		}
	}

	shm_free(ctx);
}


static int proto_hep_init_udp(struct proto_info* pi)
{

	pi->id                 = PROTO_HEP_UDP;
	pi->name               = "hep_udp";
	pi->default_port       = hep_port;
	pi->tran.init_listener = proto_hep_init_udp_listener;

	pi->tran.send          = hep_udp_send;

	pi->net.flags          = PROTO_NET_USE_UDP;
	pi->net.dgram.read     = hep_udp_read_req;

	return 0;
}

static int proto_hep_init_tcp(struct proto_info* pi)
{

	pi->id                 = PROTO_HEP_TCP;
	pi->name               = "hep_tcp";
	pi->default_port       = hep_port;
	pi->tran.init_listener = tcp_init_listener;

	pi->tran.dst_attr      = tcp_conn_fcntl;

	pi->net.flags          = PROTO_NET_USE_TCP;

	pi->net.stream.read    = hep_tcp_read_req;
	pi->net.stream.write   = tcp_async_write;

	pi->tran.send          = hep_tcp_send;

	if (hep_async) {
		pi->net.stream.async_chunks= hep_async_max_postponed_chunks;
	}

	return 0;
}

static int proto_hep_init_tls(struct proto_info* pi)
{

	pi->id                  = PROTO_HEP_TLS;
	pi->name                = "hep_tls";
	pi->default_port        = hep_port;
	pi->tran.init_listener  = tcp_init_listener;

	pi->tran.dst_attr       = tcp_conn_fcntl;

	pi->net.flags           = PROTO_NET_USE_TCP;

	pi->net.stream.read     = hep_tls_read_req;
	pi->net.stream.write    = hep_tls_async_write;

	pi->tran.send           = hep_tls_send;

	pi->net.stream.conn.init  = proto_hep_tls_conn_init;
	pi->net.stream.conn.clean = proto_hep_tls_conn_clean;

	if (hep_async && !tcp_has_async_write()) {
		LM_WARN("TCP network layer does not have support for ASYNC write, "
			"disabling it for TLS\n");
		hep_async = 0;
	}

	if (hep_async != 0) {
		pi->net.stream.async_chunks= hep_async_max_postponed_chunks;
	}

	return 0;
}

static int proto_hep_init_udp_listener(struct socket_info* si)
{
	return udp_init_listener(si, hep_async ? O_NONBLOCK : 0);
}

static int hep_udp_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id)
{
	int n, tolen;
	tolen = sockaddru_len(*to);

again:
	n=sendto(send_sock->socket, buf, len, 0, &to->s, tolen);
	if (n == -1){
		LM_ERR("sendto(sock,%p,%d,0,%p,%d): %s(%d)\n", buf, len, to, tolen,
			strerror(errno),errno);
		if (errno == EINTR || errno == EAGAIN) goto again;
		if (errno == EINVAL) {
			LM_CRIT("invalid sendtoparameters\n"
			"one possible reason is the server is bound to localhost and\n"
			"attempts to send to the net\n");
		}
	}
	return n;
}


static hep_job_t *create_hep_job(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id, unsigned int is_tls) {
	hep_job_t *new_job;
	new_job = (hep_job_t*)shm_malloc(sizeof(hep_job_t) + len);
	if (!new_job) {
		LM_ERR("failed to allocate memory for hep job\n");
		return NULL;
	}
	
	memset(new_job, 0, sizeof(*new_job));

	new_job->buf = (char *)(new_job + 1);

	memcpy(new_job->buf, buf, len);

	new_job->send_sock = (struct socket_info*)send_sock;
	new_job->len = len;
	if (to) {
		memcpy(&new_job->to, to, sizeof(union sockaddr_union));
	}
	new_job->id = id;
	new_job->is_tls = is_tls;
	new_job->timestamp = time(NULL);

	return new_job;
}

static void remove_job_from_list(hep_job_t *job) {

	lock_get(job_list_lock);

	list_del(&job->list);

	(*job_count)--;
	lock_release(job_list_lock);

	shm_free(job);
}

static void remove_expired_jobs(void) {
	time_t current_time = time(NULL);
	struct list_head *pos;
	hep_job_t *job;

	lock_get(job_list_lock);

	list_for_each(pos, hep_job_list) {
		job = list_entry(pos, hep_job_t, list);
		if (difftime(current_time, job->timestamp) > MAX_KEEP_JOB_TIME) {
			LM_INFO("Removing expired job with id: %u\n", job->id);
			remove_job_from_list(job);
		}
	}
	lock_release(job_list_lock);
}

static void add_job_to_list(hep_job_t *job) {

	remove_expired_jobs();

	if (*job_count >= MAX_NUMBER_OF_JOBS) {
		LM_ERR("Cannot add job, maximum number of jobs reached\n");
		return;
	}

	lock_get(job_list_lock);

	list_add_tail(&job->list, hep_job_list);

	lock_release(job_list_lock);

}


static void rpc_hep_tcp_or_tls_send(int sender, void* data) {
	hep_job_t* job = (hep_job_t*)data;
	LM_DBG("Handling job\n");
	if (hep_tcp_or_tls_send_single(job->send_sock, job->buf, job->len, &job->to, job->id, job->is_tls) < 0)
		add_job_to_list(job);

}


static int hep_tcp_or_tls_send_unify(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id, unsigned int is_tls) {
	hep_job_t *new_job;
	if (*hep_process_no != process_no) {
		LM_DBG("Sending to hep process: %d\n", *hep_process_no);
		new_job = create_hep_job(send_sock, buf, len, to, id, is_tls);
		if (new_job && ipc_send_rpc(*hep_process_no, rpc_hep_tcp_or_tls_send, new_job) == 0)
			return len;

	}
	add_job_to_list(new_job);

	return hep_tcp_or_tls_send(send_sock, buf, len, to, id, is_tls);
}

static int hep_tcp_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id)
{
	return hep_tcp_or_tls_send_unify(send_sock, buf, len, to, id, 0);
}

static int hep_tls_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id)
{
	return hep_tcp_or_tls_send_unify(send_sock, buf, len, to, id, 1);
}

static int hep_tcp_or_tls_send_single(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id, unsigned int is_tls)
{
	struct tcp_connection* c;
	int port = 0;
	struct ip_addr ip;
	int fd, n;

	if (to) {
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, is_tls ? PROTO_HEP_TLS : PROTO_HEP_TCP, NULL, &c, &fd, send_sock);
	} else if (id) {
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd, NULL);
	} else {
		LM_CRIT("tcp_send called with null id & to\n");
		return -1;
	}

	if (n < 0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to acquire connection\n");
		return -1;
	}

	/* was connection found ?? */
	if (c == 0) {
		struct tcp_conn_profile prof;
		int matched = tcp_con_get_profile(to, &send_sock->su, send_sock->proto, &prof);

		if ((matched && prof.no_new_conn) || (!matched && tcp_no_new_conn))
			return -1;

		if (!to) {
			LM_ERR("Unknown destination - cannot open new tcp connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one, async = %d\n", hep_async);
		/* create tcp connection */
		if (hep_async) {
			n = tcp_async_connect(send_sock, to, &prof,
					hep_async_local_connect_timeout, &c, &fd, 1);
			if (n < 0) {
				LM_ERR("async TCP connect failed\n");
				return -1;
			}
			/* connect succeeded, we have a connection */
			if (n == 0) {
				/* attach the write buffer to it */
				if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
					LM_ERR("Failed to add the initial write chunk\n");
					len = -1; /* report an error - let the caller decide what to do */
				}

				/* mark the ID of the used connection (tracing purposes) */
				last_outgoing_tcp_id = c->id;
				send_sock->last_real_ports->local = c->rcv.dst_port;
				send_sock->last_real_ports->remote = c->rcv.src_port;
				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when
				 * connect will be completed */
				LM_DBG("Successfully started async connection \n");
				tcp_conn_release(c, 0);
				return len;
			}
			if (is_tls) {
				LM_DBG("first TCP connect attempt succeeded in less than %dms, "
					"proceed to TLS connect \n", hep_async_local_connect_timeout);
				/* succesful TCP conection done - starting async SSL connect */

				lock_get(&c->write_lock);
				/* we connect under lock to make sure no one else is reading our
				 * connect status */
				tls_mgm_api.tls_update_fd(c, fd);
				n = tls_mgm_api.tls_async_connect(c, fd,
					hep_tls_async_handshake_connect_timeout, NULL);
				lock_release(&c->write_lock);
				if (n < 0) {
					LM_ERR("failed async TLS connect\n");
					tcp_conn_release(c, 0);
					return -1;
				}
				if (n == 0) {
					/* attach the write buffer to it */
					if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
						LM_ERR("failed to add the initial write chunk\n");
						tcp_conn_release(c, 0);
						return -1;
					}

					LM_DBG("successfully started async TLS connection\n");
					tcp_conn_release(c, 1);
					return len;
				}

				LM_DBG("first TLS handshake attempt succeeded in less than %dms, "
					"proceed to writing \n", hep_tls_async_handshake_connect_timeout);
			}
		} else if ((c = tcp_sync_connect(send_sock, to, &prof, &fd, 1)) == 0) {
			LM_ERR("connect failed\n");
			return -1;
		}
		goto send_it;
	}

	/* now we have a connection, let's see what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd == -1) {
		/* connection is not writable because of its state - can we append
		 * data to it for later writting (async writting)? */
		if (c->state == S_CONN_CONNECTING) {
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
				tcp_conn_release(c, 0);
				return -1;
			}

			/* mark the ID of the used connection (tracing purposes) */
			last_outgoing_tcp_id = c->id;
			send_sock->last_real_ports->local = c->rcv.dst_port;
			send_sock->last_real_ports->remote = c->rcv.src_port;

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

	if (is_tls) {
		n = hep_tls_write_on_socket(c, fd, buf, len);
	} else {
		n = tcp_write_on_socket(c, fd, buf, len,
			hep_send_timeout, hep_async_local_write_timeout);
	}

	tcp_conn_reset_lifetime(c);

	LM_DBG("after write: c= %p n/len=%d/%d fd=%d\n", c, n, len, fd);
	/* LM_DBG("buf=\n%.*s\n", (int)len, buf); */
	if (n < 0){
		LM_ERR("failed to send\n");
		c->state = S_CONN_BAD;
		if (c->proc_id != process_no) {
			close(fd);
		}
		tcp_conn_release(c, 0);
		return -1;
	}
	/* mark the ID of the used connection (tracing purposes) */
	last_outgoing_tcp_id = c->id;
	send_sock->last_real_ports->local = c->rcv.dst_port;
	send_sock->last_real_ports->remote = c->rcv.src_port;

	/* only close the FD if not already in the context of our process
	either we just connected, or main sent us the FD */
	if (c->proc_id != process_no) {
		close(fd);
	}


	tcp_conn_release(c, (n < len) ? 1 : 0 /*pending data in async mode?*/);

	return n;
}

static int hep_tcp_or_tls_send(const struct socket_info* send_sock,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id, unsigned int is_tls)
{
	struct tcp_connection* c;
	int port = 0;
	struct ip_addr ip;
	int fd, n;

	if (to) {
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, is_tls ? PROTO_HEP_TLS : PROTO_HEP_TCP, NULL, &c, &fd, send_sock);
	} else if (id) {
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd, NULL);
	} else {
		LM_CRIT("tcp_send called with null id & to\n");
		return -1;
	}

	if (n < 0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to acquire connection\n");
		return -1;
	}

	/* was connection found ?? */
	if (c == 0) {
		struct tcp_conn_profile prof;
		int matched = tcp_con_get_profile(to, &send_sock->su, send_sock->proto, &prof);

		if ((matched && prof.no_new_conn) || (!matched && tcp_no_new_conn))
			return -1;

		if (!to) {
			LM_ERR("Unknown destination - cannot open new tcp connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one, async = %d\n", hep_async);
		/* create tcp connection */
		if (hep_async) {
			n = tcp_async_connect(send_sock, to, &prof,
					hep_async_local_connect_timeout, &c, &fd, 1);
			if (n < 0) {
				LM_ERR("async TCP connect failed\n");
				return -1;
			}
			/* connect succeeded, we have a connection */
			if (n == 0) {
				/* attach the write buffer to it */
				if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
					LM_ERR("Failed to add the initial write chunk\n");
					len = -1; /* report an error - let the caller decide what to do */
				}

				/* mark the ID of the used connection (tracing purposes) */
				last_outgoing_tcp_id = c->id;
				send_sock->last_real_ports->local = c->rcv.dst_port;
				send_sock->last_real_ports->remote = c->rcv.src_port;
				/* connect is still in progress, break the sending
				 * flow now (the actual write will be done when
				 * connect will be completed */
				LM_DBG("Successfully started async connection \n");
				tcp_conn_release(c, 0);
				return len;
			}
			if (is_tls) {
				LM_DBG("first TCP connect attempt succeeded in less than %dms, "
					"proceed to TLS connect \n", hep_async_local_connect_timeout);
				/* succesful TCP conection done - starting async SSL connect */

				lock_get(&c->write_lock);
				/* we connect under lock to make sure no one else is reading our
				 * connect status */
				tls_mgm_api.tls_update_fd(c, fd);
				n = tls_mgm_api.tls_async_connect(c, fd,
					hep_tls_async_handshake_connect_timeout, NULL);
				lock_release(&c->write_lock);
				if (n < 0) {
					LM_ERR("failed async TLS connect\n");
					tcp_conn_release(c, 0);
					return -1;
				}
				if (n == 0) {
					/* attach the write buffer to it */
					if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
						LM_ERR("failed to add the initial write chunk\n");
						tcp_conn_release(c, 0);
						return -1;
					}

					LM_DBG("successfully started async TLS connection\n");
					tcp_conn_release(c, 1);
					return len;
				}

				LM_DBG("first TLS handshake attempt succeeded in less than %dms, "
					"proceed to writing \n", hep_tls_async_handshake_connect_timeout);
			}
		} else if ((c = tcp_sync_connect(send_sock, to, &prof, &fd, 1)) == 0) {
			LM_ERR("connect failed\n");
			return -1;
		}
		goto send_it;
	}

	/* now we have a connection, let's see what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd == -1) {
		/* connection is not writable because of its state - can we append
		 * data to it for later writting (async writting)? */
		if (c->state == S_CONN_CONNECTING) {
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
				tcp_conn_release(c, 0);
				return -1;
			}

			/* mark the ID of the used connection (tracing purposes) */
			last_outgoing_tcp_id = c->id;
			send_sock->last_real_ports->local = c->rcv.dst_port;
			send_sock->last_real_ports->remote = c->rcv.src_port;

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

	if (is_tls) {
		n = hep_tls_write_on_socket(c, fd, buf, len);
	} else {
		n = tcp_write_on_socket(c, fd, buf, len,
			hep_send_timeout, hep_async_local_write_timeout);
	}

	tcp_conn_reset_lifetime(c);

	LM_DBG("after write: c= %p n/len=%d/%d fd=%d\n", c, n, len, fd);
	/* LM_DBG("buf=\n%.*s\n", (int)len, buf); */
	if (n < 0){
		LM_ERR("failed to send\n");
		c->state = S_CONN_BAD;
		if (c->proc_id != process_no) {
			close(fd);
		}
		tcp_conn_release(c, 0);
		return -1;
	}
	/* mark the ID of the used connection (tracing purposes) */
	last_outgoing_tcp_id = c->id;
	send_sock->last_real_ports->local = c->rcv.dst_port;
	send_sock->last_real_ports->remote = c->rcv.src_port;

	/* only close the FD if not already in the context of our process
	either we just connected, or main sent us the FD */
	if (c->proc_id != process_no) {
		close(fd);
	}


	tcp_conn_release(c, (n < len) ? 1 : 0 /*pending data in async mode?*/);

	return n;
}

static void hep_parse_headers(struct tcp_req* req){
	/* message length */
	u_int16_t length = 0;
	hep_ctrl_t* ctrl;

	if (req->content_len == 0 && req->pos - req->buf < sizeof(hep_ctrl_t)) {
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

	if (req->pos - req->buf == req->content_len) {
		LM_DBG("received a COMPLETE message\n");
		req->complete = 1;
		req->parsed = req->buf + req->content_len;
	} else if (req->pos - req->buf > req->content_len) {
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

static int _tcp_read(struct tcp_connection* c, struct tcp_req* r) {
	int bytes_free, bytes_read;
	int fd;

	fd = c->fd;
	bytes_free= TCP_BUF_SIZE - (int)(r->pos - r->buf);

	if (bytes_free == 0) {
		LM_ERR("buffer overrun, dropping\n");
		r->error = TCP_REQ_OVERRUN;
		return -1;
	}

again:
	bytes_read=read(fd, r->pos, bytes_free);

	if (bytes_read == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			return 0; /* nothing has been read */
		} else if (errno == EINTR) {
			goto again;
		} else if (errno == ECONNRESET) {
			c->state=S_CONN_EOF;
			LM_DBG("EOF on %p, FD %d\n", c, fd);
			bytes_read = 0;
		} else {
			LM_ERR("error reading: %s\n",strerror(errno));
			r->error = TCP_READ_ERROR;
			return -1;
		}
	} else if (bytes_read==0) {
		c->state = S_CONN_EOF;
		LM_DBG("EOF on %p, FD %d\n", c, fd);
	}
#ifdef EXTRA_DEBUG
	LM_DBG("read %d bytes:\n%.*s\n", bytes_read, bytes_read, r->pos);
#endif
	r->pos += bytes_read;
	return bytes_read;
}

static inline int hep_handle_req(struct tcp_req* req,
							struct tcp_connection* con, int _max_msg_chunks)
{
	struct receive_info local_rcv;
	char* msg_buf;
	int msg_len;
	long size;

	int ret = 0;

	struct hep_context* hep_ctx = NULL;
	context_p ctx = NULL;

	if (req->complete){
		/* update the timeout - we successfully read the request */
		tcp_conn_reset_lifetime(con);
		con->timeout = con->lifetime;

		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1 = con->id; /* copy the id */

		/* prepare for next request */
		size = req->pos-req->parsed;

		msg_buf = req->buf;
		msg_len = req->parsed-req->start;
		local_rcv = con->rcv;

		if (!size) {
			/* did not read any more things -  we can release
			 * the connection */
			LM_DBG("Nothing more to read on TCP conn %p, currently in state %d \n",
				con, con->state);
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

		if (msg_buf[0] == 'H' && msg_buf[1] == 'E' && msg_buf[2] == 'P') {
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
			set_global_context(ctx);
			ret=run_hep_cbs();
			if (ret < 0) {
				LM_ERR("failed to run hep callbacks\n");
				goto error_free_hep;
			}
			set_global_context(NULL);

			msg_len = hep_ctx->h.u.hepv3.payload_chunk.chunk.length - sizeof(hep_chunk_t);
			/* remove the hep header; leave only the payload */
			msg_buf = hep_ctx->h.u.hepv3.payload_chunk.data;
		}

		/* skip receive msg if we were told so from at least one callback */
		if (ret != HEP_SCRIPT_SKIP) {
			if (receive_msg(msg_buf, msg_len, &local_rcv, ctx, 0) < 0) {
				LM_ERR("receive_msg failed \n");
			}
		} else {
			if (ctx) {
				context_free(ctx);
			}
		}

		if (hep_ctx) {
			free_hep_context(hep_ctx);
		}

		if (!size && req != &hep_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			shm_free(req);
			con->con_req = NULL;
		}

		con->msg_attempts = 0;

		if (size) {
			memmove(req->buf, req->parsed, size);
			init_tcp_req(req, size);
			return 1;
		}
	} else {
		/* request not complete - check the if the thresholds are exceeded */
		if (con->msg_attempts == 0) {
			/* if first iteration, set a short timeout for reading
			 * a whole SIP message */
			con->timeout = get_ticks() + tcp_max_msg_time;
		}

		con->msg_attempts++;
		if (con->msg_attempts == _max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				"closing connection \n",con->msg_attempts);
			goto error;
		}

		if (req == &hep_current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request\n");
			con->con_req = shm_malloc(sizeof(struct tcp_req));
			if (con->con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				goto error;
			}

			if (req->pos != req->buf) {
				/* we have read some bytes */
				memcpy(con->con_req->buf, req->buf, req->pos-req->buf);
				con->con_req->pos = con->con_req->buf + (req->pos-req->buf);
			} else {
				con->con_req->pos = con->con_req->buf;
			}

			if (req->parsed != req->buf) {
				con->con_req->parsed =con->con_req->buf+(req->parsed-req->buf);
			} else {
				con->con_req->parsed = con->con_req->buf;
			}

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

static int hep_tls_async_write(struct tcp_connection* con, int fd)
{
	int n;
	struct tcp_async_chunk* chunk;

	n = tls_mgm_api.tls_fix_read_conn(con, fd, hep_tls_handshake_timeout, NULL, 0);
	if (n < 0) {
		LM_ERR("failed to do pre-tls handshake!\n");
		return -1;
	} else if (n == 0) {
		LM_DBG("SSL accept/connect still pending!\n");
		return 1;
	}

	tls_mgm_api.tls_update_fd(con, fd);

	while ((chunk = tcp_async_get_chunk(con)) != NULL) {
		LM_DBG("trying to send %d bytes from chunk %p in conn %p - %d %d \n",
			chunk->len, chunk, con, chunk->ticks, get_ticks());

		n = tls_mgm_api.tls_write(con, fd, chunk->buf, chunk->len, NULL);
		if (n == 0) {
			LM_DBG("Can't finish to write chunk %p on conn %p\n",
				chunk,con);
			return 1;
		} else if (n < 0) {
			return -1;
		}

		tcp_async_update_write(con, n);
	}
	return 0;
}

static int hep_tcp_read_req(struct tcp_connection* con, int* bytes_read)
{
	return hep_tcp_or_tls_read_req(con, bytes_read, 0);
}

static int hep_tls_read_req(struct tcp_connection* con, int* bytes_read)
{
	return hep_tcp_or_tls_read_req(con, bytes_read, 1);
}

static int hep_tcp_or_tls_read_req(struct tcp_connection* con, int* bytes_read,
		unsigned int is_tls)
{
	int ret;
	int bytes;
	int total_bytes;
	struct tcp_req* req;

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
	
	if (is_tls) {
		ret = tls_mgm_api.tls_fix_read_conn(con, con->fd, hep_tls_handshake_timeout, NULL, 1);
		if (ret < 0) {
			LM_ERR("failed to do pre-tls handshake!\n");
			return -1;
		} else if (ret == 0) {
			LM_DBG("SSL accept/connect still pending!\n");
			return 0;
		}
	}

	if (con->state != S_CONN_OK) {
		goto done;
	}

again:
	if (req->error == TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed < req->pos){
			bytes = 0;
		} else {
			if (is_tls) {
				bytes = tls_mgm_api.tls_read(con, req);
			} else {
				bytes = _tcp_read(con, req);
			}
			if (bytes < 0) {
				LM_ERR("failed to read \n");
				goto error;
			} else if (bytes == 0 && con->state != S_CONN_EOF) {
				/* read would block */
				goto done;
			}
		}

		hep_parse_headers(req);

		total_bytes += bytes;
		/* eof check:
		 * is EOF if eof on fd and req.  not complete yet,
		 * if req. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state == S_CONN_EOF) && (req->complete == 0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->error != TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
			  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
			  (int)(req->pos-req->buf), req->buf,
			  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ", &con->rcv.src_ip, "\n");
		goto error;
	}

	int max_chunks = tcp_attr_isset(con, TCP_ATTR_MAX_MSG_CHUNKS) ?
			con->profile.attrs[TCP_ATTR_MAX_MSG_CHUNKS] : hep_max_msg_chunks;

	switch (hep_handle_req(req, con, max_chunks)) {
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

static int hep_udp_read_req(const struct socket_info* si, int* bytes_read)
{
	struct receive_info ri;
	int len;
	static char buf [BUF_SIZE + 1];
	unsigned int fromlen;
	str msg;

	struct hep_context* hep_ctx;

	int ret = 0;

	context_p ctx = NULL;

	fromlen=sockaddru_len(si->su);
	len=recvfrom(bind_address->socket, buf, BUF_SIZE, 0, &ri.src_su.s, &fromlen);
	if (len == -1){
		if (errno == EAGAIN) {
			return 0;
		}
		if ((errno == EINTR) || (errno == EWOULDBLOCK) || (errno == ECONNREFUSED)) {
			return -1;
		}
		LM_ERR("recvfrom:[%d] %s\n", errno, strerror(errno));
		return -2;
	}


	if (len < MIN_UDP_PACKET) {
		LM_DBG("probing packet received len = %d\n", len);
		return 0;
	}

	/* we must 0-term the messages, receive_msg expects it */
	buf[len] = 0; /* no need to save the previous char */

	ri.bind_address = si;
	ri.dst_port = si->port_no;
	ri.dst_ip = si->address;
	ri.proto = si->proto;
	ri.proto_reserved1 = ri.proto_reserved2 = 0;

	su2ip_addr(&ri.src_ip, &ri.src_su);
	ri.src_port = su_getport(&ri.src_su);

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
		/* coverity[tainted_data] */
		if (unpack_hepv3(buf, len, &hep_ctx->h)) {
			LM_ERR("hepv3 unpacking failed\n");
			return -1;
		}
	} else {
		/* HEPv2 */
		/* coverity[tainted_data] */
		if (unpack_hepv12(buf, len, &hep_ctx->h)) {
			LM_ERR("hepv12 unpacking failed\n");
			return -1;
		}
	}

	/* set context for receive_msg */
	if ((ctx = context_alloc(CONTEXT_GLOBAL)) == NULL) {
		LM_ERR("failed to allocate new context! skipping...\n");
		goto error_free_hep;
	}

	memset(ctx, 0, context_size(CONTEXT_GLOBAL));

	context_put_ptr(CONTEXT_GLOBAL, ctx, hep_ctx_idx, hep_ctx);

	update_recv_info(&ri, &hep_ctx->h);

	/* run hep callbacks; set the current processing context
	 * to hep context; this way callbacks will have all the data
	 * needed */
	set_global_context(ctx);
	ret = run_hep_cbs();
	set_global_context(NULL);
	if (ret < 0) {
		LM_ERR("failed to run hep callbacks\n");
		return -1;
	}

	if (hep_ctx->h.version == 3) {
		/* HEPv3 */
		msg.len =
			hep_ctx->h.u.hepv3.payload_chunk.chunk.length - sizeof(hep_chunk_t);
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
		receive_msg( msg.s, msg.len, &ri, ctx, 0);
	} else {
		if (ctx) {
			context_free(ctx);
		}
	}

	free_hep_context(hep_ctx);

	return 0;

error_free_hep:
	shm_free(hep_ctx);
	return -1;

}

static void update_recv_info(struct receive_info* ri, struct hep_desc* h)
{
	unsigned proto;
	unsigned ip_family;
	unsigned sport, dport;

	struct ip_addr dst_ip, src_ip;

	switch (h->version) {
		case 1:
		case 2:
			ip_family = h->u.hepv12.hdr.hp_f;
			proto     = h->u.hepv12.hdr.hp_p;
			sport     = h->u.hepv12.hdr.hp_sport;
			dport     = h->u.hepv12.hdr.hp_dport;
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

	     if (proto == IPPROTO_UDP) ri->proto=PROTO_UDP;
	else if (proto == IPPROTO_TCP) ri->proto=PROTO_TCP;
	else if (proto == IPPROTO_IDP) ri->proto=PROTO_TLS;
	/* fake protocol */
	else if (proto == IPPROTO_SCTP) ri->proto=PROTO_SCTP;
	else if (proto == IPPROTO_ESP) ri->proto=PROTO_WS;
	/* fake protocol */
	else {
		LM_ERR("unknown protocol [%d]\n", proto);
		proto = PROTO_NONE;
	}

	if (h->version == 3) {
		h->u.hepv3.hg.ip_proto.data = ri->proto;
	}

	ri->src_ip   = src_ip;
	ri->src_port = sport;

	ri->dst_ip   = dst_ip;
	ri->dst_port = dport;
}

static int proto_hep_tls_conn_init(struct tcp_connection* c)
{
	struct tls_domain* dom;

	c->proto_data = 0;

	if (c->flags & F_CONN_ACCEPTED) {
		LM_DBG("looking up TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = tls_mgm_api.find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
	} else {
		dom = tls_mgm_api.find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
	}
	if (!dom) {
		LM_ERR("no TLS %s domain found\n",
			(c->flags & F_CONN_ACCEPTED ? "server" : "client"));
		return -1;
	}

	return tls_mgm_api.tls_conn_init(c, dom);
}

static void proto_hep_tls_conn_clean(struct tcp_connection* c)
{
	struct tls_domain* dom;

	tls_mgm_api.tls_conn_clean(c, &dom);

	if (!dom) {
		LM_ERR("Failed to retrieve the tls_domain pointer in the SSL struct\n");
	} else {
		tls_mgm_api.release_domain(dom);
	}
}

static int hep_tls_write_on_socket(struct tcp_connection* c, int fd, char* buf, int len)
{
	int n;
	lock_get(&c->write_lock);
	if (c->async) {
		if (!c->async->pending) {
			if (tls_mgm_api.tls_update_fd(c, fd) < 0) {
				n = -1;
				goto release;
			}

			n = tls_mgm_api.tls_write(c, fd, buf, len, NULL);
			if (n >= 0 && len - n) {
				n = tcp_async_add_chunk(c, buf + n, len - n, 0);
			}
		} else {
			n = tcp_async_add_chunk(c, buf, len, 0);
		}
	} else {
		n = tls_mgm_api.tls_blocking_write(c, fd, buf, len,
			hep_tls_handshake_timeout, hep_send_timeout, NULL);
}
release:
	lock_release(&c->write_lock);
	return n;
}
