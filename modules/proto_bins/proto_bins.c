/*
 * Copyright (C) 2021 - OpenSIPS Foundation
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
 */

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/tcp_common.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../bin_interface.h"
#include "../../ut.h"

#include "../tls_mgm/api.h"

#define MARKER_SIZE 4

static int mod_init(void);

static int proto_bins_init(struct proto_info *pi);
static int proto_bins_init_listener(struct socket_info *si);
static int proto_bins_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id);
static int bins_read_req(struct tcp_connection* con, int* bytes_read);
static int bins_async_write(struct tcp_connection* con,int fd);
static int proto_bins_conn_init(struct tcp_connection* c);
static void proto_bins_conn_clean(struct tcp_connection* c);

static int bins_port = 5556;
static int bins_send_tout = 100;
static int bins_max_msg_chunks = 32;
static int bins_async = 1;
static int bins_async_max_postponed_chunks = 32;
static int bins_async_local_connect_timeout = 100;
static int bins_handshake_tout = 100;
static int bins_async_handshake_connect_timeout = 10;

static struct tcp_req bins_current_req;

#define _bin_common_current_req  bins_current_req
#include "../proto_bin/bin_common.h"

struct tls_mgm_binds tls_mgm_api;

static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_bins_init, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[] = {
	{ "bins_port",                       INT_PARAM, &bins_port              },
	{ "bins_send_timeout",               INT_PARAM, &bins_send_tout         },
	{ "bins_max_msg_chunks",             INT_PARAM, &bins_max_msg_chunks    },
	{ "bins_handshake_timeout", 	     INT_PARAM, &bins_handshake_tout    },
	{ "bins_async",                      INT_PARAM, &bins_async             },
	{ "bins_async_max_postponed_chunks", INT_PARAM,
											&bins_async_max_postponed_chunks},
	{ "bins_async_local_connect_timeout",INT_PARAM,
										   &bins_async_local_connect_timeout},
	{ "bins_async_handshake_timeout",	 INT_PARAM,
									&bins_async_handshake_connect_timeout },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tls_mgm", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	PROTO_PREFIX "bins",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,		    /* load function */
	&deps,       /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
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

static int proto_bins_init(struct proto_info *pi)
{
	pi->id					= PROTO_BINS;
	pi->name				= "bins";
	pi->default_port		= bins_port;

	pi->tran.init_listener	= proto_bins_init_listener;
	pi->tran.send			= proto_bins_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)bins_read_req;
	pi->net.write			= (proto_net_write_f)bins_async_write;
	pi->net.conn_init		= proto_bins_conn_init;
	pi->net.conn_clean		= proto_bins_conn_clean;

	if (bins_async && !tcp_has_async_write()) {
		LM_WARN("TCP network layer does not have support for ASYNC write, "
			"disabling it for BINS\n");
		bins_async = 0;
	}

	if (bins_async != 0)
		pi->net.async_chunks= bins_async_max_postponed_chunks;

	return 0;
}

static int mod_init(void)
{
	LM_INFO("initializing BINS protocol\n");

	if (load_tls_mgm_api(&tls_mgm_api) != 0){
		LM_DBG("failed to find tls API - is tls_mgm module loaded?\n");
		return -1;
	}

	return 0;
}

static int proto_bins_init_listener(struct socket_info *si)
{
	/* we do not do anything particular, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}

static int proto_bins_conn_init(struct tcp_connection* c)
{
	struct tls_domain *dom;

	c->proto_data = 0;

	if (c->flags&F_CONN_ACCEPTED) {
		LM_DBG("looking up TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = tls_mgm_api.find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
	} else {
		dom = tls_mgm_api.find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
	}
	if (!dom) {
		LM_ERR("no TLS %s domain found\n",
				(c->flags&F_CONN_ACCEPTED?"server":"client"));
		return -1;
	}

	return tls_mgm_api.tls_conn_init(c, dom);
}

static void proto_bins_conn_clean(struct tcp_connection* c)
{
	struct tls_domain *dom;

	tls_mgm_api.tls_conn_clean(c, &dom);

	if (!dom)
		LM_ERR("Failed to retrieve the tls_domain pointer in the SSL struct\n");
	else
		tls_mgm_api.release_domain(dom);
}

static int bins_write_on_socket(struct tcp_connection* c, int fd,
		char *buf, int len)
{
	int n;

	lock_get(&c->write_lock);
	if (c->async) {
		/*
		 * if there is any data pending to write, we have to wait for those chunks
		 * to be sent, otherwise we will completely break the messages' order
		 */
		if (!c->async->pending) {
			if (tls_mgm_api.tls_update_fd(c, fd) < 0) {
				n = -1;
				goto release;
			}

			n = tls_mgm_api.tls_write(c, fd, buf, len, NULL);
			if (n >= 0 && len - n) {
				/* if could not write entire buffer, delay it */
				n = tcp_async_add_chunk(c, buf + n, len - n, 0);
			}
		} else {
			n = tcp_async_add_chunk(c, buf, len, 0);
		}
	} else {
		n = tls_mgm_api.tls_blocking_write(c, fd, buf, len,
				bins_handshake_tout, bins_send_tout, NULL);
	}
release:
	lock_release(&c->write_lock);

	return n;
}

static int proto_bins_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to,
		unsigned int id)
{
	struct tcp_connection *c;
	struct ip_addr ip;
	int port;
	int fd, n;
	int send2main = 0;

	port=0;

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, PROTO_BINS, NULL, &c, &fd, send_sock);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd, NULL);
	}else{
		LM_CRIT("send called with null id & to\n");
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
		LM_DBG("no open tcp connection found, opening new one, async = %d\n",
			bins_async);
		/* create tcp connection */
		if (bins_async) {
			n = tcp_async_connect(send_sock, to,
					bins_async_local_connect_timeout, &c, &fd, 1);
			if ( n<0 ) {
				LM_ERR("async TCP connect failed\n");
				return -1;
			}
			/* connect succeeded, we have a connection */
			if (n==0) {
				/* attach the write buffer to it */
				if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
					LM_ERR("Failed to add the initial write chunk\n");
					tcp_conn_release(c, 0);
					return -1;
				}

				/* mark the ID of the used connection (tracing purposes) */
				last_outgoing_tcp_id = c->id;
				send_sock->last_local_real_port = c->rcv.dst_port;
				send_sock->last_remote_real_port = c->rcv.src_port;

				LM_DBG("Successfully started async connection\n");
				tcp_conn_release(c, 0);
				return len;
			}

			LM_DBG("First TCP connect attempt succeeded in less than %dms, "
				"proceed to TLS connect \n",bins_async_local_connect_timeout);
			/* succesful TCP conection done - starting async SSL connect */

			lock_get(&c->write_lock);
			/* we connect under lock to make sure no one else is reading our
			 * connect status */
			tls_mgm_api.tls_update_fd(c, fd);
			n = tls_mgm_api.tls_async_connect(c, fd,
				bins_async_handshake_connect_timeout, NULL);
			lock_release(&c->write_lock);
			if (n<0) {
				LM_ERR("failed async TLS connect\n");
				tcp_conn_release(c, 0);
				return -1;
			}
			if (n==0) {
				/* attach the write buffer to it */
				if (tcp_async_add_chunk(c, buf, len, 1) < 0) {
					LM_ERR("Failed to add the initial write chunk\n");
					tcp_conn_release(c, 0);
					return -1;
				}

				LM_DBG("Successfully started async TLS connection\n");
				tcp_conn_release(c, 1);
				return len;
			}

			LM_DBG("First TLS handshake attempt succeeded in less than %dms, "
				"proceed to writing \n",bins_async_handshake_connect_timeout);
		} else {
			if ((c=tcp_sync_connect(send_sock, to, &fd, 0))==0) {
				LM_ERR("connect failed\n");
				return -1;
			}

			send2main = 1;
		}

		goto send;
	}

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
				tcp_conn_release(c, 0);
				return -1;
			}

			/* mark the ID of the used connection (tracing purposes) */
			last_outgoing_tcp_id = c->id;
			send_sock->last_local_real_port = c->rcv.dst_port;
			send_sock->last_remote_real_port = c->rcv.src_port;

			/* we successfully added our write chunk - success */
			tcp_conn_release(c, 0);
			return len;
		} else {
			/* return error, nothing to do about it */
			LM_ERR("Bad connection state\n");
			tcp_conn_release(c, 0);
			return -1;
		}
	}

send:
	LM_DBG("sending via fd %d...\n",fd);

	n = bins_write_on_socket(c, fd, buf, len);

	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n/len=%d/%d fd=%d\n",c, n, len, fd);
	if (n<0){
		LM_ERR("failed to send\n");
		goto err_release;
	}

	if (send2main && tcp_conn_send(c) < 0) {
		LM_ERR("cannot send socket to main\n");
		goto err_release;
	}

	/* only close the FD if not already in the context of our process
	either we just connected, or main sent us the FD */
	if (c->proc_id != process_no)
		close(fd);

	/* mark the ID of the used connection (tracing purposes) */
	last_outgoing_tcp_id = c->id;
	send_sock->last_local_real_port = c->rcv.dst_port;
	send_sock->last_remote_real_port = c->rcv.src_port;

	tcp_conn_release(c, (n<len)?1:0/*pending data in async mode?*/ );
	return n;
err_release:
	if (send2main) {
		close(fd);
		tcp_conn_destroy(c);
	} else {
		c->state=S_CONN_BAD;
		if (c->proc_id != process_no)
			close(fd);
		tcp_conn_release(c, 0);
	}
	return -1;
}

static int bins_async_write(struct tcp_connection* con, int fd)
{
	int n;
	struct tcp_async_chunk *chunk;

	n = tls_mgm_api.tls_fix_read_conn(con, fd, bins_handshake_tout, NULL, 0);
	if (n < 0) {
		LM_ERR("failed to do pre-tls handshake!\n");
		return -1;
	} else if (n == 0) {
		LM_DBG("SSL accept/connect still pending!\n");
		return 1;
	}

	tls_mgm_api.tls_update_fd(con, fd);

	while ((chunk = tcp_async_get_chunk(con)) != NULL) {
		LM_DBG("Trying to send %d bytes from chunk %p in conn %p - %d %d \n",
				chunk->len, chunk, con, chunk->ticks, get_ticks());

		n = tls_mgm_api.tls_write(con, fd, chunk->buf, chunk->len, NULL);
		if (n==0) {
			LM_DBG("Can't finish to write chunk %p on conn %p\n",
					chunk,con);
			/* report back we have more writting to be done */
			return 1;
		} else if (n < 0) {
			return -1;
		}

		tcp_async_update_write(con, n);
	}
	return 0;
}

static int bins_read_req(struct tcp_connection* con, int* bytes_read)
{
	int ret;
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
		init_tcp_req(&bins_current_req, 0);
		req = &bins_current_req;
	}

	ret=tls_mgm_api.tls_fix_read_conn(con, con->fd, bins_handshake_tout, NULL, 1);
	if (ret < 0) {
		LM_ERR("failed to do pre-tls handshake!\n");
		return -1;
	} else if (ret == 0) {
		LM_DBG("SSL accept/connect still pending!\n");
		return 0;
	}

	if(con->state!=S_CONN_OK)
		goto done; /* not enough data */

again:
	if(req->error == TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed < req->pos){
			bytes=0;
		} else {
			bytes=tls_mgm_api.tls_read(con,req);
			if (bytes < 0) {
				LM_ERR("failed to read \n");
				goto error;
			} else if (bytes == 0 && con->state != S_CONN_EOF) {
				/* read would block */
				goto done;
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

	switch (bin_handle_req(req, con, bins_max_msg_chunks) ) {
		case 1:
			goto again;
		case -1:
			goto error;
	}

	LM_DBG("bins_read_req end\n");
done:
	if (bytes_read) *bytes_read=total_bytes;
	/* connection will be released */
		return 0;
error:
	/* connection will be released as ERROR */
		return -1;
}
