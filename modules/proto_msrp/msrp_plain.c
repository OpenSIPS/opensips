/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../socket_info.h"
#include "../../trace_api.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../net/net_tcp_report.h"
#include "../../net/trans_trace.h"
#include "../../net/tcp_common.h"
#include "msrp_common.h"


extern trace_dest msrp_t_dst;

int msrp_send_timeout = 100;
int msrp_max_msg_chunks = 4;

int *msrp_trace_is_on;
int  msrp_trace_filter_route_id = -1;

#define F_TCP_CONN_TRACED ( 1 << 0 )
#define TRACE_ON(flags) (msrp_t_dst && (*msrp_trace_is_on) && \
						!(flags & F_CONN_TRACE_DROPPED))



int proto_msrp_init_listener(struct socket_info *si)
{
	/* we do not do anything particular to TCP plain here, so
	 * transparently use the generic listener init from net TCP layer */
	return tcp_init_listener(si);
}


void msrp_report(int type, unsigned long long conn_id, int conn_flags,
		void *extra)
{
	str s;

	if (type==TCP_REPORT_CLOSE) {

		if ( !TRACE_ON( conn_flags ) )
			return;

		/* grab reason text */
		if (extra) {
			s.s = (char*)extra;
			s.len = strlen (s.s);
		}

		trace_message_atonce( PROTO_MSRP, conn_id, NULL/*src*/, NULL/*dst*/,
			TRANS_TRACE_CLOSED, TRANS_TRACE_SUCCESS, extra?&s:NULL,
			msrp_t_dst );
	}

	return;
}


/**************  SEND related functions ***************/

/*! \brief Finds a tcpconn & sends on it */
int proto_msrp_send(struct socket_info* send_sock,
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
		LM_DBG("no open tcp connection found, opening new one\n");
		/* create tcp connection */
		if ((c=tcp_sync_connect(send_sock, to, &fd, 1))==0) {
			LM_ERR("connect failed\n");
			get_time_difference(get,tcpthreshold,tcp_timeout_con_get);
			return -1;
		}

		if ( TRACE_ON( c->flags ) &&
				check_trace_route( msrp_trace_filter_route_id, c) ) {
			c->proto_flags |= F_TCP_CONN_TRACED;
			if ( tcpconn2su( c, &src_su, &dst_su) < 0 ) {
				LM_ERR("can't create su structures for tracing!\n");
			} else {
				trace_message_atonce( PROTO_TCP, c->cid, &src_su, &dst_su,
					TRANS_TRACE_CONNECTED, TRANS_TRACE_SUCCESS,
					&CONNECT_OK, msrp_t_dst );
			}
		}

		LM_DBG( "Successfully connected from interface %s:%d to %s:%d!\n",
			ip_addr2a( &c->rcv.src_ip ), c->rcv.src_port,
			ip_addr2a( &c->rcv.dst_ip ), c->rcv.dst_port );

		goto send_it;
	}

	if ( !(c->proto_flags & F_TCP_CONN_TRACED) ) {
		/* most probably it's an async connect */
		if ( TRACE_ON( c->flags ) ) {
			trace_message_atonce( PROTO_TCP, c->cid, 0, 0,
				TRANS_TRACE_CONNECTED, TRANS_TRACE_SUCCESS,
				&CONNECT_OK, msrp_t_dst );
		}

		c->proto_flags |= F_TCP_CONN_TRACED;
	}

	get_time_difference(get,tcpthreshold,tcp_timeout_con_get);

	/* now we have a connection, let's see what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd==-1) {
		/* connection is not writable because of its state */
		/* return error, nothing to do about it */
		tcp_conn_release(c, 0);
		return -1;
	}


send_it:
	LM_DBG("sending via fd %d...\n",fd);

	start_expire_timer(snd,tcpthreshold);

	n = tcp_write_on_socket(c, fd, buf, len,
			msrp_send_timeout, 0);

	get_time_difference(snd,tcpthreshold,tcp_timeout_send);
	stop_expire_timer(get,tcpthreshold,"MSRP ops",buf,(int)len,1);

	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n/len=%d/%d fd=%d\n",c, n, len, fd);
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
	send_sock->last_local_real_port = c->rcv.dst_port;
	send_sock->last_remote_real_port = c->rcv.src_port;

	tcp_conn_release(c, 0);
	return n;
}



/**************  READ related functions ***************/

/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also r->error
 */
static int msrp_read(struct tcp_connection *c, struct msrp_req *r)
{
	int bytes_free, bytes_read;
	int fd;

	fd=c->fd;
	bytes_free=MSRP_BUF_SIZE- (int)(r->pos - r->buf);

	if (bytes_free==0){
		LM_ERR("buffer overrun, dropping\n");
		r->error=MSRP_REQ_OVERRUN;
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
			r->error=MSRP_READ_ERROR;
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
int msrp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	struct msrp_req* req;

	union sockaddr_union src_su, dst_su;

	if ( !(con->proto_flags & F_TCP_CONN_TRACED)) {
		con->proto_flags |= F_TCP_CONN_TRACED;

		LM_DBG("Accepted connection from %s:%d on interface %s:%d!\n",
			ip_addr2a( &con->rcv.src_ip ), con->rcv.src_port,
			ip_addr2a( &con->rcv.dst_ip ), con->rcv.dst_port );

		if ( TRACE_ON( con->flags ) &&
					check_trace_route( msrp_trace_filter_route_id, con) ) {
			if ( tcpconn2su( con, &src_su, &dst_su) < 0 ) {
				LM_ERR("can't create su structures for tracing!\n");
			} else {
				trace_message_atonce( PROTO_MSRP, con->cid, &src_su, &dst_su,
					TRANS_TRACE_ACCEPTED, TRANS_TRACE_SUCCESS,
					&ACCEPT_OK, msrp_t_dst );
			}
		}
	}

	bytes=-1;
	total_bytes=0;

	if (con->con_req) {
		req = (struct msrp_req*)con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_msrp_req(&msrp_current_req, 0);
		req = &msrp_current_req;
	}

again:
	if(req->error==MSRP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed<req->pos){
			bytes=0;
		}else{
			bytes=msrp_read(con,req);
			if (bytes<0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		/* some data left unparsed */
		if ( req->parsed<req->pos ) {

			msrp_brief_parse_msg(req);
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
		}

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

	if (req->error!=MSRP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
				  (int)(req->pos-req->buf), req->buf,
				  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		goto error;
	}

	switch (msrp_handle_req(req, con, msrp_max_msg_chunks) ) {
		case 1:
			goto again;
		case -1:
			goto error;
	}

	LM_DBG("msrp_read_req end\n");
done:
	if (bytes_read) *bytes_read=total_bytes;
	/* connection will be released */
	return 0;
error:
	/* connection will be released as ERROR */
	return -1;
}


