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


/* here we have "network layer"-specific functions that are
 * shared both by msrp "plain" and "tls"
 */

#include <ctype.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../net/trans_trace.h"
#include "../../net/tcp_common.h"
#include "../../timer.h"
#include "msrp_handler.h"
#include "msrp_plain.h"
#include "msrp_common.h"
#include "msrp_tls.h"

int *msrp_trace_is_on;
struct script_route_ref *msrp_trace_filter_route = NULL;
trace_dest msrp_t_dst;

struct msrp_req msrp_current_req;

int msrp_send_timeout = 100;
int msrp_tls_handshake_timeout = 100;
int msrp_max_msg_chunks = 4;

extern int msrp_check_cert_on_reusage;

#define _READ4(_p) \
	((*((unsigned char *)(_p) + 0) + \
	 (*((unsigned char *)(_p) + 1) << 8) + \
	 (*((unsigned char *)(_p) + 2) << 16) + \
	 (*((unsigned char *)(_p) + 3) << 24)) | 0x20202020)

#define MSRP_DEBUG



void msrp_brief_parse_msg(struct msrp_req *r)
{
	str s;
	char *p;

	/* pos - current "reading" position in the buffer, basically the end of
	         message we are parsing here;
	   parsed - last parsed position in the buffer
	 */

	p = r->tcp.parsed;

	switch (r->state) {

	case MSRP_START:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state START at offset %d, char[%c]\n",
			(int)(r->tcp.pos-p),*p);
#endif
		/* req-start  = pMSRP SP transact-id SP method CRLF
		 * => min len of the first line is 4+1+3+1+2+2
		 */
		if (r->tcp.pos - p < 4+1+3+1+2+2 ) {
			/* we still to read more in order to cover first line */
			return;
		}

		if ( _READ4(p) != 0x7072736d /*msrp*/) {
			LM_DBG("not starting with MSRP, <%.*s>, %x\n", 4, p,_READ4(p));
			goto error;
		}
		p += 4;

		/* one space */
		if (*(p++)!=' ')
			goto error;

		r->state = MSRP_FIRSTLINE_IDENT;
		r->tcp.parsed = p;

	case MSRP_FIRSTLINE_IDENT:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state IDENT at offset %d, char[%c]\n",
			(int)(r->tcp.pos-p),*p);
#endif
		/* identifier */
		/* p is the first char in the identifier */
		s.s = p;
		if ( !isalnum( *(p++) ))
			goto error;
		while ( p < r->tcp.pos && *p!=' ') p++;
		if (p==r->tcp.pos) {
			/* not full reading, partial transaction ID */
			return;
		}
		/* p-1 is the last char in the identifier */
		s.len = p - s.s;
#ifdef MSRP_DEBUG
		LM_DBG("IDENT found [%.*s]\n",s.len,s.s);
#endif

		/* current char is the space */
		p++;

		r->state = MSRP_FIRSTLINE_METHOD;
		r->tcp.parsed = p;
		r->fl.ident = s;

	case MSRP_FIRSTLINE_METHOD:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state METHOD at offset %d, char[%c]\n",
			(int)(r->tcp.pos-p),*p);
#endif
		/* dig in for the CRLF ending the first line */
		s.s = p;
		while ( p < r->tcp.pos-1 ) {
			if (p[0]=='\r' && p[1]=='\n') {
				s.len = p - s.s;
				r->fl.u.request.method = s;
#ifdef MSRP_DEBUG
				LM_DBG("METHOD found [%.*s]\n",s.len,s.s);
#endif
				r->fl.eol = p+1;
				r->state = MSRP_HEADERS;
				p += 2;
				r->tcp.parsed = p;
				goto parse_headers;
			}
			p++;
		}

		/* EOH not found, not a full first line, still to read */
		return;

	case MSRP_HEADERS:
		parse_headers:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state HEADERS at offset %d, char[%c]\n",
			(int)(r->tcp.pos-p),*p);
#endif
		/* we should be positioned somewhere inside a hdr,
		 * so parse and consume one hdr at a time */
		while ( p < r->tcp.pos-1 ) {
			if (p[0]=='\r' && p[1]=='\n') {
#ifdef MSRP_DEBUG
				LM_DBG("new EOH found at offset %d\n",(int)(p-r->tcp.start));
#endif
				/* we need at least 2 more chars to decide what's next */
				if (p >= r->tcp.pos-3)
					return;
				if (p[2]=='\r' && p[3]=='\n') {
					/* BODY found */
					p += 4;
					r->tcp.parsed = p;
					r->state = MSRP_BODY;
					r->body.s = p;
					goto parse_body;
				} else
				if (p[2]=='-' && p[3]=='-') {
					/* we need 5 more chars */
					if (p >= r->tcp.pos-8)
						return;
					if ( _READ4(p+4)==0x2d2d2d2d /*----*/ && p[8]=='-') {
						/* EOM found */
						p += 9;
						r->tcp.parsed = p;
						r->state = MSRP_EOM;
						goto parse_eom;
					} else
						goto error; /* not all 7 '-' directly after last hdr*/
				} else {
					/* EOH */
					p += 2;
				}
			} else {
				p++;
			}
		}

		/* EOH not found, not a full header, still to read */
		r->tcp.parsed = p;
		return;

	case MSRP_BODY:
		parse_body:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state BODY at offset %d, char[%c]\n",
			(int)(r->tcp.pos-p),*p);
#endif
		/* parse until finding the end-line */
		/*    end-line = "-------" transact-id continuation-flag CRLF
		 *    continuation-flag = "+" / "$" / "#"
		 */
		while ( p < r->tcp.pos-8 /* CRLF 7x'-' */ ) {
			if ( p[0]=='\r' && p[1]=='\n' && _READ4(p+2)==0x2d2d2d2d/*----*/ &&
			p[6]=='-' && p[7]=='-' && p[8]=='-') {
				r->body.len = p - r->body.s;
#ifdef MSRP_DEBUG
				LM_DBG("BODY found [%.*s]/%d\n",
					r->body.len,r->body.s,r->body.len);
#endif
				p += 9;
				r->state = MSRP_EOM;
				r->tcp.parsed = p;
				goto parse_eom;
			}
			p++;
		}

		/* EOH not found, not a full first line, still to read */
		return;

	case MSRP_EOM:
		parse_eom:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state EndOfMessage at offset %d, char[%c]\n",
			(int)(r->tcp.pos-p),*p);
#endif
		/* we should be here only when a the 7x'-' sequance was 
		 * found; the parsing points to the first char in the potential
		 * 'ident' */
		if ( p > r->tcp.pos - (r->fl.ident.len+1+CRLF_LEN) )
			/* still to read */
			return;
		if ( p[r->fl.ident.len] != '+' &&
		p[r->fl.ident.len] != '$' && p[r->fl.ident.len] != '#' )
			goto error;
		if (p[r->fl.ident.len+1] != '\r' || p[r->fl.ident.len+2] != '\n')
			goto error;

		if ( memcmp( p, r->fl.ident.s, r->fl.ident.len)!=0 ) {
			LM_ERR("end ident not matching, fl=[%.*s], end=[%.*s]\n",
				r->fl.ident.len, r->fl.ident.s,
				r->fl.ident.len, p);
			goto error;
		}
		p += r->fl.ident.len+1+CRLF_LEN;
		r->tcp.parsed = p;
		r->complete = 1;
#ifdef MSRP_DEBUG
		LM_DBG("full message successfully parsed, bytes left %d\n",
			(int)(r->tcp.pos-r->tcp.parsed));
#endif
		return;
	}

error:
	LM_ERR("parsing failed around char %d[%c]\n", (int)(p-r->tcp.start), *p);
	r->tcp.error=TCP_REQ_BAD;
	return;
}


static int msrp_handle_req(struct msrp_req *req,
		struct tcp_connection *con, int _max_msg_chunks)
{
	struct receive_info local_rcv;
	struct msrp_req *con_req;
	char *msg_buf;
	int msg_len;
	long size;
	char c;

	if (req->complete){
#ifdef EXTRA_DEBUG
		LM_DBG("end of header part\n");
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ", &con->rcv.src_ip, "\n");
#endif

		/* update the timeout - we successfully read the request */
		tcp_conn_reset_lifetime(con);
		con->timeout=con->lifetime;

		/* if we are here everything is nice and ok*/
		bind_address=con->rcv.bind_address;
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */
		c=*req->tcp.parsed; /* ugly hack: zero term the msg & save the
						   previous char, req->tcp.parsed should be ok
						   because we always alloc BUF_SIZE+1 */
		*req->tcp.parsed=0;

		/* prepare for next request */
		size=req->tcp.pos-req->tcp.parsed;

		//if (req->state!=H_SKIP_EMPTY) {
			msg_buf = req->tcp.start;
			msg_len = req->tcp.parsed-req->tcp.start;
			local_rcv = con->rcv;

			if (!size) {
				/* did not read any more things -  we can release
				 * the connection */
				LM_DBG("Nothing more to read on TCP conn %p, currently "
					"in state %d \n", con,con->state);
				if (req != &msrp_current_req) {
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

			if (handle_msrp_msg( msg_buf, msg_len, &req->fl, &req->body, 
			&local_rcv) <0)
				LM_ERR("receive_msg failed \n");

		//}

		con->msg_attempts = 0;

		if (size) {
			/* restoring the char only makes sense if there is something else to
			 * process, otherwise we can leave it. This prevents us from accessing
			 * unallocated memory - razvanc */
			*req->tcp.parsed=c;
			memmove(req->tcp.buf, req->tcp.parsed, size);

#ifdef EXTRA_DEBUG
			LM_DBG("preparing for new request, kept %ld bytes\n", size);
#endif
			init_msrp_req(req, size);

			/* if we still have some unparsed bytes, try to parse them too */
			return 1;
		}

		if (req != &msrp_current_req) {
			/* if we no longer need this tcp_req
			 * we can free it now */
			shm_free(req);
			con->con_req = NULL;
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

		if (req == &msrp_current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request\n");
			con_req = shm_malloc(sizeof(struct msrp_req));
			if (con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				goto error;
			}
			con->con_req = (void*)con_req;

			if (req->tcp.pos != req->tcp.buf) {
				/* we have read some bytes */
				memcpy( con_req->tcp.buf, req->tcp.buf, req->tcp.pos-req->tcp.buf);
				con_req->tcp.pos = con_req->tcp.buf + (req->tcp.pos-req->tcp.buf);
			} else {
				con_req->tcp.pos = con_req->tcp.buf;
			}

			if (req->tcp.start != req->tcp.buf)
				con_req->tcp.start = con_req->tcp.buf +(req->tcp.start-req->tcp.buf);
			else
				con_req->tcp.start = con_req->tcp.buf;

			if (req->tcp.parsed != req->tcp.buf)
				con_req->tcp.parsed = con_req->tcp.buf+(req->tcp.parsed-req->tcp.buf);
			else
				con_req->tcp.parsed = con_req->tcp.buf;

			con_req->complete=req->complete;
			con_req->tcp.error = req->tcp.error;
			con_req->state = req->state;
			/* req will be reset on the next usage */
		}
	}

	/* everything ok */
	return 0;
error:
	/* report error */
	return -1;
}


/**************  READ related functions ***************/

/* Responsible for reading the request
 *	* if returns >= 0 : the connection will be released
 *	* if returns <  0 : the connection will be released as BAD / broken
 */
int msrp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes, ret;
	int total_bytes;
	struct msrp_req* req;

	union sockaddr_union src_su, dst_su;

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


	if (con->type==PROTO_MSRPS) {
		/* do this trick in order to trace whether if it's an error or not */
		ret = tls_mgm_api.tls_fix_read_conn(con, con->fd,
			msrp_tls_handshake_timeout, msrp_t_dst, 1);
		if (ret < 0) {
			LM_ERR("failed to do pre-tls handshake!\n");
			return -1;
		} else if (ret == 0) {
			LM_DBG("SSL accept/connect still pending!\n");
			return 0;
		}
	}

	if ( !(con->proto_flags & F_TCP_CONN_TRACED)) {
		con->proto_flags |= F_TCP_CONN_TRACED;

		LM_DBG("Accepted connection from %s:%d on interface %s:%d!\n",
			ip_addr2a( &con->rcv.src_ip ), con->rcv.src_port,
			ip_addr2a( &con->rcv.dst_ip ), con->rcv.dst_port );

		if ( TRACE_ON( con->flags ) &&
					check_trace_route( msrp_trace_filter_route, con) ) {
			if ( tcpconn2su( con, &src_su, &dst_su) < 0 ) {
				LM_ERR("can't create su structures for tracing!\n");
			} else {
				trace_message_atonce( PROTO_MSRP, con->cid, &src_su, &dst_su,
					TRANS_TRACE_ACCEPTED, TRANS_TRACE_SUCCESS,
					&ACCEPT_OK, msrp_t_dst );
			}
		}
	}

	if(con->state!=S_CONN_OK)
		goto done; /* not enough data */

again:
	if(req->tcp.error==TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->tcp.parsed<req->tcp.pos){
			bytes=0;
		}else{
			if (con->type==PROTO_MSRPS)
				bytes=tls_mgm_api.tls_read(con,&req->tcp);
			else
				bytes=msrp_read_plain(con,req);
			if (bytes<0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		/* some data left unparsed */
		if ( req->tcp.parsed<req->tcp.pos ) {

			msrp_brief_parse_msg(req);
#ifdef EXTRA_DEBUG
					/* if timeout state=0; goto end__req; */
			LM_DBG("read= %d bytes, parsed=%d, state=%d, error=%d\n",
				bytes, (int)(req->tcp.parsed-req->tcp.start), req->state,
				req->tcp.error );
			LM_DBG("last char=0x%02X, parsed msg=\n%.*s\n",
				*(req->tcp.parsed-1), (int)(req->tcp.parsed-req->tcp.start),
				req->tcp.start);
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

	if (req->tcp.error!=TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->tcp.error,
				  (int)(req->tcp.pos-req->tcp.buf), req->tcp.buf,
				  (int)(req->tcp.parsed-req->tcp.start), req->tcp.start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		goto error;
	}

	int max_chunks = tcp_attr_isset(con, TCP_ATTR_MAX_MSG_CHUNKS) ?
			con->profile.attrs[TCP_ATTR_MAX_MSG_CHUNKS] : msrp_max_msg_chunks;

	switch (msrp_handle_req(req, con, max_chunks) ) {
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


/**************  SEND related functions ***************/

/*! \brief Finds a tcpconn & sends on it */
int proto_msrp_send(struct socket_info* send_sock,
		char* buf, unsigned int len,
		union sockaddr_union* to, unsigned int id)
{
	struct tcp_connection *c;
	struct tcp_conn_profile prof;
	struct ip_addr ip;
	struct timeval get,snd;
	union sockaddr_union src_su, dst_su;
	int port = 0, fd, n, matched;
	struct tls_domain *dom;

	matched = tcp_con_get_profile(to, &send_sock->su, send_sock->proto, &prof);

	reset_tcp_vars(prof.send_threshold);
	start_expire_timer(get,prof.send_threshold);

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		dom = (msrp_check_cert_on_reusage==0 || send_sock->proto==PROTO_MSRP)?
			NULL : tls_mgm_api.find_client_domain( &ip, port);
		n = tcp_conn_get(id, &ip, port, PROTO_MSRP, NULL, &c, &fd, send_sock);
		if (dom)
			tls_mgm_api.release_domain(dom);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, NULL, &c, &fd, NULL);
	}else{
		LM_CRIT("tcp_send called with null id & to\n");
		get_time_difference(get,prof.send_threshold,tcp_timeout_con_get);
		return -1;
	}

	if (n<0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to acquire connection\n");
		get_time_difference(get,prof.send_threshold,tcp_timeout_con_get);
		return -1;
	}

	/* was connection found ?? */
	if (c==0) {
		if ((matched && prof.no_new_conn) || (!matched && tcp_no_new_conn))
			return -1;

		if (!to) {
			LM_ERR("Unknown destination - cannot open new tcp connection\n");
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one\n");
		/* create tcp connection */
		if ((c=tcp_sync_connect(send_sock, to, &prof, &fd, 1))==0) {
			LM_ERR("connect failed\n");
			get_time_difference(get,prof.send_threshold,tcp_timeout_con_get);
			return -1;
		}

		if ( TRACE_ON( c->flags ) &&
				check_trace_route( msrp_trace_filter_route, c) ) {
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

	get_time_difference(get,prof.send_threshold,tcp_timeout_con_get);

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

	start_expire_timer(snd,prof.send_threshold);

	if (send_sock->proto==PROTO_MSRP)
		n = tcp_write_on_socket(c, fd, buf, len,
			msrp_send_timeout, 0);
	else
		n = msrps_write_on_socket(c, fd, buf, len,
			msrp_tls_handshake_timeout, msrp_send_timeout);

	get_time_difference(snd,prof.send_threshold,tcp_timeout_send);
	stop_expire_timer(get,prof.send_threshold,"MSRP ops",buf,(int)len,1);

	tcp_conn_reset_lifetime(c);

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
