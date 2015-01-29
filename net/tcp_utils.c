/*
 * Copyright (C) 2015 OpenSIPS Project
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#include "../ut.h"
#include "../pt.h"
#include "../timer.h"
#include "../globals.h"
#include "../receive.h"
#include "tcp_utils.h"
#include "tcp_conn.h"

#if 0
// TODO: do we really need this here
static struct tcp_connection* tcp_conn_lst=0;		/*!< list of tcp connections handled by this process */
#endif

/* buffer to be used for reading all TCP SIP messages
   detached from the actual con - in order to improve
   paralelism ( process the SIP message while the con
   can be sent back to main to do more stuff */
struct tcp_req current_req;


inline struct tcp_req *tcp_utils_get_req(struct tcp_connection *con)
{
	if (con->con_req) {
		LM_DBG("Using the per connection buff \n");
		return con->con_req;
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		return &current_req;
	}
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
static int utils_read_hdrs(struct tcp_connection *c,struct tcp_req *r,
		int (*read_f)(struct tcp_connection *c,struct tcp_req *r))
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
		bytes=read_f(c,r);
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
 *	* if returns >= 0 : it keeps the connection for further usage
 *			or releases it manually
 *	* if returns <  0 : the connection should be released by the
 *			upper layer
 */
int tcp_utils_read_req(struct tcp_connection* con,
		int (*read_f)(struct tcp_connection *c,struct tcp_req *r))
{
	int bytes;
	int total_bytes;
	int resp;
	long size;
	struct tcp_req* req;
	char c;
	struct receive_info local_rcv;
	char *msg_buf;
	int msg_len;

	bytes=-1;
	total_bytes=0;
	resp=CONN_RELEASE;

	req = tcp_utils_get_req(con);
	if (con->con_req) {
		req=con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		req=&current_req;
	}

#if 0
	// TODO: why should we connect here, since read already connects
#ifdef USE_TLS
	if (con->type==PROTO_TLS){
		if (tls_fix_read_conn(con)!=0){
			resp=CONN_ERROR;
			goto end_req;
		}
		if(con->state!=S_CONN_OK) goto end_req; /* not enough data */
	}
#endif
#endif

again:
	if(req->error==TCP_REQ_OK){
		bytes=utils_read_hdrs(con,req,read_f);
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
			resp=CONN_ERROR;
			goto end_req;
		}
		total_bytes+=bytes;
		/* eof check:
		 * is EOF if eof on fd and req.  not complete yet,
		 * if req. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF\n");
			resp=CONN_EOF;
			goto end_req;
		}

	}
	if (req->error!=TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
				  (int)(req->pos-req->buf), req->buf,
				  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		resp=CONN_ERROR;
		goto end_req;
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
			resp=CONN_ERROR;
			goto end_req;
		}

		/* update the timeout - we succesfully read the request */
		con->timeout=get_ticks()+tcp_max_msg_time;

		/* if we are here everything is nice and ok*/
		update_stat( pt[process_no].load, +1 );
		resp=CONN_RELEASE;
#ifdef EXTRA_DEBUG
		LM_DBG("calling receive_msg(%p, %d, )\n",
				req->start, (int)(req->parsed-req->start));
#endif
		/* rcv.bind_address should always be !=0 */
		bind_address=con->rcv.bind_address;
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		/*
		if (con->rcv.dst_ip.af==AF_INET6){
			bind_address=sendipv6_tcp;
		}else{
			bind_address=sendipv4_tcp;
		}
		*/
		con->rcv.proto_reserved1=con->id; /* copy the id */
		c=*req->parsed; /* ugly hack: zero term the msg & save the
						   previous char, req->parsed should be ok
						   because we always alloc BUF_SIZE+1 */
		*req->parsed=0;

		/* prepare for next request */
		size=req->pos-req->parsed;

		if (req->state==H_PING_CRLFCRLF) {
			/* we send the reply */
/*
 * TODO: what to do with the reply?
			if (tcp_send( con->rcv.bind_address, con->rcv.proto,CRLF,
			CRLF_LEN, &(con->rcv.src_su), con->rcv.proto_reserved1) < 0) {
				LM_ERR("CRLF pong - tcp_send() failed\n");
			}
 */


#if 0
			// TODO: how are we sending the conn back now?
			if (!size) {
				/* we can release the connection */
				reactor_del_reader( con->fd, -1, IO_FD_CLOSING);
				tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
				if (con->state==S_CONN_EOF)
					release_tcpconn(con, CONN_EOF, tcpmain_sock);
				else
					release_tcpconn(con, CONN_RELEASE, tcpmain_sock);
			}
#endif
		} else {
			msg_buf = req->start;
			msg_len = req->parsed-req->start;
			local_rcv = con->rcv;

			if (!size) {
				/* did not read any more things -  we can release the connection */
				LM_DBG("We're releasing the connection in state %d \n",con->state);

				if (req != &current_req) {
					/* we have the buffer in the connection tied buff -
					 *	detach it , release the conn and free it afterwards */
					con->con_req = NULL;
				}

#if 0
				// TODO: same problem relesing the conn
				reactor_del_reader( con->fd, -1, IO_FD_CLOSING);
				tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
				/* if we have EOF, signal that to MAIN as well
				 * otherwise - just pass it back */
				if (con->state==S_CONN_EOF)
					release_tcpconn(con, CONN_EOF, tcpmain_sock);
				else
					release_tcpconn(con, CONN_RELEASE, tcpmain_sock);
#endif
			} else {
				LM_DBG("We still have things on the pipe - keeping connection \n");
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
		req->pos=req->buf+size;
		req->parsed=req->buf;
		req->start=req->buf;
		req->body=0;
		req->error=TCP_REQ_OK;
		req->state=H_SKIP_EMPTY;
		req->complete=req->content_len=req->has_content_len=0;
		req->bytes_to_go=0;
		con->msg_attempts = 0;

		/* if we still have some unparsed bytes, try to  parse them too*/
		if (size) goto again;
	} else {
		/* request not complete - check the if the thresholds are exceeded */

		con->msg_attempts ++;
		if (con->msg_attempts == tcp_max_msg_chunks) {
			LM_ERR("Made %u read attempts but message is not complete yet - "
				   "closing connection \n",con->msg_attempts);
			resp = CONN_ERROR;
			goto end_req;
		}

		if (req == &current_req) {
			/* let's duplicate this - most likely another conn will come in */

			LM_DBG("We didn't manage to read a full request. Back to child poll\n");
			/* FIXME - PKG or SHM ? */
			con->con_req = pkg_malloc(sizeof(struct tcp_req));
			if (con->con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				resp = CONN_ERROR;
				goto end_req;
			}

			if (req->pos != req->buf) {
				/* we have read some bytes */
				memcpy(con->con_req->buf,req->buf,req->pos-req->buf);
				con->con_req->pos = con->con_req->buf + (req->pos-req->buf);
			} else {
				con->con_req->pos = con->con_req->buf;
			}

			if (req->start != req->buf)
				con->con_req->start = con->con_req->buf + (req->start-req->buf);
			else
				con->con_req->start = con->con_req->buf;

			if (req->parsed != req->buf)
				con->con_req->parsed = con->con_req->buf + (req->parsed-req->buf);
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

			/* zero out the per process req for the future SIP msg */
			init_tcp_req(&current_req);
		}
	}


	LM_DBG("tcp_read_req end\n");
end_req:
		return resp;
}
