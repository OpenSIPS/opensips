/*
 * $Id$
 *
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
 * History:
 * --------
 * 2002-12-??  created by andrei.
 * 2003-02-10  zero term before calling receive_msg & undo afterward (andrei)
 * 2003-05-13  l: (short form of Content-Length) is now recognized (andrei)
 * 2003-07-01  tcp_read & friends take no a single tcp_connection 
 *              parameter & they set c->state to S_CONN_EOF on eof (andrei)
 * 2003-07-04  fixed tcp EOF handling (possible infinite loop) (andrei)
 * 2005-07-05  migrated to the new io_wait code (andrei)
 */

/*!
 * \file
 * \brief TCP connections - read functions
 */

#ifdef USE_TCP

#include <stdio.h>
#include <errno.h>
#include <string.h>


#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <unistd.h>
#include <stdlib.h> /* for abort() */


#include "dprint.h"
#include "tcp_conn.h"
#include "pass_fd.h"
#include "globals.h"
#include "receive.h"
#include "timer.h"
#include "ut.h"
#ifdef USE_TLS
#include "tls/tls_server.h"
#endif

#define HANDLE_IO_INLINE
#include "io_wait.h"
#include <fcntl.h> /* must be included after io_wait.h if SIGIO_RT is used */
#include "forward.h"
#include "pt.h"

enum fd_types { F_NONE, F_TCPMAIN, F_TCPCONN };		/*!< types used in io_wait* */

static struct tcp_connection* tcp_conn_lst=0;		/*!< list of tcp connections handled by this process */
static io_wait_h io_w; /* io_wait handler*/
static int tcpmain_sock=-1;


/*! \brief reads next available bytes
 * \return number of bytes read, 0 on EOF or -1 on error,
 * on EOF it also sets c->state to S_CONN_EOF
 * (to distinguish from reads that would block which could return 0)
 * sets also r->error 
 */
int tcp_read(struct tcp_connection *c)
{
	int bytes_free, bytes_read;
	struct tcp_req *r;
	int fd;

	r=&c->req;
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
int tcp_read_headers(struct tcp_connection *c)
{
	unsigned int remaining;
	int bytes;
	char *p;
	struct tcp_req* r;
	
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


	r=&c->req;
	/* if we still have some unparsed part, parse it first, don't do the read*/
	if (r->parsed<r->pos){
		bytes=0;
	}else{
#ifdef USE_TLS
		if (c->type==PROTO_TLS)
			bytes=tls_read(c);
		else
#endif
			bytes=tcp_read(c);
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
skip:
	r->parsed=p;
	return bytes;
}



int tcp_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	int resp;
	long size;
	struct tcp_req* req;
/*	int s; */
	char c;
		
		bytes=-1;
		total_bytes=0;
		resp=CONN_RELEASE;
		/* s=con->fd; */
		req=&con->req;
#ifdef USE_TLS
		if (con->type==PROTO_TLS){
			if (tls_fix_read_conn(con)!=0){
				resp=CONN_ERROR;
				goto end_req;
			}
			if(con->state!=S_CONN_OK) goto end_req; /* not enough data */
		}
#endif

again:
		if(req->error==TCP_REQ_OK){
			bytes=tcp_read_headers(con);
#ifdef EXTRA_DEBUG
						/* if timeout state=0; goto end__req; */
			LM_DBG("read= %d bytes, parsed=%d, state=%d, error=%d\n",
					bytes, (int)(req->parsed-req->start), req->state,
					req->error );
			LM_DBG("last char=0x%02X, parsed msg=\n%.*s\n",
					*(req->parsed-1), (int)(req->parsed-req->start),
					req->start);
#endif
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

			if (req->state==H_PING_CRLFCRLF) {
				if (tcp_send( con->rcv.bind_address, con->rcv.proto,CRLF,
				CRLF_LEN, &(con->rcv.src_su), con->rcv.proto_reserved1) < 0) {
					LM_ERR("CRLF pong - tcp_send() failed\n");
				}
			} else if (receive_msg(req->start, req->parsed-req->start,
			&con->rcv)<0) {
				*req->parsed=c;
				resp=CONN_ERROR;
				update_stat( pt[process_no].load, -1 );
				goto end_req;
			}
			*req->parsed=c;
		
			update_stat( pt[process_no].load, -1 );

			/* prepare for next request */
			size=req->pos-req->parsed;
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
			/* if we still have some unparsed bytes, try to  parse them too*/
			if (size) goto again;
			else if (con->state==S_CONN_EOF){
				LM_DBG("EOF after reading complete request\n");
				resp=CONN_EOF;
			}
			
		}
		
		
	end_req:
		if (bytes_read) *bytes_read=total_bytes;
		return resp;
}



void release_tcpconn(struct tcp_connection* c, long state, int unix_sock)
{
	long response[2];
	
		LM_DBG(" releasing con %p, state %ld, fd=%d, id=%d\n",
				c, state, c->fd, c->id);
		LM_DBG(" extra_data %p\n", c->extra_data);
		/* release req & signal the parent */
		if (c->fd!=-1) close(c->fd);
		/* errno==EINTR, EWOULDBLOCK a.s.o todo */
		response[0]=(long)c;
		response[1]=state;
		if (send_all(unix_sock, response, sizeof(response))<=0)
			LM_ERR("send_all failed\n");
}


#ifdef DEBUG_TCP_RECEIVE
/* old code known to work, kept arround for debuging */
void tcp_receive_loop(int unix_sock)
{
	struct tcp_connection* list; /* list with connections in use */
	struct tcp_connection* con;
	struct tcp_connection* c_next;
	int n;
	int nfds;
	int s;
	long resp;
	fd_set master_set;
	fd_set sel_set;
	int maxfd;
	struct timeval timeout;
	int ticks;
	
	
	/* init */
	list=con=0;
	FD_ZERO(&master_set);
	FD_SET(unix_sock, &master_set);
	maxfd=unix_sock;
	
	/* listen on the unix socket for the fd */
	for(;;){
			timeout.tv_sec=TCP_CHILD_SELECT_TIMEOUT;
			timeout.tv_usec=0;
			sel_set=master_set;
			nfds=select(maxfd+1, &sel_set, 0 , 0 , &timeout);
#ifdef EXTRA_DEBUG
			for (n=0; n<maxfd; n++){
				if (FD_ISSET(n, &sel_set)) 
					LM_DBG("fd %d is set\n", n);
			}
#endif
			if (nfds<0){
				if (errno==EINTR) continue; /* just a signal */
				/* errors */
				LM_ERR("select:(%d) %s\n", errno,
					strerror(errno));
				continue;
			}
			if (FD_ISSET(unix_sock, &sel_set)){
				nfds--;
				/* a new conn from "main" */
				n=receive_fd(unix_sock, &con, sizeof(con), &s, 0);
				if (n<0){
					if (errno == EWOULDBLOCK || errno == EAGAIN ||
							errno == EINTR){
						goto skip;
					}else{
						LM_CRIT("read_fd: %s\n",strerror(errno));
						abort(); /* big error*/
					}
				}
				LM_DBG("received n=%d con=%p, fd=%d\n", n, con, s);
				if (n==0){
					LM_WARN("0 bytes read\n");
					goto skip;
				}
				if (con==0){
					LM_CRIT("null pointer\n");
					goto skip;
				}
				con->fd=s;
				if (s==-1) {
					LM_ERR("read_fd: no fd read\n");
					resp=CONN_ERROR;
					con->state=S_CONN_BAD;
					release_tcpconn(con, resp, unix_sock);
					goto skip;
				}
				con->timeout=get_ticks()+TCP_CHILD_TIMEOUT;
				FD_SET(s, &master_set);
				if (maxfd<s) maxfd=s;
				if (con==list){
					LM_CRIT("duplicate"
							" connection received: %p, id %d, fd %d, refcnt %d"
							" state %d (n=%d)\n", con, con->id, con->fd,
							con->refcnt, con->state, n);
					resp=CONN_ERROR;
					release_tcpconn(con, resp, unix_sock);
					goto skip; /* try to recover */
				}
				tcpconn_listadd(list, con, c_next, c_prev);
			}
skip:
			ticks=get_ticks();
			for (con=list; con ; con=c_next){
				c_next=con->c_next; /* safe for removing*/
#ifdef EXTRA_DEBUG
				LM_DBG("list fd=%d, id=%d, timeout=%d, refcnt=%d\n",
						con->fd, con->id, con->timeout, con->refcnt);
#endif
				if (con->state<0){
					/* S_CONN_BAD or S_CONN_ERROR, remove it */
					resp=CONN_ERROR;
					FD_CLR(con->fd, &master_set);
					tcpconn_listrm(list, con, c_next, c_prev);
					con->state=S_CONN_BAD;
					release_tcpconn(con, resp, unix_sock);
					continue;
				}
				if (nfds && FD_ISSET(con->fd, &sel_set)){
#ifdef EXTRA_DEBUG
					LM_DBG("match, fd:isset\n");
#endif
					nfds--;
					resp=tcp_read_req(con);
					
					if (resp<0){
						FD_CLR(con->fd, &master_set);
						tcpconn_listrm(list, con, c_next, c_prev);
						con->state=S_CONN_BAD;
						release_tcpconn(con, resp, unix_sock);
					}else{
						/* update timeout */
						con->timeout=ticks+TCP_CHILD_TIMEOUT;
					}
				}else{
					/* timeout */
					if (con->timeout<=ticks){
						/* expired, return to "tcp main" */
						LM_DBG("%p expired (%d, %d)\n",
								con, con->timeout, ticks);
						resp=CONN_RELEASE;
						FD_CLR(con->fd, &master_set);
						tcpconn_listrm(list, con, c_next, c_prev);
						release_tcpconn(con, resp, unix_sock);
					}
				}
			}
		
	}
}
#else /* DEBUG_TCP_RECEIVE */



/*! \brief
 *  handle io routine, based on the fd_map type
 * (it will be called from io_wait_loop* )
 * params:  fm  - pointer to a fd hash entry
 *          idx - index in the fd_array (or -1 if not known)
 * return: -1 on error, or when we are not interested any more on reads
 *            from this fd (e.g.: we are closing it )
 *          0 on EAGAIN or when by some other way it is known that no more 
 *            io events are queued on the fd (the receive buffer is empty).
 *            Usefull to detect when there are no more io events queued for
 *            sigio_rt, epoll_et, kqueue.
 *         >0 on successfull read from the fd (when there might be more io
 *            queued -- the receive buffer might still be non-empty)
 */
inline static int handle_io(struct fd_map* fm, int idx)
{	
	int ret;
	int n;
	struct tcp_connection* con;
	int s;
	long resp;
	
	switch(fm->type){
		case F_TCPMAIN:
again:
			ret=n=receive_fd(fm->fd, &con, sizeof(con), &s, 0);
			LM_DBG("received n=%d con=%p, fd=%d\n", n, con, s);
			if (n<0){
				if (errno == EWOULDBLOCK || errno == EAGAIN){
					ret=0;
					break;
				}else if (errno == EINTR) goto again;
				else{
					LM_CRIT("read_fd: %s \n", strerror(errno));
						abort(); /* big error*/
				}
			}
			if (n==0){
				LM_WARN("0 bytes read\n");
				break;
			}
			if (con==0){
					LM_CRIT("null pointer\n");
					break;
			}
			con->fd=s;
			if (s==-1) {
				LM_ERR("read_fd:no fd read\n");
				goto con_error;
			}
			if (con==tcp_conn_lst){
				LM_CRIT("duplicate"
							" connection received: %p, id %d, fd %d, refcnt %d"
							" state %d (n=%d)\n", con, con->id, con->fd,
							con->refcnt, con->state, n);
				release_tcpconn(con, CONN_ERROR, tcpmain_sock);
				break; /* try to recover */
			}
			/* must be before io_watch_add, io_watch_add might catch some
			 * already existing events => might call handle_io and
			 * handle_io might decide to del. the new connection =>
			 * must be in the list */
			tcpconn_listadd(tcp_conn_lst, con, c_next, c_prev);
			con->timeout=get_ticks()+TCP_CHILD_TIMEOUT;
			if (io_watch_add(&io_w, s, F_TCPCONN, con)<0){
				LM_CRIT("failed to add new socket to the fd list\n");
				tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
				goto con_error;
			}
			break;
		case F_TCPCONN:
			con=(struct tcp_connection*)fm->data;
			resp=tcp_read_req(con, &ret);
			if (resp<0){
				ret=-1; /* some error occured */
				io_watch_del(&io_w, con->fd, idx, IO_FD_CLOSING);
				tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
				con->state=S_CONN_BAD;
				release_tcpconn(con, resp, tcpmain_sock);
			}else{
				/* update timeout */
				con->timeout=get_ticks()+TCP_CHILD_TIMEOUT;
			}
			break;
		case F_NONE:
			LM_CRIT("empty fd map %p (%d): "
						"{%d, %d, %p}\n", fm, (int)(fm-io_w.fd_hash),
						fm->fd, fm->type, fm->data);
			goto error;
		default:
			LM_CRIT("uknown fd type %d\n", fm->type); 
			goto error;
	}
	
	return ret;
con_error:
	con->state=S_CONN_BAD;
	release_tcpconn(con, CONN_ERROR, fm->fd);
	return ret;
error:
	return -1;
}



static unsigned int c_tcp_con_lifetime = 0;
static int c_tcp_con_id = -1;


void force_tcp_conn_lifetime(struct receive_info *rcv, unsigned int timeout)
{
	c_tcp_con_lifetime = get_ticks() + timeout;
	c_tcp_con_id = rcv->proto_reserved1;
}



/*! \brief  releases expired connections and cleans up bad ones (state<0) */
static inline void tcp_receive_timeout(void)
{
	struct tcp_connection* con;
	struct tcp_connection* next;
	unsigned int ticks;
	
	ticks=get_ticks();
	for (con=tcp_conn_lst; con; con=next){
		next=con->c_next; /* safe for removing */
		if (con->state<0){   /* kill bad connections */ 
			/* S_CONN_BAD or S_CONN_ERROR, remove it */
			/* fd will be closed in release_tcpconn */
			io_watch_del(&io_w, con->fd, -1, IO_FD_CLOSING);
			tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
			con->state=S_CONN_BAD;
			release_tcpconn(con, CONN_ERROR, tcpmain_sock);
			continue;
		}
		if (con->timeout<=ticks){
			/* expired, return to "tcp main" */
			if (c_tcp_con_id==con->id) {
				con->lifetime = c_tcp_con_lifetime;
			}
			LM_DBG("%p expired (%d, %d) lt=%d\n",
					con, con->timeout, ticks,con->lifetime);
			/* fd will be closed in release_tcpconn */
			io_watch_del(&io_w, con->fd, -1, IO_FD_CLOSING);
			tcpconn_listrm(tcp_conn_lst, con, c_next, c_prev);
			release_tcpconn(con, CONN_RELEASE, tcpmain_sock);
		}
	}
}



void tcp_receive_loop(int unix_sock)
{
	
	/* init */
	tcpmain_sock=unix_sock; /* init com. socket */
	if (init_io_wait(&io_w, tcp_max_fd_no, tcp_poll_method)<0)
		goto error;
	/* add the unix socket */
	if (io_watch_add(&io_w, tcpmain_sock, F_TCPMAIN, 0)<0){
		LM_CRIT("failed to add socket to the fd list\n");
		goto error;
	}
	/* main loop */
	switch(io_w.poll_method){
		case POLL_POLL:
				while(1){
					io_wait_loop_poll(&io_w, TCP_CHILD_SELECT_TIMEOUT, 0);
					tcp_receive_timeout();
				}
				break;
#ifdef HAVE_SELECT
		case POLL_SELECT:
			while(1){
				io_wait_loop_select(&io_w, TCP_CHILD_SELECT_TIMEOUT, 0);
				tcp_receive_timeout();
			}
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			while(1){
				io_wait_loop_sigio_rt(&io_w, TCP_CHILD_SELECT_TIMEOUT);
				tcp_receive_timeout();
			}
			break;
#endif
#ifdef HAVE_EPOLL
		case POLL_EPOLL_LT:
			while(1){
				io_wait_loop_epoll(&io_w, TCP_CHILD_SELECT_TIMEOUT, 0);
				tcp_receive_timeout();
			}
			break;
		case POLL_EPOLL_ET:
			while(1){
				io_wait_loop_epoll(&io_w, TCP_CHILD_SELECT_TIMEOUT, 1);
				tcp_receive_timeout();
			}
			break;
#endif
#ifdef HAVE_KQUEUE
		case POLL_KQUEUE:
			while(1){
				io_wait_loop_kqueue(&io_w, TCP_CHILD_SELECT_TIMEOUT, 0);
				tcp_receive_timeout();
			}
			break;
#endif
#ifdef HAVE_DEVPOLL
		case POLL_DEVPOLL:
			while(1){
				io_wait_loop_devpoll(&io_w, TCP_CHILD_SELECT_TIMEOUT, 0);
				tcp_receive_timeout();
			}
			break;
#endif
		default:
			LM_CRIT("no support for poll method %s (%d)\n", 
					poll_method_name(io_w.poll_method), io_w.poll_method);
			goto error;
	}
error:
	destroy_io_wait(&io_w);
	LM_CRIT("exiting...");
	exit(-1);
}

#endif /* DEBUG_TCP_RECEIVE */

#endif /* USE_TCP */
