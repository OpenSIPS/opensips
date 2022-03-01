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
#include "msrp_handler.h"
#include "msrp_common.h"

struct msrp_req msrp_current_req;

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

	p = r->parsed;

	switch (r->state) {

	case MSRP_START:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state START at offset %d, char[%c]\n",
			(int)(r->pos-p),*p);
#endif
		/* req-start  = pMSRP SP transact-id SP method CRLF
		 * => min len of the first line is 4+1+3+1+2+2
		 */
		if (r->pos - p < 4+1+3+1+2+2 ) {
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
		r->parsed = p;

	case MSRP_FIRSTLINE_IDENT:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state IDENT at offset %d, char[%c]\n",
			(int)(r->pos-p),*p);
#endif
		/* identifier */
		/* p is the first char in the identifier */
		s.s = p;
		if ( !isalnum( *(p++) ))
			goto error;
		while ( p < r->pos && *p!=' ') p++;
		if (p==r->pos) {
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
		r->parsed = p;
		r->fl.ident = s;

	case MSRP_FIRSTLINE_METHOD:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state METHOD at offset %d, char[%c]\n",
			(int)(r->pos-p),*p);
#endif
		/* dig in for the CRLF ending the first line */
		s.s = p;
		while ( p < r->pos-1 ) {
			if (p[0]=='\r' && p[1]=='\n') {
				s.len = p - s.s;
				r->fl.u.request.method = s;
#ifdef MSRP_DEBUG
				LM_DBG("METHOD found [%.*s]\n",s.len,s.s);
#endif
				r->fl.eol = p+1;
				r->state = MSRP_HEADERS;
				p += 2;
				r->parsed = p;
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
			(int)(r->pos-p),*p);
#endif
		/* we should be positioned somewhere inside a hdr,
		 * so parse and consume one hdr at a time */
		while ( p < r->pos-1 ) {
			if (p[0]=='\r' && p[1]=='\n') {
#ifdef MSRP_DEBUG
				LM_DBG("new EOH found at offset %d\n",(int)(p-r->start));
#endif
				/* we need at least 2 more chars to decide what's next */
				if (p >= r->pos-3)
					return;
				if (p[2]=='\r' && p[3]=='\n') {
					/* BODY found */
					p += 4;
					r->parsed = p;
					r->state = MSRP_BODY;
					r->body.s = p;
					goto parse_body;
				} else
				if (p[2]=='-' && p[3]=='-') {
					/* we need 5 more chars */
					if (p >= r->pos-8)
						return;
					if ( _READ4(p+4)==0x2d2d2d2d /*----*/ && p[8]=='-') {
						/* EOM found */
						p += 9;
						r->parsed = p;
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
		r->parsed = p;
		return;

	case MSRP_BODY:
		parse_body:
#ifdef MSRP_DEBUG
		LM_DBG("parsing in state BODY at offset %d, char[%c]\n",
			(int)(r->pos-p),*p);
#endif
		/* parse until finding the end-line */
		/*    end-line = "-------" transact-id continuation-flag CRLF
		 *    continuation-flag = "+" / "$" / "#"
		 */
		while ( p < r->pos-8 /* CRLF 7x'-' */ ) {
			if ( p[0]=='\r' && p[1]=='\n' && _READ4(p+2)==0x2d2d2d2d/*----*/ &&
			p[6]=='-' && p[7]=='-' && p[8]=='-') {
				r->body.len = p - r->body.s;
#ifdef MSRP_DEBUG
				LM_DBG("BODY found [%.*s]/%d\n",
					r->body.len,r->body.s,r->body.len);
#endif
				p += 9;
				r->state = MSRP_EOM;
				r->parsed = p;
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
			(int)(r->pos-p),*p);
#endif
		/* we should be here only when a the 7x'-' sequance was 
		 * found; the parsing points to the first char in the potential
		 * 'ident' */
		if ( p > r->pos - (r->fl.ident.len+1+CRLF_LEN) )
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
		r->parsed = p;
		r->complete = 1;
#ifdef MSRP_DEBUG
		LM_DBG("full message successfully parsed, bytes left %d\n",
			(int)(r->pos-r->parsed));
#endif
		return;
	}

error:
	LM_ERR("parsing failed around char %d[%c]\n", (int)(p-r->start), *p);
	r->error=MSRP_REQ_BAD;
	return;
}


int msrp_handle_req(struct msrp_req *req,
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
		tcp_conn_set_lifetime( con, tcp_con_lifetime);
		con->timeout=con->lifetime;

		/* if we are here everything is nice and ok*/
		bind_address=con->rcv.bind_address;
		/* just for debugging use sendipv4 as receiving socket  FIXME*/
		con->rcv.proto_reserved1=con->id; /* copy the id */
		c=*req->parsed; /* ugly hack: zero term the msg & save the
						   previous char, req->parsed should be ok
						   because we always alloc BUF_SIZE+1 */
		*req->parsed=0;

		/* prepare for next request */
		size=req->pos-req->parsed;

		//if (req->state!=H_SKIP_EMPTY) {
			msg_buf = req->start;
			msg_len = req->parsed-req->start;
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
			*req->parsed=c;
			memmove(req->buf, req->parsed, size);

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
			pkg_free(req);
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
			con_req = pkg_malloc(sizeof(struct msrp_req));
			if (con_req == NULL) {
				LM_ERR("No more mem for dynamic con request buffer\n");
				goto error;
			}
			con->con_req = (void*)con_req;

			if (req->pos != req->buf) {
				/* we have read some bytes */
				memcpy( con_req->buf, req->buf, req->pos-req->buf);
				con_req->pos = con_req->buf + (req->pos-req->buf);
			} else {
				con_req->pos = con_req->buf;
			}

			if (req->start != req->buf)
				con_req->start = con_req->buf +(req->start-req->buf);
			else
				con_req->start = con_req->buf;

			if (req->parsed != req->buf)
				con_req->parsed = con_req->buf+(req->parsed-req->buf);
			else
				con_req->parsed = con_req->buf;

			con_req->complete=req->complete;
			con_req->error = req->error;
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


