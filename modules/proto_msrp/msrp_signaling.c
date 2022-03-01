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

#include "../../ut.h"
#include "../../forward.h"
#include "../../mem/mem.h"
#include "msrp_parser.h"

#define MSRP_PREFIX "MSRP "
#define MSRP_PREFIX_LEN (sizeof(MSRP_PREFIX) - 1)

#define EOM_PREFIX "-------"
#define EOM_PREFIX_LEN (sizeof(EOM_PREFIX) - 1)

#define TO_PATH_PREFIX "To-Path: "
#define TO_PATH_PREFIX_LEN (sizeof(TO_PATH_PREFIX) - 1)

#define FROM_PATH_PREFIX "From-Path: "
#define FROM_PATH_PREFIX_LEN (sizeof(FROM_PATH_PREFIX) - 1)

/* convenience macro */
#define  append_string(_d,_s,_len) \
	do{\
		memcpy((_d),(_s),(_len));\
		(_d) += (_len);\
	}while(0);



int msrp_send_reply( struct msrp_msg *req, int code, str* reason,
		str *hdrs, int hdrs_no)
{
	char *buf, *p;
	str to_body, from_body;
	int i, len = 0;

	if (code<100 || code>999) {
		LM_ERR("invalid status reply %d, must be [100..999]\n",code);
		return -1;
	}

	/* compute the lenght of the reply*/

	/* first line
	 * MSRP SP transact-id SP status-code [SP comment] CRLF
	 */
	len += MSRP_PREFIX_LEN + req->fl.ident.len + 1 + 3
		+ (reason?(1 + reason->len):0) + CRLF_LEN;
	
	/* headers
	 * headers = To-Path CRLF From-Path CRLF 1*( header CRLF )
	 */
	if (req->fl.u.request.method_id==MSRP_METHOD_SEND) {
		/* we need to parse the From-Path too, to get the first URL only */
		if (req->from_path->parsed == NULL) {
			req->from_path->parsed = parse_msrp_path( &req->from_path->body);
			if (req->from_path->parsed == NULL) {
				LM_ERR("Invalid From-Path payload :(\n");
				return -1;
			}
		}
		to_body = ((struct msrp_url*)(req->from_path->parsed))->whole;
	} else {
		/* take the whole list of URLs from the From-Path*/
		to_body = req->from_path->body;
	}
	/* as FROM use the first URL from TO, which is already parsed */
	from_body = ((struct msrp_url*)(req->to_path->parsed))->whole;
	/* and now let's calcalate */
	len += TO_PATH_PREFIX_LEN + to_body.len + CRLF_LEN
		+ FROM_PATH_PREFIX_LEN + from_body.len + CRLF_LEN;
	/* add the hdrs */
	for ( i=0 ; i<hdrs_no ; i++)
		len += hdrs[i].len + CRLF_LEN;

	 /* EOM
	  * end-line = "-------" transact-id continuation-flag CRLF
	  */
	len += EOM_PREFIX_LEN + req->fl.ident.len + 1 + CRLF_LEN;


	/* allocate the buffer */
	buf = pkg_malloc( len );
	if (buf==NULL) {
		LM_ERR("failed to pkg allocate the reply buffer\n");
		return -1;
	}


	/* start building */
	p = buf;

	/* first line */
	append_string( p, MSRP_PREFIX, MSRP_PREFIX_LEN);
	append_string( p, req->fl.ident.s, req->fl.ident.len);
	*(p++) = ' ';
	p += btostr( p, code );
	if (reason) {
		*(p++) = ' ';
		append_string( p, reason->s, reason->len);
	}
	append_string( p, CRLF, CRLF_LEN);

	/* headers */
	append_string( p, TO_PATH_PREFIX, TO_PATH_PREFIX_LEN);
	append_string( p, to_body.s, to_body.len);
	append_string( p, CRLF, CRLF_LEN);

	append_string( p, FROM_PATH_PREFIX, FROM_PATH_PREFIX_LEN);
	append_string( p, from_body.s, from_body.len);
	append_string( p, CRLF, CRLF_LEN);

	for ( i=0 ; i<hdrs_no ; i++) {
		append_string( p,  hdrs[i].s,  hdrs[i].len);
		append_string( p, CRLF, CRLF_LEN);
	}

	/* EOM */
	append_string( p, EOM_PREFIX, EOM_PREFIX_LEN);
	append_string( p, req->fl.ident.s, req->fl.ident.len);
	*(p++) = '$';
	append_string( p, CRLF, CRLF_LEN);

	if (p-buf!=len) {
		LM_BUG("computed %d, but wrote %d :(\n",len,(int)(p-buf));
		goto error;
	}

	/* now, send it out*/
	i = msg_send( req->rcv.bind_address, PROTO_MSRP,
			&req->rcv.src_su, req->rcv.proto_reserved1,
			buf, len, NULL);
	if (i<0) {
		/* sending failed, FIXME - close the connection */
		LM_ERR("failed to send MSRP reply\n");
		goto error;
	}

	pkg_free(buf);
	return 0;

error:
	pkg_free(buf);
	return -1;
}


/* Returns :
 *  -1 - bad request
 *  -2 - cannot resolve destination
 *  -3 - internal error
 */
int msrp_fwd_request( struct msrp_msg *req, str *hdrs, int hdrs_no)
{
	char *buf, *p, *s, bk;
	struct msrp_url *to, *from;
	union sockaddr_union su;
	struct hostent* he;
	int i, len;

	if (req==NULL)
		return -1;

	/* we need both TO and FROM path hdrs to be parsed. The TO should be
	 * already, so let's do the FROM */
	if (req->from_path->parsed == NULL) {
		req->from_path->parsed = parse_msrp_path( &req->from_path->body);
		if (req->from_path->parsed == NULL) {
			LM_ERR("Invalid From-Path payload :(\n");
			return -1;
		}
	}
	from = ((struct msrp_url*)(req->from_path->parsed));
	to   = ((struct msrp_url*)(req->to_path->parsed));

	/* we need to move the top path from TO to FROM, while keeping the
	 * the whole message the same */

	if (to->next==NULL) {
		LM_ERR("cannot forward as there is no second URL in TO-PATH\n");
		return -1;
	}

	/* before doing and heavy lifting (as building the out buffer), let's
	 * resolve the destination first. */
	bk = to->next->host.s[to->next->host.len]; // usual hack
	to->next->host.s[to->next->host.len] = 0;
	he = resolvehost( to->next->host.s, 0/*no_ip_test*/); // FIXME - do SRV
	to->next->host.s[to->next->host.len] = bk;
	if (he==NULL) {
		LM_ERR("Could not resolve the destination <%.*s>\n",
			to->next->host.len, to->next->host.s);
		return -2;
	}
	if ( to->next->port_no==0 ) {
		LM_BUG("Add the check or SRV support !!\n");
		return -2;
	}
	if ( hostent2su( &su, he, 0/*idx*/, to->next->port_no )!=0 ) {
		LM_ERR("Could translate he to su :-/, bad familly type??\n");
		return -2;
	}


	/* the len will be the same after moving the URL, the only diff will
	 * be imposed by any extra hdrs */
	len = req->len;
	if (hdrs_no>0 && hdrs) 
		for( i=0 ; i<hdrs_no ; i++ )
			len += hdrs[i].len + CRLF_LEN;


	/* allocate the buffer */
	buf = pkg_malloc( len );
	if (buf==NULL) {
		LM_ERR("failed to pkg allocate the request buffer\n");
		return -3;
	}


	/* start building */
	p = buf;
	s = req->buf;

	/* TO is the first hdr, so copy everything up to its first URL (which
	 * needs to be skipped here) */
	append_string( p, s, (int)(to->whole.s-s));
	// copy starting with the second URL, all the way to the first FROM URL
	s = to->next->whole.s;
	append_string( p, s, (int)(from->whole.s-s));
	// first place here the first TO URL that was skipped
	append_string( p, to->whole.s, to->whole.len);
	*(p++) = ' ';
	// copy starting with the first FROM URL
	s = from->whole.s;
	if (hdrs_no>0 && hdrs) {
		/* copy up to the end of the last hdr (including its CRLF) */
		append_string( p, s,
			(int)(req->last_header->name.s+req->last_header->len -s));
		/* add the new extra hdrs */
		for ( i=0 ; i<hdrs_no ; i++) {
			append_string( p,  hdrs[i].s,  hdrs[i].len);
			append_string( p, CRLF, CRLF_LEN);
		}
		/* copy from the end of the last hdr all the way to the end of buffer*/
		s = req->last_header->name.s + req->last_header->len;
		append_string( p, s, (int)(req->buf+req->len-s));
	} else {
		/* nothing to append, copy all the way to the end of buffer*/
		append_string( p, s, (int)(req->buf+req->len-s));
	}

	if (p-buf!=len) {
		LM_BUG("computed %d, but wrote %d :(\n",len,(int)(p-buf));
		goto error;
	}
#ifdef MSRP_DEBUG
	LM_DBG("----|\n%.*s|-----\n",len,buf);
#endif


	/* now, send it out*/
	// TODO - for now we use the same socket (as the received one), but
	//        it will nice to be able to change it (via script??) in order
	//        to do traffic bridging between 2 interfaces.
	i = msg_send( req->rcv.bind_address, PROTO_MSRP, &su, 0 /*conn-id*/,
			buf, len, NULL);
	if (i<0) {
		/* sending failed, TODO - close the connection */
		LM_ERR("failed to fwd MSRP request\n");
		goto error;
	}

	pkg_free(buf);
	return 0;

error:
	pkg_free(buf);
	return -3;
}


int msrp_fwd_reply( struct msrp_msg *rpl)
{
	char *buf, *p;
	struct msrp_url *to, *from;

	if (rpl==NULL)
		return -1;

	/* we need both TO and FROM path hdrs to be parsed, none are 
	 * parsed for sure at this point */
	if (rpl->from_path->parsed == NULL) {
		rpl->from_path->parsed = parse_msrp_path( &rpl->from_path->body);
		if (rpl->from_path->parsed == NULL) {
			LM_ERR("Invalid From-Path payload :(\n");
			return -1;
		}
	}
	from = ((struct msrp_url*)(rpl->from_path->parsed));
	to   = ((struct msrp_url*)(rpl->to_path->parsed));

	/* we need to move the top path from TO to FROM, while keeping the
	 * the whole message the same */

	if (to->next==NULL) {
		LM_ERR("cannot forward as there is no second URL in TO-PATH\n");
		return -1;
	}

	/*  WIP - we need the transactional support
	 */
	p = NULL; buf = p; p = buf;
	to = from;


	return -1;
}
