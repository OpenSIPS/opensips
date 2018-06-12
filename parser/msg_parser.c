/*
 * $Id$
 *
 * sip msg. header proxy parser 
 *
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * ---------
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-01-29  scrathcpad removed (jiri)
 *  2003-01-27  next baby-step to removing ZT - PRESERVE_ZT (jiri)
 *  2003-03-31  removed msg->repl_add_rm (andrei)
 *  2003-04-26 ZSW (jiri)
 *  2003-05-01  parser extended to support Accept header field (janakj)
 */


#include <string.h>
#include <stdlib.h>

#include "../comp_defs.h"
#include "msg_parser.h"
#include "parser_f.h"
#include "../ut.h"
#include "../error.h"
#include "../dprint.h"
#include "../data_lump_rpl.h"
#include "../mem/mem.h"
#include "../error.h"
#include "../globals.h"
#include "parse_hname2.h"
#include "parse_uri.h"
#include "parse_content.h"

#ifdef DEBUG_DMALLOC
#include <mem/dmalloc.h>
#endif


#define parse_hname(_b,_e,_h) parse_hname2((_b),(_e),(_h))

/* number of via's encounteded */
int via_cnt;

/* returns pointer to next header line, and fill hdr_f ;
 * if at end of header returns pointer to the last crlf  (always buf)*/
char* get_hdr_field(char* buf, char* end, struct hdr_field* hdr)
{

	char* tmp;
	char *match;
	struct via_body *vb;
	struct cseq_body* cseq_b;
	struct to_body* to_b;
	int integer;

	if ((*buf)=='\n' || (*buf)=='\r'){
		/* double crlf or lflf or crcr */
		DBG("found end of header\n");
		hdr->type=HDR_EOH;
		return buf;
	}

	tmp=parse_hname(buf, end, hdr);
	if (hdr->type==HDR_ERROR){
		LOG(L_ERR, "ERROR: get_hdr_field: bad header\n");
		goto error;
	}

	/* eliminate leading whitespace */
	tmp=eat_lws_end(tmp, end);
	if (tmp>=end) {
		LOG(L_ERR, "ERROR: get_hdr_field: HF empty\n");
		goto error;
	}

	/* if header-field well-known, parse it, find its end otherwise ;
	 * after leaving the hdr->type switch, tmp should be set to the
	 * next header field
	 */
	switch(hdr->type){
		case HDR_VIA:
			/* keep number of vias parsed -- we want to report it in
			   replies for diagnostic purposes */
			via_cnt++;
			vb=pkg_malloc(sizeof(struct via_body));
			if (vb==0){
				LOG(L_ERR, "get_hdr_field: out of memory\n");
				goto error;
			}
			memset(vb,0,sizeof(struct via_body));
			hdr->body.s=tmp;
			tmp=parse_via(tmp, end, vb);
			if (vb->error==PARSE_ERROR){
				LOG(L_ERR, "ERROR: get_hdr_field: bad via\n");
				pkg_free(vb);
				goto error;
			}
			hdr->parsed=vb;
			vb->hdr.s=hdr->name.s;
			vb->hdr.len=hdr->name.len;
			hdr->body.len=tmp-hdr->body.s;
			break;
		case HDR_CSEQ:
			cseq_b=pkg_malloc(sizeof(struct cseq_body));
			if (cseq_b==0){
				LOG(L_ERR, "get_hdr_field: out of memory\n");
				goto error;
			}
			memset(cseq_b, 0, sizeof(struct cseq_body));
			hdr->body.s=tmp;
			tmp=parse_cseq(tmp, end, cseq_b);
			if (cseq_b->error==PARSE_ERROR){
				LOG(L_ERR, "ERROR: get_hdr_field: bad cseq\n");
				pkg_free(cseq_b);
				goto error;
			}
			hdr->parsed=cseq_b;
			hdr->body.len=tmp-hdr->body.s;
			DBG("get_hdr_field: cseq <%.*s>: <%.*s> <%.*s>\n",
					hdr->name.len, ZSW(hdr->name.s), 
					cseq_b->number.len, ZSW(cseq_b->number.s), 
					cseq_b->method.len, cseq_b->method.s);
			break;
		case HDR_TO:
			to_b=pkg_malloc(sizeof(struct to_body));
			if (to_b==0){
				LOG(L_ERR, "get_hdr_field: out of memory\n");
				goto error;
			}
			memset(to_b, 0, sizeof(struct to_body));
			hdr->body.s=tmp;
			tmp=parse_to(tmp, end,to_b);
			if (to_b->error==PARSE_ERROR){
				LOG(L_ERR, "ERROR: get_hdr_field: bad to header\n");
				pkg_free(to_b);
				goto error;
			}
			hdr->parsed=to_b;
			hdr->body.len=tmp-hdr->body.s;
			DBG("DEBUG: get_hdr_field: <%.*s> [%d]; uri=[%.*s] \n",
				hdr->name.len, ZSW(hdr->name.s), 
				hdr->body.len, to_b->uri.len,ZSW(to_b->uri.s));
			DBG("DEBUG: to body [%.*s]\n",to_b->body.len,
				ZSW(to_b->body.s));
			break;
		case HDR_CONTENTLENGTH:
			hdr->body.s=tmp;
			tmp=parse_content_length(tmp,end, &integer);
			if (tmp==0){
				LOG(L_ERR, "ERROR:get_hdr_field: bad content_length header\n");
				goto error;
			}
			hdr->parsed=(void*)(long)integer;
			hdr->body.len=tmp-hdr->body.s;
			DBG("DEBUG: get_hdr_body : content_length=%d\n",
					(int)(long)hdr->parsed);
			break;
		case HDR_SUPPORTED:
		case HDR_CONTENTTYPE:
		case HDR_FROM:
		case HDR_CALLID:
		case HDR_CONTACT:
		case HDR_ROUTE:
		case HDR_RECORDROUTE:
		case HDR_MAXFORWARDS:
		case HDR_AUTHORIZATION:
		case HDR_EXPIRES:
		case HDR_PROXYAUTH:
		case HDR_PROXYREQUIRE:
		case HDR_UNSUPPORTED:
		case HDR_ALLOW:
		case HDR_EVENT:
	        case HDR_ACCEPT:
	        case HDR_ACCEPTLANGUAGE:
	        case HDR_ORGANIZATION:
	        case HDR_PRIORITY:
	        case HDR_SUBJECT:
	        case HDR_USERAGENT:
	        case HDR_CONTENTDISPOSITION:
	        case HDR_ACCEPTDISPOSITION:
		case HDR_OTHER:
			/* just skip over it */
			hdr->body.s=tmp;
			/* find end of header */
			/* find lf */
			do{
				match=q_memchr(tmp, '\n', end-tmp);
				if (match){
					match++;
				}else {
					LOG(L_ERR,
							"ERROR: get_hdr_field: bad body for <%s>(%d)\n",
							hdr->name.s, hdr->type);
					/* abort(); */
					tmp=end;
					goto error;
				}
				tmp=match;
			}while( match<end &&( (*match==' ')||(*match=='\t') ) );
			tmp=match;
			hdr->body.len=match-hdr->body.s;
			break;
		default:
			LOG(L_CRIT, "BUG: get_hdr_field: unknown header type %d\n",
					hdr->type);
			goto error;
	}
	/* jku: if \r covered by current length, shrink it */
	trim_r( hdr->body );
	hdr->len=tmp-hdr->name.s;
	return tmp;
error:
	DBG("get_hdr_field: error exit\n");
	hdr->type=HDR_ERROR;
	hdr->len=tmp-hdr->name.s;
	return tmp;
}



/* parse the headers and adds them to msg->headers and msg->to, from etc.
 * It stops when all the headers requested in flags were parsed, on error
 * (bad header) or end of headers */
/* note: it continues where it previously stopped and goes ahead until
   end is encountered or desired HFs are found; if you call it twice
   for the same HF which is present only once, it will fail the second
   time; if you call it twice and the HF is found on second time too,
   it's not replaced in the well-known HF pointer but just added to
   header list; if you want to use a dumbie convenience function which will
   give you the first occurance of a header you are interested in,
   look at check_transaction_quadruple
*/
int parse_headers(struct sip_msg* msg, int flags, int next)
{
	struct hdr_field* hf;
	char* tmp;
	char* rest;
	char* end;
	int orig_flag;

	end=msg->buf+msg->len;
	tmp=msg->unparsed;
	
	if (next) {
		orig_flag = msg->parsed_flag;
		msg->parsed_flag &= ~flags;
	}else
		orig_flag=0; 
	
	DBG("parse_headers: flags=%d\n", flags);
	while( tmp<end && (flags & msg->parsed_flag) != flags){
		hf=pkg_malloc(sizeof(struct hdr_field));
		if (hf==0){
			ser_error=E_OUT_OF_MEM;
			LOG(L_ERR, "ERROR:parse_headers: memory allocation error\n");
			goto error;
		}
		memset(hf,0, sizeof(struct hdr_field));
		hf->type=HDR_ERROR;
		rest=get_hdr_field(tmp, msg->buf+msg->len, hf);
		switch (hf->type){
			case HDR_ERROR:
				LOG(L_INFO,"ERROR: bad header  field\n");
				goto  error;
			case HDR_EOH:
				msg->eoh=tmp; /* or rest?*/
				msg->parsed_flag|=HDR_EOH;
				pkg_free(hf);
				goto skip;
			case HDR_OTHER: /*do nothing*/
				break;
			case HDR_CALLID:
				if (msg->callid==0) msg->callid=hf;
				msg->parsed_flag|=HDR_CALLID;
				break;
			case HDR_TO:
				if (msg->to==0) msg->to=hf;
				msg->parsed_flag|=HDR_TO;
				break;
			case HDR_CSEQ:
				if (msg->cseq==0) msg->cseq=hf;
				msg->parsed_flag|=HDR_CSEQ;
				break;
			case HDR_FROM:
				if (msg->from==0) msg->from=hf;
				msg->parsed_flag|=HDR_FROM;
				break;
			case HDR_CONTACT:
				if (msg->contact==0) msg->contact=hf;
				msg->parsed_flag|=HDR_CONTACT;
				break;
			case HDR_MAXFORWARDS:
				if(msg->maxforwards==0) msg->maxforwards=hf;
				msg->parsed_flag|=HDR_MAXFORWARDS;
				break;
			case HDR_ROUTE:
				if (msg->route==0) msg->route=hf;
				msg->parsed_flag|=HDR_ROUTE;
				break;
			case HDR_RECORDROUTE:
				if (msg->record_route==0) msg->record_route = hf;
				msg->parsed_flag|=HDR_RECORDROUTE;
				break;
			case HDR_CONTENTTYPE:
				if (msg->content_type==0) msg->content_type = hf;
				msg->parsed_flag|=HDR_CONTENTTYPE;
				break;
			case HDR_CONTENTLENGTH:
				if (msg->content_length==0) msg->content_length = hf;
				msg->parsed_flag|=HDR_CONTENTLENGTH;
				break;
			case HDR_AUTHORIZATION:
				if (msg->authorization==0) msg->authorization = hf;
				msg->parsed_flag|=HDR_AUTHORIZATION;
				break;
			case HDR_EXPIRES:
				if (msg->expires==0) msg->expires = hf;
				msg->parsed_flag|=HDR_EXPIRES;
				break;
			case HDR_PROXYAUTH:
				if (msg->proxy_auth==0) msg->proxy_auth = hf;
				msg->parsed_flag|=HDR_PROXYAUTH;
				break;
		        case HDR_PROXYREQUIRE:
				if (msg->proxy_require==0) msg->proxy_require = hf;
				msg->parsed_flag|=HDR_PROXYREQUIRE;
				break;
	                case HDR_SUPPORTED:
				if (msg->supported==0) msg->supported=hf;
				msg->parsed_flag|=HDR_SUPPORTED;
				break;
			case HDR_UNSUPPORTED:
				if (msg->unsupported==0) msg->unsupported=hf;
				msg->parsed_flag|=HDR_UNSUPPORTED;
				break;
			case HDR_ALLOW:
				if (msg->allow==0) msg->allow = hf;
				msg->parsed_flag|=HDR_ALLOW;
				break;
			case HDR_EVENT:
				if (msg->allow==0) msg->event = hf;
				msg->parsed_flag|=HDR_EVENT;
				break;
		        case HDR_ACCEPT:
				if (msg->accept==0) msg->accept = hf;
				msg->parsed_flag|=HDR_ACCEPT;
				break;
		        case HDR_ACCEPTLANGUAGE:
				if (msg->accept_language==0) msg->accept_language = hf;
				msg->parsed_flag|=HDR_ACCEPTLANGUAGE;
				break;
		        case HDR_ORGANIZATION:
				if (msg->organization==0) msg->organization = hf;
				msg->parsed_flag|=HDR_ORGANIZATION;
				break;
		        case HDR_PRIORITY:
				if (msg->priority==0) msg->priority = hf;
				msg->parsed_flag|=HDR_PRIORITY;
				break;
		        case HDR_SUBJECT:
				if (msg->subject==0) msg->subject = hf;
				msg->parsed_flag|=HDR_SUBJECT;
				break;
		        case HDR_USERAGENT:
				if (msg->user_agent==0) msg->user_agent = hf;
				msg->parsed_flag|=HDR_USERAGENT;
				break;
		        case HDR_CONTENTDISPOSITION:
				if (msg->content_disposition==0) msg->content_disposition = hf;
				msg->parsed_flag|=HDR_CONTENTDISPOSITION;
				break;
		        case HDR_ACCEPTDISPOSITION:
				if (msg->accept_disposition==0) msg->accept_disposition = hf;
				msg->parsed_flag|=HDR_ACCEPTDISPOSITION;
				break;
			case HDR_VIA:
				msg->parsed_flag|=HDR_VIA;
				DBG("parse_headers: Via found, flags=%d\n", flags);
				if (msg->via1==0) {
					DBG("parse_headers: this is the first via\n");
					msg->h_via1=hf;
					msg->via1=hf->parsed;
					if (msg->via1->next){
						msg->via2=msg->via1->next;
						msg->parsed_flag|=HDR_VIA2;
					}
				}else if (msg->via2==0){
					msg->h_via2=hf;
					msg->via2=hf->parsed;
					msg->parsed_flag|=HDR_VIA2;
					DBG("parse_headers: this is the second via\n");
				}
				break;
			default:
				LOG(L_CRIT, "BUG: parse_headers: unknown header type %d\n",
							hf->type);
				goto error;
		}
		/* add the header to the list*/
		if (msg->last_header==0){
			msg->headers=hf;
			msg->last_header=hf;
		}else{
			msg->last_header->next=hf;
			msg->last_header=hf;
		}
#ifdef EXTRA_DEBUG
		DBG("header field type %d, name=<%.*s>, body=<%.*s>\n",
			hf->type, 
			hf->name.len, ZSW(hf->name.s), 
			hf->body.len, ZSW(hf->body.s));
#endif
		tmp=rest;
	}
skip:
	msg->unparsed=tmp;
	return 0;

error:
	ser_error=E_BAD_REQ;
	if (hf) pkg_free(hf);
	if (next) msg->parsed_flag |= orig_flag;
	return -1;
}





/* returns 0 if ok, -1 for errors */
int parse_msg(char* buf, unsigned int len, struct sip_msg* msg)
{

	char *tmp;
	char* rest;
	char* first_via;
	char* second_via;
	struct msg_start *fl;
	int offset;
	int flags;

	/* eat crlf from the beginning */
	for (tmp=buf; (*tmp=='\n' || *tmp=='\r')&&
			tmp-buf < len ; tmp++);
	offset=tmp-buf;
	fl=&(msg->first_line);
	rest=parse_first_line(tmp, len-offset, fl);
#if 0
	rest=parse_fline(tmp, buf+len, fl);
#endif
	offset+=rest-tmp;
	tmp=rest;
	switch(fl->type){
		case SIP_INVALID:
			DBG("parse_msg: invalid message\n");
			goto error;
			break;
		case SIP_REQUEST:
			DBG("SIP Request:\n");
			DBG(" method:  <%.*s>\n",fl->u.request.method.len,
				ZSW(fl->u.request.method.s));
			DBG(" uri:     <%.*s>\n",fl->u.request.uri.len,
				ZSW(fl->u.request.uri.s));
			DBG(" version: <%.*s>\n",fl->u.request.version.len,
				ZSW(fl->u.request.version.s));
			flags=HDR_VIA;
			break;
		case SIP_REPLY:
			DBG("SIP Reply  (status):\n");
			DBG(" version: <%.*s>\n",fl->u.reply.version.len,
					ZSW(fl->u.reply.version.s));
			DBG(" status:  <%.*s>\n", fl->u.reply.status.len,
					ZSW(fl->u.reply.status.s));
			DBG(" reason:  <%.*s>\n", fl->u.reply.reason.len,
					ZSW(fl->u.reply.reason.s));
			/* flags=HDR_VIA | HDR_VIA2; */
			/* we don't try to parse VIA2 for local messages; -Jiri */
			flags=HDR_VIA;
			break;
		default:
			DBG("unknown type %d\n",fl->type);
			goto error;
	}
	msg->unparsed=tmp;
	/*find first Via: */
	first_via=0;
	second_via=0;
	if (parse_headers(msg, flags, 0)==-1) goto error;

#ifdef EXTRA_DEBUG
	/* dump parsed data */
	if (msg->via1){
		DBG(" first  via: <%.*s/%.*s/%.*s> <%.*s:%.*s(%d)>",
			msg->via1->name.len, 
			ZSW(msg->via1->name.s), 
			msg->via1->version.len,
			ZSW(msg->via1->version.s),
			msg->via1->transport.len,
			ZSW(msg->via1->transport.s), 
			msg->via1->host.len,
			ZSW(msg->via1->host.s),
			msg->via1->port_str.len, 
			ZSW(msg->via1->port_str.s), 
			msg->via1->port);
		if (msg->via1->params.s)  DBG(";<%.*s>", 
				msg->via1->params.len, ZSW(msg->via1->params.s));
		if (msg->via1->comment.s) 
				DBG(" <%.*s>", 
					msg->via1->comment.len, ZSW(msg->via1->comment.s));
		DBG ("\n");
	}
	if (msg->via2){
		DBG(" first  via: <%.*s/%.*s/%.*s> <%.*s:%.*s(%d)>",
			msg->via2->name.len, 
			ZSW(msg->via2->name.s), 
			msg->via2->version.len,
			ZSW(msg->via2->version.s),
			msg->via2->transport.len, 
			ZSW(msg->via2->transport.s), 
			msg->via2->host.len,
			ZSW(msg->via2->host.s),
			msg->via2->port_str.len, 
			ZSW(msg->via2->port_str.s), 
			msg->via2->port);
		if (msg->via2->params.s)  DBG(";<%.*s>", 
				msg->via2->params.len, ZSW(msg->via2->params.s));
		if (msg->via2->comment.s) DBG(" <%.*s>", 
				msg->via2->comment.len, ZSW(msg->via2->comment.s));
		DBG ("\n");
	}
#endif
	

#ifdef EXTRA_DEBUG
	DBG("exiting parse_msg\n");
#endif

	return 0;
	
error:
	/* more debugging, msg->orig is/should be null terminated*/
	LOG(L_ERR, "ERROR: parse_msg: message=<%.*s>\n", 
			(int)msg->len, ZSW(msg->buf));
	return -1;
}



void free_reply_lump( struct lump_rpl *lump)
{
	struct lump_rpl *foo, *bar;
	for(foo=lump;foo;)
	{
		bar=foo->next;
		free_lump_rpl(foo);
		foo = bar;
	}
}


/*only the content*/
void free_sip_msg(struct sip_msg* msg)
{
	if (msg->new_uri.s) { pkg_free(msg->new_uri.s); msg->new_uri.len=0; }
	if (msg->headers)     free_hdr_field_lst(msg->headers);
	if (msg->add_rm)      free_lump_list(msg->add_rm);
	if (msg->body_lumps)  free_lump_list(msg->body_lumps);
	if (msg->reply_lump)   free_reply_lump(msg->reply_lump);
	/* don't free anymore -- now a pointer to a static buffer */
#	ifdef DYN_BUF
	pkg_free(msg->buf); 
#	endif
}


/* make sure all HFs needed for transaction identification have been
   parsed; return 0 if those HFs can't be found
*/

int check_transaction_quadruple( struct sip_msg* msg )
{
	if ( parse_headers(msg, HDR_FROM|HDR_TO|HDR_CALLID|HDR_CSEQ,0)!=-1
		&& msg->from && msg->to && msg->callid && msg->cseq ) {
		return 1;
	} else {
		ser_error=E_BAD_TUPEL;
		return 0;
	}
}
