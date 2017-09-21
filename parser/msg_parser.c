/*
 * sip msg. header proxy parser
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * ---------
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-01-29  scrathcpad removed (jiri)
 *  2003-01-27  next baby-step to removing ZT - PRESERVE_ZT (jiri)
 *  2003-03-31  removed msg->repl_add_rm (andrei)
 *  2003-04-26 ZSW (jiri)
 *  2003-05-01  parser extended to support Accept header field (janakj)
 *  2005-03-02  free_via_list(vb) on via parse error (andrei)
 *  2006-02-17 Session-Expires, Min-SE (dhsueh@somanetworks.com)
 *  2006-03-02 header of same type are linked as sibling (bogdan)
 *  2006-11-28 Added statistic support for bad message headers.
 *             (Jeffrey Magder - SOMA Networks)
 *  2008-09-09 Added sdp parsing support (osas)
 */


#include <string.h>
#include <stdlib.h>

#include "msg_parser.h"
#include "parser_f.h"
#include "../ut.h"
#include "../error.h"
#include "../dprint.h"
#include "../data_lump_rpl.h"
#include "../mem/mem.h"
#include "../error.h"
#include "../globals.h"
#include "../core_stats.h"
#include "../errinfo.h"
#include "../dset.h"
#include "parse_hname2.h"
#include "parse_uri.h"
#include "parse_content.h"
#include "../msg_callbacks.h"

#ifdef DEBUG_DMALLOC
#include <mem/dmalloc.h>
#endif


#define parse_hname(_b,_e,_h) parse_hname2((_b),(_e),(_h))

/* number of via's encountered */
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
		LM_DBG("found end of header\n");
		hdr->type=HDR_EOH_T;
		return buf;
	}

	tmp=parse_hname(buf, end, hdr);
	if (hdr->type==HDR_ERROR_T){
		LM_ERR("bad header\n");
		goto error_bad_hdr;
	}

	/* eliminate leading whitespace */
	tmp=eat_lws_end(tmp, end);
	if (tmp>=end) {
		LM_ERR("hf empty\n");
		goto error_bad_hdr;
	}

	/* if header-field well-known, parse it, find its end otherwise ;
	 * after leaving the hdr->type switch, tmp should be set to the
	 * next header field
	 */
	switch(hdr->type){
		case HDR_VIA_T:
			/* keep number of vias parsed -- we want to report it in
			   replies for diagnostic purposes */
			via_cnt++;
			vb=pkg_malloc(sizeof(struct via_body));
			if (vb==0){
				LM_ERR("out of pkg memory\n");
				goto error;
			}
			memset(vb,0,sizeof(struct via_body));
			hdr->body.s=tmp;
			tmp=parse_via(tmp, end, vb);
			if (vb->error==PARSE_ERROR){
				LM_ERR("bad via\n");
				free_via_list(vb);
				set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
					"error parsing Via");
				set_err_reply(400, "bad Via header");
				goto error;
			}
			hdr->parsed=vb;
			vb->hdr.s=hdr->name.s;
			vb->hdr.len=hdr->name.len;
			hdr->body.len=tmp-hdr->body.s;
			break;
		case HDR_CSEQ_T:
			cseq_b=pkg_malloc(sizeof(struct cseq_body));
			if (cseq_b==0){
				LM_ERR("out of pkg memory\n");
				goto error;
			}
			memset(cseq_b, 0, sizeof(struct cseq_body));
			hdr->body.s=tmp;
			tmp=parse_cseq(tmp, end, cseq_b);
			if (cseq_b->error==PARSE_ERROR){
				LM_ERR("bad cseq\n");
				pkg_free(cseq_b);
				set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
					"error parsing CSeq`");
				set_err_reply(400, "bad CSeq header");
				goto error;
			}
			hdr->parsed=cseq_b;
			hdr->body.len=tmp-hdr->body.s;
			LM_DBG("cseq <%.*s>: <%.*s> <%.*s>\n",
					hdr->name.len, ZSW(hdr->name.s),
					cseq_b->number.len, ZSW(cseq_b->number.s),
					cseq_b->method.len, cseq_b->method.s);
			break;
		case HDR_TO_T:
			to_b=pkg_malloc(sizeof(struct to_body));
			if (to_b==0){
				LM_ERR("out of pkg memory\n");
				goto error;
			}
			memset(to_b, 0, sizeof(struct to_body));
			hdr->body.s=tmp;
			tmp=parse_to(tmp, end,to_b);
			if (to_b->error==PARSE_ERROR){
				LM_ERR("bad to header\n");
				pkg_free(to_b);
				set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
					"error parsing To header");
				set_err_reply(400, "bad header");
				goto error;
			}
			hdr->parsed=to_b;
			hdr->body.len=tmp-hdr->body.s;
			LM_DBG("<%.*s> [%d]; uri=[%.*s] \n",
				hdr->name.len, ZSW(hdr->name.s),
				hdr->body.len, to_b->uri.len,ZSW(to_b->uri.s));
			LM_DBG("to body [%.*s]\n",to_b->body.len, ZSW(to_b->body.s));
			break;
		case HDR_CONTENTLENGTH_T:
			hdr->body.s=tmp;
			tmp=parse_content_length(tmp,end, &integer);
			if (tmp==0){
				LM_ERR("bad content_length header\n");
				set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
					"error parsing Content-Length");
				set_err_reply(400, "bad Content-Length header");
				goto error;
			}
			hdr->parsed=(void*)(long)integer;
			hdr->body.len=tmp-hdr->body.s;
			LM_DBG("content_length=%d\n", (int)(long)hdr->parsed);
			break;
		case HDR_SUPPORTED_T:
		case HDR_CONTENTTYPE_T:
		case HDR_FROM_T:
		case HDR_CALLID_T:
		case HDR_CONTACT_T:
		case HDR_ROUTE_T:
		case HDR_RECORDROUTE_T:
		case HDR_PATH_T:
		case HDR_MAXFORWARDS_T:
		case HDR_AUTHORIZATION_T:
		case HDR_EXPIRES_T:
		case HDR_PROXYAUTH_T:
		case HDR_PROXYREQUIRE_T:
		case HDR_UNSUPPORTED_T:
		case HDR_ALLOW_T:
		case HDR_EVENT_T:
		case HDR_ACCEPT_T:
		case HDR_ACCEPTLANGUAGE_T:
		case HDR_ORGANIZATION_T:
		case HDR_PRIORITY_T:
		case HDR_SUBJECT_T:
		case HDR_USERAGENT_T:
		case HDR_CONTENTDISPOSITION_T:
		case HDR_ACCEPTDISPOSITION_T:
		case HDR_DIVERSION_T:
		case HDR_RPID_T:
		case HDR_REFER_TO_T:
		case HDR_SESSION_EXPIRES_T:
		case HDR_MIN_SE_T:
		case HDR_MIN_EXPIRES_T:
		case HDR_PPI_T:
		case HDR_PAI_T:
		case HDR_PRIVACY_T:
		case HDR_RETRY_AFTER_T:
		case HDR_CALL_INFO_T:
		case HDR_WWW_AUTHENTICATE_T:
		case HDR_PROXY_AUTHENTICATE_T:
		case HDR_OTHER_T:
			/* just skip over it */
			hdr->body.s=tmp;
			/* find end of header */
			/* find lf */
			do{
				match=q_memchr(tmp, '\n', end-tmp);
				if (match){
					match++;
				}else {
					LM_ERR("bad body for <%s>(%d)\n", hdr->name.s, hdr->type);
					tmp=end;
					goto error_bad_hdr;
				}
				tmp=match;
			}while( match<end &&( (*match==' ')||(*match=='\t') ) );
			tmp=match;
			hdr->body.len=match-hdr->body.s;
			break;
		default:
			LM_CRIT("unknown header type %d\n", hdr->type);
			goto error;
	}
	/* jku: if \r covered by current length, shrink it */
	trim_r( hdr->body );
	hdr->len=tmp-hdr->name.s;
	return tmp;

error_bad_hdr:
	set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
		"error parsing headers");
	set_err_reply(400, "bad headers");
error:
	LM_DBG("error exit\n");
	update_stat( bad_msg_hdr, 1);
	hdr->type=HDR_ERROR_T;
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
   header list; if you want to use a dumb convenience function which will
   give you the first occurrence of a header you are interested in,
   look at check_transaction_quadruple
*/
int parse_headers(struct sip_msg* msg, hdr_flags_t flags, int next)
{
	struct hdr_field *hf;
	struct hdr_field *itr;
	char* tmp;
	char* rest;
	char* end;
	hdr_flags_t orig_flag;

#define link_sibling_hdr(_hook, _hdr) \
	do{ \
		if (msg->_hook==0) msg->_hook=_hdr;\
			else {\
				for(itr=msg->_hook;itr->sibling;itr=itr->sibling);\
				itr->sibling = _hdr;\
			}\
	}while(0)

	end=msg->buf+msg->len;
	tmp=msg->unparsed;

	if (next) {
		orig_flag = msg->parsed_flag;
		msg->parsed_flag &= ~flags;
	}else
		orig_flag=0;

	LM_DBG("flags=%llx\n", (unsigned long long)flags);
	while( tmp<end && (flags & msg->parsed_flag) != flags){
		hf=pkg_malloc(sizeof(struct hdr_field));
		if (hf==0){
			ser_error=E_OUT_OF_MEM;
			LM_ERR("pkg memory allocation failed\n");
			goto error;
		}
		memset(hf,0, sizeof(struct hdr_field));
		hf->type=HDR_ERROR_T;
		rest=get_hdr_field(tmp, msg->buf+msg->len, hf);
		switch (hf->type){
			case HDR_ERROR_T:
				LM_INFO("bad header field\n");
				goto  error;
			case HDR_EOH_T:
				msg->eoh=tmp; /* or rest?*/
				msg->parsed_flag|=HDR_EOH_F;
				pkg_free(hf);
				goto skip;
			case HDR_OTHER_T: /*do nothing*/
				break;
			case HDR_CALLID_T:
				if (msg->callid==0) msg->callid=hf;
				msg->parsed_flag|=HDR_CALLID_F;
				break;
			case HDR_TO_T:
				if (msg->to==0) msg->to=hf;
				msg->parsed_flag|=HDR_TO_F;
				break;
			case HDR_CSEQ_T:
				if (msg->cseq==0) msg->cseq=hf;
				msg->parsed_flag|=HDR_CSEQ_F;
				break;
			case HDR_FROM_T:
				if (msg->from==0) msg->from=hf;
				msg->parsed_flag|=HDR_FROM_F;
				break;
			case HDR_CONTACT_T:
				link_sibling_hdr(contact,hf);
				msg->parsed_flag|=HDR_CONTACT_F;
				break;
			case HDR_MAXFORWARDS_T:
				if(msg->maxforwards==0) msg->maxforwards=hf;
				msg->parsed_flag|=HDR_MAXFORWARDS_F;
				break;
			case HDR_ROUTE_T:
				link_sibling_hdr(route,hf);
				msg->parsed_flag|=HDR_ROUTE_F;
				break;
			case HDR_RECORDROUTE_T:
				link_sibling_hdr(record_route,hf);
				msg->parsed_flag|=HDR_RECORDROUTE_F;
				break;
			case HDR_PATH_T:
				link_sibling_hdr(path,hf);
				msg->parsed_flag|=HDR_PATH_F;
				break;
			case HDR_CONTENTTYPE_T:
				if (msg->content_type==0) msg->content_type = hf;
				msg->parsed_flag|=HDR_CONTENTTYPE_F;
				break;
			case HDR_CONTENTLENGTH_T:
				if (msg->content_length==0) msg->content_length = hf;
				msg->parsed_flag|=HDR_CONTENTLENGTH_F;
				break;
			case HDR_AUTHORIZATION_T:
				link_sibling_hdr(authorization,hf);
				msg->parsed_flag|=HDR_AUTHORIZATION_F;
				break;
			case HDR_EXPIRES_T:
				if (msg->expires==0) msg->expires = hf;
				msg->parsed_flag|=HDR_EXPIRES_F;
				break;
			case HDR_PROXYAUTH_T:
				link_sibling_hdr(proxy_auth,hf);
				msg->parsed_flag|=HDR_PROXYAUTH_F;
				break;
			case HDR_PROXYREQUIRE_T:
				link_sibling_hdr(proxy_require,hf);
				msg->parsed_flag|=HDR_PROXYREQUIRE_F;
				break;
			case HDR_SUPPORTED_T:
				link_sibling_hdr(supported,hf);
				msg->parsed_flag|=HDR_SUPPORTED_F;
				break;
			case HDR_UNSUPPORTED_T:
				link_sibling_hdr(unsupported,hf);
				msg->parsed_flag|=HDR_UNSUPPORTED_F;
				break;
			case HDR_ALLOW_T:
				link_sibling_hdr(allow,hf);
				msg->parsed_flag|=HDR_ALLOW_F;
				break;
			case HDR_EVENT_T:
				link_sibling_hdr(event,hf);
				msg->parsed_flag|=HDR_EVENT_F;
				break;
			case HDR_ACCEPT_T:
				link_sibling_hdr(accept,hf);
				msg->parsed_flag|=HDR_ACCEPT_F;
				break;
			case HDR_ACCEPTLANGUAGE_T:
				link_sibling_hdr(accept_language,hf);
				msg->parsed_flag|=HDR_ACCEPTLANGUAGE_F;
				break;
			case HDR_ORGANIZATION_T:
				if (msg->organization==0) msg->organization = hf;
				msg->parsed_flag|=HDR_ORGANIZATION_F;
				break;
			case HDR_PRIORITY_T:
				if (msg->priority==0) msg->priority = hf;
				msg->parsed_flag|=HDR_PRIORITY_F;
				break;
			case HDR_SUBJECT_T:
				if (msg->subject==0) msg->subject = hf;
				msg->parsed_flag|=HDR_SUBJECT_F;
				break;
			case HDR_USERAGENT_T:
				if (msg->user_agent==0) msg->user_agent = hf;
				msg->parsed_flag|=HDR_USERAGENT_F;
				break;
			case HDR_CONTENTDISPOSITION_T:
				if (msg->content_disposition==0) msg->content_disposition = hf;
				msg->parsed_flag|=HDR_CONTENTDISPOSITION_F;
				break;
			case HDR_ACCEPTDISPOSITION_T:
				link_sibling_hdr(accept_disposition,hf);
				msg->parsed_flag|=HDR_ACCEPTDISPOSITION_F;
				break;
			case HDR_DIVERSION_T:
				link_sibling_hdr(diversion,hf);
				msg->parsed_flag|=HDR_DIVERSION_F;
				break;
			case HDR_RPID_T:
				if (msg->rpid==0) msg->rpid = hf;
				msg->parsed_flag|=HDR_RPID_F;
				break;
			case HDR_CALL_INFO_T:
				link_sibling_hdr(call_info,hf);
				msg->parsed_flag|=HDR_CALL_INFO_F;
				break;
			case HDR_WWW_AUTHENTICATE_T:
				link_sibling_hdr(www_authenticate,hf);
				msg->parsed_flag|=HDR_WWW_AUTHENTICATE_F;
				break;
			case HDR_PROXY_AUTHENTICATE_T:
				link_sibling_hdr(proxy_authenticate,hf);
				msg->parsed_flag|=HDR_PROXY_AUTHENTICATE_F;
				break;
			case HDR_REFER_TO_T:
				if (msg->refer_to==0) msg->refer_to = hf;
				msg->parsed_flag|=HDR_REFER_TO_F;
				break;
			case HDR_SESSION_EXPIRES_T:
				if ( msg->session_expires == 0 ) msg->session_expires = hf;
				msg->parsed_flag |= HDR_SESSION_EXPIRES_F;
				break;
			case HDR_MIN_SE_T:
				if ( msg->min_se == 0 ) msg->min_se = hf;
				msg->parsed_flag |= HDR_MIN_SE_F;
				break;
			case HDR_MIN_EXPIRES_T:
				if ( msg->min_expires == 0 ) msg->min_expires = hf;
				msg->parsed_flag |= HDR_MIN_EXPIRES_F;
				break;
			case HDR_PPI_T:
				if (msg->ppi==0) msg->ppi = hf;
				msg->parsed_flag|=HDR_PPI_F;
				break;
			case HDR_PAI_T:
				if (msg->pai==0) msg->pai = hf;
				msg->parsed_flag|=HDR_PAI_F;
				break;
			case HDR_PRIVACY_T:
				if (msg->privacy==0) msg->privacy = hf;
				msg->parsed_flag|=HDR_PRIVACY_F;
				break;
			case HDR_RETRY_AFTER_T:
				break;
			case HDR_VIA_T:
				link_sibling_hdr(h_via1,hf);
				msg->parsed_flag|=HDR_VIA_F;
				LM_DBG("via found, flags=%llx\n", (unsigned long long)flags);
				if (msg->via1==0) {
					LM_DBG("this is the first via\n");
					msg->h_via1=hf;
					msg->via1=hf->parsed;
					if (msg->via1->next){
						msg->via2=msg->via1->next;
						msg->parsed_flag|=HDR_VIA2_F;
					}
				}else if (msg->via2==0){
					msg->h_via2=hf;
					msg->via2=hf->parsed;
					msg->parsed_flag|=HDR_VIA2_F;
					LM_DBG("parse_headers: this is the second via\n");
				}
				break;
			default:
				LM_CRIT("unknown header type %d\n",	hf->type);
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
		LM_DBG("header field type %d, name=<%.*s>, body=<%.*s>\n",
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
	struct msg_start *fl;
	int offset;
	hdr_flags_t flags;

	/* eat crlf from the beginning */
	for (tmp=buf; (*tmp=='\n' || *tmp=='\r')&&
			(unsigned int)(tmp-buf) < len ; tmp++);
	offset=tmp-buf;
	fl=&(msg->first_line);
	rest=parse_first_line(tmp, len-offset, fl);

	offset+=rest-tmp;
	tmp=rest;
	switch(fl->type){
		case SIP_INVALID:
			LM_DBG("invalid message\n");
			/* if failed to parse the first line, we simply consider that the whole
			   buffer was parsed, so that nothing is left to be parsed :) - this will
			   do the trick and make "msg" struct acceptable for following parsing
			   attempts */
			msg->unparsed = msg->buf + msg->len;
			goto error;
			break;
		case SIP_REQUEST:
			LM_DBG("SIP Request:\n");
			LM_DBG(" method:  <%.*s>\n",fl->u.request.method.len,
				ZSW(fl->u.request.method.s));
			LM_DBG(" uri:     <%.*s>\n",fl->u.request.uri.len,
				ZSW(fl->u.request.uri.s));
			LM_DBG(" version: <%.*s>\n",fl->u.request.version.len,
				ZSW(fl->u.request.version.s));
			flags=HDR_VIA_F;
			break;
		case SIP_REPLY:
			LM_DBG("SIP Reply  (status):\n");
			LM_DBG(" version: <%.*s>\n",fl->u.reply.version.len,
					ZSW(fl->u.reply.version.s));
			LM_DBG(" status:  <%.*s>\n", fl->u.reply.status.len,
					ZSW(fl->u.reply.status.s));
			LM_DBG(" reason:  <%.*s>\n", fl->u.reply.reason.len,
					ZSW(fl->u.reply.reason.s));
			flags=HDR_VIA_F;
			break;
		default:
			LM_DBG("unknown type %d\n",fl->type);
			goto error;
	}
	msg->unparsed=tmp;
	/*find first Via: */
	if (parse_headers(msg, flags, 0)==-1) goto error;

#ifdef EXTRA_DEBUG
	/* dump parsed data */
	if (msg->via1){
		LM_DBG(" first  via: <%.*s/%.*s/%.*s> <%.*s:%.*s(%d)>\n",
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
		if (msg->via1->params.s)  LM_DBG(";<%.*s>\n",
				msg->via1->params.len, ZSW(msg->via1->params.s));
		if (msg->via1->comment.s)
				LM_DBG(" <%.*s>\n",
					msg->via1->comment.len, ZSW(msg->via1->comment.s));
		LM_DBG ("\n");
	}
	if (msg->via2){
		LM_DBG(" first  via: <%.*s/%.*s/%.*s> <%.*s:%.*s(%d)>\n",
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
		if (msg->via2->params.s)  LM_DBG(";<%.*s>\n",
				msg->via2->params.len, ZSW(msg->via2->params.s));
		if (msg->via2->comment.s) LM_DBG(" <%.*s>\n",
				msg->via2->comment.len, ZSW(msg->via2->comment.s));
		LM_DBG ("\n");
	}
#endif


#ifdef EXTRA_DEBUG
	LM_DBG("exiting\n");
#endif

	return 0;

error:
	/* more debugging, msg->orig is/should be null terminated*/
	LM_ERR("message=<%.*s>\n", (int)len, ZSW(buf));
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
	if (msg->msg_cb) { msg_callback_process(msg, MSG_DESTROY, NULL); }
	if (msg->new_uri.s) { pkg_free(msg->new_uri.s); msg->new_uri.len=0; }
	if (msg->set_global_address.s) {
		pkg_free(msg->set_global_address.s);
		msg->set_global_address.s = NULL;
	}
	if (msg->set_global_port.s) {
		pkg_free(msg->set_global_port.s);
		msg->set_global_port.s = NULL;
	}
	if (msg->dst_uri.s) { pkg_free(msg->dst_uri.s); msg->dst_uri.len=0; }
	if (msg->path_vec.s) { pkg_free(msg->path_vec.s); msg->path_vec.len=0; }
	if (msg->headers)     free_hdr_field_lst(msg->headers);
	if (msg->add_rm)      free_lump_list(msg->add_rm);
	if (msg->body_lumps)  free_lump_list(msg->body_lumps);
	if (msg->reply_lump)   free_reply_lump(msg->reply_lump);
	if (msg->body )    { free_sip_body(msg->body);msg->body = 0;}
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
	if ( parse_headers(msg, HDR_FROM_F|HDR_TO_F|HDR_CALLID_F|HDR_CSEQ_F,0)!=-1
		&& msg->from && msg->to && msg->callid && msg->cseq ) {
		return 1;
	} else {
		ser_error=E_BAD_TUPEL;
		return 0;
	}
}


/*
 * Make a private copy of the string and assign it to new_uri
 */
int set_ruri(struct sip_msg *msg, str *uri)
{
	if (!msg || !uri) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* strange/corrupt input: best to assume it's an empty URI */
	if (!uri->s || uri->len == 0) {
		pkg_free(msg->new_uri.s);
		memset(&msg->new_uri, 0, sizeof msg->new_uri);
		return 0;
	}

	if (msg->new_uri.s && (msg->new_uri.len >= uri->len)) {
		memcpy(msg->new_uri.s, uri->s, uri->len);
		msg->new_uri.len = uri->len;
	} else {
		msg->new_uri.s = pkg_realloc(msg->new_uri.s, uri->len + 1);
		if (!msg->new_uri.s) {
			LM_ERR("not enough pkg memory (%d)\n",uri->len);
			return -1;
		}

		memcpy(msg->new_uri.s, uri->s, uri->len);
		msg->new_uri.len = uri->len;
	}

	set_ruri_q(msg, Q_UNSPECIFIED);
	msg->parsed_uri_ok = 0;
	return 0;
}



/*
 * Make a private copy of the string and assign it to dst_uri
 */
int set_dst_uri(struct sip_msg *msg, str *uri)
{
	if (!msg || !uri) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* strange/corrupt input: best to assume it's an empty URI */
	if (!uri->s || uri->len == 0) {
		pkg_free(msg->dst_uri.s);
		memset(&msg->dst_uri, 0, sizeof msg->dst_uri);
		return 0;
	}

	if (msg->dst_uri.s && (msg->dst_uri.len >= uri->len)) {
		memcpy(msg->dst_uri.s, uri->s, uri->len);
		msg->dst_uri.len = uri->len;
	} else {
		msg->dst_uri.s = pkg_realloc(msg->dst_uri.s, uri->len);
		if (!msg->dst_uri.s) {
			LM_ERR("not enough pkg memory\n");
			return -1;
		}

		memcpy(msg->dst_uri.s, uri->s, uri->len);
		msg->dst_uri.len = uri->len;
	}

	return 0;
}

/*
 * Make a private copy of the string and assign it to path_vec
 */
int set_path_vector(struct sip_msg *msg, str *path)
{
	if (!msg || !path) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* strange/corrupt input: best to assume it's an empty URI */
	if (!path->s || path->len == 0) {
		pkg_free(msg->path_vec.s);
		memset(&msg->path_vec, 0, sizeof msg->path_vec);
		return 0;
	}

	if (msg->path_vec.s && (msg->path_vec.len >= path->len)) {
		memcpy(msg->path_vec.s, path->s, path->len);
		msg->path_vec.len = path->len;
	} else {
		msg->path_vec.s = pkg_realloc(msg->path_vec.s, path->len);
		if (!msg->path_vec.s) {
			LM_ERR("not enough pkg memory\n");
			return -1;
		}

		memcpy(msg->path_vec.s, path->s, path->len);
		msg->path_vec.len = path->len;
	}

	return 0;
}


/* convenience macros */
#define LC(_cp) ((*(_cp))|0x20)
#define SET_FOUND(_new_state) \
	do{\
		fill->s=b;fill->len=p-b;\
		LM_DBG("hdr %d extracted as <%.*s>\n",\
			flag,fill->len,fill->s);\
		flags&=~(flag);\
		if (flags) {state=_new_state;}\
		else {goto done;}\
	}while(0)
#define GET_CSEQ() \
	do{\
		for(p++;p<end&&isspace((int)*p);p++);\
		for(fill->s=b;p<end&&isdigit((int)*p);p++);\
		fill->len=p-fill->s;\
		if ( (flags&=~(flag))==0) goto done;\
		state=1;\
	}while(0)
int extract_ftc_hdrs( char *buf, int len, str *from, str *to, str *cseq,str *callid)
{
	char *end, *p;
	char *b;
	str  *fill;
	int state;
	int flags;
	int flag;

	p = buf;
	end = buf+len;
	state = 1;
	b = 0;
	flags = ((from!=0)?0x1:0) | ((to!=0)?0x2:0) | ((cseq!=0)?0x4:0)
				| ((callid!=0)?0x8:0);
	flag = 0;
	fill = 0;

	LM_DBG("flags = %d\n",flags);

	while(p<end) {
		switch (*p) {
			case '\n':
			case '\r':
				switch (state) {
					case 4: state=5;break;
					case 5: case 6: state=6;break;
					default : state=2;break;
				}
				break;
			case ' ':
			case '\t':
				switch (state) {
					case 4: case 6: state=5; break;
					case 2: state=1; break;/*folded line*/
				}
				break;
			case ':':
				switch (state) {
					case 4:case 5: state=5;if(flag==0x04)GET_CSEQ();break;
					case 6: SET_FOUND(1);break;/*found*/
					case 2: state=1;break;
				}
				break;
			case 'f':
			case 'F':
				if (state==5) break;
				if (state==6) SET_FOUND(2);/*found*/;
				if (state!=2) {state = 1;break;}
				/* hdr starting with 'f' */
				if (from==0) break;
				b = p;
				if (p+3<end && LC(p+1)=='r' && LC(p+2)=='o' && LC(p+3)=='m')
					p+=3;
				state = 4; /* "f" or "from" found */
				fill = from;
				flag = 0x1;
				break;
			case 't':
			case 'T':
				if (state==5) break;
				if (state==6) SET_FOUND(2);/*found*/;
				if (state!=2) {state = 1;break;}
				/* hdr starting with 't' */
				if (to==0) break;
				b = p;
				if (p+1<end && LC(p+1)=='o')
					p+=1;
				state = 4; /* "t" or "to" found */
				fill = to;
				flag = 0x2;
				break;
			case 'c':
			case 'C':
				if (state==5) break;
				if (state==6) SET_FOUND(2);/*found*/;
				if (state!=2) {state = 1;break;}
				/* hdr starting with 'c' */
				if (cseq==0 && callid == 0) break;
				if (cseq && p+3<end && LC(p+1)=='s' && LC(p+2)=='e' && LC(p+3)=='q') {
					b = p;
					p+=3;
					state = 4; /* "cseq" found */
					fill = cseq;
					flag = 0x4;
				} else if (callid && p+6<end && LC(p+1)=='a' && LC(p+2) == 'l' &&
					LC(p+3) == 'l' && LC(p+4) == '-' && LC(p+5) == 'i' &&
					LC(p+6) == 'd') {
					b = p;
					p+=6;
					state = 4; /* callid found */
					fill = callid;
					flag = 0x8;
				}
				break;
			case 'I':
			case 'i':
				if (state==5) break;
				if (state==6) SET_FOUND(2);/*found*/;
				if (state!=2) {state = 1;break;}
				if (callid == 0) break;
				b = p;
				state=4; /* callid found */
				fill = callid;
				flag=0x8;
				break;
			default:
				switch (state) {
					case 2:case 4: state=1; break;
					case 6: SET_FOUND(1);break;/*found*/;
				}
		}
		p++;
	}

	LM_CRIT("no hdrs found in outgoing buffer\n");
	return -1;
done:
	return 0;
}


