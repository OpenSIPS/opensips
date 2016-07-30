/*
 * message printing
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
 *
 * History:
 * ----------
 * 2003-01-27  next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2003-02-13  build_uac_request uses proto (andrei)
 * 2003-02-28  scratchpad compatibility abandoned (jiri)
 * 2003-04-14  build_local no longer checks reply status as it
 *             is now called before reply status is updated to
 *             avoid late ACK sending (jiri)
 * 2003-10-02  added via_builder set host/port support (andrei)
 * 2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 * 2004-02-13  t->is_invite and t->local replaced with flags (bogdan)
 * 2008-04-04 added support for local and remote dispaly name in TM dialogs
 *            (by Andrei Pisau <andrei.pisau at voice-system dot ro> )
 */

#include "../../hash_func.h"
#include "../../dprint.h"
#include "../../parser/parser_f.h"
#include "../../ut.h"
#include "../../parser/msg_parser.h"
#include "../../parser/contact/parse_contact.h"
#include "t_funcs.h"
#include "t_msgbuilder.h"
#include "uac.h"


#define ROUTE_PREFIX "Route: "
#define ROUTE_PREFIX_LEN (sizeof(ROUTE_PREFIX) - 1)

#define ROUTE_SEPARATOR ", "
#define ROUTE_SEPARATOR_LEN (sizeof(ROUTE_SEPARATOR) - 1)

#define LOCAL_MAXFWD_HEADER "Max-Forwards: " LOCAL_MAXFWD_VALUE CRLF
#define LOCAL_MAXFWD_HEADER_LEN (sizeof(LOCAL_MAXFWD_HEADER) - 1)

/* convenience macros */
#define  append_string(_d,_s,_len) \
	do{\
		memcpy((_d),(_s),(_len));\
		(_d) += (_len);\
	}while(0);


static inline struct hdr_field* extract_parsed_hdrs( char *buf, int len)
{
	char *p;
	static struct sip_msg msg;
	struct hdr_field  *hdr;

	/* skip the first line - not interesting */
	p = eat_line( buf, len);
	if (p>=buf+len)
		return 0;

	memset( &msg, 0, sizeof(struct sip_msg) );
	msg.buf = buf;
	msg.len = len;
	msg.unparsed = p;

	/* as we need all Route headers, we need to parse all headers */
	if (parse_headers( &msg, HDR_EOH_F, 0)==-1)
		goto error;

	hdr = msg.headers;
	msg.headers = 0;

	free_sip_msg( &msg );
	return hdr;
error:
	free_sip_msg( &msg );
	return 0;
}


/* Build a local request based on a previous request; the only
   customers of this function are local ACK and local CANCEL
 */
char *build_local(struct cell *Trans,unsigned int branch,
	str *method, str *extra, struct sip_msg* rpl, unsigned int *len)
{
	char                *cancel_buf, *p, *via;
	unsigned int         via_len;
	struct hdr_field    *buf_hdrs;
	struct hdr_field    *hdr;
	struct sip_msg      *req;
	char branch_buf[MAX_BRANCH_PARAM_LEN];
	str branch_str;
	struct hostport hp;
	str from;
	str to;
	str cseq_n;

	req = Trans->uas.request;
	cseq_n = Trans->cseq_n;
	buf_hdrs = 0;

	if (rpl && rpl!=FAKED_REPLY) {
		/* take from and to hdrs from reply */
		to.s = rpl->to->name.s;
		to.len = rpl->to->len;
		from.s = rpl->from->name.s;
		from.len = rpl->from->len;
		if (req && req->msg_flags&FL_USE_UAC_CSEQ) {
			if ( extract_ftc_hdrs( Trans->uac[branch].request.buffer.s,
				Trans->uac[branch].request.buffer.len,0 ,0 ,
				&cseq_n ,0)!=0 ) {
				LM_ERR("build_local: failed to extract UAC hdrs\n");
				goto error;
			}
		}
	} else {
		to = Trans->to;
		from = Trans->from;
		if (req && req->msg_flags&(FL_USE_UAC_FROM|FL_USE_UAC_TO|FL_USE_UAC_CSEQ)) {
			if ( extract_ftc_hdrs( Trans->uac[branch].request.buffer.s,
				Trans->uac[branch].request.buffer.len,
				(req->msg_flags&FL_USE_UAC_FROM)?&from:0 ,
				(req->msg_flags&FL_USE_UAC_TO)?&to:0 ,
				(req->msg_flags&FL_USE_UAC_CSEQ)?&cseq_n:0 ,0)!=0 ) {
				LM_ERR("build_local: failed to extract UAC hdrs\n");
				goto error;
			}
		}
	}

	LM_DBG("using FROM=<%.*s>, TO=<%.*s>, CSEQ_N=<%.*s>\n",
		from.len,from.s , to.len,to.s , cseq_n.len,cseq_n.s);

	/* method, separators, version  */
	*len=SIP_VERSION_LEN + method->len + 2 /* spaces */ + CRLF_LEN;
	*len+=Trans->uac[branch].uri.len;

	/*via*/
	branch_str.s=branch_buf;
	if (!t_calc_branch(Trans,  branch, branch_str.s, &branch_str.len ))
		goto error;
	set_hostport(&hp, (is_local(Trans))?0:req);
	if (Trans->uac[branch].adv_address.len)
		hp.host = &Trans->uac[branch].adv_address;
	if (Trans->uac[branch].adv_port.len)
		hp.port = &Trans->uac[branch].adv_port;
	via=via_builder(&via_len, Trans->uac[branch].request.dst.send_sock,
		&branch_str, 0, Trans->uac[branch].request.dst.proto, &hp );
	if (!via){
		LM_ERR("no via header got from builder\n");
		goto error;
	}
	*len+= via_len;
	/*headers*/
	*len+=from.len+Trans->callid.len+to.len+cseq_n.len+1+method->len+CRLF_LEN;

	/* copy'n'paste Route headers that were sent out */
	if (!is_local(Trans) &&
	( (req && req->route) || /* at least one route was received*/
	(Trans->uac[branch].path_vec.len!=0)) ) /* path was forced */
	{
		buf_hdrs = extract_parsed_hdrs(Trans->uac[branch].request.buffer.s,
			Trans->uac[branch].request.buffer.len );
		if (buf_hdrs==NULL) {
			LM_ERR("failed to reparse the request buffer\n");
			goto error01;
		}
		for ( hdr=buf_hdrs ; hdr ; hdr=hdr->next )
			if (hdr->type==HDR_ROUTE_T)
				*len+=hdr->len;
	}

	/* User Agent */
	if (server_signature) {
		*len += user_agent_header.len + CRLF_LEN;
	}
	/* Content Length, MaxFwd, EoM */
	*len+=LOCAL_MAXFWD_HEADER_LEN + CONTENT_LENGTH_LEN+1 + (extra?extra->len:0)
		+ (Trans->extra_hdrs.s?Trans->extra_hdrs.len:0) + CRLF_LEN + CRLF_LEN;

	cancel_buf=shm_malloc( *len+1 );
	if (!cancel_buf)
	{
		LM_ERR("no more share memory\n");
		goto error02;
	}
	p = cancel_buf;

	append_string( p, method->s, method->len );
	*(p++) = ' ';
	append_string( p, Trans->uac[branch].uri.s, Trans->uac[branch].uri.len);
	append_string( p, " " SIP_VERSION CRLF, 1+SIP_VERSION_LEN+CRLF_LEN );

	/* insert our via */
	append_string(p,via,via_len);

	/*other headers*/
	append_string( p, from.s, from.len );
	append_string( p, Trans->callid.s, Trans->callid.len );
	append_string( p, to.s, to.len );

	append_string( p, cseq_n.s, cseq_n.len );
	*(p++) = ' ';
	append_string( p, method->s, method->len );
	append_string( p, CRLF LOCAL_MAXFWD_HEADER,
		CRLF_LEN+LOCAL_MAXFWD_HEADER_LEN );

	/* add Route hdrs (if any) */
	for ( hdr=buf_hdrs ; hdr ; hdr=hdr->next )
		if(hdr->type==HDR_ROUTE_T) {
			append_string(p, hdr->name.s, hdr->len );
		}

	if (extra)
		append_string(p, extra->s, extra->len );

	if (Trans->extra_hdrs.s)
		append_string(p, Trans->extra_hdrs.s, Trans->extra_hdrs.len );

	/* User Agent header, Content Length, EoM */
	if (server_signature) {
		append_string(p, user_agent_header.s, user_agent_header.len);
		append_string(p, CRLF CONTENT_LENGTH "0" CRLF CRLF ,
			CRLF_LEN+CONTENT_LENGTH_LEN+1 + CRLF_LEN + CRLF_LEN);
	} else {
		append_string(p, CONTENT_LENGTH "0" CRLF CRLF ,
			CONTENT_LENGTH_LEN+1 + CRLF_LEN + CRLF_LEN);
	}
	*p=0;

	pkg_free(via);
	free_hdr_field_lst(buf_hdrs);
	return cancel_buf;
error02:
	free_hdr_field_lst(buf_hdrs);
error01:
	pkg_free(via);
error:
	return NULL;
}


struct rte {
	rr_t* ptr;
	struct rte* next;
};


static inline void free_rte_list(struct rte* list)
{
	struct rte* ptr;

	while(list) {
		ptr = list;
		list = list->next;
		pkg_free(ptr);
	}
}


static inline int process_routeset(struct sip_msg* msg, str* contact, struct rte** list, str* ruri, str* next_hop)
{
	struct hdr_field* ptr;
	rr_t* p;
	struct rte* t, *head;
	struct sip_uri puri;

	ptr = msg->record_route;
	head = 0;
	while(ptr) {
		if (ptr->type == HDR_RECORDROUTE_T) {
			if (parse_rr(ptr) < 0) {
				LM_ERR("failed to parse Record-Route header\n");
				return -1;
			}

			p = (rr_t*)ptr->parsed;
			while(p) {
				t = (struct rte*)pkg_malloc(sizeof(struct rte));
				if (!t) {
					LM_ERR("no more pkg memory\n");
					free_rte_list(head);
					return -1;
				}
				t->ptr = p;
				t->next = head;
				head = t;
				p = p->next;
			}
		}
		ptr = ptr->next;
	}

	if (head) {
		if (parse_uri(head->ptr->nameaddr.uri.s, head->ptr->nameaddr.uri.len, &puri) < 0) {
			LM_ERR("failed to parse URI\n");
			free_rte_list(head);
			return -1;
		}

		if (puri.lr.s) {
			     /* Next hop is loose router */
			*ruri = *contact;
			*next_hop = head->ptr->nameaddr.uri;
		} else {
			     /* Next hop is strict router */
			*ruri = head->ptr->nameaddr.uri;
			*next_hop = *ruri;
			t = head;
			head = head->next;
			pkg_free(t);
		}
	} else {
		     /* No routes */
		*ruri = *contact;
		*next_hop = *contact;
	}

	*list = head;
	return 0;
}


static inline int calc_routeset_len(struct rte* list, str* contact)
{
	struct rte* ptr;
	int ret;

	if (list || contact) {
		ret = ROUTE_PREFIX_LEN + CRLF_LEN;
	} else {
		return 0;
	}

	ptr = list;
	while(ptr) {
		if (ptr != list) {
			ret += ROUTE_SEPARATOR_LEN;
		}
		ret += ptr->ptr->len;
		ptr = ptr->next;
	}

	if (contact) {
		if (list) ret += ROUTE_SEPARATOR_LEN;
		ret += 2 + contact->len;
	}

	return ret;
}


/*
 * Print the route set
 */
static inline char* print_rs(char* p, struct rte* list, str* contact)
{
	struct rte* ptr;

	if (list || contact) {
		append_string(p, ROUTE_PREFIX, ROUTE_PREFIX_LEN);
	} else {
		return p;
	}

	ptr = list;
	while(ptr) {
		if (ptr != list) {
			append_string(p, ROUTE_SEPARATOR, ROUTE_SEPARATOR_LEN);
		}

		append_string(p, ptr->ptr->nameaddr.name.s, ptr->ptr->len);
		ptr = ptr->next;
	}

	if (contact) {
		if (list) append_string(p, ROUTE_SEPARATOR, ROUTE_SEPARATOR_LEN);
		*p++ = '<';
		append_string(p, contact->s, contact->len);
		*p++ = '>';
	}

	append_string(p, CRLF, CRLF_LEN);
	return p;
}


/*
 * Parse Contact header field body and extract URI
 * Does not parse headers !
 */
static inline int get_contact_uri(struct sip_msg* msg, str* uri)
{
	contact_t* c;

	uri->len = 0;
	if (!msg->contact) return 1;

	if (parse_contact(msg->contact) < 0) {
		LM_ERR("failed to parse Contact body\n");
		return -1;
	}

	c = ((contact_body_t*)msg->contact->parsed)->contacts;

	if (!c) {
		LM_ERR("body or * contact\n");
		return -2;
	}

	*uri = c->uri;
	return 0;
}



/*
 * The function creates an ACK for a local INVITE. If 200 OK, route set
 * will be created and parsed
 */
char *build_dlg_ack(struct sip_msg* rpl, struct cell *Trans,
							unsigned int branch, str* to, unsigned int *len)
{
	char *req_buf, *p, *via;
	unsigned int via_len;
	char branch_buf[MAX_BRANCH_PARAM_LEN];
	int branch_len;
	str branch_str;
	struct hostport hp;
	struct rte* list;
	str contact, ruri, *cont;
	struct socket_info* send_sock;
	str next_hop;


	if (rpl->first_line.u.reply.statuscode < 300 ) {
		/* build e2e ack for 2xx reply -> we need the route set */
		if (get_contact_uri(rpl, &contact) < 0) {
			return 0;
		}

		if (process_routeset(rpl, &contact, &list, &ruri, &next_hop) < 0) {
			return 0;
		}

		if ((contact.s != ruri.s) || (contact.len != ruri.len)) {
			/* contact != ruri means that the next
			 * hop is a strict router, cont will be non-zero
			 * and print_routeset will append it at the end
			 * of the route set
			 */
			cont = &contact;
		} else {
			/* Next hop is a loose router, nothing to append */
			cont = 0;
		}
	} else {
		/* build hop-by-hop ack for negative reply ->
		 * ruri is the same as in INVITE; no route set */
		ruri = Trans->uac[branch].uri;
		cont = 0;
		list = 0;
	}

	/* method, separators, version: "ACK sip:user@domain.org SIP/2.0" */
	*len = SIP_VERSION_LEN + ACK_LEN + 2 /* spaces */ + CRLF_LEN;
	*len += ruri.len;

	/* use same socket as for INVITE -bogdan */
	send_sock = Trans->uac[branch].request.dst.send_sock;

	if (!t_calc_branch(Trans,  branch, branch_buf, &branch_len)) goto error;
	branch_str.s = branch_buf;
	branch_str.len = branch_len;
	set_hostport(&hp, 0);

	/* build via */
	via = via_builder(&via_len, send_sock, &branch_str, 0,
			send_sock->proto, &hp);
	if (!via) {
		LM_ERR("no via header got from builder\n");
		goto error;
	}
	*len+= via_len;

	/*headers*/
	*len += Trans->from.len + Trans->callid.len + to->len +
		Trans->cseq_n.len + 1 + ACK_LEN + CRLF_LEN + LOCAL_MAXFWD_HEADER_LEN;

	/* copy'n'paste Route headers */
	*len += calc_routeset_len(list, cont);

	/* User Agent */
	if (server_signature)
		*len += user_agent_header.len + CRLF_LEN;

	/* Content Length, EoM */
	*len += CONTENT_LENGTH_LEN + 1 + CRLF_LEN + CRLF_LEN;

	req_buf = shm_malloc(*len + 1);
	if (!req_buf) {
		LM_ERR("no more share memory\n");
		goto error01;
	}
	p = req_buf;

	append_string( p, ACK " ", ACK_LEN+1 );
	append_string(p, ruri.s, ruri.len );
	append_string( p, " " SIP_VERSION CRLF, 1 + SIP_VERSION_LEN + CRLF_LEN);

	/* insert our via */
	append_string(p, via, via_len);

	/*other headers*/
	append_string(p, Trans->from.s, Trans->from.len);
	append_string(p, Trans->callid.s, Trans->callid.len);
	append_string(p, to->s, to->len);

	append_string(p, Trans->cseq_n.s, Trans->cseq_n.len);
	*(p++) = ' ';
	append_string( p, ACK CRLF LOCAL_MAXFWD_HEADER,
		ACK_LEN+CRLF_LEN+LOCAL_MAXFWD_HEADER_LEN );

	/* Routeset */
	p = print_rs(p, list, cont);

	/* User Agent header, Content Length, EoM */
	if (server_signature) {
		append_string(p, user_agent_header.s, user_agent_header.len);
		append_string(p, CRLF CONTENT_LENGTH "0" CRLF CRLF,
			CRLF_LEN+CONTENT_LENGTH_LEN + 1 + CRLF_LEN + CRLF_LEN);
	} else {
		append_string(p, CONTENT_LENGTH "0" CRLF CRLF,
			CONTENT_LENGTH_LEN + 1 + CRLF_LEN + CRLF_LEN);
	}
	*p = 0;

	pkg_free(via);
	free_rte_list(list);
	return req_buf;
error01:
	pkg_free(via);
error:
	free_rte_list(list);
	return 0;
}


/*
 * Convert length of body into asciiz
 */
static inline int print_content_length(str* dest, str* body)
{
	static char content_length[INT2STR_MAX_LEN];
	int len;

	/* Print Content-Length */
	if (body && body->len) {
		dest->s = int2bstr(body->len, content_length, &len);
		dest->len = len;
	} else {
		dest->s = "0";
		dest->len = 1;
	}
	return 0;
}


/*
 * Convert CSeq number into asciiz
 */
static inline int print_cseq_num(str* _s, dlg_t* _d)
{
	static char cseq[INT2STR_MAX_LEN];
	int len;

	_s->s = int2bstr(_d->loc_seq.value, cseq, &len);
	_s->len = len;
	return 0;
}


/*
 * Create Via header
 */
static inline int assemble_via(str* dest, struct cell* t, struct socket_info* sock, int branch)
{
	static char branch_buf[MAX_BRANCH_PARAM_LEN];
	char* via;
	int len;
	unsigned int via_len;
	str branch_str;
	struct hostport hp;

	if (!t_calc_branch(t, branch, branch_buf, &len)) {
		LM_ERR("branch calculation failed\n");
		return -1;
	}

	branch_str.s = branch_buf;
	branch_str.len = len;

#ifdef XL_DEBUG
	printf("!!!proto: %d\n", sock->proto);
#endif

	set_hostport(&hp, 0);
	via = via_builder(&via_len, sock, &branch_str, 0, sock->proto, &hp);
	if (!via) {
		LM_ERR("via building failed\n");
		return -2;
	}

	dest->s = via;
	dest->len = via_len;
	return 0;
}


/*
 * Print Request-URI
 */
static inline char* print_request_uri(char* w, str* method, dlg_t* dialog, struct cell* t, int branch)
{
	append_string(w, method->s, method->len);
	*(w++) = ' ';

	t->uac[branch].uri.s = w;
	t->uac[branch].uri.len = dialog->hooks.request_uri->len;

	append_string(w, dialog->hooks.request_uri->s, dialog->hooks.request_uri->len);
	append_string(w, " " SIP_VERSION CRLF, 1 + SIP_VERSION_LEN + CRLF_LEN);
	LM_DBG("%.*s\n",dialog->hooks.request_uri->len, dialog->hooks.request_uri->s );
	return w;
}


/*
 * Print To header field
 */
static inline char* print_to(char* w, dlg_t* dialog, struct cell* t)
{
	t->to.s = w;
	t->to.len = TO_LEN + dialog->rem_uri.len + CRLF_LEN;

	append_string(w, TO, TO_LEN);

	if(dialog->rem_dname.len) {
		t->to.len += dialog->rem_dname.len;
		append_string(w, dialog->rem_dname.s, dialog->rem_dname.len);
		*(w++) = ' ';
	}

	if(dialog->rem_dname.len || dialog->id.rem_tag.len) {
		t->to.len +=1;
		*(w++) = '<';
	}

	append_string(w, dialog->rem_uri.s, dialog->rem_uri.len);

	if(dialog->rem_dname.len || dialog->id.rem_tag.len) {
		t->to.len +=1;
		*(w++) = '>';
	}


	if (dialog->id.rem_tag.len) {
		t->to.len += TOTAG_LEN + dialog->id.rem_tag.len ;
		append_string(w, TOTAG, TOTAG_LEN);
		append_string(w, dialog->id.rem_tag.s, dialog->id.rem_tag.len);
	}

	append_string(w, CRLF, CRLF_LEN);
	return w;
}


/*
 * Print From header field
 */
static inline char* print_from(char* w, dlg_t* dialog, struct cell* t)
{
	t->from.s = w;
	t->from.len = FROM_LEN + dialog->loc_uri.len + CRLF_LEN;

	append_string(w, FROM, FROM_LEN);

	if(dialog->loc_dname.len) {
		t->from.len += dialog->loc_dname.len + 1;
		append_string(w, dialog->loc_dname.s, dialog->loc_dname.len);
		*(w++) = ' ';
	}

	if(dialog->loc_dname.len || dialog->id.loc_tag.len) {
		t->from.len +=1;
		*(w++) = '<';
	}

	append_string(w, dialog->loc_uri.s, dialog->loc_uri.len);

	if(dialog->loc_dname.len || dialog->id.loc_tag.len) {
		t->from.len += 1;
		*(w++) = '>';
	}

	if (dialog->id.loc_tag.len) {
		t->from.len += FROMTAG_LEN + dialog->id.loc_tag.len;
		append_string(w, FROMTAG, FROMTAG_LEN);
		append_string(w, dialog->id.loc_tag.s, dialog->id.loc_tag.len);
	}

	append_string(w, CRLF, CRLF_LEN);
	return w;
}


/*
 * Print CSeq header field
 */
char* print_cseq_mini(char* target, str* cseq, str* method) {
	append_string(target, CSEQ, CSEQ_LEN);
	append_string(target, cseq->s, cseq->len);
	*(target++) = ' ';
	append_string(target, method->s, method->len);
	return target;
}

static inline char* print_cseq(char* w, str* cseq, str* method, struct cell* t)
{
	t->cseq_n.s = w;
	/* don't include method name and CRLF -- subsequent
	 * local requests ACK/CANCEL will add their own */
	t->cseq_n.len = CSEQ_LEN + cseq->len;
	w = print_cseq_mini(w, cseq, method);
	return w;
}

/*
 * Print Call-ID header field
 * created an extra function for pure header field creation
 */
char* print_callid_mini(char* target, str callid) {
	append_string(target, CALLID, CALLID_LEN);
	append_string(target, callid.s, callid.len);
	append_string(target, CRLF, CRLF_LEN);
	return target;
}

static inline char* print_callid(char* w, dlg_t* dialog, struct cell* t)
{
	/* begins with CRLF, not included in t->callid, don`t know why...?!? */
	append_string(w, CRLF, CRLF_LEN);
	t->callid.s = w;
	t->callid.len = CALLID_LEN + dialog->id.call_id.len + CRLF_LEN;

	w = print_callid_mini(w, dialog->id.call_id);
	return w;
}


/*
 * Create a request
 */
char* build_uac_req(str* method, str* headers, str* body, dlg_t* dialog,
										int branch, struct cell *t, int* len)
{
	char* buf, *w;
	str content_length, cseq, via;

	if (!method || !dialog) {
		LM_ERR("inalid parameter value\n");
		return 0;
	}
	if (print_content_length(&content_length, body) < 0) {
		LM_ERR("failed to print content-length\n");
		return 0;
	}
	if (print_cseq_num(&cseq, dialog) < 0) {
		LM_ERR("failed to print CSeq number\n");
		return 0;
	}
	*len = method->len + 1 + dialog->hooks.request_uri->len + 1 +
		SIP_VERSION_LEN + CRLF_LEN;

	if (assemble_via(&via, t, dialog->send_sock, branch) < 0) {
		LM_ERR("failed to assemble Via\n");
		return 0;
	}
	*len += via.len;

	/* To */
	*len += TO_LEN
		+ (dialog->rem_dname.len ? dialog->rem_dname.len+1 : 0)
		+ dialog->rem_uri.len
		+ (dialog->id.rem_tag.len ? TOTAG_LEN + dialog->id.rem_tag.len : 0)
		+ (dialog->rem_dname.len || dialog->id.rem_tag.len ? 2 : 0)
		+ CRLF_LEN;
	/* From */
	*len += FROM_LEN
		+ (dialog->loc_dname.len ? dialog->loc_dname.len+1 : 0)
		+ dialog->loc_uri.len
		+ (dialog->id.loc_tag.len ? FROMTAG_LEN + dialog->id.loc_tag.len : 0)
		+ (dialog->loc_dname.len || dialog->id.loc_tag.len ? 2 : 0)
		+ CRLF_LEN;
	/* Call-ID */
	*len += CALLID_LEN + dialog->id.call_id.len + CRLF_LEN;
	/* CSeq */
	*len += CSEQ_LEN + cseq.len + 1 + method->len + CRLF_LEN;
	/* Route set */
	*len += calculate_routeset_length(dialog);
	/* Max-Forwards */
	*len += LOCAL_MAXFWD_HEADER_LEN;
	/* Content-Length */
	*len += CONTENT_LENGTH_LEN + content_length.len + CRLF_LEN;
	/* Signature */
	*len += (server_signature ? (user_agent_header.len + CRLF_LEN) : 0);
	/* Additional headers */
	*len += (headers ? headers->len : 0);
	/* Message body */
	*len += (body ? body->len : 0);
	/* End of Header */
	*len += CRLF_LEN;

	buf = shm_malloc(*len + 1);
	if (!buf) {
		LM_ERR("no more share memory\n");
		goto error;
	}

	w = buf;

	w = print_request_uri(w, method, dialog, t, branch);  /* Request-URI */
	append_string(w, via.s, via.len);                     /* Top-most Via */
	w = print_to(w, dialog, t);                           /* To */
	w = print_from(w, dialog, t);                         /* From */
	w = print_cseq(w, &cseq, method, t);                  /* CSeq */
	w = print_callid(w, dialog, t);                       /* Call-ID */
	w = print_routeset(w, dialog);                        /* Route set */

	/* Max-Forwards */
	append_string(w, LOCAL_MAXFWD_HEADER, LOCAL_MAXFWD_HEADER_LEN);

	/* Content-Length */
	append_string(w, CONTENT_LENGTH, CONTENT_LENGTH_LEN);
	append_string(w, content_length.s, content_length.len);
	append_string(w, CRLF, CRLF_LEN);

	/* Server signature */
	if (server_signature) {
		append_string(w, user_agent_header.s, user_agent_header.len);
		append_string(w, CRLF, CRLF_LEN);
	}

	/* extra headers (containing CRLF) */
	if (headers)
		append_string(w, headers->s, headers->len);

	/* add CRLF between headers and body */
	append_string(w, CRLF, CRLF_LEN);

	/* add body (if required) */
	if (body)
		append_string(w, body->s, body->len);

#ifdef EXTRA_DEBUG
	if (w-buf != *len ) abort();
#endif

	/* make buffer NULL terminated */
	buf[*len] = 0;

	pkg_free(via.s);
	return buf;

 error:
	pkg_free(via.s);
	return 0;
}


int t_calc_branch(struct cell *t,
	int b, char *branch, int *branch_len)
{
	return syn_branch ?
		branch_builder( t->hash_index,
			t->label, 0,
			b, branch, branch_len )
		: branch_builder( t->hash_index,
			0, t->md5,
			b, branch, branch_len );
}

