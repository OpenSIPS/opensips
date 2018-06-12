#include <string.h>
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../parser/hf.h"
#include "../../dprint.h"
#include "../../parser/parse_uri.h"
#include "../../unixsock_server.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_cseq.h"
#include "../../parser/parse_from.h"
#include "../../ut.h"
#include "uac_unixsock.h"
#include "config.h"
#include "ut.h"
#include "t_hooks.h"
#include "callid.h"
#include "uac.h"
#include "dlg.h"

struct str_list {
	str s;
	struct str_list *next;
};


#define skip_hf(_hf) (             \
    ((_hf)->type == HDR_FROM)   || \
    ((_hf)->type == HDR_TO)     || \
    ((_hf)->type == HDR_CALLID) || \
    ((_hf)->type == HDR_CSEQ)      \
)


static int unixsock_get_method(str* method, str* msg)
{
	if (unixsock_read_line(method, msg) != 0) {
		unixsock_reply_asciiz("400 Method expected");
		unixsock_reply_send();
		return -1;
	}
	DBG("unixsock_get_method: method: '%.*s'\n", method->len, ZSW(method->s));
	return 0;
}


static int unixsock_get_ruri(str* ruri, struct sip_uri* puri, str* msg)
{
	if (unixsock_read_line(ruri, msg) != 0) {
		unixsock_reply_asciiz("400 Request-URI expected");
		unixsock_reply_send();
		return -1;
	}
	
	if (parse_uri(ruri->s, ruri->len, puri) < 0 ) {
		unixsock_reply_asciiz("400 Request-URI is invalid\n");
		unixsock_reply_send();
		return -1;
	}
	DBG("unixsock_get_ruri: '%.*s'\n", ruri->len, ZSW(ruri->s));
	return 0;
}


static int unixsock_get_nexthop(str* nexthop, struct sip_uri* pnexthop, str* msg)
{
	if (unixsock_read_line(nexthop, msg) != 0) {
		unixsock_reply_asciiz("400 Next-hop URI expected\n");
		unixsock_reply_send();
		return -1;
	}

	if (nexthop->len == 1 && nexthop->s[0] == '.' ) {
		DBG("unixsock_get_nexthop: next hop empty\n");
		nexthop->s = 0; 
		nexthop->len = 0;
	} else if (parse_uri(nexthop->s, nexthop->len, pnexthop) < 0 ) {
		unixsock_reply_asciiz("400 Next-hop URI is invalid\n");
		unixsock_reply_send();
		return -1;
	} else {
		DBG("unixsock_get_nexthop: '%.*s'\n", nexthop->len, ZSW(nexthop->s));
	}
	return 0;
}


static int unixsock_get_headers(str* headers, str* msg)
{
	static char headers_buf[MAX_HEADER];

	headers->s = headers_buf;
	headers->len = MAX_HEADER;

	     /* now read and parse header fields */
	if (unixsock_read_lineset(headers, msg) < 0) {
		unixsock_reply_asciiz("400 Header fields expected\n");
		unixsock_reply_send();
		return -1;
	}

	DBG("unixsock_get_headers: %.*s\n", headers->len, ZSW(headers->s));
	return 0;
}


static int unixsock_get_body(str* body, str* msg)
{
	if (unixsock_read_body(body, msg) < 0) {
		unixsock_reply_asciiz("400 Body expected\n");
		unixsock_reply_send();
		return -1;
	}
	DBG("unixsock_get_body: body: %.*s\n", body->len,  ZSW(body->s));
	return 0;
}


/*
 * Make sure that the FIFO user created the message
 * correctly
 */
static int unixsock_check_msg(struct sip_msg* msg, str* method, str* body, 
			      int* fromtag, int *cseq_is, int* cseq, str* callid)
{
	struct to_body* parsed_from;
	struct cseq_body *parsed_cseq;
	int i;
	char c;

	if (body->len && !msg->content_type) {
		unixsock_reply_asciiz("400 Content-Type missing");
		goto err;
	}

	if (body->len && msg->content_length) {
		unixsock_reply_asciiz("400 Content-Length disallowed");
		goto err;
	}

	if (!msg->to) {
		unixsock_reply_asciiz("400 To missing");
		goto err;
	}

	if (!msg->from) {
		unixsock_reply_asciiz("400 From missing");
		goto err;
	}

	     /* we also need to know if there is from-tag and add it otherwise */
	if (parse_from_header(msg) < 0) {
		unixsock_reply_asciiz("400 Error in From");
		goto err;
	}

	parsed_from = (struct to_body*)msg->from->parsed;
	*fromtag = parsed_from->tag_value.s && parsed_from->tag_value.len;

	*cseq = 0;
	if (msg->cseq && (parsed_cseq = get_cseq(msg))) {
		*cseq_is = 1;
		for (i = 0; i < parsed_cseq->number.len; i++) {
			c = parsed_cseq->number.s[i];
			if (c >= '0' && c <= '9' ) *cseq = (*cseq) * 10 + c - '0';
			else {
			        DBG("found non-numerical in CSeq: <%i>='%c'\n",(unsigned int)c,c);
				unixsock_reply_asciiz("400 Non-numberical CSeq");
				goto err;
			}
		}
		
		if (parsed_cseq->method.len != method->len 
		    || memcmp(parsed_cseq->method.s, method->s, method->len) !=0 ) {
			unixsock_reply_asciiz("400 CSeq method mismatch");
			goto err;
		}
	} else {
		*cseq_is = 0;
	}

	if (msg->callid) {
		callid->s = msg->callid->body.s;
		callid->len = msg->callid->body.len;
	} else {
		callid->s = 0;
		callid->len = 0;
	}
	return 0;

 err:
	unixsock_reply_send();
	return -1;
}


static inline struct str_list *new_str(char *s, int len, struct str_list **last, int *total)
{
	struct str_list *new;
	new=pkg_malloc(sizeof(struct str_list));
	if (!new) {
		LOG(L_ERR, "ERROR: get_hfblock: not enough mem\n");
		return 0;
	}
	new->s.s=s;
	new->s.len=len;
	new->next=0;

	(*last)->next=new;
	*last=new;
	*total+=len;

	return new;
}


static char *get_hfblock(str *uri, struct hdr_field *hf, int *l, int proto) 
{
	struct str_list sl, *last, *new, *i, *foo;
	int hf_avail, frag_len, total_len;
	char *begin, *needle, *dst, *ret, *d;
	str *sock_name, *portname;
	union sockaddr_union to_su;
	struct socket_info* send_sock;

	ret=0; /* pesimist: assume failure */
	total_len=0;
	last=&sl;
	last->next=0;
	portname=sock_name=0;

	for (; hf; hf=hf->next) {
		if (skip_hf(hf)) continue;

		begin=needle=hf->name.s; 
		hf_avail=hf->len;

		/* substitution loop */
		while(hf_avail) {
			d=memchr(needle, SUBST_CHAR, hf_avail);
			if (!d || d+1>=needle+hf_avail) { /* nothing to substitute */
				new=new_str(begin, hf_avail, &last, &total_len); 
				if (!new) goto error;
				break;
			} else {
				frag_len=d-begin;
				d++; /* d not at the second substitution char */
				switch(*d) {
					case SUBST_CHAR:	/* double SUBST_CHAR: IP */
						/* string before substitute */
						new=new_str(begin, frag_len, &last, &total_len); 
						if (!new) goto error;
						/* substitute */
						if (!sock_name) {
							send_sock=uri2sock( uri, &to_su, proto );
							if (!send_sock) {
								LOG(L_ERR, "ERROR: get_hf_block: send_sock failed\n");
								goto error;
							}
							sock_name=&send_sock->address_str;
							portname=&send_sock->port_no_str;
						}
						new=new_str(sock_name->s, sock_name->len,
								&last, &total_len );
						if (!new) goto error;
						/* inefficient - FIXME --andrei*/
						new=new_str(":", 1, &last, &total_len);
						if (!new) goto error;
						new=new_str(portname->s, portname->len,
								&last, &total_len );
						if (!new) goto error;
						/* keep going ... */
						begin=needle=d+1;hf_avail-=frag_len+2;
						continue;
					default:
						/* no valid substitution char -- keep going */
						hf_avail-=frag_len+1;
						needle=d;
				}
			} /* possible substitute */
		} /* substitution loop */
		/* proceed to next header */
		/* new=new_str(CRLF, CRLF_LEN, &last, &total_len );
		if (!new) goto error; */
		DBG("DEBUG: get_hf_block: one more hf processed\n");
	} /* header loop */


	/* construct a single header block now */
	ret=pkg_malloc(total_len);
	if (!ret) {
		LOG(L_ERR, "ERROR: get_hf_block no pkg mem for hf block\n");
		goto error;
	}
	i=sl.next;
	dst=ret;
	while(i) {
		foo=i;
		i=i->next;
		memcpy(dst, foo->s.s, foo->s.len);
		dst+=foo->s.len;
		pkg_free(foo);
	}
	*l=total_len;
	return ret;

error:
	i=sl.next;
	while(i) {
		foo=i;
		i=i->next;
		pkg_free(foo);
	}
	*l=0;
	return 0;
}


#define FIFO_ROUTE_PREFIX "Route: "
#define FIFO_ROUTE_SEPARATOR ", "

static void print_routes(dlg_t* _d)
{
	rr_t* ptr;

	ptr = _d->hooks.first_route;

	if (ptr) {
		unixsock_reply_asciiz(FIFO_ROUTE_PREFIX);
	} else {
		unixsock_reply_asciiz(".\n");
		return;
	}

	while(ptr) {
		unixsock_reply_printf("%.*s", ptr->len, ptr->nameaddr.name.s);

		ptr = ptr->next;
		if (ptr) {
			unixsock_reply_asciiz(FIFO_ROUTE_SEPARATOR);
		}
	} 

	if (_d->hooks.last_route) {
		unixsock_reply_asciiz(FIFO_ROUTE_SEPARATOR "<");
		unixsock_reply_printf("%.*s", _d->hooks.last_route->len, _d->hooks.last_route->s);
		unixsock_reply_asciiz(">");
	}

	if (_d->hooks.first_route) {
		unixsock_reply_asciiz(CRLF);
	}
}



static int print_uris(struct sip_msg* reply)
{
	dlg_t* dlg;
	
	dlg = (dlg_t*)shm_malloc(sizeof(dlg_t));
	if (!dlg) {
		LOG(L_ERR, "print_uris(): No memory left\n");
		return -1;
	}

	memset(dlg, 0, sizeof(dlg_t));
	if (dlg_response_uac(dlg, reply) < 0) {
		LOG(L_ERR, "print_uris(): Error while creating dialog structure\n");
		free_dlg(dlg);
		return -2;
	}

	if (dlg->state != DLG_CONFIRMED) {
		unixsock_reply_asciiz(".\n.\n.\n");
		free_dlg(dlg);
		return 0;
	}

	if (dlg->hooks.request_uri->s) {	
		unixsock_reply_printf("%.*s\n", dlg->hooks.request_uri->len, dlg->hooks.request_uri->s);
	} else {
		unixsock_reply_asciiz(".\n");
	}
	if (dlg->hooks.next_hop->s) {
		unixsock_reply_printf("%.*s\n", dlg->hooks.next_hop->len, dlg->hooks.next_hop->s);
	} else {
		unixsock_reply_asciiz(".\n");
	}
	print_routes(dlg);
	free_dlg(dlg);
	return 0;
}

static void unixsock_callback(struct cell *t, int type, struct tmcb_params *ps )
{
	struct sockaddr_un* to;
	str text;

	if (!*ps->param) {
		LOG(L_INFO, "INFO: fifo UAC completed with status %d\n", ps->code);
		return;
	}
	
	to = (struct sockaaddr_un*)(*ps->param);
	unixsock_reply_reset();

	if (ps->rpl == FAKED_REPLY) {
		get_reply_status(&text, ps->rpl, ps->code);
		if (text.s == 0) {
			LOG(L_ERR, "unixsock_callback: get_reply_status failed\n");
			unixsock_reply_asciiz("500 fifo_callback: get_reply_status failed\n");
			goto done;
		}
		unixsock_reply_printf("%.*s\n", text.len, text.s);
		pkg_free(text.s);
	} else {
		text.s = ps->rpl->first_line.u.reply.reason.s;
		text.len = ps->rpl->first_line.u.reply.reason.len;

		     /* FIXME: check for return values here */
		unixsock_reply_printf("%d %.*s\n", ps->rpl->first_line.u.reply.statuscode, text.len, text.s);
		print_uris( ps->rpl);
		unixsock_reply_printf("%s\n", ps->rpl->headers->name.s);
	}
done:
	unixsock_reply_sendto(to);
	shm_free(to);
}



/*
 * Create shm_copy of filename
 */
static int unixsock_cbp(char** dest, struct sockaddr_un* addr)
{
	if (addr) {
		*dest = shm_malloc(sizeof(*addr));
		if (!*dest) {
			unixsock_reply_asciiz("500 No shared memory");
			return -1;
		}
		memcpy(*dest, addr, sizeof(*addr));
	} else {
		*dest = 0;
	}
	return 0;
}


int unixsock_uac(str* msg)
{
	str method, ruri, nexthop, headers, body, hfb, callid;
	struct sip_uri puri, pnexthop;
	struct sip_msg faked_msg;
	int ret, sip_error, err_ret;
	int fromtag, cseq_is, cseq;
	char err_buf[MAX_REASON_LEN];
	char* shm_sockaddr;
	dlg_t dlg;

	if (unixsock_get_method(&method, msg) < 0) return -1;
	if (unixsock_get_ruri(&ruri, &puri, msg) < 0) return -1;
	if (unixsock_get_nexthop(&nexthop, &pnexthop, msg) < 0) return -1;
	if (unixsock_get_headers(&headers, msg) < 0) return -1;

	/* use SIP parser to look at what is in the FIFO request */
	memset(&faked_msg, 0, sizeof(struct sip_msg));
	faked_msg.len = headers.len; 
	faked_msg.buf = faked_msg.unparsed = headers.s;
	if (parse_headers(&faked_msg, HDR_EOH, 0) == -1 ) {
		unixsock_reply_asciiz("400 HFs unparsable\n");
		unixsock_reply_send();
		goto error;
	}

	if (unixsock_get_body(&body, msg) < 0) goto error;
	
	     /* at this moment, we collected all the things we got, let's
	      * verify user has not forgotten something */
	if (unixsock_check_msg(&faked_msg, &method, &body, &fromtag, 
			       &cseq_is, &cseq, &callid) < 0) goto error;

	hfb.s = get_hfblock(nexthop.len ? &nexthop : &ruri, 
			    faked_msg.headers, &hfb.len, PROTO_UDP);
	if (!hfb.s) {
		unixsock_reply_asciiz("500 No memory for HF block");
		unixsock_reply_send();
		goto error;
	}

	memset(&dlg, 0, sizeof(dlg_t));
	     /* Fill in Call-ID, use given Call-ID if
	      * present and generate it if not present
	      */
	if (callid.s && callid.len) dlg.id.call_id = callid;
	else generate_callid(&dlg.id.call_id);
	
	     /* We will not fill in dlg->id.rem_tag because
	      * if present it will be printed within To HF
	      */
	
	     /* Generate fromtag if not present */
	if (!fromtag) {
		generate_fromtag(&dlg.id.loc_tag, &dlg.id.call_id);
	}

	     /* Fill in CSeq */
	if (cseq_is) dlg.loc_seq.value = cseq;
	else dlg.loc_seq.value = DEFAULT_CSEQ;
	dlg.loc_seq.is_set = 1;

	dlg.loc_uri = faked_msg.from->body;
	dlg.rem_uri = faked_msg.to->body;
	dlg.hooks.request_uri = &ruri;
	dlg.hooks.next_hop = (nexthop.len ? &nexthop : &ruri);

	/* we got it all, initiate transaction now! */
	if (unixsock_cbp(&shm_sockaddr, unixsock_sender_addr()) < 0) goto error01;

	ret = t_uac(&method, &hfb, &body, &dlg, unixsock_callback, shm_sockaddr);

	if (ret <= 0) {
		err_ret = err2reason_phrase(ret, &sip_error, err_buf,
			sizeof(err_buf), "FIFO/UAC") ;
		if (err_ret > 0) {
			unixsock_reply_printf("%d %s", sip_error, err_buf);
		} else {
			unixsock_reply_asciiz("500 UNIXSOCK/UAC error");
		}
		unixsock_reply_send();
	}

	return 0;
	
 error01:
	pkg_free(hfb.s);
	
 error:
	     /* free_sip_msg(&faked_msg); */
	if (faked_msg.headers) free_hdr_field_lst(faked_msg.headers);
	return -1;
}
