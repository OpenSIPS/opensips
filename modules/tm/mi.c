/*
 * Header file for TM MI functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
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
 * --------
 *  2006-12-04  created (bogdan)
 */

#include <stdlib.h>
#include "../../parser/parse_from.h"
#include "../../str_list.h"

#include "mi.h"
#include "h_table.h"
#include "t_lookup.h"
#include "t_reply.h"
#include "t_cancel.h"
#include "dlg.h"
#include "callid.h"
#include "uac.h"



#define skip_hf(_hf) \
	(((_hf)->type == HDR_FROM_T)  || \
	((_hf)->type == HDR_TO_T)     || \
	((_hf)->type == HDR_CALLID_T) || \
	((_hf)->type == HDR_CSEQ_T))


/************** Helper functions (from previous FIFO impl) *****************/

/*
 * check if the request pushed via MI is correctly formed
 */
static inline mi_response_t *mi_check_msg(struct sip_msg* msg, str* method,
										str* body, int* cseq, str* callid)
{
	struct cseq_body *parsed_cseq;

	if (body && body->len && !msg->content_type)
		return init_mi_error( 400, MI_SSTR("Content-Type missing"));

	if (body && body->len && msg->content_length)
		return init_mi_error( 400, MI_SSTR("Content-Length disallowed"));

	if (!msg->to)
		return init_mi_error( 400, MI_SSTR("To missing"));

	if (!msg->from)
		return init_mi_error( 400, MI_SSTR("From missing"));

	/* we also need to know if there is from-tag and add it otherwise */
	if (parse_from_header(msg) < 0)
		return init_mi_error( 400, MI_SSTR("Error in From"));

	if (msg->cseq && (parsed_cseq = get_cseq(msg))) {
		if (str2int( &parsed_cseq->number, (unsigned int*)cseq)!=0)
			return init_mi_error( 400, MI_SSTR("Bad CSeq number"));

		if (parsed_cseq->method.len != method->len
		|| memcmp(parsed_cseq->method.s, method->s, method->len) !=0 )
			return init_mi_error( 400, MI_SSTR("CSeq method mismatch"));
	} else {
		*cseq = -1;
	}

	if (msg->callid) {
		callid->s = msg->callid->body.s;
		callid->len = msg->callid->body.len;
	} else {
		callid->s = 0;
		callid->len = 0;
	}

	return 0;
}


static inline str_list *new_str(char *s, int len, str_list **last, int *total)
{
	str_list *new;

	new = pkg_malloc(sizeof *new);
	if (!new) {
		LM_ERR("no more pkg mem\n");
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


static inline char *get_hfblock( str *uri, struct hdr_field *hf, int *l,
											struct socket_info** send_sock)
{
	str_list sl, *last, *new, *i, *foo;
	int hf_avail, frag_len, total_len;
	char *begin, *needle, *dst, *ret, *d;
	str *sock_name, *portname;
	union sockaddr_union to_su;

	ret=0; /* pessimist: assume failure */
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
							if (*send_sock==0){
								*send_sock=uri2sock(0, uri, &to_su,PROTO_NONE);
								if (!*send_sock) {
									LM_ERR("send_sock failed\n");
									goto error;
								}
							}
							sock_name=&(*send_sock)->address_str;
							portname=&(*send_sock)->port_no_str;
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
		LM_DBG("one more hf processed\n");
	} /* header loop */


	/* construct a single header block now */
	ret=pkg_malloc(total_len);
	if (!ret) {
		LM_ERR("no pkg mem for hf block\n");
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


static inline int mi_print_routes(mi_item_t *resp_obj, dlg_t* dlg)
{
	rr_t* ptr;
	mi_item_t *routes_arr;

	ptr = dlg->hooks.first_route;

	if (dlg->hooks.first_route==NULL)
		return 0;

	routes_arr = add_mi_array(resp_obj, MI_SSTR("Routes"));
	if (!routes_arr)
		return -1;

	for( ptr = dlg->hooks.first_route ; ptr ; ptr=ptr->next)
		if (add_mi_string(routes_arr, 0, 0, ptr->nameaddr.name.s, ptr->len) < 0)
			return -1;

	if (dlg->hooks.last_route)
		if (add_mi_string_fmt(routes_arr, 0, 0, "<%.*s>",
			dlg->hooks.last_route->len, dlg->hooks.last_route->s) < 0)
			return -1;

	return 0;
}


static inline int mi_print_uris(mi_item_t *resp_obj, struct sip_msg* reply)
{
	dlg_t* dlg;

	if (reply==0)
		return 0;

	dlg = (dlg_t*)shm_malloc(sizeof(dlg_t));
	if (!dlg) {
		LM_ERR("no shm memory left\n");
		return -1;
	}

	memset(dlg, 0, sizeof(dlg_t));
	if (dlg_response_uac(dlg, reply) < 0) {
		LM_ERR("failed to create dialog\n");
		free_dlg(dlg);
		return -1;
	}

	if (dlg->state != DLG_CONFIRMED) {
		free_dlg(dlg);
		return 0;
	}

	if (dlg->hooks.request_uri->s)
		if (add_mi_string(resp_obj, MI_SSTR("RURI"),
			dlg->hooks.request_uri->s, dlg->hooks.request_uri->len) < 0)
			return -1;

	if (dlg->hooks.next_hop->s)
		if (add_mi_string(resp_obj, MI_SSTR("Next-hop"),
			dlg->hooks.next_hop->s, dlg->hooks.next_hop->len) < 0)
			return -1;

	if (mi_print_routes(resp_obj, dlg) < 0)
		return -1;

	free_dlg(dlg);
	return 0;
}



static void mi_uac_dlg_hdl( struct cell *t, int type, struct tmcb_params *ps )
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	struct mi_handler *mi_hdl;
	str text;

	LM_DBG("MI UAC generated status %d\n", ps->code);
	if (!*ps->param)
		return;

	mi_hdl = (struct mi_handler *)(*ps->param);

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		goto done;

	if (ps->rpl==FAKED_REPLY) {
		get_reply_status( &text, ps->rpl, ps->code);
		if (text.s==0) {
			LM_ERR("get_reply_status failed\n");
			goto error;
		}
		if (add_mi_string(resp_obj, MI_SSTR("Status"),
			text.s, text.len) < 0) {
			goto error;
		}
		pkg_free(text.s);
	} else {
		if (add_mi_string_fmt(resp_obj, MI_SSTR("Status"), "%d %.*s",
			ps->rpl->first_line.u.reply.statuscode,
			ps->rpl->first_line.u.reply.reason.len,
			ps->rpl->first_line.u.reply.reason.s) < 0) {
			goto error;
		}

		if (mi_print_uris(resp_obj, ps->rpl) < 0)
			goto error;

		if (add_mi_string(resp_obj, MI_SSTR("Message"),
			ps->rpl->headers->name.s,
			ps->rpl->len-(ps->rpl->headers->name.s - ps->rpl->buf)) < 0)
			goto error;
	}

	LM_DBG("mi_callback successfully completed\n");
	goto done;

error:
	free_mi_response(resp);
	resp = 0;
done:
	if (ps->code >= 200) {
		mi_hdl->handler_f( resp, mi_hdl, 1 /*done*/ );
		*ps->param = 0;
	} else {
		mi_hdl->handler_f( resp, mi_hdl, 0 );
	}
}



/**************************** MI functions ********************************/


/*
  Syntax of "t_uac_dlg" :
    method
    RURI
    NEXT_HOP
    socket
    headers
    [Body]
*/
static mi_response_t *mi_tm_uac_dlg(const mi_params_t *params, str *nexthop,
						str *socket, str *body, struct mi_handler *async_hdl)
{
	static char err_buf[MAX_REASON_LEN];
	static struct sip_msg tmp_msg;
	static dlg_t dlg;
	struct sip_uri pruri;
	struct sip_uri pnexthop;
	struct socket_info* sock;
	str method;
	str ruri;
	str hdrs;
	str s;
	str callid = {0,0};
	int sip_error;
	int proto = PROTO_NONE;
	int port = 0;
	int cseq = 0;
	int n;
	mi_response_t *resp;

	if (get_mi_string_param(params, "method", &method.s, &method.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "ruri", &ruri.s, &ruri.len) < 0)
		return init_mi_param_error();

	if (parse_uri( ruri.s, ruri.len, &pruri) < 0 )
		return init_mi_error(400, MI_SSTR("Invalid ruri"));

	if (nexthop && parse_uri( nexthop->s, nexthop->len, &pnexthop) < 0 )
		return init_mi_error( 400, MI_SSTR("Invalid next_hop"));

	if (socket && socket->len) {
		if (parse_phostport( socket->s, socket->len, &s.s, &s.len,
		&port,&proto)!=0)
			return init_mi_error( 404, MI_SSTR("Invalid local socket"));
		set_sip_defaults( port, proto);
		sock = grep_internal_sock_info( &s, (unsigned short)port, proto);
		if (sock==0)
			return init_mi_error( 404, MI_SSTR("Local socket not found"));
	} else {
		sock = NULL;
	}

	if (get_mi_string_param(params, "headers", &hdrs.s, &hdrs.len) < 0)
		return init_mi_param_error();

	unescape_crlf(&hdrs);

	/* use SIP parser to look at what is in the FIFO request */
	memset( &tmp_msg, 0, sizeof(struct sip_msg));
	tmp_msg.len = hdrs.len;
	tmp_msg.buf = tmp_msg.unparsed = hdrs.s;
	if (parse_headers( &tmp_msg, HDR_EOH_F, 0) == -1 )
		return init_mi_error( 400, MI_SSTR("Bad headers"));

	/* at this moment, we collected all the things we got, let's
	 * verify user has not forgotten something */
	resp = mi_check_msg( &tmp_msg, &method, body, &cseq, &callid);
	if (resp) {
		if (tmp_msg.headers) free_hdr_field_lst(tmp_msg.headers);
		return resp;
	}

	s.s = get_hfblock( nexthop ? nexthop : &ruri,
			tmp_msg.headers, &s.len, &sock);
	if (s.s==0) {
		if (tmp_msg.headers) free_hdr_field_lst(tmp_msg.headers);
		return 0;
	}

	memset( &dlg, 0, sizeof(dlg_t));
	/* Fill in Call-ID, use given Call-ID if
	 * present and generate it if not present */
	if (callid.s && callid.len)
		dlg.id.call_id = callid;
	else
		generate_callid(&dlg.id.call_id);

	/* We will not fill in dlg->id.rem_tag because
	 * if present it will be printed within To HF */

	/* Generate fromtag if not present */
	if (!(get_from(&tmp_msg)->tag_value.len&&get_from(&tmp_msg)->tag_value.s))
		generate_fromtag(&dlg.id.loc_tag, &dlg.id.call_id);

	/* Fill in CSeq */
	if (cseq!=-1)
		dlg.loc_seq.value = cseq;
	else
		dlg.loc_seq.value = DEFAULT_CSEQ;
	dlg.loc_seq.is_set = 1;

	if (get_from(&tmp_msg)->tag_value.len!=0)
		dlg.id.loc_tag = get_from(&tmp_msg)->tag_value;
	if (get_to(&tmp_msg)->tag_value.len!=0)
		dlg.id.rem_tag = get_to(&tmp_msg)->tag_value;
	dlg.loc_uri = get_from(&tmp_msg)->uri;
	dlg.rem_uri = get_to(&tmp_msg)->uri;
	dlg.loc_dname = get_from(&tmp_msg)->display;
	dlg.rem_dname = get_to(&tmp_msg)->display;
	dlg.hooks.request_uri = &ruri;
	dlg.hooks.next_hop = (nexthop ? nexthop : &ruri);
	dlg.send_sock = sock;

	if (async_hdl==NULL)
		n = t_uac( &method, &s, body, &dlg, 0, 0, 0);
	else
		n = t_uac( &method, &s, body, &dlg, mi_uac_dlg_hdl,
				(void*)async_hdl, 0);

	pkg_free(s.s);
	if (tmp_msg.headers) free_hdr_field_lst(tmp_msg.headers);

	if (n<=0) {
		/* error */
		n = err2reason_phrase( n, &sip_error, err_buf, sizeof(err_buf), "MI/UAC");
		if (n > 0 )
			return init_mi_error(sip_error, err_buf, n);
		else
			return init_mi_error(500, MI_SSTR("MI/UAC failed"));
	} else {
		if (async_hdl==NULL)
			return init_mi_result_string(MI_SSTR("Accepted"));
		else
			return MI_ASYNC_RPL;
	}
}

mi_response_t *mi_tm_uac_dlg_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_tm_uac_dlg(params, NULL, NULL, NULL, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str nexthop;

	if (get_mi_string_param(params, "next_hop", &nexthop.s, &nexthop.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, &nexthop, NULL, NULL, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str socket;

	if (get_mi_string_param(params, "socket", &socket.s, &socket.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, NULL, &socket, NULL, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str body;

	if (get_mi_string_param(params, "body", &body.s, &body.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, NULL, NULL, &body, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_5(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str nexthop, socket;

	if (get_mi_string_param(params, "next_hop", &nexthop.s, &nexthop.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "socket", &socket.s, &socket.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, &nexthop, &socket, NULL, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_6(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str nexthop, body;

	if (get_mi_string_param(params, "next_hop", &nexthop.s, &nexthop.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "body", &body.s, &body.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, &nexthop, NULL, &body, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_7(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str socket, body;

	if (get_mi_string_param(params, "socket", &socket.s, &socket.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "body", &body.s, &body.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, NULL, &socket, &body, async_hdl);
}

mi_response_t *mi_tm_uac_dlg_8(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str nexthop, socket, body;

	if (get_mi_string_param(params, "next_hop", &nexthop.s, &nexthop.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "socket", &socket.s, &socket.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "body", &body.s, &body.len) < 0)
		return init_mi_param_error();

	return mi_tm_uac_dlg(params, &nexthop, &socket, &body, async_hdl);
}

/*
  Syntax of "t_uac_cancel" :
    callid
    cseq
*/
mi_response_t *mi_tm_cancel(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct cell *trans;
	str callid, cseq;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "cseq", &cseq.s, &cseq.len) < 0)
		return init_mi_param_error();

	if( t_lookup_callid( &trans, callid, cseq) < 0 )
		return init_mi_error( 481, MI_SSTR("No such transaction"));

	/* cancel the call */
	LM_DBG("cancelling transaction %p\n",trans);

	cancel_uacs( trans, ~0/*all branches*/);

	UNREF(trans);

	return init_mi_result_ok();
}


/*
  Syntax of "t_hash" :
    no nodes
*/
mi_response_t *mi_tm_hash(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_arr, *resp_item;
	struct s_table* tm_t;
	int i;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	tm_t = get_tm_table();

	for (i=0; i<TM_TABLE_ENTRIES; i++) {
		resp_item = add_mi_object(resp_arr, NULL, 0);
		if (!resp_item)
			goto error;

		if (add_mi_number(resp_item, MI_SSTR("index"), i) < 0)
			goto error;

		if (add_mi_number(resp_item, MI_SSTR("Current"),
			tm_t->entrys[i].cur_entries) < 0)
			goto error;
		if (add_mi_number(resp_item, MI_SSTR("Total"),
			tm_t->entrys[i].acc_entries) < 0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return init_mi_error(500, MI_SSTR("Internal error"));
}


/*
  Syntax of "t_reply" :
  code
  reason
  trans_id
  to_tag
  new headers
  [Body]
*/
mi_response_t *mi_tm_reply(const mi_params_t *params, str *new_hdrs, str *body)
{
	unsigned int hash_index;
	unsigned int hash_label;
	int rpl_code;
	struct cell *trans;
	str reason;
	str totag;
	str tmp, trans_id;
	char *p;
	int n;

	/* get all info from the command */

	if (get_mi_int_param(params, "code", &rpl_code) < 0)
		return init_mi_param_error();
	if (rpl_code>=700)
		return init_mi_error(400, MI_SSTR("Invalid reply code"));

	if (get_mi_string_param(params, "reason", &reason.s, &reason.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "trans_id", &trans_id.s, &trans_id.len) < 0)
		return init_mi_param_error();

	tmp = trans_id;
	p = memchr( tmp.s, ':', tmp.len);
	if ( p==NULL)
		return init_mi_error(400, MI_SSTR("Invalid trans_id"));

	tmp.len = p-tmp.s;
	if( str2int( &tmp, &hash_index)!=0 )
		return init_mi_error(400, MI_SSTR("Invalid index in trans_id"));

	tmp.s = p+1;
	tmp.len = (trans_id.s+trans_id.len) - tmp.s;
	if( str2int( &tmp, &hash_label)!=0 )
		return init_mi_error(400, MI_SSTR("Invalid label in trans_id"));

	if( t_lookup_ident( &trans, hash_index, hash_label)<0 )
		return init_mi_error(404, MI_SSTR("Transaction not found"));

	if (get_mi_string_param(params, "to_tag", &totag.s, &totag.len) < 0)
		return init_mi_param_error();

	n = t_reply_with_body( trans, rpl_code, &reason, body, new_hdrs, &totag);

	UNREF(trans);

	if (n<0)
		return init_mi_error(500, MI_SSTR("Reply failed"));

	return init_mi_result_ok();
}

mi_response_t *mi_tm_reply_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_tm_reply(params, NULL, NULL);
}

mi_response_t *mi_tm_reply_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str new_headers;

	if (get_mi_string_param(params, "new_headers",
		&new_headers.s, &new_headers.len) < 0)
		return init_mi_param_error();

	return mi_tm_reply(params, &new_headers, NULL);
}

mi_response_t *mi_tm_reply_3(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str body;

	if (get_mi_string_param(params, "body", &body.s, &body.len) < 0)
		return init_mi_param_error();

	return mi_tm_reply(params, NULL, &body);
}

mi_response_t *mi_tm_reply_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str new_headers;
	str body;

	if (get_mi_string_param(params, "new_headers",
		&new_headers.s, &new_headers.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "body", &body.s, &body.len) < 0)
		return init_mi_param_error();

	return mi_tm_reply(params, &new_headers, &body);
}
