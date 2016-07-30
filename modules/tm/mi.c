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
#include "mi.h"
#include "h_table.h"
#include "t_lookup.h"
#include "t_reply.h"
#include "t_cancel.h"
#include "dlg.h"
#include "callid.h"
#include "uac.h"


struct str_list {
	str s;
	struct str_list *next;
};


#define skip_hf(_hf) \
	(((_hf)->type == HDR_FROM_T)  || \
	((_hf)->type == HDR_TO_T)     || \
	((_hf)->type == HDR_CALLID_T) || \
	((_hf)->type == HDR_CSEQ_T))


/************** Helper functions (from previous FIFO impl) *****************/

/*
 * check if the request pushed via MI is correctly formed
 */
static inline struct mi_root* mi_check_msg(struct sip_msg* msg, str* method,
										str* body, int* cseq, str* callid)
{
	struct cseq_body *parsed_cseq;

	if (body && body->len && !msg->content_type)
		return init_mi_tree( 400, MI_SSTR("Content-Type missing"));

	if (body && body->len && msg->content_length)
		return init_mi_tree( 400, MI_SSTR("Content-Length disallowed"));

	if (!msg->to)
		return init_mi_tree( 400, MI_SSTR("To missing"));

	if (!msg->from)
		return init_mi_tree( 400, MI_SSTR("From missing"));

	/* we also need to know if there is from-tag and add it otherwise */
	if (parse_from_header(msg) < 0)
		return init_mi_tree( 400, MI_SSTR("Error in From"));

	if (msg->cseq && (parsed_cseq = get_cseq(msg))) {
		if (str2int( &parsed_cseq->number, (unsigned int*)cseq)!=0)
			return init_mi_tree( 400, MI_SSTR("Bad CSeq number"));

		if (parsed_cseq->method.len != method->len
		|| memcmp(parsed_cseq->method.s, method->s, method->len) !=0 )
			return init_mi_tree( 400, MI_SSTR("CSeq method mismatch"));
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


static inline struct str_list *new_str(char *s, int len,
											struct str_list **last, int *total)
{
	struct str_list *new;
	new=pkg_malloc(sizeof(struct str_list));
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
	struct str_list sl, *last, *new, *i, *foo;
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


static inline void mi_print_routes( struct mi_node *node, dlg_t* dlg)
{
#define MI_ROUTE_PREFIX_S       "Route: "
#define MI_ROUTE_PREFIX_LEN     (sizeof(MI_ROUTE_PREFIX_S)-1)
#define MI_ROUTE_SEPARATOR_S    ", "
#define MI_ROUTE_SEPARATOR_LEN  (sizeof(MI_ROUTE_SEPARATOR_S)-1)
	rr_t* ptr;
	int len;
	char *p, *s;

	ptr = dlg->hooks.first_route;

	if (ptr==NULL) {
		add_mi_node_child( node, 0, 0, 0, ".",1);
		return;
	}

	len = MI_ROUTE_PREFIX_LEN;
	for( ; ptr ; ptr=ptr->next)
		len += ptr->len + MI_ROUTE_SEPARATOR_LEN*(ptr->next!=NULL);
	if (dlg->hooks.last_route)
		len += dlg->hooks.last_route->len + 2;


	s = pkg_malloc( len );
	if (s==0) {
		LM_ERR("no more pkg mem\n");
		return;
	}


	p = s;
	memcpy( p, MI_ROUTE_PREFIX_S, MI_ROUTE_PREFIX_LEN);
	p += MI_ROUTE_PREFIX_LEN;

	for( ptr = dlg->hooks.first_route ; ptr ; ptr=ptr->next) {
		memcpy( p, ptr->nameaddr.name.s, ptr->len);
		p += ptr->len;
		if (ptr->next) {
			memcpy( p, MI_ROUTE_SEPARATOR_S, MI_ROUTE_SEPARATOR_LEN);
			p += MI_ROUTE_SEPARATOR_LEN;
		}
	}

	if (dlg->hooks.last_route) {
		*(p++) = '<';
		memcpy( p, dlg->hooks.last_route->s, dlg->hooks.last_route->len);
		p += dlg->hooks.last_route->len;
		*(p++) = '>';
	}

	add_mi_node_child( node, MI_DUP_VALUE, 0, 0, s, len);
	pkg_free(s);
}


static inline int mi_print_uris( struct mi_node *node, struct sip_msg* reply)
{
	dlg_t* dlg;

	if (reply==0)
		goto empty;

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
		goto empty;
	}

	if (dlg->hooks.request_uri->s) {
		add_mi_node_child( node, MI_DUP_VALUE, 0, 0,
			dlg->hooks.request_uri->s, dlg->hooks.request_uri->len);
	} else {
		add_mi_node_child( node, 0, 0, 0, ".",1);
	}
	if (dlg->hooks.next_hop->s) {
		add_mi_node_child( node, MI_DUP_VALUE, 0, 0,
			dlg->hooks.next_hop->s, dlg->hooks.next_hop->len);
	} else {
		add_mi_node_child( node, 0, 0, 0, ".",1);
	}

	mi_print_routes( node, dlg);

	free_dlg(dlg);
	return 0;
empty:
	add_mi_node_child( node, 0, 0, 0, ".",1);
	add_mi_node_child( node, 0, 0, 0, ".",1);
	add_mi_node_child( node, 0, 0, 0, ".",1);
	return 0;
}



static void mi_uac_dlg_hdl( struct cell *t, int type, struct tmcb_params *ps )
{
	struct mi_handler *mi_hdl;
	struct mi_root *rpl_tree;
	str text;

	LM_DBG("MI UAC generated status %d\n", ps->code);
	if (!*ps->param)
		return;

	mi_hdl = (struct mi_handler *)(*ps->param);

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		goto done;

	if (ps->rpl==FAKED_REPLY) {
		get_reply_status( &text, ps->rpl, ps->code);
		if (text.s==0) {
			LM_ERR("get_reply_status failed\n");
			rpl_tree = 0;
			goto done;
		}
		add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE, 0, 0,
			text.s, text.len);
		pkg_free(text.s);
		mi_print_uris( &rpl_tree->node, 0 );
		add_mi_node_child( &rpl_tree->node, 0, 0, 0, ".",1);
	} else {
		addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "%d %.*s",
			ps->rpl->first_line.u.reply.statuscode,
			ps->rpl->first_line.u.reply.reason.len,
			ps->rpl->first_line.u.reply.reason.s);
		mi_print_uris( &rpl_tree->node, ps->rpl);
		add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE, 0, 0,
			ps->rpl->headers->name.s,
			ps->rpl->len-(ps->rpl->headers->name.s - ps->rpl->buf));
	}

	LM_DBG("mi_callback successfully completed\n");
done:
	if (ps->code >= 200) {
		mi_hdl->handler_f( rpl_tree, mi_hdl, 1 /*done*/ );
		*ps->param = 0;
	} else {
		mi_hdl->handler_f( rpl_tree, mi_hdl, 0 );
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
struct mi_root*  mi_tm_uac_dlg(struct mi_root* cmd_tree, void* param)
{
	static char err_buf[MAX_REASON_LEN];
	static struct sip_msg tmp_msg;
	static dlg_t dlg;
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct sip_uri pruri;
	struct sip_uri pnexthop;
	struct socket_info* sock;
	str *method;
	str *ruri;
	str *nexthop;
	str *socket;
	str *hdrs;
	str *body;
	str s;
	str callid = {0,0};
	int sip_error;
	int proto;
	int port;
	int cseq = 0;
	int n;

	for( n=0,node = cmd_tree->node.kids; n<6 && node ; n++,node=node->next );
	if ( !(n==5 || n==6) || node!=0)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* method name (param 1) */
	node = cmd_tree->node.kids;
	method = &node->value;

	/* RURI (param 2) */
	node = node->next;
	ruri = &node->value;
	if (parse_uri( ruri->s, ruri->len, &pruri) < 0 )
		return init_mi_tree( 400, MI_SSTR("Invalid RURI"));

	/* nexthop RURI (param 3) */
	node = node->next;
	nexthop = &node->value;
	if (nexthop->len==1 && nexthop->s[0]=='.') {
		nexthop = 0;
	} else {
		if (parse_uri( nexthop->s, nexthop->len, &pnexthop) < 0 )
			return init_mi_tree( 400, MI_SSTR("Invalid NEXTHOP"));
	}

	/* socket (param 4) */
	node = node->next;
	socket = &node->value;
	if (socket->len==1 && socket->s[0]=='.' ) {
		sock = 0;
	} else {
		if (parse_phostport( socket->s, socket->len, &s.s, &s.len,
		&port,&proto)!=0)
			return init_mi_tree( 404, MI_SSTR("Invalid local socket"));
		set_sip_defaults( port, proto);
		sock = grep_sock_info( &s, (unsigned short)port, proto);
		if (sock==0)
			return init_mi_tree( 404, MI_SSTR("Local socket not found"));
	}

	/* new headers (param 5) */
	node = node->next;
	if (node->value.len==1 && node->value.s[0]=='.')
		hdrs = 0;
	else {
		hdrs = &node->value;
		/* use SIP parser to look at what is in the FIFO request */
		memset( &tmp_msg, 0, sizeof(struct sip_msg));
		tmp_msg.len = hdrs->len;
		tmp_msg.buf = tmp_msg.unparsed = hdrs->s;
		if (parse_headers( &tmp_msg, HDR_EOH_F, 0) == -1 )
			return init_mi_tree( 400, MI_SSTR("Bad headers"));
	}

	/* body (param 5 - optional) */
	node = node->next;
	if (node)
		body = &node->value;
	else
		body = 0;

	/* at this moment, we collected all the things we got, let's
	 * verify user has not forgotten something */
	rpl_tree = mi_check_msg( &tmp_msg, method, body, &cseq, &callid);
	if (rpl_tree) {
		if (tmp_msg.headers) free_hdr_field_lst(tmp_msg.headers);
		return rpl_tree;
	}

	s.s = get_hfblock( nexthop ? nexthop : ruri,
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
	dlg.hooks.request_uri = ruri;
	dlg.hooks.next_hop = (nexthop ? nexthop : ruri);
	dlg.send_sock = sock;

	if (cmd_tree->async_hdl==NULL)
		n = t_uac( method, &s, body, &dlg, 0, 0, 0);
	else
		n = t_uac( method, &s, body, &dlg, mi_uac_dlg_hdl,
				(void*)cmd_tree->async_hdl, 0);

	pkg_free(s.s);
	if (tmp_msg.headers) free_hdr_field_lst(tmp_msg.headers);

	if (n<=0) {
		/* error */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==0)
			return 0;

		n = err2reason_phrase( n, &sip_error, err_buf, sizeof(err_buf),
			"MI/UAC") ;
		if (n > 0 )
			addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "%d %.*s",
				sip_error, n, err_buf);
		else
			add_mi_node_child( &rpl_tree->node, 0, 0, 0,
				"500 MI/UAC failed", 17);

		return rpl_tree;
	} else {
		if (cmd_tree->async_hdl==NULL)
			return init_mi_tree( 202, MI_SSTR("Accepted"));
		else
			return MI_ROOT_ASYNC_RPL;
	}
}


/*
  Syntax of "t_uac_cancel" :
    callid
    cseq
*/
struct mi_root* mi_tm_cancel(struct mi_root* cmd_tree, void* param)
{
	struct mi_node *node;
	struct cell *trans;

	node =  cmd_tree->node.kids;
	if ( !node || !node->next || node->next->next)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if( t_lookup_callid( &trans, node->value, node->next->value) < 0 )
		return init_mi_tree( 481, MI_SSTR("No such transaction"));

	/* cancel the call */
	LM_DBG("cancelling transaction %p\n",trans);

	cancel_uacs( trans, ~0/*all branches*/);

	UNREF(trans);

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}


/*
  Syntax of "t_hash" :
    no nodes
*/
struct mi_root* mi_tm_hash(struct mi_root* cmd_tree, void* param)
{
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl;
	struct mi_node* node;
	struct mi_attr* attr;
	struct s_table* tm_t;
	char *p;
	int i;
	int len;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==0)
		return 0;
	rpl = &rpl_tree->node;
	tm_t = get_tm_table();

	for (i=0; i<TM_TABLE_ENTRIES; i++) {
		p = int2str((unsigned long)i, &len );
		node = add_mi_node_child(rpl, MI_DUP_VALUE , 0, 0, p, len);
		if(node == NULL)
			goto error;

		p = int2str((unsigned long)tm_t->entrys[i].cur_entries, &len );
		attr = add_mi_attr(node, MI_DUP_VALUE, "Current", 7, p, len );
		if(attr == NULL)
			goto error;

		p = int2str((unsigned long)tm_t->entrys[i].acc_entries, &len );
		attr = add_mi_attr(node, MI_DUP_VALUE, "Total", 5, p, len );
		if(attr == NULL)
			goto error;
	}

	return rpl_tree;
error:
	free_mi_tree(rpl_tree);
	return init_mi_tree( 500, MI_INTERNAL_ERR_S, MI_INTERNAL_ERR_LEN);
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
struct mi_root* mi_tm_reply(struct mi_root* cmd_tree, void* param)
{
	struct mi_node* node;
	unsigned int hash_index;
	unsigned int hash_label;
	unsigned int rpl_code;
	struct cell *trans;
	str *reason;
	str *totag;
	str *new_hdrs;
	str *body;
	str tmp;
	char *p;
	int n;

	for( n=0,node = cmd_tree->node.kids; n<6 && node ; n++,node=node->next );
	if ( !(n==5 || n==6) || node!=0)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* get all info from the command */

	/* reply code (param 1) */
	node = cmd_tree->node.kids;
	if (str2int( &node->value, &rpl_code)!=0 || rpl_code>=700)
		return init_mi_tree( 400, MI_SSTR("Invalid reply code"));

	/* reason text (param 2) */
	node = node->next;
	reason = &node->value;

	/* trans_id (param 3) */
	node = node->next;
	tmp = node->value;
	p = memchr( tmp.s, ':', tmp.len);
	if ( p==NULL)
		return init_mi_tree( 400, MI_SSTR("Invalid trans_id"));

	tmp.len = p-tmp.s;
	if( str2int( &tmp, &hash_index)!=0 )
		return init_mi_tree( 400, MI_SSTR("Invalid index in trans_id"));

	tmp.s = p+1;
	tmp.len = (node->value.s+node->value.len) - tmp.s;
	if( str2int( &tmp, &hash_label)!=0 )
		return init_mi_tree( 400, MI_SSTR("Invalid label in trans_id"));

	if( t_lookup_ident( &trans, hash_index, hash_label)<0 )
		return init_mi_tree( 404, MI_SSTR("Transaction not found"));

	/* to_tag (param 4) */
	node = node->next;
	totag = &node->value;

	/* new headers (param 5) */
	node = node->next;
	if (node->value.len==1 && node->value.s[0]=='.')
		new_hdrs = 0;
	else
		new_hdrs = &node->value;

	/* body (param 5 - optional) */
	node = node->next;
	if (node)
		body = &node->value;
	else
		body = 0;

	n = t_reply_with_body( trans, rpl_code, reason, body, new_hdrs, totag);

	UNREF(trans);

	if (n<0)
		return init_mi_tree( 500, MI_SSTR("Reply failed"));

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}

