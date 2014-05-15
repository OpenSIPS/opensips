/*
 * $Id: dlg_tophiding.c $
 *
 * dialog module - basic support for dialog tracking
 *
 * Copyright (C) 2011 Free Software Fundation
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
 *  2011-05-02  initial version (Anca Vamanu)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../data_lump.h"
#include "../tm/tm_load.h"
#include "../../mod_fix.h"
#include "../../parser/contact/parse_contact.h"
#include "dlg_tophiding.h"
#include "dlg_handlers.h"

extern struct tm_binds d_tmb;
extern str rr_param;

extern str topo_hiding_prefix;
extern str topo_hiding_seed;

#define RECORD_ROUTE "Record-Route: "
#define RECORD_ROUTE_LEN (sizeof(RECORD_ROUTE)-1)

int dlg_del_vias(struct sip_msg* req)
{
	struct hdr_field *it;
	char *buf;

	/* parse all headers to be sure that all VIAs are found */
	if (parse_headers(req, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	buf = req->buf;
	it = req->h_via1;
	if(it) {
		/* delete first via1 to set the type (the build_req_buf_from_sip_req will know not to add lump in via1)*/
		if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
			LM_ERR("del_lump failed \n");
			return -1;
		}
		LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		for (it=it->sibling; it; it=it->sibling) {
			if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
				LM_ERR("del_lump failed \n");
				return -1;
			}
			LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		}
	}

	return 0;
}

int dlg_replace_contact(struct sip_msg* msg, struct dlg_cell* dlg)
{
	struct lump* lump, *crt, *prev_crt =0, *a, *foo;
	int offset;
	int len,n;
	char *prefix=NULL,*suffix=NULL,*p,*p_init,*ct_username=NULL;
	int prefix_len,suffix_len,ct_username_len=0;
	struct sip_uri ctu;
	str contact;

	if(!msg->contact)
	{
		if(parse_headers(msg, HDR_CONTACT_F, 0)< 0)
		{
			LM_ERR("Failed to parse headers\n");
			return -1;
		}
		if(!msg->contact)
			return 0;
	}

	prefix_len = 5; /* <sip: */

	if (dlg->flags & DLG_FLAG_TOPH_KEEP_USER) {
		if ( parse_contact(msg->contact)<0 ||
			((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
			((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
				LM_ERR("bad Contact HDR\n");
		} else {
			contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
			if(parse_uri(contact.s, contact.len, &ctu) < 0) {
				LM_ERR("Bad Contact URI \n");
			} else {
				ct_username = ctu.user.s;
				ct_username_len = ctu.user.len;
				LM_DBG("Trying to propagate username [%.*s] \n",ct_username_len,
									ct_username);
				if (ct_username_len > 0)
					prefix_len += 1 + /* @ */ + ct_username_len;
			}
		}
	}

	prefix = pkg_malloc(prefix_len);
	if (!prefix) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	suffix_len = RR_DLG_PARAM_SIZE+1; /* > */
	suffix = pkg_malloc(suffix_len);
	if (!suffix) {
		LM_ERR("no more pkg\n");
		goto error;
	}

	memcpy(prefix,"<sip:",prefix_len);
	if (dlg->flags & DLG_FLAG_TOPH_KEEP_USER && ct_username_len > 0) {
		memcpy(prefix+5,ct_username,ct_username_len);
		prefix[prefix_len-1] = '@';
	}

	p_init = p = suffix;
	*p++ = ';';
	memcpy(p,rr_param.s,rr_param.len);
	p+=rr_param.len;
	*p++ = '=';

	n = RR_DLG_PARAM_SIZE - (p-p_init);
	if (int2reverse_hex( &p, &n, dlg->h_entry)==-1)
		return -1;

	*(p++) = DLG_SEPARATOR;

	n = RR_DLG_PARAM_SIZE - (p-p_init);
	if (int2reverse_hex( &p, &n, dlg->h_id)==-1)
		return -1;

	*p++ = '>';
	suffix_len = p - p_init;

	offset = msg->contact->body.s - msg->buf;
	len = msg->contact->body.len;

	for (crt = msg->add_rm;crt;) {
		if (crt->type == HDR_CONTACT_T && crt->op == LUMP_DEL &&
				crt->u.offset >= offset && crt->u.offset <= offset + len) {
			lump = crt;
			crt = crt->next;
			a=lump->before;
			while(a) {
				LM_DBG("before [%p], op=%d\n", a, a->op);
				if(a->op == LUMP_ADD)
					LM_DBG("value= %.*s\n", a->len, a->u.value);
				foo=a; a=a->before;
				if (!(foo->flags&(LUMPFLAG_DUPED|LUMPFLAG_SHMEM)))
					free_lump(foo);
				if (!(foo->flags&LUMPFLAG_SHMEM))
					pkg_free(foo);
			}

			a=lump->after;
			while(a) {
				LM_DBG("after [%p], op=%d\n", a, a->op);
				if(a->op == LUMP_ADD)
					LM_DBG("value= %.*s\n", a->len, a->u.value);
				foo=a; a=a->after;
				if (!(foo->flags&(LUMPFLAG_DUPED|LUMPFLAG_SHMEM)))
					free_lump(foo);
				if (!(foo->flags&LUMPFLAG_SHMEM))
					pkg_free(foo);
			}
			if(lump == msg->add_rm)
				msg->add_rm = lump->next;
			else
				prev_crt->next = lump->next;
			if (!(lump->flags&(LUMPFLAG_DUPED|LUMPFLAG_SHMEM)))
				free_lump(lump);
			if (!(lump->flags&LUMPFLAG_SHMEM))
				pkg_free(lump);
			continue;
		}
		prev_crt = crt;
		crt= crt->next;
	}

	if ((lump = del_lump(msg, msg->contact->body.s - msg->buf, msg->contact->body.len,HDR_CONTACT_T)) == 0) {
		LM_ERR("del_lump failed \n");
		goto error;
	}

	if ((lump = insert_new_lump_after(lump,prefix,prefix_len,HDR_CONTACT_T)) == 0) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}

	if ((lump = insert_subst_lump_after(lump, SUBST_SND_ALL, HDR_CONTACT_T)) == 0) {
		LM_ERR("failed inserting SUBST_SND buf\n");
		goto error;
	}

	if ((lump = insert_new_lump_after(lump,suffix,suffix_len,HDR_CONTACT_T)) == 0) {
		LM_ERR("failed inserting '<sip:'\n");
		goto error;
	}


	return 0;
error:
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl, struct sip_msg *req,
		int init_req, int dir)
{
	struct hdr_field *it;
	char* buf = rpl->buf;
	int peer_leg;
	struct lump* lmp;
	int size;
	char* route,*p;
	str via_str;
	struct dlg_leg* leg;

	/* parse all headers to be sure that all RR and Contact hdrs are found */
	if (parse_headers(rpl, HDR_EOH_F, 0)< 0) {
		LM_ERR("Failed to parse reply\n");
		return -1;
	}

	/* replace contact */
	if(dlg_replace_contact(rpl, dlg) < 0) {
		LM_ERR("Failed to replace contact\n");
		return -1;
	}

	if(dir == DLG_DIR_UPSTREAM)
		peer_leg = DLG_CALLER_LEG;
	else
		peer_leg = callee_idx(dlg);
	leg = &dlg->legs[peer_leg];

	LM_DBG("peer_leg = %d\n", peer_leg);
	LM_DBG("first RR hdr = %p\n", rpl->record_route);
	/* delete record route */
	for (it=rpl->record_route; it; it=it->sibling) { /* changed here for contact - it was & it->sibling */
		/* skip the one added by this proxy */
		if ((lmp = del_lump(rpl, it->name.s - buf, it->len,HDR_RECORDROUTE_T)) == 0) {
			LM_ERR("del_lump failed \n");
			return -1;
		}
		LM_DBG("Delete record route: [%.*s]\n", it->len, it->name.s);
	}

	LM_DBG("deleted rr stuff\n");
	/* add Via headers */
	lmp = anchor_lump(rpl,rpl->headers->name.s - buf,0);
	if (lmp == 0)
	{
		LM_ERR("failed anchoring new lump\n");
		return -1;
	}

	it = req->h_via1;
	via_str.len = 0;
	while (it) {
		via_str.len += it->len;
		it = it->sibling;
	}

	LM_DBG("via len = %d\n",via_str.len);

	if (via_str.len == 0)
		goto restore_rr;

	via_str.s = pkg_malloc(via_str.len);
	if (!via_str.s) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	LM_DBG("allocated via_str %p\n",via_str.s);

	it = req->h_via1;
	p = via_str.s;
	while (it) {
		memcpy(p,it->name.s,it->len);
		p+=it->len;
		it = it->sibling;
	}

	LM_DBG("inserting via headers - [%.*s]\n",via_str.len,via_str.s);

	if ((lmp = insert_new_lump_after(lmp, via_str.s, via_str.len, 0)) == 0) {
		LM_ERR("failed inserting new old vias\n");
		pkg_free(via_str.s);
		return -1;
	}

restore_rr:
	/* if dialog not confirmed and 200OK for Invite */
	/* pass the record route headers for this leg */
	if(init_req && dir == DLG_DIR_UPSTREAM && leg->route_set.s) {

		/* changed here for contact ( take care to insert the routes after own) */

		/* pass record route headers */
		size = leg->route_set.len + RECORD_ROUTE_LEN + CRLF_LEN;
		route = pkg_malloc(size);
		if (route == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}

		memcpy(route, RECORD_ROUTE, RECORD_ROUTE_LEN);
		memcpy(route+RECORD_ROUTE_LEN, leg->route_set.s, leg->route_set.len);
		memcpy(route+RECORD_ROUTE_LEN+leg->route_set.len, CRLF, CRLF_LEN);

		/* put after Via */
		if ((lmp = insert_new_lump_after(lmp, route, size, HDR_RECORDROUTE_T)) == 0) {
			LM_ERR("failed inserting new route set\n");
			pkg_free(route);
			return -1;
		}
		LM_DBG("Added record route [%.*s]\n", size, route);
	}

	return 0;
}

/* hide via, route sets and contacts */
static int topology_hiding(struct sip_msg *req,int extra_flags)
{
	struct dlg_cell *dlg;
	struct hdr_field *it;
	char* buf;
	struct lump* lump, *crt, *prev_crt =0, *a, *foo;
	struct cell* t;

	t = d_tmb.t_gett();
	if (t == T_UNDEFINED)
		t=NULL;
	dlg = get_current_dialog();
	if(!dlg) {
		if(dlg_create_dialog( t, req, 0) != 0) {
			LM_ERR("Failed to create dialog\n");
			return -1;
		}
		/* double check if the dialog can be retrieved */
		if (!(dlg = get_current_dialog())) {
			LM_ERR("failed to get dialog\n");
			return -1;
		}
	}

	dlg->flags |= DLG_FLAG_TOPHIDING;
	dlg->flags |= extra_flags;

	/* delete also the added record route and the did param */
	for(crt=req->add_rm; crt;) {
		lump = 0;
		if(crt->type != HDR_RECORDROUTE_T)
			/* check on before list for parameters */
			for( lump=crt->before ; lump ; lump=lump->before ) {
				/* we are looking for the lump that adds the
				 * suffix of the RR header */
				if ( lump->type==HDR_RECORDROUTE_T && lump->op==LUMP_ADD)
				{
					LM_DBG("lump before root %p\n", crt);
					LM_DBG("Found lump = %p, %.*s\n", lump, lump->len,lump->u.value);
					break;
				}
			}

		if((crt->type==HDR_RECORDROUTE_T) || lump) {
			/* lump found */
			lump = crt;
			crt = crt->next;
			a=lump->before;
			while(a) {
				LM_DBG("before [%p], op=%d\n", a, a->op);
				if(a->op == LUMP_ADD)
					LM_DBG("value= %.*s\n", a->len, a->u.value);
				foo=a; a=a->before;
				if (!(foo->flags&(LUMPFLAG_DUPED|LUMPFLAG_SHMEM)))
					free_lump(foo);
				if (!(foo->flags&LUMPFLAG_SHMEM))
					pkg_free(foo);
			}

			a=lump->after;
			while(a) {
				LM_DBG("after [%p], op=%d\n", a, a->op);
				if(a->op == LUMP_ADD)
					LM_DBG("value= %.*s\n", a->len, a->u.value);
				foo=a; a=a->after;
				if (!(foo->flags&(LUMPFLAG_DUPED|LUMPFLAG_SHMEM)))
					free_lump(foo);
				if (!(foo->flags&LUMPFLAG_SHMEM))
					pkg_free(foo);
			}
			if(lump == req->add_rm)
				req->add_rm = lump->next;
			else
				prev_crt->next = lump->next;
			if (!(lump->flags&(LUMPFLAG_DUPED|LUMPFLAG_SHMEM)))
				free_lump(lump);
			if (!(lump->flags&LUMPFLAG_SHMEM))
				pkg_free(lump);
//				goto after_del_rr;
//			break;
			continue;
		}
		prev_crt = crt;
		crt= crt->next;
	}

	buf = req->buf;
	/* delete record-route headers */
	for (it=req->record_route;it;it=it->sibling) {
		if (del_lump(req,it->name.s - buf,it->len,HDR_RECORDROUTE_T) == 0) {
			LM_ERR("del_lump failed - while deleting record-route\n");
			return -1;
		}
	}

	/* delete via headers */
	if(dlg_del_vias(req) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return -1;
	}

	/* replace contact*/
	if(dlg_replace_contact(req, dlg) < 0) {
		LM_ERR("Failed to replace contact\n");
		return -1;
	}

	return 1;
}

int w_topology_hiding1(struct sip_msg *req,char *param)
{
	str res = {0,0};
	int flags=0;
	char *p;

	if (fixup_get_svalue(req, (gparam_p)param, &res) !=0)
	{
		LM_ERR("no create dialog flags\n");
		return -1;
	}

	for (p=res.s;p<res.s+res.len;p++)
	{
		switch (*p)
		{
			case 'U':
				flags |= DLG_FLAG_TOPH_KEEP_USER;
				LM_DBG("Will preserve usernames while doing topo hiding \n");
				break;
			case 'C':
				flags |= DLG_FLAG_TOPH_HIDE_CALLID;
				LM_DBG("Will change callid while doing topo hiding \n");
				break;
			default:
				LM_DBG("unknown topology_hiding flag : [%c] . Skipping\n",*p);
		}
	}

	return topology_hiding(req,flags);
}

int w_topology_hiding(struct sip_msg *req)
{
	return topology_hiding(req,0);
}

void dlg_th_down_onreply(struct cell* t, int type,struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, param->req,0, DLG_DIR_DOWNSTREAM) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

void dlg_th_up_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, param->req, 0, DLG_DIR_UPSTREAM) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

int dlg_th_onroute(struct dlg_cell *dlg, struct sip_msg *req, int dir)
{
	struct hdr_field *it;
	char* buf = req->buf;

	/* delete vias */
	if(dlg_del_vias(req) < 0) {
		LM_ERR("Failed to remove via headers\n");
		return -1;
	}

	/* delete record route */
	for (it=req->record_route;it;it=it->sibling) {
		if (del_lump(req, it->name.s - buf, it->len,HDR_RECORDROUTE_T) == 0) {
			LM_ERR("del_lump failed \n");
			return -1;
		}
		LM_DBG("Delete record route: [%.*s]\n", it->len, it->name.s);
	}

	/* add route headers */
	fix_route_dialog(req, dlg);

	/* replace contact*/
	if(dlg_replace_contact(req, dlg) < 0) {
		LM_ERR("Failed to replace contact\n");
		return -1;
	}

	/* register tm callback for response in  */
	ref_dlg( dlg , 1);
	if ( d_tmb.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
			(dir==DLG_DIR_UPSTREAM)?dlg_th_down_onreply:dlg_th_up_onreply,
			(void*)dlg, unreference_dialog)<0 ) {
		LM_ERR("failed to register TMCB\n");
		unref_dlg( dlg , 1);
	}

	if (dir == DLG_DIR_UPSTREAM) {
		/* destination leg is the caller - force the send socket
		 * as the one the caller was inited from */
		req->force_send_socket = dlg->legs[DLG_CALLER_LEG].bind_addr;
		LM_DBG("forcing send socket for req going to caller\n");
	} else {
		/* destination leg is the callee - force the send socket
		 * as the one the callee was inited from */
		req->force_send_socket = dlg->legs[callee_idx(dlg)].bind_addr;
		LM_DBG("forcing send socket for req going to callee\n");
	}

	return 0;
}

int dlg_th_decode_callid(struct sip_msg *msg)
{
	struct lump *del;
	str new_callid;
	int i,max_size;

	if (msg->callid == NULL) {
		LM_ERR("Message with no callid \n");
		return -1;
	}

	max_size = calc_max_base64_decode_len(msg->callid->body.len - topo_hiding_prefix.len);
	new_callid.s = pkg_malloc(max_size);
	if (new_callid.s==NULL) {
		LM_ERR("No more pkg\n");
		return -1;
	}
		
	new_callid.len = base64decode((unsigned char *)(new_callid.s),
			(unsigned char *)(msg->callid->body.s + topo_hiding_prefix.len),
			msg->callid->body.len - topo_hiding_prefix.len);
	for (i=0;i<new_callid.len;i++)
		new_callid.s[i] ^= topo_hiding_seed.s[i%topo_hiding_seed.len]; 

	del=del_lump(msg, msg->callid->body.s-msg->buf, msg->callid->body.len, HDR_CALLID_T);
	if (del==NULL) {               
		LM_ERR("Failed to delete old callid \n");
		pkg_free(new_callid.s);
		return -1;
	}

	if (insert_new_lump_after(del,new_callid.s,new_callid.len,HDR_CALLID_T)==NULL) {
		LM_ERR("Failed to insert new callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	return 0;

	return 0;
}

int dlg_th_encode_callid(struct sip_msg *msg)
{
	struct lump *del;
	str new_callid;
	int i;

	if (msg->callid == NULL) {
		LM_ERR("Message with no callid \n");
		return -1;
	}

	new_callid.len = calc_base64_encode_len(msg->callid->body.len);
	new_callid.len += topo_hiding_prefix.len;
	new_callid.s = pkg_malloc(new_callid.len);
	if (new_callid.s==NULL) {
		LM_ERR("Failed to alocate callid len\n");
		return -1;
	}

	if (new_callid.s == NULL) {
		LM_ERR("Failed to encode callid \n");
		return -1;
	}

	memcpy(new_callid.s,topo_hiding_prefix.s,topo_hiding_prefix.len);
	for (i=0;i<msg->callid->body.len;i++)
		msg->callid->body.s[i] ^= topo_hiding_seed.s[i%topo_hiding_seed.len]; 

	base64encode((unsigned char *)(new_callid.s+topo_hiding_prefix.len),
		     (unsigned char *)(msg->callid->body.s),msg->callid->body.len);

	/* reset the callid back to original value - some might still need it ( eg. post script )
	FIXME : use bigger buffer here ? mem vs cpu */
	for (i=0;i<msg->callid->body.len;i++)
		msg->callid->body.s[i] ^= topo_hiding_seed.s[i%topo_hiding_seed.len]; 

	del=del_lump(msg, msg->callid->body.s-msg->buf, msg->callid->body.len, HDR_CALLID_T);
	if (del==NULL) {               
		LM_ERR("Failed to delete old callid \n");
		pkg_free(new_callid.s);
		return -1;
	}

	if (insert_new_lump_after(del,new_callid.s,new_callid.len,HDR_CALLID_T)==NULL) {
		LM_ERR("Failed to insert new callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	return 0;
}

int dlg_th_needs_decoding(struct sip_msg *msg)
{
	if (msg->callid == NULL) {
		LM_ERR("Message with no callid \n");
		return 0;
	}

	if (memcmp(msg->callid->body.s,topo_hiding_prefix.s,
	topo_hiding_prefix.len) == 0)
		return 1;

	return 0;
}

static inline char *dlg_th_rebuild_req(struct sip_msg *msg,int *len)
{
	return build_req_buf_from_sip_req(msg,(unsigned int*)len,
			NULL,PROTO_NONE,MSG_TRANS_NOVIA_FLAG);
}

static inline char *dlg_th_rebuild_rpl(struct sip_msg *msg,int *len)
{
	return build_res_buf_from_sip_res(msg,(unsigned int*)len,
			NULL,MSG_TRANS_NOVIA_FLAG);
}

#define MSG_SKIP_BITMASK	(METHOD_REGISTER|METHOD_PUBLISH|METHOD_NOTIFY|METHOD_SUBSCRIBE)
int dlg_th_callid_pre_parse(struct sip_msg *msg,int want_from)
{
#ifdef CHANGEABLE_DEBUG_LEVEL
	int prev_dbg_level;
#endif

#ifdef CHANGEABLE_DEBUG_LEVEL
	prev_dbg_level = *debug;
	*debug = L_ALERT; 
#endif

	if (parse_msg(msg->buf,msg->len,msg)!=0) {
		LM_ERR("Invalid SIP msg \n");
		goto error;
	}

	if (parse_headers(msg,HDR_EOH_F,0)<0) {
		LM_ERR("Failed to parse SIP headers\n");
		goto error;
	}

	if (msg->cseq==NULL || get_cseq(msg)==NULL) {
		LM_ERR("Failed to parse CSEQ header \n");
		goto error;
	}       

	if((get_cseq(msg)->method_id)&MSG_SKIP_BITMASK) {
		LM_DBG("Skipping %d for DLG callid topo hiding\n",get_cseq(msg)->method_id);
		goto error;
	}

	if (parse_to_header(msg)<0 || msg->to==NULL || get_to(msg)==NULL) {
		LM_ERR("cannot parse TO header\n");
		goto error;
	}

	if (parse_from_header(msg)<0 || msg->from==NULL || get_from(msg)==NULL) {
		LM_ERR("cannot parse TO header\n");
		goto error;
	}

#ifdef CHANGEABLE_DEBUG_LEVEL
	*debug = prev_dbg_level; 
#endif
	return 0;

error:
#ifdef CHANGEABLE_DEBUG_LEVEL
	*debug = prev_dbg_level; 
#endif
	return -1;
}

int dlg_th_pre_raw(str *data)
{
	struct sip_msg msg;

	memset(&msg,0,sizeof(struct sip_msg));
	msg.buf=data->s;
	msg.len=data->len;
	if (dlg_th_callid_pre_parse(&msg,0) < 0)
		goto done;

	if (msg.first_line.type==SIP_REQUEST) {
		if (get_to(&msg)->tag_value.len>0) {
			/* sequential request, check if callid needs to be unmasked */
			if (dlg_th_needs_decoding(&msg)) {
				if (dlg_th_decode_callid(&msg) < 0) {
					LM_ERR("Failed to decode callid for sequential request \n");
					goto error;
				}
				goto rebuild_msg;
			}	
		} else {
			/* initial request, don't do anything
			callid masking will be done on the out side */
		}
	} else if (msg.first_line.type==SIP_REPLY) {
		/* we might need to decode callid if mangled */
		if (dlg_th_needs_decoding(&msg)) {
			if (dlg_th_decode_callid(&msg) < 0) {
				LM_ERR("Failed to decode callid for reply \n");
				goto error;
			}
			goto rebuild_rpl;
		} else {
			/* encoding will be done on the out side */
		}	
	} else {
		/* non sip, most likely, let it through */
		return 0;
	}

done:
	free_sip_msg(&msg);
	return 0;

rebuild_msg:
	data->s = dlg_th_rebuild_req(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;

rebuild_rpl:
	data->s = dlg_th_rebuild_rpl(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;
error:
	free_sip_msg(&msg);
	return -1;
}

int dlg_th_post_raw(str *data)
{
	struct sip_msg msg;
	struct dlg_cell *dlg; 

	dlg = get_current_dialog(); 
	if (dlg == NULL || (dlg->flags & DLG_FLAG_TOPH_HIDE_CALLID) == 0 ) {
		/* dialog module not involved or not callid topo hiding
		 - let is pass freely */
		return 0;
	}

	memset(&msg,0,sizeof(struct sip_msg));
	msg.buf=data->s;
	msg.len=data->len;
	if (dlg_th_callid_pre_parse(&msg,1) < 0)
		goto done;

	if (msg.first_line.type==SIP_REQUEST) {
		if (get_to(&msg)->tag_value.len>0) {
			/* sequential request, check if callid needs to be unmasked */
			if (get_from(&msg)->tag_value.len != 0) {
				if (memcmp(get_from(&msg)->tag_value.s,
				dlg->legs[0].tag.s,dlg->legs[0].tag.len) == 0) {
					/* request from caller -  need to encode callid */
					if (dlg_th_encode_callid(&msg) < 0) {
						LM_ERR("Failed to mask callid for initial request \n");
						goto error;
					}
					goto rebuild_req;
				} else {
					/* let request go through - was decoded on the in side */
				}
			} else {
				/* no from tag in request - kinda foobar ? - let it through */
				goto done;
			}
		} else {
			/* initial request, mask callid */
			if (dlg_th_encode_callid(&msg) < 0) {
				LM_ERR("Failed to mask callid for initial request \n");
				goto error;
			}
			goto rebuild_req;
		}
	} else if (msg.first_line.type==SIP_REPLY) {
		/* we need to look at the direction */
		if (get_from(&msg)->tag_value.len != 0) {
			if (memcmp(get_from(&msg)->tag_value.s,
			dlg->legs[0].tag.s,dlg->legs[0].tag.len) == 0) {
				/* reply going to caller - 
				decode was done on the receiving end, let it unchanged */
			} else {
				/* reply going to callee , need to encode callid */
				if (dlg_th_encode_callid(&msg) < 0) {
					LM_ERR("Failed to decode callid for reply \n");
					goto error;
				}
				goto rebuild_rpl;
			}
		} else {
			/* no from tag in reply - kinda foobar ? - let it through */
			goto done;
		}
	}

done:
	free_sip_msg(&msg);
	return 0;

rebuild_req:
	data->s = dlg_th_rebuild_req(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;
rebuild_rpl:
	data->s = dlg_th_rebuild_rpl(&msg,&data->len);
	free_sip_msg(&msg);
	return 0;
	
error:
	free_sip_msg(&msg);
	return -1;
}
