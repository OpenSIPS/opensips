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
	/* make sure we do not free this string in case of a further error */
	prefix = NULL;

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
	lmp = anchor_lump(rpl,rpl->headers->name.s - buf,0,0);
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
