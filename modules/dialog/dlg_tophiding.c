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
#include "dlg_tophiding.h"
#include "dlg_handlers.h"

extern struct tm_binds d_tmb;

#define RECORD_ROUTE "Record-Route: "
#define RECORD_ROUTE_LEN (sizeof(RECORD_ROUTE)-1)

int dlg_save_del_vias(struct sip_msg* req, struct dlg_leg* leg)
{
	struct hdr_field *it;
	int size=0;
	char* p, *buf;

	for (it=req->h_via1;it;it=it->sibling)
		size+= it->len;

	if(size > leg->last_vias.len) {
		leg->last_vias.s = (char*)shm_realloc(leg->last_vias.s, size);
		if(leg->last_vias.s == NULL) {
			LM_ERR("no more shared memory\n");
			return -1;
		}
	}

	buf = req->buf;
	p = leg->last_vias.s;
	it = req->h_via1;
	if(it) {
		/* delete first via1 to set the type (the build_req_buf_from_sip_req will know not to add lump in via1)*/
		memcpy(p, it->name.s, it->len);
		p+= it->len;
		if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
			LM_ERR("del_lump failed \n");
			return -1;
		}
		LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		for (it=it->sibling; it; it=it->sibling) {
			memcpy(p, it->name.s, it->len);
			p+= it->len;
			if (del_lump(req,it->name.s - buf,it->len, 0) == 0) {
				LM_ERR("del_lump failed \n");
				return -1;
			}
			LM_DBG("Delete via [%.*s]\n", it->len, it->name.s);
		}
	}

	leg->last_vias.len = size;

	LM_DBG("[leg= %p] last_vias: %.*s\n", leg, size, leg->last_vias.s);
	return 0;
}

int dlg_replace_contact(struct sip_msg* msg, struct dlg_cell* dlg)
{
//	str local_contact;
	struct lump* lump, *crt, *prev_crt =0, *a, *foo;
	int offset;
	int len,n;
	char *prefix=NULL,*suffix=NULL,*p,*p_init;
	int prefix_len,suffix_len;

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
	
	p_init = p = suffix;
	*p++ = ';';
	memcpy(p,"did",3);
	p+=3;
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
	
//	LM_DBG("Replaced contact with [%.*s]\n", local_contact.len, local_contact.s);

	return 0;
error:
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	return -1;
}

int dlg_th_onreply(struct dlg_cell *dlg, struct sip_msg *rpl, int init_req, int dir)
{
	struct hdr_field *it;
	char* buf = rpl->buf;
	int peer_leg;
	struct lump* lmp;
	int size;
	char* route;
	str lv_str;
	struct dlg_leg* leg;

	LM_DBG("start\n");

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

	/* add Via headers */
	lmp = anchor_lump(rpl,rpl->headers->name.s - buf,0,0);
	if (lmp == 0)
	{
		LM_ERR("failed anchoring new lump\n");
		return -1;
	}
	if(pkg_str_dup(&lv_str, &leg->last_vias) < 0) {
		LM_ERR("Failed to duplicate memory\n");
		return 1;
	}
	if ((lmp = insert_new_lump_after(lmp, lv_str.s, lv_str.len, HDR_VIA_T)) == 0) {
		LM_ERR("failed inserting new vias\n");
		pkg_free(lv_str.s);
		return -1;
	}
	LM_DBG("Added Via headers [%.*s] leg=%p\n", lv_str.len, lv_str.s, leg);

	/* if dialog not confirmed and 200OK for Invite */
	/* pass the record route headers for this leg */
	if(init_req && dir == DLG_DIR_UPSTREAM && rpl->first_line.u.reply.statuscode==200
			&& leg->route_set.s) {

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
int w_topology_hiding(struct sip_msg *req)
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
		dlg = get_current_dialog();
	}

	dlg->flags |= DLG_FLAG_TOPHIDING;

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

	/* save also via headers */
	if(dlg_save_del_vias(req, &dlg->legs[DLG_CALLER_LEG]) < 0) {
		LM_ERR("Failed to save and remove via headers\n");
		return -1;
	}

	/* replace contact*/
	if(dlg_replace_contact(req, dlg) < 0) {
		LM_ERR("Failed to replace contact\n");
		return -1;
	}

	return 1;
}

void dlg_th_down_onreply(struct cell* t, int type,struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, 0, DLG_DIR_DOWNSTREAM) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

void dlg_th_up_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (dlg==0)
		return;

	if(dlg_th_onreply(dlg, param->rpl, 0, DLG_DIR_UPSTREAM) < 0)
		LM_ERR("Failed to transform the reply for topology hiding\n");
}

int dlg_th_onroute(struct dlg_cell *dlg, struct sip_msg *req, int dir)
{
	struct hdr_field *it;
	char* buf = req->buf;
	int leg_id;

	if(dir == DLG_DIR_UPSTREAM)
		leg_id = callee_idx(dlg);
	else
		leg_id = DLG_CALLER_LEG;

	/* delete vias */
	if(dlg_save_del_vias(req, &dlg->legs[leg_id]) < 0) {
		LM_ERR("Failed to save and remove via headers\n");
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

	return 0;
}
