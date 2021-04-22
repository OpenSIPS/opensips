/*
 * Copyright (C) 2009-2020 OpenSIPS Solutions
 * Copyright (C) 2006-2009 Voice System SRL
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
 */

#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../hash_func.h"
#include "../../mi/mi.h"
#include "../../route.h"
#include "../../md5utils.h"
#include "../../parser/parse_to.h"
#include "../../parser/contact/parse_contact.h"
#include "../tm/tm_load.h"
#include "../../script_cb.h"
#include "dlg_hash.h"
#include "dlg_profile.h"
#include "dlg_replication.h"
#include "dlg_req_within.h"
#include "dlg_handlers.h"
#include "dlg_db_handler.h"
#include "../../evi/evi_params.h"
#include "../../evi/evi_modules.h"

#define MAX_LDG_LOCKS  2048
#define MIN_LDG_LOCKS  2

/* useful for dialog ref debugging, once -DDBG_DIALOG is enabled */
struct struct_hist_list *dlg_hist;

struct dlg_table *d_table = NULL;
int ctx_dlg_idx = 0;

static inline void raise_state_changed_event(struct dlg_cell *dlg,
						unsigned int ostate, unsigned int nstate);
static str ei_st_ch_name = str_init("E_DLG_STATE_CHANGED");
static evi_params_p event_params;

static str ei_h_entry = str_init("hash_entry");
static str ei_h_id = str_init("hash_id");
static str ei_id = str_init("id");
static str ei_db_id = str_init("db_id");
static str ei_c_id = str_init("callid");
static str ei_from_tag = str_init("from_tag");
static str ei_to_tag = str_init("to_tag");
static str ei_old_state = str_init("old_state");
static str ei_new_state = str_init("new_state");

static event_id_t ei_st_ch_id = EVI_ERROR;

static evi_param_p hentry_p, hid_p, id_p, db_id_p, cid_p, fromt_p, tot_p;
static evi_param_p ostate_p, nstate_p;

int dialog_cleanup( struct sip_msg *msg, void *param )
{
	if (current_processing_ctx && ctx_dialog_get()) {
		unref_dlg( ctx_dialog_get(), 1);
		ctx_dialog_set(NULL);
	}

	return SCB_RUN_ALL;
}



struct dlg_cell *get_current_dialog(void)
{
	struct cell *trans;

	if (current_processing_ctx && ctx_dialog_get()) {
		/* use the processing context */
		return ctx_dialog_get();
	}
	/* look into transaction */
	trans = d_tmb.t_gett();
	if (trans==NULL || trans==T_UNDEFINED) {
		/* no transaction */
		return NULL;
	}
	if (current_processing_ctx && trans->dialog_ctx) {
		/* if we have context, but no dlg info, and we
		   found dlg info into transaction, populate
		   the dialog too */
		ref_dlg((struct dlg_cell*)trans->dialog_ctx, 1);
		ctx_dialog_set(trans->dialog_ctx);
	}
	return (struct dlg_cell*)trans->dialog_ctx;
}



int init_dlg_table(unsigned int size)
{
	unsigned int n;
	unsigned int i;

	d_table = (struct dlg_table*)shm_malloc
		( sizeof(struct dlg_table) + size*sizeof(struct dlg_entry));
	if (d_table==0) {
		LM_ERR("no more shm mem (1)\n");
		goto error0;
	}

#if defined(DBG_STRUCT_HIST) && defined(DBG_DIALOG)
	dlg_hist = shl_init("dialog hist", 10000, 0);
	if (!dlg_hist) {
		LM_ERR("oom\n");
		goto error1;
	}
#endif

	memset( d_table, 0, sizeof(struct dlg_table) );
	d_table->size = size;
	d_table->entries = (struct dlg_entry*)(d_table+1);

	n = (size<MAX_LDG_LOCKS)?size:MAX_LDG_LOCKS;
	for(  ; n>=MIN_LDG_LOCKS ; n-- ) {
		d_table->locks = lock_set_alloc(n);
		if (d_table->locks==0)
			continue;
		if (lock_set_init(d_table->locks)==0) {
			lock_set_dealloc(d_table->locks);
			d_table->locks = 0;
			continue;
		}
		d_table->locks_no = n;
		break;
	}

	if (d_table->locks==0) {
		LM_ERR("unable to allocted at least %d locks for the hash table\n",
			MIN_LDG_LOCKS);
		goto error1;
	}

	for( i=0 ; i<size; i++ ) {
		memset( &(d_table->entries[i]), 0, sizeof(struct dlg_entry) );
		d_table->entries[i].next_id = rand();
		d_table->entries[i].lock_idx = i % d_table->locks_no;
	}

	return 0;
error1:
	shm_free( d_table );
error0:
	return -1;
}

static inline void free_dlg_dlg(struct dlg_cell *dlg)
{
	struct dlg_val *dv;
	unsigned int i;

	if (dlg->cbs.first)
		destroy_dlg_callbacks_list(dlg->cbs.first);
	context_destroy(CONTEXT_DIALOG, context_of(dlg));

	if (dlg->profile_links) {
		destroy_linkers_unsafe(dlg);
		remove_dlg_prof_table(dlg, 1);
	}

	if (dlg->legs) {
		for( i=0 ; i<dlg->legs_no[DLG_LEGS_USED] ; i++) {
			shm_free(dlg->legs[i].tag.s);
			shm_free(dlg->legs[i].r_cseq.s);
			if (dlg->legs[i].inv_cseq.s)
				shm_free(dlg->legs[i].inv_cseq.s);
			if (dlg->legs[i].prev_cseq.s)
				shm_free(dlg->legs[i].prev_cseq.s);
			if (dlg->legs[i].contact.s)
				shm_free(dlg->legs[i].contact.s);
			if (dlg->legs[i].route_set.s)
				shm_free(dlg->legs[i].route_set.s);
			if (dlg->legs[i].adv_contact.s)
				shm_free(dlg->legs[i].adv_contact.s);
			if (dlg->legs[i].from_uri.s)
				shm_free(dlg->legs[i].from_uri.s);
			if (dlg->legs[i].to_uri.s)
				shm_free(dlg->legs[i].to_uri.s);
			if (dlg->legs[i].out_sdp.s)
				shm_free(dlg->legs[i].out_sdp.s);
			if (dlg->legs[i].in_sdp.s)
				shm_free(dlg->legs[i].in_sdp.s);
			if (dlg->legs[i].tmp_out_sdp.s)
				shm_free(dlg->legs[i].tmp_out_sdp.s);
			if (dlg->legs[i].tmp_in_sdp.s)
				shm_free(dlg->legs[i].tmp_in_sdp.s);
		}
		shm_free(dlg->legs);
	}

	while (dlg->vals) {
		dv = dlg->vals;
		dlg->vals = dlg->vals->next;
		shm_free(dv);
	}

	if (dlg->shtag.s)
		shm_free(dlg->shtag.s);

	if (dlg->terminate_reason.s)
		shm_free(dlg->terminate_reason.s);

#ifdef DBG_DIALOG
	sh_log(dlg->hist, DLG_DESTROY, "ref %d", dlg->ref);
	sh_unref(dlg->hist);
	dlg->hist = NULL;
#endif

	shm_free(dlg);
}


void destroy_dlg(struct dlg_cell *dlg)
{
	int ret = 0;

	LM_DBG("destroying dialog %p\n",dlg);

	ret = remove_dlg_timer(&dlg->tl);
	if (ret < 0) {
		LM_CRIT("unable to unlink the timer on dlg %p [%u:%u] "
			"with clid '%.*s' and tags '%.*s' '%.*s'\n",
			dlg, dlg->h_entry, dlg->h_id,
			dlg->callid.len, dlg->callid.s,
			dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
			dlg_leg_print_info( dlg, callee_idx(dlg), tag));
	} else if (ret > 0) {
		LM_DBG("dlg expired or not in list - dlg %p [%u:%u] "
			"with clid '%.*s' and tags '%.*s' '%.*s'\n",
			dlg, dlg->h_entry, dlg->h_id,
			dlg->callid.len, dlg->callid.s,
			dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
			dlg_leg_print_info( dlg, callee_idx(dlg), tag));
	}

	run_dlg_callbacks(DLGCB_DESTROY , dlg, 0, DLG_DIR_NONE, NULL, 0, 1);

	free_dlg_dlg(dlg);
}



void destroy_dlg_table(void)
{
	struct dlg_cell *dlg, *l_dlg;
	unsigned int i;

	if (d_table==0)
		return;

	if (d_table->locks) {
		lock_set_destroy(d_table->locks);
		lock_set_dealloc(d_table->locks);
	}

	for( i=0 ; i<d_table->size; i++ ) {
		dlg = d_table->entries[i].first;
		while (dlg) {
			l_dlg = dlg;
			dlg = dlg->next;
			free_dlg_dlg(l_dlg);
		}

	}

	shm_free(d_table);
	d_table = 0;

	return;
}



struct dlg_cell* build_new_dlg( str *callid, str *from_uri, str *to_uri,
																str *from_tag)
{
	struct dlg_cell *dlg;
	int len;
	char *p;

	len = sizeof(struct dlg_cell) + callid->len + from_uri->len +
		to_uri->len + context_size(CONTEXT_DIALOG);
	dlg = (struct dlg_cell*)shm_malloc( len );
	if (dlg==0) {
		LM_ERR("no more shm mem (%d)\n",len);
		return 0;
	}

	memset(dlg, 0, len);

#if defined(DBG_STRUCT_HIST) && defined(DBG_DIALOG)
	dlg->hist = sh_push(dlg, dlg_hist);
	if (!dlg->hist) {
		LM_ERR("oom\n");
		shm_free(dlg);
		return NULL;
	}
#endif

	dlg->state = DLG_STATE_UNCONFIRMED;

	dlg->h_entry = dlg_hash( callid);

	LM_DBG("new dialog %p (c=%.*s,f=%.*s,t=%.*s,ft=%.*s) on hash %u\n",
		dlg, callid->len,callid->s, from_uri->len, from_uri->s,
		to_uri->len,to_uri->s, from_tag->len, from_tag->s, dlg->h_entry);

	p = (char*)(dlg+1);
	/* dialog context has to be first, otherwise context_of will break */
	p += context_size(CONTEXT_DIALOG);

	dlg->callid.s = p;
	dlg->callid.len = callid->len;
	memcpy( p, callid->s, callid->len);
	p += callid->len;

	dlg->from_uri.s = p;
	dlg->from_uri.len = from_uri->len;
	memcpy( p, from_uri->s, from_uri->len);
	p += from_uri->len;

	dlg->to_uri.s = p;
	dlg->to_uri.len = to_uri->len;
	memcpy( p, to_uri->s, to_uri->len);
	p += to_uri->len;

	return dlg;
}

int dlg_clone_callee_leg(struct dlg_cell *dlg, int cloned_leg_idx)
{
	struct dlg_leg *leg, *src_leg;

	if (ensure_leg_array(dlg->legs_no[DLG_LEGS_USED] + 1, dlg) != 0)
		return -1;
	src_leg = &dlg->legs[cloned_leg_idx];
	leg = &dlg->legs[dlg->legs_no[DLG_LEGS_USED]];

	if (shm_str_dup(&leg->adv_contact, &src_leg->adv_contact) != 0) {
		LM_ERR("oom contact\n");
		return -1;
	}

	if (src_leg->out_sdp.s && shm_str_dup(&leg->out_sdp, &src_leg->out_sdp) != 0) {
		shm_free(leg->adv_contact.s);
		LM_ERR("oom sdp\n");
		return -1;
	}

	return dlg->legs_no[DLG_LEGS_USED]++;
}


static inline int translate_contact_ipport( str *ct, struct socket_info *sock,
																	str *dst)
{
	struct hdr_field ct_hdr;
	struct contact_body *cb;
	contact_t *c;
	struct sip_uri puri;
	str hostport;
	str *send_address_str, *send_port_str;
	char *p;

	/* rely on the fact that the replicated hdr is well formated, so 
	 * skip the hdr name */
	if ((p=q_memchr(ct->s, ':', ct->len))==NULL) {
		LM_ERR("failed find hdr body in "
			"advertised contact <%.*s>\n", ct->len, ct->s);
	}

	memset( &ct_hdr, 0, sizeof(ct_hdr));
	ct_hdr.body.s = p+1;
	ct_hdr.body.len = (ct->s+ct->len)-ct_hdr.body.s;

	if (parse_contact( &ct_hdr )<0 ||
	(cb=(contact_body_t*)ct_hdr.parsed)==NULL ||
	(c=cb->contacts)==NULL || c->next!=NULL ) {
		LM_ERR("failed to parsed or wrong nr of contacts in "
			"advertised contact <%.*s>\n", ct->len, ct->s);
		return -1;
	}

	if (parse_uri( c->uri.s, c->uri.len, &puri)<0) {
		LM_ERR("failed to parsed URI in contact <%.*s>\n",
			c->uri.len, c->uri.s);
		goto error;
	}
	hostport.s = puri.host.s;
	hostport.len = puri.port.len ?
		(puri.port.s+puri.port.len-puri.host.s) :  puri.host.len ;

	LM_DBG("replacing <%.*s> from ct <%.*s>\n",
		hostport.len, hostport.s, ct->len, ct->s);

	/* init send_address_str & send_port_str */
	if(sock->adv_name_str.len)
		send_address_str=&(sock->adv_name_str);
	else if (default_global_address.s)
		send_address_str=&default_global_address;
	else
		send_address_str=&(sock->address_str);
	if(sock->adv_port_str.len)
		send_port_str=&(sock->adv_port_str);
	else if (default_global_port.s)
		send_port_str=&default_global_port;
	else
		send_port_str=&(sock->port_no_str);

	dst->len = (hostport.s - ct->s) +  /* staring preserved part */
		(send_address_str->len + 1 + send_port_str->len) + /*new ip:port part*/
		(ct->s + ct->len - hostport.s - hostport.len);
	dst->s = (char*)shm_malloc( dst->len );
	if (dst->s==NULL) {
		LM_ERR("failed to allocated new host:port, len %d\n",dst->len);
		goto error;
	}

	/* start building the new ct hdr */
	p = dst->s;
	memcpy( p, ct->s, hostport.s - ct->s);
	p += hostport.s - ct->s;

	memcpy( p, send_address_str->s, send_address_str->len);
	p += send_address_str->len;
	*(p++) = ':';
	memcpy( p, send_port_str->s, send_port_str->len);
	p += send_port_str->len;

	memcpy( p, hostport.s+hostport.len, ct->s+ct->len-hostport.s-hostport.len);
	p += ct->s+ct->len-hostport.s-hostport.len;

	LM_DBG("resulting ct is <%.*s> / %d\n",
		dst->len, dst->s, dst->len);

	free_contact( &cb );
	return 0;
error:
	free_contact( &cb );
	return -1;
}


/* first time it will called for a CALLER leg - at that time there will
   be no leg allocated, so automatically CALLER gets the first position, while
   the CALLEE legs will follow into the array in the same order they came */
int dlg_update_leg_info(int leg_idx, struct dlg_cell *dlg, str* tag, str *rr,
		str *contact, str *adv_ct, str *cseq, struct socket_info *sock,
		str *mangled_from,str *mangled_to,str *in_sdp, str *out_sdp)
{
	struct dlg_leg *leg;
	rr_t *head = NULL, *rrp;

	if (leg_idx >= MAX_BRANCHES) {
		LM_WARN("invalid callee leg index (branch id part): %d\n", leg_idx);
		return -1;
	}

	if (ensure_leg_array(leg_idx + 1, dlg) != 0)
		return -1;

	leg = &dlg->legs[leg_idx];

	leg->tag.s = (char*)shm_malloc(tag->len);
	if ( leg->tag.s==NULL) {
		LM_ERR("no more shm mem for tag\n");
		return -1;
	}
	leg->r_cseq.s = (char*)shm_malloc( cseq->len );
	if (leg->r_cseq.s==NULL) {
		LM_ERR("no more shm mem for cseq\n");
		goto error1;
	}

	if (dlg->legs_no[DLG_LEGS_USED] == 0) {
		/* first leg = caller. also store inv cseq */
		leg->inv_cseq.s = (char *)shm_malloc( cseq->len);
		if (leg->inv_cseq.s == NULL) {
			LM_ERR("no more shm mem\n");
			goto error2;
		}
	}

	if (contact->len) {
		/* contact */
		leg->contact.s = shm_malloc(contact->len);
		if (leg->contact.s==NULL) {
			LM_ERR("no more shm mem\n");
			goto error2;
		}
		leg->contact.len = contact->len;
		memcpy( leg->contact.s, contact->s, contact->len);
		/* rr */
		if (rr->len) {
			leg->route_set.s = shm_malloc(rr->len);
			if (leg->route_set.s==NULL) {
				LM_ERR("no more shm mem for rr set\n");
				goto error_all;
			}
			leg->route_set.len = rr->len;
			memcpy(leg->route_set.s, rr->s, rr->len);

			if (parse_rr_body(leg->route_set.s,leg->route_set.len,&head) != 0) {
				LM_ERR("failed parsing route set\n");
				goto error_all;
			}
			rrp = head;
			leg->nr_uris = 0;
			while (rrp) {
				leg->route_uris[leg->nr_uris++] = rrp->nameaddr.uri;
				rrp = rrp->next;
			}
			free_rr(&head);
		}
	}

	/* save mangled FROM/TO URIs, if any */
	if (mangled_from && mangled_from->s && mangled_from->len &&
	shm_str_dup( &leg->from_uri, mangled_from)==-1 ) {
		LM_ERR("failed to shm duplicate mangled FROM hdr\n");
		goto error_all;
	}

	if (mangled_to && mangled_to->s && mangled_to->len &&
	shm_str_dup( &leg->to_uri, mangled_to)==-1 ) {
		LM_ERR("failed to shm duplicate mangled TO hdr\n");
		goto error_all;
	}

	/* these are the inbound/outbound SDPs for this leg */
	if (in_sdp && in_sdp->s && in_sdp->len &&
	shm_str_dup( &leg->in_sdp, in_sdp)==-1 ) {
		LM_ERR("failed to shm duplicate inbound SDP\n");
		goto error_all;
	}

	if (out_sdp && out_sdp->s && out_sdp->len &&
	shm_str_dup( &leg->out_sdp, out_sdp)==-1 ) {
		LM_ERR("failed to shm duplicate outbound SDP\n");
		goto error_all;
	}

	/* this is the advertised contact for this leg */
	if (adv_ct && adv_ct->s && adv_ct->len) {
		/* if the advertised tag is correlated with an interface indetified 
		 * by a TAG, it means that the actual IP of the interface may be
		 * different, so we better re-compute the IP:port part of the contact*/
		if (sock->tag.s) {
			if (translate_contact_ipport(adv_ct,sock, &leg->adv_contact)<0){
				LM_ERR("failed to shm translate advertised contact\n");
				goto error_all;
			}
		} else if (shm_str_dup( &leg->adv_contact, adv_ct)==-1 ) {
			LM_ERR("failed to shm duplicate advertised contact\n");
			goto error_all;
		}
	}

	/* tag */
	leg->tag.len = tag->len;
	memcpy( leg->tag.s, tag->s, tag->len);

	/* socket */
	leg->bind_addr = sock;

	if (dlg->legs_no[DLG_LEGS_USED] == 0)
	{
		/* first leg = caller . store inv cseq */
		leg->inv_cseq.len = cseq->len;
		memcpy(leg->inv_cseq.s,cseq->s,cseq->len);

		/* set cseq for caller to 0
		 * future requests to the caller leg will update this
		 * needed for proper validation of in-dialog requests
		 *
		 * TM also increases this value by one, if dialog
		 * is terminated from the middle, so 0 is ok*/
		leg->r_cseq.len = 1;
		leg->r_cseq.s[0]='0';
	} else {
		/* cseq */
		leg->r_cseq.len = cseq->len;
		memcpy( leg->r_cseq.s, cseq->s, cseq->len);
	}

	/* make leg visible for searchers */
	if (leg_idx >= dlg->legs_no[DLG_LEGS_USED])
		dlg->legs_no[DLG_LEGS_USED] = leg_idx + 1;

	LM_DBG("set leg %d for %p: tag=<%.*s> rcseq=<%.*s>\n",
		dlg->legs_no[DLG_LEGS_USED]-1, dlg,
		leg->tag.len,leg->tag.s,
		leg->r_cseq.len,leg->r_cseq.s );

	return 0;
error_all:
	if (leg->to_uri.s) {
		shm_free(leg->to_uri.s);
		leg->to_uri.s = NULL;
	}
	if (leg->from_uri.s) {
		shm_free(leg->from_uri.s);
		leg->from_uri.s = NULL;
	}
	if (leg->route_set.s) {
		shm_free(leg->route_set.s);
		leg->route_set.s = NULL;
	}
	if (leg->contact.s) {
		shm_free(leg->contact.s);
		leg->contact.s = NULL;
	}

	if (leg->in_sdp.s) {
		shm_free(leg->in_sdp.s);
		leg->in_sdp.s = NULL;
	}
error2:
	shm_free(leg->r_cseq.s);
error1:
	shm_free(leg->tag.s);
	return -1;
}


/* update cseq filed in leg
 * if inv = 1, update the inv_cseq field
 * else, update the r_cseq */
int dlg_update_cseq(struct dlg_cell * dlg, unsigned int leg, str *cseq,int inv)
{
	str* update_cseq;

	if (inv == 1)
		update_cseq = &dlg->legs[leg].inv_cseq;
	else
		update_cseq = &dlg->legs[leg].r_cseq;

	if ( update_cseq->s ) {
		if (update_cseq->len < cseq->len) {
			update_cseq->s = (char*)shm_realloc(update_cseq->s,cseq->len);
			if (update_cseq->s==NULL) {
				LM_ERR("no more shm mem for realloc (%d)\n",cseq->len);
				goto error;
			}
		}
	} else {
		update_cseq->s = (char*)shm_malloc(cseq->len);
		if (update_cseq->s==NULL) {
			LM_ERR("no more shm mem for malloc (%d)\n",cseq->len);
			goto error;
		}
	}

	memcpy( update_cseq->s, cseq->s, cseq->len );
	update_cseq->len = cseq->len;

	if (inv == 1)
		LM_DBG("dlg %p[%d]: last invite cseq is %.*s\n", dlg,leg,
			dlg->legs[leg].inv_cseq.len, dlg->legs[leg].inv_cseq.s);
	else
		LM_DBG("dlg %p[%d]: cseq is %.*s\n", dlg,leg,
			dlg->legs[leg].r_cseq.len, dlg->legs[leg].r_cseq.s);

	return 0;
error:
	LM_ERR("not more shm mem\n");
	return -1;
}



int dlg_update_routing(struct dlg_cell *dlg, unsigned int leg,
	str *rr, str *contact)
{
	rr_t *head = NULL, *rrp;

	LM_DBG("dialog %p[%d]: rr=<%.*s> contact=<%.*s>\n",
		dlg, leg,
		rr->len,rr->s,
		contact->len,contact->s );

	if (dlg->legs[leg].contact.s)
		shm_free(dlg->legs[leg].contact.s);

	dlg->legs[leg].contact.s = shm_malloc(contact->len);
	if (dlg->legs[leg].contact.s==NULL) {
		LM_ERR("no more shm mem\n");
		return -1;
	}
	dlg->legs[leg].contact.len = contact->len;
	memcpy( dlg->legs[leg].contact.s, contact->s, contact->len);
	/* rr */
	if (rr->len) {
		if (dlg->legs[leg].route_set.s)
			shm_free(dlg->legs[leg].route_set.s);
		dlg->legs[leg].route_set.s = shm_malloc(rr->len);
		if (!dlg->legs[leg].route_set.s) {
			LM_ERR("failed to alloc route set!\n");
			/* leave the contact there, otherwise we will get no contact at
			 * all, or worse, we will use free'd memory */
			return -1;
		}
		dlg->legs[leg].route_set.len = rr->len;
		memcpy( dlg->legs[leg].route_set.s, rr->s, rr->len);

		/* also update URI pointers */
		if (parse_rr_body(dlg->legs[leg].route_set.s,
					dlg->legs[leg].route_set.len,&head) != 0) {
			LM_ERR("failed parsing route set\n");
			shm_free(dlg->legs[leg].route_set.s);
			dlg->legs[leg].route_set.s = NULL;
			return -1;
		}
		rrp = head;
		dlg->legs[leg].nr_uris = 0;
		while (rrp) {
			dlg->legs[leg].route_uris[dlg->legs[leg].nr_uris++] = rrp->nameaddr.uri;
			rrp = rrp->next;
		}
		free_rr(&head);
	}

	return 0;
}



struct dlg_cell* lookup_dlg( unsigned int h_entry, unsigned int h_id)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;

	if (h_entry>=d_table->size)
		goto not_found;

	d_entry = &(d_table->entries[h_entry]);

	dlg_lock( d_table, d_entry);

	for( dlg=d_entry->first ; dlg ; dlg=dlg->next ) {
		if (dlg->h_id == h_id) {
			if (dlg->state==DLG_STATE_DELETED) {
				dlg_unlock( d_table, d_entry);
				goto not_found;
			}
			DBG_REF(dlg, 1);
			dlg->ref++;
			dlg_unlock( d_table, d_entry);
			LM_DBG("dialog id=%u found on entry %u\n", h_id, h_entry);
			return dlg;
		}
	}

	dlg_unlock( d_table, d_entry);
not_found:
	LM_DBG("no dialog id=%u found on entry %u\n", h_id, h_entry);
	return 0;
}



/* Get dialog that correspond to CallId, From Tag and To Tag         */
/* See RFC 3261, paragraph 4. Overview of Operation:                 */
/* "The combination of the To tag, From tag, and Call-ID completely  */
/* defines a peer-to-peer SIP relationship between [two UAs] and is  */
/* referred to as a dialog."*/
struct dlg_cell* get_dlg( str *callid, str *ftag, str *ttag,
									unsigned int *dir, unsigned int *dst_leg)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	unsigned int h_entry;

	h_entry = dlg_hash(callid);
	d_entry = &(d_table->entries[h_entry]);

	dlg_lock( d_table, d_entry);

	LM_DBG("input ci=<%.*s>(%d), tt=<%.*s>(%d), ft=<%.*s>(%d)\n",
		callid->len,callid->s, callid->len,
		ftag->len, ftag->s, ftag->len,
		ttag->len, ttag->s, ttag->len);

	for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
		/* Check callid / fromtag / totag */
#ifdef EXTRA_DEBUG
		LM_DBG("DLG (%p)(%d): ci=<%.*s>(%d), ft=<%.*s>(%d), tt=<%.*s>(%d),"
			"ct_er=%d, ct_ee=%d\n",
			dlg,dlg->state,dlg->callid.len,dlg->callid.s, dlg->callid.len,
			dlg->legs[DLG_CALLER_LEG].tag.len,dlg->legs[DLG_CALLER_LEG].tag.s,
				dlg->legs[DLG_CALLER_LEG].tag.len,
			dlg->legs[callee_idx(dlg)].tag.len,dlg->legs[callee_idx(dlg)].tag.s,
				dlg->legs[callee_idx(dlg)].tag.len,
			dlg->legs[DLG_CALLER_LEG].contact.len,
				dlg->legs[DLG_CALLER_LEG].contact.len);
#endif
		if (match_dialog( dlg, callid, ftag, ttag, dir, dst_leg)==1) {
			if (dlg->state==DLG_STATE_DELETED)
				/* even if matched, skip the deleted dialogs as they may be
				   a previous unsuccessful attempt of established call
				   with the same callid and fromtag - like in auth/challenge
				   case -bogdan */
				continue;
			DBG_REF(dlg, 1);
			dlg->ref++;
			dlg_unlock( d_table, d_entry);
			LM_DBG("dialog callid='%.*s' found\n on entry %u, dir=%d\n",
				callid->len, callid->s,h_entry,*dir);
			return dlg;
		}
	}

	dlg_unlock( d_table, d_entry);

	LM_DBG("no dialog callid='%.*s' found\n", callid->len, callid->s);
	return 0;
}


struct dlg_cell* get_dlg_by_val(str *attr, str *val)
{
	struct dlg_entry *d_entry;
	struct dlg_cell  *dlg;
	unsigned int h;

	/* go through all hash entries (entire table) */
	for ( h=0 ; h<d_table->size ; h++ ) {

		d_entry = &(d_table->entries[h]);
		dlg_lock( d_table, d_entry);

		/* go through all dialogs on entry */
		for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
			LM_DBG("dlg in state %d to check\n",dlg->state);
			if ( dlg->state>DLG_STATE_CONFIRMED )
				continue;
			if (check_dlg_value_unsafe( dlg, attr, val)==0) {
				ref_dlg_unsafe( dlg, 1);
				dlg_unlock( d_table, d_entry);
				return dlg;
			}
		}

		dlg_unlock( d_table, d_entry);
	}

	return NULL;
}


struct dlg_cell* get_dlg_by_callid( str *callid, int active_only)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	unsigned int h_entry;

	h_entry = dlg_hash(callid);
	d_entry = &(d_table->entries[h_entry]);

	dlg_lock( d_table, d_entry);

	LM_DBG("input ci=<%.*s>(%d)\n", callid->len,callid->s, callid->len);

	for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
		if ( active_only && dlg->state>DLG_STATE_CONFIRMED )
			continue;
		if ( dlg->callid.len==callid->len &&
		strncmp( dlg->callid.s, callid->s, callid->len)==0 ) {
			ref_dlg_unsafe( dlg, 1);
			dlg_unlock( d_table, d_entry);
			return dlg;
		}
	}

	dlg_unlock( d_table, d_entry);
	return NULL;
}


struct dlg_cell* get_dlg_by_did(str *did, int active_only)
{
	struct dlg_cell *dlg;
	struct dlg_entry *d_entry;
	unsigned h_entry, h_id;

	if (parse_dlg_did(did, &h_entry, &h_id) < 0)
		return NULL;

	if (h_entry>=d_table->size)
		return NULL;

	LM_DBG("looking for hentry=%d hid=%d\n", h_entry, h_id);

	d_entry = &(d_table->entries[h_entry]);
	dlg_lock( d_table, d_entry);
	for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
		if (active_only && dlg->state>DLG_STATE_CONFIRMED )
			continue;
		if (dlg->h_id == h_id) {
			ref_dlg_unsafe( dlg, 1);
			dlg_unlock( d_table, d_entry);
			return dlg;
		}
	}

	dlg_unlock( d_table, d_entry);
	return NULL;
}

struct dlg_cell *get_dlg_by_dialog_id(str *dialog_id)
{
	struct dlg_cell *dlg = NULL;
	unsigned int h_entry, h_id;

	if (parse_dlg_did(dialog_id, &h_entry, &h_id) == 0) {
		/* we might have a dialog did */
		LM_DBG("ID: %*s (h_entry %u h_id %u)\n",
				dialog_id->len, dialog_id->s, h_entry, h_id);
		dlg = lookup_dlg(h_entry, h_id);
	}
	if (!dlg) {
		/* the ID is not a number, so let's consider
		 * the value a SIP call-id */
		LM_DBG("Call-ID: <%.*s>\n", dialog_id->len, dialog_id->s);
		dlg = get_dlg_by_callid(dialog_id, 1);
	}
	return dlg;
}


void link_dlg(struct dlg_cell *dlg, int extra_refs)
{
	struct dlg_entry *d_entry;

	d_entry = &(d_table->entries[dlg->h_entry]);

	dlg_lock(d_table, d_entry);

	link_dlg_unsafe(d_entry, dlg);

	DBG_REF(dlg, extra_refs);
	dlg->ref += extra_refs;

	LM_DBG("ref dlg %p with %d -> %d in h_entry %p - %d \n",
	       dlg, extra_refs + 1, dlg->ref, d_entry, dlg->h_entry);

	dlg_unlock( d_table, d_entry);
}



void unlink_unsafe_dlg(struct dlg_entry *d_entry,
													struct dlg_cell *dlg)
{
	if (dlg->next)
		dlg->next->prev = dlg->prev;
	else
		d_entry->last = dlg->prev;
	if (dlg->prev)
		dlg->prev->next = dlg->next;
	else
		d_entry->first = dlg->next;

	dlg->next = dlg->prev = 0;
	d_entry->cnt--;

	return;
}


void _ref_dlg(struct dlg_cell *dlg, unsigned int cnt)
{
	struct dlg_entry *d_entry;

	d_entry = &(d_table->entries[dlg->h_entry]);

	dlg_lock( d_table, d_entry);
	ref_dlg_unsafe( dlg, cnt);
	dlg_unlock( d_table, d_entry);
}

void _unref_dlg(struct dlg_cell *dlg, unsigned int cnt)
{
	struct dlg_entry *d_entry;

	d_entry = &(d_table->entries[dlg->h_entry]);

	dlg_lock( d_table, d_entry);
	unref_dlg_unsafe( dlg, cnt, d_entry);
	dlg_unlock( d_table, d_entry);
}

/*
 * create DLG_STATE_CHANGED_EVENT
 */
int state_changed_event_init(void)
{
	/* publish the event */
	ei_st_ch_id = evi_publish_event(ei_st_ch_name);
	if (ei_st_ch_id == EVI_ERROR) {
		LM_ERR("cannot register dialog state changed event\n");
		return -1;
	}

	event_params = pkg_malloc(sizeof(evi_params_t));
	if (event_params == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(event_params, 0, sizeof(evi_params_t));

	if (dlg_event_id_format < 0 || dlg_event_id_format > 2) {
		LM_WARN("unhandled 'dialog_event_id_format' %d! "
				"using default\n", dlg_event_id_format);
		dlg_event_id_format = 0;
	}
	if (dlg_event_id_format != 1) {
		hentry_p = evi_param_create(event_params, &ei_h_entry);
		if (hentry_p == NULL)
			goto create_error;

		hid_p = evi_param_create(event_params, &ei_h_id);
		if (hid_p == NULL)
			goto create_error;
	}
	if (dlg_event_id_format != 0) {
		id_p = evi_param_create(event_params, &ei_id);
		if (id_p == NULL)
			goto create_error;

		db_id_p = evi_param_create(event_params, &ei_db_id);
		if (db_id_p == NULL)
			goto create_error;
	}

	cid_p = evi_param_create(event_params, &ei_c_id);
	if (cid_p == NULL)
		goto create_error;

	fromt_p = evi_param_create(event_params, &ei_from_tag);
	if (fromt_p == NULL)
		goto create_error;

	tot_p = evi_param_create(event_params, &ei_to_tag);
	if (tot_p == NULL)
		goto create_error;

	ostate_p = evi_param_create(event_params, &ei_old_state);
	if (ostate_p == NULL)
		goto create_error;

	nstate_p = evi_param_create(event_params, &ei_new_state);
	if (nstate_p == NULL)
		goto create_error;

	return 0;

create_error:
	LM_ERR("cannot create event parameter\n");
	return -1;
}

/*
 * destroy DLG_STATE_CHANGED event
 */
void state_changed_event_destroy(void)
{
	evi_free_params(event_params);
}

/*
 * raise DLG_STATE_CHANGED event
 */
static void raise_state_changed_event(struct dlg_cell *dlg,
									unsigned int ostate, unsigned int nstate)
{
	char b1[INT2STR_MAX_LEN], b2[INT2STR_MAX_LEN];
	str s1, s2;
	int callee_leg_idx;

	if (!evi_probe_event(ei_st_ch_id))
		return;

	if (hentry_p && hid_p) {
		s1.s = int2bstr( (unsigned long)dlg->h_entry, b1, &s1.len);
		s2.s = int2bstr( (unsigned long)dlg->h_id, b2, &s2.len);
		if (s1.s==NULL || s2.s==NULL) {
			LM_ERR("cannot convert hash params\n");
			return;
		}
		if (evi_param_set_str(hentry_p, &s1) < 0) {
			LM_ERR("cannot set hash entry parameter\n");
			return;
		}
		if (evi_param_set_str(hid_p, &s2) < 0) {
			LM_ERR("cannot set hash id parameter\n");
			return;
		}
	}

	if (id_p && db_id_p) {
		str *did = dlg_get_did(dlg);
		if (evi_param_set_str(id_p, did) < 0) {
			LM_ERR("cannot set dialog id parameter\n");
			return;
		}
		s1.s = int2str(dlg_get_db_id(dlg), &s1.len);
		if (evi_param_set_str(db_id_p, &s1) < 0) {
			LM_ERR("cannot set dialog db id parameter\n");
			return;
		}
	}

	if (evi_param_set_str(cid_p, &dlg->callid) < 0) {
		LM_ERR("cannot set callid parameter\n");
		return;
	}

	if (evi_param_set_str(fromt_p, &dlg->legs[DLG_CALLER_LEG].tag) < 0) {
		LM_ERR("cannot set from tag parameter\n");
		return;
	}

	callee_leg_idx = callee_idx(dlg);
	if (evi_param_set_str(tot_p, &dlg->legs[callee_leg_idx].tag) < 0) {
		LM_ERR("cannot set from tag parameter\n");
		return;
	}

	/* coverity[overrun-buffer-val] */
	if (evi_param_set_int(ostate_p, &ostate) < 0) {
		LM_ERR("cannot set old state parameter\n");
		return;
	}

	/* coverity[overrun-buffer-val] */
	if (evi_param_set_int(nstate_p, &nstate) < 0) {
		LM_ERR("cannot set new state parameter\n");
		return;
	}

	if (evi_raise_event(ei_st_ch_id, event_params) < 0)
		LM_ERR("cannot raise event\n");

}

/**
 * Small logging helper functions for next_state_dlg.
 * \param event logged event
 * \param dlg dialog data
 * \see next_state_dlg
 */
static inline void log_next_state_dlg(const int event,
                                      const struct dlg_cell *dlg) {
	LM_WARN("bogus event %d in state %d for dlg %p [%u:%u] with "
		"clid '%.*s' and tags '%.*s' '%.*s'\n",
		event, dlg->state, dlg, dlg->h_entry, dlg->h_id,
		dlg->callid.len, dlg->callid.s,
		dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
		dlg_leg_print_info( dlg, callee_idx(dlg), tag));
}


void next_state_dlg(struct dlg_cell *dlg, int event, int dir, int *old_state,
		int *new_state, int *unref, int last_dst_leg, char replicate_events)
{
	struct dlg_entry *d_entry;

	d_entry = &(d_table->entries[dlg->h_entry]);
	*unref = 0;

	dlg_lock( d_table, d_entry);

	*old_state = dlg->state;

	switch (event) {
		case DLG_EVENT_TDEL:
			switch (dlg->state) {
				case DLG_STATE_UNCONFIRMED:
				case DLG_STATE_EARLY:
					dlg->state = DLG_STATE_DELETED;
					unref_dlg_unsafe(dlg,1,d_entry); /* unref from TM CBs*/
					*unref = 1; /* unref from hash -> t failed */
					break;
				case DLG_STATE_CONFIRMED_NA:
				case DLG_STATE_CONFIRMED:
					unref_dlg_unsafe(dlg,1,d_entry); /* unref from TM CBs*/
					break;
				case DLG_STATE_DELETED:
					/* as the dialog aleady is in DELETE state, it is
					dangerous to directly unref it from here as it might
					be last ref -> dialog will be destroied and we will end up
					with a dangling pointer :D - bogdan */
					*unref = 1; /* unref from TM CBs*/
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		case DLG_EVENT_RPL1xx:
			switch (dlg->state) {
				case DLG_STATE_UNCONFIRMED:
				case DLG_STATE_EARLY:
					dlg->state = DLG_STATE_EARLY;
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		case DLG_EVENT_RPL3xx:
			switch (dlg->state) {
				case DLG_STATE_UNCONFIRMED:
				case DLG_STATE_EARLY:
					dlg->state = DLG_STATE_DELETED;
					*unref = 1; /* unref from hash -> t failed */
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		case DLG_EVENT_RPL2xx:
			switch (dlg->state) {
				case DLG_STATE_DELETED:
					if (dlg->flags&DLG_FLAG_HASBYE) {
						log_next_state_dlg(event, dlg);
						break;
					}
					ref_dlg_unsafe(dlg,1); /* back in hash */
				case DLG_STATE_UNCONFIRMED:
				case DLG_STATE_EARLY:
					dlg->state = DLG_STATE_CONFIRMED_NA;
					break;
				case DLG_STATE_CONFIRMED_NA:
				case DLG_STATE_CONFIRMED:
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		case DLG_EVENT_REQACK:
			switch (dlg->state) {
				case DLG_STATE_CONFIRMED_NA:
					dlg->state = DLG_STATE_CONFIRMED;
					break;
				case DLG_STATE_CONFIRMED:
					break;
				case DLG_STATE_DELETED:
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		case DLG_EVENT_REQBYE:
			switch (dlg->state) {
				case DLG_STATE_CONFIRMED_NA:
				case DLG_STATE_CONFIRMED:
					if (dir == DLG_DIR_DOWNSTREAM &&
					last_dst_leg!=dlg->legs_no[DLG_LEG_200OK] )
						/* to end the call, the BYE must be received
						 * on the same leg as the 200 OK for INVITE */
						break;
					dlg->flags |= DLG_FLAG_HASBYE;
					dlg->state = DLG_STATE_DELETED;
					*unref = 1; /* unref from hash -> dialog ended */
					break;
				case DLG_STATE_DELETED:
					break;
				default:
					/* only case for BYEs in early or unconfirmed states
					 * is for requests generate by caller or callee.
					 * We never internally generate BYEs for early dialogs
					 *
					 * RFC says caller may send BYEs for early dialogs,
					 * while the callee side MUST not send such requests*/
					if (last_dst_leg == 0) {
						log_next_state_dlg(event, dlg);
					} else {
						/* we don't transition, but rather we
						 * mark the BYE as received */
						dlg->flags |= DLG_FLAG_HASBYE;
					}
			}
			break;
		case DLG_EVENT_REQPRACK:
			switch (dlg->state) {
				case DLG_STATE_EARLY:
				case DLG_STATE_CONFIRMED_NA:
				case DLG_STATE_CONFIRMED:
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		case DLG_EVENT_REQ:
			switch (dlg->state) {
				case DLG_STATE_EARLY:
				case DLG_STATE_CONFIRMED_NA:
				case DLG_STATE_CONFIRMED:
					break;
				default:
					log_next_state_dlg(event, dlg);
			}
			break;
		default:
			LM_INFO("unknown event %d in state %d "
				"for dlg %p [%u:%u] with clid '%.*s' and tags '%.*s' '%.*s'\n",
				event, dlg->state, dlg, dlg->h_entry, dlg->h_id,
				dlg->callid.len, dlg->callid.s,
				dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
				dlg_leg_print_info( dlg, callee_idx(dlg), tag));
	}
	*new_state = dlg->state;

	dlg_unlock( d_table, d_entry);

	if (*old_state != *new_state)
		raise_state_changed_event(dlg, (unsigned int)(*old_state),
			(unsigned int)(*new_state));

	 if (dialog_repl_cluster && replicate_events &&
	(*old_state==DLG_STATE_CONFIRMED_NA || *old_state==DLG_STATE_CONFIRMED) &&
	*new_state==DLG_STATE_DELETED )
		replicate_dialog_deleted(dlg);


	LM_DBG("dialog %p changed from state %d to "
		"state %d, due event %d\n",dlg,*old_state,*new_state,event);
}


/**************************** MI functions ******************************/
static char *dlg_val_buf;
static inline int internal_mi_print_dlg(mi_item_t *dialog_obj,
									struct dlg_cell *dlg, int with_context)
{
	struct dlg_profile_link *dl;
	struct dlg_val* dv;
	char* p;
	int i, j;
	time_t _ts;
	struct tm t;
	char date_buf[MI_DATE_BUF_LEN];
	int date_buf_len;
	mi_item_t *callees_arr, *values_arr, *profiles_arr;
	mi_item_t *context_obj, *callee_item, *values_item, *profiles_item;
	str *did = dlg_get_did(dlg);

	if (add_mi_string(dialog_obj, MI_SSTR("ID"), did->s, did->len) < 0)
		goto error;
	if (add_mi_string_fmt(dialog_obj, MI_SSTR("db_id"), "%llu",
			(((long long unsigned)dlg->h_entry)<<(8*sizeof(int)))+dlg->h_id) < 0)
		goto error;

	if (add_mi_number(dialog_obj, MI_SSTR("state"), dlg->state) < 0)
		goto error;
	if (add_mi_number(dialog_obj, MI_SSTR("user_flags"), dlg->user_flags) < 0)
		goto error;

	_ts = (time_t)dlg->start_ts;
	if (add_mi_number(dialog_obj, MI_SSTR("timestart"), _ts) < 0)
		goto error;
	if (_ts) {
		localtime_r(&_ts, &t);
		date_buf_len = strftime(date_buf, MI_DATE_BUF_LEN - 1,
						"%Y-%m-%d %H:%M:%S", &t);
		if (date_buf_len != 0)
			if (add_mi_string(dialog_obj, MI_SSTR("datestart"),
				date_buf, date_buf_len) < 0)
				goto error;
	}

	_ts = (time_t)(dlg->tl.timeout?((unsigned int)time(0) +
                dlg->tl.timeout - get_ticks()):0);
	if (add_mi_number(dialog_obj, MI_SSTR("timeout"), _ts) < 0)
		goto error;
	if (_ts) {
		localtime_r(&_ts, &t);
		date_buf_len = strftime(date_buf, MI_DATE_BUF_LEN - 1,
						"%Y-%m-%d %H:%M:%S", &t);
		if (date_buf_len != 0)
			if (add_mi_string(dialog_obj, MI_SSTR("dateout"),
				date_buf, date_buf_len) < 0)
				goto error;
	}

	if (add_mi_string(dialog_obj, MI_SSTR("callid"),
		dlg->callid.s, dlg->callid.len) < 0)
		goto error;
	if (add_mi_string(dialog_obj, MI_SSTR("from_uri"),
		dlg->from_uri.s, dlg->from_uri.len) < 0)
		goto error;
	if (add_mi_string(dialog_obj, MI_SSTR("to_uri"),
		dlg->to_uri.s, dlg->to_uri.len) < 0)
		goto error;

	if (dlg->legs_no[DLG_LEGS_USED]>0) {
		if (add_mi_string(dialog_obj, MI_SSTR("caller_tag"),
			dlg->legs[DLG_CALLER_LEG].tag.s,
			dlg->legs[DLG_CALLER_LEG].tag.len) < 0)
			goto error;
		if (add_mi_string(dialog_obj, MI_SSTR("caller_contact"),
			dlg->legs[DLG_CALLER_LEG].contact.s,
			dlg->legs[DLG_CALLER_LEG].contact.len) < 0)
			goto error;
		if (add_mi_string(dialog_obj, MI_SSTR("callee_cseq"),
			dlg->legs[DLG_CALLER_LEG].r_cseq.s,
			dlg->legs[DLG_CALLER_LEG].r_cseq.len) < 0)
			goto error;
		if (add_mi_string(dialog_obj, MI_SSTR("caller_route_set"),
			dlg->legs[DLG_CALLER_LEG].route_set.s,
			dlg->legs[DLG_CALLER_LEG].route_set.len) < 0)
			goto error;
		if (add_mi_string(dialog_obj, MI_SSTR("caller_bind_addr"),
			dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str.s,
			dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str.len) < 0)
			goto error;
		if (dlg->legs[DLG_CALLER_LEG].in_sdp.s &&
			add_mi_string(dialog_obj, MI_SSTR("caller_sdp"),
			dlg->legs[DLG_CALLER_LEG].in_sdp.s,
			dlg->legs[DLG_CALLER_LEG].in_sdp.len) < 0)
			goto error;
		if (dlg->legs[DLG_CALLER_LEG].out_sdp.s &&
			add_mi_string(dialog_obj, MI_SSTR("caller_sent_sdp"),
			dlg->legs[DLG_CALLER_LEG].out_sdp.s,
			dlg->legs[DLG_CALLER_LEG].out_sdp.len) < 0)
			goto error;
	}

	callees_arr = add_mi_array(dialog_obj, MI_SSTR("CALLEES"));
	if (!callees_arr)
		goto error;

	for( i=1 ; i < dlg->legs_no[DLG_LEGS_USED] ; i++  ) {
		callee_item = add_mi_object(callees_arr, NULL, 0);
		if (!callee_item)
			goto error;

		if (add_mi_string(callee_item, MI_SSTR("callee_tag"),
			dlg->legs[i].tag.s, dlg->legs[i].tag.len) < 0)
			goto error;
		if (add_mi_string(callee_item, MI_SSTR("callee_contact"),
			dlg->legs[i].contact.s, dlg->legs[i].contact.len) < 0)
			goto error;
		if (add_mi_string(callee_item, MI_SSTR("caller_cseq"),
			dlg->legs[i].r_cseq.s, dlg->legs[i].r_cseq.len) < 0)
			goto error;
		if (add_mi_string(callee_item, MI_SSTR("callee_route_set"),
			dlg->legs[i].route_set.s, dlg->legs[i].route_set.len) < 0)
			goto error;

		if (dlg->legs[i].bind_addr) {
			if (add_mi_string(callee_item, MI_SSTR("callee_bind_addr"),
				dlg->legs[i].bind_addr->sock_str.s,
				dlg->legs[i].bind_addr->sock_str.len) < 0)
				goto error;
		} else {
			if (add_mi_null(callee_item, MI_SSTR("callee_bind_addr")) < 0)
				goto error;
		}

		if (dlg->legs[i].in_sdp.s &&
			add_mi_string(callee_item, MI_SSTR("callee_sdp"),
			dlg->legs[i].in_sdp.s, dlg->legs[i].in_sdp.len) < 0)
			goto error;
		if (dlg->legs[i].out_sdp.s &&
			add_mi_string(callee_item, MI_SSTR("callee_sent_sdp"),
			dlg->legs[i].out_sdp.s, dlg->legs[i].out_sdp.len) < 0)
			goto error;
	}

	if (with_context) {
		context_obj = add_mi_object(dialog_obj, MI_SSTR("context"));
		if (!context_obj)
			goto error;

		if (dlg->vals) {
			values_arr = add_mi_array(context_obj, MI_SSTR("values"));
			if (!values_arr)
				goto error;

			/* print dlg values -> iterate the list */
			for( dv=dlg->vals ; dv ; dv=dv->next) {
				/* escape non-printable chars */
				p = pkg_realloc(dlg_val_buf, 4 * dv->val.len + 1);
				if (!p) {
					LM_ERR("not enough mem to allocate: %d\n", dv->val.len);
					continue;
				}
				for (i = 0, j = 0; i < dv->val.len; i++) {
					if (dv->val.s[i] < 0x20 || dv->val.s[i] >= 0x7F) {
						p[j++] = '\\';
						switch ((unsigned char)dv->val.s[i]) {
						case 0x8: p[j++] = 'b'; break;
						case 0x9: p[j++] = 't'; break;
						case 0xA: p[j++] = 'n'; break;
						case 0xC: p[j++] = 'f'; break;
						case 0xD: p[j++] = 'r'; break;
						default:
							p[j++] = 'x';
							j += snprintf(&p[j], 3, "%02x",
									(unsigned char)dv->val.s[i]);
							break;
						}
					} else {
						p[j++] = dv->val.s[i];
					}
				}

				values_item = add_mi_object(values_arr, NULL, 0);
				if (!values_item)
					goto error;
				if (add_mi_string(values_item,dv->name.s,dv->name.len,p,j) < 0)
					goto error;

				dlg_val_buf = p;
			}
		}

		/* print dlg profiles */
		if (dlg->profile_links) {
			profiles_arr = add_mi_array(context_obj, MI_SSTR("profiles"));
			if (!profiles_arr)
				goto error;

			for( dl=dlg->profile_links ; dl ; dl=dl->next) {
				profiles_item = add_mi_object(profiles_arr, NULL, 0);
				if (!profiles_item)
					goto error;
				if (add_mi_string(profiles_item, dl->profile->name.s,
					dl->profile->name.len, ZSW(dl->value.s),dl->value.len) < 0)
					goto error;
			}
		}

		/* print external context info */
		run_dlg_callbacks(DLGCB_MI_CONTEXT, dlg, NULL,
			DLG_DIR_NONE, (void *)context_obj, 0, 1);
	}

	return 0;

error:
	LM_ERR("failed to add MI item\n");
	return -1;
}


int mi_print_dlg(mi_item_t *dialog_obj, struct dlg_cell *dlg, int with_context)
{
	return internal_mi_print_dlg(dialog_obj, dlg, with_context);
}


static mi_response_t *internal_mi_print_dlgs(int with_context,
								unsigned int idx, unsigned int cnt)
{
	struct dlg_cell *dlg;
	unsigned int i;
	unsigned int n;
	unsigned int total;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *dialogs_arr, *dialog_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	total = 0;
	if (cnt) {
		for(i=0;i<d_table->size ; total+=d_table->entries[i++].cnt );
		if (add_mi_number(resp_obj, MI_SSTR("count"), total) < 0)
			goto error;
	}

	LM_DBG("printing %i dialogs, idx=%d, cnt=%d\n", total,idx,cnt);

	dialogs_arr = add_mi_array(resp_obj, MI_SSTR("Dialogs"));
	if (!dialogs_arr)
		goto error;

	for( i=0,n=0 ; i<d_table->size ; i++ ) {
		dlg_lock( d_table, &(d_table->entries[i]) );

		for( dlg=d_table->entries[i].first ; dlg ; dlg=dlg->next ) {
			if (cnt && n<idx) {n++;continue;}

			dialog_item = add_mi_object(dialogs_arr, NULL, 0);
			if (!dialog_item)
				goto error_unlock;

			if (internal_mi_print_dlg(dialog_item, dlg, with_context)!=0)
				goto error_unlock;
			n++;
			if (cnt && n>=idx+cnt) {
				dlg_unlock( d_table, &(d_table->entries[i]) );
				return resp;
			}
		}
		dlg_unlock( d_table, &(d_table->entries[i]) );
	}

	return resp;

error_unlock:
	dlg_unlock( d_table, &(d_table->entries[i]) );
error:
	LM_ERR("failed to print dialog\n");
	free_mi_response(resp);
	return NULL;
}


static int match_downstream_dialog(struct dlg_cell *dlg,
													str *callid, str *ftag)
{
	if (dlg->callid.len!=callid->len ||
		(ftag && dlg->legs[DLG_CALLER_LEG].tag.len!=ftag->len)  ||
		strncmp(dlg->callid.s,callid->s,callid->len)!=0 ||
		(ftag && strncmp(dlg->legs[DLG_CALLER_LEG].tag.s,ftag->s,ftag->len)))
		return 0;
	return 1;
}


static mi_response_t *mi_match_print_dlg(int with_context,
					const mi_params_t *params, str *from_tag)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *dialog_obj;
	str callid;
	struct dlg_entry *d_entry;
	struct dlg_cell *dlg, *match_dlg = NULL;
	unsigned int h_entry;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	h_entry = dlg_hash(&callid);

	d_entry = &(d_table->entries[h_entry]);
	dlg_lock(d_table, d_entry);

	for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
		if (match_downstream_dialog(dlg, &callid, from_tag) == 1) {
			if (dlg->state==DLG_STATE_DELETED) {
				match_dlg = NULL;
				break;
			} else {
				match_dlg = dlg;
				break;
			}
		}
	}

	if (!match_dlg) {
		dlg_unlock(d_table, d_entry);
		return init_mi_error(404, MI_SSTR("No such dialog"));
	}

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return NULL;

	dialog_obj = add_mi_object(resp_obj, MI_SSTR("Dialog"));
	if (!dialog_obj)
		goto error;

	if (internal_mi_print_dlg(dialog_obj, match_dlg, with_context) != 0)
		goto error;

	dlg_unlock(d_table, d_entry);

	return resp;

error:
	dlg_unlock(d_table, d_entry);
	free_mi_response(resp);
	return NULL;
}

mi_response_t *mi_print_dlgs(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return internal_mi_print_dlgs(0, 0, 0);
}

mi_response_t *mi_print_dlgs_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_match_print_dlg(0, params, 0);
}

mi_response_t *mi_print_dlgs_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str from_tag;

	if (get_mi_string_param(params, "from_tag", &from_tag.s, &from_tag.len) < 0)
		return init_mi_param_error();

	return mi_match_print_dlg(0, params, &from_tag);
}

mi_response_t *mi_print_dlgs_cnt(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int index, counter;

	if (get_mi_int_param(params, "index", &index) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "counter", &counter) < 0)
		return init_mi_param_error();

	return internal_mi_print_dlgs(0, index, counter);
}


mi_response_t *mi_print_dlgs_ctx(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return internal_mi_print_dlgs(1, 0, 0);
}

mi_response_t *mi_print_dlgs_1_ctx(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_match_print_dlg(1, params, 0);
}

mi_response_t *mi_print_dlgs_2_ctx(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str from_tag;

	if (get_mi_string_param(params, "from_tag", &from_tag.s, &from_tag.len) < 0)
		return init_mi_param_error();

	return mi_match_print_dlg(1, params, &from_tag);
}

mi_response_t *mi_print_dlgs_cnt_ctx(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int index, counter;

	if (get_mi_int_param(params, "index", &index) < 0)
		return init_mi_param_error();
	if (get_mi_int_param(params, "counter", &counter) < 0)
		return init_mi_param_error();

	return internal_mi_print_dlgs(1, index, counter);
}

mi_response_t *mi_push_dlg_var(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str dlg_var_name,dlg_var_value,dialog_id;
	struct dlg_cell * dlg = NULL;
	int shtag_state = 1, db_update = 0;
	mi_item_t *did_param_arr;
	int i, no_dids;

	if ( d_table == NULL)
		goto not_found;

	if (get_mi_string_param(params, "dlg_val_name",
		&dlg_var_name.s, &dlg_var_name.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "dlg_val_value",
		&dlg_var_value.s, &dlg_var_value.len) < 0)
		return init_mi_param_error();

	if (get_mi_array_param(params, "DID", &did_param_arr, &no_dids) < 0)
		return init_mi_param_error();

	for (i = 0; i < no_dids; i++) {
		if (get_mi_arr_param_string(did_param_arr, i,
			&dialog_id.s, &dialog_id.len) < 0)
			return init_mi_param_error();

		/* Get the dialog based of the dialog_id. This may be a
		 * numerical DID or a string SIP Call-ID */

		/* convert to unsigned long long */
		dlg = get_dlg_by_dialog_id(&dialog_id);
		if (dlg == NULL) {
			/* XXX - not_found or loop_end here ? */
			continue;
		}

		if (dialog_repl_cluster) {
			shtag_state = get_shtag_state(dlg);
			if (shtag_state < 0) {
				unref_dlg(dlg, 1);
				goto dlg_error;
			} else if (shtag_state == SHTAG_STATE_BACKUP) {
				/* editing dlg vars on backup servers - no no */
				unref_dlg(dlg, 1);
				return init_mi_error(403, MI_SSTR(MI_DIALOG_BACKUP_ERR));
			}
		}

		if (store_dlg_value( dlg, &dlg_var_name, &dlg_var_value)!=0) {
			LM_ERR("failed to store dialog values <%.*s>:<%.*s>\n",
			dlg_var_name.len,dlg_var_name.s,
			dlg_var_value.len,dlg_var_value.s);

			unref_dlg(dlg, 1);
			goto dlg_error;
		}

		if (dlg->state >= DLG_STATE_CONFIRMED && dlg_db_mode == DB_MODE_REALTIME) {
			db_update = 1;
		} else {
			dlg->flags |= DLG_FLAG_CHANGED;
			db_update = 0;
		}

		if (db_update)
			update_dialog_timeout_info(dlg);
		if (dialog_repl_cluster && shtag_state != SHTAG_STATE_BACKUP)
			replicate_dialog_updated(dlg);

		unref_dlg(dlg, 1);
	}

	return init_mi_result_ok();

not_found:
	return init_mi_error(404, MI_SSTR(MI_DIALOG_NOT_FOUND));
dlg_error:
	return init_mi_error(403, MI_SSTR(MI_DLG_OPERATION_ERR));
}
