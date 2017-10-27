/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 * 2006-04-14  initial version (bogdan)
 * 2007-03-06  syncronized state machine added for dialog state. New tranzition
 *             design based on events; removed num_1xx and num_2xx (bogdan)
 * 2007-04-30  added dialog matching without DID (dialog ID), but based only
 *             on RFC3261 elements - based on an original patch submitted
 *             by Michel Bensoussan <michel@extricom.com> (bogdan)
 * 2007-07-06  additional information stored in order to save it in the db:
 *             cseq, route_set, contact and sock_info for both caller and
 *             callee (ancuta)
 * 2007-07-10  Optimized dlg_match_mode 2 (DID_NONE), it now employs a proper
 *             hash table lookup and isn't dependant on the is_direction
 *             function (which requires an RR param like dlg_match_mode 0
 *             anyways.. ;) ; based on a patch from
 *             Tavis Paquette <tavis@galaxytelecom.net>
 *             and Peter Baer <pbaer@galaxytelecom.net>  (bogdan)
 * 2008-04-17  added new type of callback to be triggered right before the
 *              dialog is destroyed (deleted from memory) (bogdan)
 * 2008-04-17  added new dialog flag to avoid state tranzitions from DELETED to
 *             CONFIRMED_NA due delayed "200 OK" (bogdan)
 * 2009-09-09  support for early dialogs added; proper handling of cseq
 *             while PRACK is used (bogdan)
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
#include "../tm/tm_load.h"
#include "../../script_cb.h"
#include "dlg_hash.h"
#include "dlg_profile.h"
#include "dlg_replication.h"
#include "../../evi/evi_params.h"
#include "../../evi/evi_modules.h"

#define MAX_LDG_LOCKS  2048
#define MIN_LDG_LOCKS  2


extern struct tm_binds d_tmb;


struct dlg_table *d_table = NULL;
int ctx_dlg_idx = 0;

static inline void raise_state_changed_event(
	unsigned int h_entry, unsigned int h_id,
	unsigned int ostate, unsigned int nstate);
static str ei_st_ch_name = str_init("E_DLG_STATE_CHANGED");
static evi_params_p event_params;

static str ei_h_entry = str_init("hash_entry");
static str ei_h_id = str_init("hash_id");
static str ei_old_state = str_init("old_state");
static str ei_new_state = str_init("new_state");

static event_id_t ei_st_ch_id = EVI_ERROR;

static evi_param_p hentry_p, hid_p, ostate_p, nstate_p;


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
		ref_dlg( trans->dialog_ctx, 1);
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

	if (dlg->profile_links)
		destroy_linkers(dlg->profile_links, 0);

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
			if (dlg->legs[i].th_sent_contact.s)
				shm_free(dlg->legs[i].th_sent_contact.s);
			if (dlg->legs[i].from_uri.s)
				shm_free(dlg->legs[i].from_uri.s);
			if (dlg->legs[i].to_uri.s)
				shm_free(dlg->legs[i].to_uri.s);
			if (dlg->legs[i].sdp.s)
				shm_free(dlg->legs[i].sdp.s);
		}
		shm_free(dlg->legs);
	}

	while (dlg->vals) {
		dv = dlg->vals;
		dlg->vals = dlg->vals->next;
		shm_free(dv);
	}

	if (dlg->terminate_reason.s)
		shm_free(dlg->terminate_reason.s);
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

	run_dlg_callbacks( DLGCB_DESTROY , dlg, 0, DLG_DIR_NONE, 0);

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
		to_uri->len;
	dlg = (struct dlg_cell*)shm_malloc( len );
	if (dlg==0) {
		LM_ERR("no more shm mem (%d)\n",len);
		return 0;
	}

	memset( dlg, 0, len);
	dlg->state = DLG_STATE_UNCONFIRMED;

	dlg->h_entry = dlg_hash( callid);

	LM_DBG("new dialog %p (c=%.*s,f=%.*s,t=%.*s,ft=%.*s) on hash %u\n",
		dlg, callid->len,callid->s, from_uri->len, from_uri->s,
		to_uri->len,to_uri->s, from_tag->len, from_tag->s, dlg->h_entry);

	p = (char*)(dlg+1);

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


/* first time it will called for a CALLER leg - at that time there will
   be no leg allocated, so automatically CALLER gets the first position, while
   the CALLEE legs will follow into the array in the same order they came */
int dlg_add_leg_info(struct dlg_cell *dlg, str* tag, str *rr,
		str *contact,str *cseq, struct socket_info *sock,
		str *mangled_from,str *mangled_to,str *sdp)
{
	struct dlg_leg* leg,*new_legs;
	rr_t *head = NULL, *rrp;

	if ( (dlg->legs_no[DLG_LEGS_ALLOCED]-dlg->legs_no[DLG_LEGS_USED])==0) {
		new_legs = (struct dlg_leg*)shm_realloc(dlg->legs,
			(dlg->legs_no[DLG_LEGS_ALLOCED]+2)*sizeof(struct dlg_leg));
		if (new_legs==NULL) {
			LM_ERR("Failed to resize legs array\n");
			return -1;
		}
		dlg->legs=new_legs;
		dlg->legs_no[DLG_LEGS_ALLOCED] += 2;
		memset( dlg->legs+dlg->legs_no[DLG_LEGS_ALLOCED]-2, 0,
			2*sizeof(struct dlg_leg));
	}
	leg = &dlg->legs[ dlg->legs_no[DLG_LEGS_USED] ];

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

	/* save mangled from URI, if any */
	if (mangled_from && mangled_from->s && mangled_from->len) {
		leg->from_uri.s = shm_malloc(mangled_from->len);
		if (!leg->from_uri.s) {
			LM_ERR("no more shm\n");
			goto error_all;
		}

		leg->from_uri.len = mangled_from->len;
		memcpy(leg->from_uri.s,mangled_from->s,mangled_from->len);
	}

	if (mangled_to && mangled_to->s && mangled_to->len) {
		leg->to_uri.s = shm_malloc(mangled_to->len);
		if (!leg->to_uri.s) {
			LM_ERR("no more shm\n");
			goto error_all;
		}

		leg->to_uri.len = mangled_to->len;
		memcpy(leg->to_uri.s,mangled_to->s,mangled_to->len);
	}

	if (sdp && sdp->s && sdp->len) {
		leg->sdp.s = shm_malloc(sdp->len);
		if (!leg->sdp.s) {
			LM_ERR("no more shm\n");
			goto error_all;
		}

		leg->sdp.len = sdp->len;
		memcpy(leg->sdp.s,sdp->s,sdp->len);
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
	dlg->legs_no[DLG_LEGS_USED]++;

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
			dlg->ref++;
			LM_DBG("ref dlg %p with 1 -> %d\n", dlg, dlg->ref);
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
				   a previous unsuccessfull attempt of established call
				   with the same callid and fromtag - like in auth/challenge
				   case -bogdan */
				continue;
			dlg->ref++;
			LM_DBG("ref dlg %p with 1 -> %d\n", dlg, dlg->ref);
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


void link_dlg(struct dlg_cell *dlg, int n)
{
	struct dlg_entry *d_entry;

	d_entry = &(d_table->entries[dlg->h_entry]);

	dlg_lock( d_table, d_entry);

	dlg->h_id = d_entry->next_id++;
	if (d_entry->first==0) {
		d_entry->first = d_entry->last = dlg;
	} else {
		d_entry->last->next = dlg;
		dlg->prev = d_entry->last;
		d_entry->last = dlg;
	}

	dlg->ref += 1 + n;
	d_entry->cnt++;

	LM_DBG("ref dlg %p with %d -> %d in h_entry %p - %d \n", dlg, n+1, dlg->ref,
								d_entry,dlg->h_entry);

	dlg_unlock( d_table, d_entry);
	return;
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


void ref_dlg(struct dlg_cell *dlg, unsigned int cnt)
{
	struct dlg_entry *d_entry;

	d_entry = &(d_table->entries[dlg->h_entry]);

	dlg_lock( d_table, d_entry);
	ref_dlg_unsafe( dlg, cnt);
	dlg_unlock( d_table, d_entry);
}


void unref_dlg(struct dlg_cell *dlg, unsigned int cnt)
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

	hentry_p = evi_param_create(event_params, &ei_h_entry);
	if (hentry_p == NULL)
		goto create_error;

	hid_p = evi_param_create(event_params, &ei_h_id);
	if (hid_p == NULL)
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
static void raise_state_changed_event(unsigned int h_entry, unsigned int h_id,
									unsigned int ostate, unsigned int nstate)
{
	char b1[INT2STR_MAX_LEN], b2[INT2STR_MAX_LEN];
	str s1, s2;

	s1.s = int2bstr( (unsigned long)h_entry, b1, &s1.len );
	s2.s = int2bstr( (unsigned long)h_id, b2, &s2.len );
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

	if (evi_param_set_int(ostate_p, &ostate) < 0) {
		LM_ERR("cannot set old state parameter\n");
		return;
	}

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
		int *new_state, int *unref, int last_dst_leg, char is_replicated)
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
					if (last_dst_leg == 0)
						log_next_state_dlg(event, dlg);
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
		raise_state_changed_event(  dlg->h_entry, dlg->h_id,
			(unsigned int)(*old_state), (unsigned int)(*new_state) );

	 if ( !is_replicated && dialog_replicate_cluster &&
	(*old_state==DLG_STATE_CONFIRMED_NA || *old_state==DLG_STATE_CONFIRMED) &&
	*new_state==DLG_STATE_DELETED )
		replicate_dialog_deleted(dlg);


	LM_DBG("dialog %p changed from state %d to "
		"state %d, due event %d\n",dlg,*old_state,*new_state,event);
}


/**************************** MI functions ******************************/
static char *dlg_val_buf;
static inline int internal_mi_print_dlg(struct mi_node *rpl,
									struct dlg_cell *dlg, int with_context)
{
	struct mi_node* node= NULL;
	struct mi_node* node1 = NULL;
	struct mi_node* node2 = NULL;
	struct mi_node* node3 = NULL;
	struct mi_attr* attr= NULL;
	struct dlg_profile_link *dl;
	struct dlg_val* dv;
	int len;
	char* p;
	int i, j;
	time_t _ts;
	struct tm* t;
	char date_buf[MI_DATE_BUF_LEN];
	int date_buf_len;

	node = add_mi_node_child(rpl, 0, "dialog",6 , 0, 0 );
	if (node==0)
		goto error;

	attr = addf_mi_attr( node, 0, "hash", 4, "%u:%u",
			dlg->h_entry, dlg->h_id );
	if (attr==0)
		goto error;

	attr = addf_mi_attr( node, 0, "dialog_id", 9, "%llu",
			(((long long unsigned)dlg->h_entry)<<(8*sizeof(int)))+dlg->h_id );
	if (attr==0)
		goto error;

	p= int2str((unsigned long)dlg->state, &len);
	node1 = add_mi_node_child( node, MI_DUP_VALUE, "state", 5, p, len);
	if (node1==0)
		goto error;

	p= int2str((unsigned long)dlg->user_flags, &len);
	node1 = add_mi_node_child( node, MI_DUP_VALUE, "user_flags", 10, p, len);
	if (node1==0)
		goto error;

	_ts = (time_t)dlg->start_ts;
	p= int2str((unsigned long)_ts, &len);
	node1 = add_mi_node_child(node,MI_DUP_VALUE,"timestart",9, p, len);
	if (node1==0)
		goto error;
	if (_ts) {
		t = localtime(&_ts);
		date_buf_len = strftime(date_buf, MI_DATE_BUF_LEN - 1,
						"%Y-%m-%d %H:%M:%S", t);
		if (date_buf_len != 0) {
			node1 = add_mi_node_child(node,MI_DUP_VALUE, "datestart", 9,
						date_buf, date_buf_len);
			if (node1==0)
				goto error;
		}
	}

	_ts = (time_t)(dlg->tl.timeout?((unsigned int)time(0) +
                dlg->tl.timeout - get_ticks()):0);
	p= int2str((unsigned long)_ts, &len);
	node1 = add_mi_node_child(node,MI_DUP_VALUE, "timeout", 7, p, len);
	if (node1==0)
		goto error;
	if (_ts) {
		t = localtime(&_ts);
		date_buf_len = strftime(date_buf, MI_DATE_BUF_LEN - 1,
						"%Y-%m-%d %H:%M:%S", t);
		if (date_buf_len != 0) {
			node1 = add_mi_node_child(node,MI_DUP_VALUE, "dateout", 7,
						date_buf, date_buf_len);
			if (node1==0)
				goto error;
		}
	}

	node1 = add_mi_node_child(node, MI_DUP_VALUE, "callid", 6,
			dlg->callid.s, dlg->callid.len);
	if(node1 == 0)
		goto error;

	node1 = add_mi_node_child(node, MI_DUP_VALUE, "from_uri", 8,
			dlg->from_uri.s, dlg->from_uri.len);
	if(node1 == 0)
		goto error;

	node1 = add_mi_node_child(node, MI_DUP_VALUE, "to_uri", 6,
			dlg->to_uri.s, dlg->to_uri.len);
	if(node1 == 0)
		goto error;

	if (dlg->legs_no[DLG_LEGS_USED]>0) {
		node1 = add_mi_node_child(node, MI_DUP_VALUE, "caller_tag", 10,
				dlg->legs[DLG_CALLER_LEG].tag.s,
				dlg->legs[DLG_CALLER_LEG].tag.len);
		if(node1 == 0)
			goto error;

		node1 = add_mi_node_child(node, MI_DUP_VALUE, "caller_contact", 14,
				dlg->legs[DLG_CALLER_LEG].contact.s,
				dlg->legs[DLG_CALLER_LEG].contact.len);
		if(node1 == 0)
			goto error;

		node1 = add_mi_node_child(node, MI_DUP_VALUE, "callee_cseq", 11,
				dlg->legs[DLG_CALLER_LEG].r_cseq.s,
				dlg->legs[DLG_CALLER_LEG].r_cseq.len);
		if(node1 == 0)
			goto error;

		node1 = add_mi_node_child(node, MI_DUP_VALUE,"caller_route_set",16,
				dlg->legs[DLG_CALLER_LEG].route_set.s,
				dlg->legs[DLG_CALLER_LEG].route_set.len);
		if(node1 == 0)
			goto error;

		node1 = add_mi_node_child(node, 0,"caller_bind_addr",16,
				dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str.s,
				dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str.len);
		if(node1 == 0)
			goto error;

		node1 = add_mi_node_child(node, MI_DUP_VALUE,"caller_sdp",10,
				dlg->legs[DLG_CALLER_LEG].sdp.s,
				dlg->legs[DLG_CALLER_LEG].sdp.len);
		if(node1 == 0)
			goto error;
	}

	node1 = add_mi_node_child(node, MI_IS_ARRAY, "CALLEES", 7, NULL, 0);
	if(node1 == 0)
		goto error;

	for( i=1 ; i < dlg->legs_no[DLG_LEGS_USED] ; i++  ) {

		node2 = add_mi_node_child(node1, 0, "callee", 6, NULL, 0);
		if(node2 == 0)
			goto error;

		node3 = add_mi_node_child(node2, MI_DUP_VALUE, "callee_tag", 10,
				dlg->legs[i].tag.s, dlg->legs[i].tag.len);
		if(node3 == 0)
			goto error;

		node3 = add_mi_node_child(node2, MI_DUP_VALUE, "callee_contact", 14,
				dlg->legs[i].contact.s, dlg->legs[i].contact.len);
		if(node3 == 0)
			goto error;

		node3 = add_mi_node_child(node2, MI_DUP_VALUE, "caller_cseq", 11,
				dlg->legs[i].r_cseq.s, dlg->legs[i].r_cseq.len);
		if(node3 == 0)
			goto error;

		node3 = add_mi_node_child(node2, MI_DUP_VALUE,"callee_route_set",16,
				dlg->legs[i].route_set.s, dlg->legs[i].route_set.len);
		if(node3 == 0)
			goto error;

		if (dlg->legs[i].bind_addr) {
			node3 = add_mi_node_child(node2, 0,
				"callee_bind_addr",16,
				dlg->legs[i].bind_addr->sock_str.s,
				dlg->legs[i].bind_addr->sock_str.len);
		} else {
			node3 = add_mi_node_child(node2, 0,
				"callee_bind_addr",16,0,0);
		}
		if(node3 == 0)
			goto error;
		
		node3 = add_mi_node_child(node2, MI_DUP_VALUE,"callee_sdp",10,
				dlg->legs[i].sdp.s,
				dlg->legs[i].sdp.len);
		if(node3 == 0)
			goto error;
	}

	if (with_context) {
		node1 = add_mi_node_child(node, 0, "context", 7, 0, 0);
		if(node1 == 0)
			goto error;
		if (dlg->vals) {
			node2 = add_mi_node_child(node1, 0, "values", 6, 0, 0);
			if(node2 == 0)
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
				add_mi_node_child(node2, MI_DUP_NAME|MI_DUP_VALUE,dv->name.s,dv->name.len,
					p,j);
				dlg_val_buf = p;
			}
		}
		/* print dlg profiles */
		if (dlg->profile_links) {
			node3 = add_mi_node_child(node1, 0, "profiles", 8, 0, 0);
			if(node3 == 0)
				goto error;
			for( dl=dlg->profile_links ; dl ; dl=dl->next) {
				add_mi_node_child(node3, MI_DUP_NAME|MI_DUP_VALUE,
					dl->profile->name.s,dl->profile->name.len,
					ZSW(dl->value.s),dl->value.len);
			}
		}
		/* print external context info */
		run_dlg_callbacks( DLGCB_MI_CONTEXT, dlg, NULL,
			DLG_DIR_NONE, (void *)node1);
	}

	return 0;

error:
	LM_ERR("failed to add node\n");
	return -1;
}


int mi_print_dlg(struct mi_node *rpl, struct dlg_cell *dlg, int with_context)
{
	return internal_mi_print_dlg( rpl, dlg, with_context);
}


static int internal_mi_print_dlgs(struct mi_root *rpl_tree,struct mi_node *rpl,
						int with_context, unsigned int idx, unsigned int cnt)
{
	struct dlg_cell *dlg;
	unsigned int i;
	unsigned int n;
	unsigned int total;
	char *p;

	total = 0;
	if (cnt) {
		for(i=0;i<d_table->size ; total+=d_table->entries[i++].cnt );
		p = int2str((unsigned long)total, (int*)&n);
		if (add_mi_node_child(rpl,MI_DUP_VALUE,"dlg_counter",11,p,n)==0)
			return -1;
	}

	LM_DBG("printing %i dialogs, idx=%d, cnt=%d\n", total,idx,cnt);
	rpl->flags |= MI_NOT_COMPLETED;

	for( i=0,n=0 ; i<d_table->size ; i++ ) {
		dlg_lock( d_table, &(d_table->entries[i]) );

		for( dlg=d_table->entries[i].first ; dlg ; dlg=dlg->next ) {
			if (cnt && n<idx) {n++;continue;}
			if (internal_mi_print_dlg(rpl, dlg, with_context)!=0)
				goto error;
			n++;
			if (cnt && n>=idx+cnt) {
				dlg_unlock( d_table, &(d_table->entries[i]) );
				return 0;
			}
			if ( (n % 50) == 0 )
				flush_mi_tree(rpl_tree);
		}
		dlg_unlock( d_table, &(d_table->entries[i]) );
	}
	return 0;

error:
	dlg_unlock( d_table, &(d_table->entries[i]) );
	LM_ERR("failed to print dialog\n");
	return -1;
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


/*
 * IMPORTANT: if a dialog reference is returned, the dialog hash entry will
   be kept locked when this function returns
   NOTE: if a reply tree is returned, no dialog reference is returned.
 */
static inline struct mi_root* process_mi_params(struct mi_root *cmd_tree,
			struct dlg_cell **dlg_p, unsigned int *idx, unsigned int *cnt)
{
	struct mi_node* node;
	struct dlg_entry *d_entry;
	struct dlg_cell *dlg;
	str *p1;
	str *p2;
	unsigned int h_entry;

	node = cmd_tree->node.kids;
	if (node == NULL) {
		/* no parameters at all */
		*dlg_p = NULL;
		*idx = *cnt = 0;
		return NULL;
	}

	/* we have params -> get p1 and p2 */
	p1 = &node->value;
	LM_DBG("p1='%.*s'\n", p1->len, p1->s);

	node = node->next;
	if ( !node || !node->value.s || !node->value.len) {
		p2 = NULL;
	} else {
		p2 = &node->value;
		LM_DBG("p2='%.*s'\n", p2->len, p2->s);
		if ( node->next!=NULL )
			return init_mi_tree( 400, MI_SSTR(MI_MISSING_PARM));
	}

	/* check the params */
	if (p2 && str2int(p1,idx)==0 && str2int(p2,cnt)==0) {
		/* 2 numerical params -> index and counter */
		*dlg_p = NULL;
		return NULL;
	}

	*idx = *cnt = 0;

        if (!p1->s)
                return init_mi_tree( 400, "Invalid Call-ID specified", 25);

	h_entry = dlg_hash( p1/*callid*/ );

	d_entry = &(d_table->entries[h_entry]);
	dlg_lock( d_table, d_entry);

	for( dlg = d_entry->first ; dlg ; dlg = dlg->next ) {
		if (match_downstream_dialog( dlg, p1/*callid*/, p2/*from_tag*/)==1) {
			if (dlg->state==DLG_STATE_DELETED) {
				*dlg_p = NULL;
				break;
			} else {
				*dlg_p = dlg;
				return 0;
			}
		}
	}
	dlg_unlock( d_table, d_entry);

	return init_mi_tree( 404, MI_SSTR("No such dialog"));
}


struct mi_root * mi_print_dlgs(struct mi_root *cmd_tree, void *param )
{
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl = NULL;
	struct dlg_cell* dlg = NULL;
	unsigned int idx = 0;
	unsigned int cnt = 0;

	rpl_tree = process_mi_params( cmd_tree, &dlg, &idx, &cnt);
	if (rpl_tree)
		/* param error - no dialog returned */
		return rpl_tree;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		goto error;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	if (dlg==NULL) {
		if ( internal_mi_print_dlgs(rpl_tree, rpl, 0, idx, cnt)!=0 )
			goto error;
	} else {
		if ( internal_mi_print_dlg(rpl,dlg,0)!=0 )
			goto error;
		/* done with the dialog -> unlock it */
		dlg_unlock_dlg(dlg);
	}

	return rpl_tree;
error:
	/* if a dialog ref was returned, unlock it now */
	if (dlg) dlg_unlock_dlg(dlg);
	/* trash everything that was built so far */
	if (rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}


struct mi_root * mi_print_dlgs_ctx(struct mi_root *cmd_tree, void *param )
{
	struct mi_root* rpl_tree= NULL;
	struct mi_node* rpl = NULL;
	struct dlg_cell* dlg = NULL;
	unsigned int idx = 0;
	unsigned int cnt = 0;

	rpl_tree = process_mi_params( cmd_tree, &dlg, &idx, &cnt);
	if (rpl_tree)
		/* param error */
		return rpl_tree;

	rpl_tree = init_mi_tree( 200, MI_SSTR(MI_OK));
	if (rpl_tree==0)
		goto error;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	if (dlg==NULL) {
		if ( internal_mi_print_dlgs(rpl_tree, rpl, 1, idx, cnt)!=0 )
			goto error;
	} else {
		if ( internal_mi_print_dlg(rpl,dlg,1)!=0 )
			goto error;
		/* done with the dialog -> unlock it */
		dlg_unlock_dlg(dlg);
	}

	return rpl_tree;
error:
	/* if a dialog ref was returned, unlock it now */
	if (dlg) dlg_unlock_dlg(dlg);
	/* trash everything that was built so far */
	if (rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}



