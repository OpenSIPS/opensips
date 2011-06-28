/*
 * $Id$
 *
 * Copyright (C) 2007-2009 Voice System SRL
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
 * 2007-07-10  initial version (ancuta)
 * 2008-04-04  added direction reporting in dlg callbacks (bogdan)
 * 2009-09-09  support for early dialogs added; proper handling of cseq
 *             while PRACK is used (bogdan)
*/

#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../config.h"
#include "../../socket_info.h"
#include "../../parser/parse_methods.h"
#include "../tm/dlg.h"
#include "../tm/tm_load.h"
#include "../../mi/tree.h"
#include "dlg_hash.h"
#include "dlg_req_within.h"
#include "dlg_db_handler.h"
#include "dlg_profile.h"



#define MAX_FWD_HDR        "Max-Forwards: " MAX_FWD CRLF
#define MAX_FWD_HDR_LEN    (sizeof(MAX_FWD_HDR) - 1)

extern str dlg_extra_hdrs;

int free_tm_dlg(dlg_t *td)
{
	if(td)
	{
		if(td->route_set)
			free_rr(&td->route_set);
		pkg_free(td);
	}
	return 0;
}

dlg_t * build_dlg_t(struct dlg_cell * cell, int dst_leg, int src_leg)
{
	dlg_t* td = NULL;
	str cseq;
	unsigned int loc_seq;

	td = (dlg_t*)pkg_malloc(sizeof(dlg_t));
	if(!td){
		LM_ERR("out of pkg memory\n");
		return NULL;
	}
	memset(td, 0, sizeof(dlg_t));

	if ((dst_leg == DLG_CALLER_LEG && (cell->flags & DLG_FLAG_PING_CALLER)) ||
		(dst_leg == callee_idx(cell) && (cell->flags & DLG_FLAG_PING_CALLEE)))
	{
		dlg_lock_dlg(cell);
		if (cell->legs[dst_leg].last_gen_cseq == 0)
		{
			/* no OPTIONS pings for this dlg yet */
			dlg_unlock_dlg(cell);
			goto before_strcseq;
		}
		else
		{
			/* OPTIONS pings sent, use new cseq */
			td->loc_seq.value = ++(cell->legs[dst_leg].last_gen_cseq);
			td->loc_seq.is_set=1;
			dlg_unlock_dlg(cell);
			goto after_strcseq;
		}
	}
before_strcseq:
	/*local sequence number*/
	cseq = cell->legs[dst_leg].r_cseq;
	if( !cseq.s || !cseq.len || str2int(&cseq, &loc_seq) != 0){
		LM_ERR("invalid cseq\n");
		goto error;
	}
	/*we don not increase here the cseq as this will be done by TM*/
	td->loc_seq.value = loc_seq;
	td->loc_seq.is_set = 1;

after_strcseq:

	/*route set*/
	if( cell->legs[dst_leg].route_set.s && cell->legs[dst_leg].route_set.len){
		if( parse_rr_body(cell->legs[dst_leg].route_set.s,
			cell->legs[dst_leg].route_set.len, &td->route_set) !=0){
		 	LM_ERR("failed to parse route set\n");
			goto error;
		}
	} 

	/*remote target--- Request URI*/
	if (cell->legs[dst_leg].contact.s==0 || cell->legs[dst_leg].contact.len==0){
		LM_ERR("no contact available\n");
		goto error;
	}
	td->rem_target = cell->legs[dst_leg].contact;

	td->rem_uri = (dst_leg==DLG_CALLER_LEG)? *dlg_leg_from_uri(cell,dst_leg): 
					 *dlg_leg_to_uri(cell,dst_leg);
	td->loc_uri = (dst_leg==DLG_CALLER_LEG)? *dlg_leg_to_uri(cell,dst_leg):
					 *dlg_leg_from_uri(cell,dst_leg);
	td->id.call_id = cell->callid;
	td->id.rem_tag = cell->legs[dst_leg].tag;
	td->id.loc_tag = cell->legs[src_leg].tag;

	td->state= DLG_CONFIRMED;
	td->send_sock = cell->legs[dst_leg].bind_addr;

	return td;

error:
	free_tm_dlg(td);
	return NULL;
}



dlg_t * build_dialog_info(struct dlg_cell * cell, int dst_leg, int src_leg)
{
	dlg_t* td = NULL;
	str cseq;
	unsigned int loc_seq;
	struct dlg_entry *d_entry = &(d_table->entries[cell->h_entry]);

	td = (dlg_t*)pkg_malloc(sizeof(dlg_t));
	if(!td){
		LM_ERR("out of pkg memory\n");
		return NULL;
	}
	memset(td, 0, sizeof(dlg_t));

	/*local sequence number*/
	cseq = cell->legs[dst_leg].r_cseq;
	if( !cseq.s || !cseq.len || str2int(&cseq, &loc_seq) != 0){
		LM_ERR("invalid cseq\n");
		goto error;
	}

	dlg_lock( d_table, d_entry);

	if (cell->legs[dst_leg].last_gen_cseq == 0)
		cell->legs[dst_leg].last_gen_cseq = loc_seq+1;
	else
		cell->legs[dst_leg].last_gen_cseq++;

	cell->legs[dst_leg].reply_received = 0;

	td->loc_seq.value = cell->legs[dst_leg].last_gen_cseq -1;
	dlg_unlock( d_table, d_entry);
	td->loc_seq.is_set = 1;

	/*route set*/
	if( cell->legs[dst_leg].route_set.s && cell->legs[dst_leg].route_set.len){
		if( parse_rr_body(cell->legs[dst_leg].route_set.s,
			cell->legs[dst_leg].route_set.len, &td->route_set) !=0){
		 	LM_ERR("failed to parse route set\n");
			goto error;
		}
	} 

	/*remote target--- Request URI*/
	if (cell->legs[dst_leg].contact.s==0 || cell->legs[dst_leg].contact.len==0){
		LM_ERR("no contact available\n");
		goto error;
	}
	td->rem_target = cell->legs[dst_leg].contact;

	td->rem_uri = (dst_leg==DLG_CALLER_LEG)? *dlg_leg_from_uri(cell,dst_leg): 
					 *dlg_leg_to_uri(cell,dst_leg);
	td->loc_uri = (dst_leg==DLG_CALLER_LEG)? *dlg_leg_to_uri(cell,dst_leg):
					 *dlg_leg_from_uri(cell,dst_leg);
	td->id.call_id = cell->callid;
	td->id.rem_tag = cell->legs[dst_leg].tag;
	td->id.loc_tag = cell->legs[src_leg].tag;

	td->state= DLG_CONFIRMED;
	td->send_sock = cell->legs[dst_leg].bind_addr;

	return td;

error:
	free_tm_dlg(td);
	return NULL;
}


static void dual_bye_event(struct dlg_cell* dlg, struct sip_msg *req, int extra_unref)
{
	int event, old_state, new_state, unref, ret;

	event = DLG_EVENT_REQBYE;
	next_state_dlg(dlg, event, &old_state, &new_state, &unref);
	unref += extra_unref;

	if(new_state == DLG_STATE_DELETED && old_state != DLG_STATE_DELETED){
		
		LM_DBG("removing dialog with h_entry %u and h_id %u\n",
			dlg->h_entry, dlg->h_id);

		/*destroy linkers */
		destroy_linkers(dlg->profile_links);
		dlg->profile_links = NULL;

		/* remove from timer */
		ret = remove_dlg_timer(&dlg->tl);
		if (ret < 0) {
			LM_CRIT("unable to unlink the timer on dlg %p [%u:%u] "
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",
				dlg, dlg->h_entry, dlg->h_id,
				dlg->callid.len, dlg->callid.s,
				dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
				dlg_leg_print_info( dlg, callee_idx(dlg), tag));
		} else if (ret > 0) {
			LM_DBG("dlg already expired (not in timer list) %p [%u:%u] "
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",
				dlg, dlg->h_entry, dlg->h_id,
				dlg->callid.len, dlg->callid.s,
				dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
				dlg_leg_print_info( dlg, callee_idx(dlg), tag));
		} else {
			/* successfully removed from timer list */
			unref++;
		}

		if (remove_ping_timer(dlg) == 0)
			unref++;

		/* dialog terminated (BYE) */
		run_dlg_callbacks( DLGCB_TERMINATED, dlg, req, DLG_DIR_NONE, 0);

		LM_DBG("first final reply\n");
		/* derefering the dialog */
		unref_dlg(dlg, unref);

		if_update_stat( dlg_enable_stats, active_dlgs, -1);
	}

	if(new_state == DLG_STATE_DELETED && old_state == DLG_STATE_DELETED ) {
		/* trash the dialog from DB and memory */
		LM_DBG("second final reply\n");
		/* delete the dialog from DB */
		if (should_remove_dlg_db())
			remove_dialog_from_db(dlg);
		/* force delete from mem */
		unref_dlg(dlg, unref);
	}
}


/*callback function to handle responses to the BYE request */
void bye_reply_cb(struct cell* t, int type, struct tmcb_params* ps)
{
	if(ps->param == NULL || *ps->param == NULL){
		LM_ERR("invalid parameter\n");
		return;
	}

	if(ps->code < 200){
		LM_DBG("receiving a provisional reply\n");
		return;
	}

	LM_DBG("receiving a final reply %d\n",ps->code);

	dual_bye_event( (struct dlg_cell *)(*(ps->param)), ps->req, 1);
}


static inline int build_extra_hdr(struct dlg_cell * cell, str *extra_hdrs,
																str *str_hdr)
{
	char *p;

	str_hdr->len = MAX_FWD_HDR_LEN + dlg_extra_hdrs.len + 
		(extra_hdrs?extra_hdrs->len:0);

	str_hdr->s = (char*)pkg_malloc( str_hdr->len * sizeof(char) );
	if(!str_hdr->s){
		LM_ERR("out of pkg memory\n");
		goto error;
	}

	memcpy(str_hdr->s , MAX_FWD_HDR, MAX_FWD_HDR_LEN );
	p = str_hdr->s + MAX_FWD_HDR_LEN;
	if (dlg_extra_hdrs.len) {
		memcpy( p, dlg_extra_hdrs.s, dlg_extra_hdrs.len);
		p += dlg_extra_hdrs.len;
	}
	if (extra_hdrs) {
		memcpy( p, extra_hdrs->s, extra_hdrs->len);
		p += extra_hdrs->len;
	}

	if (str_hdr->len != p-str_hdr->s )
		LM_CRIT("BUG in computing extra hdrs: computed len = %d ;"
			" build len = %d",str_hdr->len,(int)(long)(p-str_hdr->s) );

	return 0;

error: 
	return -1;
}


/* cell- pointer to a struct dlg_cell
 * leg - a dialog leg to be BYE'ed :
 *     = 0: caller leg
 *     > 0: callee legs
 */
static inline int send_leg_bye(struct dlg_cell *cell, int dst_leg, int src_leg,
														str *extra_hdrs)
{
	dlg_t* dialog_info;
	struct dlg_cell *old_cell;
	str met = {"BYE", 3};
	int result;

	if ((dialog_info = build_dlg_t(cell, dst_leg, src_leg)) == 0){
		LM_ERR("failed to create dlg_t\n");
		goto err;
	}

	LM_DBG("sending BYE to %s (%d)\n",
		(dst_leg==DLG_CALLER_LEG)?"caller":"callee", dst_leg);

	ref_dlg(cell, 1);

	old_cell = current_dlg_pointer;
	current_dlg_pointer = cell;

	result = d_tmb.t_request_within
		(&met,         /* method*/
		extra_hdrs,    /* extra headers*/
		NULL,          /* body*/
		dialog_info,   /* dialog structure*/
		bye_reply_cb,  /* callback function*/
		(void*)cell,   /* callback parameter*/
		NULL);         /* release function*/

	current_dlg_pointer = old_cell;

	if(result < 0){
		LM_ERR("failed to send the BYE request\n");
		goto err1;
	}

	free_tm_dlg(dialog_info);

	LM_DBG("BYE sent to %s\n", (dst_leg==DLG_CALLER_LEG)?"caller":"callee");
	return 0;

err1:
	unref_dlg(cell, 1);
err:
	return -1;
}


/* sends BYE in both directions
 * returns 0 if both BYEs were successful
 */
int dlg_end_dlg(struct dlg_cell *dlg, str *extra_hdrs)
{
	str str_hdr = {NULL,0};
	int i,res = 0;
	int callee;

	/* lookup_dlg has incremented the reference count !! */
	if (dlg->state == DLG_STATE_UNCONFIRMED || dlg->state == DLG_STATE_EARLY) {
		LM_DBG("cannot terminate a dialog in EARLY or UNCONFIRMED state\n");
		return 0;
	}

	if ((build_extra_hdr(dlg, extra_hdrs, &str_hdr)) != 0){
		LM_ERR("failed to create extra headers\n");
		return -1;
	}

	callee = callee_idx(dlg);
	if ( send_leg_bye( dlg, DLG_CALLER_LEG, callee, &str_hdr)!=0) {
		res--;
	}
	if (send_leg_bye( dlg, callee, DLG_CALLER_LEG, &str_hdr)!=0 ) {
		res--;
	}

	for( i=res ; i<0 ; i++)
		dual_bye_event( dlg, NULL, 0);

	pkg_free(str_hdr.s);
	return res;
}

/*parameters from MI: h_entry, h_id of the requested dialog*/
struct mi_root * mi_terminate_dlg(struct mi_root *cmd_tree, void *param ){

	struct mi_node* node;
	unsigned int h_entry, h_id;
	struct dlg_cell * dlg = NULL;
	str *mi_extra_hdrs = NULL;
	int status, msg_len;
	char *msg;


	if( d_table ==NULL)
		goto end;

	node = cmd_tree->node.kids;
	h_entry = h_id = 0;

	if (node==NULL || node->next==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s|| !node->value.len|| strno2int(&node->value,&h_entry)<0)
		goto error;

	node = node->next;
	if ( !node->value.s || !node->value.len || strno2int(&node->value,&h_id)<0)
		goto error;

	if (node->next) {
		node = node->next;
		if (node->value.len && node->value.s)
			mi_extra_hdrs = &node->value;
	}

	LM_DBG("h_entry %u h_id %u\n", h_entry, h_id);

	dlg = lookup_dlg(h_entry, h_id);

	/* lookup_dlg has incremented the reference count !! */

	if(dlg){
		if ( dlg_end_dlg( dlg, mi_extra_hdrs) ) {
			status = 500;
			msg = MI_DLG_OPERATION_ERR;
			msg_len = MI_DLG_OPERATION_ERR_LEN;
		} else {
			status = 200;
			msg = MI_OK_S;
			msg_len = MI_OK_LEN;
		}

		unref_dlg(dlg, 1);

		return init_mi_tree(status, msg, msg_len);
	}

end:
	return init_mi_tree(404, MI_DIALOG_NOT_FOUND, MI_DIALOG_NOT_FOUND_LEN);
	
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

}

int send_leg_msg(struct dlg_cell *dlg,str *method,int src_leg,int dst_leg,
		str *hdrs,str *body,dlg_request_callback func,void *param,dlg_release_func release)
{
	dlg_t* dialog_info;
	struct dlg_cell *old_cell;
	int result;
	unsigned int method_type;

	if (parse_method(method->s,method->s+method->len,&method_type) == 0)
	{
		LM_ERR("Failed to parse method - [%.*s]\n",method->len,method->s);
		return -1;
	}

	if (method_type == METHOD_INVITE && (body == NULL || body->s == NULL ||
				body->len == 0))
	{
		LM_ERR("Cannot send INVITE without SDP body\n");
		return -1;
	}

	if ((dialog_info = build_dialog_info(dlg, dst_leg, src_leg)) == 0)
	{
		LM_ERR("failed to create dlg_t\n");
		return -1;
	}

	LM_DBG("sending [%.*s] to %s (%d)\n",method->len,method->s,
		(dst_leg==DLG_CALLER_LEG)?"caller":"callee", dst_leg);

	old_cell = current_dlg_pointer;
	current_dlg_pointer = dlg;

	dialog_info->T_flags=T_NO_AUTOACK_FLAG;

	result = d_tmb.t_request_within
		(method,         /* method*/
		hdrs,		    /* extra headers*/
		body,          /* body*/
		dialog_info,   /* dialog structure*/
		func,  /* callback function*/
		param,   /* callback parameter*/
		release);         /* release function*/

	current_dlg_pointer = old_cell;

	if(result < 0)
	{
		LM_ERR("failed to send the in-dialog request\n");
		free_tm_dlg(dialog_info);
		return -1;
	}

	free_tm_dlg(dialog_info);
	return 0;
}
