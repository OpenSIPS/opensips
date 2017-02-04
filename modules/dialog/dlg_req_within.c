/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "dlg_handlers.h"


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
		(dst_leg == callee_idx(cell) && (cell->flags & DLG_FLAG_PING_CALLEE)) || 
		(dst_leg == DLG_CALLER_LEG && (cell->flags & DLG_FLAG_REINVITE_PING_CALLER)) ||
		(dst_leg == callee_idx(cell) && (cell->flags & DLG_FLAG_REINVITE_PING_CALLEE)) || 
		cell->flags & DLG_FLAG_CSEQ_ENFORCE)
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

	/* link the dialog cell here - it will eventually be linked
	 * within the upcoming created transaction */
	td->dialog_ctx = cell;

	return td;

error:
	free_tm_dlg(td);
	return NULL;
}



dlg_t * build_dialog_info(struct dlg_cell * cell, int dst_leg, int src_leg,char *reply_marker)
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

	/*local sequence number*/
	cseq = cell->legs[dst_leg].r_cseq;
	if( !cseq.s || !cseq.len || str2int(&cseq, &loc_seq) != 0){
		LM_ERR("invalid cseq\n");
		goto error;
	}

	if (cell->legs[dst_leg].last_gen_cseq == 0)
		cell->legs[dst_leg].last_gen_cseq = loc_seq+1;
	else
		cell->legs[dst_leg].last_gen_cseq++;

	*reply_marker = DLG_PING_PENDING;

	td->loc_seq.value = cell->legs[dst_leg].last_gen_cseq -1;

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

	/* link the dialog cell here - it will eventually be linked
	 * within the upcoming created transaction */
	td->dialog_ctx = cell;

	return td;

error:
	free_tm_dlg(td);
	return NULL;
}


static void dual_bye_event(struct dlg_cell* dlg, struct sip_msg *req, int extra_unref)
{
	int event, old_state, new_state, unref, ret;
	struct sip_msg *fake_msg=NULL;
	context_p old_ctx;
	context_p *new_ctx;

	event = DLG_EVENT_REQBYE;
	next_state_dlg(dlg, event, DLG_DIR_DOWNSTREAM, &old_state, &new_state,
			&unref, dlg->legs_no[DLG_LEG_200OK], 0);
	unref += extra_unref;

	if(new_state == DLG_STATE_DELETED && old_state != DLG_STATE_DELETED){

		LM_DBG("removing dialog with h_entry %u and h_id %u\n",
			dlg->h_entry, dlg->h_id);

		/*destroy linkers */
		dlg_lock_dlg(dlg);
		destroy_linkers(dlg->profile_links, 0);
		dlg->profile_links = NULL;
		dlg_unlock_dlg(dlg);

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

		if (req==NULL) {
			/* set new msg & processing context */
			if (push_new_processing_context( dlg, &old_ctx, &new_ctx, &fake_msg)==0) {
				/* dialog terminated (BYE) */
				run_dlg_callbacks( DLGCB_TERMINATED, dlg, fake_msg,
					DLG_DIR_NONE, NULL, 0);
				/* reset the processing context */
				if (current_processing_ctx == NULL)
					*new_ctx = NULL;
				else
					context_destroy(CONTEXT_GLOBAL, *new_ctx);
				current_processing_ctx = old_ctx;
			} /* no CB run in case of failure FIXME */
		} else {
			/* we should have the msg and context from upper levels */
			/* dialog terminated (BYE) */
			run_dlg_callbacks( DLGCB_TERMINATED, dlg, req,
				DLG_DIR_NONE, NULL, 0);
		}

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
	/* mark the transaction as belonging to this dialog */
	t->dialog_ctx = *(ps->param);

	dual_bye_event( (struct dlg_cell *)(*(ps->param)), ps->req, 1);
}


static inline int build_extra_hdr(struct dlg_cell * cell, str *extra_hdrs,
																str *str_hdr)
{
	char *p;

	str_hdr->len = dlg_extra_hdrs.len +
		(extra_hdrs?extra_hdrs->len:0);

	str_hdr->s = (char*)pkg_malloc( str_hdr->len * sizeof(char) );
	if(!str_hdr->s){
		LM_ERR("out of pkg memory\n");
		goto error;
	}

	p = str_hdr->s;
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
	context_p old_ctx;
	context_p *new_ctx;
	dlg_t* dialog_info;
	str met = {"BYE", 3};
	int result;

	if ((dialog_info = build_dlg_t(cell, dst_leg, src_leg)) == 0){
		LM_ERR("failed to create dlg_t\n");
		goto err;
	}

	LM_DBG("sending BYE to %s (%d)\n",
		(dst_leg==DLG_CALLER_LEG)?"caller":"callee", dst_leg);

	/* set new processing context */
	if (push_new_processing_context( cell, &old_ctx, &new_ctx, NULL)!=0)
		goto err;

	ctx_lastdstleg_set(dst_leg);

	ref_dlg(cell, 1);

	result = d_tmb.t_request_within
		(&met,         /* method*/
		extra_hdrs,    /* extra headers*/
		NULL,          /* body*/
		dialog_info,   /* dialog structure*/
		bye_reply_cb,  /* callback function*/
		(void*)cell,   /* callback parameter*/
		NULL);         /* release function*/

	/* reset the processing contect */
	if (current_processing_ctx == NULL)
		*new_ctx = NULL;
	else
		context_destroy(CONTEXT_GLOBAL, *new_ctx);
	current_processing_ctx = old_ctx;

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
	struct cell* t;
	int i,res = 0;
	int callee;

	/* lookup_dlg has incremented the reference count !! */
	if (dlg->state == DLG_STATE_UNCONFIRMED || dlg->state == DLG_STATE_EARLY) {
		/* locate initial transaction */
		LM_DBG("trying to find transaction with hash_index = %u and label = %u\n",
				dlg->initial_t_hash_index,dlg->initial_t_label);
		if (d_tmb.t_lookup_ident(&t,dlg->initial_t_hash_index,dlg->initial_t_label) < 0) {
			LM_ERR("Initial transaction does not exist any more\n");
			return -1;
		}

		if (d_tmb.t_cancel_trans(t,NULL) < 0) {
			LM_ERR("Failed to send cancels\n");
			d_tmb.unref_cell(t);
			return -1;
		}

		/* lookup_ident refs the transaction */
		d_tmb.unref_cell(t);
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

/*parameters from MI: dialog ID of the requested dialog*/
struct mi_root * mi_terminate_dlg(struct mi_root *cmd_tree, void *param ){

	struct mi_node* node;
	unsigned int h_entry, h_id;
	unsigned long long d_id;
	struct dlg_cell * dlg = NULL;
	str *mi_extra_hdrs = NULL;
	str dialog_id;
	int status, msg_len;
	char *msg;
	char *end;
	char bkp;


	if( d_table ==NULL)
		goto end;

	node = cmd_tree->node.kids;
	h_entry = h_id = 0;

	if (node==NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	/* parse first param as long long (dialog_id ) */
	if ( node->value.s==NULL || node->value.len==0 )
		goto error;
	dialog_id = node->value;

	/* second param (optional) is the extra hdrs */
	if (node->next) {
		node = node->next;
		if (node->value.len && node->value.s)
			mi_extra_hdrs = &node->value;
	}

	/* Get the dialog based of the dialog_id. This may be a
	 * numerical DID or a string SIP Call-ID */

	/* make value null terminated (in an ugly way) */
	bkp = dialog_id.s[dialog_id.len];
	dialog_id.s[dialog_id.len] = 0;
	/* conver to long long */
	d_id = strtoll( dialog_id.s, &end, 10);
	dialog_id.s[dialog_id.len] = bkp;
	if (end-dialog_id.s==dialog_id.len) {
		/* the ID is numeric, so let's consider it DID */
		h_entry = (unsigned int)(d_id>>(8*sizeof(int)));
		h_id = (unsigned int)(d_id &
			(((unsigned long long)1<<(8*sizeof(int)))-1) );
		LM_DBG("ID: %llu (h_entry %u h_id %u)\n", d_id, h_entry, h_id);
		dlg = lookup_dlg(h_entry, h_id);
	} else {
		/* the ID is not a number, so let's consider
		 * the value a SIP call-id */
		LM_DBG("Call-ID: <%.*s>\n", dialog_id.len, dialog_id.s);
		dlg = get_dlg_by_callid( &dialog_id );
	}

	if (dlg) {
		/* lookup_dlg has incremented the reference count !! */
		init_dlg_term_reason(dlg,"MI Termination",sizeof("MI Termination")-1);

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
	str *hdrs,str *body,dlg_request_callback func,
	void *param,dlg_release_func release,char *reply_marker)
{
	context_p old_ctx;
	context_p *new_ctx;
	dlg_t* dialog_info;
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

	if ((dialog_info = build_dialog_info(dlg, dst_leg, src_leg,reply_marker)) == 0)
	{
		LM_ERR("failed to create dlg_t\n");
		return -1;
	}

	LM_DBG("sending [%.*s] to %s (%d)\n",method->len,method->s,
		(dst_leg==DLG_CALLER_LEG)?"caller":"callee", dst_leg);

	/* set new processing context */
	if (push_new_processing_context( dlg, &old_ctx, &new_ctx, NULL)!=0)
		return -1;

	//dialog_info->T_flags=T_NO_AUTOACK_FLAG;

	result = d_tmb.t_request_within
		(method,         /* method*/
		hdrs,		    /* extra headers*/
		body,          /* body*/
		dialog_info,   /* dialog structure*/
		func,  /* callback function*/
		param,   /* callback parameter*/
		release);         /* release function*/

	/* reset the processing contect */
	if (current_processing_ctx == NULL)
		*new_ctx = NULL;
	else
		context_destroy(CONTEXT_GLOBAL, *new_ctx);
	current_processing_ctx = old_ctx;

	if(result < 0)
	{
		LM_ERR("failed to send the in-dialog request\n");
		free_tm_dlg(dialog_info);
		return -1;
	}

	free_tm_dlg(dialog_info);
	return 0;
}
