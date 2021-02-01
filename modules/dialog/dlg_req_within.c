/*
 * Copyright (C) 2008-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "../../ipc.h"
#include "dlg_hash.h"
#include "dlg_req_within.h"
#include "dlg_db_handler.h"
#include "dlg_profile.h"
#include "dlg_handlers.h"
#include "dlg_replication.h"

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

	dlg_lock_dlg(cell);
	if (cell->legs[dst_leg].last_gen_cseq != 0)
	{
		/* OPTIONS pings sent, use new cseq */
		td->loc_seq.value = ++(cell->legs[dst_leg].last_gen_cseq);
		td->loc_seq.is_set=1;
		dlg_unlock_dlg(cell);
		goto after_strcseq;
	}

	dlg_unlock_dlg(cell);
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



dlg_t * build_dialog_info(struct dlg_cell * cell, int dst_leg, int src_leg,
	char *reply_marker, int inc_cseq)
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

	loc_seq = cell->legs[dst_leg].last_gen_cseq;

	if (loc_seq == 0) {
		/*local sequence number*/
		cseq = cell->legs[dst_leg].r_cseq;
		if( !cseq.s || !cseq.len || str2int(&cseq, &loc_seq) != 0){
			LM_ERR("invalid cseq\n");
			goto error;
		}

		cell->legs[dst_leg].last_gen_cseq = loc_seq+1;
	} else if (inc_cseq)
		cell->legs[dst_leg].last_gen_cseq++;

	if (reply_marker)
		*reply_marker = DLG_PING_PENDING;

	td->loc_seq.value = loc_seq;

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


static void dual_bye_event(struct dlg_cell* dlg, struct sip_msg *req,
																int is_active)
{
	int event, old_state, new_state, unref, ret;
	struct sip_msg *fake_msg=NULL;
	context_p old_ctx;
	context_p *new_ctx;

	event = DLG_EVENT_REQBYE;
	next_state_dlg(dlg, event, DLG_DIR_DOWNSTREAM, &old_state, &new_state,
			&unref, dlg->legs_no[DLG_LEG_200OK], is_active);

	if(new_state == DLG_STATE_DELETED && old_state != DLG_STATE_DELETED){

		LM_DBG("removing dialog with h_entry %u and h_id %u\n",
			dlg->h_entry, dlg->h_id);

		if (dlg->rt_on_hangup)
			run_dlg_script_route( dlg, dlg->rt_on_hangup);

		/*destroy linkers */
		destroy_linkers(dlg);
		remove_dlg_prof_table(dlg,is_active);

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
					DLG_DIR_NONE, NULL, 0, is_active);
				/* reset the processing context */
				if (current_processing_ctx == NULL)
					*new_ctx = NULL;
				else
					context_destroy(CONTEXT_GLOBAL, *new_ctx);
				current_processing_ctx = old_ctx;
				release_dummy_sip_msg(fake_msg);
			} /* no CB run in case of failure FIXME */
		} else {
			/* we should have the msg and context from upper levels */
			/* dialog terminated (BYE) */
			run_dlg_callbacks( DLGCB_TERMINATED, dlg, req,
				DLG_DIR_NONE, NULL, 0, is_active);
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

	LM_DBG("receiving a final reply %d for transaction %p, dialog %p\n",
		ps->code, t, (*(ps->param)));
	/* mark the transaction as belonging to this dialog */
	t->dialog_ctx = *(ps->param);

	dual_bye_event((struct dlg_cell *)(*(ps->param)), ps->req, 1);
}


void bye_reply_cb_release(void *param)
{
	unref_dlg( (struct dlg_cell *)(param), 1);
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

	LM_DBG("sending BYE on dialog %p to %s (%d)\n",
		cell, (dst_leg==DLG_CALLER_LEG)?"caller":"callee", dst_leg);

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
		bye_reply_cb_release);         /* release function*/

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

struct dlg_end_params {
	struct dlg_cell *dlg;
	str hdrs;
};

static int dlg_send_dual_bye(struct dlg_cell *dlg, str *headers)
{
	int i,res = 0;
	int callee;

	callee = callee_idx(dlg);
	if (send_leg_bye(dlg, DLG_CALLER_LEG, callee, headers)!=0) {
		res--;
	}
	if (send_leg_bye(dlg, callee, DLG_CALLER_LEG, headers)!=0 ) {
		res--;
	}

	for(i=res ; i<0 ; i++)
		dual_bye_event(dlg, NULL, 1);

	return res;
}

static void dlg_end_rpc(int sender, void *param)
{
	struct dlg_end_params *params = (struct dlg_end_params *)param;
	dlg_send_dual_bye(params->dlg, &params->hdrs);
	unref_dlg(params->dlg, 1);
	shm_free(params);
}

/* sends BYE in both directions
 * returns 0 if both BYEs were successful
 */
int dlg_end_dlg(struct dlg_cell *dlg, str *extra_hdrs, int send_byes)
{
	struct dlg_end_params *params;
	str str_hdr = {NULL,0};
	struct cell* t;
	int res = -1;

	if (!send_byes) {
		dual_bye_event(dlg, NULL, 0);
		dual_bye_event(dlg, NULL, 0);
		return 0;
	}

	/* lookup_dlg has incremented the reference count !! */
	if ((dlg->state == DLG_STATE_UNCONFIRMED || dlg->state == DLG_STATE_EARLY)) {
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

	if (build_extra_hdr(dlg, extra_hdrs, &str_hdr) != 0) {
		LM_ERR("failed to create extra headers\n");
		return -1;
	}

	if (!sroutes) {
		params = shm_malloc(sizeof(struct dlg_end_params) + str_hdr.len);
		if (!params) {
			LM_ERR("could not create dlg end params!\n");
			goto end;
		}
		params->hdrs.s = (char *)(params + 1);
		params->hdrs.len = str_hdr.len;
		memcpy(params->hdrs.s, str_hdr.s, str_hdr.len);
		ref_dlg(dlg, 1);
		params->dlg = dlg;

		if (ipc_dispatch_rpc(dlg_end_rpc, params) < 0) {
			LM_ERR("could not dispatch dlg end job!\n");
			goto end;
		}
		res = 0;
	} else
		res = dlg_send_dual_bye(dlg, &str_hdr);

end:
	if (str_hdr.s)
		pkg_free(str_hdr.s);

	return res;
}

/*parameters from MI: dialog ID of the requested dialog*/
mi_response_t *mi_terminate_dlg(const mi_params_t *params, str *extra_hdrs)
{
	struct dlg_cell * dlg = NULL;
	str dialog_id;
	int shtag_state = 1;

	if( d_table ==NULL)
		return init_mi_error(404, MI_SSTR(MI_DIALOG_NOT_FOUND));

	if (get_mi_string_param(params, "dialog_id", &dialog_id.s, &dialog_id.len) < 0)
		return init_mi_param_error();

	/* Get the dialog based of the dialog_id. This may be a
	 * numerical DID or a string SIP Call-ID */

	dlg = get_dlg_by_dialog_id(&dialog_id);
	if (dlg) {
		if (dialog_repl_cluster) {
			shtag_state = get_shtag_state(dlg);
			if (shtag_state == -1) {
				unref_dlg(dlg, 1);
				return init_mi_error(403, MI_SSTR(MI_DLG_OPERATION_ERR));
			} else if (shtag_state == 0) {
				unref_dlg(dlg, 1);
				return init_mi_error(403, MI_SSTR(MI_DIALOG_BACKUP_ERR));
			}
		}

		/* lookup_dlg has incremented the reference count !! */
		init_dlg_term_reason(dlg,"MI Termination",sizeof("MI Termination")-1);

		if (dlg_end_dlg(dlg, extra_hdrs, 1)) {
			unref_dlg(dlg, 1);
			return init_mi_error(500, MI_SSTR(MI_DLG_OPERATION_ERR));
		} else {
			unref_dlg(dlg, 1);
			return init_mi_result_ok();
		}
	}

	return init_mi_error(404, MI_SSTR(MI_DIALOG_NOT_FOUND));
}

mi_response_t *mi_terminate_dlg_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_terminate_dlg(params, 0);
}

mi_response_t *mi_terminate_dlg_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str extra_hdrs;

	if (get_mi_string_param(params, "extra_hdrs",
		&extra_hdrs.s, &extra_hdrs.len) < 0)
		return init_mi_param_error();

	return mi_terminate_dlg(params, &extra_hdrs);
}

int send_leg_msg(struct dlg_cell *dlg,str *method,int src_leg,int dst_leg,
	str *hdrs,str *body,dlg_request_callback func,
	void *param,dlg_release_func release,char *reply_marker)
{
	context_p old_ctx;
	context_p *new_ctx;
	dlg_t* dialog_info;
	int result;
	/*
	unsigned int method_type;

	if (parse_method(method->s,method->s+method->len,&method_type) == 0)
	{
		LM_ERR("Failed to parse method - [%.*s]\n",method->len,method->s);
		return -1;
	}

	 * we can send INVITEs with body for late negotiation
	if (method_type == METHOD_INVITE && (body == NULL || body->s == NULL ||
				body->len == 0))
	{
		LM_ERR("Cannot send INVITE without SDP body\n");
		return -1;
	}
	*/

	if ((dialog_info = build_dialog_info(dlg, dst_leg, src_leg,reply_marker,
		!(method->len == 3 && memcmp(method->s, "ACK", 3) == 0))) == 0)
	{
		LM_ERR("failed to create dlg_t\n");
		return -1;
	}

	LM_DBG("sending [%.*s] to %s (%d)\n",method->len,method->s,
		(dst_leg==DLG_CALLER_LEG)?"caller":"callee", dst_leg);

	/* set new processing context */
	if (push_new_processing_context( dlg, &old_ctx, &new_ctx, NULL)!=0)
		return -1;

	dialog_info->T_flags=T_NO_AUTOACK_FLAG;

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

	/* update the cseq, so we can be ready to generate other sequential
	 * messages on other nodes too */
	if (dialog_repl_cluster)
		replicate_dialog_cseq_updated(dlg, dst_leg);

	if(result < 0)
	{
		LM_ERR("failed to send the in-dialog request\n");
		free_tm_dlg(dialog_info);
		return -1;
	}

	free_tm_dlg(dialog_info);
	return 0;
}

enum  dlg_challenge { DLG_CHL_START, /* sent request */
	DLG_CHL_PENDING, /* challenge pending */
	DLG_CHL_DONE /* challenge ended */};


struct dlg_sequential_param {
	enum dlg_challenge state;
	char challenge;
	char ref;
	int leg;
	str method;
	struct dlg_cell *dlg;
	struct mi_handler *async;
};

void dlg_sequential_free(void *params)
{
	struct dlg_sequential_param *p = (struct dlg_sequential_param *)params;
	unref_dlg_destroy_safe(p->dlg, 1);
	p->ref--;
	if (p->ref == 0)
		shm_free(p);
}

static void dlg_async_response(struct dlg_sequential_param *p,
		struct sip_msg *rpl, int statuscode)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	char *reply_msg;

	if (p->state == DLG_CHL_DONE)
		return;

	if (rpl != FAKED_REPLY) {
		resp = init_mi_result_object(&resp_obj);
		if (add_mi_number(resp_obj, MI_SSTR("Code"), statuscode) < 0 ||
				add_mi_string(resp_obj, MI_SSTR("Reason"),
					rpl->first_line.u.reply.reason.s,
					rpl->first_line.u.reply.reason.len) < 0) {
			free_mi_response(resp);
			resp = 0;
		}
	} else {
		reply_msg = error_text(statuscode);
		resp = init_mi_error(statuscode, reply_msg, strlen(reply_msg));
	}
	p->state = DLG_CHL_DONE;
	p->async->handler_f(resp, p->async, 1);
}

static void dlg_sequential_reply(struct cell* t, int type, struct tmcb_params* ps)
{
	static str ct_hdr = str_init("application/sdp");
	int statuscode;
	struct sip_msg *rpl;
	struct dlg_cell *dlg;
	struct dlg_sequential_param *p;
	str body;
	str extra_headers;

	if (!ps || !ps->rpl) {
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if (!ps->param) {
			LM_ERR("NULL callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	p = (struct dlg_sequential_param *)(*ps->param);
	dlg = p->dlg;

	if (dlg_handle_seq_reply(dlg, rpl, statuscode, other_leg(dlg, p->leg),
	    (p->method.len == 6 && memcmp(p->method.s, "INVITE", 6) == 0)) < 0) {
		LM_ERR("Bad reply %d for callid %.*s\n",
				statuscode, dlg->callid.len,dlg->callid.s);
		dlg_async_response(p, rpl, statuscode);
		return;
	}
	/* waiting for final replies */
	if (statuscode < 200)
		return;

	if (p->state == DLG_CHL_DONE) {
		LM_DBG("Retransmission for reply %d received for callid %.*s\n",
				statuscode, dlg->callid.len, dlg->callid.s);
		return;
	}

	/* if we do not challenge, or we do challenge but this is the leg that
	 * sent the second reply, this means that we are done, so we shall return
	 */
	if (!p->challenge || p->state == DLG_CHL_PENDING) {
		LM_DBG("Reply %d received for callid %.*s\n", statuscode,
				dlg->callid.len, dlg->callid.s);
		return dlg_async_response(p, rpl, statuscode);
	}

	/* from now on we have negotiate enabled */
	if (statuscode > 300) {
		LM_DBG("Negative reply %d received for our challenge in callid %.*s\n",
		statuscode, dlg->callid.len, dlg->callid.s);
		return dlg_async_response(p, rpl, statuscode);
	}

	if (get_body(rpl, &body) < 0 || body.len == 0) {
		LM_INFO("No body received in reply %d for callid %.*s\n",
				statuscode, dlg->callid.len, dlg->callid.s);
		return dlg_async_response(p, rpl, 400);
	}

	if (!dlg_get_leg_hdrs(dlg, other_leg(dlg, p->leg), p->leg, &ct_hdr, NULL, &extra_headers)) {
		LM_ERR("No more pkg for extra headers \n");
		goto error;
	}

	/* if we have to negotiate, let's do it! */
	p->ref++;
	p->state = DLG_CHL_PENDING;
	/* swap the leg */
	p->leg = other_leg(dlg, p->leg);

	ref_dlg(dlg, 1);
	if (send_leg_msg(dlg, &p->method, p->leg, other_leg(dlg, p->leg),
			&extra_headers, &body,
			dlg_sequential_reply, p, dlg_sequential_free,
			&dlg->legs[p->leg].reply_received) < 0) {
		LM_ERR("cannot send sequential message!\n");
		goto error;
	}
	return;
error:
	dlg_sequential_free(p);
	p->async->handler_f(NULL, p->async, 1);
}

static mi_response_t *mi_send_sequential(struct dlg_cell *dlg, int sleg,
		str *method, str *body, str *ct, int challenge, struct mi_handler *async_hdl)
{
	struct dlg_sequential_param *param;
	int dleg = other_leg(dlg, sleg);
	str extra_headers;

	param = shm_malloc(sizeof(*param) + method->len);
	if (!param) {
		LM_ERR("no more shm info!\n");
		return init_mi_error(500, MI_SSTR("Internal Error"));
	}
	param->state = DLG_CHL_START;
	param->challenge = challenge;
	param->async = async_hdl;
	param->dlg = dlg;
	param->ref = 1;
	param->leg = sleg;
	param->method.len = method->len;
	param->method.s = (char *)(param + 1);
	memcpy(param->method.s, method->s, method->len);

	if (!dlg_get_leg_hdrs(dlg, sleg, dleg, ct, NULL, &extra_headers)) {
		LM_ERR("No more pkg for extra headers \n");
		shm_free(param);
		return init_mi_error(500, MI_SSTR("Internal Error"));
	}

	if (send_leg_msg(dlg, method, sleg, dleg, &extra_headers, body,
			dlg_sequential_reply, param, dlg_sequential_free,
			dlg_has_reinvite_pinging(dlg) ? &dlg->legs[dleg].reinvite_confirmed :
			&dlg->legs[dleg].reply_received) < 0) {
		pkg_free(extra_headers.s);
		dlg_sequential_free(param);
		LM_ERR("cannot send sequential message!\n");
		return init_mi_error(500, MI_SSTR("Internal Error"));
	}
	pkg_free(extra_headers.s);

	if (async_hdl==NULL)
		return init_mi_result_string(MI_SSTR("Accepted"));
	else
		return MI_ASYNC_RPL;
}

/* possible mode values:
 * - caller (default)
 * - callee
 * - challenge
 * - challenge caller
 * - challenge callee
 */
static int mi_parse_mode(const mi_params_t *params, int *src_leg, int *challenge)
{
	str mode_s;

	*src_leg = 1; /* by default, the caller is the destination */
	*challenge = 0; /* and challenge is disabled */

	if (try_get_mi_string_param(params, "mode", &mode_s.s, &mode_s.len) < 0)
		return 0;

	if (mode_s.len >= 9) {
		if (strncasecmp(mode_s.s, "challenge", 9) != 0) {
			LM_WARN("Invalid challenge mode '%.*s'\n", mode_s.len, mode_s.s);
			return -1;
		}
		/* we are challenging */
		*challenge = 1;
		if (mode_s.len == 9)
			return 0; /* challenge alone, thus caller is challenged */
		if (mode_s.len < 10) {
			LM_WARN("Invalid leg in challenge mode '%.*s'\n", mode_s.len, mode_s.s);
			return -1;
		}
		/* 10 because we skip the separator, whatever that is */
		mode_s.s += 10;
		mode_s.len -= 10;
	}
	if (mode_s.len != 6) {
		LM_WARN("Invalid leg specified '%.*s'\n", mode_s.len, mode_s.s);
		return -1;
	}
	/* if callee */
	if (strncasecmp(mode_s.s, "callee", 6) == 0)
		*src_leg = 0;
	else if (strncasecmp(mode_s.s, "caller", 6) != 0) {
		/* if not caller */
		LM_WARN("Invalid leg mode '%.*s'\n", mode_s.len, mode_s.s);
		return -1;
	}
	return 0;
}

/* possible body mode values:
 * - none (return 0, default)
 * - inbound (return 1)
 * - outbound (return 2)
 * - custom (return 3 + body)
 */
static int mi_parse_body_mode(const mi_params_t *params, str *ct, str *body)
{
	str body_s;

	body_s.len = 0;
	body_s.s = 0;

	if (try_get_mi_string_param(params, "body", &body_s.s, &body_s.len) < 0)
		return 0;

	switch (body_s.len) {
		case 4:
			if (strncasecmp(body_s.s, "none", 4) != 0)
				goto error;
			return 0; /* none */
		case 7:
			if (strncasecmp(body_s.s, "inbound", 7) != 0)
				goto error;
			return 1; /* inbound */
		case 8:
			if (strncasecmp(body_s.s, "outbound", 8) != 0)
				goto error;
			return 2; /* outbound */
		default:
			if (body_s.len < 10 || strncasecmp(body_s.s, "custom", 6) != 0)
				goto error;
			/* we skip 'custom' + the separator after it and get the content
			 * type */
			ct->s = body_s.s + 7;

			body->s = q_memchr(ct->s, ':', body_s.len - 7);
			if (!body->s) {
				LM_WARN("Missing content type in custom body! No body assumed!\n");
				return 0;
			}
			ct->len = body->s - ct->s;
			/* we have the body, but we need to skip the separator */
			body->s++;
			body->len = body_s.len - (body->s - body_s.s);

			return 3; /* custom */
	}

error:
	LM_ERR("Invalid body mode specified '%.*s'\n", body_s.len, body_s.s);
	return -1;
}

mi_response_t *mi_send_sequential_dlg(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	static str ct_hdr = str_init("application/sdp");
	struct dlg_cell *dlg;
	str *content = &ct_hdr;
	str method;
	str callid;
	str body;
	str ct;
	int leg, challenge, body_mode;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	if (mi_parse_mode(params, &leg, &challenge) < 0)
		return init_mi_error(400, MI_SSTR("Invalid mode"));

	if (try_get_mi_string_param(params, "method", &method.s, &method.len) < 0) {
		method.s = "INVITE";
		method.len = 6;
	}

	if ((body_mode = mi_parse_body_mode(params, &ct, &body)) < 0)
		return init_mi_error(400, MI_SSTR("Invalid body mode"));

	if (challenge != 0) {
		/* if challenge is used, the method has to be INVITE or UPDATE */
		if (method.len != 6 || (strncasecmp(method.s, "UPDATE", 6) != 0 &&
				strncasecmp(method.s, "INVITE", 6) != 0)) {
			LM_ERR("cannot challenge with method %.*s\n",
					method.len, method.s);
			return init_mi_error(406, MI_SSTR("Not Acceptable"));
		}
	}

	dlg = get_dlg_by_callid(&callid, 1);
	if (!dlg)
		return init_mi_error(404, MI_SSTR("Dialog Not Found"));
	/* now that we have the dialog, figure out the leg and body to use */
	if (leg != 0) /* callee */
		leg = callee_idx(dlg);

	/* if inbound should be used, our outbound body, but it wasn't changed by
	 * any function */
	if (body_mode == 1 || (body_mode == 2 && dlg->legs[leg].out_sdp.s == 0))
		body = dlg->legs[leg].in_sdp;
	else if (body_mode == 2)
		body = dlg->legs[other_leg(dlg, leg)].out_sdp;
	else if (body_mode == 3)
		content = &ct;
	else /* if mode = 0 */
		content = NULL;

	return mi_send_sequential(dlg, leg, &method,
			(body_mode == 0?NULL:&body), content, challenge, async_hdl);
}

struct dlg_indialog_req_param {
	int leg;
	int is_invite;
	struct dlg_cell *dlg;
	indialog_reply_f func;
	void *param;
};

static void dlg_indialog_reply_release(void *param)
{
	struct dlg_indialog_req_param *p = (struct dlg_indialog_req_param *)param;
	unref_dlg(p->dlg, 1);
	shm_free(p);
}

static void dlg_indialog_reply(struct cell* t, int type, struct tmcb_params* ps)
{
	int statuscode;
	str ack = str_init("ACK");
	struct dlg_indialog_req_param *param;

	if (!ps || !ps->rpl || !ps->param) {
		LM_ERR("wrong tm callback params!\n");
		return;
	}

	statuscode = ps->code;
	param = *(struct dlg_indialog_req_param **)ps->param;

	if (param->func)
		param->func(ps->rpl, statuscode, param->param);

	if (param->is_invite && statuscode < 300 &&
			send_leg_msg(param->dlg, &ack, other_leg(param->dlg, param->leg), param->leg,
				NULL, NULL, NULL, NULL, NULL, NULL) < 0)
		LM_ERR("cannot send ACK message!\n");
}

int send_indialog_request(struct dlg_cell *dlg, str *method,
		int dstleg, str *body, str *ct, str *hdrs, indialog_reply_f func, void *param)
{
	str extra_headers;
	struct dlg_indialog_req_param *p;

	if (!dlg_get_leg_hdrs(dlg, other_leg(dlg, dstleg), dstleg, ct, hdrs, &extra_headers)) {
		LM_ERR("could not build extra headers!\n");
		return -1;
	}

	p = shm_malloc(sizeof *p);
	if (!p) {
		LM_ERR("oom for allocating params!\n");
		pkg_free(extra_headers.s);
		return -1;
	}
	if (method->len == 6 && memcmp(method->s, "INVITE", 6) == 0)
		p->is_invite = 1;
	else
		p->is_invite = 0;
	p->dlg = dlg;
	p->func = func;
	p->param = param;
	p->leg = dstleg;

	ref_dlg(dlg, 1);
	if (send_leg_msg(dlg, method, other_leg(dlg, dstleg), dstleg, &extra_headers,
			body, dlg_indialog_reply, p, dlg_indialog_reply_release,
			dlg_has_reinvite_pinging(dlg) ? &dlg->legs[dstleg].reinvite_confirmed :
			&dlg->legs[dstleg].reply_received) < 0) {
		pkg_free(extra_headers.s);
		unref_dlg(dlg, 1);
		shm_free(p);
		return -2;
	}
	pkg_free(extra_headers.s);
	return 0;
}

int get_dlg_direction(void)
{
	struct dlg_cell *dlg;

	if ( (dlg=get_current_dialog())==NULL || ctx_lastdstleg_get()<0)
		return DLG_DIR_NONE;
	if (ctx_lastdstleg_get()==0)
		return DLG_DIR_UPSTREAM;
	else
		return DLG_DIR_DOWNSTREAM;
}
