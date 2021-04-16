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


#include <string.h>
#include <time.h>

#include "../../pvar.h"
#include "../../timer.h"
#include "../../statistics.h"
#include "../../data_lump.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_cseq.h"
#include "../../parser/contact/contact.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_cseq.h"
#include "../../parser/parse_hname2.h"
#include "../../parser/parser_f.h"
#include "../tm/tm_load.h"
#include "../rr/api.h"
#include "dlg_hash.h"
#include "dlg_timer.h"
#include "dlg_cb.h"
#include "dlg_handlers.h"
#include "dlg_db_handler.h"
#include "dlg_profile.h"
#include "dlg_req_within.h"
#include "dlg_replication.h"

extern str       rr_param;

static int       default_timeout;
static int       shutdown_done = 0;

extern int       seq_match_mode;
extern struct rr_binds d_rrb;
#define has_rr() (d_rrb.add_rr_param!=NULL)
extern int race_condition_timeout;

/* statistic variables */
extern stat_var *processed_dlgs;
extern stat_var *expired_dlgs;
extern stat_var *failed_dlgs;

int ctx_lastdstleg_idx = -1;
int ctx_timeout_idx = -1;

static inline int dlg_update_contact(struct dlg_cell *dlg, struct sip_msg *msg,
		unsigned int leg);

static inline int dlg_update_sdp(struct dlg_cell *dlg, struct sip_msg *msg,
		unsigned int leg, int tmp);

static inline void dlg_merge_tmp_sdp(struct dlg_cell *dlg, unsigned int leg);


void init_dlg_handlers(int default_timeout_p)
{
	default_timeout = default_timeout_p;
}


void destroy_dlg_handlers(void)
{
	shutdown_done = 1;
}

static int dlg_get_did_buf(struct dlg_cell *dlg, str *buf)
{
	char *p;

	p = buf->s;
	if (int2reverse_hex(&p, &buf->len, dlg->h_entry) == -1)
		return -1;

	if (!buf->len)
		return -1;

	*(p++) = DLG_SEPARATOR;
	buf->len--;

	if (int2reverse_hex(&p, &buf->len, dlg->h_id) == -1)
		return -1;
	buf->len = p - buf->s;
	return 0;
}

str *dlg_get_did(struct dlg_cell *dlg)
{
	static str did_str;
	static char did_buf[DLG_DID_SIZE];

	did_str.s = did_buf;
	did_str.len = DLG_DID_SIZE;

	if (dlg_get_did_buf(dlg, &did_str) < 0)
		return NULL;
	return &did_str;
}

int run_dlg_script_route(struct dlg_cell *dlg, int rt_idx)
{
	static struct sip_msg* fake_msg= NULL;
	context_p old_ctx, *new_ctx;
	int old_route_type;

	/************* pre-run sequance ****************/

	if (push_new_processing_context( dlg, &old_ctx, &new_ctx, &fake_msg)<0) {
		LM_ERR("failed to prepare context for runing dlg route\n");
		return -1;
	}

	swap_route_type(old_route_type, REQUEST_ROUTE);

	/************* actual run sequance ****************/
	run_top_route( sroutes->request[rt_idx].a, fake_msg);

	/************* post-run sequance ****************/

	set_route_type(old_route_type);
	release_dummy_sip_msg(fake_msg);

	/* reset the processing context */
	if (current_processing_ctx == NULL)
		*new_ctx = NULL;
	else
		context_destroy(CONTEXT_GLOBAL, *new_ctx);
	current_processing_ctx = old_ctx;

	/* remove all added AVP - here we use all the time the default AVP list */
	reset_avps( );

	return 0;
}


static inline int add_dlg_rr_param(struct sip_msg *req, struct dlg_cell *dlg)
{
	static char buf[RR_DLG_PARAM_SIZE];
	char *p;
	str id;

	p = buf;

	*(p++) = ';';
	memcpy(p, rr_param.s, rr_param.len);
	p += rr_param.len;
	*(p++) = '=';

	id.s = p;
	id.len = RR_DLG_PARAM_SIZE - (p-buf);
	if (dlg_get_did_buf(dlg, &id) < 0)
		return -1;

	id.len += p - buf;
	id.s -= p - buf;
	if (d_rrb.add_rr_param( req, &id)<0) {
		LM_ERR("failed to add rr param\n");
		return -1;
	}

	return 0;
}



static inline void get_routing_info(struct sip_msg *msg, int is_req,
							unsigned int *skip_rrs, str *contact, str *rr_set)
{
	/* extract the contact address */
	if (!msg->contact&&(parse_headers(msg,HDR_CONTACT_F,0)<0||!msg->contact)){
		//LM_ERR("bad sip message or missing Contact hdr\n");
		contact->s = NULL;
		contact->len = 0;
	} else {
		if ( parse_contact(msg->contact)<0 ||
		((contact_body_t *)msg->contact->parsed)->contacts==NULL ||
		((contact_body_t *)msg->contact->parsed)->contacts->next!=NULL ) {
			LM_ERR("bad Contact HDR\n");
			contact->s = NULL;
			contact->len = 0;
		} else {
			*contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
		}
	}

	/* extract the RR parts - parse all headers as we can have multiple
	   RR headers in the same message */
	if( parse_headers(msg,HDR_EOH_F,0)<0 ){
		LM_ERR("failed to parse record route header\n");
		rr_set->s = 0;
		rr_set->len = 0;
	} else {
		if(msg->record_route){
			if( print_rr_body(msg->record_route, rr_set, !is_req, 0,
								skip_rrs) != 0 ){
				LM_ERR("failed to print route records \n");
				rr_set->s = 0;
				rr_set->len = 0;
			}
		} else {
			rr_set->s = 0;
			rr_set->len = 0;
		}
	}
}



/*usage: dlg: the dialog to add cseq, contact & record_route
 * 		 msg: sip message
 * 		 flag: 0-for a request(INVITE),
 * 		 		1- for a reply(200 ok)
 *
 *	for a request: get record route in normal order
 *	for a reply  : get in reverse order, skipping the ones from the request and
 *				   the proxies' own
 */
static int update_leg_info(int leg, struct dlg_cell *dlg, struct sip_msg *msg,
						   str *tag,str *mangled_from,str *mangled_to)
{
	unsigned int skip_recs;
	str cseq;
	str contact = STR_NULL;
	str rr_set;
	int is_req;
	str sdp;

	is_req = (msg->first_line.type==SIP_REQUEST)?1:0;

	/* extract the cseq number as string */
	if (is_req) {
		/* cseq */
		if((!msg->cseq && (parse_headers(msg,HDR_CSEQ_F,0)<0 || !msg->cseq)) ||
		!msg->cseq->parsed){
			LM_ERR("bad sip message or missing CSeq hdr :-/\n");
			goto error0;
		}
		cseq = (get_cseq(msg))->number;

		/* routing info */
		skip_recs = 0;
		get_routing_info(msg, is_req, &skip_recs, &contact, &rr_set);
		dlg->from_rr_nb = skip_recs;
	} else {
		/* use the same as in invite cseq in caller leg */
		cseq = dlg->legs[DLG_CALLER_LEG].inv_cseq;

		if ((dlg->mod_flags & TOPOH_ONGOING) && (msg->REPLY_STATUS<200 &&
					msg->REPLY_STATUS>100)) {
			/* save contact && rr_set , may need need to route requests
			 * before the INVITE transaction terminates */
			get_routing_info(msg,is_req,0,&contact,&rr_set);
		} else {
			/* no need to save these here, wait for final response */
			rr_set.len = contact.len = 0;
			rr_set.s = contact.s = NULL;
		}
	}

	LM_DBG("route_set %.*s, contact %.*s, cseq %.*s and bind_addr %.*s\n",
		rr_set.len, ZSW(rr_set.s), contact.len, ZSW(contact.s),
		cseq.len, cseq.s,
		msg->rcv.bind_address->sock_str.len,
		msg->rcv.bind_address->sock_str.s);

	if (get_body(msg,&sdp) < 0) {
		sdp.s = NULL;
		sdp.len = 0;
	}

	if (dlg_update_leg_info(leg, dlg, tag, &rr_set, &contact, NULL, &cseq,
	msg->rcv.bind_address,mangled_from,mangled_to, &sdp, NULL)!=0) {
		LM_ERR("dlg_update_leg_info failed\n");
		if (rr_set.s) pkg_free(rr_set.s);
		goto error0;
	}

	if (rr_set.s) pkg_free(rr_set.s);

	return 0;
error0:
	return -1;
}

static str extracted_to_uri;
static inline str* extract_mangled_touri(str *mangled_to_hdr)
{
	struct to_body to_b;
	struct hdr_field hdr;
	char *tmp,*end;

	if (mangled_to_hdr->len == 0 || mangled_to_hdr->s == NULL)
		return NULL;

	end = mangled_to_hdr->s+mangled_to_hdr->len;

	tmp=parse_hname2(mangled_to_hdr->s,end,&hdr);
	if (hdr.type==HDR_ERROR_T) {
		LM_ERR("bad to header\n");
		return NULL;
	}

	tmp = eat_lws_end(tmp,end);
	if (tmp >= end) {
		LM_ERR("empty header\n");
		return NULL;
	}

	parse_to(tmp,end,&to_b);
	if (to_b.error == PARSE_ERROR) {
		LM_ERR("bad to header [%.*s]\n",mangled_to_hdr->len,mangled_to_hdr->s);
		return NULL;
	}

	extracted_to_uri = to_b.uri;
	free_to_params(&to_b);

	LM_DBG("extracted to uri [%.*s]\n",extracted_to_uri.len,extracted_to_uri.s);
	return &extracted_to_uri;
}

static str extracted_from_uri;
static inline str* extract_mangled_fromuri(str *mangled_from_hdr)
{
	struct to_body from_b;
	struct hdr_field hdr;
	char *tmp,*end;

	if (mangled_from_hdr->len == 0 || mangled_from_hdr->s == NULL)
		return NULL;

	end = mangled_from_hdr->s+mangled_from_hdr->len;

	tmp=parse_hname2(mangled_from_hdr->s,end,&hdr);
	if (hdr.type==HDR_ERROR_T) {
		LM_ERR("bad from header\n");
		return NULL;
	}

	tmp=eat_lws_end(tmp, end);
	if (tmp >= end) {
		LM_ERR("empty header\n");
		return NULL;
	}

	parse_to(tmp,end,&from_b);
	if (from_b.error == PARSE_ERROR) {
		LM_ERR("bad from header [%.*s]\n",mangled_from_hdr->len,mangled_from_hdr->s);
		return NULL;
	}

	extracted_from_uri = from_b.uri;
	free_to_params(&from_b);

	LM_DBG("extracted from uri [%.*s]\n",extracted_from_uri.len,extracted_from_uri.s);
	return &extracted_from_uri;
}

static inline void push_reply_in_dialog(struct sip_msg *rpl, struct cell* t,
				struct dlg_cell *dlg,str *mangled_from,str *mangled_to)
{
	str tag,contact,rr_set;
	unsigned int skip_rrs, cseq_no;
	int leg;

	get_totag(rpl, &tag);
	if (ZSTR(tag)) {
		/* Don't print error for final replies in DLG_STATE_UNCONFIRMED */
		if (!(dlg->state == DLG_STATE_UNCONFIRMED &&
			rpl->first_line.u.reply.statuscode >= 300)) {
			LM_ERR("[%d] reply in dlg state [%d]: missing TAG param in TO hdr\n",
				rpl->first_line.u.reply.statuscode, dlg->state);
		}
		tag.s = NULL;
		tag.len = 0;
	}

	LM_DBG("%p totag in rpl %d is <%.*s> (%d)\n",
		dlg, rpl->REPLY_STATUS, tag.len,tag.s,tag.len);

	/* ignore provisional replies replies without totag */
	if (tag.len==0 && rpl->REPLY_STATUS<200 )
		return;

	dlg_lock_dlg(dlg);

	/* is the totag already known ?? */
	for(leg=DLG_FIRST_CALLEE_LEG ; leg<dlg->legs_no[DLG_LEGS_USED] ; leg++ ) {
		/* coverity[var_deref_model]
		 * false positivie - when tag.s = NULL, len is 0 - CID #40640 */
		if ( dlg->legs[leg].tag.len==tag.len &&
		strncmp(dlg->legs[leg].tag.s,tag.s,tag.len)==0 ) {
			/* we have a match -> branch already known... */
			LM_DBG("branch with tag <%.*s> already exists\n",tag.len,tag.s);
			goto routing_info;
		}
	}

	leg = d_tmb.get_branch_index() + 1;

	/* has the downstream element forked an extra branch starting from ours?
	 * Treat these extra branches exactly the same (a callee leg) */
	if (leg_is_answered(&dlg->legs[leg])) {
		leg = dlg_clone_callee_leg(dlg, leg);
		if (leg < 0) {
			LM_ERR("failed to add callee leg!\n");
			goto out;
		}
	}

	/* save callee's tag and cseq */
	LM_DBG("new branch with tag <%.*s>, leg_idx=%d\n", tag.len, tag.s, leg);
	if (update_leg_info(leg, dlg, rpl, &tag,extract_mangled_fromuri(mangled_from),
				extract_mangled_touri(mangled_to)) !=0) {
		LM_ERR("could not add further info to the dialog\n");
		goto out;
	}

routing_info:
	/* update dlg info only if 2xx reply and if not already done so */
	if (rpl->REPLY_STATUS>=200 && rpl->REPLY_STATUS<300 &&
	dlg->legs_no[DLG_LEG_200OK] != leg) {
		/* set this branch as primary */
		if (!dlg->legs_no[DLG_LEG_200OK])
			dlg->legs_no[DLG_LEG_200OK] = leg;

		if (dlg->flags & DLG_FLAG_CSEQ_ENFORCE) {
			/* increase all future requests going to this leg */
			if (str2int( &(get_cseq(rpl)->number), &cseq_no) < 0) {
				LM_ERR("Failed to convert cseq to integer \n");
			} else {
				dlg->legs[dlg->legs_no[DLG_LEG_200OK]].last_gen_cseq = cseq_no;
			}
		}

		/* update routing info */
		if(dlg->mod_flags & TOPOH_ONGOING)
			skip_rrs = 0; /* changed here for contact - it was 1 */
		else
			skip_rrs = dlg->from_rr_nb +
					((t->relaied_reply_branch>=0)?
					(t->uac[t->relaied_reply_branch].added_rr):0);

		LM_DBG("Skipping %d ,%d, %d, %d \n",skip_rrs, dlg->from_rr_nb,t->relaied_reply_branch,t->uac[t->relaied_reply_branch].added_rr);
		get_routing_info(rpl, 0, &skip_rrs, &contact, &rr_set);

		dlg_update_sdp(dlg, rpl, leg, 0);
		dlg_update_routing( dlg, leg, &rr_set, &contact);
		if( rr_set.s )
			pkg_free( rr_set.s);
	}

out:
	dlg_unlock_dlg(dlg);
}

static void _dlg_setup_reinvite_callbacks(struct cell *t, struct sip_msg *req,
		struct dlg_cell *dlg);

void dlg_setup_reinvite_callbacks(struct cell *t, struct sip_msg *req,
		struct dlg_cell *dlg)
{
	_dlg_setup_reinvite_callbacks(t, req, dlg);
}

static void dlg_onreply(struct cell* t, int type, struct tmcb_params *param)
{
	struct sip_msg *rpl,*req;
	struct dlg_cell *dlg;
	int new_state;
	int old_state;
	int unref;
	int event;
	str mangled_from = {0,0};
	str mangled_to = {0,0};
	str *req_out_buff;

	dlg = (struct dlg_cell *)(*param->param);
	if (shutdown_done || dlg==0)
		return;

	rpl = param->rpl;
	req = param->req;

	if (type==TMCB_RESPONSE_FWDED) {
		/* this callback is under transaction lock (by TM), so it is save
		   to operate at write level, but we need to take care on write-read
		   conflicts -bogdan */
		if (rpl!=FAKED_REPLY) {
			if (req->msg_flags & (FL_USE_UAC_FROM | FL_USE_UAC_TO ) ) {
				req_out_buff = &t->uac[d_tmb.get_branch_index()].request.buffer;
				if (extract_ftc_hdrs(req_out_buff->s,req_out_buff->len,
				(req->msg_flags & FL_USE_UAC_FROM )?&mangled_from:0,
				(req->msg_flags & FL_USE_UAC_TO )?&mangled_to:0,0,0) != 0) {
					LM_ERR("failed to extract mangled FROM and TO hdrs\n");
					mangled_from.len = 0;
					mangled_from.s = NULL;
					mangled_to.len = 0;
					mangled_to.s = NULL;
				} else {
					if ((req->msg_flags & FL_USE_UAC_FROM) && (mangled_from.len == 0 || mangled_from.s == NULL))
						LM_CRIT("extract_ftc_hdrs ok but no from extracted : [%.*s]\n",req_out_buff->len,req_out_buff->s);

					if ((req->msg_flags & FL_USE_UAC_TO) && (mangled_to.len == 0 || mangled_to.s == NULL))
						LM_CRIT("extract_ftc_hdrs ok but no to extracted : [%.*s]\n",req_out_buff->len,req_out_buff->s);
				}
			}
			push_reply_in_dialog( rpl, t, dlg,&mangled_from,&mangled_to);
		} else {
			LM_DBG("dialog replied from script - cannot get callee info\n");
		}
		/* The state does not change, but the msg is mutable in this callback*/
		run_dlg_callbacks(DLGCB_RESPONSE_FWDED, dlg, rpl,
			DLG_DIR_UPSTREAM, NULL, 0, 1);
		return;
	}
	if (type==TMCB_TRANS_CANCELLED) {
		/* only if we did force match the Cancel to the
		 * dialog before ( from the script ) */
		dlg->flags |= DLG_FLAG_WAS_CANCELLED;

		if (dlg->flags & DLG_FLAG_END_ON_RACE_CONDITION &&
		dlg->state>= DLG_STATE_CONFIRMED_NA) {
			dlg->lifetime_dirty = 1;

			LM_DBG("Received CANCEL for a 200 OK'ed call call %.*s - terminating\n",
			dlg->callid.len,dlg->callid.s);

			dlg->lifetime = race_condition_timeout; 
			dlg->flags |= DLG_FLAG_RACE_CONDITION_OCCURRED;

			switch ( update_dlg_timer( &dlg->tl, dlg->lifetime ) ) {
			case -1:
				LM_ERR("failed to update dialog lifetime\n");
			case 0:
				/* timeout value was updated */
				break;
			case 1:
				/* dlg inserted in timer list with new expire (reference it)*/
				ref_dlg(dlg,1);
				dlg->lifetime_dirty = 0;
			}
		} else {
			init_dlg_term_reason(dlg,"Cancelled",sizeof("Cancelled")-1);
		}

		if (current_processing_ctx && ctx_dialog_get()==NULL) {
			/* reference and attached to script */
			ref_dlg(dlg,1);
			ctx_dialog_set(t->dialog_ctx);
		}
		return;
	}
	if (type==TMCB_RESPONSE_OUT) {
		if (dlg->state == DLG_STATE_CONFIRMED_NA && dialog_repl_cluster &&
			param->code >= 200 && param->code < 300)
			replicate_dialog_created(dlg);
		return;
	}

	if (type==TMCB_TRANS_DELETED) {
		event = DLG_EVENT_TDEL;
	} else if (param->code<200) {
		event = DLG_EVENT_RPL1xx;
		ctx_lastdstleg_set(DLG_CALLER_LEG);
	} else if (param->code<300) {
		event = DLG_EVENT_RPL2xx;
		ctx_lastdstleg_set(DLG_CALLER_LEG);
	} else {
		event = DLG_EVENT_RPL3xx;
		ctx_lastdstleg_set(DLG_CALLER_LEG);
	}

	next_state_dlg(dlg, event, DLG_DIR_UPSTREAM, &old_state, &new_state,
	               &unref, DLG_CALLER_LEG, 1);

	if (new_state==DLG_STATE_EARLY && old_state!=DLG_STATE_EARLY) {
		run_dlg_callbacks(DLGCB_EARLY, dlg, rpl, DLG_DIR_UPSTREAM, NULL, 0, 1);
		if_update_stat(dlg_enable_stats, early_dlgs, 1);
		return;
	}

	if (new_state==DLG_STATE_CONFIRMED_NA &&
	old_state!=DLG_STATE_CONFIRMED_NA && old_state!=DLG_STATE_CONFIRMED ) {
		LM_DBG("dialog %p confirmed\n",dlg);
		
		if (dlg->flags & DLG_FLAG_WAS_CANCELLED &&
		dlg->flags & DLG_FLAG_END_ON_RACE_CONDITION) {
			LM_DBG("Received 200OK for Cancelled call %.*s - terminating\n",
			dlg->callid.len,dlg->callid.s);
			
			dlg->lifetime = race_condition_timeout;
			dlg->flags |= DLG_FLAG_RACE_CONDITION_OCCURRED;
		} else if (dlg->flags & DLG_FLAG_HASBYE &&
		dlg->flags & DLG_FLAG_END_ON_RACE_CONDITION) {
			LM_DBG("Received 200OK for early BYE call %.*s - terminating\n",
			dlg->callid.len,dlg->callid.s);

			dlg->lifetime = race_condition_timeout;
			dlg->flags |= DLG_FLAG_RACE_CONDITION_OCCURRED;
		}


		/* set start time */
		dlg->start_ts = (unsigned int)(time(0));

		if (0 != insert_dlg_timer( &dlg->tl, dlg->lifetime )) {
			LM_CRIT("Unable to insert dlg %p [%u:%u] on event %d [%d->%d] "
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",
				dlg, dlg->h_entry, dlg->h_id, event, old_state, new_state,
				dlg->callid.len, dlg->callid.s,
				dlg->legs[DLG_CALLER_LEG].tag.len,
				dlg->legs[DLG_CALLER_LEG].tag.s,
				dlg->legs[callee_idx(dlg)].tag.len,
				ZSW(dlg->legs[callee_idx(dlg)].tag.s));
		} else {
			/* reference dialog as kept in timer list */
			ref_dlg(dlg,1);
		}

		/* save the settings to the database,
		 * if realtime saving mode configured- save dialog now
		 * else: the next time the timer will fire the update*/
		dlg->flags |= DLG_FLAG_NEW;
		if (dlg_db_mode == DB_MODE_REALTIME)
			update_dialog_dbinfo(dlg);

		/* dialog confirmed */
		run_dlg_callbacks(DLGCB_CONFIRMED, dlg, rpl, DLG_DIR_UPSTREAM,
			NULL, 0, 1);

		if (dlg->rt_on_answer) {
			run_dlg_script_route( dlg, dlg->rt_on_answer);
			/* also replicate an update, if some dlg data changed during
			 * the execution of the on-timeout route */
			if (dialog_repl_cluster && dlg->flags&DLG_FLAG_VP_CHANGED)
				replicate_dialog_updated(dlg);
		}

		if (old_state==DLG_STATE_EARLY)
			if_update_stat(dlg_enable_stats, early_dlgs, -1);

		if_update_stat(dlg_enable_stats, active_dlgs, 1);
		return;
	}

	if ( old_state!=DLG_STATE_DELETED && new_state==DLG_STATE_DELETED ) {
		LM_DBG("dialog %p failed (negative reply)\n", dlg);

		/*destroy profile linkers */
		destroy_linkers(dlg);
		remove_dlg_prof_table(dlg, 1);

		/* dialog setup not completed (3456XX), but there is still a bit of
		 * room to go *back* to 2XX if we're racing against a 200 OK! */
		run_dlg_callbacks(DLGCB_FAILED, dlg, rpl, DLG_DIR_UPSTREAM, NULL, 0, 1);

		/* do unref */
		if (unref)
			unref_dlg(dlg,unref);
		if (old_state==DLG_STATE_EARLY)
			if_update_stat(dlg_enable_stats, early_dlgs, -1);
		if_update_stat(dlg_enable_stats, failed_dlgs, 1);
		return;
	}

	/* in any other case, check if the dialog state machine
	   requests to unref the dialog */
	if (unref)
		unref_dlg(dlg,unref);

	return;
}

/* modifies the sip_msg, setting the cseq header to
 * new_cseq.s + value	OR
 * value if new_cseq is NULL
 */
static inline int update_msg_cseq(struct sip_msg *msg,str *new_cseq,
		unsigned int value)
{
	int offset,len;
	struct lump *tmp;
	char *buf;
	unsigned int loc_cseq;
	str final_cseq;
	str pkg_cseq;

	if (!msg)
	{
		LM_ERR("null pointer provided\n");
		return -1;
	}

	if(parse_headers(msg, HDR_CSEQ_F, 0) <0 )
	{
		LM_ERR("failed to parse headers \n");
		return -1;
	}

	if (new_cseq == 0 || new_cseq->s == 0 || new_cseq->len == 0)
	{
		LM_DBG("null str provided. Using only int value for cseq\n");
		final_cseq.s = int2str(value,&final_cseq.len);
	}
	else
	{
		if( str2int(new_cseq, &loc_cseq) != 0){
			LM_ERR("could not convert string cseq to number\n");
			return -1;
		}

		loc_cseq += value;
		final_cseq.s = int2str(loc_cseq,&final_cseq.len);
	}

	buf = msg->buf;
	len = ((struct cseq_body *)msg->cseq->parsed)->number.len;
	offset = ((struct cseq_body *)msg->cseq->parsed)->number.s - buf;

	if ((tmp = del_lump(msg,offset,len,0)) == 0)
	{
		LM_ERR("failed to remove the existing CSEQ\n");
		return -1;
	}

	/* Make pkg copy of cseq */
	pkg_cseq.s = pkg_malloc(final_cseq.len);
	if (pkg_cseq.s == 0)
	{
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	pkg_cseq.len = final_cseq.len;
	memcpy(pkg_cseq.s,final_cseq.s,final_cseq.len);

	LM_DBG("Message CSEQ translated from [%.*s] to [%.*s]\n",
			((struct cseq_body *)msg->cseq->parsed)->number.len,
			((struct cseq_body *)msg->cseq->parsed)->number.s,pkg_cseq.len,
			pkg_cseq.s);

	if (insert_new_lump_after(tmp,pkg_cseq.s,pkg_cseq.len,0) == 0)
	{
		LM_ERR("failed to insert new CSEQ\n");
		pkg_free(pkg_cseq.s);
		return -1;
	}

	return 0;
}


static void dlg_update_out_sdp(struct dlg_cell *dlg, int in_leg, int out_leg, struct sip_msg *msg, int tmp)
{
	str sdp;
	str *in_sdp, *out_sdp;

	if (get_body(msg,&sdp) < 0) {
		LM_ERR("Failed to extract SDP \n");
		sdp.s = NULL;
		sdp.len = 0;
	}

	dlg_lock_dlg(dlg);

	if (tmp) {
		in_sdp = &dlg->legs[in_leg].tmp_in_sdp;
		out_sdp = &dlg->legs[out_leg].tmp_out_sdp;
	} else {
		in_sdp = &dlg->legs[in_leg].in_sdp;
		out_sdp = &dlg->legs[out_leg].out_sdp;
	}

	if (in_sdp->len == sdp.len &&
			memcmp(in_sdp->s, sdp.s, sdp.len) == 0) {
		/* we have the same sdp in outbound as the one in inbound */
		if (out_sdp->s)
			shm_free(out_sdp->s);
		memset(out_sdp, 0, sizeof(*out_sdp));
		goto end;
	}

	if (shm_str_sync(out_sdp, &sdp) < 0)
		LM_ERR("Failed to (re)allocate sdp\n");
	else
		LM_DBG("update outbound sdp for leg %d\n", out_leg);
end:
	dlg_unlock_dlg(dlg);
}

static void dlg_update_callee_sdp(struct cell* t, int type,
		struct tmcb_params *ps)
{
	struct sip_msg *rpl,*msg;
	int statuscode;
	struct dlg_cell *dlg;
	str buffer;

	if(ps == NULL || ps->rpl == NULL) {
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if( ps->param== NULL ) {
			LM_ERR("Null callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	dlg = *(ps->param);

	if(rpl==NULL || rpl==FAKED_REPLY) {
		/* we only care about actual replayed replies */
		return;
	}

	LM_DBG("Status Code received =  [%d]\n", statuscode);
	if (statuscode == 200) {
		dlg_merge_tmp_sdp(dlg, DLG_CALLER_LEG);
		dlg_update_sdp(dlg, rpl, callee_idx(dlg), 0);

		buffer.s = ((str*)ps->extra1)->s;
		buffer.len = ((str*)ps->extra1)->len;

		msg=pkg_malloc(sizeof(struct sip_msg));
		if (msg==0) {
			LM_ERR("no pkg mem left for sip_msg\n");
			return;
		}

		memset(msg,0, sizeof(struct sip_msg));
		msg->buf=buffer.s;
	        msg->len=buffer.len;

		if (parse_msg(buffer.s,buffer.len, msg)!=0) {
			pkg_free(msg);
			return;
		}

		dlg_update_out_sdp(dlg, callee_idx(dlg), DLG_CALLER_LEG, msg, 0);

		free_sip_msg(msg);
		pkg_free(msg);
	}
}

static void dlg_update_caller_sdp(struct cell* t, int type,
		struct tmcb_params *ps)
{
	struct sip_msg *rpl,*msg;
	int statuscode;
	struct dlg_cell *dlg;
	str buffer;

	if(ps == NULL || ps->rpl == NULL) {
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if( ps->param== NULL ) {
			LM_ERR("Null callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	dlg = *(ps->param);

	if(rpl==NULL || rpl==FAKED_REPLY) {
		/* we only care about actual replayed replies */
		return;
	}

	LM_DBG("Status Code received =  [%d]\n", statuscode);

	if (statuscode == 200) {
		dlg_merge_tmp_sdp(dlg, callee_idx(dlg));
		dlg_update_sdp(dlg, rpl, DLG_CALLER_LEG, 0);

		buffer.s = ((str*)ps->extra1)->s;
		buffer.len = ((str*)ps->extra1)->len;

		msg=pkg_malloc(sizeof(struct sip_msg));
		if (msg==0) {
			LM_ERR("no pkg mem left for sip_msg\n");
			return;
		}

		memset(msg,0, sizeof(struct sip_msg));
		msg->buf=buffer.s;
	        msg->len=buffer.len;

		if (parse_msg(buffer.s,buffer.len, msg)!=0) {
			pkg_free(msg);
			return;
		}

		dlg_update_out_sdp(dlg, DLG_CALLER_LEG, callee_idx(dlg),msg, 0);

		free_sip_msg(msg);
		pkg_free(msg);
	}
}

static void dlg_update_caller_rpl_contact(struct cell* t, int type,
		struct tmcb_params *ps)
{
	struct sip_msg *rpl;
	int statuscode;
	struct dlg_cell *dlg;

	if(ps == NULL || ps->rpl == NULL) {
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if( ps->param== NULL ) {
			LM_ERR("Null callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	dlg = *(ps->param);

	if(rpl==NULL || rpl==FAKED_REPLY) {
		/* we only care about actual replayed replies */
		return;
	}

	LM_DBG("Status Code received =  [%d]\n", statuscode);

	if (statuscode >= 200 && statuscode < 300)
		dlg_update_contact(dlg, rpl, DLG_CALLER_LEG);
}

static void dlg_update_callee_rpl_contact(struct cell* t, int type,
		struct tmcb_params *ps)
{
	struct sip_msg *rpl;
	int statuscode;
	struct dlg_cell *dlg;

	if(ps == NULL || ps->rpl == NULL) {
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if( ps->param== NULL ) {
			LM_ERR("Null callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	dlg = *(ps->param);

	if(rpl==NULL || rpl==FAKED_REPLY) {
		/* we only care about actual replayed replies */
		return;
	}

	LM_DBG("Status Code received =  [%d]\n", statuscode);

	if (statuscode >= 200 && statuscode < 300)
		dlg_update_contact(dlg, rpl, callee_idx(dlg));
}

static void dlg_seq_up_onreply_mod_cseq(struct cell* t, int type,
													struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = ((dlg_cseq_wrapper*)*param->param)->dlg;
	if (shutdown_done || dlg==0)
		return;

	if (update_msg_cseq((struct sip_msg *)param->rpl,&((dlg_cseq_wrapper *)*param->param)->cseq,0) != 0)
		LM_ERR("failed to update CSEQ in msg\n");

	if (type==TMCB_RESPONSE_FWDED &&
			(dlg->cbs.types)&DLGCB_RESPONSE_WITHIN) {
		run_dlg_callbacks(DLGCB_RESPONSE_WITHIN, dlg, param->rpl,
			DLG_DIR_UPSTREAM, NULL, 0, 1);
		return;
	}

	return;
}

static void dlg_seq_up_onreply(struct cell* t, int type,
													struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (shutdown_done || dlg==0)
		return;

	if (type==TMCB_RESPONSE_FWDED &&
			(dlg->cbs.types)&DLGCB_RESPONSE_WITHIN) {
		run_dlg_callbacks(DLGCB_RESPONSE_WITHIN, dlg, param->rpl,
			DLG_DIR_UPSTREAM, NULL, 0, 1);
		return;
	}

	return;
}

static void dlg_seq_down_onreply_mod_cseq(struct cell* t, int type,
													struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = ((dlg_cseq_wrapper*)*param->param)->dlg;
	if (shutdown_done || dlg==0)
		return;

	if (update_msg_cseq((struct sip_msg *)param->rpl,&((dlg_cseq_wrapper *)*param->param)->cseq,0) != 0)
		LM_ERR("failed to update CSEQ in msg\n");

	if (type==TMCB_RESPONSE_FWDED &&
		(dlg->cbs.types)&DLGCB_RESPONSE_WITHIN) {
		run_dlg_callbacks(DLGCB_RESPONSE_WITHIN, dlg, param->rpl,
			DLG_DIR_DOWNSTREAM, NULL, 0, 1);
		return;
	}

	return;
}

static void free_final_cseq(void *cseq)
{
	shm_free(cseq);
}

static void fix_final_cseq(struct cell *t,int type,
									struct tmcb_params *param)
{
	str cseq;

	cseq.s = (char *)(*param->param);
	cseq.len = strlen(cseq.s);

	if (update_msg_cseq((struct sip_msg *)param->rpl,&cseq,0) != 0)
		LM_ERR("failed to update CSEQ in msg\n");

	return ;
}

static void dlg_seq_down_onreply(struct cell* t, int type,
													struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*param->param);
	if (shutdown_done || dlg==0)
		return;

	if (type==TMCB_RESPONSE_FWDED &&
		(dlg->cbs.types)&DLGCB_RESPONSE_WITHIN) {
		run_dlg_callbacks(DLGCB_RESPONSE_WITHIN, dlg, param->rpl,
			DLG_DIR_DOWNSTREAM, NULL, 0, 1);
		return;
	}

	return;
}

inline static int get_dlg_timeout(struct sip_msg *msg)
{
	return (current_processing_ctx && (ctx_timeout_get()!=0)) ?
			ctx_timeout_get() : default_timeout;
}


static void unreference_dialog_cseq(void *cseq_wrap)
{
	/* if the dialog table is gone, it means the system is shutting down.*/
	if (!d_table)
		return;

	dlg_cseq_wrapper *wrap = (dlg_cseq_wrapper *)cseq_wrap;
	unref_dlg(wrap->dlg, 1);
	shm_free(wrap);
}

void unreference_dialog(void *dialog)
{
	/* if the dialog table is gone, it means the system is shutting down.*/
	unref_dlg_destroy_safe((struct dlg_cell*)dialog, 1);
}


static void unreference_dialog_create(void *dialog)
{
	struct tmcb_params params;

	memset(&params, 0, sizeof(struct tmcb_params));
	params.param = (void*)&dialog;
	/* just a wapper */
	dlg_onreply( 0, TMCB_TRANS_DELETED, &params);
}


static void tmcb_unreference_dialog(struct cell* t, int type,
													struct tmcb_params *param)
{
	unref_dlg_destroy_safe((struct dlg_cell*)*param->param, 1);
}

static void dlg_onreply_out(struct cell* t, int type, struct tmcb_params *ps)
{
	struct sip_msg *msg,*rpl;
	struct dlg_cell *dlg;
	str buffer,contact;

	dlg = (struct dlg_cell *)(*ps->param);

	rpl = ps->rpl;
	if(rpl==NULL || rpl==FAKED_REPLY) {
		/* we only care about actual replayed replies */
		return;
	}

	if (ps->code == 200) {
		buffer.s = ((str*)ps->extra1)->s;
		buffer.len = ((str*)ps->extra1)->len;

		msg=pkg_malloc(sizeof(struct sip_msg));
		if (msg==0) {
			LM_ERR("no pkg mem left for sip_msg\n");
			return;
		}

		memset(msg,0, sizeof(struct sip_msg));
		msg->buf=buffer.s;
	        msg->len=buffer.len;

		if (parse_msg(buffer.s,buffer.len, msg)!=0) {
			pkg_free(msg);
			return;
		}

		dlg_update_out_sdp(dlg, callee_idx(dlg), DLG_CALLER_LEG, msg, 0);

		/* save the outgoing contact only if TH */
		if (dlg->mod_flags & TOPOH_ONGOING) {
			/* extract the adv contact address */
			if (!msg->contact&&(parse_headers(msg,HDR_CONTACT_F,0)<0 ||
			!msg->contact)){
				LM_ERR("There is no contact header in the outgoing 200OK \n");
			} else {
				contact.s = msg->contact->name.s;
				contact.len = msg->contact->len;

				dlg_lock_dlg(dlg);
				if (shm_str_sync(&dlg->legs[DLG_CALLER_LEG].adv_contact,
				                  &contact) != 0) {
					dlg_unlock_dlg(dlg);
					LM_ERR("No more shm mem for outgoing contact hdr\n");
					free_sip_msg(msg);
					pkg_free(msg);
					return;
				}
				dlg_unlock_dlg(dlg);
			}
		}

		free_sip_msg(msg);
		pkg_free(msg);
	}
}

static void dlg_caller_reinv_onreq_out(struct cell* t, int type, struct tmcb_params *ps)
{
	struct sip_msg *msg;
	struct dlg_cell *dlg;
	str buffer;

	buffer.s = ((str*)ps->extra1)->s;
	buffer.len = ((str*)ps->extra1)->len;

	dlg = (struct dlg_cell *)(*ps->param);

	msg=pkg_malloc(sizeof(struct sip_msg));
        if (msg==0) {
                LM_ERR("no pkg mem left for sip_msg\n");
                return;
        }

	memset(msg,0, sizeof(struct sip_msg));
	msg->buf=buffer.s;
	msg->len=buffer.len;

        if (parse_msg(buffer.s,buffer.len, msg)!=0) {
		pkg_free(msg);
		return;
	}

	/* we use the initial request, which already has the contact parsed/fixed */
	dlg_update_contact(dlg, ps->req, DLG_CALLER_LEG);
	dlg_update_out_sdp(dlg, DLG_CALLER_LEG, callee_idx(dlg), msg, 1);
	free_sip_msg(msg);
	pkg_free(msg);
}

static void dlg_callee_reinv_onreq_out(struct cell* t, int type, struct tmcb_params *ps)
{
	struct sip_msg *msg;
	struct dlg_cell *dlg;
	str buffer;

	buffer.s = ((str*)ps->extra1)->s;
	buffer.len = ((str*)ps->extra1)->len;

	dlg = (struct dlg_cell *)(*ps->param);

	msg=pkg_malloc(sizeof(struct sip_msg));
        if (msg==0) {
                LM_ERR("no pkg mem left for sip_msg\n");
                return;
        }

	memset(msg,0, sizeof(struct sip_msg));
	msg->buf=buffer.s;
	msg->len=buffer.len;

        if (parse_msg(buffer.s,buffer.len, msg)!=0) {
		pkg_free(msg);
		return;
	}

	dlg_update_contact(dlg, ps->req, callee_idx(dlg));
	dlg_update_out_sdp(dlg, callee_idx(dlg), DLG_CALLER_LEG, msg, 1);
	free_sip_msg(msg);
	pkg_free(msg);
}

static void dlg_set_tm_dialog_ctx(struct dlg_cell *dlg, struct cell *t)
{
	/* dialog already stored */
	if (t->dialog_ctx)
		return;

	if ( d_tmb.register_tmcb( NULL, t, TMCB_TRANS_DELETED,
			tmcb_unreference_dialog, (void*)dlg, NULL)<0){
		LM_ERR("failed to register TMCB\n");
		return;
	}
	/* and attached the dialog to the transaction */
	t->dialog_ctx = (void*)dlg;
	/* and keep a reference on it */
	ref_dlg( dlg , 1);
}


void dlg_onreq(struct cell* t, int type, struct tmcb_params *param)
{
	struct dlg_cell *dlg;

	/* is the dialog already created? */
	if (current_processing_ctx && (dlg=ctx_dialog_get())!=NULL ) {
		/* new, un-initialized dialog ? */
		if ( dlg->flags & DLG_FLAG_ISINIT ) {
			/* fully init dialog -> check if attached to the transaction */
			dlg_set_tm_dialog_ctx(dlg, t);
			return;
		}

		/* dialog was previously created by create_dialog()
		   -> just do the last settings */
		run_create_callbacks( dlg, param->req);

		LM_DBG("t hash_index = %u, t label = %u\n",t->hash_index,t->label);
		dlg->initial_t_hash_index = t->hash_index;
		dlg->initial_t_label = t->label;

		t->dialog_ctx = (void*)dlg;

		/* dialog is fully initialized */
		dlg->flags |= DLG_FLAG_ISINIT;
		_dlg_setup_reinvite_callbacks(t, param->req, dlg);
	}
}

static void dlg_onreq_out(struct cell* t, int type, struct tmcb_params *ps)
{
	struct sip_msg *msg;
	struct dlg_cell *dlg;
	struct dlg_leg *leg;
	str buffer, contact;
	int callee_leg;

	buffer.s = ((str*)ps->extra1)->s;
	buffer.len = ((str*)ps->extra1)->len;

	dlg = (struct dlg_cell *)(*ps->param);

	msg=pkg_malloc(sizeof(struct sip_msg));
        if (msg==0) {
                LM_ERR("no pkg mem left for sip_msg\n");
                return;
        }

	memset(msg,0, sizeof(struct sip_msg));
        msg->buf=buffer.s;
        msg->len=buffer.len;

	if (parse_msg(buffer.s,buffer.len, msg) != 0)
		goto out_free;

	if (msg->REQ_METHOD != METHOD_INVITE) {
		LM_DBG("skipping method %d\n", msg->REQ_METHOD);
		goto out_free;
	}

	/*
	 * - we get called exactly once for each outgoing branch
	 * - in parallel forking, we may concurrently run with reply code!
	 */
	dlg_lock_dlg(dlg);

	if (ensure_leg_array(dlg->legs_no[DLG_LEGS_USED] + 1, dlg) != 0)
		goto out_free;

	/* store the caller SDP into each callee leg, useful for Re-INVITE pings */
	leg = &dlg->legs[dlg->legs_no[DLG_LEGS_USED]];
	callee_leg = dlg->legs_no[DLG_LEGS_USED];

	dlg_unlock_dlg(dlg);

	dlg_update_out_sdp(dlg, DLG_CALLER_LEG, callee_leg, msg, 0);

	dlg_lock_dlg(dlg);

	/* save the outgoing contact only if TH */
	if (dlg->mod_flags & TOPOH_ONGOING) {
		/* extract the contact address */
		if (!msg->contact&&(parse_headers(msg,HDR_CONTACT_F,0)<0 ||
		!msg->contact)){
			LM_ERR("No outgoing contact in the initial INVITE \n");
		} else {
			contact.s = msg->contact->name.s;
			contact.len = msg->contact->len;

			if (shm_str_dup(&leg->adv_contact, &contact) != 0) {
				LM_ERR("No more shm for INVITE outgoing contact \n");
				goto out_free;
			}
		}
	}

	dlg->legs_no[DLG_LEGS_USED]++;

out_free:
	dlg_unlock_dlg(dlg);
	free_sip_msg(msg);
	pkg_free(msg);
}

/*
 * Updates the contact of a specific leg
 * Returns:
 * -1: if an error occured
 *  0: if contact did not change
 *  1: if contact has changed
 */
static inline int dlg_update_contact(struct dlg_cell *dlg, struct sip_msg *msg,
											unsigned int leg)
{
	str contact;
	char *tmp;
	int ret = 0;
	contact_t *ct = NULL;

	if (!msg->contact &&
		(parse_headers(msg, HDR_CONTACT_F, 0) < 0 || !msg->contact)) {
		LM_DBG("INVITE or UPDATE w/o a contact - not updating!\n");
		return 0;
	}
	if (!msg->contact->parsed) {
		contact = msg->contact->body;
		trim_leading(&contact);
		if (parse_contacts(&contact, &ct) < 0) {
			LM_WARN("INVITE or UPDATE w/ broken contact [%.*s] - not updating!\n",
				contact.len, contact.s);
			return 0;
		}
		contact = ct->uri;
		LM_DBG("Found unparsed contact [%.*s]\n", contact.len, contact.s);
	} else {
		contact = ((contact_body_t *)msg->contact->parsed)->contacts->uri;
	}

	if (dlg->legs[leg].contact.s) {
		/* if the same contact, don't do anything */
		if (dlg->legs[leg].contact.len == contact.len &&
				strncmp(dlg->legs[leg].contact.s, contact.s, contact.len) == 0) {
			LM_DBG("Using the same contact <%.*s> for dialog %p on leg %d\n",
					contact.len, contact.s, dlg, leg);
			goto end;
		}
		dlg->flags |= DLG_FLAG_CHANGED;
		LM_DBG("Replacing old contact <%.*s> for dialog %p on leg %d\n",
				dlg->legs[leg].contact.len, dlg->legs[leg].contact.s, dlg, leg);
		tmp = shm_realloc(dlg->legs[leg].contact.s, contact.len);
	} else
		tmp = shm_malloc(contact.len);
	if (!tmp) {
		LM_ERR("not enough memory for new contact!\n");
		ret = -1;
		goto end;
	}
	dlg->legs[leg].contact.s = tmp;
	dlg->legs[leg].contact.len = contact.len;
	memcpy(dlg->legs[leg].contact.s, contact.s, contact.len);
	LM_DBG("Updated contact to <%.*s> for dialog %p on leg %d\n",
			contact.len, contact.s, dlg, leg);
	ret = 1;
end:
	if (ct) free_contacts(&ct);
	return ret;
}


static inline void dlg_merge_tmp_sdp(struct dlg_cell *dlg, unsigned int leg)
{
	dlg_lock_dlg(dlg);

	if (dlg->legs[leg].tmp_in_sdp.s) {
		if (shm_str_sync(&dlg->legs[leg].in_sdp, &dlg->legs[leg].tmp_in_sdp))
			LM_ERR("could not update inbound SDP from temporary SDP!\n");

		shm_free(dlg->legs[leg].tmp_in_sdp.s);
		memset(&dlg->legs[leg].tmp_in_sdp, 0, sizeof(str));
	}

	if (dlg->legs[leg].tmp_out_sdp.s) {
		if (shm_str_sync(&dlg->legs[leg].out_sdp, &dlg->legs[leg].tmp_out_sdp))
			LM_ERR("could not update outbound SDP from temporary SDP!\n");

		shm_free(dlg->legs[leg].tmp_out_sdp.s);
		memset(&dlg->legs[leg].tmp_out_sdp, 0, sizeof(str));
	}

	dlg_unlock_dlg(dlg);
}


static inline int dlg_update_sdp(struct dlg_cell *dlg, struct sip_msg *msg,
		unsigned int leg, int tmp)
{
	str sdp;
	str *sync_sdp;

	if (get_body(msg, &sdp) < 0)
		return -1;

	if (sdp.len == 0)
		return 0; /* nothing to do, no body */

	/* check if we need to update it */
	if (str_match(&dlg->legs[leg].in_sdp, &sdp)) {
		LM_DBG("SDP not changed, using the same one!\n");
		return 0;
	}

	sync_sdp = (tmp?&dlg->legs[leg].tmp_in_sdp:&dlg->legs[leg].in_sdp);

	if (shm_str_sync(sync_sdp, &sdp) != 0) {
		LM_ERR("cannot update inbound SDP!\n");
		return -1;
	}

	LM_DBG("update inbound sdp for leg %d\n", leg);

	return 1;
}

static void dlg_update_contact_req(struct cell* t, int type, struct tmcb_params *ps)
{
	struct sip_msg *msg;
	struct dlg_cell *dlg;

	dlg = (struct dlg_cell *)(*ps->param);
	msg = ps->req;

	if (!dlg || !msg) {
		LM_ERR("no request found (%p) or no dialog(%p) provided!\n", msg, dlg);
		return;
	}

	/* we only update the caller if branch index is 0, since all the other
	   branches contain unfixed contact */
	if (d_tmb.get_branch_index() != 0)
		return;

	dlg_update_contact(dlg, msg, DLG_CALLER_LEG);
}

static void _dlg_setup_reinvite_callbacks(struct cell *t, struct sip_msg *req,
		struct dlg_cell *dlg)
{
	if (!(dlg->flags & DLG_FLAG_REINVITE_PING_ENGAGED_REQ)) {
		/* register out callback in order to save SDP */
		if (d_tmb.register_tmcb(req, 0, TMCB_REQUEST_BUILT,
				dlg_onreq_out, (void *)dlg, 0) <= 0)
			LM_ERR("can't register trace_onreq_out\n");
		else
			dlg->flags |= DLG_FLAG_REINVITE_PING_ENGAGED_REQ;
	}

	if (t && (!(dlg->flags & DLG_FLAG_REINVITE_PING_ENGAGED_REPL))) {
		if (d_tmb.register_tmcb(0, t, TMCB_RESPONSE_OUT,
				dlg_onreply_out, (void *)dlg, 0) <= 0)
			LM_ERR("can't register trace_onreply_out\n");
		else
			dlg->flags |= DLG_FLAG_REINVITE_PING_ENGAGED_REPL;
	}
}

int dlg_create_dialog(struct cell* t, struct sip_msg *req,unsigned int flags)
{
	struct dlg_cell *dlg;
	str s;
	int extra_ref,types;

	/* module is strictly designed for dialog calls */
	if (req->first_line.u.request.method_value!=METHOD_INVITE)
		return -1;

	if ( (!req->to && parse_headers(req, HDR_TO_F,0)<0) || !req->to ) {
		LM_ERR("bad request or missing TO hdr :-/\n");
		return -1;
	}
	s = get_to(req)->tag_value;
	if (s.s!=0 && s.len!=0)
		return -1;

	dlg = get_current_dialog();
	if (dlg) {
		/* a dialog is already created - just update flags, if provisioned */
		if (flags) {
			dlg->flags &= ~(DLG_FLAG_PING_CALLER | DLG_FLAG_PING_CALLEE |
			DLG_FLAG_BYEONTIMEOUT | DLG_FLAG_REINVITE_PING_CALLER | DLG_FLAG_REINVITE_PING_CALLEE);
			dlg->flags |= flags;
			dlg_setup_reinvite_callbacks(t, req, dlg);
		}
		return 0;
	}

	if ( parse_from_header(req)) {
		LM_ERR("bad request or missing FROM hdr :-/\n");
		return -1;
	}
	if ((!req->callid && parse_headers(req,HDR_CALLID_F,0)<0) || !req->callid){
		LM_ERR("bad request or missing CALLID hdr :-/\n");
		return -1;
	}
	s = req->callid->body;
	trim(&s);

	/* some sanity checks */
	if (s.len==0 || get_from(req)->tag_value.len==0) {
		LM_ERR("invalid request -> callid (%d) or from TAG (%d) empty\n",
			s.len, get_from(req)->tag_value.len);
		return -1;
	}

	dlg = build_new_dlg( &s /*callid*/, &(get_from(req)->uri) /*from uri*/,
		&(get_to(req)->uri) /*to uri*/,
		&(get_from(req)->tag_value)/*from_tag*/ );
	if (dlg==0) {
		LM_ERR("failed to create new dialog\n");
		return -1;
	}

	dlg->flags |= flags;

	/* save caller's tag, cseq, contact and record route*/
	if (update_leg_info(0, dlg, req, &(get_from(req)->tag_value),NULL,NULL ) !=0) {
		LM_ERR("could not add further info to the dialog\n");
		shm_free(dlg);
		return -1;
	}

	/* set current dialog */
	ctx_dialog_set(dlg);
	ctx_lastdstleg_set(DLG_FIRST_CALLEE_LEG);

	extra_ref=2; /* extra ref for the callback and current dlg hook */
	if (dlg_db_mode == DB_MODE_DELAYED)
		extra_ref++; /* extra ref for the timer to delete the dialog */
	link_dlg( dlg , extra_ref);

	if ( seq_match_mode!=SEQ_MATCH_NO_ID && has_rr() &&
		add_dlg_rr_param( req, dlg)<0 ) {
		LM_ERR("failed to add RR param\n");
		goto error;
	}

	types = TMCB_RESPONSE_PRE_OUT|TMCB_RESPONSE_FWDED|TMCB_TRANS_CANCELLED;
	/* replicate dialogs after the 200 OK was fwded - speed & after all msg
	 * processing was done ( eg. ACC ) */
	if (dialog_repl_cluster)
		types |= TMCB_RESPONSE_OUT;

	if ( d_tmb.register_tmcb( req, t,types,dlg_onreply,
	(void*)dlg, unreference_dialog_create)<0 ) {
		LM_ERR("failed to register TMCB\n");
		goto error;
	}

	/* complete the dialog setup only if transaction aleady exists;
	   if not, wait for the TMCB_REQUEST_IN callback to do this job */
	if (t) {
		/* first INVITE seen (dialog created, unconfirmed) */
		run_create_callbacks( dlg, req);
		LM_DBG("t hash_index = %u, t label = %u\n",t->hash_index,t->label);
		dlg->initial_t_hash_index = t->hash_index;
		dlg->initial_t_label = t->label;

		t->dialog_ctx = (void*) dlg;
		dlg->flags |= DLG_FLAG_ISINIT;
	}
	dlg->lifetime = get_dlg_timeout(req);

	_dlg_setup_reinvite_callbacks(t, req, dlg);

	if(d_tmb.register_tmcb(req, 0, TMCB_REQUEST_FWDED, dlg_update_contact_req,
			(void *)dlg, 0) <=0) {
		LM_ERR("can't register dlg_update_contact\n");
		return -1;
	}

	if_update_stat( dlg_enable_stats, processed_dlgs, 1);

	return 0;
error:
	unref_dlg(dlg,extra_ref);
	dialog_cleanup( req, NULL);
	if_update_stat(dlg_enable_stats, failed_dlgs, 1);
	return -1;
}

static inline void update_sequential_sdp(struct dlg_cell *dlg, struct sip_msg *req,
		unsigned int leg)
{
	int ret;

	if (req->REQ_METHOD != METHOD_INVITE && req->REQ_METHOD != METHOD_UPDATE)
		return;

	dlg_lock_dlg(dlg);
	ret = dlg_update_sdp(dlg, req, leg, 1);
	dlg_unlock_dlg(dlg);

	/* if anything has changed in the meantime, also update replicate */
	if (ret > 0 && dialog_repl_cluster)
		replicate_dialog_updated(dlg);
}

/* update inv_cseq field if update_field=1
 * else update r_cseq */
static inline int update_cseqs(struct dlg_cell *dlg, struct sip_msg *req,
											unsigned int leg, int update_field)
{
	int ret;
	if ( (!req->cseq && parse_headers(req,HDR_CSEQ_F,0)<0) || !req->cseq ||
	!req->cseq->parsed) {
		LM_ERR("bad sip message or missing CSeq hdr :-/\n");
		return -1;
	}

	dlg_lock_dlg(dlg);
	ret = dlg_update_cseq(dlg, leg, &((get_cseq(req))->number),update_field);
	dlg_unlock_dlg(dlg);
	return ret;
}

/* move r_cseq to prev_cseq in leg */
static inline int switch_cseqs(struct dlg_cell *dlg,unsigned int leg_no)
{
	int ret = -1;
	str* r_cseq,*prev_cseq;

	r_cseq = &dlg->legs[leg_no].r_cseq;
	prev_cseq = &dlg->legs[leg_no].prev_cseq;

	dlg_lock_dlg(dlg);
	if ( prev_cseq->s ) {
		if (prev_cseq->len < r_cseq->len) {
			prev_cseq->s = (char*)shm_realloc(prev_cseq->s,r_cseq->len);
			if (prev_cseq->s==NULL) {
				LM_ERR("no more shm mem for realloc (%d)\n",r_cseq->len);
				goto end;
			}
		}
	} else {
		prev_cseq->s = (char*)shm_malloc(r_cseq->len);
		if (prev_cseq->s==NULL) {
			LM_ERR("no more shm mem for malloc (%d)\n",r_cseq->len);
			goto end;
		}
	}

	memcpy( prev_cseq->s, r_cseq->s, r_cseq->len );
	prev_cseq->len = r_cseq->len;

	LM_DBG("prev_cseq = %.*s for leg %d\n",prev_cseq->len,prev_cseq->s,leg_no);
	ret = 0;
end:
	dlg_unlock_dlg(dlg);
	return ret;
}

static inline void log_bogus_dst_leg(struct dlg_cell *dlg)
{
	if (ctx_lastdstleg_get()>=dlg->legs_no[DLG_LEGS_USED])
		LM_CRIT("bogus dst leg %d in state %d for dlg %p [%u:%u] with "
			"clid '%.*s' and tags '%.*s' '%.*s'. legs used %d\n",
			ctx_lastdstleg_get(),dlg->state, dlg, dlg->h_entry, dlg->h_id,
			dlg->callid.len, dlg->callid.s,
			dlg_leg_print_info( dlg, DLG_CALLER_LEG, tag),
			dlg_leg_print_info( dlg, callee_idx(dlg), tag),dlg->legs_no[DLG_LEGS_USED]);
}

void dlg_onroute(struct sip_msg* req, str *route_params, void *param)
{
	struct dlg_cell *dlg;
	str val = {0,0};
	str callid;
	str ftag;
	str ttag;
	unsigned int h_entry;
	unsigned int h_id;
	int new_state;
	int old_state;
	int unref;
	int event;
	unsigned int update_val;
	unsigned int dir,dst_leg,src_leg;
	int ret = 0,ok = 1;
	struct dlg_entry *d_entry;
	str *msg_cseq;
	char *final_cseq;
	int is_active = 1;
	struct cell *t;

	/* as this callback is triggered from loose_route, which can be
	   accidentaly called more than once from script, we need to be sure
	   we do this only once !*/
	if (ctx_dialog_get())
		return;

	/* skip initial requests - they may end up here because of the
	 * preloaded route */
	if ( (!req->to && parse_headers(req, HDR_TO_F,0)<0) || !req->to ) {
		LM_ERR("bad request or missing TO hdr :-/\n");
		return;
	}
	if ( get_to(req)->tag_value.len==0 )
		return;

	dlg = 0;
	dir = DLG_DIR_NONE;
	dst_leg = -1;

	/* From RR callback, param will be NULL
	 * From match_dialog, param might have a value, if we
	 * are in the topology hiding case & we were able to extract the
	 * DID from the R-URI */
	if (param)
		val = *((str *)param);

	if ( seq_match_mode!=SEQ_MATCH_NO_ID ) {
		if( val.s == NULL &&
		(!has_rr() || d_rrb.get_route_param( req, &rr_param, &val)!=0) ) {
			LM_DBG("Route param '%.*s' not found\n", rr_param.len,rr_param.s);
			if (seq_match_mode==SEQ_MATCH_STRICT_ID )
				return;
		} else {
			LM_DBG("route param is '%.*s' (len=%d)\n",val.len,val.s,val.len);

			if ( parse_dlg_did(&val, &h_entry, &h_id)<0 ) {
				LM_ERR("malformed route param [%.*s]\n", val.len, val.s);
				return;
			}

			dlg = lookup_dlg( h_entry, h_id);
			if (dlg==0) {
				LM_DBG("unable to find dialog for %.*s "
					"with route param '%.*s'\n",
					req->first_line.u.request.method.len,
					req->first_line.u.request.method.s,
					val.len,val.s);
			} else {
				/* lookup_dlg has incremented the ref count by 1 */
				if (pre_match_parse( req, &callid, &ftag, &ttag)<0) {
					unref_dlg(dlg, 1);
					return;
				}
				if (match_dialog(dlg,&callid,&ftag,&ttag,&dir, &dst_leg )==0){
					if (!dialog_repl_cluster) {
						/* not an error when accepting replicating dialogs -
						   we might have generated a different h_id when
						   accepting the replicated dialog */
						LM_WARN("tight matching failed for %.*s with "
							"callid='%.*s'/%d,"
							" ftag='%.*s'/%d, ttag='%.*s'/%d and direction=%d\n",
							req->first_line.u.request.method.len,
							req->first_line.u.request.method.s,
							callid.len, callid.s, callid.len,
							ftag.len, ftag.s, ftag.len,
							ttag.len, ttag.s, ttag.len, dir);
						LM_WARN("dialog identification elements are "
							"callid='%.*s'/%d, "
							"caller tag='%.*s'/%d, callee tag='%.*s'/%d\n",
							dlg->callid.len, dlg->callid.s, dlg->callid.len,
							dlg->legs[DLG_CALLER_LEG].tag.len,
							dlg->legs[DLG_CALLER_LEG].tag.s,
							dlg->legs[DLG_CALLER_LEG].tag.len,
							dlg->legs[callee_idx(dlg)].tag.len,
							ZSW(dlg->legs[callee_idx(dlg)].tag.s),
							dlg->legs[callee_idx(dlg)].tag.len);
					}
					unref_dlg(dlg, 1);
					/* potentially fall through to SIP-wise dialog matching,
					   depending on seq_match_mode */
					dlg = NULL;
				}
			}
			if (dlg==NULL && seq_match_mode==SEQ_MATCH_STRICT_ID )
				return;
		}
	}

	if (dlg==0) {
		if (pre_match_parse( req, &callid, &ftag, &ttag)<0)
			return;
		/* TODO - try to use the RR dir detection to speed up here the
		 * search -bogdan */
		dlg = get_dlg(&callid, &ftag, &ttag, &dir, &dst_leg);
		if (!dlg){
			LM_DBG("Callid '%.*s' not found\n",
				req->callid->body.len, req->callid->body.s);
			return;
		}
	}
	update_sequential_sdp(dlg, req,
			dst_leg == DLG_CALLER_LEG? callee_idx(dlg): DLG_CALLER_LEG);

	if (dialog_repl_cluster)
		is_active = get_shtag_state(dlg) != SHTAG_STATE_BACKUP;

	/* run state machine */
	switch ( req->first_line.u.request.method_value ) {
		case METHOD_PRACK:
			event = DLG_EVENT_REQPRACK; break;
		case METHOD_ACK:
			event = DLG_EVENT_REQACK; break;
		case METHOD_BYE:
			event = DLG_EVENT_REQBYE; break;
		default:
			event = DLG_EVENT_REQ;
	}

	next_state_dlg(dlg, event, dir, &old_state, &new_state, &unref, dst_leg, 1);

	/* set current dialog - it will keep a ref! */
	ctx_dialog_set(dlg);
	ctx_lastdstleg_set(dst_leg);
	log_bogus_dst_leg(dlg);
	d_entry = &(d_table->entries[dlg->h_entry]);

	/* if there was a transaction created before, store the dialog in it */
	t = d_tmb.t_gett();
	if (t && t != T_UNDEFINED)
		dlg_set_tm_dialog_ctx(dlg, t);

	/* run actions for the transition */
	if (event==DLG_EVENT_REQBYE && new_state==DLG_STATE_DELETED &&
	old_state!=DLG_STATE_DELETED) {

		if (dlg->rt_on_hangup)
			run_dlg_script_route( dlg, dlg->rt_on_hangup);

		/*destroy profile linkers */
		destroy_linkers(dlg);
		remove_dlg_prof_table(dlg,is_active);

		if (!dlg->terminate_reason.s) {
			if (dst_leg == 0)
				init_dlg_term_reason(dlg,"Upstream BYE",sizeof("Upstream BYE")-1);
			else
				init_dlg_term_reason(dlg,"Downstream BYE",sizeof("Downstream BYE")-1);
		}

		LM_DBG("BYE successfully processed - dst_leg = %d\n",dst_leg);

		dlg_lock (d_table,d_entry);
		if (dlg->legs[dst_leg].last_gen_cseq) {

			update_val = ++(dlg->legs[dst_leg].last_gen_cseq);
			dlg_unlock (d_table,d_entry);

			if (update_msg_cseq(req,0,update_val) != 0)
				LM_ERR("failed to update BYE msg cseq\n");

			msg_cseq = &((struct cseq_body *)req->cseq->parsed)->number;

			final_cseq = shm_malloc(msg_cseq->len + 1);
			if (final_cseq == 0) {
				LM_ERR("no more shm mem\n");
				goto after_unlock5;
			}

			memcpy(final_cseq,msg_cseq->s,msg_cseq->len);
			final_cseq[msg_cseq->len] = 0;

			if ( d_tmb.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
			fix_final_cseq,
			(void*)final_cseq, free_final_cseq)<0 ) {
				LM_ERR("failed to register TMCB (2)\n");
			}
		}
		else
			dlg_unlock (d_table,d_entry);

after_unlock5:

		/* remove from timer */
		ret = remove_dlg_timer(&dlg->tl);
		if (ret < 0) {
			LM_CRIT("unable to unlink the timer on dlg %p [%u:%u] "
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",
				dlg, dlg->h_entry, dlg->h_id,
				dlg->callid.len, dlg->callid.s,
				dlg->legs[DLG_CALLER_LEG].tag.len,
				dlg->legs[DLG_CALLER_LEG].tag.s,
				dlg->legs[callee_idx(dlg)].tag.len,
				ZSW(dlg->legs[callee_idx(dlg)].tag.s));
		} else if (ret > 0) {
			LM_DBG("dlg expired (not in timer list) on dlg %p [%u:%u] "
				"with clid '%.*s' and tags '%.*s' '%.*s'\n",
				dlg, dlg->h_entry, dlg->h_id,
				dlg->callid.len, dlg->callid.s,
				dlg->legs[DLG_CALLER_LEG].tag.len,
				dlg->legs[DLG_CALLER_LEG].tag.s,
				dlg->legs[callee_idx(dlg)].tag.len,
				ZSW(dlg->legs[callee_idx(dlg)].tag.s));
		} else {
			/* dialog successfully removed from timer -> unref */
			unref++;
		}

		/* dialog terminated (BYE) */
		run_dlg_callbacks(DLGCB_TERMINATED, dlg, req, dir, NULL, 0, is_active);

		/* delete the dialog from DB */
		if (should_remove_dlg_db())
			remove_dialog_from_db(dlg);

		/* destroy dialog */
		unref_dlg(dlg, unref);

		if_update_stat( dlg_enable_stats, active_dlgs, -1);
		return;
	}

	if ( (event==DLG_EVENT_REQ || event==DLG_EVENT_REQACK)
	&& (new_state==DLG_STATE_CONFIRMED || new_state==DLG_STATE_CONFIRMED_NA) ) {
		LM_DBG("sequential request successfully processed (dst_leg=%d)\n",
			dst_leg);

		/* update the dialog timeout from the processing context */
		if (current_processing_ctx && (ctx_timeout_get()!=0) ) {
			dlg->lifetime = ctx_timeout_get();
			dlg->lifetime_dirty = 1;
		}

		/* within dialog request */
		run_dlg_callbacks(DLGCB_REQ_WITHIN, dlg, req, dir, NULL, 0, 1);

		/* update timer during sequential request? */
		if (dlg->lifetime_dirty) {
			switch ( update_dlg_timer( &dlg->tl, dlg->lifetime ) ) {
			case -1:
				LM_ERR("failed to update dialog lifetime\n");
			case 0:
				/* timeout value was updated */
				break;
			case 1:
				/* dlg inserted in timer list with new expire (reference it)*/
				ref_dlg(dlg,1);
				dlg->lifetime_dirty = 0;
			}
		}
		LM_DBG("dialog_timeout: %d\n", dlg->lifetime);
		if ( event!=DLG_EVENT_REQACK ) {

			if (dst_leg==-1 || switch_cseqs(dlg, dst_leg) != 0 ||
				update_cseqs(dlg,req,dst_leg,0)) {
				ok = 0;
				LM_ERR("cseqs update failed on leg=%d\n",dst_leg);
			}

			if (req->first_line.u.request.method_value == METHOD_INVITE ||
					req->first_line.u.request.method_value == METHOD_UPDATE) {
				if (dst_leg == DLG_CALLER_LEG)
					src_leg = callee_idx(dlg);
				else
					src_leg = DLG_CALLER_LEG;

				if (update_cseqs(dlg,req,src_leg,1) != 0) {
					ok=0;
					LM_ERR("failed to update inv cseq on leg %d\n",src_leg);
				}

				/* we need to update the SDP for this leg
				and involve TM to update the SDP for the other side as well */
				if(d_tmb.register_tmcb( req, 0, TMCB_REQUEST_BUILT,
				(dir==DLG_DIR_UPSTREAM)?dlg_callee_reinv_onreq_out:dlg_caller_reinv_onreq_out,
				(void *)dlg, 0) <=0) {
					LM_ERR("can't register trace_onreq_out\n");
					ok = 0;
				}

				if (ok) {
					ref_dlg( dlg , 1);
					if ( d_tmb.register_tmcb( req, 0, TMCB_RESPONSE_OUT,
					(dir==DLG_DIR_UPSTREAM)?dlg_update_caller_sdp:dlg_update_callee_sdp,
					(void*)dlg, unreference_dialog)<0 ) {
						LM_ERR("failed to register TMCB (2)\n");
							unref_dlg( dlg , 1);
					} else {
						ref_dlg( dlg , 1);
						if ( d_tmb.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
						(dir==DLG_DIR_UPSTREAM)?dlg_update_caller_rpl_contact:
						dlg_update_callee_rpl_contact, (void*)dlg, unreference_dialog)<0 ) {
							LM_ERR("failed to register TMCB (4)\n");
								unref_dlg( dlg , 1);
						}
					}
				}
			}

			dlg_lock (d_table, d_entry);

			if (dlg->legs[dst_leg].last_gen_cseq) {

				update_val = ++(dlg->legs[dst_leg].last_gen_cseq);
				if (req->first_line.u.request.method_value == METHOD_INVITE) {
					/* save INVITE cseq, in case any requests follow after this
					( pings or other in-dialog requests until the ACK comes in */
					dlg->legs[dst_leg].last_inv_gen_cseq = dlg->legs[dst_leg].last_gen_cseq;
				}

				dlg_unlock( d_table, d_entry );

				if (update_msg_cseq(req,0,update_val) != 0) {
					LM_ERR("failed to update sequential request msg cseq\n");
					ok = 0;
				}
			} else {
				if (req->first_line.u.request.method_value == METHOD_INVITE) {
					/* we did not generate any pings yet - still we need to store the INV cseq,
					in case there's a race between the ACK for the INVITE and sending of new pings */
					if (str2int(&((struct cseq_body *)req->cseq->parsed)->number,
							&dlg->legs[dst_leg].last_inv_gen_cseq) < 0)
						LM_ERR("invalid INVITE cseq [%.*s]\n",
								((struct cseq_body *)req->cseq->parsed)->number.len,
								((struct cseq_body *)req->cseq->parsed)->number.s);
				}

				dlg_unlock( d_table, d_entry );
			}

			if (ok) {
				dlg->flags |= DLG_FLAG_CHANGED;
				/* unmark dlg as loaded from DB (otherwise it would have been
				 * dropped later when syncing from cluster is done) */
				dlg->flags &= ~DLG_FLAG_FROM_DB;
				if (dlg_db_mode==DB_MODE_REALTIME)
					update_dialog_dbinfo(dlg);

				if (dialog_repl_cluster)
					replicate_dialog_updated(dlg);
			}
		} else {

			dlg_lock (d_table, d_entry);

			if (dlg->legs[dst_leg].last_gen_cseq ||
			dlg->legs[dst_leg].last_inv_gen_cseq ) {
				if (dlg->legs[dst_leg].last_inv_gen_cseq)
					update_val = dlg->legs[dst_leg].last_inv_gen_cseq;
				else
					update_val = dlg->legs[dst_leg].last_gen_cseq;
				dlg_unlock( d_table, d_entry );

				if (update_msg_cseq(req,0,update_val) != 0) {
					LM_ERR("failed to update ACK msg cseq\n");
				}
			} else
				dlg_unlock( d_table, d_entry );
		}

		if ( event!=DLG_EVENT_REQACK) {
			/* register callback for the replies of this request */

			dlg_lock( d_table, d_entry);
			if (dlg->legs[dst_leg].last_gen_cseq) {
				/* ref the dialog as registered into the transaction callback.
				 * unref will be done when the callback will be destroyed */
				ref_dlg_unsafe( dlg, 1);
				dlg_unlock( d_table,d_entry);

				if(parse_headers(req, HDR_CSEQ_F, 0) <0 ) {
					LM_ERR("failed to parse cseq header \n");
					unref_dlg(dlg,1);
					goto early_check;
				}

				msg_cseq = &((struct cseq_body *)req->cseq->parsed)->number;
				dlg_cseq_wrapper *wrap = shm_malloc(sizeof(dlg_cseq_wrapper) +
						msg_cseq->len);

				if (wrap == 0){
					LM_ERR("No more shm mem\n");
					unref_dlg(dlg, 1);
					goto early_check;
				}

				wrap->dlg = dlg;
				wrap->cseq.s = (char *)(wrap + 1);
				wrap->cseq.len = msg_cseq->len;
				memcpy(wrap->cseq.s,msg_cseq->s,msg_cseq->len);

				if ( d_tmb.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
				(dir==DLG_DIR_UPSTREAM)?dlg_seq_down_onreply_mod_cseq:dlg_seq_up_onreply_mod_cseq,
				(void*)wrap, unreference_dialog_cseq)<0 ) {
					LM_ERR("failed to register TMCB (2)\n");
					unref_dlg( dlg , 1);
					shm_free(wrap);
				}
			}
			else {
				/* dialog is in ping timer list
				 * but no pings have been generated yet */
				dlg_unlock ( d_table, d_entry );
			}
			if (dlg->cbs.types & DLGCB_RESPONSE_WITHIN)
			{
				ref_dlg( dlg , 1);
				if ( d_tmb.register_tmcb( req, 0, TMCB_RESPONSE_FWDED,
				(dir==DLG_DIR_UPSTREAM)?dlg_seq_down_onreply:dlg_seq_up_onreply,
				(void*)dlg, unreference_dialog)<0 ) {
					LM_ERR("failed to register TMCB (2)\n");
						unref_dlg( dlg , 1);
				}
			}
		}
	}

early_check:
	if ( (event==DLG_EVENT_REQPRACK || event == DLG_EVENT_REQ ||
			event == DLG_EVENT_REQBYE) && new_state==DLG_STATE_EARLY) {
		/* within dialog request */
		run_dlg_callbacks(DLGCB_REQ_WITHIN, dlg, req, dir, NULL, 0, 1);

		LM_DBG("EARLY event %d successfully processed (dst_leg=%d)\n",
			event,dst_leg);

		if (dst_leg==-1 || switch_cseqs(dlg, dst_leg) != 0 ||
		update_cseqs(dlg,req,dst_leg,0))
			LM_ERR("cseqs update failed on leg=%d\n",dst_leg);
	}

	if(new_state==DLG_STATE_CONFIRMED && old_state==DLG_STATE_CONFIRMED_NA){
		dlg->flags |= DLG_FLAG_CHANGED;
		/* unmark dlg as loaded from DB (otherwise it would have been
		 * dropped later when syncing from cluster is done) */
		dlg->flags &= ~DLG_FLAG_FROM_DB;
		if (dlg_db_mode == DB_MODE_REALTIME)
			update_dialog_dbinfo(dlg);

		if (dialog_repl_cluster && is_active)
			replicate_dialog_updated(dlg);

		if (dlg->flags & DLG_FLAG_PING_CALLER ||
		dlg->flags & DLG_FLAG_PING_CALLEE) {
			if (0 != insert_ping_timer( dlg)) {
				LM_CRIT("Unable to insert ping dlg %p [%u:%u] on event %d "
					"[%d->%d] with clid '%.*s' and tags '%.*s' '%.*s'\n",
					dlg, dlg->h_entry, dlg->h_id, event, old_state, new_state,
					dlg->callid.len, dlg->callid.s,
					dlg->legs[DLG_CALLER_LEG].tag.len,
					dlg->legs[DLG_CALLER_LEG].tag.s,
					dlg->legs[callee_idx(dlg)].tag.len,
					ZSW(dlg->legs[callee_idx(dlg)].tag.s));
			} else {
				/* reference dialog as kept in ping timer list */
				ref_dlg(dlg,1);
			}
		}

		if (dlg_has_reinvite_pinging(dlg)) {
			if (0 != insert_reinvite_ping_timer( dlg)) {
				LM_CRIT("Unable to insert ping dlg %p [%u:%u] on event %d "
					"[%d->%d] with clid '%.*s' and tags '%.*s' '%.*s'\n",
					dlg, dlg->h_entry, dlg->h_id, event, old_state, new_state,
					dlg->callid.len, dlg->callid.s,
					dlg->legs[DLG_CALLER_LEG].tag.len,
					dlg->legs[DLG_CALLER_LEG].tag.s,
					dlg->legs[callee_idx(dlg)].tag.len,
					ZSW(dlg->legs[callee_idx(dlg)].tag.s));
			} else {
				/* reference dialog as kept in reinvite ping timer list */
				ref_dlg(dlg,1);
			}
		}

	}

	return;
}


#define get_dlg_tl_payload(_tl_)  ((struct dlg_cell*)((char *)(_tl_)- \
		(unsigned long)(&((struct dlg_cell*)0)->tl)))

/* When done, this function also has the job to unref the dialog as removed
 * from timer list. This must be done in all cases!!
 */
void dlg_ontimeout(struct dlg_tl *tl)
{
	struct sip_msg *fake_msg = NULL;
	context_p old_ctx;
	context_p *new_ctx;
	struct dlg_cell *dlg;
	int new_state;
	int old_state;
	int unref;
	int do_expire_actions = 1;

	dlg = get_dlg_tl_payload(tl);

	LM_DBG("byeontimeout ? flags = %d , state = %d\n",dlg->flags,dlg->state);

	if (dialog_repl_cluster) {
		/* if dialog replication is used, send BYEs only if the current node
		 * is "in charge" of the dialog (or if unable to fetch this info) */
		do_expire_actions = get_shtag_state(dlg) != SHTAG_STATE_BACKUP;

		/* if we are backup for a dialog with on-timeout route, wait 10 mins
		 * more to see what decision the active takes, otherwise just expire
		 * the dialog. We this self prolonging only once! */
		if (!do_expire_actions && dlg->rt_on_timeout
		&& dlg->state<DLG_STATE_DELETED
		&& !(dlg->flags&DLG_FLAG_SELF_EXTENDED_TIMEOUT)) {
			LM_DBG("self prolonging with 10 mins to see what the active"
				"decides after the on-timeout route\n");
			dlg->flags |= DLG_FLAG_SELF_EXTENDED_TIMEOUT;
			tl->next = tl->prev = NULL;
			/* inherit the ref here */
			if (insert_dlg_timer( tl, 60*10) != 0) {
				LM_CRIT("Unable to insert dlg %p [%u:%u] in timer "
						"with clid '%.*s' and tags '%.*s' '%.*s'\n",
						dlg, dlg->h_entry, dlg->h_id,
						dlg->callid.len, dlg->callid.s,
						dlg->legs[DLG_CALLER_LEG].tag.len,
						dlg->legs[DLG_CALLER_LEG].tag.s,
						dlg->legs[callee_idx(dlg)].tag.len,
						ZSW(dlg->legs[callee_idx(dlg)].tag.s));
			}
			return;
		}
	}

	if (do_expire_actions && dlg->rt_on_timeout
	&& dlg->state<DLG_STATE_DELETED) {
		struct dlg_tl bk_tl = *tl;
		/* allow the dialog to be re-inserted in the timer list */
		tl->next = tl->prev = NULL;
		/* run the on_timeout route - only the active server will do this */
		run_dlg_script_route( dlg, dlg->rt_on_timeout);
		/* let's see what happened */
		if (tl->timeout) {
			/* dialog is back on the timelist, inheriting the ref count;
			 * also replicate an update, if some dlg data changed during
			 * the execution of the on-timeout route */
			if (dialog_repl_cluster && dlg->flags&DLG_FLAG_VP_CHANGED)
				replicate_dialog_updated(dlg);
			return;
		}
		/* continue with the handling of the timeout */
		*tl = bk_tl;
		/* there is no need to explicitly replicate the dialog termination
		 * here, as the following code will do this for us later */
	}

	if ((dlg->flags&DLG_FLAG_BYEONTIMEOUT) &&
	(dlg->state==DLG_STATE_CONFIRMED_NA || dlg->state==DLG_STATE_CONFIRMED)) {

		if (do_expire_actions) {
			if (dlg->flags & DLG_FLAG_RACE_CONDITION_OCCURRED)
				init_dlg_term_reason(dlg,"SIP Race Condition",
					sizeof("SIP Race Condition")-1);
			else
				init_dlg_term_reason(dlg,"Lifetime Timeout",
					sizeof("Lifetime Timeout")-1);
		}
		/* we just send the BYEs in both directions */
		dlg_end_dlg(dlg, NULL, do_expire_actions);
		/* dialog is no longer refed by timer; from now on it is refed
		   by the send_bye functions */
		unref_dlg(dlg, 1);
		/* is not 100% sure, but do it */
		if_update_stat(dlg_enable_stats, expired_dlgs, 1);

		return;
	}

	/* act like as if we've received a BYE from caller */
	next_state_dlg(dlg, DLG_EVENT_REQBYE, DLG_DIR_DOWNSTREAM, &old_state,
		&new_state, &unref, dlg->legs_no[DLG_LEG_200OK], do_expire_actions);

	if (new_state==DLG_STATE_DELETED && old_state!=DLG_STATE_DELETED) {
		LM_DBG("timeout for dlg with CallID '%.*s' and tags '%.*s' '%.*s'\n",
			dlg->callid.len, dlg->callid.s,
			dlg->legs[DLG_CALLER_LEG].tag.len,
			dlg->legs[DLG_CALLER_LEG].tag.s,
			dlg->legs[callee_idx(dlg)].tag.len,
			ZSW(dlg->legs[callee_idx(dlg)].tag.s));

		/*destroy profile linkers */
		destroy_linkers(dlg);
		remove_dlg_prof_table(dlg,do_expire_actions);

		/* dialog timeout */
		if (push_new_processing_context(dlg, &old_ctx, &new_ctx, &fake_msg)==0) {
			if (do_expire_actions)
				run_dlg_callbacks(DLGCB_EXPIRED, dlg, fake_msg,
					DLG_DIR_NONE, NULL, 0, do_expire_actions);

			if (current_processing_ctx == NULL)
				*new_ctx = NULL;
			else
				context_destroy(CONTEXT_GLOBAL, *new_ctx);

			/* reset the processing context */
			current_processing_ctx = old_ctx;
			release_dummy_sip_msg(fake_msg);
		}

		/* delete the dialog from DB */
		if (should_remove_dlg_db())
			remove_dialog_from_db(dlg);

		unref_dlg(dlg, unref + 1 /*timer list*/);

		if_update_stat(dlg_enable_stats, expired_dlgs, 1);
		if_update_stat(dlg_enable_stats, active_dlgs, -1);
	} else {
		unref_dlg(dlg, 1 /*just timer list*/);
	}

	return;
}

#define ROUTE_STR "Route: "
#define CRLF "\r\n"
#define ROUTE_LEN (sizeof(ROUTE_STR) - 1)
#define CRLF_LEN (sizeof(CRLF) - 1)

#define ROUTE_PREF "Route: <"
#define ROUTE_PREF_LEN (sizeof(ROUTE_PREF) -1)
#define ROUTE_SUFF ">\r\n"
#define ROUTE_SUFF_LEN (sizeof(ROUTE_SUFF) -1)

int fix_route_dialog(struct sip_msg *req,struct dlg_cell *dlg)
{
	struct dlg_leg *leg;
	struct hdr_field *it;
	char * buf,*route,*hdrs,*remote_contact;
	struct lump* lmp = NULL;
	int size;
	rr_t *head = NULL;
	struct sip_uri fru;
	int next_strict = 0;

	if (ctx_lastdstleg_get()<0 || ctx_lastdstleg_get()>=dlg->legs_no[DLG_LEGS_USED]) {
		log_bogus_dst_leg(dlg);
		LM_ERR("Script error - validate function before having a dialog\n");
		return -1;
	}

	leg = & dlg->legs[ ctx_lastdstleg_get() ];

	/* check in the stored routes */
	if ( leg->route_set.len && leg->route_set.s) {
		if(parse_uri(leg->route_uris[0].s, leg->route_uris[0].len, &fru) < 0) {
			LM_ERR("Failed to parse SIP uri\n");
			return -1;
		}
		LM_DBG("Next params [%.*s]\n", fru.params.len, fru.params.s);
		if(is_strict(&fru.params))
			next_strict = 1;
	}

	if (req->dst_uri.s && req->dst_uri.len) {
		/* reset dst_uri if previously set
		 * either by loose route or manually */
		pkg_free(req->dst_uri.s);
		req->dst_uri.s = NULL;
		req->dst_uri.len = 0;
	}

	/* r-uri is taken care of in all below cases,
	 * no need for manual resetting */

	//if ((*(d_rrb.routing_type) ==  ROUTING_LL) || (*d_rrb.routing_type) == ROUTING_SL )
	if (!next_strict)
	{
		LM_DBG("Fixing message. Next hop is Loose router\n");

		if (leg->contact.len && leg->contact.s) {
			LM_DBG("Setting new URI to  <%.*s> \n",leg->contact.len,
					leg->contact.s);

			if (set_ruri(req,&leg->contact) != 0) {
				LM_ERR("failed setting ruri\n");
				return -1;
			}
		}

		if( parse_headers( req, HDR_EOH_F, 0)<0 ) {
			LM_ERR("failed to parse headers when looking after ROUTEs\n");
			return -1;
		}

		buf = req->buf;

		if (req->route) {
			for (it=req->route;it;it=it->sibling) {
				if (it->parsed && ((rr_t*)it->parsed)->deleted)
					continue;
				if ((lmp = del_lump(req,it->name.s - buf,it->len,HDR_ROUTE_T)) == 0) {
					LM_ERR("del_lump failed \n");
					return -1;
				}
			}
		}

		if ( leg->route_set.len !=0 && leg->route_set.s) {

			lmp = anchor_lump(req,req->headers->name.s - buf,0);
			if (lmp == 0)
			{
				LM_ERR("failed anchoring new lump\n");
				return -1;
			}

			size = leg->route_set.len + ROUTE_LEN + CRLF_LEN;
			route = pkg_malloc(size+1);
			if (route == 0) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}

			memcpy(route,ROUTE_STR,ROUTE_LEN);
			memcpy(route+ROUTE_LEN,leg->route_set.s,leg->route_set.len);
			memcpy(route+ROUTE_LEN+leg->route_set.len,CRLF,CRLF_LEN);

			route[size] = 0;

			if ((lmp = insert_new_lump_after(lmp,route,size,HDR_ROUTE_T)) == 0) {
				LM_ERR("failed inserting new route set\n");
				pkg_free(route);
				return -1;
			}

			LM_DBG("Setting route  header to <%s> \n",route);

			if (parse_rr_body(leg->route_set.s,leg->route_set.len,&head) != 0) {
						LM_ERR("failed parsing route set\n");
						return -1;
			}

			LM_DBG("setting dst_uri to <%.*s> \n",head->nameaddr.uri.len,
					head->nameaddr.uri.s);

			if (set_dst_uri(req,&head->nameaddr.uri) !=0 ) {
				LM_ERR("failed setting new dst uri\n");
				free_rr(&head);
				return -1;
			}

			free_rr(&head);
		}
	}
	else
	{
		LM_DBG("Fixing message. Next hop is Strict router\n");

		if( parse_headers( req, HDR_EOH_F, 0)<0 ) {
			LM_ERR("failed to parse headers when looking after ROUTEs\n");
			return -1;
		}

		buf = req->buf;

		if (req->route) {
			for (it=req->route;it;it=it->sibling) {
				if (it->parsed && ((rr_t*)it->parsed)->deleted)
					continue;
				if ((lmp = del_lump(req,it->name.s - buf,it->len,HDR_ROUTE_T)) == 0) {
					LM_ERR("del_lump failed \n");
					return -1;
				}
			}
		}

		if ( leg->route_set.len !=0 && leg->route_set.s) {

			LM_DBG("setting R-URI to <%.*s> \n",leg->route_uris->len,
					leg->route_uris->s);

			if (set_ruri(req,leg->route_uris) !=0 ) {
				LM_ERR("failed setting new dst uri\n");
				return -1;
			}

			/* If there are more routes other than the first, add them */
			if (leg->nr_uris > 1) {

				/* FIXME - find a better way to skip the first route header.
				 * Instead or parsing again the entire route set, maybe remmember
				 * the needed pointer at the initial parsing of the route_set */
				if (parse_rr_body(leg->route_set.s,leg->route_set.len,&head) != 0) {
					LM_ERR("failed parsing route set\n");
					return -1;
				}

				lmp = anchor_lump(req,req->headers->name.s - buf,0);
				if (lmp == 0) {
					LM_ERR("failed anchoring new lump\n");
					free_rr(&head);
					return -1;
				}

				hdrs = leg->route_set.s + head->len + 1;

				size = leg->route_set.len - head->len - 1 + ROUTE_LEN + CRLF_LEN;
				route = pkg_malloc(size);
				if (route == 0) {
					LM_ERR("no more pkg memory\n");
					free_rr(&head);
					return -1;
				}

				memcpy(route,ROUTE_STR,ROUTE_LEN);
				memcpy(route+ROUTE_LEN,hdrs,leg->route_set.len - head->len-1);
				memcpy(route+ROUTE_LEN+leg->route_set.len - head->len-1,CRLF,CRLF_LEN);

				LM_DBG("Adding Route header : [%.*s] \n",size,route);

				if ((lmp = insert_new_lump_after(lmp,route,size,HDR_ROUTE_T)) == 0) {
					LM_ERR("failed inserting new route set\n");
					pkg_free(route);
					free_rr(&head);
					return -1;
				}
				free_rr(&head);
			}

			if (lmp == NULL) {
				lmp = anchor_lump(req,req->headers->name.s - buf,0);
				if (lmp == 0)
				{
					LM_ERR("failed anchoring new lump\n");
					return -1;
				}
			}

			if (leg->contact.len && leg->contact.s) {
				size = leg->contact.len + ROUTE_PREF_LEN + ROUTE_SUFF_LEN;
				remote_contact = pkg_malloc(size);
				if (remote_contact == NULL) {
					LM_ERR("no more pkg memory\n");
					return -1;
				}

				memcpy(remote_contact,ROUTE_PREF,ROUTE_PREF_LEN);
				memcpy(remote_contact+ROUTE_PREF_LEN,leg->contact.s,leg->contact.len);
				memcpy(remote_contact+ROUTE_PREF_LEN+leg->contact.len,
						ROUTE_SUFF,ROUTE_SUFF_LEN);

				LM_DBG("Adding remote contact route header : [%.*s]\n",
						size,remote_contact);

				if (insert_new_lump_after(lmp,remote_contact,size,HDR_ROUTE_T) == 0) {
					LM_ERR("failed inserting remote contact route\n");
					pkg_free(remote_contact);
					return -1;
				}
			}
		}
	}
	return 0;
}

int dlg_validate_dialog( struct sip_msg* req, struct dlg_cell *dlg)
{
	struct dlg_leg *leg;
	unsigned int n,m;
	int nr_routes,i,src_leg;
	str *rr_uri,*route_uris;

	if (ctx_lastdstleg_get()<0 || ctx_lastdstleg_get()>=dlg->legs_no[DLG_LEGS_USED]) {
		log_bogus_dst_leg(dlg);
		LM_ERR("Script error - validate function before having a dialog\n");
		return -4;
	}

	leg = & dlg->legs[ ctx_lastdstleg_get() ];

	/* first check the cseq */
	if ( (!req->cseq && parse_headers(req,HDR_CSEQ_F,0)<0) || !req->cseq ||
	!req->cseq->parsed) {
		LM_ERR("bad sip message or missing CSeq hdr :-/\n");
		return -4;
	}

	n = m = 0;

	if (req->first_line.u.request.method_value == METHOD_ACK) {
		/* ACKs should have the same cseq as INVITEs */
		if (ctx_lastdstleg_get() == DLG_CALLER_LEG)
			src_leg = callee_idx(dlg);
		else
			src_leg = DLG_CALLER_LEG;

		if ( str2int( &((get_cseq(req))->number), &n)!=0 ||
		str2int( &(dlg->legs[src_leg].inv_cseq), &m)!=0 || n!=m ) {
			LM_DBG("cseq test for ACK falied recv=%d, old=%d\n",n,m);
			return -1;
		}
	} else {
		if ( str2int( &((get_cseq(req))->number), &n)!=0 ||
		(leg->prev_cseq.s ?
			str2int( &(leg->prev_cseq), &m)!=0 :
			str2int( &(leg->r_cseq), &m)!=0
		 ) ||
		n<=m ) {
			LM_DBG("cseq test falied recv=%d, old=%d\n",n,m);
			return -1;
		}
	}



	LM_DBG("CSEQ validation passed\n");

	/* because fix_routing was called on the request */

	if ((dlg->mod_flags & TOPOH_ONGOING) || !has_rr())
		return 0;

	if (dlg->state <= DLG_STATE_EARLY)
		return 0;

	if (leg->contact.len) {
		rr_uri = d_rrb.get_remote_target(req);
		if (rr_uri == NULL)
		{
			LM_ERR("failed fetching remote target from msg\n");
			return -4;
		}

		if (compare_uris(rr_uri,0,&leg->contact,0))
		{
			LM_ERR("failed to validate remote contact: dlg=[%.*s] , req=[%.*s]\n",
					leg->contact.len,leg->contact.s,rr_uri->len,rr_uri->s);
			return -2;
		}
	}

	LM_DBG("Remote contact successfully validated\n");

	/* check the route set - is the the same as in original request */
	/* the route set (without the first Route) must be the same as the
	   one stored in the destination leg */
	/* extract the RR parts */

	if( parse_headers( req, HDR_EOH_F, 0)<0 ) {
		LM_ERR("failed to parse headers when looking after ROUTEs\n");
		return -4;
	}

	if ( req->route==NULL) {
		if ( leg->route_set.len!=0) {
			LM_DBG("route check failed (req has no route, but dialog has\n");
			return -3;
		}
	} else {
		route_uris = d_rrb.get_route_set(req,&nr_routes);
		if (route_uris == NULL) {
			LM_ERR("failed fetching route URIs from the msg\n");
			return -4;
		}

		if (nr_routes != leg->nr_uris) {
			LM_ERR("Different number of routes found in msg. req=%d, dlg=%d\n",
					nr_routes,leg->nr_uris);
			return -3;
		}

		for (i=0;i<nr_routes;i++)
		{
			LM_DBG("route %d. req=[%.*s],dlg=[%.*s]\n",
					i,route_uris[i].len,route_uris[i].s,leg->route_uris[i].len,
					leg->route_uris[i].s);
			if (compare_uris(&route_uris[i],0,&leg->route_uris[i],0))
			{
				LM_ERR("Check failed for route number %d. req=[%.*s],dlg=[%.*s]\n",
						i,route_uris[i].len,route_uris[i].s,leg->route_uris[i].len,
						leg->route_uris[i].s);
				return -3;
			}
		}
	}

	LM_DBG("Route Headers successfully validated\n");

	return 0;
}

int terminate_dlg(str *callid, unsigned int h_entry, unsigned int h_id,
	str *reason)
{
	struct dlg_cell * dlg = NULL;
	int ret = 0;

	if (callid)
		dlg = get_dlg_by_callid(callid, 1);
	else
		dlg = lookup_dlg(h_entry, h_id);

	if(!dlg)
		return 0;

	init_dlg_term_reason(dlg,reason->s,reason->len);

	if (dlg_end_dlg(dlg, 0, 1) ) {
		LM_ERR("Failed to end dialog\n");
		ret = -1;
	}

	unref_dlg(dlg, 1);
	return ret;
}

int test_and_set_dlg_flag(struct dlg_cell *dlg, unsigned long index,
		unsigned long value)
{
	int ret = -1;
	struct dlg_entry *d_entry = NULL;

	if (index > 31) {
		LM_ERR("invalid index %lu\n", index);
		goto end;
	}
	if (value > 1) {
		LM_ERR("Only binary values accepted - received %lu\n", value);
		goto end;
	}

	value = value << index;
	index = 1 << index;

	d_entry = &(d_table->entries[dlg->h_entry]);
	dlg_lock (d_table,d_entry);

	if ((dlg->user_flags & index) == value) {
		ret = 1;
		if (value)
			dlg->user_flags &= ~index;
		else
			dlg->user_flags |= index;
	}

	dlg_unlock (d_table,d_entry);

end:
	return ret;
}
