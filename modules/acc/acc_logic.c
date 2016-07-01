/*
 * $Id$
 *
 * Accounting module logic
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2006-09-19  forked from the acc_mod.c file during a big re-structuring
 *             of acc module (bogdan)
 */

#include <stdio.h>
#include <string.h>

#include "../../dprint.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_content.h"
#include "../tm/tm_load.h"
#include "../rr/api.h"

#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../../aaa/aaa.h"

#ifdef DIAM_ACC
#include "diam_dict.h"
#include "diam_tcp.h"
#endif

#include "acc.h"
#include "acc_mod.h"
#include "acc_logic.h"

extern struct tm_binds tmb;
extern struct rr_binds rrb;
extern str flags_str;
extern str table_str;

struct acc_enviroment acc_env;

static query_list_t *acc_ins_list = NULL;
static query_list_t *mc_ins_list = NULL;

#define is_acc_flag_set(_rq,_flag)  (((_rq)->flags)&(_flag))
#define reset_acc_flag(_rq,_flag)   (_rq)->flags &= ~(_flag)

#define is_failed_acc_on(_rq)  is_acc_flag_set(_rq,failed_transaction_flag)

#define is_log_acc_on(_rq)     is_acc_flag_set(_rq,log_flag)
#define is_log_mc_on(_rq)      is_acc_flag_set(_rq,log_missed_flag)

#define is_aaa_acc_on(_rq)     is_acc_flag_set(_rq,aaa_flag)
#define is_aaa_mc_on(_rq)      is_acc_flag_set(_rq,aaa_missed_flag)

#define is_db_acc_on(_rq)     is_acc_flag_set(_rq,db_flag)
#define is_db_mc_on(_rq)      is_acc_flag_set(_rq,db_missed_flag)

#define is_evi_acc_on(_rq)     is_acc_flag_set(_rq,evi_flag)
#define is_evi_mc_on(_rq)      is_acc_flag_set(_rq,evi_missed_flag)

#define is_cdr_acc_on(_rq)     is_acc_flag_set(_rq,cdr_flag)

#ifdef DIAM_ACC
	#define is_diam_acc_on(_rq)     is_acc_flag_set(_rq,diameter_flag)
	#define is_diam_mc_on(_rq)      is_acc_flag_set(_rq,diameter_missed_flag)
#else
	#define is_diam_acc_on(_rq)     (0)
	#define is_diam_mc_on(_rq)      (0)
#endif


#define is_acc_on(_rq) \
	( (is_log_acc_on(_rq)) || (is_db_acc_on(_rq)) \
	|| (is_aaa_acc_on(_rq)) || (is_diam_acc_on(_rq)) \
	|| (is_evi_acc_on(_rq)) )

#define is_mc_on(_rq) \
	( (is_log_mc_on(_rq)) || (is_db_mc_on(_rq)) \
	|| (is_aaa_mc_on(_rq)) || (is_diam_mc_on(_rq)) \
	|| (is_evi_mc_on(_rq)) )

#define skip_cancel(_rq) \
	(((_rq)->REQ_METHOD==METHOD_CANCEL) && report_cancels==0)




static void tmcb_func( struct cell* t, int type, struct tmcb_params *ps );
static void acc_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);


static inline struct hdr_field* get_rpl_to( struct cell *t,
														struct sip_msg *reply)
{
	if (reply==FAKED_REPLY || !reply || !reply->to)
		return t->uas.request->to;
	else
		return reply->to;
}


static inline void env_set_to(struct hdr_field *to)
{
	acc_env.to = to;
}


static inline void env_set_text(char *p, int len)
{
	acc_env.text.s = p;
	acc_env.text.len = len;
}


static inline void env_set_code_status( int code, struct sip_msg *reply)
{
	static char code_buf[INT2STR_MAX_LEN];

	acc_env.code = code;
	if (reply==FAKED_REPLY || reply==NULL) {
		/* code */
		acc_env.code_s.s =
			int2bstr((unsigned long)code, code_buf, &acc_env.code_s.len);
		/* reason */
		acc_env.reason.s = error_text(code);
		acc_env.reason.len = strlen(acc_env.reason.s);
	} else {
		acc_env.code_s = reply->first_line.u.reply.status;
		acc_env.reason = reply->first_line.u.reply.reason;
	}
}


static inline void env_set_comment(struct acc_param *accp)
{
	acc_env.code = accp->code;
	acc_env.code_s = accp->code_s;
	acc_env.reason = accp->reason;
}

static inline void env_set_event(event_id_t ev)
{
	acc_env.event = ev;
}


static inline int acc_preparse_req(struct sip_msg *req)
{
	if ( (parse_headers(req,HDR_CALLID_F|HDR_CSEQ_F|HDR_FROM_F|HDR_TO_F,0)<0)
	|| (parse_from_header(req)<0 ) ) {
		LM_ERR("failed to preparse request\n");
		return -1;
	}
	return 0;
}



int w_acc_log_request(struct sip_msg *rq, pv_elem_t* comment, char *foo)
{
	struct acc_param accp;

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_pvel_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );
	env_set_text( ACC_REQUEST, ACC_REQUEST_LEN);
	return acc_log_request( rq, NULL);
}


int w_acc_aaa_request(struct sip_msg *rq, pv_elem_t* comment, char* foo)
{
	struct acc_param accp;

	if (!aaa_proto_url) {
		LM_ERR("aaa support not configured\n");
		return -1;
	}

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_pvel_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );
	return acc_aaa_request( rq, NULL);
}


int w_acc_db_request(struct sip_msg *rq, pv_elem_t* comment, char *table)
{
	struct acc_param accp;
	int table_len;

	if (!table) {
		LM_ERR("db support not configured\n");
		return -1;
	}

	if (acc_preparse_req(rq)<0)
		return -1;

	table_len = strlen(table);

	acc_pvel_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );
	env_set_text(table, table_len);

	if (table_len == db_table_mc.len && (strncmp(table, db_table_mc.s, table_len) == 0)) {
		return acc_db_request(rq, NULL, &mc_ins_list);
	}

	if (table_len == db_table_acc.len && (strncmp(table, db_table_acc.s, table_len) == 0)) {
		return acc_db_request(rq, NULL, &acc_ins_list);
	}

	return acc_db_request( rq, NULL,NULL);
}

#ifdef DIAM_ACC
int w_acc_diam_request(struct sip_msg *rq, pv_elem_t* comment, char *foo)
{
	struct acc_param accp;

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_pvel_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );
	return acc_diam_request( rq, NULL);
}
#endif

int w_acc_evi_request(struct sip_msg *rq, pv_elem_t* comment, char *foo)
{
	struct acc_param accp;

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_pvel_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );

	return acc_evi_request( rq, NULL);
}

int acc_pvel_to_acc_param(struct sip_msg* rq, pv_elem_t* pv_el, struct acc_param* accp)
{
	str buf;
	if(pv_printf_s(rq, pv_el, &buf) < 0) {
		LM_ERR("Cannot parse comment\n");
		return 1;
	}

	accp->reason = buf;

	if (accp->reason.len>=3 && isdigit((int)buf.s[0])
	&& isdigit((int)buf.s[1]) && isdigit((int)buf.s[2]) ) {
		/* reply code is in the comment string */
		accp->code = (buf.s[0]-'0')*100 + (buf.s[1]-'0')*10 + (buf.s[2]-'0');
		accp->code_s.s = buf.s;
		accp->code_s.len = 3;
		accp->reason.s += 3;
		accp->reason.len -= 3;
		for( ; isspace((int)accp->reason.s[0]) ; accp->reason.s++,accp->reason.len-- );
	} else {
		/* no reply code */
		accp->code = 0;
		accp->code_s.s = NULL;
		accp->code_s.len = 0;
	}

	/*Default comment if none supplied*/
	if (accp->reason.len <= 0) {
		accp->reason.s = error_text(accp->code);
		accp->reason.len = strlen(accp->reason.s);
	}

	return 0;
}

static inline int has_totag(struct sip_msg *msg)
{
	/* check if it has to tag */
	if ( (!msg->to && parse_headers(msg, HDR_TO_F,0)<0) || !msg->to ) {
		LM_ERR("bad request or missing TO hdr :-/\n");
		return 0;
	}
	if (get_to(msg)->tag_value.s != 0 && get_to(msg)->tag_value.len != 0)
		return 1;
	return 0;
}



/* prepare message and transaction context for later accounting */
void acc_onreq( struct cell* t, int type, struct tmcb_params *ps )
{
	int tmcb_types;
	int is_invite;

	if ( ps->req && !skip_cancel(ps->req) &&
	(is_acc_on(ps->req) || is_mc_on(ps->req)) ) {
		/* do some parsing in advance */
		if (acc_preparse_req(ps->req)<0)
			return;
		is_invite = (ps->req->REQ_METHOD==METHOD_INVITE)?1:0;
		/* install additional handlers */
		tmcb_types =
			/* report on completed transactions */
			TMCB_RESPONSE_OUT |
			/* get incoming replies ready for processing */
			TMCB_RESPONSE_IN |
			/* report on missed calls */
			((is_invite && is_mc_on(ps->req))?TMCB_ON_FAILURE:0) ;

		/* if cdr accounting is enabled */
		if (is_cdr_acc_on(ps->req) && !has_totag(ps->req)) {
			if (is_invite && create_acc_dlg(ps->req) < 0) {
				LM_ERR("cannot use dialog accounting module\n");
				return;
			}
		}
		if (tmb.register_tmcb( 0, t, tmcb_types, tmcb_func, 0, 0 )<=0) {
			LM_ERR("cannot register additional callbacks\n");
			return;
		}
		/* if required, determine request direction */
		if( detect_direction && !rrb.is_direction(ps->req,RR_FLOW_UPSTREAM) ) {
			LM_DBG("detected an UPSTREAM req -> flaging it\n");
			ps->req->msg_flags |= FL_REQ_UPSTREAM;
		}
	}
}



/* is this reply of interest for accounting ? */
static inline int should_acc_reply(struct sip_msg *req,struct sip_msg *rpl,
																	int code)
{
	/* negative transactions reported otherwise only if explicitly
	 * demanded */
	if ( !is_failed_acc_on(req) && code >=300 )
		return 0;
	if ( !is_acc_on(req) )
		return 0;
	if ( code<200 && !(early_media && rpl!=FAKED_REPLY &&
	parse_headers(rpl,HDR_CONTENTLENGTH_F, 0)==0 && rpl->content_length &&
	get_content_length(rpl)>0 ) )
		return 0;

	return 1; /* seed is through, we will account this reply */
}



/* parse incoming replies before cloning */
static inline void acc_onreply_in(struct cell *t, struct sip_msg *req,
											struct sip_msg *reply, int code)
{
	/* don't parse replies in which we are not interested */
	/* missed calls enabled ? */
	if ( (reply && reply!=FAKED_REPLY) && (should_acc_reply(req,reply,code)
	|| (is_invite(t) && code>=300 && is_mc_on(req))) ) {
		parse_headers(reply, HDR_TO_F, 0 );
	}
}



/* initiate a report if we previously enabled MC accounting for this t */
static inline void on_missed(struct cell *t, struct sip_msg *req,
											struct sip_msg *reply, int code)
{
	str new_uri_bk={0,0};
	str dst_uri_bk={0,0};
	int flags_to_reset = 0;

	if (t->nr_of_outgoings) {
		/* set as new_uri the last branch */
		new_uri_bk = req->new_uri;
		dst_uri_bk = req->dst_uri;
		req->new_uri = t->uac[t->nr_of_outgoings-1].uri;
		req->dst_uri = t->uac[t->nr_of_outgoings-1].duri;
		req->parsed_uri_ok = 0;
	}

	/* set env variables */
	env_set_to( get_rpl_to(t,reply) );
	env_set_code_status( code, reply);

	/* we report on missed calls when the first
	 * forwarding attempt fails; we do not wish to
	 * report on every attempt; so we clear the flags;
	 */

	if (is_evi_mc_on(req)) {
		env_set_event(acc_missed_event);
		acc_evi_request( req, reply );
		flags_to_reset |= evi_missed_flag;
	}

	if (is_log_mc_on(req)) {
		env_set_text( ACC_MISSED, ACC_MISSED_LEN);
		acc_log_request( req, reply );
		flags_to_reset |= log_missed_flag;
	}

	if (is_aaa_mc_on(req)) {
		acc_aaa_request( req, reply );
		flags_to_reset |= aaa_missed_flag;
	}

	if (is_db_mc_on(req)) {
		env_set_text(db_table_mc.s, db_table_mc.len);
		acc_db_request( req, reply,&mc_ins_list);
		flags_to_reset |= db_missed_flag;
	}
/* DIAMETER */
#ifdef DIAM_ACC
	if (is_diam_mc_on(req)) {
		acc_diam_request( req, reply );
		flags_to_reset |= diameter_missed_flag;
	}
#endif

	/* Reset the accounting missed_flags
	 * These can't be reset in the blocks above, because
	 * it would skip accounting if the flags are identical
	 */
	reset_acc_flag( req, flags_to_reset );

	if (t->nr_of_outgoings) {
		req->new_uri = new_uri_bk;
		req->dst_uri = dst_uri_bk;
		req->parsed_uri_ok = 0;
	}
}


/* restore callbacks */
void acc_loaded_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params) {
		str flags_s;
		unsigned int flags_l;

		if (!dlg) {
			LM_ERR("null dialog - cannot fetch message flags\n");
			return;
		}

		if (dlg_api.fetch_dlg_value(dlg, &flags_str, &flags_s, 0) < 0) {
			LM_DBG("flags were not saved in dialog\n");
			return;
		}
		flags_l = flag_list_to_bitmask(&flags_s, FLAG_TYPE_MSG, FLAG_DELIM);

		/* register database callbacks */
		if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED |
				DLGCB_EXPIRED, acc_dlg_callback, (void*)(long)flags_l, 0)){
			LM_ERR("cannot register callback for database accounting\n");
			return;
		}
}

/* initiate a report if we previously enabled accounting for this t */
static inline void acc_onreply( struct cell* t, struct sip_msg *req,
											struct sip_msg *reply, int code)
{
	str new_uri_bk;
	str dst_uri_bk;
	struct dlg_cell *dlg = NULL;
	str flags_s;
	int_str table;
	struct usr_avp *avp;

	/* acc_onreply is bound to TMCB_REPLY which may be called
	   from _reply, like when FR hits; we should not miss this
	   event for missed calls either */
	if (is_invite(t) && code>=300 && is_mc_on(req) )
		on_missed(t, req, reply, code);

	if (!should_acc_reply(req, reply, code))
		return;

	/* for reply processing, set as new_uri the winning branch */
	if (t->relaied_reply_branch>=0) {
		new_uri_bk = req->new_uri;
		dst_uri_bk = req->dst_uri;
		req->new_uri = t->uac[t->relaied_reply_branch].uri;
		req->dst_uri = t->uac[t->relaied_reply_branch].duri;
		req->parsed_uri_ok = 0;
	} else {
		new_uri_bk.len = dst_uri_bk.len = -1;
		new_uri_bk.s = dst_uri_bk.s = NULL;
	}
	/* set env variables */
	env_set_to( get_rpl_to(t,reply) );
	env_set_code_status( code, reply);

	/* search for table avp */
	table.s = db_table_acc;
	if (db_table_name != -1 && is_db_acc_on(req)) {
		avp = search_first_avp(db_table_name_type, db_table_name, &table, 0);
		if (!avp) {
			LM_DBG("table not set: using default %.*s\n",
					db_table_acc.len, db_table_acc.s);
		} else {
			if (!(avp->flags & AVP_VAL_STR)) {
				LM_WARN("invalid integer table name: using default %.*s\n",
					db_table_acc.len, db_table_acc.s);
				table.s = db_table_acc;
			}
		}
	}

	if (is_invite(t) && !has_totag(req) && is_cdr_acc_on(req) &&
			code >= 200 && code < 300 && (dlg=dlg_api.get_dlg()) != NULL) {
		/* if dialog module loaded and INVITE and success reply */
		if (store_core_leg_values(dlg, req) < 0) {
			LM_ERR("cannot store core and leg values\n");
			return;
		}

		if(is_log_acc_on(req) && store_log_extra_values(dlg,req,reply)<0){
			LM_ERR("cannot store string values\n");
			return;
		}

		if(is_aaa_acc_on(req) && store_aaa_extra_values(dlg, req, reply)<0){
			LM_ERR("cannot store aaa extra values\n");
			return;
		}

		if (is_db_acc_on(req) && store_db_extra_values(dlg,req,reply)<0) {
			LM_ERR("cannot store database extra values\n");
			return;
		}

		if (is_evi_acc_on(req) && store_evi_extra_values(dlg,req,reply)<0) {
			LM_ERR("cannot store database extra values\n");
			return;
		}

		flags_s = bitmask_to_flag_list(FLAG_TYPE_MSG, req->flags);

		/* store flags into dlg */
		if ( dlg_api.store_dlg_value(dlg, &flags_str, &flags_s) < 0) {
			LM_ERR("cannot store flag value into dialog\n");
			return;
		}

		/* store flags into dlg */
		if ( dlg_api.store_dlg_value(dlg, &table_str, &table.s) < 0) {
			LM_ERR("cannot store the table name into dialog\n");
			return;
		}
		/* register database callbacks */
		if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED |
				DLGCB_EXPIRED, acc_dlg_callback,(void *)(long)req->flags,0) != 0) {
			LM_ERR("cannot register callback for database accounting\n");
			return;
		}
	} else {
		/* do old accounting */
		if ( is_evi_acc_on(req) ) {
			env_set_event(acc_event);
			acc_evi_request( req, reply );
		}

		if ( is_log_acc_on(req) ) {
			env_set_text( ACC_ANSWERED, ACC_ANSWERED_LEN);
			acc_log_request( req, reply );
		}

		if (is_aaa_acc_on(req))
			acc_aaa_request( req, reply );

		if (is_db_acc_on(req)) {
			env_set_text( table.s.s, table.s.len);
			acc_db_request( req, reply, &acc_ins_list);
		}
	}

/* DIAMETER */
#ifdef DIAM_ACC
	if (is_diam_acc_on(req))
		acc_diam_request( req, reply );
#endif

	if (new_uri_bk.len>=0) {
		req->new_uri = new_uri_bk;
		req->dst_uri = dst_uri_bk;
		req->parsed_uri_ok = 0;
	}
}

static void acc_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	unsigned int flags;

	if (!_params) {
		LM_ERR("not enough info\n");
		return;
	}
	flags = (unsigned int)(long)(*_params->param);

	if (flags & evi_flag) {
		env_set_event(acc_cdr_event);
		if (acc_evi_cdrs(dlg, _params->msg) < 0) {
			LM_ERR("cannot send accounting events\n");
			return;
		}
	}

	if (flags & log_flag) {
		env_set_text( ACC_ENDED, ACC_ENDED_LEN);
		if (acc_log_cdrs(dlg, _params->msg) < 0) {
			LM_ERR("Cannot log values\n");
			return;
		}
	}

	if (flags & db_flag) {
		env_set_text( db_table_acc.s, db_table_acc.len);
		if (acc_db_cdrs(dlg, _params->msg) < 0) {
			LM_ERR("Cannot insert into database\n");
			return;
		}
	}

	if ((flags & aaa_flag) && acc_aaa_cdrs(dlg, _params->msg) < 0) {
		LM_ERR("Cannot create radius accounting\n");
		return;
	}
}


static void tmcb_func( struct cell* t, int type, struct tmcb_params *ps )
{
	if (type&TMCB_RESPONSE_OUT) {
		acc_onreply( t, ps->req, ps->rpl, ps->code);
	} else if (type&TMCB_ON_FAILURE) {
		on_missed( t, ps->req, ps->rpl, ps->code);
	} else if (type&TMCB_RESPONSE_IN) {
		acc_onreply_in( t, ps->req, ps->rpl, ps->code);
	}
}

