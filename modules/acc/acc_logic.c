/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "../../mod_fix.h"
#include "../../dprint.h"

#include "acc.h"
#include "acc_mod.h"
#include "acc_logic.h"
#include "acc_extra.h"
#include "acc_vars.h"

extern struct tm_binds tmb;
extern struct rr_binds rrb;
extern str flags_str;
extern str table_str;
extern str extra_str;
extern str leg_str;
extern str created_str;

extern str acc_created_avp_name;
extern int acc_created_avp_id;

extern int acc_flags_ctx_idx;
extern int acc_tm_flags_ctx_idx;
extern int acc_dlg_ctx_idx;

extern tag_t* extra_tags;
extern int extra_tgs_len;

extern tag_t* leg_tags;
extern int leg_tgs_len;

struct acc_enviroment acc_env;

static query_list_t *acc_ins_list = NULL;
static query_list_t *mc_ins_list = NULL;

int is_cdr_enabled=0;

#define is_acc_flag_set(_mask, _type, _flag) ( _mask & ((_type * _flag)))

#define is_log_flag_on(_mask, _flag) is_acc_flag_set(_mask, DO_ACC_LOG, _flag)
#define is_log_acc_on(_mask)         is_log_flag_on(_mask, DO_ACC)
#define is_log_cdr_on(_mask)         is_log_flag_on(_mask, DO_ACC_CDR)
#define is_log_mc_on(_mask)          is_log_flag_on(_mask, DO_ACC_MISSED)
#define is_log_failed_on(_mask)      is_log_flag_on(_mask, DO_ACC_FAILED)

#define is_aaa_flag_on(_mask, _flag) is_acc_flag_set(_mask, DO_ACC_AAA, _flag)
#define is_aaa_acc_on(_mask)         is_aaa_flag_on(_mask, DO_ACC)
#define is_aaa_cdr_on(_mask)         is_aaa_flag_on(_mask, DO_ACC_CDR)
#define is_aaa_mc_on(_mask)          is_aaa_flag_on(_mask, DO_ACC_MISSED)
#define is_aaa_failed_on(_mask)      is_aaa_flag_on(_mask, DO_ACC_FAILED)

#define is_db_flag_on(_mask, _flag)  is_acc_flag_set(_mask, DO_ACC_DB, _flag)
#define is_db_acc_on(_mask)          is_db_flag_on(_mask, DO_ACC)
#define is_db_cdr_on(_mask)          is_db_flag_on(_mask, DO_ACC_CDR)
#define is_db_mc_on(_mask)           is_db_flag_on(_mask, DO_ACC_MISSED)
#define is_db_failed_on(_mask)       is_db_flag_on(_mask, DO_ACC_FAILED)

#define is_evi_flag_on(_mask, _flag) is_acc_flag_set(_mask, DO_ACC_EVI, _flag)
#define is_evi_acc_on(_mask)         is_evi_flag_on(_mask, DO_ACC)
#define is_evi_cdr_on(_mask)         is_evi_flag_on(_mask, DO_ACC_CDR)
#define is_evi_mc_on(_mask)          is_evi_flag_on(_mask, DO_ACC_MISSED)
#define is_evi_failed_on(_mask)      is_evi_flag_on(_mask, DO_ACC_FAILED)


#define is_acc_on(_mask) \
	( (is_log_acc_on(_mask)) || (is_db_acc_on(_mask)) \
	|| (is_aaa_acc_on(_mask)) || (is_evi_acc_on(_mask)) )

#define is_cdr_acc_on(_mask) (is_log_cdr_on(_mask)  ||              \
		is_aaa_cdr_on(_mask) || is_db_cdr_on(_mask) ||              \
		is_evi_cdr_on(_mask))

#define is_mc_acc_on(_mask) (is_log_mc_on(_mask)    ||              \
		is_aaa_mc_on(_mask) || is_db_mc_on(_mask)  ||              \
		is_evi_mc_on(_mask))

#define is_failed_acc_on(_mask) (is_log_failed_on(_mask)  ||        \
		is_aaa_failed_on(_mask) || is_db_failed_on(_mask) ||        \
		is_evi_failed_on(_mask))

#define is_dialog_context(_mask) ((_mask)&ACC_DIALOG_CONTEXT)

#define set_cdr_values_registered(_mask) \
	(_mask) |= ACC_CDR_REGISTERED;

#define set_dlg_cb_used(_mask) \
	(_mask) |= ACC_DLG_CB_USED;

#define was_dlg_cb_used(_mask) (_mask&ACC_DLG_CB_USED)

#define cdr_values_registered(_mask) ((_mask)&ACC_CDR_REGISTERED)

#define acc_ref_unsafe(_ctx, _val) (_ctx)->ref_no += (_val)

#define acc_ref_ex(_ctx, _val) \
	do { \
		accX_lock(&(_ctx)->lock); \
		acc_ref_unsafe(_ctx, _val); \
		accX_unlock(&(_ctx)->lock); \
	} while(0)

#define acc_unref_ex(_ctx, _val) \
	do { \
		accX_lock(&(_ctx)->lock); \
		acc_ref_unsafe(_ctx, -(_val)); \
		if ((_ctx)->ref_no == 0) {\
			accX_unlock(&(_ctx)->lock); \
			free_acc_ctx(_ctx); \
		} else { \
			if ((_ctx)->ref_no < 0) \
				LM_BUG("ref=%d ctx=%p gone negative! (%s:%d)\n", \
						(_ctx)->ref_no, (_ctx), __FILE__, __LINE__); \
			accX_unlock(&(_ctx)->lock); \
		} \
	} while(0)

#define acc_ref(_ctx) acc_ref_ex(_ctx, 1)
#define acc_unref(_ctx) acc_unref_ex(_ctx, 1)

#define reset_flags(_flags, _flags_to_reset) \
	_flags &= ~_flags_to_reset;


#define skip_cancel(_rq) \
	(((_rq)->REQ_METHOD==METHOD_CANCEL) && report_cancels==0)


static void tmcb_func( struct cell* t, int type, struct tmcb_params *ps );
static void acc_dlg_ended(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);
static void acc_dlg_onwrite(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);
static void acc_cdr_cb( struct cell* t, int type, struct tmcb_params *ps );

void free_extra_array(extra_value_t* array, int array_len)
{
	int i;

	for (i=0; i < array_len; i++) {
		if (array[i].value.s)
			shm_free(array[i].value.s);
	}
	shm_free(array);
}

static inline void free_acc_ctx(acc_ctx_t* ctx)
{
	int i;
	struct dlg_cell *dlg;

	if (ctx->extra_values)
		free_extra_array(ctx->extra_values, extra_tgs_len);

	if (ctx->leg_values) {
		for (i=0; i<ctx->legs_no; i++) {
			free_extra_array(ctx->leg_values[i], leg_tgs_len);
		}
		shm_free(ctx->leg_values);
	}
	if (ctx->acc_table.s)
		shm_free(ctx->acc_table.s);

	/* also cleanup dialog */
	dlg = dlg_api.get_dlg ? dlg_api.get_dlg() : NULL;
	if (dlg && ctx == dlg_api.dlg_ctx_get_ptr(dlg, acc_dlg_ctx_idx))
		dlg_api.dlg_ctx_put_ptr(dlg, acc_dlg_ctx_idx, NULL);
	shm_free(ctx);
}

static inline struct hdr_field* get_rpl_to( struct cell *t,
														struct sip_msg *reply)
{
	if (reply==FAKED_REPLY || !reply || !reply->to)
		return t->uas.request->to;
	else
		return reply->to;
}

acc_ctx_t* try_fetch_ctx(void)
{
	acc_ctx_t* ret=NULL;

	struct cell* t;
	struct dlg_cell* dlg;

	if ((ret = ACC_GET_CTX()) == NULL) {
		if (!tmb.t_gett || (t = tmb.t_gett()) == T_UNDEFINED)
			t = NULL;

		dlg = dlg_api.get_dlg ? dlg_api.get_dlg() : NULL;

		/* search for the context in transaction context */
		if (t && (ret=ACC_GET_TM_CTX(t))==NULL) {
			/* try fetching the context from dialog only if dialog exists */
			if (!dlg)
				return NULL;
			ret = dlg_api.dlg_ctx_get_ptr(dlg, acc_dlg_ctx_idx);
			if (!ret)
				/* can't find the context anywhere */
				return NULL;

			acc_ref_ex(ret, 2);
			ACC_PUT_TM_CTX(t, ret);
			ACC_PUT_CTX(ret);
		} else if (ret) { /* we have the context in transaction */
			/* in transaction; put them in dialog(if possible) and in processing context */
			acc_ref(ret);
			ACC_PUT_CTX(ret);
		} else if (dlg) { /* no (context in) transaction; search only in dialog*/
			ret = dlg_api.dlg_ctx_get_ptr(dlg, acc_dlg_ctx_idx);
			if (!ret)
				/* can't find the context anywhere */
				return NULL;
			if (t) {
				acc_ref_ex(ret, 2); /* ref twice - for local and tm ctx */
				ACC_PUT_TM_CTX(t, ret);
			} else
				acc_ref(ret); /* ref only once, for local ctx */
			ACC_PUT_CTX(ret);
		}
	}

	return ret;
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

static inline void env_set_event(event_id_t ev, evi_params_p params_list,
	evi_param_p *params)
{
	acc_env.event = ev;
	acc_env.ev_params_list = params_list;
	acc_env.ev_params = params;
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



int w_acc_log_request(struct sip_msg *rq, str* comment)
{
	struct acc_param accp;

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_comm_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );
	env_set_text( ACC_REQUEST, ACC_REQUEST_LEN);

	return acc_log_request( rq, NULL, 0);
}


int w_acc_aaa_request(struct sip_msg *rq, str* comment)
{
	struct acc_param accp;

	if (!aaa_proto_url) {
		LM_ERR("aaa support not configured\n");
		return -1;
	}

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_comm_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );

	return acc_aaa_request( rq, NULL, 0);
}


int w_acc_db_request(struct sip_msg *rq, str* comment, str *table)
{
	struct acc_param accp;

	if (!table) {
		LM_ERR("db support not configured\n");
		return -1;
	}

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_comm_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );
	env_set_text(table->s, table->len);

	if (str_match(table, &db_table_mc))
		return acc_db_request(rq, NULL, &mc_ins_list, 0, 1);

	if (str_match(table, &db_table_acc))
		return acc_db_request(rq, NULL, &acc_ins_list, 0, 0);

	return acc_db_request( rq, NULL,NULL, 0, 0);
}

int w_acc_evi_request(struct sip_msg *rq, str* comment)
{
	struct acc_param accp;

	if (acc_preparse_req(rq)<0)
		return -1;

	acc_comm_to_acc_param(rq, comment, &accp);

	env_set_to( rq->to );
	env_set_comment( &accp );

#if 0
	if (is_cdr_acc_on(rq) && is_evi_acc_on(rq)) {
		env_set_event(acc_cdr_event);
	} else if (is_evi_acc_on(rq) && acc_env.code < 300) {
		env_set_event(acc_event);
	} else if (is_evi_mc_on(rq)) {
		env_set_event(acc_missed_event);
	} else {
		LM_WARN("evi request flags not set\n");
		return 1;
	}
#endif
	if (acc_env.code < 300) {
		env_set_event(acc_event, acc_event_params, evi_params);
		return acc_evi_request( rq, NULL, 0, 0);
	} else {
		env_set_event(acc_missed_event, acc_missed_event_params,
			evi_missed_params);
		return acc_evi_request( rq, NULL, 0, 1);
	}
}

int acc_comm_to_acc_param(struct sip_msg* rq, str* comm, struct acc_param* accp)
{
	accp->reason = *comm;

	if (accp->reason.len>=3 && isdigit((int)comm->s[0])
	&& isdigit((int)comm->s[1]) && isdigit((int)comm->s[2]) ) {
		/* reply code is in the comment string */
		accp->code = (comm->s[0]-'0')*100 + (comm->s[1]-'0')*10 + (comm->s[2]-'0');
		accp->code_s.s = comm->s;
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


/* is this reply of interest for accounting ? */
static inline int should_acc_reply(struct sip_msg *req,struct sip_msg *rpl,
								int code, unsigned long long* flags)
{
	/* negative transactions reported otherwise only if explicitly
	 * demanded */
	if ( !is_failed_acc_on(*flags) && code >=300 ) {
		return 0;
	}
	if ( !is_acc_on(*flags) ) {
		return 0;
	}
	if ( code<200 && !(early_media && rpl!=FAKED_REPLY &&
	parse_headers(rpl,HDR_CONTENTLENGTH_F, 0)==0 && rpl->content_length &&
	get_content_length(rpl)>0 ) ) {
		return 0;
	}

	return 1; /* seed is through, we will account this reply */
}



/* parse incoming replies before cloning */
static inline void acc_onreply_in(struct cell *t, struct sip_msg *req,
					struct sip_msg *reply, int code, acc_ctx_t* ctx)
{
	/* don't parse replies in which we are not interested */
	/* missed calls enabled ? */
	if (reply
			&& reply != FAKED_REPLY
			&& (should_acc_reply(req,reply,code, &ctx->flags)
				|| (is_invite(t)
					&& code >= 300
					&& is_mc_acc_on(ctx->flags)))) {
		parse_headers(reply, HDR_TO_F, 0 );
	}
}



/* initiate a report if we previously enabled MC accounting for this t */
static inline void on_missed(struct cell *t, struct sip_msg *req,
					struct sip_msg *reply, int code, acc_ctx_t *ctx)
{
	str new_uri_bk={0,0};
	str dst_uri_bk={0,0};
	unsigned long long flags_to_reset=0;
	unsigned long long *flags = &ctx->flags;

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

	if (is_evi_mc_on(*flags)) {
		env_set_event(acc_missed_event, acc_missed_event_params,
			evi_missed_params);
		acc_evi_request( req, reply, is_evi_cdr_on(*flags) ? 1 : 0, 1 );
		flags_to_reset |= DO_ACC_EVI * DO_ACC_MISSED;
	}

	if (is_log_mc_on(*flags)) {
		env_set_text( ACC_MISSED, ACC_MISSED_LEN);
		acc_log_request( req, reply, is_log_cdr_on(*flags) );
		flags_to_reset |= DO_ACC_LOG * DO_ACC_MISSED;
	}

	if (is_aaa_mc_on(*flags)) {
		acc_aaa_request( req, reply, is_aaa_cdr_on(*flags) );
		flags_to_reset |= DO_ACC_AAA * DO_ACC_MISSED;
	}

	if (is_db_mc_on(*flags)) {
		env_set_text(db_table_mc.s, db_table_mc.len);
		acc_db_request( req, reply,&mc_ins_list, is_db_cdr_on(*flags), 1);
		flags_to_reset |= DO_ACC_DB * DO_ACC_MISSED;
	}

	/* Reset the accounting missed_flags
	 * These can't be reset in the blocks above, because
	 * it would skip accounting if the flags are identical
	 */

	if (t->nr_of_outgoings) {
		req->new_uri = new_uri_bk;
		req->dst_uri = dst_uri_bk;
		req->parsed_uri_ok = 0;
	}

	reset_flags(*flags, flags_to_reset);

}

/*
 * This mid-dialog request callback ensures that any extra/leg settings done
 * at script level before dialog matching is performed will get properly
 * transferred into the dialog context, once the dialog is matched
 */
static void acc_merge_contexts(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	acc_ctx_t *ctx;

	/* if there is already a acc context in the processing
	 * context, be sure to destroy it for now */
	if ((ctx = ACC_GET_CTX())) {
		push_ctx_to_ctx( ctx, (acc_ctx_t *)(*_params->param));
		acc_unref(ctx); /* unref it now beause it will disapear from local ctx */
	}

	ctx = (acc_ctx_t *)(*_params->param);
	acc_ref(ctx);
	ACC_PUT_CTX(ctx);
}


/* restore callbacks */
void acc_update_ctx_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params)
{
	str flags_s;
	acc_ctx_t* ctx = (acc_ctx_t *)(*_params->param);
	unsigned long long flags;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch message flags\n");
		return;
	}

	/* check if the ctx exists in the dialog */
	if (!ctx) {
		LM_DBG("there's no dialog ctx created before - can't do anything\n");
		return;
	}

	flags_s.s = (char *)&flags;
	flags_s.len = sizeof(flags);
	if (dlg_api.fetch_dlg_value(dlg, &flags_str, &flags_s, 1) < 0) {
		LM_DBG("flags were not saved in dialog\n");
		return;
	}
	ctx->flags = flags;

	if (restore_dlg_extra_ctx(dlg, ctx)) {
		LM_ERR("failed to rebuild acc context!\n");
		return;
	}
}

void acc_loaded_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params) {
		str flags_s, table_s, created_s;
		acc_ctx_t* ctx;
		time_t created;
		unsigned long long flags;

		if (!dlg) {
			LM_ERR("null dialog - cannot fetch message flags\n");
			return;
		}

		flags_s.s = (char *)&flags;
		flags_s.len = sizeof(flags);
		if (dlg_api.fetch_dlg_value(dlg, &flags_str, &flags_s, 1) < 0) {
			LM_DBG("flags were not saved in dialog\n");
			return;
		}

		created_s.s = (char *)&created;
		created_s.len = sizeof(created);
		if (dlg_api.fetch_dlg_value(dlg, &created_str, &created_s, 1) < 0) {
			LM_DBG("created time was not saved in dialog\n");
			return;
		}

		/**
		 * restore acc extra context(extra and leg values)
		 */
		if (restore_dlg_extra(dlg, &ctx)) {
			LM_ERR("failed to rebuild acc context!\n");
			return;
		}

		/* copy flags value into the context */
		ctx->flags = flags;

		/* copy created value into the context */
		ctx->created = created;

		/* restore accounting table if db accounting is used */
		if (is_db_acc_on(ctx->flags)) {
			if (dlg_api.fetch_dlg_value(dlg, &table_str, &table_s, 0) < 0) {
				LM_DBG("table was not saved in dialog\n");
				return;
			}

			if ((ctx->acc_table.s=shm_malloc(table_s.len)) == NULL) {
				LM_ERR("no more shm!\n");
				return;
			}

			memcpy(ctx->acc_table.s, table_s.s, table_s.len);
			ctx->acc_table.len = table_s.len;
		}



		/* replace the context value with a good pointer */
		acc_ref_ex(ctx, 3);
		dlg_api.dlg_ctx_put_ptr(dlg, acc_dlg_ctx_idx, ctx);

		/* register database callbacks */
		if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED |
				DLGCB_EXPIRED, acc_dlg_ended, ctx, unref_acc_ctx)){
			LM_ERR("cannot register callback for database accounting\n");
			acc_unref_ex(ctx, 2); /* storing the pointer was successful */
			return;
		}

		/* register dlg callbacks for ctx management */
		if (dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN,
				acc_merge_contexts, ctx, unref_acc_ctx) != 0) {
			acc_unref(ctx); /* only one, the other one was successful */
			LM_ERR("cannot register callback ctx management\n");
			return;
		}

		/* register dlg callbacks for updating extra vars */
		if (dlg_api.register_dlgcb(dlg, DLGCB_PROCESS_VARS,
				acc_update_ctx_callback, ctx, NULL) != 0) {
			acc_unref(ctx); /* only one, the other one was successful */
			LM_ERR("cannot register callback ctx management\n");
			return;
		}

}

/* initiate a report if we previously enabled accounting for this t */
static inline void acc_onreply( struct cell* t, struct sip_msg *req,
					struct sip_msg *reply, int code, acc_ctx_t* ctx)
{
	str new_uri_bk;
	str dst_uri_bk;
	struct dlg_cell *dlg = NULL;
	str table;

	unsigned long long* flags = &ctx->flags;

	/* acc_onreply is bound to TMCB_REPLY which may be called
	   from _reply, like when FR hits; we should not miss this
	   event for missed calls either */
	if (is_invite(t) && code>=300 && is_mc_acc_on(*flags) ) {
		on_missed(t, req, reply, code, ctx);
	}

	if (!should_acc_reply(req, reply, code, flags))
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
	if (is_db_acc_on(ctx->flags))
		table = ctx->acc_table;
	else {
		table.s = 0;
		table.len = 0;
	}

	if (is_invite(t) && !has_totag(req) && is_cdr_acc_on(ctx->flags) &&
			code >= 200 && code < 300 && (dlg=dlg_api.get_dlg()) != NULL) {
		/* if dialog module loaded and INVITE and success reply */
		if (store_core_leg_values(dlg, req) < 0) {
			LM_ERR("cannot store core and leg values\n");
			goto restore;
		}

		/* register callback for program shutdown or dialog replication
		 * won't register free function since TERMINATED|EXPIRED callback
		 * free function will be called to free */
		if (dlg_api.register_dlgcb(dlg, DLGCB_WRITE_VP,
					acc_dlg_onwrite, ctx, NULL) != 0) {
			LM_ERR("cannot register callback for context serialization\n");
			goto restore;
		}

		/* register database callbacks */
		acc_ref_ex(ctx, 2);
		if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
								acc_dlg_ended, ctx, unref_acc_ctx) != 0) {
			acc_unref_ex(ctx, 2);
			LM_ERR("cannot register callback for database accounting\n");
			goto restore;
		}

		/* register dlg callbacks for ctx management */
		if (dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN,
								acc_merge_contexts, ctx, unref_acc_ctx) != 0) {
			acc_unref(ctx); /* only one, the other one was successful */
			LM_ERR("cannot register callback ctx management\n");
			goto restore;
		}

	} else {
		/* do old accounting */
		if ( is_evi_acc_on(*flags) ) {
			env_set_event(acc_event, acc_event_params, evi_params);
			acc_evi_request( req, reply, 0, 0 );
		}

		if ( is_log_acc_on(*flags) ) {
			env_set_text( ACC_ANSWERED, ACC_ANSWERED_LEN);
			acc_log_request( req, reply, 0 );
		}

		if (is_aaa_acc_on(*flags))
			acc_aaa_request( req, reply, 0 );

		if (is_db_acc_on(*flags)) {
			env_set_text( table.s, table.len);
			acc_db_request( req, reply, &acc_ins_list, 0, 0);
		}
	}

restore:
	if (new_uri_bk.len>=0) {
		req->new_uri = new_uri_bk;
		req->dst_uri = dst_uri_bk;
		req->parsed_uri_ok = 0;
	}
}

static void acc_dlg_ended(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	struct cell* t;
	acc_ctx_t* ctx;

	if (!_params) {
		LM_ERR("not enough info\n");
		return;
	}

	/* resolve local/dlg ctx conflict by merging them together */
	acc_merge_contexts(dlg, type, _params);
	ctx = (acc_ctx_t *)(*_params->param);

	/*
	 * this way we "enable" the refcount
	 * if opensips shuts down before dialog terminated then the refcount
	 * won't be enabled
	 */
	if (was_dlg_cb_used(ctx->flags)) {
		LM_INFO("CDR callback already registered [%p|%u] - do not run it again!\n",
				*_params->param, ctx->ref_no);
		return;
	}
	set_dlg_cb_used(ctx->flags);

	/* this time will be used to set */
	gettimeofday(&ctx->bye_time, NULL);

	/* if it's not a local transaction we do the accounting on the tm callbacks */
	if (((t=tmb.t_gett()) == T_UNDEFINED) || !t ||
			!tmb.t_is_local(_params->msg)) {
		/* normal dialogs will have to do accounting when the response for
		 * the bye will come since users should be able to populate extra
		 * vars and leg vars */
		acc_ref(ctx);
		if (tmb.register_tmcb( _params->msg, NULL,
						TMCB_RESPONSE_OUT, acc_cdr_cb, ctx, unref_acc_ctx) < 0) {
			acc_unref(ctx);
			LM_ERR("failed to register cdr callback!\n");
			return;
		}
	/* for local transactions we do the accounting here since all the messages
	 * have been processed */
	} else {
		/* expired dialogs will be handled here */
		if (is_log_acc_on(ctx->flags)) {
			env_set_text( ACC_ENDED, ACC_ENDED_LEN);
			if (acc_log_cdrs(dlg, _params->msg, ctx) < 0) {
				LM_ERR("Cannot log values\n");
				return;
			}
		}

		if (is_db_acc_on(ctx->flags)) {
			env_set_text( db_table_acc.s, db_table_acc.len);
			if (acc_db_cdrs(dlg, _params->msg, ctx) < 0) {
				LM_ERR("Cannot insert into database\n");
				return;
			}
		}

		if (is_aaa_acc_on(ctx->flags) && acc_aaa_cdrs(dlg, _params->msg, ctx) < 0) {
			LM_ERR("Cannot create radius accounting\n");
			return;
		}

		if (is_evi_acc_on(ctx->flags)) {
			env_set_event(acc_cdr_event, acc_cdr_event_params, evi_cdr_params);
			if (acc_evi_cdrs(dlg, _params->msg, ctx) < 0) {
				LM_ERR("cannot send accounting events\n");
				return;
			}
		}
	}

}


static void acc_dlg_onwrite(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	str flags_s;
	acc_ctx_t* ctx;

	str created_s;

	if (!_params) {
		LM_ERR("not enough info!\n");
		return;
	}

	ctx = *_params->param;

	if (ctx->extra_values &&
		store_extra_values(ctx->extra_values, &extra_str, dlg) < 0) {
		LM_ERR("cannot store extra values!\n");
		return;
	}

	if (ctx->leg_values &&
		store_leg_values(ctx, &leg_str, dlg) < 0) {
		LM_ERR("cannot store leg values!\n");
		return;
	}

	flags_s.s = (char*)(&ctx->flags);
	flags_s.len = sizeof(unsigned long long);

	/* store flags into dlg */
	if ( dlg_api.store_dlg_value(dlg, &flags_str, &flags_s) < 0) {
		LM_ERR("cannot store flag value into dialog\n");
		return;
	}

	created_s.s = (char*)(&ctx->created);
	created_s.len = sizeof(time_t);

	if ( dlg_api.store_dlg_value(dlg,&created_str,&created_s) < 0) {
		LM_ERR("cannot store created value!\n");
		return;
	}

	if (is_db_acc_on(ctx->flags) && ctx->acc_table.s && ctx->acc_table.len) {
		if ( dlg_api.store_dlg_value(dlg, &table_str, &ctx->acc_table) < 0) {
			LM_ERR("cannot store table name into dialog\n");
			return;
		}
	}
}

static void acc_cdr_cb( struct cell* t, int type, struct tmcb_params *ps )
{
	acc_ctx_t* ctx = *ps->param;
	struct dlg_cell *dlg;

	dlg = dlg_api.get_dlg();

	if (dlg == NULL) {
		LM_DBG("dlg is null!\n");
		return;
	}

	if (is_log_acc_on(ctx->flags)) {
		env_set_text( ACC_ENDED, ACC_ENDED_LEN);
		if (acc_log_cdrs(dlg, ps->req, ctx) < 0) {
			LM_ERR("Cannot log values\n");
			return;
		}
	}

	if (is_db_acc_on(ctx->flags)) {
		env_set_text( db_table_acc.s, db_table_acc.len);
		if (acc_db_cdrs(dlg, ps->req, ctx) < 0) {
			LM_ERR("Cannot insert into database\n");
			return;
		}
	}

	if (is_aaa_acc_on(ctx->flags) && acc_aaa_cdrs(dlg, ps->req, ctx) < 0) {
		LM_ERR("Cannot create radius accounting\n");
		return;
	}

	if (is_evi_acc_on(ctx->flags)) {
		env_set_event(acc_cdr_event, acc_cdr_event_params, evi_cdr_params);
		if (acc_evi_cdrs(dlg, ps->req, ctx) < 0) {
			LM_ERR("cannot send accounting events\n");
			return;
		}
	}
}


static void tmcb_func( struct cell* t, int type, struct tmcb_params *ps )
{
	acc_ctx_t *tmp_ctx, *ctx = *ps->param;

	if (ACC_GET_TM_CTX(t) == NULL) {
		acc_ref(ctx);
		ACC_PUT_TM_CTX(t, ctx);
	}

	if (type&(TMCB_RESPONSE_OUT|TMCB_LOCAL_COMPLETED)) {
		acc_onreply( t, ps->req, ps->rpl, ps->code, ctx);
	} else if (type&TMCB_ON_FAILURE) {
		on_missed( t, ps->req, ps->rpl, ps->code, ctx);
	} else if (type&TMCB_RESPONSE_IN) {
		/* merge any context created within global "onreply_route" */
		if ((tmp_ctx = ACC_GET_CTX()) && tmp_ctx != ctx) {
			push_ctx_to_ctx(tmp_ctx, ctx);
			acc_unref(tmp_ctx);

			acc_ref(ctx);
			ACC_PUT_CTX(ctx);
		}

		acc_onreply_in( t, ps->req, ps->rpl, ps->code, ctx);
	}
}


/*
 * use case
 *
 * {
 *    do_acc("db", "cdr", "myacc")
 *    do_acc("db|radius", "cdr|missed", "myacc")
 * }
 *
 *
 */

/* accounting type strings */
static str do_acc_log_s=str_init(DO_ACC_LOG_STR);
static str do_acc_aaa_s=str_init(DO_ACC_AAA_STR);
static str do_acc_db_s=str_init(DO_ACC_DB_STR);
static str do_acc_evi_s=str_init(DO_ACC_EVI_STR);

/* accounting flags strings */
static str do_acc_cdr_s=str_init(DO_ACC_CDR_STR);
static str do_acc_missed_s=str_init(DO_ACC_MISSED_STR);
static str do_acc_failed_s=str_init(DO_ACC_FAILED_STR);


/**
 * types: log, aaa, db, evi
 * case insesitive
 *
 */
static inline
unsigned long long do_acc_type_parser(str* token)
{
	trim(token);

	if (token->len == do_acc_log_s.len &&
			!strncasecmp(token->s, do_acc_log_s.s, token->len)) {
		return DO_ACC_LOG;
	} else if (token->len == do_acc_aaa_s.len &&
			!strncasecmp(token->s, do_acc_aaa_s.s, token->len)) {
		return DO_ACC_AAA;
	} else if (token->len == do_acc_db_s.len &&
			!strncasecmp(token->s, do_acc_db_s.s, token->len)) {
		return DO_ACC_DB;
	}  else if (token->len == do_acc_evi_s.len &&
			!strncasecmp(token->s, do_acc_evi_s.s, token->len)) {
		return DO_ACC_EVI;
	} else {
		LM_ERR("invalid accounting backend: <%.*s>!\n", token->len, token->s);
		return DO_ACC_ERR;
	}
}

/**
 * types: cdr, missed
 * case insesitive
 *
 */
static inline
unsigned long long do_acc_flags_parser(str* token)
{
	trim(token);

	if (token->len == do_acc_cdr_s.len &&
			!strncasecmp(token->s, do_acc_cdr_s.s, token->len)) {

		if (!is_cdr_enabled) {
			LM_ERR("dialog module not loaded - cdrs cannot be generated\n");
			return DO_ACC_NONE;
		}

		return DO_ACC_CDR;
	} else if (token->len == do_acc_missed_s.len &&
			!strncasecmp(token->s, do_acc_missed_s.s, token->len)) {
		/* load dialog module if these are used */
		return DO_ACC_MISSED;
	} else if (token->len == do_acc_failed_s.len &&
			!strncasecmp(token->s, do_acc_failed_s.s, token->len)) {
		return DO_ACC_FAILED;
	} else {
		LM_ERR("invalid flag: <%.*s>!\n", token->len, token->s);
		return DO_ACC_ERR;
	}
}


static unsigned long long
do_acc_parse(str* in, do_acc_parser parser)
{
	char *found;
	str token;

	unsigned long long fret=0, ret;

	if (!in || !in->s || !in->len)
		return -1;

	do {
		found=q_memchr(in->s, DO_ACC_PARAM_DELIMITER, in->len);
		if (found) {
			token.s = in->s;
			token.len = found - in->s;

			in->len -= token.len + 1;
			in->s = found + 1;
		} else {
			token = *in;
		}

		if ((ret=parser(&token)) == DO_ACC_ERR) {
			LM_ERR("Invalid token <%.*s>!\n", token.len, token.s);
			return -1;
		}

		fret |= ret;
	} while(found);

	return fret;
}

int _do_acc_fixup(void **param, do_acc_parser parser)
{
	unsigned long long *ival;

	ival = pkg_malloc(sizeof *ival);
	if (!ival) {
		LM_ERR("No more pkg mem!\n");
		return E_OUT_OF_MEM;
	}

	if ((*ival = do_acc_parse((str*)*param, parser)) == DO_ACC_ERR) {
		LM_ERR("Invalid value <%.*s>!\n", ((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}

	*param = ival;
	return 0;
}

int do_acc_fixup_type(void **param)
{
	return _do_acc_fixup(param, do_acc_type_parser);
}

int do_acc_fixup_flags(void **param)
{
	return _do_acc_fixup(param, do_acc_flags_parser);
}

int do_acc_fixup_free_ival(void **param)
{
	pkg_free(*param);
	return 0;
}

static inline int store_acc_table(acc_ctx_t* ctx, str* table)
{
	if (ctx == NULL || table == NULL || table->s == NULL || table->len == 0) {
		LM_ERR("bad usage!\n");
		return -1;
	}

	if (shm_str_sync(&ctx->acc_table, table) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}

int init_acc_ctx(acc_ctx_t** ctx_p)
{
	acc_ctx_t* ctx;

	if (ctx_p == NULL) {
		LM_ERR("bad usage!\n");
		return -1;
	}

	ctx=shm_malloc(sizeof(acc_ctx_t));
	if (ctx == NULL) {
		LM_ERR("no more shm!\n");
		return -1;
	}

	memset(ctx, 0, sizeof(acc_ctx_t));
	lock_init(&ctx->lock);

	/* init extra s array */
	if (extra_tags != NULL &&
			build_acc_extra_array(extra_tgs_len, &ctx->extra_values) < 0) {
		LM_ERR("failed to build extra values array!\n");
		return -1;
	}
	if (leg_tags != NULL && push_leg(ctx) < 0) {
		LM_ERR("failed to build extra values array!\n");
		return -1;
	}
	acc_ref_unsafe(ctx, 1);
	ACC_PUT_CTX(ctx);

	*ctx_p = ctx;
	return 0;

}

void unref_acc_ctx(void *ctx)
{
	acc_unref((acc_ctx_t *)ctx);
}

int w_do_acc(struct sip_msg* msg, unsigned long long *type,
			unsigned long long *flags, str *table_name)
{
	unsigned long long flag_mask;
	struct dlg_cell *dlg;

	acc_ctx_t* acc_ctx;

	int tmcb_types;
	int is_invite;

	if (!msg) {
		LM_ERR("no SIP message\n");
		return -1;
	}

	if (skip_cancel(msg)) {
		LM_WARN("do_accounting() called on CANCEL but 'report_cancels' modparam"
				" not set - no accounting will be done for this transaction!\n");
		return 1;
	}

	flag_mask = *type + *type * (flags ? *flags : 0);
	if (is_cdr_acc_on(flag_mask)) {
		/* setting this flag will allow us to register everything
		 * that is needed for CDR accounting only once */
		set_cdr_values_registered(flag_mask);
	}

	/* is it the first time when the function was called ? */
	acc_ctx = try_fetch_ctx();

	/* we go in here only if do_accounting function was called before;
	 * if accounting context is null or it's created but flags value is
	 * 0(meaning that context was created from somewhere else but do_accounting
	 * wasn't called)  then we need to jump over this and register
	 * all the callbacks we need */
	if (acc_ctx != NULL  && acc_ctx->flags != 0) {
		/* do_accounting already called once */
		/* first check if the accounting table changed  */
		if (is_db_acc_on(flag_mask) &&
				(table_name != NULL || ZSTR(acc_ctx->acc_table))) {
			if (table_name == NULL) {
				table_name = &db_table_acc;
			}

			if (store_acc_table( acc_ctx, table_name) < 0) {
				LM_ERR("failed to store acc table!\n");
				return -1;
			}
		}

		if (!cdr_values_registered(acc_ctx->flags) &&
				cdr_values_registered(flag_mask)) {
			/* CDR support requested for the first time, we need to create
			 * the dialog support, if an initial INVITE */
			if (!has_totag(msg)) {
				acc_ctx->created = time(NULL);

				if (msg->REQ_METHOD == METHOD_INVITE) {
					if ((dlg = create_acc_dlg(msg)) == 0) {
						LM_ERR("cannot use dialog accounting module\n");
						return -1;
					}
					acc_ref(acc_ctx);
					dlg_api.dlg_ctx_put_ptr(dlg, acc_dlg_ctx_idx, acc_ctx);
				}
			}
		}

		acc_ctx->flags |= flag_mask;
		return 1;
	}

	/* initialize accounting context if not created before */
	if (acc_ctx == NULL && init_acc_ctx(&acc_ctx) < 0) {
		LM_ERR("failed to create accounting context!\n");
		return -1;
	}

	/* move acc table in context if we have database accounting */
	if (is_db_acc_on(flag_mask)) {
		if (table_name == NULL) {
			table_name = &db_table_acc;
		}

		if (store_acc_table( acc_ctx, table_name) < 0) {
			LM_ERR("failed to store acc table!\n");
			return -1;
		}
	}


	/*
	 * the first bit in each byte will just tell that we want that type of
	 * accounting
	 * next bits will tell extra options for that type of accounting
	 * so we keep the first bits in each byte and on the following positions
	 * next flags
	 */
	acc_ctx->flags = flag_mask;

	if (is_acc_on(acc_ctx->flags) || is_mc_acc_on(acc_ctx->flags)) {
		/* do some parsing in advance */
		if (acc_preparse_req(msg)<0)
			return -1;
		is_invite = (msg->REQ_METHOD==METHOD_INVITE)?1:0;
		/* install additional handlers */
		tmcb_types =
			/* report on completed transactions */
			TMCB_RESPONSE_IN|TMCB_RESPONSE_OUT|TMCB_LOCAL_COMPLETED
			/* report on missed calls */
			|TMCB_ON_FAILURE;

		/* if cdr accounting is enabled */
		if (is_cdr_acc_on(acc_ctx->flags) && !has_totag(msg)) {
			acc_ctx->created = time(NULL);

			if (is_invite) {
				if ((dlg = create_acc_dlg(msg)) == 0) {
					LM_ERR("cannot use dialog accounting module\n");
					return -1;
				}
				acc_ref(acc_ctx);
				dlg_api.dlg_ctx_put_ptr(dlg, acc_dlg_ctx_idx, acc_ctx);
			}
		}

		acc_ref(acc_ctx);
		if (tmb.register_tmcb( msg, 0, tmcb_types, tmcb_func,
				acc_ctx, unref_acc_ctx)<=0) {
			LM_ERR("cannot register additional callbacks\n");
			acc_unref(acc_ctx);
			return -1;
		}

		/* if required, determine request direction */
		if( detect_direction && !rrb.is_direction(msg,RR_FLOW_UPSTREAM) ) {
			LM_DBG("detected an UPSTREAM req -> flaging it\n");
			msg->msg_flags |= FL_REQ_UPSTREAM;
		}
	}

	return 1;
}

int w_drop_acc(struct sip_msg* msg, unsigned long long *type,
			unsigned long long *flags)
{
	unsigned long long flag_mask;

	acc_ctx_t* acc_ctx=try_fetch_ctx();

	if (acc_ctx == NULL) {
		LM_ERR("do_accounting() not used! This function resets flags in "
				"do_accounting()!\n");
		return -1;
	}

	flag_mask = (type ? *type : DO_ACC_LOG | DO_ACC_AAA | DO_ACC_DB | DO_ACC_EVI) *
		(flags ? *flags : ALL_ACC_FLAGS);

	reset_flags(acc_ctx->flags, flag_mask);

	return 1;
}


int w_new_leg(struct sip_msg* msg)
{
	acc_ctx_t* ctx = try_fetch_ctx();

	if (ctx == NULL) {
		if (init_acc_ctx(&ctx) < 0) {
			LM_ERR("failed to create accounting context!\n");
			return -1;
		}
	}

	accX_lock(&ctx->lock);
	if (push_leg(ctx) < 0) {
		LM_ERR("failed to create new leg!\n");
		accX_unlock(&ctx->lock);
		return -1;
	}
	accX_unlock(&ctx->lock);

	return 1;

}


static acc_ctx_t *stored_local_ctx = NULL;
static unsigned int stores_local_ctx = 0;

int w_load_ctx_from_dlg(struct sip_msg* msg)
{
	acc_ctx_t* ctx;
	struct dlg_cell *dlg;

	/* no nested calls */
	if (stores_local_ctx)
		return -1;

	dlg = dlg_api.get_dlg ? dlg_api.get_dlg() : NULL;

	/* any dialog ? */
	if (!dlg)
		return -1;

	/* get the acc ctx from dialog */
	ctx = dlg_api.dlg_ctx_get_ptr(dlg, acc_dlg_ctx_idx);
	if (!ctx)
		return -1;

	/* no need for extra ref as we move the ctx pointer */
	stored_local_ctx = ACC_GET_CTX();
	stores_local_ctx = 1;

	/* we create one more copy of the pointer, do ref */
	acc_ref_ex(ctx, 1);
	ACC_PUT_CTX(ctx);

	return 1;
}

int w_unload_ctx_from_dlg(struct sip_msg* msg)
{
	acc_ctx_t* ctx;

	/* something loaded/stored? */
	if (!stores_local_ctx)
		return -1;

	ctx = ACC_GET_CTX();
	acc_unref_ex(ctx, 1);

	ACC_PUT_CTX(stored_local_ctx);
	stores_local_ctx = 0;

	return 1;
}
