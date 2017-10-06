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

extern str acc_created_avp_name;
extern int acc_created_avp_id;

extern int acc_flags_ctx_idx;
extern int acc_tm_flags_ctx_idx;

struct acc_enviroment acc_env;

static query_list_t *acc_ins_list = NULL;
static query_list_t *mc_ins_list = NULL;

static int is_cdr_enabled=0;

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


#ifdef DIAM_ACC
	#define is_diam_flag_on(_mask, _flag) is_acc_flag_set(_mask, DO_ACC_DIAM, _flag)
	#define is_diam_acc_on(_mask) is_diam_flag_on(_mask, DO_ACC)
	#define is_diam_cdr_on(_mask) is_diam_flag_on(_mask, DO_ACC_CDR)
	#define is_diam_mc_on(_mask) is_diam_flag_on(_mask, DO_ACC_MISSED)
	#define is_diam_failed_on(_mask) is_diam_flag_on(_mask, DO_ACC_FAILED)
#else
	#define is_diam_acc_on(_mask)     (0)
	#define is_diam_cdr_on(_mask)     (0)
	#define is_diam_mc_on(_mask)      (0)
	#define is_diam_failed_on(_mask)  (0)
#endif

#define is_acc_on(_mask) \
	( (is_log_acc_on(_mask)) || (is_db_acc_on(_mask)) \
	|| (is_aaa_acc_on(_mask)) || (is_diam_acc_on(_mask)) \
	|| (is_evi_acc_on(_mask)) )

#define is_cdr_acc_on(_mask) (is_log_cdr_on(_mask)  ||              \
		is_aaa_cdr_on(_mask) || is_db_cdr_on(_mask) ||              \
		is_evi_cdr_on(_mask)||is_diam_cdr_on(_mask))

#define is_mc_acc_on(_mask) (is_log_mc_on(_mask)    ||              \
		is_aaa_mc_on(_mask) || is_db_mc_on(_mask)  ||              \
		is_evi_mc_on(_mask) || is_diam_mc_on(_mask))

#define is_failed_acc_on(_mask) (is_log_failed_on(_mask)  ||        \
		is_aaa_failed_on(_mask) || is_db_failed_on(_mask) ||        \
		is_evi_failed_on(_mask) || is_diam_failed_on(_mask))

#define set_dialog_context(_mask) \
	(_mask) |= ACC_DIALOG_CONTEXT;

#define is_dialog_context(_mask) ((_mask)&ACC_DIALOG_CONTEXT)

#define set_cdr_values_registered(_mask) \
	(_mask) |= ACC_CDR_REGISTERED;

#define set_dlg_cb_used(_mask) \
	(_mask) |= ACC_DLG_CB_USED;

#define set_failure_cb_registered(_mask) \
	(_mask) |= ACC_TMCB_MISSED_REGISTERED;

#define was_dlg_cb_used(_mask) (_mask&ACC_DLG_CB_USED)

#define cdr_values_registered(_mask) ((_mask)&ACC_CDR_REGISTERED)

#define failure_cb_registered(_mask) ((_mask)&ACC_TMCB_MISSED_REGISTERED)




#define reset_flags(_flags, _flags_to_reset) \
	_flags &= ~_flags_to_reset;


#define skip_cancel(_rq) \
	(((_rq)->REQ_METHOD==METHOD_CANCEL) && report_cancels==0)


/*
 * the 8th byte of the mask will be a reference counter for dialog callbacks
 * each time we enter a diallog callback(acc_dlg_callback) the reference counter shall
 * be increased
 * each time we enter a dialog callback free function(dlg_free_acc_mask) the refernce
 * counter shall be decreased
 * when the counter reaches 0 the mask shall be freed */
#define ACC_MASK_INC_REF(mask) \
	do { \
		mask = mask + (0x100000000000000); \
	} while (0);

#define ACC_MASK_DEC_REF(mask) \
	do { \
		if (was_dlg_cb_used(mask)) { \
			if (!(mask&0xFF00000000000000)) { \
				LM_BUG("More subtractions than additions in acc mask!\n"); \
				return; \
			} \
			mask = mask - (0x100000000000000); \
		} \
	} while (0);

/* read the value of the 8th byte as a char type value */
#define ACC_MASK_GET_REF(mask) (mask >> (8*7))

/* just for debugging purposes
 * read the value of the flags without the ref counter to know
 * that the actual flags value is not altered */
#define ACC_MASK_GET_VALUE(mask) (mask & 0x00FFFFFFFFFFFFFF)



static void tmcb_func( struct cell* t, int type, struct tmcb_params *ps );
static void acc_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);


void dlg_free_acc_mask(void* param) {
	/*
	 * decrease the number of references to the shm memory pointer
	 * the free functions are executed sequentially so we know that this operation
	 * is atomic
	 **/
	ACC_MASK_DEC_REF(*((unsigned long long*)param));
	LM_DBG("flags[%p] ref counter value after dereferencing[%llu]\n",
				param,
				ACC_MASK_GET_REF(*((unsigned long long*)param)));
	/*
	 * if the reference counter gets to 0 we can free
	 * the shm pointer
	 * */
	if (ACC_MASK_GET_REF(*((unsigned long long*)param)) == 0)
		shm_free((unsigned long long *)param);
}

void tm_free_acc_mask(void* param) {
	if (!is_dialog_context(*(unsigned long long*)param)) {
		shm_free((unsigned long long *)param);
	}
}



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

	return acc_log_request( rq, NULL, 0);
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

	return acc_aaa_request( rq, NULL, 0);
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
		return acc_db_request(rq, NULL, &mc_ins_list, 0);
	}

	if (table_len == db_table_acc.len && (strncmp(table, db_table_acc.s, table_len) == 0)) {
		return acc_db_request(rq, NULL, &acc_ins_list, 0);
	}

	return acc_db_request( rq, NULL,NULL, 0);
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
		env_set_event(acc_event);
	} else {
		env_set_event(acc_missed_event);
	}

	return acc_evi_request( rq, NULL, 0);
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
					struct sip_msg *reply, int code, unsigned long long* flags)
{
	/* don't parse replies in which we are not interested */
	/* missed calls enabled ? */
	if ( (reply && reply!=FAKED_REPLY)
			&& (should_acc_reply(req,reply,code, flags)
	|| (is_invite(t) && code>=300 && is_mc_acc_on(*flags))) ) {
		parse_headers(reply, HDR_TO_F, 0 );
	}
}



/* initiate a report if we previously enabled MC accounting for this t */
static inline void on_missed(struct cell *t, struct sip_msg *req,
					struct sip_msg *reply, int code, unsigned long long *flags)
{
	str new_uri_bk={0,0};
	str dst_uri_bk={0,0};
	unsigned long long flags_to_reset=0;

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
		env_set_event(acc_missed_event);
		acc_evi_request( req, reply, is_evi_cdr_on(*flags) );
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
		acc_db_request( req, reply,&mc_ins_list, is_db_cdr_on(*flags));
		flags_to_reset |= DO_ACC_DB * DO_ACC_MISSED;
	}
/* DIAMETER */
#ifdef DIAM_ACC
	if (is_diam_mc_on(*flags)) {
		acc_diam_request( req, reply );
		flags_to_reset |= DO_ACC_DIAM * DO_ACC_MISSED;
	}
#endif

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


/* restore callbacks */
void acc_loaded_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params) {
		str flags_s;
		unsigned long long *flags;

		if (!dlg) {
			LM_ERR("null dialog - cannot fetch message flags\n");
			return;
		}

		if (dlg_api.fetch_dlg_value(dlg, &flags_str, &flags_s, 0) < 0) {
			LM_DBG("flags were not saved in dialog\n");
			return;
		}

		flags = shm_malloc(sizeof(unsigned long long));
		if (flags == NULL) {
			LM_ERR("no more shm!\n");
			return;
		}

		memcpy(flags, flags_s.s, sizeof(unsigned long long));

		/* register database callbacks */
		if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED |
				DLGCB_EXPIRED, acc_dlg_callback, flags, dlg_free_acc_mask)){
			LM_ERR("cannot register callback for database accounting\n");
			return;
		}
}

/* initiate a report if we previously enabled accounting for this t */
static inline void acc_onreply( struct cell* t, struct sip_msg *req,
					struct sip_msg *reply, int code, unsigned long long *flags)
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
	if (is_invite(t) && code>=300 && is_mc_acc_on(*flags) ) {
		on_missed(t, req, reply, code, flags);
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
	table.s = db_table_acc;
	if (db_table_name != -1 && is_db_acc_on(*flags)) {
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

	if (is_invite(t) && !has_totag(req) && is_cdr_acc_on(*flags) &&
			code >= 200 && code < 300 && (dlg=dlg_api.get_dlg()) != NULL) {
		/* if dialog module loaded and INVITE and success reply */
		if (store_core_leg_values(dlg, req) < 0) {
			LM_ERR("cannot store core and leg values\n");
			goto restore;
		}

		if(is_log_acc_on(*flags) && store_log_extra_values(dlg,req,reply)<0){
			LM_ERR("cannot store string values\n");
			goto restore;
		}

		if(is_aaa_acc_on(*flags) && store_aaa_extra_values(dlg, req, reply)<0){
			LM_ERR("cannot store aaa extra values\n");
			goto restore;
		}

		if (is_db_acc_on(*flags) && store_db_extra_values(dlg,req,reply)<0) {
			LM_ERR("cannot store database extra values\n");
			goto restore;
		}

		if (is_evi_acc_on(*flags) && store_evi_extra_values(dlg,req,reply)<0) {
			LM_ERR("cannot store database extra values\n");
			goto restore;
		}

		flags_s.s = (char*)flags;
		flags_s.len = sizeof(unsigned long long);

		/* store flags into dlg */
		if ( dlg_api.store_dlg_value(dlg, &flags_str, &flags_s) < 0) {
			LM_ERR("cannot store flag value into dialog\n");
			goto restore;
		}

		/* store flags into dlg */
		if ( dlg_api.store_dlg_value(dlg, &table_str, &table.s) < 0) {
			LM_ERR("cannot store the table name into dialog\n");
			goto restore;
		}

		/* report that flags shall be freed only by dialog module
		 * tm must never free it */
		set_dialog_context(*flags);

		/* register database callbacks */
		if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED |
				DLGCB_EXPIRED, acc_dlg_callback,flags, dlg_free_acc_mask) != 0) {
			LM_ERR("cannot register callback for database accounting\n");
			goto restore;
		}
	} else {
		/* do old accounting */
		if ( is_evi_acc_on(*flags) ) {
			env_set_event(acc_event);
			acc_evi_request( req, reply, 0 );
		}

		if ( is_log_acc_on(*flags) ) {
			env_set_text( ACC_ANSWERED, ACC_ANSWERED_LEN);
			acc_log_request( req, reply, 0 );
		}

		if (is_aaa_acc_on(*flags))
			acc_aaa_request( req, reply, 0 );

		if (is_db_acc_on(*flags)) {
			env_set_text( table.s.s, table.s.len);
			acc_db_request( req, reply, &acc_ins_list, 0);
		}
	}

/* DIAMETER */
#ifdef DIAM_ACC
	if (is_diam_acc_on(req))
		acc_diam_request( req, reply );
#endif

restore:
	if (new_uri_bk.len>=0) {
		req->new_uri = new_uri_bk;
		req->dst_uri = dst_uri_bk;
		req->parsed_uri_ok = 0;
	}
}

static void acc_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	unsigned long long flags;
	struct timeval end;

	if (!_params) {
		LM_ERR("not enough info\n");
		return;
	}


	flags = *((unsigned long long*)(*_params->param));
	/**
	 * we've read the value of the flags
	 * increase the number of references to the shm memory pointer
	 * we know that this operation is atomic since the dialog callbacks
	 * are executed sequentially
	 */
	ACC_MASK_INC_REF(*((unsigned long long *)*_params->param));
	LM_DBG("flags[%p] ref counter value after referencing [%llu]\n",
				*_params->param,
				ACC_MASK_GET_REF(*((unsigned long long*)*_params->param)));
	/*
	 * this way we "enable" the refcount
	 * if opensips shuts down before dialog terminated then the refcount
	 * won't be enabled
	 */
	set_dlg_cb_used(*((unsigned long long*)*_params->param));

	gettimeofday(&end,NULL);

	if (is_evi_acc_on(flags)) {
		env_set_event(acc_cdr_event);
		if (acc_evi_cdrs(dlg, _params->msg, &end) < 0) {
			LM_ERR("cannot send accounting events\n");
			return;
		}
	}

	if (is_log_acc_on(flags)) {
		env_set_text( ACC_ENDED, ACC_ENDED_LEN);
		if (acc_log_cdrs(dlg, _params->msg, &end) < 0) {
			LM_ERR("Cannot log values\n");
			return;
		}
	}

	if (is_db_acc_on(flags)) {
		env_set_text( db_table_acc.s, db_table_acc.len);
		if (acc_db_cdrs(dlg, _params->msg, &end) < 0) {
			LM_ERR("Cannot insert into database\n");
			return;
		}
	}

	if (is_aaa_acc_on(flags) && acc_aaa_cdrs(dlg, _params->msg, &end) < 0) {
		LM_ERR("Cannot create radius accounting\n");
		return;
	}
}


static void tmcb_func( struct cell* t, int type, struct tmcb_params *ps )
{
	unsigned long long *flags = *ps->param;

	if (ACC_GET_TM_FLAGS(t) == NULL)
		ACC_PUT_TM_FLAGS(t, flags);

	if (type&TMCB_RESPONSE_OUT) {
		acc_onreply( t, ps->req, ps->rpl, ps->code, flags);
	} else if (type&TMCB_ON_FAILURE) {
		on_missed( t, ps->req, ps->rpl, ps->code, flags);
	} else if (type&TMCB_RESPONSE_IN) {
		acc_onreply_in( t, ps->req, ps->rpl, ps->code, flags);
	}
}


/*
 * helper function to retrieve flags from processing context or
 * transaction context
 */
static inline unsigned long long* try_fetch_flags(void)
{
	unsigned long long* ret=NULL;
	struct cell* t;

	if ((ret=ACC_GET_FLAGS) == NULL)
		if (((t=tmb.t_gett()) != NULL) && (t!=T_UNDEFINED)
				&& ((ret=ACC_GET_TM_FLAGS(t)) == NULL))
			return NULL;

	return ret;
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
static str do_acc_diam_s=str_init(DO_ACC_DIAM_STR);
static str do_acc_evi_s=str_init(DO_ACC_EVI_STR);

/* accounting flags strings */
static str do_acc_cdr_s=str_init(DO_ACC_CDR_STR);
static str do_acc_missed_s=str_init(DO_ACC_MISSED_STR);
static str do_acc_failed_s=str_init(DO_ACC_FAILED_STR);


/**
 * types: log, aaa, db, diam, evi
 * case insesitive
 *
 */
static inline
unsigned long long do_acc_type_parser(str* token)
{
	str_trim_spaces_lr(*token);

	if (token->len == do_acc_log_s.len &&
			!strncasecmp(token->s, do_acc_log_s.s, token->len)) {
		return DO_ACC_LOG;
	} else if (token->len == do_acc_aaa_s.len &&
			!strncasecmp(token->s, do_acc_aaa_s.s, token->len)) {
		return DO_ACC_AAA;
	} else if (token->len == do_acc_db_s.len &&
			!strncasecmp(token->s, do_acc_db_s.s, token->len)) {
		return DO_ACC_DB;
	} else if (token->len == do_acc_diam_s.len &&
			!strncasecmp(token->s, do_acc_diam_s.s, token->len)) {
		return DO_ACC_DIAM;
	} else if (token->len == do_acc_evi_s.len &&
			!strncasecmp(token->s, do_acc_evi_s.s, token->len)) {
		return DO_ACC_EVI;
	} else {
		LM_ERR("Invalid token <%.*s>!\n", token->len, token->s);
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
	str_trim_spaces_lr(*token);

	if (token->len == do_acc_cdr_s.len &&
			!strncasecmp(token->s, do_acc_cdr_s.s, token->len)) {

		if (!is_cdr_enabled) {
			if (parse_avp_spec( &acc_created_avp_name, &acc_created_avp_id) < 0) {
				LM_ERR("failed to register AVP name <%s>\n", acc_created_avp_name.s);
				return DO_ACC_ERR;
			}

			if (load_dlg_api(&dlg_api)!=0)
						LM_DBG("failed to find dialog API - is dialog module loaded?\n");

			if (!dlg_api.get_dlg) {
				LM_WARN("error loading dialog module - cdrs cannot be generated\n");
				return DO_ACC_NONE;
			}

			if (dlg_api.get_dlg && dlg_api.register_dlgcb(NULL,
						DLGCB_LOADED,acc_loaded_callback, NULL, NULL) < 0)
					LM_ERR("cannot register callback for dialog loaded - accounting "
							"for ongoing calls will be lost after restart\n");

			is_cdr_enabled=1;
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
		return DO_ACC_ERR;
	}
}


static unsigned long long
do_acc_parse(str* in, do_acc_parser parser)
{

	char* found=NULL;
	str token;

	unsigned long long fret=0, ret;

	if (!in || !in->s || !in->len)
		return -1;

	do {
		found=q_memchr(in->s, DO_ACC_PARAM_DELIMITER, in->len);
		if (found) {
			token.s = in->s;
			token.len = found - in->s;

			in->len -= (found - in->s) + 1;
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


int do_acc_fixup(void** param, int param_no)
{
	str s;
	pv_elem_p el;

	unsigned long long ival;
	unsigned long long* ival_p;

	acc_type_param_t* acc_param;

	do_acc_parser parser;

	if (param_no < 1 || param_no > 3) {
		LM_ERR("invalid param_no <%d>!\n", param_no);
		return -1;
	}

	switch (param_no) {
	case 1:
		parser=do_acc_type_parser;
		s.s = *param;
		s.len = strlen(s.s);

		if (pv_parse_format(&s, &el) < 0) {
			LM_ERR("invalid format <%.*s>!\n", s.len, s.s);
			return -1;
		}

		acc_param=pkg_malloc(sizeof(acc_type_param_t));
		if (acc_param == NULL) {
			LM_ERR("no more pkg mem!\n");
			return -1;
		}

		memset(acc_param, 0, sizeof(acc_type_param_t));

		if (el->next == 0 && el->spec.getf == 0) {
			pv_elem_free_all(el);
			if ( (ival=do_acc_parse(&el->text, parser)) == DO_ACC_ERR) {
				LM_ERR("Invalid value <%.*s>!\n", el->text.len, el->text.s);
				return -1;
			}

			acc_param->t = DO_ACC_PARAM_TYPE_VALUE;
			acc_param->u.ival = ival;
		} else {
			acc_param->t = DO_ACC_PARAM_TYPE_PV;
			acc_param->u.pval = el;
		}

		*param = acc_param;

		break;

	case 2:
		parser=do_acc_flags_parser;
		s.s = *param;
		s.len = strlen(s.s);

		if ( (ival=do_acc_parse(&s, parser)) == DO_ACC_ERR) {
			LM_ERR("Invalid value <%.*s>!\n", s.len, s.s);
			return -1;
		}

		if ((ival_p=pkg_malloc(sizeof(unsigned long long))) == NULL) {
			LM_ERR("no more pkg mem!\n");
			return -1;
		}

		*ival_p = ival;

		*param = ival_p;
		break;
	case 3:
		return fixup_sgp(param);
	}

	return 0;
}




int w_do_acc_1(struct sip_msg* msg, char* type)
{
	return w_do_acc_3(msg, type, NULL, NULL);
}

int w_do_acc_2(struct sip_msg* msg, char* type, char* flags)
{
	return w_do_acc_3(msg, type, flags, NULL);
}

int w_do_acc_3(struct sip_msg* msg, char* type_p, char* flags_p, char* table_p)
{
	unsigned long long type=0, flags=0;
	unsigned long long *flag_mask_p, flag_mask;

	acc_type_param_t* acc_param;

	str in;
	str table_name;

	int tmcb_types;
	int is_invite;

	int_str _avp_created_value;

	if (type_p == NULL) {
		LM_ERR("accounting type is mandatory!\n");
		return -1;
	}

	if (!msg) {
		LM_ERR("no SIP message\n");
		return -1;
	}

	if (skip_cancel(msg)) {
		LM_WARN("do_accounting() called on CANCEL but 'report_cancels' modparam"
				" not set - no accounting will be done for this transaction!\n");
		return 1;
	}

	acc_param = (acc_type_param_t *)type_p;
	if (acc_param->t == DO_ACC_PARAM_TYPE_VALUE) {
		type = acc_param->u.ival;
	} else {
		if (pv_printf_s(msg, acc_param->u.pval, &in) < 0) {
			LM_ERR("failed to fetch type value!\n");
			return -1;
		}

		if ((type=do_acc_parse(&in, do_acc_type_parser)) == DO_ACC_ERR) {
			LM_ERR("Invalid expression <%.*s> for acc type!\n", in.len, in.s);
			return -1;
		}
	}

	if (flags_p != NULL) {
		flags= *(unsigned long long*)flags_p;
	}

	flag_mask = type + type * flags;
	if (is_cdr_acc_on(flag_mask)) {
		/* setting this flag will allow us to register everything
		 * that is needed for CDR accounting only once */
		set_cdr_values_registered(flag_mask);
	}


	/* is it the first time when the function was called ? */
	if ((flag_mask_p=try_fetch_flags()) != NULL) {
		/* no the first time ; check now if CDRs are requested now
		 * for the first time */
		if (!cdr_values_registered(*flag_mask_p) &&
				cdr_values_registered(flag_mask)) {
			/* CDR support requested for the first time, we need to create
			 * the dialog support, if an initial INVITE */
			if (!has_totag(msg)) {
				_avp_created_value.n = time(NULL);

				if ( add_avp(0, acc_created_avp_id, _avp_created_value) != 0) {
					LM_ERR("failed to add created avp value!\n");
					return -1;
				}

				if (msg->REQ_METHOD == METHOD_INVITE && create_acc_dlg(msg) < 0) {
					LM_ERR("cannot use dialog accounting module\n");
					return -1;
				}
			}
		}

		/* if it's the first time the missed calls flag was used register the callback */
		if (is_mc_acc_on(flag_mask) && !failure_cb_registered(*flag_mask_p)) {
			if (tmb.register_tmcb( msg, 0, TMCB_ON_FAILURE, tmcb_func, flag_mask_p, 0)<=0) {
				LM_ERR("cannot register missed calls callback\n");
				return -1;
			}

			/* don't allow the callback to be registered agian in the future */
			set_failure_cb_registered(*flag_mask_p);
		}

		*flag_mask_p |= flag_mask;
		return 1;
	}

	/* setting accouting for the first time, allocate the flags holder */
	flag_mask_p=shm_malloc(sizeof(unsigned long long));
	if (flag_mask_p==NULL) {
		LM_ERR("No more shm mem!\n");
		return -1;
	}


	/*
	 * the first bit in each byte will just tell that we want that type of
	 * accounting
	 * next bits will tell extra options for that type of accounting
	 * so we keep the first bits in each byte and on the following positions
	 * next flags
	 */
	*flag_mask_p = flag_mask;
	ACC_PUT_FLAGS(flag_mask_p);

	if (table_p != NULL) {
		if (fixup_get_svalue(msg, (gparam_p)table_p, &table_name) < 0) {
			LM_ERR("failed to fetch table name!\n");
			return -1;
		}
	}


	if (is_acc_on(*flag_mask_p) || is_mc_acc_on(*flag_mask_p)) {
		/* do some parsing in advance */
		if (acc_preparse_req(msg)<0)
			return -1;
		is_invite = (msg->REQ_METHOD==METHOD_INVITE)?1:0;
		/* install additional handlers */
		tmcb_types =
			/* report on completed transactions */
			TMCB_RESPONSE_IN;

		if (is_invite && is_mc_acc_on(*flag_mask_p)) {
			/* register it manually; see explanation below
			 * get incoming replies ready for processing */
			/* TMCB_RESPONSE_OUT | */
			/* report on missed calls */
			tmcb_types |= TMCB_ON_FAILURE;
			/* the flag will help on further do_accounting calls to know
			 * not to register the callback twice */
			set_failure_cb_registered(*flag_mask_p);
		}

		/* if cdr accounting is enabled */
		if (is_cdr_acc_on(*flag_mask_p) && !has_totag(msg)) {
			_avp_created_value.n = time(NULL);

			if ( add_avp(0, acc_created_avp_id, _avp_created_value) != 0) {
				LM_ERR("failed to add created avp value!\n");
				return -1;
			}

			if (is_invite && create_acc_dlg(msg) < 0) {
				LM_ERR("cannot use dialog accounting module\n");
				return -1;
			}
		}

		/* we do register_tmcb twice because we wan't to register the free
		 * fucntion only once */
		if (tmb.register_tmcb( msg, 0, TMCB_RESPONSE_OUT, tmcb_func,
				flag_mask_p, tm_free_acc_mask)<=0) {
			LM_ERR("cannot register additional callbacks\n");
			return -1;
		}

		if (tmb.register_tmcb( msg, 0, tmcb_types, tmcb_func,
				flag_mask_p, 0)<=0) {
			LM_ERR("cannot register additional callbacks\n");
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

/* reset all flags */
int w_drop_acc_0(struct sip_msg* msg) {
	return w_drop_acc_2(msg, NULL, NULL);
}

int w_drop_acc_1(struct sip_msg* msg, char* type)
{
	return w_drop_acc_2(msg, type, NULL);
}

int w_drop_acc_2(struct sip_msg* msg, char* type_p, char* flags_p)
{
	unsigned long long type=0;
	/* if not set, we reset all flags for the type of accounting requested */
	unsigned long long flags=ALL_ACC_FLAGS;
	unsigned long long flag_mask;
	unsigned long long *context_flags_p=try_fetch_flags();


	acc_type_param_t* acc_param;

	str in;

	if (context_flags_p == NULL) {
		LM_ERR("do_accounting() not used! This function resets flags in "
				"do_accounting()!\n");
		return -1;
	}

	if (type_p != NULL) {
		acc_param = (acc_type_param_t *)type_p;
		if (acc_param->t == DO_ACC_PARAM_TYPE_VALUE) {
			type = acc_param->u.ival;
		} else {
			if (pv_printf_s(msg, acc_param->u.pval, &in) < 0) {
				LM_ERR("failed to fetch type value!\n");
				return -1;
			}

			if ((type=do_acc_parse(&in, do_acc_type_parser)) == DO_ACC_ERR) {
				LM_ERR("Invalid expression <%.*s> for acc type!\n", in.len, in.s);
				return -1;
			}
		}
	}

	if (flags_p != NULL) {
		flags= *(unsigned long long*)flags_p;
	}

	flag_mask = type * flags;

	/* reset all flags */
	if (flag_mask == 0) {
		*context_flags_p = 0;
	} else {
		reset_flags(*context_flags_p, flag_mask);
	}

	return 1;
}
