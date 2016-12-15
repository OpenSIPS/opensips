/*
 * Copyright (C) 2016 Razvan Crainea <razvan@opensips.org>
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
 */

#include "../../ut.h"
#include "../../mod_fix.h"
#include "cgrates_common.h"
#include "cgrates_acc.h"

struct dlg_binds cgr_dlgb;
struct tm_binds cgr_tmb;

enum cgr_acc_state {
	CGRS_EARLY = 0,
	CGRS_ENGAGED
};

struct cgr_acc_ctx {

	enum cgr_acc_state state;

	/* all branches info */
	str *acc;
	str *dst;
	time_t time;

	/* variables */
	struct list_head kv_store;

	/* branches */
	/*
	unsigned engaged_branches;
	struct cgr_uac uacs[MAX_BRANCHES];
	*/
};

static inline struct cgr_acc_ctx *cgr_get_acc_ctx(void);
static inline void cgr_free_acc_ctx(struct cgr_acc_ctx *ctx);
static void cgr_tmcb_func( struct cell* t, int type, struct tmcb_params *ps);
static void cgr_tmcb_func_free(void *param);
static void cgr_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);


static inline struct cgr_acc_ctx *cgr_get_acc_ctx(void)
{
	struct cgr_ctx *ctx = cgr_get_ctx();
	if (!ctx) {
		LM_ERR("cannot create global context\n");
		return NULL;
	}
	if (!ctx->acc) {
		ctx->acc = shm_malloc(sizeof(*ctx->acc));
		if (!ctx->acc) {
			LM_ERR("cannot create acc context\n");
			return NULL;
		}
		memset(ctx->acc, 0, sizeof(*ctx->acc));
		/* TODO: register to tm? */
	}
	LM_DBG("new acc ctx=%p\n", ctx->acc);
	return ctx->acc;
}

static inline void cgr_free_acc_ctx(struct cgr_acc_ctx *ctx)
{
	struct list_head *l;
	struct list_head *t;

	if (ctx->acc)
		shm_free(ctx->acc);
	if (ctx->dst)
		shm_free(ctx->dst);
	/* remove all elements */
	list_for_each_safe(l, t, &ctx->kv_store)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	shm_free(ctx);
	LM_DBG("release acc ctx=%p\n", ctx);
}

static int cgr_proc_start_acc_reply(struct cgr_conn *c, json_object *jobj,
		void *p, char *error)
{
	int_str val;
	struct dlg_cell *dlg = (struct dlg_cell *)p;

	/* we cannot set in the context, because we don't have access to it */
	if (error)
		return -1;

	if (json_object_get_type(jobj) != json_type_int) {
		LM_ERR("CGRateS returned a non-int type in InitiateSession reply: %d %s\n",
				json_object_get_type(jobj), json_object_to_json_string(jobj));
		return -4;
	}
	val.n = json_object_get_int(jobj);
	/* -1: always allowed (postpaid)
	 *  0: not allowed to call
	 *  *: allowed
	 */
	if (val.n == 0)
		return -1;
	if (val.n == -1)
		return 1;
	dlg->lifetime = val.n;
	dlg->lifetime_dirty = 1;

	LM_DBG("setting dialog timeout to %d\n", val.n);
	return 1;
}

static int cgr_proc_stop_acc_reply(struct cgr_conn *c, json_object *jobj,
		void *p, char *error)
{
	if (error) {
		LM_ERR("got CDR error: %s\n", error);
		return -1;
	}

	LM_DBG("got reply from cgrates: %s\n", json_object_to_json_string(jobj));
	return 1;
}

static int cgr_proc_cdr_acc_reply(struct cgr_conn *c, json_object *jobj,
		void *p, char *error)
{
	int_str val;
	if (error) {
		val.s.s = error;
		val.s.len = strlen(error);
		if (cgrates_set_reply(CGR_KVF_TYPE_STR, &val) < 0) {
			LM_ERR("cannot set the reply code!\n");
			return -2;
		}
		return -1;
	}

	LM_DBG("got reply from cgrates: %s\n", json_object_to_json_string(jobj));
	return 1;
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


static inline int cgr_help_set_str(str **dst, str src)
{
	if (*dst)
		shm_free(*dst);
	*dst = shm_malloc(sizeof(str) + src.len);
	if (!(*dst)) {
		LM_ERR("out of shm memory\n");
		return -1;
	}
	(*dst)->s = ((char *)(*dst)) + sizeof(str);
	(*dst)->len = src.len;
	memcpy((*dst)->s, src.s, src.len);
	return 0;
}


static json_object *cgr_get_start_acc_msg(struct sip_msg *msg,
		struct cgr_acc_ctx *ctx)
{
	struct cgr_msg *cmsg;
	str stime;

	if (msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
			(msg->callid==NULL)) ) {
		LM_ERR("Cannot get callid of the message!\n");
		return NULL;
	}
	time(&ctx->time);

	stime.s = int2str(ctx->time, &stime.len);
	cmsg = cgr_get_generic_msg("SMGenericV1.InitiateSession",
			&ctx->kv_store);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	/* OriginID */
	/* if origin was not added from script, add it now */
	if (ctx && !cgr_get_const_kv(&ctx->kv_store, "OriginID") &&
			cgr_msg_push_str(cmsg, "OriginID", &msg->callid->body) < 0) {
		LM_ERR("cannot push OriginID!\n");
		goto error;
	}

	/* Account */
	if (cgr_msg_push_str(cmsg, "Account", ctx->acc) < 0) {
		LM_ERR("cannot push Account info!\n");
		goto error;
	}

	/* SetupTime */
	if (cgr_msg_push_str(cmsg, "AnswerTime", &stime) < 0) {
		LM_ERR("cannot push AnswerTime info!\n");
		goto error;
	}

	/* Destination */
	if (cgr_msg_push_str(cmsg, "Destination", ctx->dst) < 0) {
		LM_ERR("cannot push Destination info!\n");
		goto error;
	}

	return cmsg->msg;
error:
	json_object_put(cmsg->msg);
	return cmsg->msg;
}

static json_object *cgr_get_stop_acc_msg(struct sip_msg *msg,
		struct cgr_acc_ctx *ctx, str *callid)
{
	struct list_head extra_list;
	struct list_head *l, *t;
	struct dlg_cell *dlg;
	struct cgr_msg *cmsg = NULL;
	str name;
	char int2str_buf[INT2STR_MAX_LEN + 1];
	/* compute the duration */
	unsigned int duration = time(NULL) - ctx->time;

	INIT_LIST_HEAD(&extra_list);

	/* OriginID */
	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return NULL;
	}

	/* TODO: shall we add an index or smth? */
	if (cgr_push_kv_str(&extra_list, "OriginID", callid) < 0) {
		LM_ERR("cannot add OriginID node\n");
		return NULL;
	}

	if (ctx->acc && cgr_push_kv_str(&extra_list, "Account", ctx->acc) < 0) {
		LM_ERR("cannot add Account node\n");
		goto exit;
	}
	time(&ctx->time);

	name.s = int2bstr(duration, int2str_buf, &name.len);
	/* add an s at the end */
	name.s[name.len] = 's';
	name.len++;
	name.s[name.len] = 0;
	if (cgr_push_kv_str(&extra_list, "Usage", &name) < 0) {
		LM_ERR("cannot add Usage node\n");
		goto exit;
	}

	/* TODO: shall we merge what is in extra_list with what is in the local
	 * context? */

	cmsg = cgr_get_generic_msg("SMGenericV1.TerminateSession",
			&ctx->kv_store/* TODO:h &extra_list*/);

exit:
	list_for_each_safe(l, t, &extra_list)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	return cmsg->msg;
}

static json_object *cgr_get_cdr_acc_msg(struct sip_msg *msg,
		struct cgr_acc_ctx *ctx, str *callid)
{
	struct list_head extra_list;
	struct list_head *l, *t;
	struct dlg_cell *dlg;
	struct cgr_msg *cmsg = NULL;

	INIT_LIST_HEAD(&extra_list);

	/* OriginID */
	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return NULL;
	}

	/* TODO: shall we add an index or smth? */
	if (cgr_push_kv_str(&extra_list, "OriginID", &dlg->callid) < 0) {
		LM_ERR("cannot add OriginID node\n");
		return NULL;
	}

	if (ctx->acc && cgr_push_kv_str(&extra_list, "Account", ctx->acc) < 0) {
		LM_ERR("cannot add Account node\n");
		goto exit;
	}
	time(&ctx->time);

#if 0
	name.s = int2bstr(duration, int2str_buf, &name.len);
	/* add an s at the end */
	name.s[name.len] = 's';
	name.len++;
	name.s[name.len] = 0;
	if (cgr_push_kv_str(&extra_list, "Usage", &name) < 0) {
		LM_ERR("cannot add Usage node\n");
		goto exit;
	}
#endif

	/* TODO: shall we merge what is in extra_list with what is in the local
	 * context? */

	cmsg = cgr_get_generic_msg("SMGenericV1.ProcessCDR",
			&ctx->kv_store/* TODO: , &extra_list */);

exit:
	list_for_each_safe(l, t, &extra_list)
		cgr_free_kv(list_entry(l, struct cgr_kv, list));
	return cmsg->msg;
}

static void cgr_cdr(struct sip_msg *msg, struct cgr_acc_ctx *ctx, str *callid)
{
	json_object *jmsg;

	jmsg = cgr_get_cdr_acc_msg(msg, ctx, callid);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return;
	}

	cgr_handle_cmd(msg, jmsg, cgr_proc_cdr_acc_reply, ctx);
}

int w_cgr_acc(struct sip_msg* msg, char* acc_c, char *dst_c)
{
	str *acc;
	str *dst;
	struct cgr_acc_ctx *ctx;

	if (msg->REQ_METHOD != METHOD_INVITE) {
		LM_DBG("accounting not called on INVITE\n");
		return -3;
	}

	if (!cgr_dlgb.get_dlg) {
		LM_ERR("cannot do cgrates accounting without dialog support!\n");
		return -3;
	}

	if ((acc = cgr_get_acc(msg, acc_c)) == NULL)
		return -4;
	if ((dst = cgr_get_acc(msg, dst_c)) == NULL)
		return -4;

	/* get the dialog */
	if (!cgr_dlgb.get_dlg() && cgr_dlgb.create_dlg(msg, 0) < 0) {
		LM_ERR("Cannot create dialog!\n");
		return -2;
	}

	ctx = cgr_get_acc_ctx();
	if (!ctx) {
		LM_ERR("cannot create acc context\n");
		return -1;
	}

	/* TODO: check if it was already engaged! */
	if (cgr_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_OUT|TMCB_ON_FAILURE|
			TMCB_TRANS_CANCELLED, cgr_tmcb_func, ctx, cgr_tmcb_func_free)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		goto internal_error;
	}

	if (cgr_dlgb.register_dlgcb(cgr_dlgb.get_dlg(), DLGCB_TERMINATED |
			DLGCB_EXPIRED, cgr_dlg_callback, ctx, 0)){
		LM_ERR("cannot register callback for database accounting\n");
		goto internal_error;
	}

	return 1;
internal_error:
	cgr_free_acc_ctx(ctx);
	return -1;
}

static void cgr_tmcb_func_free(void *param)
{
	struct cgr_acc_ctx *ctx = (struct cgr_acc_ctx *)param;
	/* only free in the EARLY state, because if ENGAGED, then dialog takes
	 * care of it */
	if (ctx->state == CGRS_EARLY)
		cgr_free_acc_ctx(ctx);
}

static void cgr_tmcb_func( struct cell* t, int type, struct tmcb_params *ps)
{
	struct cgr_acc_ctx *ctx;
	json_object *jmsg;
	struct dlg_cell *dlg;
	str terminate_str;

	LM_DBG("Called callback for transaction %p type %d reply_code=%d\n",
			t, type, ps->code);

	if (!is_invite(t) || has_totag(ps->req))
		return;

	/* TODO: determine context */
	ctx = (struct cgr_acc_ctx *)*ps->param;
	if (type & (TMCB_ON_FAILURE|TMCB_TRANS_CANCELLED)) {
		cgr_cdr(ps->req, ctx, &t->callid);
		return;
	} else if ((type & TMCB_RESPONSE_OUT) && (ps->code < 200 || ps->code >= 300)) {
		return;
	}

	/* we start a session only for successful calls */

	dlg = cgr_dlgb.get_dlg();
	if (!dlg) {
		LM_ERR("cannot find dialog!\n");
		return;
	}
	jmsg = cgr_get_start_acc_msg(ps->req, ctx);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		goto error;
	}

	if (cgr_handle_cmd(ps->req, jmsg, cgr_proc_start_acc_reply, dlg) < 0)
		goto error;

	ctx->state = CGRS_ENGAGED;
	return;
error:
	terminate_str.s = "CGRateS Accounting Denied";
	terminate_str.len = strlen(terminate_str.s);
	if (cgr_dlgb.terminate_dlg(dlg->h_entry, dlg->h_id, &terminate_str) < 0)
		LM_ERR("cannot terminate the dialog!\n");
	dlg->lifetime = 0;
	dlg->lifetime_dirty = 1; /* not really necessary */
	return;
}

static void cgr_cdr_cb(struct cell* t, int type, struct tmcb_params *ps)
{
	struct dlg_cell *dlg;
	struct cgr_acc_ctx *ctx;

	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return;
	}
	ctx = *ps->param;

	cgr_cdr(ps->req, ctx, &dlg->callid);
}

static void cgr_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	struct cgr_acc_ctx *ctx;
	struct cell* t;
	json_object *jmsg;
	
	if (!_params) {
		LM_ERR("no parameter specified to dlg callback!\n");
		return;
	}
	ctx = *_params->param;

	jmsg = cgr_get_stop_acc_msg(_params->msg, ctx, &dlg->callid);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return;
	}

	if (cgr_handle_cmd(_params->msg, jmsg, cgr_proc_stop_acc_reply, ctx) < 0)
		goto free_ctx;

	/* if it's not a local transaction we do the accounting on the tm callbacks */
	if (((t = cgr_tmb.t_gett()) == T_UNDEFINED) || !t ||
			(t != NULL && !cgr_tmb.t_is_local(_params->msg))) {
		/* normal dialogs will have to do accounting when the response for
		 * the bye will come since users should be able to populate extra
		 * vars and leg vars */
		if (cgr_tmb.register_tmcb(_params->msg, NULL,
						TMCB_RESPONSE_OUT, cgr_cdr_cb, ctx, 0) < 0) {
			LM_ERR("failed to register cdr callback!\n");
			goto free_ctx;
		}
		return;
	/* for local transactions we generate CDRs here, since all the messages
	 * have been processed */
	} else if (t != NULL && cgr_tmb.t_is_local(_params->msg)) {
		cgr_cdr(_params->msg, ctx, &dlg->callid);
		return;
	}
free_ctx:
	cgr_free_acc_ctx(ctx);
}
