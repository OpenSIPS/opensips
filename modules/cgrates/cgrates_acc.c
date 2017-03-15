/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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
#include "cgrates_acc.h"

#define CGR_REF_DBG(_c, _s) LM_DBG("%s ref=%d ctx=%p\n", _s, _c->ref_no, _c)

struct dlg_binds cgr_dlgb;
struct tm_binds cgr_tmb;

static inline void cgr_free_acc_ctx(struct cgr_acc_ctx *ctx);
static void cgr_tmcb_func( struct cell* t, int type, struct tmcb_params *ps);
static void cgr_tmcb_func_free(void *param);
static void cgr_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params);

static str cgr_ctx_str = str_init("cgrX_ctx");

static inline struct cgr_acc_ctx *cgr_new_acc_ctx(struct dlg_cell *dlg)
{
	str ctxstr;
	struct cgr_acc_ctx *ctx = shm_malloc(sizeof(*ctx));
	if (!ctx) {
		LM_ERR("cannot create acc context\n");
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));
	LM_DBG("new acc ctx=%p\n", ctx);
	ctxstr.len = sizeof(ctx);
	ctxstr.s = (char *)&ctx;

	ctx->ref_no = 1;
	CGR_REF_DBG(ctx, "init");
	lock_init(&ctx->ref_lock);
	if (cgr_dlgb.store_dlg_value(dlg, &cgr_ctx_str, &ctxstr))
		LM_ERR("cannot store context in dialog!\n");
	return ctx;
}

static inline struct cgr_acc_ctx *cgr_get_acc_ctx(void)
{
	struct dlg_cell *dlg;
	struct cgr_ctx *ctx = cgr_get_ctx();

	if (!ctx) {
		LM_ERR("cannot create global context\n");
		return NULL;
	}
	if (!ctx->acc) {
		dlg = cgr_dlgb.get_dlg();
		if (!dlg) {
			LM_ERR("cannot find a dialog!\n");
			return NULL;
		}
		if ((ctx->acc = cgr_new_acc_ctx(dlg)) != NULL) {
			/* point to the same kv_store */
			ctx->acc->kv_store = ctx->kv_store;
			cgr_ref_acc_ctx(ctx->acc, 1, "general ctx");
		}
	} else {
		LM_DBG("same acc ctx=%p\n", ctx->acc);
	}
	return ctx->acc;
}

struct cgr_acc_ctx *cgr_tryget_acc_ctx(void)
{
	struct cgr_acc_ctx *acc_ctx;
	str ctxstr;
	struct cgr_kv *kv;
	struct list_head *l;
	struct list_head *t;
	struct dlg_cell *dlg;
	struct cgr_ctx *ctx = CGR_GET_CTX();

	if (ctx && ctx->acc)
		return NULL;

	dlg = cgr_dlgb.get_dlg();
	if (!dlg) /* dialog not found yet, moving later */
		return NULL;
	/* search for the accounting ctx */
	if (cgr_dlgb.fetch_dlg_value(dlg, &cgr_ctx_str, &ctxstr, 0) < 0)
		return NULL;
	if (ctxstr.len != sizeof(struct cgr_acc_ctx *)) {
		LM_BUG("Invalid ctx pointer size %d\n", ctxstr.len);
		return NULL;
	}
	acc_ctx = *(struct cgr_acc_ctx **)ctxstr.s;
	if (!acc_ctx) /* nothing to do now */
		return NULL;

	/* if there is a context, move everything from static ctx to the shared
	 * one, but keep the newever values in the store */
	if (ctx) {
		list_for_each_safe(l, t, acc_ctx->kv_store) {
			kv = list_entry(l, struct cgr_kv, list);
			if (cgr_get_kv(ctx->kv_store, kv->key))
				cgr_free_kv(kv);
			else {
				list_del(&kv->list);
				list_add(&kv->list, ctx->kv_store);
			}
		}
		shm_free(acc_ctx->kv_store);
		acc_ctx->kv_store = ctx->kv_store;
	}

	return acc_ctx;
}

static inline void cgr_free_acc_ctx(struct cgr_acc_ctx *ctx)
{
	struct list_head *l;
	struct list_head *t;
	struct dlg_cell *dlg;
	str ctxstr;

	LM_DBG("release acc ctx=%p\n", ctx);
	if (ctx->acc.s)
		shm_free(ctx->acc.s);
	if (ctx->dst.s)
		shm_free(ctx->dst.s);
	/* remove all elements */
	if (ctx->kv_store) {
		list_for_each_safe(l, t, ctx->kv_store)
			cgr_free_kv(list_entry(l, struct cgr_kv, list));
		shm_free(ctx->kv_store);
		ctx->kv_store = 0;
	}
	shm_free(ctx);
	ctx = 0;
	ctxstr.len = sizeof(ctx);
	ctxstr.s = (char *)&ctx;
	dlg = cgr_dlgb.get_dlg();
	if (dlg && cgr_dlgb.store_dlg_value(dlg, &cgr_ctx_str, &ctxstr) < 0)
		LM_ERR("cannot reset context in dialog %p!\n", dlg);
}

void cgr_ref_acc_ctx(struct cgr_acc_ctx *ctx, int how, const char *who)
{
	lock_get(&ctx->ref_lock);
	ctx->ref_no += how;
	CGR_REF_DBG(ctx, who);

	if (ctx->ref_no == 0)
		cgr_free_acc_ctx(ctx);
	else if (ctx->ref_no < 0)
		LM_BUG("ref=%d ctx=%p gone negative!\n", ctx->ref_no, ctx);

	lock_release(&ctx->ref_lock);
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
		struct dlg_cell *dlg, struct cgr_acc_ctx *ctx)
{
	struct cgr_msg *cmsg;
	str stime;
	static str cmd = str_init("SMGenericV1.InitiateSession");

	if (msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
			(msg->callid==NULL)) ) {
		LM_ERR("Cannot get callid of the message!\n");
		return NULL;
	}
	time(&ctx->answer_time);

	cmsg = cgr_get_generic_msg(&cmd, ctx->kv_store);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	/* OriginID */
	/* if origin was not added from script, add it now */
	if (ctx && !cgr_get_const_kv(ctx->kv_store, "OriginID") &&
			cgr_msg_push_str(cmsg, "OriginID", &msg->callid->body) < 0) {
		LM_ERR("cannot push OriginID!\n");
		goto error;
	}

	if (ctx && !cgr_get_const_kv(ctx->kv_store, "DialogID") &&
			cgr_msg_push_int(cmsg, "DialogID", dlg->h_id) < 0) {
		LM_ERR("cannot push DialogID!\n");
		goto error;
	}

	if (ctx && !cgr_get_const_kv(ctx->kv_store, "DialogEntry") &&
			cgr_msg_push_int(cmsg, "DialogEntry", dlg->h_entry) < 0) {
		LM_ERR("cannot push DialogEntry!\n");
		goto error;
	}

	/* Account */
	if (cgr_msg_push_str(cmsg, "Account", &ctx->acc) < 0) {
		LM_ERR("cannot push Account info!\n");
		goto error;
	}

	/* SetupTime */
	stime.s = int2str(ctx->setup_time, &stime.len);
	if (cgr_msg_push_str(cmsg, "SetupTime", &stime) < 0) {
		LM_ERR("cannot push SetupTime info!\n");
		goto error;
	}

	/* AnswerTime */
	stime.s = int2str(ctx->answer_time, &stime.len);
	if (cgr_msg_push_str(cmsg, "AnswerTime", &stime) < 0) {
		LM_ERR("cannot push AnswerTime info!\n");
		goto error;
	}

	/* Destination */
	if (cgr_msg_push_str(cmsg, "Destination", &ctx->dst) < 0) {
		LM_ERR("cannot push Destination info!\n");
		goto error;
	}

	return cmsg->msg;
error:
	json_object_put(cmsg->msg);
	return NULL;
}

static json_object *cgr_get_stop_acc_msg(struct sip_msg *msg,
		struct cgr_acc_ctx *ctx, str *callid)
{
	struct dlg_cell *dlg;
	struct cgr_msg *cmsg = NULL;
	str tmp;
	char int2str_buf[INT2STR_MAX_LEN + 1];
	time_t now = time(NULL);
	static str cmd = str_init("SMGenericV1.TerminateSession");

	ctx->duration = now - ctx->answer_time;

	/* OriginID */
	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return NULL;
	}

	cmsg = cgr_get_generic_msg(&cmd, ctx->kv_store);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	/* OriginID */
	/* if origin was not added from script, add it now */
	if (ctx && !cgr_get_const_kv(ctx->kv_store, "OriginID") &&
			cgr_msg_push_str(cmsg, "OriginID", callid) < 0) {
		LM_ERR("cannot push OriginID!\n");
		goto error;
	}

	/* Account */
	if (cgr_msg_push_str(cmsg, "Account", &ctx->acc) < 0) {
		LM_ERR("cannot push Account info!\n");
		goto error;
	}

	/* SetupTime */
	if (ctx->answer_time != ctx->setup_time) {
		tmp.s = int2str(ctx->setup_time, &tmp.len);
		if (cgr_msg_push_str(cmsg, "SetupTime", &tmp) < 0) {
			LM_ERR("cannot push SetupTime info!\n");
			goto error;
		}
	}

	/* AnswerTime */
	tmp.s = int2str(ctx->answer_time, &tmp.len);
	if (cgr_msg_push_str(cmsg, "AnswerTime", &tmp) < 0) {
		LM_ERR("cannot push AnswerTime info!\n");
		goto error;
	}

	tmp.s = int2bstr(ctx->duration, int2str_buf, &tmp.len);
	/* add an s at the end */
	tmp.s[tmp.len] = 's';
	tmp.len++;
	tmp.s[tmp.len] = 0;
	if (cgr_msg_push_str(cmsg, "Usage", &tmp) < 0) {
		LM_ERR("cannot add Usage node\n");
		goto error;
	}

	return cmsg->msg;

error:
	json_object_put(cmsg->msg);
	return NULL;
}

static json_object *cgr_get_cdr_acc_msg(struct sip_msg *msg,
		struct cgr_acc_ctx *ctx, str *callid)
{
	struct dlg_cell *dlg;
	struct cgr_msg *cmsg = NULL;
	str tmp;
	char int2str_buf[INT2STR_MAX_LEN + 1];
	static str cmd = str_init("SMGenericV1.ProcessCDR");

	/* OriginID */
	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return NULL;
	}

	cmsg = cgr_get_generic_msg(&cmd, ctx->kv_store);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	/* TODO: shall we add an index or smth? */
	if (cgr_msg_push_str(cmsg, "OriginID", callid) < 0) {
		LM_ERR("cannot add OriginID node\n");
		goto error;
	}

	if (cgr_msg_push_str(cmsg, "Account", &ctx->acc) < 0) {
		LM_ERR("cannot add Account node\n");
		goto error;
	}

	tmp.s = int2bstr(ctx->duration, int2str_buf, &tmp.len);
	/* add an s at the end */
	tmp.s[tmp.len] = 's';
	tmp.len++;
	tmp.s[tmp.len] = 0;
	if (cgr_msg_push_str(cmsg, "Usage", &tmp) < 0) {
		LM_ERR("cannot add Usage node\n");
		goto error;
	}

	if (ctx->answer_time) {
		tmp.s = int2str(ctx->answer_time, &tmp.len);
		if (cgr_msg_push_str(cmsg, "AnswerTime", &tmp) < 0) {
			LM_ERR("cannot add AnswerTime node\n");
			goto error;
		}
	}

	if (ctx->setup_time && ctx->setup_time != ctx->answer_time) {
		tmp.s = int2str(ctx->setup_time, &tmp.len);
		if (cgr_msg_push_str(cmsg, "SetupTime", &tmp) < 0) {
			LM_ERR("cannot add SetupTime node\n");
			goto error;
		}
	}

	return cmsg->msg;

error:
	json_object_put(cmsg->msg);
	return NULL;
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

static void cgr_dlg_onshutdown(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	struct cgr_acc_ctx *ctx;
	struct list_head *l;
	struct cgr_kv *kv;
	str buf;
	char *p;

	ctx = *_params->param;
	LM_DBG("storing in dialog acc ctx=%p\n", ctx);

	buf.len = sizeof(ctx->flags) + sizeof(unsigned) + ctx->acc.len +
		sizeof(unsigned) + ctx->dst.len + sizeof(ctx->setup_time) +
		sizeof(ctx->answer_time);
	if (ctx->kv_store) {
		list_for_each(l, ctx->kv_store) {
			kv = list_entry(l, struct cgr_kv, list);
			buf.len += sizeof(unsigned) + kv->key.len + sizeof(unsigned char);
			if (kv->flags & CGR_KVF_TYPE_INT)
				buf.len += sizeof(int);
			else if (kv->flags & CGR_KVF_TYPE_STR)
				buf.len += sizeof(unsigned) + kv->value.s.len;
		}
	}
	buf.s = pkg_malloc(buf.len);
	if (!buf.s) {
		LM_ERR("cannot allocate buffer for context serialization!\n");
		return;
	}
	p = buf.s;
	/* flags */
	memcpy(p, &ctx->flags, sizeof(ctx->flags));
	p += sizeof(ctx->flags);

	/* acc */
	memcpy(p, &ctx->acc.len, sizeof(unsigned));
	p += sizeof(unsigned);
	memcpy(p, ctx->acc.s, ctx->acc.len);
	p += ctx->acc.len;

	/* dst */
	memcpy(p, &ctx->dst.len, sizeof(unsigned));
	p += sizeof(unsigned);
	memcpy(p, ctx->dst.s, ctx->dst.len);
	p += ctx->dst.len;

	/* setup time */
	memcpy(p, &ctx->setup_time, sizeof(ctx->setup_time));
	p += sizeof(ctx->setup_time);

	/* answer_time */
	memcpy(p, &ctx->answer_time, sizeof(ctx->answer_time));
	p += sizeof(ctx->answer_time);

	/* kv */
	if (ctx->kv_store) {
		list_for_each(l, ctx->kv_store) {
			kv = list_entry(l, struct cgr_kv, list);

			/* kv->key */
			memcpy(p, &kv->key.len, sizeof(unsigned));
			p += sizeof(unsigned);
			memcpy(p, kv->key.s, kv->key.len);
			p += kv->key.len;

			/* kv->flags */
			*(unsigned char *)p = kv->flags;
			p += sizeof(unsigned char);

			/* kv->value */
			if (kv->flags & CGR_KVF_TYPE_INT) {
				memcpy(p, &kv->value.n, sizeof(int));
				p += sizeof(int);
			} else if (kv->flags & CGR_KVF_TYPE_STR) {
				memcpy(p, &kv->value.s.len, sizeof(unsigned));
				p += sizeof(unsigned);
				memcpy(p, kv->value.s.s, kv->value.s.len);
				p += kv->value.s.len;
			}
		}
	}

	/* sanity check :D */
	if (buf.len != p - buf.s)
		LM_BUG("length mismatch between computed and result: %d != %d\n",
				buf.len, (int)(p - buf.s));

	if (cgr_dlgb.store_dlg_value(dlg, &cgr_ctx_str, &buf) < 0)
		LM_ERR("cannot store the serialized context value!\n");
	pkg_free(buf.s);
}

int w_cgr_acc(struct sip_msg* msg, char *flag_c, char* acc_c, char *dst_c)
{
	str *acc;
	str *dst;
	struct cgr_acc_ctx *ctx;
	struct dlg_cell *dlg;
	int unref = 1;

	if (msg->REQ_METHOD != METHOD_INVITE) {
		LM_DBG("accounting not called on INVITE\n");
		return -3;
	}

	if (!cgr_dlgb.get_dlg) {
		LM_ERR("cannot do cgrates accounting without dialog support!\n");
		return -2;
	}

	if ((acc = cgr_get_acc(msg, acc_c)) == NULL)
		return -2;
	if ((dst = cgr_get_dst(msg, dst_c)) == NULL)
		return -2;

	/* get the dialog */
	if (!cgr_dlgb.get_dlg() && cgr_dlgb.create_dlg(msg, 0) < 0) {
		LM_ERR("Cannot create dialog!\n");
		return -1;
	}
	dlg = cgr_dlgb.get_dlg();

	ctx = cgr_get_acc_ctx();
	if (!ctx) {
		LM_ERR("cannot create acc context\n");
		return -1;
	}

	ctx->flags = (unsigned long)flag_c;
	time(&ctx->setup_time);

	/* store accounting and destination values */
	if (shm_str_dup(&ctx->acc, acc) < 0 || shm_str_dup(&ctx->dst, dst) < 0) {
		LM_ERR("out of shm mem!\n");
		goto internal_error;
	}

	/* TODO: check if it was already engaged! */
	if (cgr_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_OUT,
			cgr_tmcb_func, ctx, cgr_tmcb_func_free)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		goto internal_error;
	}
	unref--;
	cgr_ref_acc_ctx(ctx, 1, "tm");

	if (cgr_tmb.register_tmcb( msg, 0, TMCB_ON_FAILURE|TMCB_TRANS_CANCELLED,
			cgr_tmcb_func, ctx, NULL)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		goto internal_error;
	}

	if (cgr_dlgb.register_dlgcb(dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
			cgr_dlg_callback, ctx, 0)){
		LM_ERR("cannot register callback for database accounting\n");
		goto internal_error;
	}

	if (cgr_dlgb.register_dlgcb(dlg, DLGCB_DB_WRITE_VP,
				cgr_dlg_onshutdown, ctx, NULL) != 0) {
		LM_ERR("cannot register callback for program shutdown!\n");
		goto internal_error;
	}

	return 1;
internal_error:
	cgr_ref_acc_ctx(ctx, unref, "acc");
	return -1;
}

static void cgr_tmcb_func_free(void *param)
{
	cgr_ref_acc_ctx((struct cgr_acc_ctx *)param, -1, "tm");
}

static void cgr_tmcb_func(struct cell* t, int type, struct tmcb_params *ps)
{
	struct cgr_acc_ctx *ctx;
	json_object *jmsg;
	struct dlg_cell *dlg;
	str terminate_str;

	LM_DBG("Called callback for transaction %p type %d reply_code=%d\n",
			t, type, ps->code);

	if (!is_invite(t) || has_totag(ps->req))
		return;

	ctx = (struct cgr_acc_ctx *)*ps->param;
	if (type & (TMCB_ON_FAILURE|TMCB_TRANS_CANCELLED)) {
		if (ctx->flags & CGRF_DO_MISSED && ctx->flags & CGRF_DO_CDR)
			cgr_cdr(ps->req, ctx, &t->callid);
		goto unref;
	} else if ((type & TMCB_RESPONSE_OUT) && (ps->code < 200 || ps->code >= 300)) {
		return;
	}

	/* we start a session only for successful calls */

	dlg = cgr_dlgb.get_dlg();
	if (!dlg) {
		LM_ERR("cannot find dialog!\n");
		goto unref;
	}
	jmsg = cgr_get_start_acc_msg(ps->req, dlg, ctx);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		goto error;
	}

	if (cgr_handle_cmd(ps->req, jmsg, cgr_proc_start_acc_reply, dlg) < 0)
		goto error;

	/* should have reffed engaged and unref tm, so we simply return :D */
	return;
error:
	terminate_str.s = "CGRateS Accounting Denied";
	terminate_str.len = strlen(terminate_str.s);
	if (cgr_dlgb.terminate_dlg(dlg->h_entry, dlg->h_id, &terminate_str) >= 0)
		return;
	LM_ERR("cannot terminate the dialog!\n");
unref:
	cgr_ref_acc_ctx(ctx, -1, "tm");
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
	cgr_ref_acc_ctx(ctx, -1, "engaged");
}

#define CGR_CTX_COPY(_t, _s, _e) \
	do { \
		if (p + (_s) <= end) { \
			memcpy((_t), p, (_s)); \
			p += (_s); \
		} else { \
			LM_ERR("invalid ctx stored buffer: no more length for %s\n", _e); \
			goto internal_error; \
		} \
	} while (0)

void cgr_loaded_callback(struct dlg_cell *dlg, int type,
			struct dlg_cb_params *_params)
{
	struct cgr_acc_ctx *ctx;
	str buf;
	str kvs;
	struct cgr_kv *kv;
	char *p, *end;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch message flags\n");
		return;
	}

	if (cgr_dlgb.fetch_dlg_value(dlg, &cgr_ctx_str, &buf, 0) < 0) {
		LM_DBG("ctx was not saved in dialog\n");
		return;
	}

	ctx = cgr_new_acc_ctx(dlg);
	if (!ctx)
		return;
	LM_DBG("loading from dialog acc ctx=%p\n", ctx);

	p = buf.s;
	end = buf.s + buf.len;
	CGR_CTX_COPY(&ctx->flags, sizeof(ctx->flags), "flags");
	CGR_CTX_COPY(&ctx->acc.len, sizeof(unsigned), "acc.len");
	if (!(ctx->acc.s = shm_malloc(ctx->acc.len))) {
		LM_ERR("cannot allocate account in ctx=%p len=%d!\n", ctx, ctx->acc.len);
		goto internal_error;
	}
	CGR_CTX_COPY(ctx->acc.s, ctx->acc.len, "acc.s");
	CGR_CTX_COPY(&ctx->dst.len, sizeof(unsigned), "dst.len");
	if (!(ctx->dst.s = shm_malloc(ctx->dst.len))) {
		LM_ERR("cannot allocate dest in ctx=%p len=%d!\n", ctx, ctx->dst.len);
		goto internal_error;
	}
	CGR_CTX_COPY(ctx->dst.s, ctx->dst.len, "dst.s");
	CGR_CTX_COPY(&ctx->setup_time, sizeof(ctx->setup_time), "setup time");
	CGR_CTX_COPY(&ctx->answer_time, sizeof(ctx->answer_time), "answer time");

	if (p < end) {
		/* we also have some values stored in the context */
		ctx->kv_store = shm_malloc(sizeof(*ctx->kv_store));
		if (!ctx->kv_store) {
			LM_ERR("cannot allocate key-value store for ctx=%p\n", ctx);
			goto internal_error;
		}
		INIT_LIST_HEAD(ctx->kv_store);
		while (p < end) {
			LM_DBG("p=%p end=%p\n", p, end);
			CGR_CTX_COPY(&kvs.len, sizeof(unsigned), "key.len");
			/* do the key manually because it's not worth doing a copy */
			if (p + kvs.len <= end) {
				kvs.s = p;
				p += kvs.len;
			} else {
				LM_ERR("invalid ctx stored buffer: no more length for key.str\n");
				goto internal_error;
			}
			kv = cgr_new_kv(kvs);
			if (!kv) {
				LM_ERR("cannot allocate a new kv\n");
				goto internal_error;
			}
			CGR_CTX_COPY(&kv->flags, sizeof(unsigned char), "key.flags");
			if (kv->flags & CGR_KVF_TYPE_INT)
				CGR_CTX_COPY(&kv->value.n, sizeof(int), "key.value.int");
			else if (kv->flags & CGR_KVF_TYPE_STR) {
				CGR_CTX_COPY(&kv->value.s.len, sizeof(unsigned), "key.value.str.len");
				kv->value.s.s = shm_malloc(kv->value.s.len);
				if (!kv->value.s.s) {
					LM_ERR("out of shm mem!\n");
					cgr_free_kv(kv);
					goto internal_error;
				}
				CGR_CTX_COPY(kv->value.s.s, kv->value.s.len, "key.value.str.s");
				/* all good - link the new value */
				list_add(&kv->list, ctx->kv_store);
			}
		}
	}

	if (p != end)
		LM_BUG("inconsistent state in cdr restore p=%p end=%p\n", p, end);

	cgr_ref_acc_ctx(ctx, 1, "dialog");
	if (cgr_dlgb.register_dlgcb(dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
			cgr_dlg_callback, ctx, 0)){
		LM_ERR("cannot register callback for database accounting\n");
		goto internal_error;
	}
	LM_DBG("successfully loaded acc ctx=%p\n", ctx);
	return;
internal_error:
	cgr_free_acc_ctx(ctx);
}
#undef CGR_CTX_COPY

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
		goto unref_ctx;

	if (ctx->flags & CGRF_DO_CDR) {
		/* if it's not a local transaction we do the accounting on the tm callbacks */
		if (((t = cgr_tmb.t_gett()) == T_UNDEFINED) || !t ||
				(t != NULL && !cgr_tmb.t_is_local(_params->msg))) {
			/* normal dialogs will have to do accounting when the response for
			 * the bye will come because users should be able to populate extra
			 * vars and leg vars */
			if (cgr_tmb.register_tmcb(_params->msg, NULL,
							TMCB_RESPONSE_OUT, cgr_cdr_cb, ctx, 0) < 0) {
				LM_ERR("failed to register cdr callback!\n");
				goto unref_ctx;
			}
			return;
		} else if (t != NULL && cgr_tmb.t_is_local(_params->msg)) {
			/* for local transactions we generate CDRs here, since all the messages
			 * have been processed */
			cgr_cdr(_params->msg, ctx, &dlg->callid);
		}
	}
unref_ctx:
	cgr_ref_acc_ctx(ctx, -1, "dialog");
}

int cgr_acc_terminate(json_object *param, json_object **ret)
{
	str terminate_str;
	const char *err;
	str reason = {0, 0};
	json_object *event = NULL;
	json_object *tmp = NULL;
	unsigned int h_entry = 0, h_id = 0;
	static str terminate_str_pre = str_init("CGRateS Disconnect: ");

	if (json_object_object_get_ex(param, "Reason", &tmp) && tmp &&
			json_object_get_type(tmp) == json_type_string)
		reason.s = (char *)json_object_get_string(tmp);

	if (!json_object_object_get_ex(param, "EventStart", &tmp) || !tmp ||
			json_object_get_type(tmp) != json_type_object) {
		err = "EventStart parameter is invalid or not found";
		goto error;
	}
	event = json_object_get(tmp);

	/* search for DialogID */
	if (!json_object_object_get_ex(event, "DialogID", &tmp) || !tmp ||
			json_object_get_type(tmp) != json_type_int) {
		err = "DialogID parameter is invalid or not found";
		goto error;
	}
	h_id = json_object_get_int(tmp);

	/* search for DialogEntry */
	if (!json_object_object_get_ex(event, "DialogEntry", &tmp) || !tmp ||
			json_object_get_type(tmp) != json_type_int) {
		err = "DialogEntry parameter is invalid or not found";
		goto error;
	}
	h_entry = json_object_get_int(tmp);

	if (reason.s) {
		reason.len = strlen(reason.s);
		terminate_str.s = pkg_malloc(terminate_str_pre.len + reason.len);
		if (!terminate_str.s) {
			err = "internal error";
			goto error;
		}
		memcpy(terminate_str.s, terminate_str_pre.s, terminate_str_pre.len);
		memcpy(terminate_str.s + terminate_str_pre.len, reason.s, reason.len);
		terminate_str.len = terminate_str_pre.len + reason.len;
	} else {
		terminate_str.s = terminate_str_pre.s;
		terminate_str.len = terminate_str_pre.len - 2 /* skip the ': ' */;
	}
	if (cgr_dlgb.terminate_dlg(h_entry, h_id, &terminate_str) < 0) {
		if (terminate_str.s != terminate_str_pre.s)
			pkg_free(terminate_str.s);
		err = "cannot terminate dialog";
		goto error;
	}
	if (terminate_str.s != terminate_str_pre.s)
		pkg_free(terminate_str.s);
	*ret = json_object_new_int(0);
	return 0;
error:
	LM_ERR("cannot handle terminate: %s\n", err);
	*ret = json_object_new_string(err);
	return -1;
}
