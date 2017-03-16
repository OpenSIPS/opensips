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
#define CGR_SESS_ON(_s) ((_s) && (_s)->branch_mask)
#define CGR_SESS_ON_BRANCH(_s, _b) ((_s) && (_s)->branch_mask & (1 << (_b)))

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
			/* point to the same sessions */
			ctx->acc->sessions = ctx->sessions;
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
	struct list_head *l, *sl;
	struct list_head *t, *st;
	struct cgr_session *s, *sa;
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
		list_for_each_safe(sl, st, acc_ctx->sessions) {
			sa = list_entry(sl, struct cgr_session, list);
			s = cgr_get_sess(ctx, (sa->tag.len ? &sa->tag : NULL));
			/* if there is a matching session. move everything from
			 * the one in accounting to the one in local ctx */
			if (s) {
				list_for_each_safe(l, t, &sa->kvs) {
					kv = list_entry(l, struct cgr_kv, list);
					if (cgr_get_kv(s, kv->key))
						cgr_free_kv(kv);
					else {
						list_del(&kv->list);
						list_add(&kv->list, &s->kvs);
					}
				}
				if (s->sess_info) {
					LM_WARN("found session info in a local context - discarding it!\n");
					shm_free(s->sess_info);
				}
				s->sess_info = sa->sess_info;
				sa->sess_info = 0;
				cgr_free_sess(sa);
			} else {
				/* move the dict in the local ctx */
				list_del(&s->list);
				list_add(&s->list, ctx->sessions);
			}
		}
		shm_free(acc_ctx->sessions);
		acc_ctx->sessions = ctx->sessions;
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
	/* remove all elements */
	if (ctx->sessions) {
		list_for_each_safe(l, t, ctx->sessions)
			cgr_free_sess(list_entry(l, struct cgr_session, list));
		shm_free(ctx->sessions);
		ctx->sessions = 0;
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
	/* update only if the timeout is smaller than the existing one */
	if (dlg->lifetime > val.n) {
		dlg->lifetime = val.n;
		dlg->lifetime_dirty = 1;
		LM_DBG("setting dialog timeout to %d\n", val.n);
	} else {
		LM_DBG("dialog timeout %d lower or equal than %d\n",
				dlg->lifetime, val.n);
	}

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

static inline str *cgr_get_sess_callid(struct sip_msg *msg,
		struct cgr_session *s, str *msg_cid)
{
	static str callid;
	char *tmp;
	int len;

	/* if the default tag, simply return the initial callid */
	if (!s->tag.len)
		return msg_cid;

	len = msg_cid->len + 1 /* separator */ + s->tag.len;
	tmp = pkg_realloc(callid.s, len);
	if (!tmp) {
		LM_ERR("cannot realloc callid buffer with len=%d\n", len);
		return NULL;
	}
	callid.s = tmp;
	callid.len = len;
	memcpy(callid.s, msg_cid->s, msg_cid->len);
	callid.s[msg_cid->len] = '|';
	memcpy(callid.s + msg_cid->len + 1, s->tag.s, s->tag.len);
	return &callid;
}

static json_object *cgr_get_start_acc_msg(struct sip_msg *msg,
		struct dlg_cell *dlg, struct cgr_acc_ctx *ctx, struct cgr_session *s)
{
	struct cgr_msg *cmsg;
	struct cgr_acc_sess *si = (struct cgr_acc_sess *)s->sess_info;
	static str cmd = str_init("SMGenericV1.InitiateSession");
	str stime;
	str *callid;

	cmsg = cgr_get_generic_msg(&cmd, s);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	/* OriginID */
	/* if origin was not added from script, add it now */
	if (ctx && !cgr_get_const_kv(s, "OriginID")) {
		if (msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
				(msg->callid==NULL)) ) {
			LM_ERR("Cannot get callid of the message!\n");
			goto error;
		} else {
			callid = cgr_get_sess_callid(msg, s, &msg->callid->body);
			if (!callid || cgr_msg_push_str(cmsg, "OriginID", callid) < 0) {
				LM_ERR("cannot push OriginID!\n");
				goto error;
			}
		}
	}

	if (ctx && !cgr_get_const_kv(s, "DialogID") &&
			cgr_msg_push_int(cmsg, "DialogID", dlg->h_id) < 0) {
		LM_ERR("cannot push DialogID!\n");
		goto error;
	}

	if (ctx && !cgr_get_const_kv(s, "DialogEntry") &&
			cgr_msg_push_int(cmsg, "DialogEntry", dlg->h_entry) < 0) {
		LM_ERR("cannot push DialogEntry!\n");
		goto error;
	}

	/* Account */
	if (cgr_msg_push_str(cmsg, "Account", &si->acc) < 0) {
		LM_ERR("cannot push Account info!\n");
		goto error;
	}

	/* SetupTime */
	stime.s = int2str(si->start_time, &stime.len);
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
	if (cgr_msg_push_str(cmsg, "Destination", &si->dst) < 0) {
		LM_ERR("cannot push Destination info!\n");
		goto error;
	}

	return cmsg->msg;
error:
	json_object_put(cmsg->msg);
	return NULL;
}

static json_object *cgr_get_stop_acc_msg(struct sip_msg *msg,
		struct cgr_acc_ctx *ctx, struct cgr_session *s)
{
	struct cgr_acc_sess *si = (struct cgr_acc_sess *)s->sess_info;
	struct dlg_cell *dlg;
	struct cgr_msg *cmsg = NULL;
	char int2str_buf[INT2STR_MAX_LEN + 1];
	time_t now = time(NULL);
	static str cmd = str_init("SMGenericV1.TerminateSession");
	str *callid;
	str tmp;

	ctx->duration = now - ctx->answer_time;

	/* OriginID */
	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return NULL;
	}

	cmsg = cgr_get_generic_msg(&cmd, s);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	/* OriginID */
	/* if origin was not added from script, add it now */
	if (ctx && !cgr_get_const_kv(s, "OriginID")) {
		callid = cgr_get_sess_callid(msg, s, &dlg->callid);
		if (cgr_msg_push_str(cmsg, "OriginID", callid) < 0) {
			LM_ERR("cannot push OriginID!\n");
			goto error;
		}
	}

	/* Account */
	if (cgr_msg_push_str(cmsg, "Account", &si->acc) < 0) {
		LM_ERR("cannot push Account info!\n");
		goto error;
	}

	/* SetupTime */
	if (ctx->answer_time != si->start_time) {
		tmp.s = int2str(si->start_time, &tmp.len);
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
		struct cgr_acc_ctx *ctx, struct cgr_session *s, str *callid)
{
	str tmp;
	struct cgr_msg *cmsg = NULL;
	char int2str_buf[INT2STR_MAX_LEN + 1];
	static str cmd = str_init("SMGenericV1.ProcessCDR");
	struct cgr_acc_sess *si = (struct cgr_acc_sess *)s->sess_info;

	cmsg = cgr_get_generic_msg(&cmd, s);
	if (!cmsg) {
		LM_ERR("cannot create generic cgrates message!\n");
		return NULL;
	}

	if (cgr_msg_push_str(cmsg, "OriginID", callid) < 0) {
		LM_ERR("cannot add OriginID node\n");
		goto error;
	}

	if (cgr_msg_push_str(cmsg, "Account", &si->acc) < 0) {
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

	if (si->start_time && si->start_time != ctx->answer_time) {
		tmp.s = int2str(si->start_time, &tmp.len);
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

static void cgr_cdr(struct sip_msg *msg, struct cgr_acc_ctx *ctx,
		struct cgr_session *s, str *callid)
{
	json_object *jmsg;

	jmsg = cgr_get_cdr_acc_msg(msg, ctx, s, callid);
	if (!jmsg) {
		LM_ERR("cannot build the json to send to cgrates\n");
		return;
	}

	cgr_handle_cmd(msg, jmsg, cgr_proc_cdr_acc_reply, ctx);
}

static void cgr_dlg_onshutdown(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
#if 0
TODO: SERIALIZE!
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
	if (ctx->kv_dicts) {
		list_for_each(l, ctx->kv_dicts) {
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
	if (ctx->kv_dicts) {
		list_for_each(l, ctx->kv_dicts) {
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
#endif
}

int w_cgr_acc(struct sip_msg* msg, char *flag_c, char* acc_c, char *dst_c,
		char *tag_c)
{
	str *acc;
	str *dst;
	struct cgr_acc_sess *si;
	struct cgr_acc_ctx *ctx;
	struct cgr_session *s;
	struct dlg_cell *dlg;
	branch_bm_t branch_mask = 0;

	if (msg->REQ_METHOD != METHOD_INVITE) {
		LM_DBG("accounting not called on INVITE\n");
		return -3;
	}
	/* find out where we are to see if it makes sense to engage anything */
	if (route_type == REQUEST_ROUTE || route_type == FAILURE_ROUTE) {
		branch_mask = (unsigned)-1;
		LM_DBG("engaging accounting for all branches!\n");
	} else if (route_type == BRANCH_ROUTE || route_type == ONREPLY_ROUTE) {
		branch_mask = 1 << cgr_tmb.get_branch_index();
		LM_DBG("engaging accounting for branch %d!\n", cgr_tmb.get_branch_index());
	} else {
		LM_ERR("cannot engage accounting in route type %d\n", route_type);
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
	s = cgr_get_sess_new(cgr_get_ctx(), cgr_get_tag(msg, tag_c));
	if (!s) {
		LM_ERR("cannot create a new session!\n");
		return -1;
	}
	if (!s->sess_info) {
		si = shm_malloc(sizeof(struct cgr_acc_sess) + acc->len + dst->len);
		if (!si) {
			LM_ERR("cannot create new session information!\n");
			return -1;
		}
		memset(si, 0, sizeof(struct cgr_acc_sess)); /* no need to clean the rest */
		si->acc.s = (char *)si + sizeof(struct cgr_acc_sess);
		si->dst.s = si->acc.s + acc->len;
		si->flags = (unsigned long)flag_c;
		time(&si->start_time);
		si->acc.len = acc->len;
		memcpy(si->acc.s, acc->s, acc->len);
		si->dst.len = dst->len;
		memcpy(si->dst.s, dst->s, dst->len);
		s->sess_info = si;
	} else {
		LM_DBG("session already engaged! nothing updated...\n");
		si = (struct cgr_acc_sess *)s->sess_info;
	}
	if (si->branch_mask & branch_mask) {
		LM_DBG("session already engaged on this branch\n");
		/* nothing more to do - no ref, no nothing */
		return 1;
	}
	si->branch_mask |= branch_mask;
	LM_DBG("session info tag=%.*s acc=%.*s dst=%.*s mask=%X\n",
			s->tag.len, s->tag.s, si->acc.len, si->acc.s,
			si->dst.len, si->dst.s, si->branch_mask);

	if (!ctx->engaged) {
		time(&ctx->start_time);

		if (cgr_tmb.register_tmcb( msg, 0, TMCB_RESPONSE_OUT,
				cgr_tmcb_func, ctx, cgr_tmcb_func_free)<=0) {
			LM_ERR("cannot register tm callbacks\n");
			cgr_ref_acc_ctx(ctx, -1, "acc");
			return -1;
		}
		cgr_ref_acc_ctx(ctx, 1, "tm");

		if (cgr_dlgb.register_dlgcb(dlg, DLGCB_TERMINATED|DLGCB_EXPIRED,
				cgr_dlg_callback, ctx, 0)){
			LM_ERR("cannot register callback for database accounting\n");
			return -1;
		}

		if (cgr_dlgb.register_dlgcb(dlg, DLGCB_DB_WRITE_VP,
					cgr_dlg_onshutdown, ctx, NULL) != 0) {
			LM_ERR("cannot register callback for program shutdown!\n");
			return -1;
		}
		ctx->engaged = 1;
	}

	return 1;
}

static void cgr_tmcb_func_free(void *param)
{
	cgr_ref_acc_ctx((struct cgr_acc_ctx *)param, -1, "tm");
}

static void cgr_tmcb_func(struct cell* t, int type, struct tmcb_params *ps)
{
	struct cgr_acc_ctx *ctx;
	struct cgr_acc_sess *si;
	struct cgr_session *s;
	struct dlg_cell *dlg;
	struct list_head *l;
	json_object *jmsg;
	str terminate_str;
	int branch;
	str callid;

	/* send commands only for engaged branches */
	branch = cgr_tmb.get_branch_index();

	LM_DBG("Called callback for transaction %p type %d reply_code=%d branch=%d\n",
			t, type, ps->code, branch);

	if (!is_invite(t) || has_totag(ps->req))
		return;

	ctx = (struct cgr_acc_ctx *)*ps->param;
	if (ps->code < 200)
		return;
	callid = t->callid;
	while (callid.len && (callid.s[callid.len - 1] == '\r' ||
			callid.s[callid.len - 1] == '\n'))
		callid.len--;

	if (ps->code >= 300) {
		/* we need to generate CDRs for all the branches that had engaged
		 * on this branch */
		list_for_each(l, ctx->sessions) {
			s = list_entry(l, struct cgr_session, list);
			si = (struct cgr_acc_sess *)s->sess_info;
			if (CGR_SESS_ON_BRANCH(si, branch)) {
				if ((si->flags & CGRF_DO_MISSED) && (si->flags & CGRF_DO_CDR))
					cgr_cdr(ps->req, ctx, s, &callid);
				si->branch_mask = 0;
			}
		}
		goto unref;
	}

	/* we start a session only for successful calls */
	dlg = cgr_dlgb.get_dlg();
	if (!dlg) {
		LM_ERR("cannot find dialog!\n");
		goto unref;
	}
	time(&ctx->answer_time);
	list_for_each(l, ctx->sessions) {
		s = list_entry(l, struct cgr_session, list);
		si = (struct cgr_acc_sess *)s->sess_info;
		if (!CGR_SESS_ON_BRANCH(si, branch)) {
			/* if they were ever engaged, we need to check if we have to
			 * raise a CDR */
			if (CGR_SESS_ON(si) && (si->flags & CGRF_DO_MISSED) &&
					(si->flags & CGRF_DO_CDR))
					cgr_cdr(ps->req, ctx, s, &callid);
			continue;
		}
		jmsg = cgr_get_start_acc_msg(ps->req, dlg, ctx, s);
		if (!jmsg) {
			LM_ERR("cannot build the json to send to cgrates\n");
			goto error;
		}

		if (cgr_handle_cmd(ps->req, jmsg, cgr_proc_start_acc_reply, dlg) < 0)
			goto error;
		si->started = 1;
	}

	/* should have reffed engaged and unref tm, so we simply exit :D */
	return;
error:
	/* TODO: should we close all the started sessions now? */
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
	struct cgr_acc_ctx *ctx;
	struct cgr_acc_sess *si;
	struct cgr_session *s;
	struct dlg_cell *dlg;
	struct list_head *l;

	if ((dlg = cgr_dlgb.get_dlg()) == NULL) {
		LM_ERR("cannot retrieve dialog!\n");
		return;
	}
	ctx = *ps->param;

	list_for_each(l, ctx->sessions) {
		s = list_entry(l, struct cgr_session, list);
		si = (struct cgr_acc_sess *)s->sess_info;
		if (!si || !si->started)
			continue;
		cgr_cdr(ps->req, ctx, s, &dlg->callid);
	}
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
#if 0
TODO: serialize
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
		ctx->kv_dicts = shm_malloc(sizeof(*ctx->kv_dicts));
		if (!ctx->kv_dicts) {
			LM_ERR("cannot allocate key-value store for ctx=%p\n", ctx);
			goto internal_error;
		}
		INIT_LIST_HEAD(ctx->kv_dicts);
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
				list_add(&kv->list, NULL/*TODO*/);
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
#endif
}
#undef CGR_CTX_COPY

static void cgr_dlg_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *_params)
{
	struct cgr_acc_ctx *ctx;
	struct cgr_acc_sess *si;
	struct cgr_session *s;
	struct list_head *l;
	json_object *jmsg;
	struct cell* t;
	int registered = 0;
	
	if (!_params) {
		LM_ERR("no parameter specified to dlg callback!\n");
		return;
	}
	ctx = *_params->param;

	/* stop every session started */
	list_for_each(l, ctx->sessions) {
		s = list_entry(l, struct cgr_session, list);
		si = (struct cgr_acc_sess *)s->sess_info;
		if (!si || !si->started)
			continue;
		jmsg = cgr_get_stop_acc_msg(_params->msg, ctx, s);
		if (!jmsg) {
			LM_ERR("cannot build the json to send to cgrates\n");
			continue;
		}

		if (cgr_handle_cmd(_params->msg, jmsg, cgr_proc_stop_acc_reply, ctx) < 0)
			continue;

		if (si->flags & CGRF_DO_CDR) {
			/* if it's not a local transaction we do the accounting on the tm callbacks */
			if (((t = cgr_tmb.t_gett()) == T_UNDEFINED) || !t ||
					(t != NULL && !cgr_tmb.t_is_local(_params->msg))) {
				/* normal dialogs will have to do accounting when the response for
				 * the bye will come because users should be able to populate extra
				 * vars and leg vars */
				if (!registered) {
					if (cgr_tmb.register_tmcb(_params->msg, NULL,
								TMCB_RESPONSE_OUT, cgr_cdr_cb, ctx, 0) < 0)
						LM_ERR("failed to register cdr callback!\n");
					registered = 1;
				}
			} else if (t != NULL && cgr_tmb.t_is_local(_params->msg)) {
				/* for local transactions we generate CDRs here, since all the messages
				 * have been processed */
				cgr_cdr(_params->msg, ctx, s, &dlg->callid);
				/* mark session as not started to prevent duplicate cdrs */
				si->started = 0;
			}
		}
	}
	if (!registered)
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
