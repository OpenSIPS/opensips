/*
 * Copyright (C) 2021 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "rtp_relay_ctx.h"
#include "../../mem/shm_mem.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../../bin_interface.h"

static struct tm_binds rtp_relay_tmb;
static struct dlg_binds rtp_relay_dlg;
static int rtp_relay_tm_ctx_idx = -1;
static int rtp_relay_dlg_ctx_idx = -1;
static int rtp_relay_ctx_idx = -1;

static gen_lock_t *rtp_relay_contexts_lock;
static struct list_head *rtp_relay_contexts;

#define RTP_RELAY_GET_MSG_CTX() ((struct rtp_relay_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, rtp_relay_ctx_idx))
#define RTP_RELAY_PUT_CTX(_p) context_put_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, rtp_relay_ctx_idx, (_p))
#define RTP_RELAY_GET_TM_CTX(_t) (rtp_relay_tmb.t_ctx_get_ptr(_t, rtp_relay_tm_ctx_idx))
#define RTP_RELAY_PUT_TM_CTX(_t, _p) \
	rtp_relay_tmb.t_ctx_put_ptr(_t, rtp_relay_tm_ctx_idx, _p)

#define RTP_RELAY_GET_DLG_CTX(_d) (rtp_relay_dlg.dlg_ctx_get_ptr(_d, rtp_relay_tm_ctx_idx))
#define RTP_RELAY_PUT_DLG_CTX(_d, _p) \
	rtp_relay_dlg.dlg_ctx_put_ptr(_d, rtp_relay_dlg_ctx_idx, _p)

static str rtp_relay_dlg_name = str_init("_rtp_relay_ctx_");
static int rtp_relay_dlg_callbacks(struct dlg_cell *dlg, struct rtp_relay_ctx *ctx);

static struct rtp_relay_ctx *rtp_relay_get_dlg_ctx(void)
{
	struct dlg_cell *dlg = rtp_relay_dlg.get_dlg();

	return dlg?RTP_RELAY_GET_DLG_CTX(dlg):NULL;
}

struct rtp_relay_ctx *rtp_relay_new_ctx(void)
{
	struct rtp_relay_ctx *ctx = shm_malloc(sizeof *ctx);
	if (!ctx) {
		LM_ERR("oom for creating RTP relay context!\n");
		return NULL;
	}
	memset(ctx, 0, sizeof *ctx);

	lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->sessions);
	INIT_LIST_HEAD(&ctx->list);
	return ctx;
}

struct rtp_relay_ctx *rtp_relay_get_ctx(void)
{

	struct cell* t;
	struct rtp_relay_ctx *ctx = rtp_relay_try_get_ctx();

	t = rtp_relay_tmb.t_gett();
	t = t==T_UNDEFINED ? NULL : t;

	if (ctx) {
		/* if it is local, and we have transaction, move it in transaction */
		if (t && RTP_RELAY_GET_MSG_CTX()) {
			RTP_RELAY_PUT_TM_CTX(t, ctx);
			RTP_RELAY_PUT_CTX(NULL);
		}
		return ctx;
	}
	ctx = rtp_relay_new_ctx();
	if (!ctx)
		return NULL;

	if (t)
		RTP_RELAY_PUT_TM_CTX(t, ctx);
	else
		RTP_RELAY_PUT_CTX(ctx);
	return ctx;
}

static void rtp_relay_ctx_free_sess(struct rtp_relay_sess *s)
{
	int f;

	for (f = 0; f < RTP_RELAY_FLAGS_SIZE; f++) {
		if (s->flags[RTP_RELAY_OFFER][f].s)
			shm_free(s->flags[RTP_RELAY_OFFER][f].s);
		if (s->flags[RTP_RELAY_ANSWER][f].s)
			shm_free(s->flags[RTP_RELAY_ANSWER][f].s);
	}
	if (s->server.node.s)
		shm_free(s->server.node.s);
	list_del(&s->list);
	shm_free(s);
}

void rtp_relay_ctx_free(void *param)
{
	struct list_head *it, *safe;
	struct rtp_relay_ctx *ctx = (struct rtp_relay_ctx *)param;

	if (!ctx)
		return;

	if (ctx->callid.s)
		shm_free(ctx->callid.s);

	list_for_each_safe(it, safe, &ctx->sessions)
		rtp_relay_ctx_free_sess(list_entry(it, struct rtp_relay_sess, list));

	lock_destroy(&ctx->lock);
	shm_free(ctx);
}

struct rtp_relay_ctx *rtp_relay_try_get_ctx(void)
{
	struct cell* t;
	struct rtp_relay_ctx* ctx = NULL;

	if ((ctx = rtp_relay_get_dlg_ctx()) != NULL)
		return ctx;

	if ((ctx = RTP_RELAY_GET_MSG_CTX()) != NULL)
		return ctx;

	/* local one not found - search in transaction */
	t = rtp_relay_tmb.t_gett();
	t = t==T_UNDEFINED ? NULL : t;

	return (t ? RTP_RELAY_GET_TM_CTX(t) : NULL);
}

static void rtp_relay_move_ctx( struct cell* t, int type, struct tmcb_params *ps)
{
	struct rtp_relay_ctx *ctx = rtp_relay_try_get_ctx();

	if (!ctx || rtp_relay_get_dlg_ctx())
		return; /* nothing to move */

	t = rtp_relay_tmb.t_gett();
	if (!t || t == T_UNDEFINED) {
		LM_DBG("no transaction - can't move the context - freeing!\n");
		rtp_relay_ctx_free(ctx);
		return;
	}

	RTP_RELAY_PUT_TM_CTX(t, ctx);
	RTP_RELAY_PUT_CTX(NULL);
}

#define RTP_RELAY_CTX_VERSION 1
#define RTP_RELAY_BIN_PUSH(_type, _value) \
	do { \
		if (bin_push_##_type(&packet, _value) < 0) { \
			LM_ERR("cannot push '" #_value "' in bin packet!\n"); \
			bin_free_packet(&packet); \
			return; \
		} \
	} while (0)


static void rtp_relay_store_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str buffer;
	str str_empty = str_init("");
	bin_packet_t packet;
	enum rtp_relay_type rtype;
	enum rtp_relay_var_flags flag;
	struct rtp_relay_sess *sess;
	str name = str_init("rtp_relay_ctx");
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx)
		return;

	if (bin_init(&packet, &name, 0, RTP_RELAY_CTX_VERSION, 0) < 0) {
		LM_ERR("cannot initialize bin packet!\n");
		return;
	}
	if (!ctx->main) {
		if (list_empty(&ctx->sessions)) {
			LM_WARN("no rtp relay session!\n");
			return;
		}
		LM_WARN("rtp relay session not established - storing last session!\n");
		sess = list_last_entry(&ctx->sessions, struct rtp_relay_sess, list);
	} else {
		sess = ctx->main;
	}
	RTP_RELAY_BIN_PUSH(str, &sess->relay->name);
	RTP_RELAY_BIN_PUSH(int, sess->index);
	RTP_RELAY_BIN_PUSH(int, sess->state);
	RTP_RELAY_BIN_PUSH(int, sess->server.set);
	RTP_RELAY_BIN_PUSH(str, &sess->server.node);
	for (rtype = RTP_RELAY_OFFER; rtype < RTP_RELAY_SIZE; rtype++) {
		for (flag = RTP_RELAY_FLAGS_SELF; flag < RTP_RELAY_FLAGS_SIZE; flag++) {
			if (sess->flags[rtype][flag].s)
				RTP_RELAY_BIN_PUSH(str, &sess->flags[rtype][flag]);
			else
				RTP_RELAY_BIN_PUSH(str, &str_empty);
		}
	}

	bin_get_buffer(&packet, &buffer);
	bin_free_packet(&packet);

	if (rtp_relay_dlg.store_dlg_value(dlg, &rtp_relay_dlg_name, &buffer) < 0)
		LM_WARN("rtp relay ctx was not saved in dialog\n");
}
#undef RTP_RELAY_BIN_PUSH

#define RTP_RELAY_BIN_POP(_type, _value) \
	do { \
		if (bin_pop_##_type(&packet, _value) < 0) { \
			LM_ERR("cannot pop '" #_value "' from bin packet!\n"); \
			goto error; \
		} \
	} while (0)

static void rtp_relay_loaded_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str tmp;
	int index;
	str buffer;
	bin_packet_t packet;
	struct rtp_relay *relay;
	enum rtp_relay_type rtype;
	enum rtp_relay_var_flags flag;
	struct rtp_relay_sess *sess;
	struct rtp_relay_ctx *ctx = NULL;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch rtp relay info!\n");
		return;
	}

	if (rtp_relay_dlg.fetch_dlg_value(dlg, &rtp_relay_dlg_name, &buffer, 0) < 0) {
		LM_DBG("cannot fetch rtp relay info from the dialog\n");
		return;
	}
	bin_init_buffer(&packet, buffer.s, buffer.len);

	if (get_bin_pkg_version(&packet) != RTP_RELAY_CTX_VERSION) {
		LM_ERR("invalid serialization version (%d != %d)\n",
			get_bin_pkg_version(&packet), RTP_RELAY_CTX_VERSION);
		return;
	}
	RTP_RELAY_BIN_POP(str, &tmp);
	relay = rtp_relay_get(&tmp);
	if (!relay) {
		LM_ERR("no registered '%.*s' relay module\n", tmp.len, tmp.s);
		return;
	}

	ctx = rtp_relay_new_ctx();
	if (!ctx)
		return;

	RTP_RELAY_BIN_POP(int, &index);
	sess = rtp_relay_new_sess(ctx, index);
	if (!sess)
		goto error;
	RTP_RELAY_BIN_POP(int, &sess->state);
	sess->relay = relay;
	RTP_RELAY_BIN_POP(int, &sess->server.set);
	RTP_RELAY_BIN_POP(str, &sess->server.node);

	for (rtype = RTP_RELAY_OFFER; rtype < RTP_RELAY_SIZE; rtype++) {
		for (flag = RTP_RELAY_FLAGS_SELF; flag < RTP_RELAY_FLAGS_SIZE; flag++) {
			RTP_RELAY_BIN_POP(str, &tmp);
			if (tmp.len && shm_str_dup(&sess->flags[rtype][flag], &tmp) < 0)
				LM_ERR("could not duplicate rtp session flag!\n");
		}
	}

	/* all good now - delete the dialog variable as it is useless */
	rtp_relay_dlg.store_dlg_value(dlg, &rtp_relay_dlg_name, NULL);

	ctx->main = sess;
	if (rtp_relay_dlg_callbacks(dlg, ctx) < 0)
		goto error;

	return;
error:
	rtp_relay_ctx_free(ctx);
}
#undef RTP_RELAY_BIN_POP

int rtp_relay_ctx_preinit(void)
{
	/* load the TM API */
	if (load_tm_api(&rtp_relay_tmb)!=0) {
		LM_ERR("TM not loaded - aborting!\n");
		return -1;
	}
	/* load the DLG API */
	if (load_dlg_api(&rtp_relay_dlg)!=0) {
		LM_ERR("Dialog not loaded - aborting!\n");
		return -1;
	}
	/* we need to register pointer in pre-init, to make sure the new dialogs
	 * loaded have the context registered */
	rtp_relay_dlg_ctx_idx = rtp_relay_dlg.dlg_ctx_register_ptr(rtp_relay_ctx_free);
	return 0;
}

int rtp_relay_ctx_init(void)
{

	rtp_relay_contexts_lock = lock_alloc();
	if (!rtp_relay_contexts_lock ||
			!lock_init(rtp_relay_contexts_lock)) {
		LM_ERR("cannot create lock for RTP Relay sessions\n");
		return -1;
	}

	rtp_relay_contexts = shm_malloc(sizeof *rtp_relay_contexts);
	if (!rtp_relay_contexts) {
		LM_ERR("cannot create RTP Relay sessions list\n");
		return -1;
	}

	INIT_LIST_HEAD(rtp_relay_contexts);
	rtp_relay_tm_ctx_idx = rtp_relay_tmb.t_ctx_register_ptr(rtp_relay_ctx_free);
	/* register a routine to move the pointer in tm when the transaction
	 * is created! */
	if (rtp_relay_tmb.register_tmcb(0, 0, TMCB_REQUEST_IN, rtp_relay_move_ctx, 0, 0)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		return -2;
	}

	if (rtp_relay_dlg.register_dlgcb(NULL, DLGCB_LOADED,
			rtp_relay_loaded_callback, NULL, NULL) < 0)
		LM_WARN("cannot register callback for loaded dialogs - will not be "
				"able to restore an ongoing media session after a restart!\n");
	rtp_relay_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, rtp_relay_ctx_free);
	return 0;
}

int rtp_relay_ctx_branch(void)
{
	return rtp_relay_tmb.get_branch_index();
}

int rtp_relay_ctx_upstream(void)
{
	return rtp_relay_dlg.get_direction() == DLG_DIR_UPSTREAM;
}

struct rtp_relay_sess *rtp_relay_get_sess(struct rtp_relay_ctx *ctx, int index)
{
	struct list_head *it;
	struct rtp_relay_sess *sess;
	if (index == RTP_RELAY_ALL_BRANCHES)
		return ctx->main;
	list_for_each(it, &ctx->sessions) {
		sess = list_entry(it, struct rtp_relay_sess, list);
		if (sess->index == index)
			return sess;
	}
	return NULL;
}

struct rtp_relay_sess *rtp_relay_new_sess(struct rtp_relay_ctx *ctx, int index)
{
	struct rtp_relay_sess *sess;
	sess = shm_malloc(sizeof *sess);
	if (!sess) {
		LM_ERR("oom for new sess!\n");
		return NULL;
	}
	memset(sess, 0, sizeof *sess);
	sess->server.set = -1;
	sess->index = index;
	if (index == RTP_RELAY_ALL_BRANCHES)
		ctx->main = sess;
	list_add(&sess->list, &ctx->sessions);
	return sess;
}

#define RTP_RELAY_FLAGS(_t, _f) \
	(sess->flags[_t][_f].s?&sess->flags[_t][_f]: \
	 (main?&main->flags[_t][_f]:NULL))

#define RTP_RELAY_PEER(_t) \
	(_t == RTP_RELAY_OFFER?RTP_RELAY_ANSWER:RTP_RELAY_OFFER)

static int rtp_relay_offer(struct rtp_relay_session *info,
		struct rtp_relay_sess *sess, struct rtp_relay_sess *main, enum rtp_relay_type type)
{
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	if (sess->relay->binds.offer(info, &sess->server,
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_IP),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS(type, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(type, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_PEER)) < 0) {
		LM_ERR("could not engage offer!\n");
		return -1;
	}
	rtp_sess_set_pending(sess);
	return 1;
}

static int rtp_relay_answer(struct rtp_relay_session *info,
		struct rtp_relay_sess *sess, struct rtp_relay_sess *main, enum rtp_relay_type type)
{
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	return sess->relay->binds.answer(info, &sess->server,
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_IP),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS(type, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(type, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(type), RTP_RELAY_FLAGS_PEER));
}
#undef RTP_RELAY_PEER

static int rtp_relay_delete(struct rtp_relay_session *info,
		struct rtp_relay_sess *sess, struct rtp_relay_sess *main)
{
	int ret;
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	ret = sess->relay->binds.delete(info, &sess->server,
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_PEER));
	if (ret < 0)
		return -1;
	rtp_sess_reset_pending(sess);
	return 1;
}
#undef RTP_RELAY_FLAGS

static inline void rtp_relay_sess_merge(struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess)
{
	int f;

	if (ctx->main == sess)
		return;
	if (ctx->main) {
		for (f = 0; f < RTP_RELAY_FLAGS_SIZE; f++) {
			if (!sess->flags[RTP_RELAY_OFFER][f].s) {
				sess->flags[RTP_RELAY_OFFER][f] =
					ctx->main->flags[RTP_RELAY_OFFER][f];
				ctx->main->flags[RTP_RELAY_OFFER][f].s = NULL;
			}
			if (!sess->flags[RTP_RELAY_ANSWER][f].s) {
				sess->flags[RTP_RELAY_ANSWER][f] =
					ctx->main->flags[RTP_RELAY_ANSWER][f];
				ctx->main->flags[RTP_RELAY_ANSWER][f].s = NULL;
			}
		}
		rtp_relay_ctx_free_sess(ctx->main);
	}
	ctx->main = sess;
}

static inline int rtp_relay_dlg_mi_flags(rtp_relay_flags flags,
		mi_item_t *obj)
{
	if (flags[RTP_RELAY_FLAGS_SELF].s &&
		add_mi_string(obj, MI_SSTR("flags"),
			flags[RTP_RELAY_FLAGS_SELF].s,
			flags[RTP_RELAY_FLAGS_SELF].len) < 0)
		return -1;
	if (flags[RTP_RELAY_FLAGS_PEER].s &&
		add_mi_string(obj, MI_SSTR("peer"),
			flags[RTP_RELAY_FLAGS_PEER].s,
			flags[RTP_RELAY_FLAGS_PEER].len) < 0)
		return -1;
	if (flags[RTP_RELAY_FLAGS_IP].s &&
		add_mi_string(obj, MI_SSTR("IP"),
			flags[RTP_RELAY_FLAGS_IP].s,
			flags[RTP_RELAY_FLAGS_IP].len) < 0)
		return -1;
	if (flags[RTP_RELAY_FLAGS_TYPE].s &&
		add_mi_string(obj, MI_SSTR("type"),
			flags[RTP_RELAY_FLAGS_TYPE].s,
			flags[RTP_RELAY_FLAGS_TYPE].len) < 0)
		return -1;
	if (flags[RTP_RELAY_FLAGS_IFACE].s &&
		add_mi_string(obj, MI_SSTR("interface"),
			flags[RTP_RELAY_FLAGS_IFACE].s,
			flags[RTP_RELAY_FLAGS_IFACE].len) < 0)
		return -1;
	return 0;
}

static int mi_rtp_relay_ctx(struct rtp_relay_ctx *ctx,
		mi_item_t *item, int callid)
{
	int ret = -1;
	struct rtp_relay_sess *sess;
	mi_item_t *rtp_item, *caller_item, *callee_item;

	rtp_item = add_mi_object(item, MI_SSTR("rtp_relay"));
	if (!rtp_item) {
		LM_ERR("cold not create rtp_relay!\n");
		return ret;
	}
	RTP_RELAY_CTX_LOCK(ctx);
	sess = ctx->main;
	if (!sess)
		goto end;
	if (callid && add_mi_string(rtp_item, MI_SSTR("callid"),
			ctx->callid.s, ctx->callid.len) < 0)
		goto end;
	caller_item = add_mi_object(rtp_item, MI_SSTR("caller"));
	if (!caller_item)
		goto end;
	if (rtp_relay_dlg_mi_flags(sess->flags[RTP_RELAY_OFFER], caller_item) < 0)
		goto end;
	callee_item = add_mi_object(rtp_item, MI_SSTR("callee"));
	if (!callee_item)
		goto end;
	if (rtp_relay_dlg_mi_flags(sess->flags[RTP_RELAY_ANSWER], callee_item) < 0)
		goto end;
	if (add_mi_string(rtp_item, MI_SSTR("relay"),
			sess->relay->name.s, sess->relay->name.len) < 0)
		goto end;
	if (add_mi_string(rtp_item, MI_SSTR("server"),
			sess->server.node.s, sess->server.node.len) < 0)
		goto end;
	if (add_mi_number(rtp_item, MI_SSTR("set"), sess->server.set) < 0)
		goto end;
	if (sess->index != RTP_RELAY_ALL_BRANCHES &&
			add_mi_number(rtp_item, MI_SSTR("branch"), sess->index) < 0)
		goto end;
	ret = 0;
end:
	RTP_RELAY_CTX_UNLOCK(ctx);
	return ret;
}

static void rtp_relay_dlg_mi(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	mi_item_t *item = (mi_item_t *)(params->dlg_data);
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx || !item)
		return;

	mi_rtp_relay_ctx(ctx, item, 0);
}

static void rtp_relay_dlg_end(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	struct rtp_relay_session info;
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx->main || !rtp_sess_pending(ctx->main))
		return;

	memset(&info, 0, sizeof info);
	info.callid = &ctx->callid;
	info.from_tag = &dlg->legs[DLG_CALLER_LEG].tag;
	info.to_tag = &dlg->legs[callee_idx(dlg)].tag;
	info.branch = ctx->main->index;
	RTP_RELAY_CTX_LOCK(ctx);
	rtp_relay_delete(&info, ctx->main, NULL);
	RTP_RELAY_CTX_UNLOCK(ctx);
	lock_get(rtp_relay_contexts_lock);
	list_del(&ctx->list);
	lock_release(rtp_relay_contexts_lock);
}

void rtp_relay_indlg_tm_req(struct cell* t, int type, struct tmcb_params *p)
{
	enum rtp_relay_type rtype;
	struct rtp_relay_session info;
	struct dlg_cell *dlg = (struct dlg_cell *)(*p->param);
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx || !ctx->main) {
		LM_BUG("could not find a rtp relay context in %p!\n", ctx);
		return;
	}
	memset(&info, 0, sizeof info);
	info.branch = ctx->main->index;
	info.msg = p->req;

	info.body = get_body_part(info.msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!info.body)
		return;
	rtype = (rtp_relay_ctx_upstream()?RTP_RELAY_ANSWER:RTP_RELAY_OFFER);
	rtp_relay_offer(&info, ctx->main, NULL, rtype);
}

static void rtp_relay_indlg_tm_rpl(struct sip_msg *msg, struct dlg_cell *dlg, int up)
{
	str *body;
	enum rtp_relay_type rtype;
	struct rtp_relay_session info;
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx || !ctx->main) {
		LM_BUG("could not find a rtp relay context in %p!\n", ctx);
		return;
	}

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body)
		return;

	memset(&info, 0, sizeof info);
	info.branch = ctx->main->index;
	info.msg = msg;
	info.body = body;
	rtype = (up?RTP_RELAY_OFFER:RTP_RELAY_ANSWER);
	if (rtp_sess_late(ctx->main))
		rtp_relay_offer(&info, ctx->main, NULL, rtype);
	else
		rtp_relay_answer(&info, ctx->main, NULL, rtype);
}

static void rtp_relay_indlg_tm_rpl_up(struct cell* t, int type, struct tmcb_params *p)
{
	rtp_relay_indlg_tm_rpl(p->rpl, (struct dlg_cell *)(*p->param), 1);
}

static void rtp_relay_indlg_tm_rpl_down(struct cell* t, int type, struct tmcb_params *p)
{
	rtp_relay_indlg_tm_rpl(p->rpl, (struct dlg_cell *)(*p->param), 0);
}

static void rtp_relay_indlg(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	struct rtp_relay_session info;
	struct sip_msg *msg = params->msg;
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);
	str *body;
	int ret;

	if (!msg) {
		LM_DBG("no message available\n");
		return;
	}

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	RTP_RELAY_CTX_LOCK(ctx);
	ret = (ctx->main && rtp_sess_pending(ctx->main));
	if (ret && !body) {
		if (msg->REQ_METHOD != METHOD_INVITE) {
			if (msg->REQ_METHOD != METHOD_ACK)
				LM_DBG("method %d without SDP\n", msg->REQ_METHOD);
			else if (rtp_sess_late(ctx->main))
				LM_WARN("late negociation without SDP in ACK!\n");
			ret = 0;
		} else {
			rtp_sess_set_late(ctx->main);
		}
	}
	RTP_RELAY_CTX_UNLOCK(ctx);
	if (!ret)
		return;
	if (msg->REQ_METHOD == METHOD_ACK) {
		if (ctx->main || !rtp_sess_late(ctx->main))
			return;
		memset(&info, 0, sizeof info);
		info.msg = msg;
		info.body = body;
		info.branch = ctx->main->index;
		rtp_relay_answer(&info, ctx->main, NULL,
				(rtp_relay_ctx_upstream()?RTP_RELAY_ANSWER:RTP_RELAY_OFFER));
		return;
	}
	if (!body && msg->REQ_METHOD != METHOD_INVITE) {
		LM_DBG("%d without body! skipping update\n", msg->REQ_METHOD);
		return;
	}

	rtp_sess_reset_pending(ctx->main);
	if (rtp_relay_tmb.register_tmcb(msg, 0, TMCB_REQUEST_FWDED,
				rtp_relay_indlg_tm_req, dlg, 0)!=1)
		LM_ERR("failed to install TM request callback\n");
	if (rtp_relay_ctx_upstream()) {
		if (rtp_relay_tmb.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED,
				rtp_relay_indlg_tm_rpl_up, dlg, 0)!=1)
			LM_ERR("failed to install TM upstream reply callback\n");
	} else {
		if (rtp_relay_tmb.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED,
				rtp_relay_indlg_tm_rpl_down, dlg, 0)!=1)
			LM_ERR("failed to install TM downstream reply callback\n");
	}
}

static int rtp_relay_dlg_callbacks(struct dlg_cell *dlg, struct rtp_relay_ctx *ctx)
{
	if (shm_str_sync(&ctx->callid, &dlg->callid) < 0)
		LM_ERR("could not store callid in dialog\n");

	if (rtp_relay_dlg.register_dlgcb(dlg, DLGCB_MI_CONTEXT,
			rtp_relay_dlg_mi, NULL, NULL) < 0)
		LM_ERR("could not register MI dlg print!\n");
	RTP_RELAY_PUT_DLG_CTX(dlg, ctx);
	if (rtp_relay_dlg.register_dlgcb(dlg,
			DLGCB_TERMINATED|DLGCB_EXPIRED,
			rtp_relay_dlg_end, NULL, NULL) < 0) {
		LM_ERR("could not register MI dlg end!\n");
		goto error;
	}

	if (rtp_relay_dlg.register_dlgcb(dlg,
			DLGCB_REQ_WITHIN,
			rtp_relay_indlg, NULL, NULL) != 0) {
		LM_ERR("could not register request within dlg callback!\n");
		goto error;
	}
	if (rtp_relay_dlg.register_dlgcb(dlg, DLGCB_WRITE_VP,
			rtp_relay_store_callback, NULL, NULL))
		LM_WARN("cannot register callback for rtp relay serialization! "
				"Will not be able to engage rtp relay in case of a restart!\n");
	lock_get(rtp_relay_contexts_lock);
	list_add(&ctx->list, rtp_relay_contexts);
	lock_release(rtp_relay_contexts_lock);

	return 0;

error:
	RTP_RELAY_PUT_DLG_CTX(dlg, NULL);
	return -1;
}

static int rtp_relay_sess_success(struct rtp_relay_ctx *ctx,
	struct rtp_relay_sess *sess, struct cell *t)
{
	struct dlg_cell *dlg;

	rtp_sess_set_success(sess);
	if (list_is_singular(&ctx->sessions))
		rtp_relay_sess_merge(ctx, sess);
	if (!rtp_relay_ctx_established(ctx)) {
		dlg = rtp_relay_dlg.get_dlg();
		if (!dlg) {
			LM_ERR("could not find dialog!\n");
			return -1;
		}
		/* reset old pointers */
		RTP_RELAY_PUT_TM_CTX(t, NULL);
		RTP_RELAY_PUT_CTX(NULL);

		if (rtp_relay_dlg_callbacks(dlg, ctx) < 0) {
			RTP_RELAY_PUT_TM_CTX(t, ctx);
			return -1;
		}
		rtp_relay_ctx_set_established(ctx);
	}
	return 0;
}

static void rtp_relay_sess_failed(struct rtp_relay_ctx *ctx,
		struct rtp_relay_sess *sess)
{
	struct rtp_relay_sess *last;

	rtp_sess_reset_pending(sess);
	list_del(&sess->list);
	if (list_is_singular(&ctx->sessions)) {
		last = list_last_entry(&ctx->sessions, struct rtp_relay_sess, list);
		if (rtp_sess_success(last))
			rtp_relay_sess_merge(ctx, last);
	}
}

static int handle_rtp_relay_ctx_leg_reply(struct rtp_relay_ctx *ctx, struct sip_msg *msg,
		struct cell *t, struct rtp_relay_sess *sess)
{
	int ret;
	struct rtp_relay_session info;
	memset(&info, 0, sizeof info);
	info.msg = msg;
	if (msg->REPLY_STATUS >= 300) {
		if (!rtp_sess_late(sess)) {
			rtp_relay_delete(&info, sess, ctx->main);
		} else {
			/* nothing to do */
			LM_DBG("negative reply on late branch\n");
		}
		rtp_relay_sess_failed(ctx, sess);
		return 1;
	}
	info.body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!info.body) {
		if (msg->REPLY_STATUS < 200) {
			LM_DBG("provisioning reply %d without body\n", msg->REPLY_STATUS);
			return 1;
		} else if (rtp_sess_late(sess)) {
			LM_WARN("no SDP in final reply of late negotiation\n");
			return -1;
		} else {
			LM_WARN("final reply without SDP - cannot complete negotiation!\n");
			return -1;
		}
	}
	info.branch = sess->index;
	if (rtp_sess_late(sess))
		ret = rtp_relay_offer(&info, sess, ctx->main, RTP_RELAY_ANSWER);
	else
		ret = rtp_relay_answer(&info, sess, ctx->main, RTP_RELAY_ANSWER);
	if (ret > 0 && msg->REPLY_STATUS >= 200)
		rtp_relay_sess_success(ctx, sess, t);
	return ret;
}

static void rtp_relay_ctx_initial_cb(struct cell* t, int type, struct tmcb_params *p)
{
	struct rtp_relay_session info;
	struct rtp_relay_sess *sess;
	struct rtp_relay_ctx *ctx = *(struct rtp_relay_ctx **)(p->param);

	RTP_RELAY_CTX_LOCK(ctx);
	switch (type) {
		case TMCB_RESPONSE_FWDED:
			/* first check if there's anything setup on this branch */
			sess = rtp_relay_get_sess(ctx, rtp_relay_ctx_branch());
			if (sess) {
				if (!rtp_sess_pending(sess)) {
					LM_DBG("no pending session on branch %d\n",
							rtp_relay_ctx_branch());
					sess = ctx->main;
				}
			} else {
				LM_DBG("no session on branch %d\n", rtp_relay_ctx_branch());
				sess = ctx->main;
			}
			if (!sess) {
				LM_DBG("no session to respond to\n");
				goto end;
			}
			if (rtp_sess_disabled(sess) || (!rtp_sess_late(sess) && !rtp_sess_pending(sess))) {
				LM_DBG("disabled and/or pending session %d/%d\n",
						rtp_sess_disabled(sess), rtp_sess_pending(sess));
				goto end;
			}
			handle_rtp_relay_ctx_leg_reply(ctx, p->rpl, t, sess);
			break;
		case TMCB_REQUEST_FWDED:
			if (ctx->main && (rtp_sess_pending(ctx->main) || rtp_sess_late(ctx->main))) {
				LM_DBG("RTP relay already engaged in main branch\n");
				goto end;
			}
			sess = rtp_relay_get_sess(ctx, rtp_relay_ctx_branch());
			if (!sess) /* not engagned on this branch */ {
				LM_DBG("RTP relay not engaged on branch %d!\n", rtp_relay_ctx_branch());
				goto end;
			}
			if (rtp_sess_disabled(sess)) {
				LM_DBG("rtp relay on branch %d is disabled\n", rtp_relay_ctx_branch());
				goto end;
			}
			if (rtp_sess_late(sess)) {
				LM_DBG("rtp relay on branch %d is late\n", rtp_relay_ctx_branch());
				goto end;
			}
			memset(&info, 0, sizeof info);
			info.body = get_body_part(p->req, TYPE_APPLICATION, SUBTYPE_SDP);
			info.msg = p->req;
			info.branch = sess->index;
			if (ctx->main && sess != ctx->main) {
				/* inherit props from ctx->main */
				if (sess->server.set == -1)
					sess->server.set = ctx->main->server.set;
				if (!sess->relay)
					sess->relay = ctx->main->relay;
			}
			rtp_relay_offer(&info, sess, ctx->main, RTP_RELAY_OFFER);
			break;
		default:
			LM_BUG("unhandled callback type %d\n", type);
			break;
	}
end:
	RTP_RELAY_CTX_UNLOCK(ctx);
}

int rtp_relay_ctx_engage(struct sip_msg *msg,
		struct rtp_relay_ctx *ctx, struct rtp_relay *relay, int *set)
{
	int index;
	struct rtp_relay_sess *sess;
	struct rtp_relay_session info;

	if (!rtp_relay_ctx_engaged(ctx)) {

		/* handles the replies to the original INVITE */
		if (rtp_relay_tmb.register_tmcb(msg, 0,
				TMCB_RESPONSE_FWDED|TMCB_REQUEST_FWDED,
				rtp_relay_ctx_initial_cb, ctx, 0)!=1) {
			LM_ERR("failed to install TM reply callback\n");
			return -1;
		}
		rtp_relay_ctx_set_engaged(ctx);
	}

	index = (route_type == BRANCH_ROUTE)?
		rtp_relay_ctx_branch():RTP_RELAY_ALL_BRANCHES;
	sess = rtp_relay_get_sess(ctx, index);
	if (!sess) {
		sess = rtp_relay_new_sess(ctx, index);
		if (!sess) {
			LM_ERR("could not create new RTP relay session\n");
			return -1;
		}
	}
	if (set)
		sess->server.set = *set;
	sess->relay = relay;
	if (rtp_sess_disabled(sess))
		return -3; /* nothing to do */
	memset(&info, 0, sizeof info);
	info.body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!info.body) {
		rtp_sess_set_late(sess);
		return 1;
	}
	info.msg = msg;
	info.branch = sess->index;
	return rtp_relay_offer(&info, sess, ctx->main, RTP_RELAY_OFFER);
}

mi_response_t *mi_rtp_relay_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *arr;
	struct list_head *it;
	struct rtp_relay_ctx *ctx;
	struct rtp_relay *relay = NULL;
	str *node = NULL, tmp;

	switch(try_get_mi_string_param(params, "engine", &tmp.s, &tmp.len)) {
		case -1:
			break;
		case -2:
			return init_mi_param_error();
		default:
			relay = rtp_relay_get(&tmp);
			if (!relay)
				return init_mi_error(404, MI_SSTR("unknown RTP  Relay engine"));
			/* if we have an engine, we might also have a node */
			switch(try_get_mi_string_param(params, "node", &tmp.s, &tmp.len)) {
				case -1:
					break;
				case -2:
					return init_mi_param_error();
				default:
					node = &tmp;
			}
	}

	resp = init_mi_result_array(&arr);
	if (!resp)
		return 0;

	lock_get(rtp_relay_contexts_lock);
	list_for_each(it, rtp_relay_contexts) {
		ctx = list_entry(it, struct rtp_relay_ctx, list);
		if (!ctx->main)
			continue;
		if (relay && ctx->main->relay != relay)
			continue;
		if (node && str_strcmp(node, &ctx->main->server.node))
			continue;
		if (mi_rtp_relay_ctx(ctx, arr, 1) < 0)
			goto error;
	}

	lock_release(rtp_relay_contexts_lock);

	return resp;

error:
	lock_release(rtp_relay_contexts_lock);
	if (resp)
		free_mi_response(resp);
	return 0;
}
