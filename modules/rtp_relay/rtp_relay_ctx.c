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
#include "rtp_relay_load.h"
#include "../../mem/shm_mem.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../../bin_interface.h"
#include "../../lib/cJSON.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../b2b_logic/b2b_load.h"
#include "../../parser/parse_to.h"

static b2bl_api_t rtp_relay_b2b;
static struct tm_binds rtp_relay_tmb;
static struct dlg_binds rtp_relay_dlg;
static int rtp_relay_tm_ctx_idx = -1;
static int rtp_relay_dlg_ctx_idx = -1;
static int rtp_relay_b2b_ctx_idx = -1;
static int rtp_relay_ctx_idx = -1;

static rw_lock_t *rtp_relay_contexts_lock;
static struct list_head *rtp_relay_contexts;

#define RTP_RELAY_GET_MSG_CTX() (current_processing_ctx?(struct rtp_relay_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, rtp_relay_ctx_idx):NULL)
#define RTP_RELAY_PUT_CTX(_p) context_put_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, rtp_relay_ctx_idx, (_p))
#define RTP_RELAY_GET_TM_CTX(_t) \
	(current_processing_ctx?rtp_relay_tmb.t_ctx_get_ptr(_t, rtp_relay_tm_ctx_idx):NULL)
#define RTP_RELAY_PUT_TM_CTX(_t, _p) \
	rtp_relay_tmb.t_ctx_put_ptr(_t, rtp_relay_tm_ctx_idx, _p)

#define RTP_RELAY_GET_DLG_CTX(_d) (rtp_relay_dlg.dlg_ctx_get_ptr(_d, rtp_relay_dlg_ctx_idx))
#define RTP_RELAY_PUT_DLG_CTX(_d, _p) \
	rtp_relay_dlg.dlg_ctx_put_ptr(_d, rtp_relay_dlg_ctx_idx, _p)

#define RTP_RELAY_GET_B2B_CTX(_k) (rtp_relay_b2b.ctx_get_ptr(_k, rtp_relay_b2b_ctx_idx))
#define RTP_RELAY_PUT_B2B_CTX(_k, _p) \
	rtp_relay_b2b.ctx_put_ptr(_k, rtp_relay_b2b_ctx_idx, _p)

#define RTP_RELAY_PEER(_l) \
	(_l == RTP_RELAY_CALLER?RTP_RELAY_CALLEE:RTP_RELAY_CALLER)


static str rtp_relay_dlg_name = str_init("_rtp_relay_ctx_");
static int rtp_relay_dlg_callbacks(struct dlg_cell *dlg, struct rtp_relay_ctx *ctx, str *to_tag);
static void rtp_relay_dlg_req_callbacks(struct dlg_cell *dlg, struct rtp_relay_ctx *ctx);
static void rtp_relay_ctx_release(void *param);

/* pvar handing */
static struct {
	str name;
	enum rtp_relay_var_flags flag;
} rtp_relay_var_flags_str[]= {
	{ str_init("flags"), RTP_RELAY_FLAGS_SELF },
	{ str_init("peer"), RTP_RELAY_FLAGS_PEER },
	{ str_init("ip"), RTP_RELAY_FLAGS_IP },
	{ str_init("type"), RTP_RELAY_FLAGS_TYPE },
	{ str_init("iface"), RTP_RELAY_FLAGS_IFACE },
	{ str_init("body"), RTP_RELAY_FLAGS_BODY },
	{ str_init("delete"), RTP_RELAY_FLAGS_DELETE },
	{ str_init("disabled"), RTP_RELAY_FLAGS_DISABLED },
};

static int rtp_relay_offer(struct rtp_relay_session *info,
		struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess,
		int leg, str *body);
static int rtp_relay_answer(struct rtp_relay_session *info,
		struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess,
		int leg, str *body);
static int rtp_relay_delete(struct rtp_relay_session *info,
		struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess, int leg);
static int handle_rtp_relay_ctx_leg_reply(struct rtp_relay_ctx *ctx,
		struct sip_msg *msg, struct rtp_relay_sess *sess, int type);
static void rtp_relay_fill_dlg(struct rtp_relay_ctx *ctx, str *dlg_callid,
		unsigned id, unsigned entry, str *callid, str *from_tag, str *to_tag);
static void rtp_relay_delete_ctx(struct rtp_relay_ctx *ctx,
		struct rtp_relay_sess *sess, int leg);


str *rtp_relay_flags_get_str(enum rtp_relay_var_flags flags)
{
	static str unknown = str_init("unknown");
	int s = sizeof(rtp_relay_var_flags_str) / sizeof (rtp_relay_var_flags_str[0]);
	if (flags >= s)
		return &unknown;
	for (--s; s >=0; s--)
		if (rtp_relay_var_flags_str[s].flag == flags)
			return &rtp_relay_var_flags_str[s].name;
	return &unknown;
}

enum rtp_relay_var_flags rtp_relay_flags_get(const str *name)
{
	int s = sizeof(rtp_relay_var_flags_str) / sizeof (rtp_relay_var_flags_str[0]);
	for (--s; s >= 0; s--)
		if (str_strcasecmp(name, &rtp_relay_var_flags_str[s].name) == 0)
			return rtp_relay_var_flags_str[s].flag;
	return RTP_RELAY_FLAGS_UNKNOWN;
}

static struct rtp_relay_ctx *rtp_relay_get_dlg_ctx(void)
{
	struct dlg_cell *dlg;

	if (rtp_relay_dlg_ctx_idx == -1 || !current_processing_ctx)
		return NULL;

	dlg = rtp_relay_dlg.get_dlg();

	return dlg?RTP_RELAY_GET_DLG_CTX(dlg):NULL;
}

static struct rtp_relay_ctx *rtp_relay_get_b2b_ctx(void)
{
	str *key;

	if (rtp_relay_b2b_ctx_idx == -1 || !current_processing_ctx)
		return NULL;

	key = rtp_relay_b2b.get_key();

	return key?RTP_RELAY_GET_B2B_CTX(key):NULL;
}

static struct rtp_relay_ctx *rtp_relay_new_ctx(void)
{
	struct rtp_relay_ctx *ctx = shm_malloc(sizeof *ctx);
	if (!ctx) {
		LM_ERR("oom for creating RTP relay context!\n");
		return NULL;
	}
	memset(ctx, 0, sizeof *ctx);

	ctx->ref = 1;
	lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->sessions);
	INIT_LIST_HEAD(&ctx->list);
	INIT_LIST_HEAD(&ctx->copy_contexts);
	INIT_LIST_HEAD(&ctx->legs);
	LM_RTP_DBG("new ctx=%p\n", ctx);
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
			RTP_RELAY_CTX_REF(ctx);
			RTP_RELAY_PUT_TM_CTX(t, ctx);
			RTP_RELAY_PUT_CTX(NULL);
		}
		return ctx;
	}
	ctx = rtp_relay_new_ctx();
	if (!ctx)
		return NULL;

	if (t) {
		RTP_RELAY_CTX_REF(ctx);
		RTP_RELAY_PUT_TM_CTX(t, ctx);
	} else {
		RTP_RELAY_PUT_CTX(ctx);
	}
	return ctx;
}

rtp_ctx rtp_relay_get_context(void)
{
	return rtp_relay_try_get_ctx();
}

rtp_ctx rtp_relay_get_context_dlg(struct dlg_cell *dlg)
{
	return RTP_RELAY_GET_DLG_CTX(dlg);
}

static void rtp_relay_ctx_free_leg(struct rtp_relay_leg *leg)
{
	int f;

	for (f = 0; f < RTP_RELAY_FLAGS_SIZE; f++) {
		if (!leg->flags[f].s)
			continue;
		shm_free(leg->flags[f].s);
		leg->flags[f].s = NULL;
		leg->flags[f].len = 0;
	}
	if (leg->tag.len)
		shm_free(leg->tag.s);
	list_del(&leg->list);
	shm_free(leg);
}
static void rtp_relay_ctx_release_leg(struct rtp_relay_leg *leg)
{
	if (!leg || --leg->ref != 0) /* still linked in a different session */
		return;
	rtp_relay_ctx_free_leg(leg);
}

static void rtp_relay_ctx_free_sess(struct rtp_relay_sess *s)
{
	rtp_relay_ctx_release_leg(s->legs[RTP_RELAY_CALLER]);
	rtp_relay_ctx_release_leg(s->legs[RTP_RELAY_CALLEE]);
	if (s->server.node.s)
		shm_free(s->server.node.s);
	list_del(&s->list);
	shm_free(s);
}

static void rtp_relay_ctx_free(struct rtp_relay_ctx *ctx)
{
	struct list_head *it, *safe;

	LM_DBG("releasing ctx=%p\n", ctx);
	list_for_each_safe(it, safe, &ctx->legs)
		rtp_relay_ctx_release_leg(list_entry(it, struct rtp_relay_leg, list));

	if (ctx->callid.s)
		shm_free(ctx->callid.s);
	if (ctx->from_tag.s)
		shm_free(ctx->from_tag.s);
	if (ctx->to_tag.s)
		shm_free(ctx->to_tag.s);
	if (ctx->dlg_callid.s)
		shm_free(ctx->dlg_callid.s);
	if (ctx->flags.s)
		shm_free(ctx->flags.s);
	if (ctx->delete.s)
		shm_free(ctx->delete.s);

	list_for_each_safe(it, safe, &ctx->sessions)
		rtp_relay_ctx_free_sess(list_entry(it, struct rtp_relay_sess, list));

	lock_start_write(rtp_relay_contexts_lock);
	if (list_is_valid(&ctx->list))
		list_del(&ctx->list);
	lock_stop_write(rtp_relay_contexts_lock);

	lock_destroy(&ctx->lock);
	shm_free(ctx);
}

static void rtp_relay_ctx_release(void *param)
{
	struct rtp_relay_ctx *ctx = (struct rtp_relay_ctx *)param;

	if (!ctx)
		return;
	RTP_RELAY_CTX_LOCK(ctx);
	if (ctx->ref <= 0) {
		LM_BUG("invalid ref=%d for ctx=%p\n", ctx->ref, ctx);
		RTP_RELAY_CTX_UNLOCK(ctx);
		return;
	} else if (--ctx->ref > 0) {
		LM_DBG("pending ref=%d for ctx=%p\n", ctx->ref, ctx);
		RTP_RELAY_CTX_UNLOCK(ctx);
		return;
	}
	RTP_RELAY_CTX_UNLOCK(ctx);

	rtp_relay_ctx_free(ctx);
}


struct rtp_relay_ctx *rtp_relay_try_get_ctx(void)
{
	struct cell* t;
	struct rtp_relay_ctx* ctx = NULL;

	if ((ctx = rtp_relay_get_dlg_ctx()) != NULL)
		return ctx;

	if ((ctx = rtp_relay_get_b2b_ctx()) != NULL)
		return ctx;

	if ((ctx = RTP_RELAY_GET_MSG_CTX()) != NULL)
		return ctx;

	/* local one not found - search in transaction */
	t = rtp_relay_tmb.t_gett();
	t = t==T_UNDEFINED ? NULL : t;

	return (t ? RTP_RELAY_GET_TM_CTX(t) : NULL);
}

static void rtp_relay_b2b_end(void *param)
{
	struct rtp_relay_ctx *ctx = param;
	if (!ctx)
		return;
	RTP_RELAY_CTX_LOCK(ctx);
	if (rtp_relay_ctx_established(ctx)) {
		rtp_relay_delete_ctx(ctx, ctx->established, RTP_RELAY_CALLER);
		RTP_RELAY_CTX_UNLOCK(ctx);
		lock_start_write(rtp_relay_contexts_lock);
		list_del(&ctx->list);
		lock_stop_write(rtp_relay_contexts_lock);
	} else {
		RTP_RELAY_CTX_UNLOCK(ctx);
	}
	rtp_relay_ctx_release(ctx);
}

static int rtp_relay_sess_b2b_success(struct rtp_relay_ctx *ctx,
	struct rtp_relay_sess *sess)
{
	rtp_sess_set_success(sess);
	ctx->established = sess;
	if (!rtp_relay_ctx_established(ctx)) {
		lock_start_write(rtp_relay_contexts_lock);
		list_add(&ctx->list, rtp_relay_contexts);
		lock_stop_write(rtp_relay_contexts_lock);
		rtp_relay_ctx_set_established(ctx);
	}
	return 0;
}

static void rtp_relay_b2b_local_reply(struct cell* t, int type,
		struct tmcb_params *ps)
{
	/* this callback is run in the context of a request - all we have is the
	 * body that may be present in the reply - and we are only interested
	 * in replies that contain a body
	 */
	int ltype, ret;
	struct sip_msg *msg;
	struct rtp_relay_leg *leg;
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_sess *sess;
	struct rtp_relay_session info;
	struct lump_rpl *rpl_lump;
	str new_body;
	str *body = ps->extra1;
	if (!body || !body->len)
		return;
	msg = ps->req;
	rpl_lump = get_lump_rpl(msg, LUMP_RPL_BODY);
	if (!rpl_lump)
		return;
	ctx = (*ps->param);
	if (!rtp_relay_ctx_b2b(ctx))
		return;
	if (parse_headers(msg, HDR_FROM_F, 0) < 0 || !msg->from ||
			parse_from_header(msg) < 0 || !get_from(msg)->tag_value.len) {
		LM_ERR("bad request or missing From header\n");
		return;
	}
	leg = rtp_relay_get_leg(ctx, &get_from(msg)->tag_value,
			RTP_RELAY_ALL_BRANCHES);
	if (!leg) {
		LM_DBG("leg not involved in the contxext\n");
		goto release;
	}
	sess = rtp_relay_get_sess(ctx, ctx->last_branch);
	if (!sess) {
		LM_DBG("leg not involved in the session\n");
		goto release;
	}
	if (sess->legs[RTP_RELAY_CALLER] == leg) {
		ltype = RTP_RELAY_CALLEE;
	} else if (sess->legs[RTP_RELAY_CALLEE] == leg) {
		ltype = RTP_RELAY_CALLER;
	} else {
		LM_DBG("leg not part of the session\n");
		goto release;
	}
	memset(&info, 0, sizeof info);
	info.body = body;
	LM_RTP_DBG("sess=%p late=%d ongoing=%d index=%d\n",
			sess, rtp_sess_late(sess), rtp_sess_ongoing(sess), leg->index);

	info.branch = sess->index;
	if (rtp_sess_late(sess) || !rtp_sess_ongoing(sess))
		ret = rtp_relay_offer(&info, ctx, sess, ltype, &new_body);
	else
		ret = rtp_relay_answer(&info, ctx, sess, ltype, &new_body);
	if (ret > 0) {
		/* all good - we need to replace the body lump now */
		replace_lump_rpl(rpl_lump, new_body.s, new_body.len,
				LUMP_RPL_NODUP);
		if (!rtp_sess_success(sess) && ps->code >= 200)
			rtp_relay_sess_b2b_success(ctx, sess);
	} else {
		LM_DBG("could not engage rtp relay on reply!\n");
	}
release:
	RTP_RELAY_CTX_UNLOCK(ctx);
}

static void rtp_relay_reqin(struct cell* t, int type, struct tmcb_params *ps)
{
	struct rtp_relay_ctx *ctx = rtp_relay_try_get_ctx();

	if (!ctx)
		return; /* nothing to move */

	/* register for all locally generated replies */
	RTP_RELAY_CTX_REF(ctx);
	if (rtp_relay_tmb.register_tmcb(ps->req, t, TMCB_LOCAL_RESPONSE,
			rtp_relay_b2b_local_reply, ctx,
			rtp_relay_ctx_release)!=1) {
		LM_ERR("could not register locally reply callback\n");
		RTP_RELAY_CTX_UNREF(ctx);
	}

	if (!t || t == T_UNDEFINED) {
		LM_DBG("no transaction - can't move the context - freeing!\n");
		rtp_relay_ctx_release(ctx);
		return;
	}

	RTP_RELAY_CTX_REF(ctx);
	RTP_RELAY_PUT_TM_CTX(t, ctx);
	RTP_RELAY_PUT_CTX(NULL);
}

/* indicates if the new request branch id has been computed */
static int rtp_relay_b2b_branch_computed = 0;

int rtp_relay_get_last_branch(struct rtp_relay_ctx *ctx, struct sip_msg *msg)
{
	if (rtp_relay_b2b_branch_computed)
		goto end;

	if (parse_headers(msg, HDR_TO_F, 0) < 0 || !msg->to || parse_to_header(msg) < 0) {
		LM_ERR("could not parse To header\n");
		goto end;
	}
	rtp_relay_b2b_branch_computed = 1;
	if (get_to(msg)->tag_value.len)
		goto end; /* nothing to do, already last branch available */
	ctx->last_branch++;
end:
	return ctx->last_branch;
}

static struct rtp_relay_leg *rtp_relay_get_peer_leg_ctx(struct rtp_relay_ctx *ctx, struct sip_msg *msg)
{
	str *tag = NULL;
	struct dlg_cell *dlg;
	struct rtp_relay_leg *leg;
	struct b2b_entity_info_t info;

	if (rtp_relay_dlg_ctx_idx != -1 && (dlg = rtp_relay_dlg.get_dlg()) != NULL) {
		if (rtp_relay_dlg.get_direction() == DLG_DIR_UPSTREAM) {
			tag = &dlg->legs[DLG_CALLER_LEG].tag;
		} else {
			tag = &dlg->legs[callee_idx(dlg)].tag;
		}
		return rtp_relay_get_leg(ctx, tag, RTP_RELAY_ALL_BRANCHES);
	} else if (rtp_relay_b2b_ctx_idx != -1) {
		if (rtp_relay_b2b.get_entity_info(NULL, msg, -2, &info) < 0)
			return NULL;
		if (!info.fromtag.len) {
			rtp_relay_b2b.release_entity_info(&info);
			return NULL;
		}
		leg = rtp_relay_get_leg(ctx, &info.fromtag, RTP_RELAY_ALL_BRANCHES);
		rtp_relay_b2b.release_entity_info(&info);
		return leg;
	}
	return NULL;
}

static struct rtp_relay_sess *rtp_relay_sess_empty(void)
{
	struct rtp_relay_sess *sess;
	sess = shm_malloc(sizeof *sess);
	if (!sess) {
		LM_ERR("oom for new sess!\n");
		return NULL;
	}
	memset(sess, 0, sizeof *sess);
	sess->server.set = -1;
	sess->index = RTP_RELAY_ALL_BRANCHES;
	INIT_LIST_HEAD(&sess->list);
	return sess;
}

static inline void rtp_relay_push_sess_leg(struct rtp_relay_sess *sess,
		struct rtp_relay_leg *leg, int type)
{
	if (!leg)
		return;
	if (sess->legs[type] == leg)
		return;
	if (sess->legs[type])
		rtp_relay_ctx_release_leg(sess->legs[type]);
	sess->legs[type] = leg;
	leg->peer = sess->legs[RTP_RELAY_PEER(type)];
	if (leg->peer)
		sess->legs[RTP_RELAY_PEER(type)]->peer = leg;
	leg->ref++;
}

static inline void rtp_relay_fill_sess_leg(struct rtp_relay_ctx *ctx,
		struct rtp_relay_sess *sess, int type, str *tag, int index)
{
	struct rtp_relay_leg *leg = rtp_relay_get_leg(ctx, tag, index);
	if (!leg && index != RTP_RELAY_ALL_BRANCHES)
		leg = rtp_relay_get_leg(ctx, tag, RTP_RELAY_ALL_BRANCHES);
	rtp_relay_push_sess_leg(sess, leg, type);
}

static struct rtp_relay_sess *rtp_relay_new_sess(struct rtp_relay_ctx *ctx,
		struct rtp_relay *relay, int *set, str *tag, int index)
{
	struct rtp_relay_sess *sess = rtp_relay_sess_empty();
	if (!sess)
		return NULL;
	LM_RTP_DBG("new sess=%p index=%d\n", sess, index);
	sess->index = index;
	sess->relay = relay;
	if (set)
		sess->server.set = *set;
	rtp_relay_fill_sess_leg(ctx, sess, RTP_RELAY_CALLER, tag, index);
	rtp_relay_fill_sess_leg(ctx, sess, RTP_RELAY_CALLEE, NULL, index);
	list_add(&sess->list, &ctx->sessions);
	return sess;
}


static struct rtp_relay_sess *rtp_relay_dup_sess(struct rtp_relay_ctx *ctx,
		struct rtp_relay_sess *old)
{
	int ltype;
	struct rtp_relay_sess *sess = rtp_relay_sess_empty();

	if (!sess)
		return NULL;
	memcpy(sess, old, sizeof *sess);
	INIT_LIST_HEAD(&sess->list);

	LM_RTP_DBG("dup sess=%p old=%p\n", sess, old);
	for (ltype = RTP_RELAY_CALLER; ltype <= RTP_RELAY_CALLEE; ltype++) {
		if (!old->legs[ltype])
			continue;
		sess->legs[ltype] = old->legs[ltype];
		if (old->legs[ltype])
			old->legs[ltype]->ref++;
	}

	return sess;
}

struct rtp_relay_b2b_reply {
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_sess *sess;
	int type;
};

static void rtp_relay_b2b_reply_free(void *param)
{
	rtp_relay_ctx_release(((struct rtp_relay_b2b_reply *)param)->ctx);
	shm_free(param);
}

static void rtp_relay_b2b_tm_reply(struct cell* t, int type, struct tmcb_params *p)
{
	struct rtp_relay_b2b_reply *rpl = (*p->param);
	handle_rtp_relay_ctx_leg_reply(rpl->ctx, p->rpl, rpl->sess, rpl->type);
}

static void rtp_relay_b2b_tm_req(struct cell* t, int type, struct tmcb_params *p)
{
	struct rtp_relay_session info;
	int last_branch, ltype = RTP_RELAY_CALLER;
	struct rtp_relay_sess *sess = NULL;
	struct rtp_relay_leg *leg, *peer_leg;
	struct rtp_relay_ctx *ctx = (*p->param);
	struct rtp_relay_b2b_reply *param;
	str dummy_from_tag = str_init("from_tag");
	str dummy_to_tag = str_init("to_tag");
	str *body;

	if (!ctx)
		return;

	if (p->req->REQ_METHOD != METHOD_INVITE && p->req->REQ_METHOD != METHOD_UPDATE &&
			p->req->REQ_METHOD != METHOD_ACK) {
		LM_DBG("not interested in method %d\n", p->req->REQ_METHOD);
		return;
	}

	body = get_body_part(p->req, TYPE_APPLICATION, SUBTYPE_SDP);
	if (p->req->REQ_METHOD == METHOD_ACK && (!body || body->len == 0))
		return;

	/* no more pending branches */
	last_branch = rtp_relay_get_last_branch(ctx, p->req);
	rtp_relay_b2b_branch_computed = 0; /* this was the last chance to compute the branch */

	if (parse_headers(p->req, HDR_TO_F, 0) < 0 || !p->req->to || parse_to_header(p->req) < 0) {
		LM_ERR("could not parse To header\n");
		return;
	}
	peer_leg = rtp_relay_get_peer_leg_ctx(ctx, p->req);
	if (!peer_leg) {
		LM_ERR("could not find a pending peer leg!\n");
		return;
	}
	/* if there is a tag, we should find the leg based on the tag */
	if (get_to(p->req)->tag_value.len) {
		leg = rtp_relay_get_leg(ctx, &get_to(p->req)->tag_value,
				RTP_RELAY_ALL_BRANCHES);
		if (!leg) {
			LM_DBG("no leg involved\n");
			return;
		}
	} else {
		leg = rtp_relay_get_leg(ctx, NULL, last_branch);
	}
	if (!leg) {
		if (!peer_leg->peer) {
			leg = rtp_relay_new_leg(ctx, NULL, last_branch);
			if (!leg) {
				LM_ERR("could not create a new leg\n");
				return;
				}
		} else {
			leg = peer_leg->peer;
		}
	}
	if (ctx->established) {
		sess = ctx->established;
		if (sess->legs[RTP_RELAY_CALLER] == peer_leg && sess->legs[RTP_RELAY_CALLEE] == leg) {
			ltype = RTP_RELAY_CALLER;
		} else if (sess->legs[RTP_RELAY_CALLEE] == peer_leg && sess->legs[RTP_RELAY_CALLER] == leg) {
			ltype = RTP_RELAY_CALLEE;
		} else {
			sess = NULL;
		}
	}
	if (!sess) {
		/* check if there is an existing session with the new leg,
		 * otherwise create a new one */
		sess = rtp_relay_get_sess(ctx, last_branch);
		if (!sess) {
			LM_ERR("unknown session\n");
			return;
		}
		if (sess->legs[RTP_RELAY_CALLEE] == peer_leg) {
			ltype = RTP_RELAY_CALLEE;
			rtp_relay_push_sess_leg(sess, leg, RTP_RELAY_CALLER);
			rtp_relay_push_sess_leg(sess, peer_leg, RTP_RELAY_CALLEE);
		} else {
			ltype = RTP_RELAY_CALLER;
			rtp_relay_push_sess_leg(sess, peer_leg, RTP_RELAY_CALLER);
			rtp_relay_push_sess_leg(sess, leg, RTP_RELAY_CALLEE);
		}
	}

	/* force the to&from tags */
	if (!ctx->from_tag.len) {
		/* to-tag is always the B2B key */
		rtp_relay_fill_dlg(ctx, rtp_relay_b2b.get_key(), 0, 0, NULL, &dummy_from_tag, &dummy_to_tag);
	}

	/* register our own callback to be able to answer the session */
	param = shm_malloc(sizeof *param);
	if (!param) {
		LM_ERR("no more shm memory!\n");
		return;
	}
	RTP_RELAY_CTX_REF(ctx);
	param->ctx = ctx;
	param->sess = sess;
	param->type = RTP_RELAY_PEER(ltype);
	if (rtp_relay_tmb.register_tmcb(p->req, t, TMCB_LOCAL_RESPONSE_OUT|TMCB_LOCAL_COMPLETED,
				rtp_relay_b2b_tm_reply, param, rtp_relay_b2b_reply_free)!=1) {
		RTP_RELAY_CTX_UNREF(ctx);
		LM_ERR("cannot register new callback!\n");
		return;
	}

	memset(&info, 0, sizeof info);
	info.msg = p->req;
	info.body = body;
	if (!info.body || !info.body->len) {
		rtp_sess_set_late(sess);
		return;
	}
	info.branch = sess->index;

	LM_RTP_DBG("sess=%p late=%d ongoing=%d index=%d\n",
			sess, rtp_sess_late(sess), rtp_sess_ongoing(sess), sess->index);
	if (!rtp_sess_late(sess) && !rtp_sess_ongoing(sess))
		rtp_relay_offer(&info, ctx, sess, ltype, NULL);
	else
		rtp_relay_answer(&info, ctx, sess, ltype, NULL);
}

static void rtp_relay_b2b_new_local(struct cell* t, int type, struct tmcb_params *ps)
{
	struct rtp_relay_ctx *ctx = rtp_relay_try_get_ctx();

	if (!ctx || !rtp_relay_ctx_b2b(ctx))
		return; /* nothing engaged yet */

	/* we have a new request that we need to compute the branch_id for, but we
	 * cannot do that now, since we don't know if it is an initial request, or
	 * an in-dialog one */
	rtp_relay_b2b_branch_computed = 0;

	RTP_RELAY_CTX_REF(ctx);
	/* we have an existing RTP context - engage REQUEST OUT */
	if (rtp_relay_tmb.register_tmcb(ps->req, t, TMCB_LOCAL_REQUEST_OUT,
				rtp_relay_b2b_tm_req, ctx, rtp_relay_ctx_release)!=1) {
		LM_ERR("failed to install TMCB_LOCAL_REQUEST_OUT callback\n");
		RTP_RELAY_CTX_UNREF(ctx);
	}
}

#define RTP_RELAY_CTX_VERSION 4
#define RTP_RELAY_BIN_PUSH(_type, _value) \
	do { \
		if (bin_push_##_type(&packet, _value) < 0) { \
			LM_ERR("cannot push '" #_value "' in bin packet!\n"); \
			bin_free_packet(&packet); \
			return; \
		} \
	} while (0)

typedef struct rtp_copy_ctx {
	str id;
	void *ctx;
	struct list_head list;
} rtp_copy_ctx;

rtp_copy_ctx *rtp_copy_ctx_get(struct rtp_relay_ctx *ctx, str *id)
{
	struct list_head *it;
	rtp_copy_ctx *c;

	list_for_each(it, &ctx->copy_contexts) {
		c = list_entry(it, rtp_copy_ctx, list);
		if (str_match(&c->id, id))
			return c;
	}
	return NULL;
}

rtp_copy_ctx *rtp_copy_ctx_new(struct rtp_relay_ctx *ctx, str *id)
{

	rtp_copy_ctx *copy_ctx = shm_malloc(sizeof(*copy_ctx) + id->len);
	if (!copy_ctx)
		return NULL;
	memset(copy_ctx, 0, sizeof *copy_ctx);
	copy_ctx->id.s = (char *)(copy_ctx + 1);
	copy_ctx->id.len = id->len;
	memcpy(copy_ctx->id.s, id->s, id->len);
	list_add(&copy_ctx->list, &ctx->copy_contexts);
	return copy_ctx;
};

static void rtp_relay_store_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str buffer;
	str str_empty = str_init("");
	bin_packet_t packet;
	struct list_head *it;
	enum rtp_relay_var_flags flag;
	int leg;
	struct rtp_relay_sess *sess;
	rtp_copy_ctx *copy_ctx;
	str name = str_init("rtp_relay_ctx");
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx)
		return;

	if (bin_init(&packet, &name, 0, RTP_RELAY_CTX_VERSION, 0) < 0) {
		LM_ERR("cannot initialize bin packet!\n");
		return;
	}
	if (!ctx->established) {
		if (list_empty(&ctx->sessions)) {
			LM_WARN("no rtp relay session!\n");
			return;
		}
		LM_WARN("rtp relay session not established - storing last session!\n");
		sess = list_last_entry(&ctx->sessions, struct rtp_relay_sess, list);
	} else {
		sess = ctx->established;
	}
	RTP_RELAY_BIN_PUSH(str, &sess->relay->name);
	RTP_RELAY_BIN_PUSH(int, ctx->state);
	RTP_RELAY_BIN_PUSH(int, sess->index);
	RTP_RELAY_BIN_PUSH(int, sess->state);
	RTP_RELAY_BIN_PUSH(int, sess->server.set);
	RTP_RELAY_BIN_PUSH(str, &sess->server.node);
	for (leg = RTP_RELAY_CALLER; leg <= RTP_RELAY_CALLEE; leg++) {
		RTP_RELAY_BIN_PUSH(int, sess->legs[leg]->index);
		RTP_RELAY_BIN_PUSH(int, sess->legs[leg]->state);
		RTP_RELAY_BIN_PUSH(str, &sess->legs[leg]->tag);
		for (flag = RTP_RELAY_FLAGS_FIRST; flag < RTP_RELAY_FLAGS_SIZE; flag++) {
			if (sess->legs[leg]->flags[flag].s)
				RTP_RELAY_BIN_PUSH(str, &sess->legs[leg]->flags[flag]);
			else
				RTP_RELAY_BIN_PUSH(str, &str_empty);
		}
	}
	if (sess->relay->funcs.copy_serialize) {
		RTP_RELAY_BIN_PUSH(int, list_size(&ctx->copy_contexts));
		/* also serialize all the copy contexts */
		list_for_each(it, &ctx->copy_contexts) {
			copy_ctx = list_entry(it, rtp_copy_ctx, list);
			RTP_RELAY_BIN_PUSH(str, &copy_ctx->id);
			sess->relay->funcs.copy_serialize(copy_ctx->ctx, &packet);
		}
	} else {
		RTP_RELAY_BIN_PUSH(int, 0);
	}

	RTP_RELAY_BIN_PUSH(str, &ctx->callid);
	RTP_RELAY_BIN_PUSH(str, &ctx->from_tag);
	RTP_RELAY_BIN_PUSH(str, &ctx->to_tag);
	RTP_RELAY_BIN_PUSH(str, &ctx->flags);
	RTP_RELAY_BIN_PUSH(str, &ctx->delete);
	bin_get_buffer(&packet, &buffer);
	bin_free_packet(&packet);

	if (rtp_relay_dlg.store_dlg_value(dlg, &rtp_relay_dlg_name, &buffer) < 0)
		LM_WARN("rtp relay ctx was not saved in dialog\n");
}
#undef RTP_RELAY_BIN_PUSH

#define RTP_RELAY_BIN_POP(_type, _value) \
	do { \
		if (bin_pop_##_type(&packet, _value) < 0) { \
			LM_ERR("cannot pop '" #_value "' from bin packet (line=%d)!\n", __LINE__); \
			goto error; \
		} \
	} while (0)

static void rtp_relay_loaded_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str tag;
	str tmp;
	str buffer;
	unsigned int state;
	int index, set, ltype;
	bin_packet_t packet;
	struct rtp_relay *relay;
	enum rtp_relay_var_flags flag;
	struct rtp_relay_sess *sess;
	struct rtp_relay_ctx *ctx = NULL;
	struct rtp_relay_leg *leg = NULL;
	rtp_copy_ctx *copy_ctx;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch rtp relay info!\n");
		return;
	}

	if (rtp_relay_dlg.fetch_dlg_value(dlg, &rtp_relay_dlg_name, &buffer, 0) < 0) {
		LM_DBG("no rtp relay context in dialog\n");
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
	RTP_RELAY_BIN_POP(int, &ctx->state);

	RTP_RELAY_BIN_POP(int, &index);
	RTP_RELAY_BIN_POP(int, &state);
	RTP_RELAY_BIN_POP(int, &set);
	sess = rtp_relay_new_sess(ctx, relay, &set, NULL, index);
	if (!sess)
		goto error;
	sess->state = state;
	RTP_RELAY_BIN_POP(str, &tmp);
	shm_str_dup(&sess->server.node, &tmp);

	for (ltype = RTP_RELAY_CALLER; ltype <= RTP_RELAY_CALLEE; ltype++) {
		RTP_RELAY_BIN_POP(int, &index);
		RTP_RELAY_BIN_POP(int, &state);
		RTP_RELAY_BIN_POP(str, &tag);
		leg = rtp_relay_new_leg(ctx, &tag, index);
		if (!leg)
			continue;
		leg->state = state;
		rtp_relay_push_sess_leg(sess, leg, ltype);
		for (flag = RTP_RELAY_FLAGS_FIRST; flag < RTP_RELAY_FLAGS_SIZE; flag++) {
			RTP_RELAY_BIN_POP(str, &tmp);
			if (tmp.len && shm_str_dup(&sess->legs[ltype]->flags[flag], &tmp) < 0)
				LM_ERR("could not duplicate rtp session flag!\n");
		}
	}

	RTP_RELAY_BIN_POP(int, &index);
	while (index-- > 0) {
		RTP_RELAY_BIN_POP(str, &tmp);
		copy_ctx = rtp_copy_ctx_new(ctx, &tmp);
		if (copy_ctx &&
				!relay->funcs.copy_deserialize(&copy_ctx->ctx, &packet)) {
			list_del(&copy_ctx->list);
			shm_free(copy_ctx);
		}
	}

	RTP_RELAY_BIN_POP(str, &tmp);
	if (tmp.len)
		shm_str_dup(&ctx->callid, &tmp);
	RTP_RELAY_BIN_POP(str, &tmp);
	if (tmp.len)
		shm_str_dup(&ctx->from_tag, &tmp);
	RTP_RELAY_BIN_POP(str, &tmp);
	if (tmp.len)
		shm_str_dup(&ctx->to_tag, &tmp);
	RTP_RELAY_BIN_POP(str, &tmp);
	if (tmp.len)
		shm_str_dup(&ctx->flags, &tmp);
	RTP_RELAY_BIN_POP(str, &tmp);
	if (tmp.len)
		shm_str_dup(&ctx->delete, &tmp);

	/* all good now - delete the dialog variable as it is useless */
	rtp_relay_dlg.store_dlg_value(dlg, &rtp_relay_dlg_name, NULL);

	ctx->established = sess;
	if (rtp_relay_dlg_callbacks(dlg, ctx, NULL) < 0)
		goto error;
	rtp_relay_dlg_req_callbacks(dlg, ctx);

	return;
error:
	rtp_relay_ctx_release(ctx);
}
#undef RTP_RELAY_BIN_POP

static int rtp_relay_b2b_new_tuple(struct b2bl_cb_params *p, unsigned int m)
{
	struct rtp_relay_ctx *ctx;

	if (!p || !p->key) {
		LM_ERR("unknown new b2b tuple\n");
		return -1;
	}
	/* search for an existing rtp relay context */
	ctx = rtp_relay_try_get_ctx();
	if (!ctx) {
		LM_DBG("no ongoing contexts!\n");
		return 0;
	}
	rtp_relay_ctx_set_b2b(ctx);
	RTP_RELAY_PUT_B2B_CTX(p->key, ctx);

	return 0;
}

int rtp_relay_ctx_preinit(void)
{
	/* load the TM API */
	if (load_tm_api(&rtp_relay_tmb)!=0) {
		LM_ERR("TM not loaded - aborting!\n");
		return -1;
	}
	/* load the DLG API */
	if (load_dlg_api(&rtp_relay_dlg)==0) {
		/* we need to register pointer in pre-init, to make sure the new dialogs
		 * loaded have the context registered */
		rtp_relay_dlg_ctx_idx = rtp_relay_dlg.dlg_ctx_register_ptr(rtp_relay_ctx_release);
	}
	if (load_b2b_logic_api(&rtp_relay_b2b)==0) {
		rtp_relay_b2b_ctx_idx = rtp_relay_b2b.ctx_register_ptr(rtp_relay_b2b_end);
	}
	if (rtp_relay_dlg_ctx_idx < 0 && rtp_relay_b2b_ctx_idx < 0) {
		LM_ERR("nor dialog not b2b modules loaded - cannot use this module!\n");
		return -1;
	}
	return 0;
}

int rtp_relay_ctx_init(void)
{

	rtp_relay_contexts_lock = lock_init_rw();
	if (!rtp_relay_contexts_lock) {
		LM_ERR("cannot create lock for RTP Relay sessions\n");
		return -1;
	}

	rtp_relay_contexts = shm_malloc(sizeof *rtp_relay_contexts);
	if (!rtp_relay_contexts) {
		LM_ERR("cannot create RTP Relay sessions list\n");
		return -1;
	}

	INIT_LIST_HEAD(rtp_relay_contexts);
	rtp_relay_tm_ctx_idx = rtp_relay_tmb.t_ctx_register_ptr(rtp_relay_ctx_release);
	/* register a routine to move the pointer in tm when the transaction
	 * is created! */
	if (rtp_relay_tmb.register_tmcb(0, 0, TMCB_REQUEST_IN, rtp_relay_reqin, 0, 0)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		return -2;
	}
	if (rtp_relay_tmb.register_tmcb(0, 0, TMCB_LOCAL_TRANS_NEW,
			rtp_relay_b2b_new_local, 0, 0)<=0) {
		LM_ERR("cannot register tm LOCAL callbacks\n");
		return -2;
	}

	rtp_relay_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, rtp_relay_ctx_release);
	if (rtp_relay_dlg_ctx_idx != -1) {
		if (rtp_relay_dlg.register_dlgcb(NULL, DLGCB_LOADED,
				rtp_relay_loaded_callback, NULL, NULL) < 0)
			LM_WARN("cannot register callback for loaded dialogs - will not be "
					"able to restore an ongoing media session after a restart!\n");
	}
	if (rtp_relay_b2b_ctx_idx != -1) {
		if (rtp_relay_b2b.register_cb(NULL, rtp_relay_b2b_new_tuple,
				NULL, B2B_NEW_TUPLE_CB) < 0)
			LM_WARN("cannot register callback for new B2B tuples\n");
	}
	return 0;
}

int rtp_relay_ctx_branch(void)
{
	return rtp_relay_tmb.get_branch_index();
}

struct rtp_relay_sess *rtp_relay_get_sess_index(struct rtp_relay_ctx *ctx, int index)
{
	struct list_head *it;
	struct rtp_relay_sess *sess;

	list_for_each(it, &ctx->sessions) {
		sess = list_entry(it, struct rtp_relay_sess, list);
		if (sess->index == index)
			return sess;
	}
	return NULL;
}

struct rtp_relay_sess *rtp_relay_get_sess(struct rtp_relay_ctx *ctx, int index)
{
	struct rtp_relay_sess *sess = rtp_relay_get_sess_index(ctx, index);
	return sess?sess:rtp_relay_get_sess_index(ctx, RTP_RELAY_ALL_BRANCHES);
}

#define RTP_RELAY_FLAGS(_l, _f) \
	(sess->legs[_l] && sess->legs[_l]->flags[_f].s? \
		&sess->legs[_l]->flags[_f]:NULL)
#define RTP_RELAY_S(_s) ((_s)?(_s)->len:0), ((_s)?(_s)->s:0)
#define RTP_RELAY_FLAGS_S(_l, _f) RTP_RELAY_S(RTP_RELAY_FLAGS(_l, _f))

static int rtp_relay_replace_body(struct sip_msg *msg, str *body)
{
	str *oldbody;
	struct lump *anchor;

	oldbody = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!oldbody)
		return -1;

	anchor = del_lump(msg, oldbody->s - msg->buf, oldbody->len, 0);
	if (!anchor) {
		LM_ERR("del_lump failed\n");
		return -1;
	}
	if (!insert_new_lump_after(anchor, body->s, body->len, 0)) {
		LM_ERR("insert_new_lump_after failed\n");
		return -1;
	}
	return 0;
}

static int rtp_relay_offer(struct rtp_relay_session *info,
		struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess,
		int leg, str *body)
{
	str ret_body;

	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	/* if we have a body in the session, use it */
	if (RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_BODY)) {
		info->body = RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_BODY);
		if (!body) {
			memset(&ret_body, 0, sizeof ret_body);
			body = &ret_body;
		}
	}
	if (!info->callid) {
		if (ctx->callid.len)
			info->callid = &ctx->callid;
		else if (ctx->dlg_callid.len)
			info->callid = &ctx->dlg_callid;
	}
	if (leg == RTP_RELAY_CALLER) {
		if (!info->from_tag && ctx->from_tag.len)
			info->from_tag = &ctx->from_tag;
		if (!info->to_tag && ctx->to_tag.len)
			info->to_tag = &ctx->to_tag;
	} else {
		if (!info->to_tag && ctx->from_tag.len)
			info->to_tag = &ctx->from_tag;
		if (!info->from_tag && ctx->to_tag.len)
			info->from_tag = &ctx->to_tag;
	}
	LM_DBG("callid=[%.*s] ftag=[%.*s] ttag=[%.*s] "
			"type=[%.*s] in-iface=[%.*s] out-iface=[%.*s] ctx-flags=[%.*s] "
			"flags=[%.*s] peer-flags=[%.*s]\n",
			RTP_RELAY_S(info->callid),
			RTP_RELAY_S(info->from_tag),
			RTP_RELAY_S(info->to_tag),
			RTP_RELAY_FLAGS_S(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS_S(leg, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS_S(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_IFACE),
			(ctx && ctx->flags.s?ctx->flags.len:0),
			(ctx && ctx->flags.s?ctx->flags.s:NULL),
			RTP_RELAY_FLAGS_S(leg, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS_S(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_PEER));

	if (sess->relay->funcs.offer(info, &sess->server, body,
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_IP),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_IFACE),
			(ctx && ctx->flags.s?&ctx->flags:NULL),
			RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_PEER)) < 0) {
		LM_ERR("could not engage offer!\n");
		return -1;
	}
	if (body && body == &ret_body) {
		if (rtp_relay_replace_body(info->msg, body) < 0) {
			pkg_free(body->s);
			return -2;
		}
	}
	rtp_sess_set_ongoing(sess);
	rtp_sess_set_pending(sess);
	return 1;
}

static int rtp_relay_answer(struct rtp_relay_session *info,
		struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess,
		int leg, str *body)
{
	str ret_body;

	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	if (!info->callid) {
		if (ctx->callid.len)
			info->callid = &ctx->callid;
		else if (ctx->dlg_callid.len)
			info->callid = &ctx->dlg_callid;
	}
	if (leg == RTP_RELAY_CALLEE) {
		if (!info->from_tag && ctx->from_tag.len)
			info->from_tag = &ctx->from_tag;
		if (!info->to_tag && ctx->to_tag.len)
			info->to_tag = &ctx->to_tag;
	} else {
		if (!info->to_tag && ctx->from_tag.len)
			info->to_tag = &ctx->from_tag;
		if (!info->from_tag && ctx->to_tag.len)
			info->from_tag = &ctx->to_tag;
	}
	/* if we have a body in the session, use it */
	if (RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_BODY)) {
		info->body = RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_BODY);
		if (!body) {
			memset(&ret_body, 0, sizeof ret_body);
			body = &ret_body;
		}
	}

	LM_DBG("callid=[%.*s] ftag=[%.*s] ttag=[%.*s] "
			"type=[%.*s] in-iface=[%.*s] out-iface=[%.*s] ctx-flags=[%.*s] "
			"flags=[%.*s] peer-flags=[%.*s]\n",
			RTP_RELAY_S(info->callid),
			RTP_RELAY_S(info->from_tag),
			RTP_RELAY_S(info->to_tag),
			RTP_RELAY_FLAGS_S(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS_S(leg, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS_S(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_IFACE),
			(ctx && ctx->flags.s?ctx->flags.len:0),
			(ctx && ctx->flags.s?ctx->flags.s:NULL),
			RTP_RELAY_FLAGS_S(leg, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS_S(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_PEER));
	if (sess->relay->funcs.answer(info, &sess->server, body,
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_IP),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_IFACE),
			(ctx && ctx->flags.s?&ctx->flags:NULL),
			RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_PEER(leg), RTP_RELAY_FLAGS_PEER)) < 0) {
		LM_ERR("could not engage answer!\n");
		return -1;
	}
	if (body && body == &ret_body) {
		if (rtp_relay_replace_body(info->msg, body) < 0) {
			pkg_free(body->s);
			return -2;
		}
	}
	rtp_sess_reset_ongoing(sess);
	return 1;
}

static int rtp_relay_delete(struct rtp_relay_session *info,
		struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess, int leg)
{
	int ret;
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	if (!info->callid) {
		if (ctx->callid.len)
			info->callid = &ctx->callid;
		else if (ctx->dlg_callid.len)
			info->callid = &ctx->dlg_callid;
	}
	if (!info->from_tag && ctx->from_tag.len)
		info->from_tag = &ctx->from_tag;
	if (!info->to_tag && ctx->to_tag.len)
		info->to_tag = &ctx->to_tag;

	LM_DBG("callid=[%.*s] ftag=[%.*s] ttag=[%.*s] "
			"ctx-flags=[%.*s] delete-flags=[%.*s]\n",
			RTP_RELAY_S(info->callid),
			RTP_RELAY_S(info->from_tag),
			RTP_RELAY_S(info->to_tag),
			(ctx && ctx->flags.s?ctx->flags.len:0),
			(ctx && ctx->flags.s?ctx->flags.s:NULL),
			RTP_RELAY_FLAGS_S(leg, RTP_RELAY_FLAGS_DELETE));
	ret = sess->relay->funcs.delete(info, &sess->server,
			(ctx && ctx->delete.s?&ctx->flags:NULL),
			RTP_RELAY_FLAGS(leg, RTP_RELAY_FLAGS_DELETE));
	if (ret < 0)
		return -1;
	rtp_sess_reset_pending(sess);
	return 1;
}
#undef RTP_RELAY_S
#undef RTP_RELAY_FLAGS
#undef RTP_RELAY_FLAGS_S

static inline int rtp_relay_dlg_mi_flags(struct rtp_relay_leg *leg,
		mi_item_t *obj)
{
	if (!leg)
		return 0;
	if (leg->tag.len &&
		add_mi_string(obj, MI_SSTR("tag"),
			leg->tag.s, leg->tag.len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_SELF].s &&
		add_mi_string(obj, MI_SSTR("flags"),
			leg->flags[RTP_RELAY_FLAGS_SELF].s,
			leg->flags[RTP_RELAY_FLAGS_SELF].len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_PEER].s &&
		add_mi_string(obj, MI_SSTR("peer"),
			leg->flags[RTP_RELAY_FLAGS_PEER].s,
			leg->flags[RTP_RELAY_FLAGS_PEER].len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_IP].s &&
		add_mi_string(obj, MI_SSTR("IP"),
			leg->flags[RTP_RELAY_FLAGS_IP].s,
			leg->flags[RTP_RELAY_FLAGS_IP].len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_TYPE].s &&
		add_mi_string(obj, MI_SSTR("type"),
			leg->flags[RTP_RELAY_FLAGS_TYPE].s,
			leg->flags[RTP_RELAY_FLAGS_TYPE].len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_IFACE].s &&
		add_mi_string(obj, MI_SSTR("interface"),
			leg->flags[RTP_RELAY_FLAGS_IFACE].s,
			leg->flags[RTP_RELAY_FLAGS_IFACE].len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_DELETE].s &&
		add_mi_string(obj, MI_SSTR("delete"),
			leg->flags[RTP_RELAY_FLAGS_DELETE].s,
			leg->flags[RTP_RELAY_FLAGS_DELETE].len) < 0)
		return -1;
	if (leg->flags[RTP_RELAY_FLAGS_BODY].s &&
		add_mi_string(obj, MI_SSTR("body"),
			leg->flags[RTP_RELAY_FLAGS_BODY].s,
			leg->flags[RTP_RELAY_FLAGS_BODY].len) < 0)
		return -1;
	return 0;
}

static int mi_rtp_relay_ctx(struct rtp_relay_ctx *ctx,
		mi_item_t *item, int callid)
{
	int ret = -1;
	struct rtp_relay_sess *sess;
	mi_item_t *rtp_item, *caller_item, *callee_item, *ctx_item;

	rtp_item = add_mi_object(item, MI_SSTR("rtp_relay"));
	if (!rtp_item) {
		LM_ERR("cold not create rtp_relay!\n");
		return ret;
	}
	sess = ctx->established;
	if (!sess)
		goto end;
	if (callid && ctx->dlg_callid.len && add_mi_string(rtp_item, MI_SSTR("callid"),
			ctx->dlg_callid.s, ctx->dlg_callid.len) < 0)
		goto end;
	caller_item = add_mi_object(rtp_item, MI_SSTR("caller"));
	if (!caller_item)
		goto end;
	if (rtp_relay_dlg_mi_flags(sess->legs[RTP_RELAY_CALLER], caller_item) < 0)
		goto end;
	callee_item = add_mi_object(rtp_item, MI_SSTR("callee"));
	if (!callee_item)
		goto end;
	if (rtp_relay_dlg_mi_flags(sess->legs[RTP_RELAY_CALLEE], callee_item) < 0)
		goto end;
	if (add_mi_string(rtp_item, MI_SSTR("relay"),
			sess->relay->name.s, sess->relay->name.len) < 0)
		goto end;
	if (add_mi_string(rtp_item, MI_SSTR("node"),
			sess->server.node.s, sess->server.node.len) < 0)
		goto end;
	if (add_mi_number(rtp_item, MI_SSTR("set"), sess->server.set) < 0)
		goto end;
	if (sess->index != RTP_RELAY_ALL_BRANCHES &&
			add_mi_number(rtp_item, MI_SSTR("branch"), sess->index) < 0)
		goto end;
	ctx_item = add_mi_object(rtp_item, MI_SSTR("ctx"));
	if (!ctx_item)
		goto end;
	if (ctx->callid.len && add_mi_string(ctx_item, MI_SSTR("callid"),
			ctx->callid.s, ctx->callid.len) < 0)
		goto end;
	if (ctx->from_tag.len && add_mi_string(ctx_item, MI_SSTR("from-tag"),
			ctx->from_tag.s, ctx->from_tag.len) < 0)
		goto end;
	if (ctx->to_tag.len && add_mi_string(ctx_item, MI_SSTR("to-tag"),
			ctx->to_tag.s, ctx->to_tag.len) < 0)
		goto end;
	if (ctx->flags.len && add_mi_string(ctx_item, MI_SSTR("flags"),
			ctx->flags.s, ctx->flags.len) < 0)
		goto end;
	if (ctx->delete.len && add_mi_string(ctx_item, MI_SSTR("delete"),
			ctx->delete.s, ctx->delete.len) < 0)
		goto end;
	ret = 0;
end:
	return ret;
}

static void rtp_relay_dlg_mi(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	mi_item_t *item = (mi_item_t *)(params->dlg_data);
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx || !item)
		return;

	RTP_RELAY_CTX_LOCK(ctx);
	mi_rtp_relay_ctx(ctx, item, 0);
	RTP_RELAY_CTX_UNLOCK(ctx);
}

static void rtp_relay_delete_ctx(struct rtp_relay_ctx *ctx,
		struct rtp_relay_sess *sess, int leg)
{
	struct rtp_relay_session info;
	memset(&info, 0, sizeof info);
	info.callid = &ctx->callid;
	if (!info.callid->len)
		info.callid = &ctx->dlg_callid;
	info.from_tag = &ctx->from_tag;
	info.to_tag = &ctx->to_tag;
	info.branch = sess->index;
	rtp_relay_delete(&info, ctx, sess, leg);
}

static int rtp_relay_indlg_get_type(struct sip_msg *msg,
		struct rtp_relay_ctx *ctx)
{
	int ltype;
	struct rtp_relay_leg *leg;
	if (!ctx->established)
		return -1;
	if (parse_headers(msg, HDR_FROM_F, 0) < 0 || !msg->from ||
			parse_from_header(msg) < 0 || !get_from(msg)->tag_value.len) {
		LM_ERR("bad request or missing From header\n");
		return -1;
	}
	leg = rtp_relay_get_leg(ctx, &get_from(msg)->tag_value,
			RTP_RELAY_ALL_BRANCHES);
	if (!leg)
		return -1;
	for (ltype = RTP_RELAY_CALLER; ltype <= RTP_RELAY_CALLEE; ltype++)
		if (leg == ctx->established->legs[ltype])
			return ltype;
	return -1;
}

static void rtp_relay_dlg_end(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	int ltype;
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx->established || !rtp_sess_pending(ctx->established))
		return;

	ltype = rtp_relay_indlg_get_type(params->msg, ctx);
	if (ltype < 0)
		ltype = 0;

	RTP_RELAY_CTX_LOCK(ctx);
	rtp_relay_delete_ctx(ctx, ctx->established, ltype);
	RTP_RELAY_CTX_UNLOCK(ctx);
	lock_start_write(rtp_relay_contexts_lock);
	list_del(&ctx->list);
	lock_stop_write(rtp_relay_contexts_lock);
}


static void rtp_relay_indlg_tm_req(struct cell* t, int type, struct tmcb_params *p)
{
	struct rtp_relay_session info;
	struct dlg_cell *dlg = (struct dlg_cell *)(*p->param);
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);
	struct rtp_relay_sess *sess;
	int ltype;

	if (!ctx || !ctx->established) {
		LM_BUG("could not find a rtp relay context in %p!\n", ctx);
		return;
	}
	sess = ctx->established;
	memset(&info, 0, sizeof info);
	info.branch = sess->index;
	info.msg = p->req;

	info.body = get_body_part(info.msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!info.body)
		return;
	ltype = rtp_relay_indlg_get_type(info.msg, ctx);
	if (ltype < 0)
		return;
	rtp_relay_offer(&info, ctx, sess, ltype, NULL);
}

static void rtp_relay_indlg_tm_rpl(struct cell* t, int type, struct tmcb_params *p)
{
	str *body;
	int ltype;
	struct sip_msg *msg;
	struct rtp_relay_session info;
	struct rtp_relay_sess *sess;
	struct dlg_cell *dlg = (struct dlg_cell *)(*p->param);
	struct rtp_relay_ctx *ctx = RTP_RELAY_GET_DLG_CTX(dlg);

	if (!ctx || !ctx->established) {
		LM_BUG("could not find a rtp relay context in %p!\n", ctx);
		return;
	}
	sess = ctx->established;

	ltype = rtp_relay_indlg_get_type(p->req, ctx);
	if (ltype < 0)
		return;
	ltype = RTP_RELAY_PEER(ltype);
	if (!sess->legs[ltype]) {
		LM_ERR("no peer leg for reply!\n");
		return;
	}
	msg = p->rpl;
	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body)
		return;

	memset(&info, 0, sizeof info);
	info.branch = sess->index;
	info.msg = msg;
	info.body = body;
	if (rtp_sess_late(sess))
		rtp_relay_offer(&info, ctx, sess, ltype, NULL);
	else
		rtp_relay_answer(&info, ctx, sess, ltype, NULL);
}

static void rtp_relay_indlg(struct dlg_cell* dlg, int type, struct dlg_cb_params * params)
{
	struct rtp_relay_session info;
	struct sip_msg *msg = params->msg;
	struct rtp_relay_ctx *ctx = *params->param;
	struct rtp_relay_sess *sess;
	str *body;
	int ret, ltype;

	if (!msg) {
		LM_DBG("no message available\n");
		return;
	}

	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	RTP_RELAY_CTX_LOCK(ctx);
	sess = ctx->established;
	ret = (sess && rtp_sess_pending(sess));
	if (ret && !body) {
		if (msg->REQ_METHOD != METHOD_INVITE) {
			if (msg->REQ_METHOD != METHOD_ACK)
				LM_DBG("method %d without SDP\n", msg->REQ_METHOD);
			else if (rtp_sess_late(sess))
				LM_WARN("late negociation without SDP in ACK!\n");
			ret = 0;
		} else {
			rtp_sess_set_late(sess);
		}
	} else if (body && msg->REQ_METHOD == METHOD_INVITE) {
		rtp_sess_reset_late(ctx->established);
	}
	RTP_RELAY_CTX_UNLOCK(ctx);
	if (!ret)
		return;
	if (msg->REQ_METHOD == METHOD_ACK) {
		if (!sess || !rtp_sess_late(sess))
			return;
		memset(&info, 0, sizeof info);
		info.msg = msg;
		info.body = body;
		info.branch = sess->index;
		ltype = rtp_relay_indlg_get_type(msg, ctx);
		if (ltype < 0)
			return;
		rtp_relay_answer(&info, ctx, sess, ltype, NULL);
		return;
	}
	if (!body && msg->REQ_METHOD != METHOD_INVITE) {
		LM_DBG("%d without body! skipping update\n", msg->REQ_METHOD);
		return;
	}

	if (rtp_relay_tmb.register_tmcb(msg, 0, TMCB_REQUEST_FWDED,
				rtp_relay_indlg_tm_req, dlg, 0)!=1)
		LM_ERR("failed to install TM request callback\n");
	if (rtp_relay_tmb.register_tmcb(msg, 0, TMCB_RESPONSE_FWDED,
			rtp_relay_indlg_tm_rpl, dlg, 0)!=1)
		LM_ERR("failed to install TM upstream reply callback\n");
}

static void rtp_relay_fill_dlg(struct rtp_relay_ctx *ctx, str *dlg_callid,
		unsigned id, unsigned entry, str *callid, str *from_tag, str *to_tag)
{
	ctx->dlg_id = id;
	ctx->dlg_entry = entry;
	if (dlg_callid && !ctx->dlg_callid.len && shm_str_sync(&ctx->dlg_callid, dlg_callid) < 0)
		LM_ERR("could not store dialog callid in context\n");
	if (callid && !ctx->callid.len &&  shm_str_sync(&ctx->callid, callid) < 0)
		LM_ERR("could not store callid in context\n");
	if (from_tag && !ctx->from_tag.s && shm_str_sync(&ctx->from_tag, from_tag) < 0)
		LM_ERR("could not store from tag in context\n");
	if (to_tag && !ctx->to_tag.s && shm_str_sync(&ctx->to_tag, to_tag) < 0)
		LM_ERR("could not store to tag in context\n");
}

static void rtp_relay_dlg_req_callbacks(struct dlg_cell *dlg, struct rtp_relay_ctx *ctx)
{
	if (!dlg) {
		dlg = rtp_relay_dlg.get_dlg();
		if (!dlg) {
			LM_ERR("call engage after creating dialog!\n");
			return;
		}
	}
	if (rtp_relay_dlg.register_dlgcb(dlg,
			DLGCB_REQ_WITHIN,
			rtp_relay_indlg, ctx, NULL) != 0)
		LM_ERR("could not register request within dlg callback!\n");
}

static int rtp_relay_dlg_callbacks(struct dlg_cell *dlg,
		struct rtp_relay_ctx *ctx, str *to_tag)
{
	if (rtp_relay_dlg_ctx_idx == -1)
		return 0;
	rtp_relay_fill_dlg(ctx, &dlg->callid, dlg->h_id, dlg->h_entry,
			NULL, &dlg->legs[DLG_CALLER_LEG].tag,
			(to_tag?to_tag:&dlg->legs[callee_idx(dlg)].tag));

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

	if (rtp_relay_dlg.register_dlgcb(dlg, DLGCB_WRITE_VP,
			rtp_relay_store_callback, NULL, NULL))
		LM_WARN("cannot register callback for rtp relay serialization! "
				"Will not be able to engage rtp relay in case of a restart!\n");
	lock_start_write(rtp_relay_contexts_lock);
	list_add(&ctx->list, rtp_relay_contexts);
	lock_stop_write(rtp_relay_contexts_lock);

	return 0;

error:
	RTP_RELAY_PUT_DLG_CTX(dlg, NULL);
	return -1;
}

static int rtp_relay_sess_success(struct rtp_relay_ctx *ctx,
	struct rtp_relay_sess *sess, struct cell *t, struct sip_msg *msg)
{
	struct dlg_cell *dlg;
	str *to_tag = NULL;

	rtp_sess_set_success(sess);
	ctx->established = sess;
	if (!rtp_relay_ctx_established(ctx)) {
		dlg = rtp_relay_dlg.get_dlg();
		if (!dlg) {
			LM_ERR("could not find dialog!\n");
			return -1;
		}
		/* reset old pointers */
		RTP_RELAY_CTX_REF_UNSAFE(ctx, -1);
		RTP_RELAY_PUT_TM_CTX(t, NULL);
		RTP_RELAY_PUT_CTX(NULL);

		/* if we have a to_tag, use it from dlg,
		 * otherwise fetch it from tm */
		if (!dlg->legs[callee_idx(dlg)].tag.len) {
			if (parse_headers(msg, HDR_TO_F, 0) == -1) {
				LM_ERR("failed to parse To header\n");
				return -1;
			}

			if (!msg->to) {
				LM_ERR("missing To header\n");
				return -1;
			}

			to_tag = &get_to(msg)->tag_value;

			if (to_tag->len == 0)
				to_tag = NULL;
		}

		if (rtp_relay_dlg_callbacks(dlg, ctx, to_tag) < 0) {
			/* restore the state */
			RTP_RELAY_CTX_REF(ctx);
			RTP_RELAY_PUT_TM_CTX(t, ctx);
			return -1;
		}
		rtp_relay_ctx_set_established(ctx);
	}
	return 0;
}

static int handle_rtp_relay_ctx_leg_reply(struct rtp_relay_ctx *ctx,
		struct sip_msg *msg, struct rtp_relay_sess *sess, int type)
{
	struct rtp_relay_session info;
	memset(&info, 0, sizeof info);
	info.msg = msg;
	if (msg == FAKED_REPLY || msg->REPLY_STATUS >= 300) {
		if (!rtp_sess_late(sess)) {
			if (msg == FAKED_REPLY)
				info.msg = NULL;
			rtp_relay_delete(&info, ctx, sess, type);
		} else {
			/* nothing to do */
			LM_DBG("negative reply on late branch\n");
		}
		rtp_relay_ctx_free_sess(sess);
		return 1;
	}
	/* fill in tag's tag */
	if (sess->legs[type] && sess->legs[type]->tag.len)
		return 0;
	if (parse_headers(msg, HDR_TO_F, 0) < 0 || !msg->to || parse_from_header(msg) < 0) {
		LM_ERR("bad request or missing To header\n");
		return -1;
	} else {
		if (!sess->legs[type]) {
			rtp_relay_push_sess_leg(sess, rtp_relay_new_leg(ctx,
					&get_to(msg)->tag_value, sess->index), type);
			if (!sess->legs[type]) {
				LM_ERR("could not create new leg\n");
				return -1;
			}
		} else {
			shm_str_sync(&sess->legs[type]->tag,
					&get_to(msg)->tag_value);
		}
	}
	return 0;
}

static int rtp_relay_ctx_leg_reply(struct rtp_relay_ctx *ctx, struct sip_msg *msg,
		struct cell *t, struct rtp_relay_sess *sess, int type)
{
	int ret;
	struct rtp_relay_session info;
	memset(&info, 0, sizeof info);
	info.msg = msg;
	info.body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!info.body) {
		if (msg->REPLY_STATUS < 200) {
			LM_DBG("provisioning reply %d without body\n", msg->REPLY_STATUS);
			return 1;
		} else if (rtp_sess_late(sess)) {
			LM_WARN("no SDP in final reply of late negotiation\n");
			return -1;
		} else if (msg->REPLY_STATUS < 300 && !rtp_sess_success(sess)) {
			/* we have a session which was established on a provisioning -
			 * mark it as established */
			rtp_relay_sess_success(ctx, sess, t, msg);
			return 1;
		} else if (!rtp_sess_success(sess)) {
			LM_WARN("final reply without SDP - cannot complete negotiation!\n");
			return -1;
		} else {
			return 1;
		}
	}
	info.branch = sess->index;
	if (rtp_sess_late(sess))
		ret = rtp_relay_offer(&info, ctx, sess, type, NULL);
	else
		ret = rtp_relay_answer(&info, ctx, sess, type, NULL);
	if (ret > 0 && !rtp_sess_success(sess))
		rtp_relay_sess_success(ctx, sess, t, msg);
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
					goto end;
				}
			} else {
				LM_DBG("no session on branch %d\n", rtp_relay_ctx_branch());
				goto end;
			}
			if (rtp_sess_disabled(sess) || (!rtp_sess_late(sess) && !rtp_sess_pending(sess))) {
				LM_DBG("disabled and/or pending session %d/%d\n",
						rtp_sess_disabled(sess), rtp_sess_pending(sess));
				goto end;
			}
			switch (handle_rtp_relay_ctx_leg_reply(ctx, p->rpl, sess, RTP_RELAY_CALLEE)) {
				case 0:
					rtp_relay_ctx_leg_reply(ctx, p->rpl, t, sess, RTP_RELAY_CALLEE);
					break;
				case 1:
					lock_start_write(rtp_relay_contexts_lock);
					if (list_is_valid(&ctx->list))
						list_del(&ctx->list);
					lock_stop_write(rtp_relay_contexts_lock);
					break;
			}
			break;
		case TMCB_REQUEST_FWDED:
			sess = rtp_relay_get_sess(ctx, rtp_relay_ctx_branch());
			if (sess) {
				if (rtp_sess_disabled(sess)) {
					LM_DBG("rtp relay on branch %d is disabled\n",
							rtp_relay_ctx_branch());
					goto end;
				}
				if (rtp_sess_late(sess)) {
					LM_DBG("rtp relay on branch %d is late\n",
							rtp_relay_ctx_branch());
					goto end;
				}
			} else {
				LM_DBG("no session on branch %d\n",
						rtp_relay_ctx_branch());
				goto end;
			}
			memset(&info, 0, sizeof info);
			info.body = get_body_part(p->req, TYPE_APPLICATION, SUBTYPE_SDP);
			info.msg = p->req;
			info.branch = sess->index;
			rtp_relay_offer(&info, ctx, sess, RTP_RELAY_CALLER, NULL);
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
	str *body;
	int index;
	struct rtp_relay_leg *leg;
	struct rtp_relay_sess *sess;
	int last_branch;

	switch (route_type) {
		case REQUEST_ROUTE:
			index = RTP_RELAY_ALL_BRANCHES;
			break;
		case BRANCH_ROUTE:
			index = rtp_relay_ctx_branch();
			break;
		case LOCAL_ROUTE:
			index = rtp_relay_get_last_branch(ctx, msg);
			break;
		default:
			LM_ERR("unhandled route type %d\n", route_type);
			return -1;
	}
	if (parse_headers(msg, HDR_FROM_F, 0) < 0 || !msg->from ||
			parse_from_header(msg) < 0 || !get_from(msg)->tag_value.len) {
		LM_ERR("bad request or missing From header\n");
		return -1;
	}

	if (route_type != LOCAL_ROUTE) {
		if (rtp_relay_dlg_ctx_idx < 0) {
			LM_ERR("dialog module not loaded - failed to engage\n");
			return -1;
		}
		if (!rtp_relay_ctx_engaged(ctx)) {

			/* handles the replies to the original INVITE */
			if (rtp_relay_tmb.register_tmcb(msg, 0,
					TMCB_RESPONSE_FWDED|TMCB_REQUEST_FWDED,
					rtp_relay_ctx_initial_cb, ctx, 0)!=1) {
				LM_ERR("failed to install TM reply callback\n");
				return -1;
			}
			rtp_relay_dlg_req_callbacks(NULL, ctx);
			rtp_relay_ctx_set_engaged(ctx);
		}
		sess = rtp_relay_new_sess(ctx, relay, set,
				&get_from(msg)->tag_value, index);
		if (!sess->legs[RTP_RELAY_CALLER])
			rtp_relay_push_sess_leg(sess, rtp_relay_new_leg(ctx,
					&get_from(msg)->tag_value, index), RTP_RELAY_CALLER);
	} else {
		leg = rtp_relay_get_peer_leg_ctx(ctx, msg);
		if (!leg) {
			LM_ERR("cannot identify the peer's leg\n");
			return -1;
		}
		last_branch = rtp_relay_get_last_branch(ctx, msg);

		/* if there is an existing ongoing session, duplicate it */
		if (ctx->established) {
			sess = rtp_relay_dup_sess(ctx, ctx->established);
			sess->index = last_branch;
			sess->relay = relay;
			if (set)
				sess->server.set = *set;
			if (ctx->established->legs[RTP_RELAY_CALLER] == leg) {
				rtp_relay_fill_sess_leg(ctx, sess, RTP_RELAY_CALLER,
						&leg->tag, last_branch);
				rtp_relay_fill_sess_leg(ctx, sess, RTP_RELAY_CALLEE,
						NULL, last_branch);
			} else {
				rtp_relay_fill_sess_leg(ctx, sess, RTP_RELAY_CALLER,
						NULL, last_branch);
				rtp_relay_fill_sess_leg(ctx, sess, RTP_RELAY_CALLEE,
						&leg->tag, leg->index);
			}
		} else {
			sess = rtp_relay_new_sess(ctx, relay, set,
					&leg->tag, last_branch);
		}
	}

	if (!sess) {
		LM_ERR("could not create new RTP relay session\n");
		return -1;
	}
	body = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
	if (!body)
		rtp_sess_set_late(sess);
	return 1;
}

static mi_response_t *mi_rtp_relay_params(const mi_params_t *params,
		struct rtp_relay **relay, str **node, int *set)
{
	static str tmp;

	*relay = NULL;
	*node = NULL;
	*set = -1;

	switch(try_get_mi_string_param(params, "engine", &tmp.s, &tmp.len)) {
		case -1:
			break;
		case -2:
			return init_mi_param_error();
		default:
			*relay = rtp_relay_get(&tmp);
			if (!*relay)
				return init_mi_error(404, MI_SSTR("unknown RTP  Relay engine"));
			/* if we have an engine, we might also have a node */
			switch(try_get_mi_string_param(params, "node", &tmp.s, &tmp.len)) {
				case -1:
					break;
				case -2:
					return init_mi_param_error();
				default:
					*node = &tmp;
					break;
			}
			/* if we have an engine, we might also have a node */
			switch(try_get_mi_int_param(params, "set", set)) {
					break;
				case -2:
					return init_mi_param_error();
				case -1:
				default:
					break;
			}
	}
	return NULL;
}

mi_response_t *mi_rtp_relay_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *arr;
	struct list_head *it;
	struct rtp_relay_ctx *ctx;
	struct rtp_relay *relay;
	str *node;
	int set;

	resp = mi_rtp_relay_params(params, &relay, &node, &set);
	if (resp)
		return resp;

	resp = init_mi_result_array(&arr);
	if (!resp)
		return 0;

	lock_start_read(rtp_relay_contexts_lock);
	list_for_each(it, rtp_relay_contexts) {
		ctx = list_entry(it, struct rtp_relay_ctx, list);
		RTP_RELAY_CTX_LOCK(ctx);
		if (!ctx->established)
			goto next;
		if (relay && ctx->established->relay != relay)
			goto next;
		if (node && str_strcmp(node, &ctx->established->server.node))
			goto next;
		if (mi_rtp_relay_ctx(ctx, arr, 1) < 0)
			goto error;
next:
		RTP_RELAY_CTX_UNLOCK(ctx);
	}

	lock_stop_read(rtp_relay_contexts_lock);

	return resp;

error:
	RTP_RELAY_CTX_UNLOCK(ctx);
	lock_stop_read(rtp_relay_contexts_lock);
	free_mi_response(resp);
	return 0;
}

struct rtp_async_param {
	int no, completed, success;
	gen_lock_t lock;
	struct mi_handler *async;
	struct list_head contexts;
};
static struct rtp_async_param *rtp_relay_new_async_param(
		struct mi_handler *async_hdl)
{
	struct rtp_async_param *p = shm_malloc(sizeof *p);
	if (!p) {
		LM_ERR("could not create temporary contexts list\n");
		return NULL;
	}
	memset(p, 0, sizeof *p);
	INIT_LIST_HEAD(&p->contexts);
	lock_init(&p->lock);
	p->async = async_hdl;
	return p;
}

struct rtp_relay_tmp {
	enum {
		RTP_RELAY_TMP_FAIL,
		RTP_RELAY_TMP_OFFER,
		RTP_RELAY_TMP_ANSWER,
	} state;
	struct rtp_relay_ctx *ctx;
	struct rtp_relay_sess *sess;
	struct rtp_async_param *param;
	struct dlg_cell *dlg;
	struct list_head list;
};

static struct rtp_relay_tmp *rtp_relay_new_tmp(struct rtp_relay_ctx *ctx,
		int set, str *node)
{
	struct rtp_relay_sess *s;
	struct rtp_relay_tmp *tmp = shm_malloc(sizeof *tmp);
	if (!tmp) {
		LM_ERR("could not allocate temporary ctx\n");
		return NULL;
	}
	tmp->state = 0;
	tmp->ctx = ctx;
	/* create a new session, similar to the existing one */
	tmp->sess = rtp_relay_dup_sess(ctx, ctx->established);
	if (!tmp->sess)
		goto error;
	s = ctx->established;
	memcpy(tmp->sess, s, sizeof *s);
	if (set != -1)
		tmp->sess->server.set = set;
	if (!node)
		node = &s->server.node;
	if (shm_str_dup(&tmp->sess->server.node, node) < 0)
		goto error;
	INIT_LIST_HEAD(&tmp->list);
	rtp_relay_ctx_set_pending(ctx);
	ctx->ref++;
	return tmp;
error:
	if (tmp->sess)
		rtp_relay_ctx_free_sess(tmp->sess);
	shm_free(tmp);
	return NULL;
}

static int rtp_relay_release_tmp(struct rtp_relay_tmp *tmp, int success)
{
	int ret;
	struct rtp_async_param *p;
	struct rtp_relay_sess *del_sess = NULL;

	RTP_RELAY_CTX_LOCK(tmp->ctx);
	rtp_relay_ctx_reset_pending(tmp->ctx);
	tmp->ctx->ref--;
	if (tmp->ctx->ref == 0) {
		RTP_RELAY_CTX_UNLOCK(tmp->ctx);
		rtp_relay_ctx_free(tmp->ctx);
		rtp_relay_ctx_free_sess(tmp->sess);
		tmp->ctx = NULL;
	} else {
		if (success) {
			/* if we are using a different node, or a different engine,
			 * we should terminate the previous session */
			if (tmp->ctx->established->relay != tmp->sess->relay ||
					str_strcmp(&tmp->ctx->established->server.node,
						&tmp->sess->server.node)) {
				del_sess = tmp->ctx->established;
				list_del(&del_sess->list);
				INIT_LIST_HEAD(&del_sess->list);
			} else {
				/* otherwise cleanup the structure now */
				rtp_relay_ctx_free_sess(tmp->ctx->established);
			}
			tmp->ctx->established = tmp->sess;
			list_add(&tmp->sess->list, &tmp->ctx->sessions);
		} else {
			rtp_relay_ctx_free_sess(tmp->sess);
		}
		RTP_RELAY_CTX_UNLOCK(tmp->ctx);
	}
	/* update the async param */
	p = tmp->param;
	lock_get(&p->lock);
	list_del(&tmp->list);
	p->completed++;
	if (success)
		p->success++;
	/* if all sessions completed, return the number of completed
	 * sessions, otherwise return the number of failed sessions */
	if (p->no == p->completed)
		if (p->success)
			ret = p->success;
		else
			ret = -p->no;
	else
		ret = 0;
	lock_release(&p->lock);

	/* finally, delete the previous session */
	if (del_sess) {
		if (tmp->dlg)
			rtp_relay_delete_ctx(tmp->ctx, del_sess,
					(tmp->state == RTP_RELAY_TMP_OFFER?RTP_RELAY_CALLER:RTP_RELAY_CALLEE));
		rtp_relay_ctx_free_sess(del_sess);
	}
	if (tmp->dlg)
		rtp_relay_dlg.dlg_unref(tmp->dlg, 1);
	shm_free(tmp);
	return ret;
}

static int rtp_relay_reinvite(struct rtp_relay_tmp *tmp, int leg,
		str *body, int release_body);

static int rtp_relay_reinvite_reply(struct sip_msg *msg,
		int statuscode, void *param)
{
	char retbuf[10 /* 'Sessions: */ + INT2STR_MAX_LEN];
	struct rtp_relay_tmp *tmp = (struct rtp_relay_tmp *)param;
	struct rtp_relay_session info;
	struct rtp_async_param *p;
	mi_response_t *resp;
	str body, *pbody;
	int success = 0;
	int ret;
	str sret;

	/* not interested in provisional replies */
	if (statuscode < 200)
		return 0;

	if (!param) {
		LM_BUG("cannot get reinvite param!\n");
		return -1;
	}

	if (msg == NULL || msg == FAKED_REPLY) {
		/* we only care about actual replies */
		goto error;
	}

	switch (tmp->state) {
		case RTP_RELAY_TMP_OFFER:
			pbody = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_SDP);
			if (!pbody) {
				LM_WARN("reply without SDP - dropping\n");
				goto error;
			}
			/* answer caller's SDP tp get SDP for callee */
			memset(&info, 0, sizeof info);
			/* reversed tags */
			info.from_tag = &tmp->ctx->to_tag;
			info.to_tag = &tmp->ctx->from_tag;
			info.branch = tmp->sess->index;
			info.body = pbody;
			info.msg = msg;

			ret = rtp_relay_answer(&info, tmp->ctx, tmp->sess,
					RTP_RELAY_CALLER, &body);
			if (ret < 0) {
				LM_ERR("cannot answer RTP relay for callee SDP\n");
				goto error;
			}

			tmp->state = RTP_RELAY_TMP_ANSWER;
			return rtp_relay_reinvite(tmp, callee_idx(tmp->dlg), &body, 1);

		case RTP_RELAY_TMP_ANSWER:
			if (statuscode >= 300) {
				LM_ERR("callee returned negative reply\n");
				goto error;
			}
			success = 1;
			/* fallback */
		case RTP_RELAY_TMP_FAIL:
			/* nothing to do, just release with error! */
			p = tmp->param;
			ret = rtp_relay_release_tmp(tmp, success);
			if (ret != 0) {
				/* complete */
				if (p->async) {
					sret.s = retbuf;
					memcpy(sret.s, "Sessions: ", 10);
					sret.len = 10;
					body.s = int2str(abs(ret), &body.len);
					memcpy(sret.s + 10, body.s, body.len);
					sret.len += body.len;
					if (ret > 0)
						resp = init_mi_result_string(sret.s, sret.len);
					else
						resp = init_mi_error_extra(400, MI_SSTR("Failed"), sret.s, sret.len);
					p-> async->handler_f(resp, p->async, 1);
					shm_free(p);
				}
			}
			return (success?0:-1);
		default:

			LM_BUG("unknown tmp context state %d\n", tmp->state);
			goto error;
	}
	return 0;
error:
	/* we presume that only caller was updated - send whatever was
	 * last in the out buffer */
	tmp->state = RTP_RELAY_TMP_FAIL;
	body = tmp->dlg->legs[DLG_CALLER_LEG].in_sdp;
	return rtp_relay_reinvite(tmp, DLG_CALLER_LEG, &body, 0);
}

static int rtp_relay_reinvite(struct rtp_relay_tmp *tmp, int leg,
		str *body, int release_body)
{
	static str inv = str_init("INVITE");
	static str content_type_sdp = str_init("application/sdp");

	int ret = rtp_relay_dlg.send_indialog_request(tmp->dlg,
			&inv, leg, body, &content_type_sdp, NULL,
			rtp_relay_reinvite_reply, tmp);
	if (body && release_body)
		pkg_free(body->s);
	return ret;
}

static int rtp_relay_update_reinvites(struct rtp_relay_tmp *tmp)
{
	struct ip_addr *ip = NULL;
	struct sip_uri uri;
	int callee_leg, ret = -1;
	struct rtp_relay_session info;
	memset(&info, 0, sizeof info);

	callee_leg = callee_idx(tmp->dlg);

	str body = tmp->dlg->legs[callee_leg].in_sdp;
	if (!body.s) {
		LM_ERR("cannot get callee's SDP\n");
		return -1;
	}

	/* offer callee's SDP to get SDP for caller */
	info.callid = &tmp->ctx->dlg_callid;
	info.from_tag = &tmp->ctx->to_tag;
	info.to_tag = &tmp->ctx->from_tag;
	info.branch = tmp->sess->index;
	info.body = &body;
	info.msg = get_dummy_sip_msg();
	if (!info.msg) {
		LM_ERR("could not get dummy msg!\n");
		return -1;
	}
	/* in order to advertise the right IP in to the media server, we need to
	 * store the received information in the message */
	if (parse_uri(tmp->dlg->legs[callee_leg].contact.s,
			tmp->dlg->legs[callee_leg].contact.len, &uri) < 0) {
		LM_ERR("could not parse contact's uri!\n");
		goto end;
	}

	if ((ip = str2ip(&uri.host)) != NULL || (ip = str2ip6(&uri.host)) != NULL)
		memcpy(&info.msg->rcv.src_ip, ip, sizeof *ip);
	else
		LM_DBG("could not convert uri host [%.*s] to an ip\n", uri.host.len, uri.host.s);

	ret = rtp_relay_offer(&info, tmp->ctx, tmp->sess,
			RTP_RELAY_CALLEE, &body);
	if (ret < 0) {
		LM_ERR("cannot engage RTP relay for callee SDP\n");
		goto end;
	}

	tmp->state = RTP_RELAY_TMP_OFFER;
	/* step one - send re-invite to caller with updated callee's SDP */
	ret =  rtp_relay_reinvite(tmp, DLG_CALLER_LEG, &body, 1);
end:
	release_dummy_sip_msg(info.msg);
	return ret;
}

static mi_response_t *rtp_relay_update_async(struct rtp_async_param *p)
{
	struct list_head *it, *safe;
	struct rtp_relay_tmp *tmp;
	struct dlg_cell *dlg;
	int success = 0;

	list_for_each_safe(it, safe, &p->contexts) {
		tmp = list_entry(it, struct rtp_relay_tmp, list);
		dlg = rtp_relay_dlg.get_dlg_by_ids(tmp->ctx->dlg_entry, tmp->ctx->dlg_id);
		if (!dlg) {
			LM_BUG("could not find dialog!\n");
			rtp_relay_release_tmp(tmp, 0);
			continue;
		}
		if (dlg->state > 4) {
			LM_DBG("call in terminate state; skipping!\n");
			rtp_relay_release_tmp(tmp, 0);
			continue;
		}
		tmp->param = p;
		tmp->dlg = dlg;
		if (rtp_relay_update_reinvites(tmp) < 0) {
			rtp_relay_release_tmp(tmp, 0);
			continue;
		}

		success++;
	}
	if (success) {
		if (p->async == NULL)
			return init_mi_result_string(MI_SSTR("Accepted"));
		else
			return MI_ASYNC_RPL;
	} else {
		shm_free(p);
		return init_mi_error(400, MI_SSTR("RTP Relay not available"));
	}
}


mi_response_t *mi_rtp_relay_update(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	struct rtp_relay *relay = NULL;
	struct rtp_relay_ctx *ctx;
	str *node, *new_node = NULL, tmp;
	int set, new_set = -1;
	struct rtp_relay_tmp *ctmp;
	struct list_head *it, *safe;
	struct rtp_async_param *p;

	resp = mi_rtp_relay_params(params, &relay, &node, &set);
	if (resp)
		return resp;

	switch(try_get_mi_int_param(params, "new_set", &new_set)) {
		case -1:
			break;
		case -2:
			return init_mi_param_error();
		default:
			LM_DBG("using new set %d\n", new_set);
	}
	/* we might also have a node */
	switch(try_get_mi_string_param(params, "new_node", &tmp.s, &tmp.len)) {
		case -1:
			break;
		case -2:
			return init_mi_param_error();
		default:
			new_node = &tmp;
			LM_DBG("using new node %.*s\n", tmp.len, tmp.s);
			break;
	}
	p = rtp_relay_new_async_param(async_hdl);
	if (!p) {
		LM_ERR("could not create temporary contexts list\n");
		return 0;
	}

	lock_start_read(rtp_relay_contexts_lock);
	list_for_each(it, rtp_relay_contexts) {
		ctx = list_entry(it, struct rtp_relay_ctx, list);
		RTP_RELAY_CTX_LOCK(ctx);
		if (!ctx->established)
			goto next;
		if (relay && ctx->established->relay != relay)
			goto next;
		if (set != -1 && ctx->established->server.set != set)
			goto next;
		if (node && str_strcmp(node, &ctx->established->server.node))
			goto next;
		if (rtp_relay_ctx_pending(ctx))
			goto next;
		ctmp = rtp_relay_new_tmp(ctx, new_set, new_node);
		if (!ctmp)
			goto error;
		list_add(&ctmp->list, &p->contexts);
		p->no++;
next:
		RTP_RELAY_CTX_UNLOCK(ctx);
	}

	lock_stop_read(rtp_relay_contexts_lock);

	/* all good - start async process */
	if (p->no == 0) {
		/* nothing to do */
		shm_free(p);
		return init_mi_result_ok();
	}
	return rtp_relay_update_async(p);
error:
	RTP_RELAY_CTX_UNLOCK(ctx);
	lock_stop_read(rtp_relay_contexts_lock);
	list_for_each_safe(it, safe, &p->contexts)
		rtp_relay_release_tmp(list_entry(it, struct rtp_relay_tmp, list), 0);
	shm_free(p);
	return 0;
}

static int rtp_relay_push_flags_type(struct rtp_relay_sess *sess,
		int leg, const char *stype, cJSON *jflags)
{
	str tmp;
	enum rtp_relay_var_flags f;
	cJSON *o = cJSON_GetObjectItem(jflags, stype);

	if (!o)
		return 0;

	if (!(o->type & cJSON_Object)) {
		LM_WARN("%s not an object - ignoring!\n", stype);
		return -1;
	}
	for (o = o->child; o; o = o->next) {
		tmp.s = o->string;
		tmp.len = strlen(tmp.s);
		f = rtp_relay_flags_get(&tmp);
		switch (f) {
			case RTP_RELAY_FLAGS_UNKNOWN:
				LM_WARN("Unknown RTP relay flag %s\n", o->string);
				break;
			case RTP_RELAY_FLAGS_DISABLED:
				if (!(o->type & cJSON_Number)) {
					LM_WARN("%s not a string - ignoring!\n", o->string);
					continue;
				}
				rtp_leg_set_disabled(sess->legs[leg], o->valueint);
				break;
			default:
				if (!(o->type & cJSON_String)) {
					LM_WARN("%s not a string - ignoring!\n", o->string);
					continue;
				}
				tmp.s = o->valuestring;
				tmp.len = strlen(tmp.s);
				if (shm_str_sync(&sess->legs[leg]->flags[f], &tmp) < 0)
					return -1;
				break;
		}
	}
	return 0;
}

static int rtp_relay_push_flags(struct rtp_relay_sess *sess, cJSON *flags)
{
	return rtp_relay_push_flags_type(sess, RTP_RELAY_CALLER, "caller", flags) |
		rtp_relay_push_flags_type(sess, RTP_RELAY_CALLEE, "callee", flags);
}

mi_response_t *mi_rtp_relay_update_callid(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	struct rtp_relay *relay = NULL;
	struct rtp_relay_ctx *ctx;
	str *node, flags, callid, tmp;
	struct rtp_relay_tmp *ctmp = NULL;
	struct rtp_async_param *p;
	struct list_head *it;
	cJSON *jflags = NULL;
	int set, ret;

	if (get_mi_string_param(params, "callid", &callid.s, &callid.len) < 0)
		return init_mi_param_error();

	resp = mi_rtp_relay_params(params, &relay, &node, &set);
	if (resp)
		return resp;

	switch(try_get_mi_string_param(params, "flags", &flags.s, &flags.len)) {
		case -1:
			break;
		case -2:
			return init_mi_param_error();
		default:
			if (pkg_nt_str_dup(&tmp, &flags) < 0)
				return 0;
			jflags = cJSON_Parse(tmp.s);
			if (!jflags)
				return init_mi_param_error();
			break;
	}

	lock_start_read(rtp_relay_contexts_lock);
	list_for_each(it, rtp_relay_contexts) {
		ctx = list_entry(it, struct rtp_relay_ctx, list);
		RTP_RELAY_CTX_LOCK(ctx);
		if (!str_strcmp(&ctx->dlg_callid, &callid))
			break;
		RTP_RELAY_CTX_UNLOCK(ctx);
		ctx = NULL;
	}
	if (!ctx) {
		lock_stop_read(rtp_relay_contexts_lock);
		return init_mi_error(404, MI_SSTR("RTP Relay session not found"));
	}
	if (rtp_relay_ctx_pending(ctx)) {
		RTP_RELAY_CTX_UNLOCK(ctx);
		lock_stop_read(rtp_relay_contexts_lock);
		goto error;
	}

	ctmp = rtp_relay_new_tmp(ctx, set, node);
	RTP_RELAY_CTX_UNLOCK(ctx);
	lock_stop_read(rtp_relay_contexts_lock);
	if (!ctmp)
		return 0;

	/* update relay, if needed */
	if (relay)
		ctmp->sess->relay = relay;
	if (jflags) {
		ret = rtp_relay_push_flags(ctmp->sess, jflags);
		cJSON_Delete(jflags);
		if (ret < 0)
			goto error;
	}

	p = rtp_relay_new_async_param(async_hdl);
	if (!p) {
		LM_ERR("could not create temporary contexts list\n");
		goto error;
	}
	list_add(&ctmp->list, &p->contexts);
	p->no = 1;

	return rtp_relay_update_async(p);
error:
	rtp_relay_release_tmp(ctmp, 0);
	return NULL;
}

int rtp_relay_api_offer(rtp_ctx _ctx, str *id,
		unsigned int flags, str *body)
{
	int ret;
	struct rtp_relay_session info;
	struct rtp_relay_sess *sess;
	struct rtp_relay_ctx *ctx = _ctx;
	if (!ctx) {
		LM_ERR("no context to use!\n");
		return -1;
	}
	sess = ctx->established;
	if (!sess || !(rtp_relay_ctx_engaged(ctx)) || !sess->relay) {
		LM_ERR("rtp not established!\n");
		return -1;
	}
	memset(&info, 0, sizeof info);
	info.branch = sess->index;
	info.body = body;
	info.msg = get_dummy_sip_msg();
	if (!info.msg) {
		LM_ERR("could not get dummy msg!\n");
		return -1;
	}
	ret = rtp_relay_offer(&info, ctx, sess, flags, body);
	release_dummy_sip_msg(info.msg);
	return ret;
}

int rtp_relay_api_answer(rtp_ctx _ctx, str *id,
		unsigned int flags, str *body)
{
	int ret;
	struct rtp_relay_session info;
	struct rtp_relay_sess *sess;
	struct rtp_relay_ctx *ctx = _ctx;
	if (!ctx) {
		LM_ERR("no context to use!\n");
		return -1;
	}
	sess = ctx->established;
	if (!sess || !(rtp_relay_ctx_engaged(ctx)) || !sess->relay) {
		LM_ERR("rtp not established!\n");
		return -1;
	}
	memset(&info, 0, sizeof info);
	info.branch = sess->index;
	info.body = body;
	info.msg = get_dummy_sip_msg();
	if (!info.msg) {
		LM_ERR("could not get dummy msg!\n");
		return -1;
	}
	ret = rtp_relay_answer(&info, ctx, sess, flags, body);
	release_dummy_sip_msg(info.msg);
	return ret;
}

int rtp_relay_api_delete(rtp_ctx _ctx, str *id, unsigned int flags)
{
	int ret;
	struct rtp_relay_session info;
	struct rtp_relay_sess *sess;
	struct rtp_relay_ctx *ctx = _ctx;
	if (!ctx) {
		LM_ERR("no context to use!\n");
		return -1;
	}
	sess = ctx->established;
	if (!sess || !(rtp_relay_ctx_engaged(ctx)) || !sess->relay) {
		LM_ERR("rtp not established!\n");
		return -1;
	}
	memset(&info, 0, sizeof info);
	info.branch = sess->index;
	info.msg = get_dummy_sip_msg();
	if (!info.msg) {
		LM_ERR("could not get dummy msg!\n");
		return -1;
	}
	ret = rtp_relay_delete(&info, ctx, sess, flags);
	release_dummy_sip_msg(info.msg);
	return ret;
}

int rtp_relay_copy_offer(rtp_ctx _ctx, str *id, str *flags,
		unsigned int copy_flags, unsigned int streams, str *ret_body)
{
	int release = 0;
	struct rtp_relay_session info;
	struct rtp_relay_ctx *ctx = _ctx;
	struct rtp_relay_sess *sess;
	rtp_copy_ctx *rtp_copy;
	if (!ret_body) {
		LM_ERR("no body to return!\n");
		return -1;
	}
	if (!ctx) {
		LM_ERR("no context to use!\n");
		return -1;
	}
	sess = ctx->established;
	if (!sess || !(rtp_relay_ctx_engaged(ctx)) || !sess->relay) {
		LM_ERR("rtp not established!\n");
		return -1;
	}
	if (!sess->relay->funcs.copy_offer) {
		LM_ERR("rtp does not support recording!\n");
		return -1;
	}
	rtp_copy = rtp_copy_ctx_get(ctx, id);
	if (!rtp_copy) {
		rtp_copy = rtp_copy_ctx_new(ctx, id);
		if (!rtp_copy) {
			LM_ERR("oom for rtp copy context!\n");
			return -1;
		}
		release = 1;
	}
	memset(&info, 0, sizeof info);
	info.callid = &ctx->callid;
	if (!info.callid->len)
		info.callid = &ctx->dlg_callid;
	info.from_tag = &ctx->from_tag;
	info.to_tag = &ctx->to_tag;
	info.branch = sess->index;
	if (sess->relay->funcs.copy_offer(&info, &sess->server,
			&rtp_copy->ctx, flags, copy_flags, streams, ret_body) < 0) {
		if (release) {
			list_del(&rtp_copy->list);
			shm_free(rtp_copy);
		}
		return -1;
	}
	return 0;
}

int rtp_relay_copy_answer(rtp_ctx _ctx, str *id,
		str *flags, str *body)
{
	struct rtp_relay_session info;
	struct rtp_relay_ctx *ctx = _ctx;
	struct rtp_copy_ctx *copy_ctx;
	struct rtp_relay_sess *sess;
	if (!body) {
		LM_ERR("no body to provide!\n");
		return -1;
	}
	if (!ctx) {
		LM_ERR("no context to use!\n");
		return -1;
	}
	sess = ctx->established;
	if (!sess || !(rtp_relay_ctx_engaged(ctx)) || !sess->relay) {
		LM_ERR("rtp not established!\n");
		return -1;
	}
	if (!sess->relay->funcs.copy_answer) {
		LM_ERR("rtp does not support recording!\n");
		return -1;
	}
	copy_ctx = rtp_copy_ctx_get(ctx, id);
	if (!copy_ctx) {
		LM_ERR("cannot find copy context %.*s\n", id->len, id->s);
		return -1;
	}
	memset(&info, 0, sizeof info);
	info.callid = &ctx->callid;
	if (!info.callid->len)
		info.callid = &ctx->dlg_callid;
	info.from_tag = &ctx->from_tag;
	info.to_tag = &ctx->to_tag;
	info.branch = sess->index;
	return sess->relay->funcs.copy_answer(
			&info, &sess->server,
			copy_ctx->ctx, flags, body);
}

int rtp_relay_copy_delete(rtp_ctx _ctx, str *id, str *flags)
{
	int ret;
	struct rtp_relay_session info;
	struct rtp_relay_ctx *ctx = _ctx;
	struct rtp_copy_ctx *copy_ctx;
	struct rtp_relay_sess *sess;

	if (!ctx) {
		LM_ERR("no context to use!\n");
		return -1;
	}
	sess = ctx->established;
	if (!sess || !sess->relay) {
		LM_ERR("rtp not established!\n");
		return -1;
	}
	if (!rtp_sess_pending(sess)) {
		LM_DBG("rtp session already terminated!\n");
		return 1;
	}
	if (!sess->relay->funcs.copy_delete) {
		LM_DBG("rtp does not support stop recording!\n");
		return 1;
	}
	copy_ctx = rtp_copy_ctx_get(ctx, id);
	if (!copy_ctx) {
		LM_ERR("cannot find copy context %.*s\n", id->len, id->s);
		return -1;
	}
	memset(&info, 0, sizeof info);
	info.callid = &ctx->callid;
	if (!info.callid->len)
		info.callid = &ctx->dlg_callid;
	info.from_tag = &ctx->from_tag;
	info.to_tag = &ctx->to_tag;
	info.branch = sess->index;
	ret = sess->relay->funcs.copy_delete(
			&info, &sess->server,
			copy_ctx->ctx, flags);
	list_del(&copy_ctx->list);
	shm_free(copy_ctx);
	return ret;
}

str *rtp_relay_get_sdp(struct rtp_relay_session *sess, int type)
{
	/* fetch the dialog */
	int leg;
	struct dlg_cell *dlg = rtp_relay_dlg.get_dlg();
	if (!dlg)
		dlg = rtp_relay_dlg.get_dlg_by_callid(sess->callid, 0);

	if (!dlg)
		return NULL;
	leg = (type==RTP_RELAY_CALLER?
		DLG_CALLER_LEG:callee_idx(dlg));
	return (dlg->legs[leg].tmp_in_sdp.s?
			&dlg->legs[leg].tmp_in_sdp:
			&dlg->legs[leg].in_sdp);
}

int rtp_relay_get_dlg_ids(str *callid, unsigned int *h_entry, unsigned int *h_id)
{
	int found = 0;
	struct list_head *it;
	struct rtp_relay_ctx *ctx;

	lock_start_read(rtp_relay_contexts_lock);
	list_for_each(it, rtp_relay_contexts) {
		ctx = list_entry(it, struct rtp_relay_ctx, list);
		if ((ctx->callid.len && !str_strcmp(&ctx->callid, callid)) ||
			(!ctx->callid.len && !str_strcmp(&ctx->dlg_callid, callid))) {
			*h_entry = ctx->dlg_entry;
			*h_id = ctx->dlg_id;
			found = 1;
			LM_DBG("found dlg_entry=%u dlg_id=%u for callid=%.*s\n",
					ctx->dlg_entry, ctx->dlg_id, callid->len, callid->s);
			break;
		}
	}
	lock_stop_read(rtp_relay_contexts_lock);
	return found;
}
