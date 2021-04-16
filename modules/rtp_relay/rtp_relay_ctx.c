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

static struct tm_binds rtp_relay_tmb;
static int rtp_relay_tm_ctx_idx = -1;
static int rtp_relay_ctx_idx = -1;

#define RTP_RELAY_GET_MSG_CTX() ((struct rtp_relay_ctx *)context_get_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, rtp_relay_ctx_idx))
#define RTP_RELAY_PUT_CTX(_p) context_put_ptr(CONTEXT_GLOBAL, \
		current_processing_ctx, rtp_relay_ctx_idx, (_p))
#define RTP_RELAY_GET_TM_CTX(_t) (rtp_relay_tmb.t_ctx_get_ptr(_t, rtp_relay_tm_ctx_idx))
#define RTP_RELAY_PUT_TM_CTX(_t, _p) \
	rtp_relay_tmb.t_ctx_put_ptr(_t, rtp_relay_tm_ctx_idx, _p)


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
	ctx = shm_malloc(sizeof *ctx);
	if (!ctx) {
		LM_ERR("oom for creating RTP relay context!\n");
		return NULL;
	}
	memset(ctx, 0, sizeof *ctx);

	lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->sessions);

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
	list_del(&s->list);
	shm_free(s);
}

void rtp_relay_ctx_free(void *param)
{
	struct list_head *it, *safe;
	struct rtp_relay_ctx *ctx = (struct rtp_relay_ctx *)param;

	if (!ctx)
		return;

	list_for_each_safe(it, safe, &ctx->sessions)
		rtp_relay_ctx_free_sess(list_entry(it, struct rtp_relay_sess, list));

	lock_destroy(&ctx->lock);
	shm_free(ctx);
}

struct rtp_relay_ctx *rtp_relay_try_get_ctx(void)
{
	struct cell* t;
	struct rtp_relay_ctx* ctx = NULL;

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

	if (!ctx)
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

int rtp_relay_ctx_init(void)
{
	/* load the TM API */
	if (load_tm_api(&rtp_relay_tmb)!=0) {
		LM_ERR("TM not loaded - aborting!\n");
		return -1;
	}
	rtp_relay_tm_ctx_idx = rtp_relay_tmb.t_ctx_register_ptr(rtp_relay_ctx_free);
	/* register a routine to move the pointer in tm when the transaction
	 * is created! */
	if (rtp_relay_tmb.register_tmcb(0, 0, TMCB_REQUEST_IN, rtp_relay_move_ctx, 0, 0)<=0) {
		LM_ERR("cannot register tm callbacks\n");
		return -2;
	}
	rtp_relay_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, rtp_relay_ctx_free);
	return 0;
}

int rtp_relay_ctx_branch(void)
{
	return rtp_relay_tmb.get_branch_index();
}

int rtp_relay_ctx_downstream(void)
{
	/* TODO return dlg_api.get_direction() == DLG_DIR_DOWNSTREAM */
	return 1;
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
	sess->node.set = -1;
	sess->index = index;
	if (index == RTP_RELAY_ALL_BRANCHES)
		ctx->main = sess;
	list_add(&sess->list, &ctx->sessions);
	return sess;
}

#if 0
static int rtp_relay_ctx_initial(void)
{
	struct cell* t;

	t = rtp_relay_tmb.t_gett();
	/* consider initial if transaction does not exist */
	if (t==T_UNDEFINED || t== NULL)
		return 1;
	return get_to(t->uas.request)->tag_value.len?0:1;
}
#endif

#define RTP_RELAY_FLAGS(_t, _f) \
	(sess->flags[_t][_f].s?&sess->flags[_t][_f]: \
	 (main?&main->flags[_t][_f]:NULL))

static int rtp_relay_offer(struct rtp_relay_session *info,
		struct rtp_relay_sess *sess, struct rtp_relay_sess *main)
{
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	if (sess->relay->binds.offer(info, &sess->node,
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_IP),
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_PEER)) < 0) {
		LM_ERR("could not engage offer!\n");
		return -1;
	}
	rtp_sess_set_pending(sess);
	return 1;
}

static int rtp_relay_answer(struct rtp_relay_session *info,
		struct rtp_relay_sess *sess, struct rtp_relay_sess *main)
{
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	return sess->relay->binds.answer(info, &sess->node,
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_IP),
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_TYPE),
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_IFACE),
			RTP_RELAY_FLAGS(RTP_RELAY_ANSWER, RTP_RELAY_FLAGS_SELF),
			RTP_RELAY_FLAGS(RTP_RELAY_OFFER, RTP_RELAY_FLAGS_PEER));
}

static int rtp_relay_delete(struct rtp_relay_session *info,
		struct rtp_relay_sess *sess, struct rtp_relay_sess *main)
{
	int ret;
	if (!sess->relay) {
		LM_BUG("no relay found!\n");
		return -1;
	}
	ret = sess->relay->binds.delete(info, &sess->node,
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

static int rtp_relay_sess_success(struct rtp_relay_ctx *ctx, struct rtp_relay_sess *sess)
{
	rtp_sess_set_success(sess);
	if (list_is_singular(&ctx->sessions))
		rtp_relay_sess_merge(ctx, sess);
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
		struct rtp_relay_sess *sess)
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
		ret = rtp_relay_offer(&info, sess, ctx->main);
	else
		ret = rtp_relay_answer(&info, sess, ctx->main);
	if (ret > 0 && msg->REPLY_STATUS >= 200)
		rtp_relay_sess_success(ctx, sess);
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
			if (rtp_sess_disabled(sess) || !rtp_sess_pending(sess)) {
				LM_DBG("disabled and/or pending session %d/%d\n",
						rtp_sess_disabled(sess), rtp_sess_pending(sess));
				goto end;
			}
			handle_rtp_relay_ctx_leg_reply(ctx, p->rpl, sess);
			break;
		case TMCB_REQUEST_FWDED:
			if (ctx->main && rtp_sess_pending(ctx->main)) {
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
				if (sess->node.set == -1)
					sess->node.set = ctx->main->node.set;
				if (!sess->relay)
					sess->relay = ctx->main->relay;
			}
			rtp_relay_offer(&info, sess, ctx->main);
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
		sess->node.set = *set;
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
	return rtp_relay_offer(&info, sess, ctx->main);
}
