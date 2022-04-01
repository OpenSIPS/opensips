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

#ifndef _RTP_RELAY_CTX_H_
#define _RTP_RELAY_CTX_H_

#include "../../lib/list.h"
#include "../../locking.h"
#include "../../str.h"

#include "rtp_relay.h"

#define RTP_RELAY_CTX_STATE_ENGAGED		(1<<0)
#define RTP_RELAY_CTX_STATE_ESTABLISHED	(1<<1)
#define RTP_RELAY_CTX_STATE_PENDING		(1<<2)

#define RTP_RELAY_LEG_DISABLED			(1<<0)

#define RTP_RELAY_SESS_STATE_PENDING	(1<<1)
#define RTP_RELAY_SESS_STATE_SUCCESS	(1<<2)
#define RTP_RELAY_SESS_STATE_LATE		(1<<3)

#define rtp_relay_ctx_engaged(_s) ((_s)->state & RTP_RELAY_CTX_STATE_ENGAGED)
#define rtp_relay_ctx_set_engaged(_s) (_s)->state |= RTP_RELAY_CTX_STATE_ENGAGED

#define rtp_relay_ctx_established(_s) ((_s)->state & RTP_RELAY_CTX_STATE_ESTABLISHED)
#define rtp_relay_ctx_set_established(_s) (_s)->state |= RTP_RELAY_CTX_STATE_ESTABLISHED

#define rtp_relay_ctx_pending(_s) ((_s)->state & RTP_RELAY_CTX_STATE_PENDING)
#define rtp_relay_ctx_set_pending(_s) (_s)->state |= RTP_RELAY_CTX_STATE_PENDING
#define rtp_relay_ctx_reset_pending(_s) (_s)->state &= (~RTP_RELAY_CTX_STATE_PENDING)

#define rtp_leg_disabled(_l) ((_l)->state & RTP_RELAY_LEG_DISABLED)
#define rtp_leg_set_disabled(_l, _v) (_l)->state |= ((_v)?RTP_RELAY_LEG_DISABLED:0)
#define rtp_leg_reset_disabled(_s) (_s)->state &= (~RTP_RELAY_LEG_DISABLED)
#define rtp_sess_disabled(_s) \
	(((_s)->legs[RTP_RELAY_CALLER] && rtp_leg_disabled((_s)->legs[RTP_RELAY_CALLER])) || \
	 ((_s)->legs[RTP_RELAY_CALLEE] && rtp_leg_disabled((_s)->legs[RTP_RELAY_CALLEE])))

#define rtp_sess_pending(_s) ((_s)->state & RTP_RELAY_SESS_STATE_PENDING)
#define rtp_sess_set_pending(_s) (_s)->state |= RTP_RELAY_SESS_STATE_PENDING
#define rtp_sess_reset_pending(_s) (_s)->state &= (~RTP_RELAY_SESS_STATE_PENDING)

#define rtp_sess_success(_s) ((_s)->state & RTP_RELAY_SESS_STATE_SUCCESS)
#define rtp_sess_set_success(_s) (_s)->state |= RTP_RELAY_SESS_STATE_SUCCESS
#define rtp_sess_reset_success(_s) (_s)->state &= (~RTP_RELAY_SESS_STATE_SUCCESS)

#define rtp_sess_late(_s) ((_s)->state & RTP_RELAY_SESS_STATE_LATE)
#define rtp_sess_set_late(_s) (_s)->state |= RTP_RELAY_SESS_STATE_LATE
#define rtp_sess_reset_late(_s) (_s)->state &= (~RTP_RELAY_SESS_STATE_LATE)

enum rtp_relay_var_flags {
	RTP_RELAY_FLAGS_FIRST = 0,
	RTP_RELAY_FLAGS_SELF  = 0,
	RTP_RELAY_FLAGS_PEER,
	RTP_RELAY_FLAGS_IP,
	RTP_RELAY_FLAGS_TYPE,
	RTP_RELAY_FLAGS_IFACE,
	RTP_RELAY_FLAGS_BODY,
	RTP_RELAY_FLAGS_DELETE,

	RTP_RELAY_FLAGS_SIZE,		/* keep these *after* the last entry */
	RTP_RELAY_FLAGS_UNKNOWN = RTP_RELAY_FLAGS_SIZE,
	RTP_RELAY_FLAGS_DISABLED,
};

typedef str rtp_relay_flags[RTP_RELAY_FLAGS_SIZE];

enum rtp_relay_leg_type {
	RTP_RELAY_LEG_CALLER = 0,
	RTP_RELAY_LEG_CALLEE = 1
};

struct rtp_relay_leg {
	int index;
	int ref;
	unsigned int state;
	enum rtp_relay_leg_type type;
	rtp_relay_flags flags;
	struct list_head list;
};

struct rtp_relay_sess {
	int index;
	unsigned int state;
	struct rtp_relay *relay;
	struct rtp_relay_server server;
	struct list_head list;
	struct rtp_relay_leg *legs[2];
};

struct rtp_relay_ctx {
	int ref;
	str callid;
	str dlg_callid, from_tag, to_tag;
	str flags, delete;
	gen_lock_t lock;
	unsigned int state;
	struct rtp_relay_sess *established;
	struct list_head sessions;
	struct list_head legs;
	struct list_head list;
	struct list_head copy_contexts;
};

str *rtp_relay_flags_get_str(enum rtp_relay_var_flags flags);
enum rtp_relay_var_flags rtp_relay_flags_get(const str *name);

struct rtp_relay_ctx *rtp_relay_ctx_get(void);

struct rtp_relay_ctx *rtp_relay_try_get_ctx(void);
struct rtp_relay_ctx *rtp_relay_get_ctx(void);

int rtp_relay_ctx_preinit(void);
int rtp_relay_ctx_init(void);
int rtp_relay_ctx_branch(void);
int rtp_relay_ctx_upstream(void);

int rtp_relay_ctx_engage(struct sip_msg *msg,
		struct rtp_relay_ctx *ctx, struct rtp_relay *relay, int *set);

struct rtp_relay_sess *rtp_relay_get_sess(struct rtp_relay_ctx *ctx, int index);

struct rtp_relay_leg *rtp_relay_get_leg(struct rtp_relay_ctx *ctx,
		enum rtp_relay_leg_type type, int idx);
struct rtp_relay_leg *rtp_relay_new_leg(struct rtp_relay_ctx *ctx,
		enum rtp_relay_leg_type type, int idx);

mi_response_t *mi_rtp_relay_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_rtp_relay_update(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_rtp_relay_update_callid(const mi_params_t *params,
								struct mi_handler *async_hdl);

str *rtp_relay_get_sdp(struct rtp_relay_session *sess, int type);

#define RTP_RELAY_CTX_LOCK(_c) lock_get(&_c->lock);
#define RTP_RELAY_CTX_UNLOCK(_c) lock_release(&_c->lock);

#endif /* _RTP_RELAY_CTX_H_ */
