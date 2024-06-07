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
#include "../../route.h"

#include "rtp_relay.h"

#define RTP_RELAY_CTX_STATE_ENGAGED		(1<<0)
#define RTP_RELAY_CTX_STATE_ESTABLISHED	(1<<1)
#define RTP_RELAY_CTX_STATE_PENDING		(1<<2)
#define RTP_RELAY_CTX_STATE_B2B			(1<<3)

#define RTP_RELAY_LEG_DISABLED			(1<<0)

#define RTP_RELAY_SESS_STATE_PENDING	(1<<1)
#define RTP_RELAY_SESS_STATE_SUCCESS	(1<<2)
#define RTP_RELAY_SESS_STATE_LATE		(1<<3)
#define RTP_RELAY_SESS_STATE_ONGOING	(1<<4)

#define rtp_relay_ctx_engaged(_s) ((_s)->state & RTP_RELAY_CTX_STATE_ENGAGED)
#define rtp_relay_ctx_set_engaged(_s) (_s)->state |= RTP_RELAY_CTX_STATE_ENGAGED

#define rtp_relay_ctx_established(_s) ((_s)->state & RTP_RELAY_CTX_STATE_ESTABLISHED)
#define rtp_relay_ctx_set_established(_s) (_s)->state |= RTP_RELAY_CTX_STATE_ESTABLISHED

#define rtp_relay_ctx_pending(_s) ((_s)->state & RTP_RELAY_CTX_STATE_PENDING)
#define rtp_relay_ctx_set_pending(_s) (_s)->state |= RTP_RELAY_CTX_STATE_PENDING
#define rtp_relay_ctx_reset_pending(_s) (_s)->state &= (~RTP_RELAY_CTX_STATE_PENDING)

#define rtp_relay_ctx_b2b(_c) ((_c)->state & RTP_RELAY_CTX_STATE_B2B)
#define rtp_relay_ctx_set_b2b(_c) (_c)->state |= RTP_RELAY_CTX_STATE_B2B


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

#define rtp_sess_ongoing(_s) ((_s)->state & RTP_RELAY_SESS_STATE_ONGOING)
#define rtp_sess_set_ongoing(_s) (_s)->state |= RTP_RELAY_SESS_STATE_ONGOING
#define rtp_sess_reset_ongoing(_s) (_s)->state &= (~RTP_RELAY_SESS_STATE_ONGOING)

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

struct rtp_relay_leg {
	str tag;
	int ref;
	int index;
	unsigned int state;
	rtp_relay_flags flags;
	struct list_head list;
	struct rtp_relay_leg *peer;
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
	int last_branch;
	unsigned dlg_id, dlg_entry;
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
int rtp_relay_get_last_branch(struct rtp_relay_ctx *ctx, struct sip_msg *msg);

struct rtp_relay_sess *rtp_relay_get_sess(struct rtp_relay_ctx *ctx, int index);

struct rtp_relay_leg *rtp_relay_get_leg(struct rtp_relay_ctx *ctx, str *tag, int idx);
struct rtp_relay_leg *rtp_relay_new_leg(struct rtp_relay_ctx *ctx, str *tag, int idx);

mi_response_t *mi_rtp_relay_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_rtp_relay_update(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_rtp_relay_update_callid(const mi_params_t *params,
								struct mi_handler *async_hdl);

str *rtp_relay_get_sdp(struct rtp_relay_session *sess, int type);
int rtp_relay_get_dlg_ids(str *callid, unsigned int *h_entry, unsigned int *h_id);

#define RTP_RELAY_CTX_LOCK(_c) lock_get(&_c->lock);
#define RTP_RELAY_CTX_UNLOCK(_c) lock_release(&_c->lock);

#define RTP_RELAY_CTX_REF_UNSAFE(_c, _v) \
	do { \
		(_c)->ref += (_v); \
		LM_DBG("reffing ref=%d for ctx=%p\n", (_c)->ref, (_c)); \
	} while (0);
#define RTP_RELAY_CTX_REF(_c) \
	do { \
		RTP_RELAY_CTX_LOCK(_c); \
		RTP_RELAY_CTX_REF_UNSAFE(_c, 1); \
		RTP_RELAY_CTX_UNLOCK(_c); \
	} while (0);
#define RTP_RELAY_CTX_UNREF(_c) \
	do { \
		RTP_RELAY_CTX_LOCK(_c); \
		RTP_RELAY_CTX_REF_UNSAFE(_c, -1); \
		RTP_RELAY_CTX_UNLOCK(_c); \
	} while (0);

extern char *rtp_relay_route_offer_name;
extern char *rtp_relay_route_answer_name;
extern char *rtp_relay_route_delete_name;
extern char *rtp_relay_route_copy_offer_name;
extern char *rtp_relay_route_copy_answer_name;
extern char *rtp_relay_route_copy_delete_name;

int rtp_relay_route_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags);
int rtp_relay_route_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *body,
		str *ip, str *type, str *in_iface, str *out_iface,
		str *global_flags, str *flags, str *extra_flags);
int rtp_relay_route_delete(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, str *flags, str *extra);
int rtp_relay_route_copy_offer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void **_ctx, str *flags,
		unsigned int copy_flags, unsigned int streams, str *body);
int rtp_relay_route_copy_answer(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags, str *body);
int rtp_relay_route_copy_delete(struct rtp_relay_session *sess,
		struct rtp_relay_server *server, void *_ctx, str *flags);

#endif /* _RTP_RELAY_CTX_H_ */
