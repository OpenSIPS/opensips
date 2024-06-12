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

#ifndef _RTP_RELAY_H_
#define _RTP_RELAY_H_

#include "../../str.h"
#include "../../sr_module.h"
#include "../../lib/list.h"
#include "../../bin_interface.h"
#include "rtp_relay_common.h"

#define RTP_RELAY_ALL_BRANCHES -1

struct rtp_relay_session {
	struct sip_msg *msg;
	int branch;
	str *callid;
	str *from_tag;
	str *to_tag;
	str *body;
};

struct rtp_relay_server {
	int set;
	str node;
};

struct rtp_relay_funcs {
	int (*offer)(struct rtp_relay_session *sess,
			struct rtp_relay_server *server, str *body,
			str *ip, str *type, str *in_iface, str *out_iface,
			str *global_flags, str *flags, str *extra_flags);
	int (*answer)(struct rtp_relay_session *sess,
			struct rtp_relay_server *server, str *body,
			str *ip, str *type, str *in_iface, str *out_iface,
			str *global_flags, str *flags, str *extra_flags);
	int (*delete)(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *flags, str *extra);

	int (*copy_offer)(struct rtp_relay_session *sess,
			struct rtp_relay_server *server, void **ctx, str *flags,
			unsigned int copy_flags, unsigned int streams, str *ret,
			struct rtp_relay_streams *streams_map);
	int (*copy_answer)(struct rtp_relay_session *sess,
			struct rtp_relay_server *server, void *ctx,
			str *flags, str *body);
	int (*copy_delete)(struct rtp_relay_session *sess,
			struct rtp_relay_server *server, void *ctx, str *flags);
	int (*copy_serialize)(void *ctx, bin_packet_t *packet);
	int (*copy_deserialize)(void **ctx, bin_packet_t *packet);
	void (*copy_release)(void **ctx);
};

struct rtp_relay_hooks {
	str * (*get_sdp)(struct rtp_relay_session *sess, int type);
	int (*get_dlg_ids)(str *callid, unsigned int *h_entry, unsigned int *h_id);
};

struct rtp_relay {
	str name;
	struct rtp_relay_funcs funcs;
	struct list_head list;
	char _name_s[0];
};

typedef int (*reg_rtp_relay_f)(const char *, struct rtp_relay_funcs *,
		struct rtp_relay_hooks *hooks);
struct rtp_relay *rtp_relay_get(str *name);
int rtp_relay_reg(char *name, struct rtp_relay_funcs *funcs,
		struct rtp_relay_hooks *hooks);

static inline int register_rtp_relay(const char *name,
		struct rtp_relay_funcs *funcs, struct rtp_relay_hooks *hooks)
{
	reg_rtp_relay_f func;

	/* import the rtpproxy auto-loading function */
	if (!(func=(reg_rtp_relay_f)find_export("register_rtp_relay", 0)))
		return -1;

	return func(name, funcs, hooks);
}

/* macro used for internal debugging */
#ifdef RTP_RELAY_DEBUG
#define LM_RTP_DBG(...) LM_DBG("RTP: " __VA_ARGS__);
#else
#define LM_RTP_DBG(...)
#endif

#endif /* _RTP_RELAY_H_ */
