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

struct rtp_relay_binds {
	int (*offer)(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *ip, str *type, str *in_iface, str *out_iface,
			str *flags, str *extra, str *body);
	int (*answer)(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *ip, str *type, str *in_iface, str *out_iface,
			str *flags, str *extra, str *body);
	int (*delete)(struct rtp_relay_session *sess, struct rtp_relay_server *server,
			str *flags, str *extra);
};

struct rtp_relay {
	str name;
	struct rtp_relay_binds binds;
	struct list_head list;
	char _name_s[0];
};

typedef int (*reg_rtp_relay_f)(char *, struct rtp_relay_binds *);
struct rtp_relay *rtp_relay_get(str *name);
int rtp_relay_reg(char *name, struct rtp_relay_binds *binds);

static inline int register_rtp_relay(char *name, struct rtp_relay_binds *binds)
{
	reg_rtp_relay_f func;

	/* import the rtpproxy auto-loading function */
	if (!(func=(reg_rtp_relay_f)find_export("register_rtp_relay", 0)))
		return -1;

	return func(name, binds);
}

#endif /* _RTP_RELAY_H_ */
