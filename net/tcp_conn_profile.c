/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "tcp_conn_profile.h"
#include "../str.h"
#include "../ut.h"

/* a collection of default TCP connection settings which can be overridden
 * by defining specific settings (per TCP path) using the "tcp_mgm" module */
struct tcp_conn_profile tcp_con_df_profile;

static int tcp_con_get_df_profile(union sockaddr_union *_,
        union sockaddr_union *__, enum sip_protos ___,
        struct tcp_conn_profile *out_profile)
{
	*out_profile = tcp_con_df_profile;
	return 0;
}


/* global function/variable which may be overridden by tcp_mgm */
int (*tcp_con_get_profile)(union sockaddr_union *remote,
         union sockaddr_union *local, enum sip_protos proto,
         struct tcp_conn_profile *out_profile) = tcp_con_get_df_profile;

struct tcp_conn_attr_key tcp_con_attr[] = {
	{str_init("max_msg_chunks"), TCP_ATTR_MAX_MSG_CHUNKS},
	{STR_NULL, 0},
};

int tcp_con_attr_lookup(const str *attr, enum tcp_conn_attr *out_val)
{
	struct tcp_conn_attr_key *it;

	for (it = tcp_con_attr; it->attr_key.s; it++)
		if (str_match(&it->attr_key, attr)) {
			*out_val = it->attr;
			return 1;
		}

	return 0;
}

void tcp_init_con_profiles(void)
{
	/* fill in a default profile, which simply gathers all TCP globals */
	tcp_con_df_profile = (struct tcp_conn_profile){
		.connect_timeout  = tcp_connect_timeout,
		.con_lifetime     = tcp_con_lifetime,
		.msg_read_timeout = tcp_max_msg_time,
		.send_threshold   = tcpthreshold,
		.no_new_conn      = 0, /* by default, the only way to enforce
		                         no-new-conn is via br/rpl flags */
		.alias_mode       = tcp_accept_aliases,
		.parallel_read    = tcp_parallel_read_on_workers,
		.keepalive        = tcp_keepalive,
		.keepcount        = tcp_keepcount,
		.keepidle         = tcp_keepidle,
		.keepinterval     = tcp_keepinterval,

		.id               = 0,
	};

	tcp_init_attrs(tcp_con_df_profile.attrs);
}
