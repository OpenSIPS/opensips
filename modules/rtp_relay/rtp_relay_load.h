/*
 * Copyright (C) 2021 OpenSIPS Solutions
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
 
 */

#ifndef _RTP_RELAY_LOAD_H_
#define _RTP_RELAY_LOAD_H_

#include "../../str.h"
#include "../../sr_module.h"
#include "../../bin_interface.h"
#include "rtp_relay_common.h"
struct dlg_cell;

typedef void * rtp_ctx;

struct rtp_relay_binds {
	rtp_ctx (*get_ctx)(void);
	rtp_ctx (*get_ctx_dlg)(struct dlg_cell *);
	int (*offer)(rtp_ctx ctx, str *id, unsigned int flags, str *body);
	int (*answer)(rtp_ctx ctx, str *id, unsigned int flags, str *body);
	int (*delete)(rtp_ctx ctx, str *id, unsigned int flags);
	int (*copy_offer)(rtp_ctx ctx, str *id, str *flags,
			unsigned int copy_flags, unsigned int streams, str *ret_body);
	int (*copy_answer)(rtp_ctx ctx, str *id,
			str *flags, str *body);
	int (*copy_delete)(rtp_ctx ctx, str *id,
			str *flags);
};

typedef int (*load_rtp_relay_f)(struct rtp_relay_binds *rtpb);

static inline int load_rtp_relay(struct rtp_relay_binds *rtpb)
{
	load_rtp_relay_f load_rtp_relay;

	/* import the rtp_relay auto-loading function */
	if ( !(load_rtp_relay=(load_rtp_relay_f)find_export("load_rtp_relay", 0)))
		return -1;

	/* let the auto-loading function load all rtp_relay stuff */
	if (load_rtp_relay(rtpb) == -1)
		return -1;

	return 0;
}

int rtp_relay_load(struct rtp_relay_binds *binds);
rtp_ctx rtp_relay_get_context(void);
rtp_ctx rtp_relay_get_context_dlg(struct dlg_cell *);
int rtp_relay_api_offer(rtp_ctx ctx, str *id, unsigned int flags, str *body);
int rtp_relay_api_answer(rtp_ctx ctx, str *id, unsigned int flags, str *body);
int rtp_relay_api_delete(rtp_ctx ctx, str *id, unsigned int flags);
int rtp_relay_copy_offer(rtp_ctx ctx, str *id, str *flags,
		unsigned int copy_flags, unsigned int streams, str *ret_body);
int rtp_relay_copy_answer(rtp_ctx ctx, str *id,
		str *flags, str *body);
int rtp_relay_copy_delete(rtp_ctx ctx, str *id,
		str *flags);

#endif /* _RTP_RELAY_LOAD_H_ */
