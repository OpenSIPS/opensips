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
 *
 */

#ifndef _PROTO_MSRP_MSRP_API_H_
#define _PROTO_MSRP_MSRP_API_H_

#include "../../sr_module.h"

#include "msrp_parser.h"
#include "msrp_handler.h"

typedef void* (*register_msrp_handler_f)( str *req_host_filter,
		int req_port_filter, int req_secured_filter,
		msrp_req_handler_f req_f, msrp_rpl_handler_f rpl_f,
		void *param);

typedef int (*send_reply_f)( void *hdl, struct msrp_msg *req,
		int code, str* reason,
		str *hdrs, int hdrs_no);

typedef int (*send_reply_on_cell_f)( void *hdl, struct msrp_cell *cell,
		int code, str* reason,
		str *hdrs, int hdrs_no);

typedef int (*fwd_request_f)( void *hdl, struct msrp_msg *req,
		str *hdrs, int hdrs_no);

typedef int (*fwd_reply_f)( void *hdl, struct msrp_msg *rpl,
		struct msrp_cell *cell);


struct msrp_binds {
	register_msrp_handler_f  register_msrp_handler;
	send_reply_f             send_reply;
	send_reply_on_cell_f     send_reply_on_cell;
	fwd_request_f            forward_request;
	fwd_reply_f              forward_reply;
};

void load_msrp( struct msrp_binds *binds);

typedef void (*load_msrp_f)(struct msrp_binds *binds);

static inline int load_msrp_api(struct msrp_binds *binds) {
	load_msrp_f load_msrp;

	/* import the msrp auto-loading function */
	if (!(load_msrp = (load_msrp_f) find_export("load_msrp", 0)))
		return -1;

	/* let the auto-loading function load all msrp API functions */
	load_msrp(binds);

	return 0;
}

#endif
