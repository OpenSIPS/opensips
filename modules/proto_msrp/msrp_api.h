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

#include "msrp_parser.h"
#include "msrp_handler.h"

typedef int (*register_req_handler_f)( str *host_filter, int port_filter,
		int secure_filter, msrp_req_handler_f f, void *param);

typedef int (*send_reply_f)( struct msrp_msg *req, int code, str* reason,
		str *hdrs, int hdrs_no);

typedef int (*fwd_request_f)( struct msrp_msg *req,
		str *hdrs, int hdrs_no);

typedef int (*fwd_reply_f)( struct msrp_msg *rpl);


struct msrp_binds {
	register_req_handler_f  register_req_handler;
	send_reply_f            send_reply;
	fwd_request_f           forward_request;
	fwd_reply_f             forward_reply;
};

void load_msrp( struct msrp_binds *binds);

#endif
