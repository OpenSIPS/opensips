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



#ifndef _PROTO_MSRP_MSRP_HANDLER_H_
#define _PROTO_MSRP_MSRP_HANDLER_H_

#include "../../ip_addr.h"
#include "msrp_parser.h"
#include "msrp_signaling.h"

typedef int (*msrp_req_handler_f) (struct msrp_msg *req,
		void *hdl_param);

typedef int (*msrp_rpl_handler_f) (struct msrp_msg *rpl,
		struct msrp_cell *tran, void *trans_param,
		void *hdl_param);



void* register_msrp_handler( str *host_filter, int port_filter,
		int secured_filter, msrp_req_handler_f req_f,
		msrp_rpl_handler_f rpl_f, void *hdl_param);

int handle_msrp_msg(char* buf, int len, struct msrp_firstline *fl, str *body,
		struct receive_info *local_rcv);

void handle_msrp_timeout( struct msrp_cell *list);

#endif
