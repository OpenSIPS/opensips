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



#ifndef _PROTO_MSRP_MSRP_SIGNALING_H_
#define _PROTO_MSRP_MSRP_SIGNALING_H_

#include "msrp_parser.h"

int msrp_send_reply( struct msrp_msg *req, int code, str* reason,
		str *hdrs, int hdrs_no);

int msrp_fwd_request( struct msrp_msg *req,
		str *hdrs, int hdrs_no);

int msrp_fwd_reply( struct msrp_msg *rpl);

#endif
