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


struct msrp_cell {
	unsigned short hash;
	str ident;
	str from_full;
	str to_top;
	str message_id;
	str byte_range;
	str failure_report;
	void *msrp_hdl;
	struct msrp_cell *expired_next;
};


extern unsigned int msrp_ident_hash_size;

int msrp_init_trans_layer(void);

int msrp_destroy_trans_layer(void);

int msrp_send_reply( void *hdl, struct msrp_msg *req, int code, str* reason,
		str *hdrs, int hdrs_no);

int msrp_fwd_request( void *hdl, struct msrp_msg *req,
		str *hdrs, int hdrs_no);

int msrp_fwd_reply( void *hdl, struct msrp_msg *rpl);

#endif
