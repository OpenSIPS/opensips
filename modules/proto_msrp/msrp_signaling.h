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
	int method_id;
	/* the computed ident for sending the request on this transaction */
	str ident;
	/* info on where the request was recv'ed from */
	struct dest_info recv;
	/* the received/inbound ident for the request */
	str recv_ident;
	/* FROM PATH as received in the request */
	str from_full;
	/* TO PATH (only first URL) as received in the request */
	str to_top;
	str message_id;
	str byte_range;
	str failure_report;
	void *msrp_hdl;
	struct msrp_cell *expired_next;
};

extern unsigned int msrp_ident_hash_size;

typedef void (handle_trans_timeout_f)( struct msrp_cell *list);


int msrp_init_trans_layer(handle_trans_timeout_f f);

int msrp_destroy_trans_layer(void);

void msrp_free_transaction(struct msrp_cell *cell);

struct msrp_cell *msrp_get_transaction(str *ident);



int msrp_send_reply( void *hdl, struct msrp_msg *req,
		int code, str* reason,
		str *hdrs, int hdrs_no);

int msrp_send_reply_on_cell( void *hdl, struct msrp_cell *cell,
		int code, str* reason,
		str *hdrs, int hdrs_no);

int msrp_send_report(void *hdl, str *status,
		struct msrp_msg *req, struct msrp_cell *cell);

int msrp_fwd_request( void *hdl, struct msrp_msg *req,
		str *hdrs, int hdrs_no, union sockaddr_union *to_su);

int msrp_fwd_reply( void *hdl, struct msrp_msg *rpl, struct msrp_cell *cell);

#endif
