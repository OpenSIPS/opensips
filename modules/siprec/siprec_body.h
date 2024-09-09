/*
 * Copyright (C) 2017 OpenSIPS Project
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
 *
 *
 * History:
 * ---------
 *  2017-06-20  created (razvanc)
 */

#ifndef _SIPREC_BODY_H_
#define _SIPREC_BODY_H_

#include "../../ut.h"
#include "../../str.h"
#include "../../lib/list.h"
#include "../../parser/msg_parser.h"
#include "../rtp_relay/rtp_relay_load.h"
#include "siprec_uuid.h"

extern struct rtp_relay_binds srec_rtp;
extern int siprec_port_min;
extern int siprec_port_max;

struct src_sess;
struct src_part;

struct srs_sdp_stream {
	int label;
	int port;
	int inactive;
	int medianum;
	siprec_uuid uuid;
	struct list_head list;
};

void srs_free_stream(struct srs_sdp_stream *stream);

int srs_fill_sdp_stream(int label, int medianum, siprec_uuid *uuid,
		struct src_sess *sess, struct src_part *part);
int srs_build_body(struct src_sess *sess, str *sdp, str *body);

int srs_handle_media(struct sip_msg *msg, struct src_sess *sess);

int srs_build_default_name(struct to_body *body);

#endif /* _SIPREC_BODY_H_ */
