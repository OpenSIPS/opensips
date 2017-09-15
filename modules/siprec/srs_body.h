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
#include "../rtpproxy/rtpproxy_load.h"
#include "siprec_uuid.h"

extern struct rtpproxy_binds srec_rtp;
extern int siprec_port_min;
extern int siprec_port_max;

struct src_sess;
struct src_part;

#define SRS_SDP (1 << 0)
#define SRS_XML (1 << 1)
#define SRS_BOTH (SRS_SDP|SRS_XML)

struct srs_sdp_stream {
	int label;
	int port;
	int medianum;
	str body;
	siprec_uuid uuid;
	struct list_head list;
};

void srs_free_stream(struct srs_sdp_stream *stream);

int srs_fill_sdp_stream(struct sip_msg *msg, struct src_sess *sess,
		struct src_part *part, int update);
int srs_add_raw_sdp_stream(int label, int medianum, str *body,
		siprec_uuid *uuid, struct src_sess *sess, struct src_part *part);
int srs_build_body(struct src_sess *sess, str *body, int type);

int srs_handle_media(struct sip_msg *msg, struct src_sess *sess);

int srs_build_default_name(struct to_body *body);

int srs_init(void);


#endif /* _SIPREC_BODY_H_ */
