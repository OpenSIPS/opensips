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

#include "../../str.h"
#include "../../lib/list.h"
#include "../../parser/msg_parser.h"
#include "../rtpproxy/rtpproxy_load.h"

struct src_sess;

struct srs_sdp_stream {
	int label;
	str body;
	struct list_head list;
};

struct srs_sdp {
	time_t ts;
	int version;
	int stream_no;
	struct list_head streams;
};

int srs_init_sdp_body(struct srs_sdp *body);
void srs_free_stream(struct srs_sdp_stream *stream);
void srs_free_body(struct srs_sdp *body);

int srs_get_body(struct src_sess *sess, struct srs_sdp *sdp, str *body);
int srs_add_sdp_streams(struct sip_msg *msg, struct srs_sdp *sdp);


#endif /* _SIPREC_BODY_H_ */
