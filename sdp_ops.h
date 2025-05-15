/*
 * Copyright (C) 2024-2025 OpenSIPS Solutions
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
 */

#ifndef __SDP_OPS_H__
#define __SDP_OPS_H__

#include "pvar.h"

#define SDP_OPS_FL_DIRTY  (1<<0) /* the SDP buffer requires a rebuild */
#define SDP_OPS_FL_NULL   (1<<1) /* the message has no SDP body */

struct sdp_chunk_match {
	str prefix;
	int idx;
};

struct sdp_pv_param {
	struct sdp_chunk_match match_stream;
	struct sdp_chunk_match match_line;
	struct sdp_chunk_match match_token;
};

struct sdp_body_part_ops {
	str content_type;
	str sdp;

	int flags;  /* e.g. SDP_OPS_FL_DIRTY */
};

void free_sdp_ops(struct sdp_body_part_ops *ops);

int pv_set_sdp(struct sip_msg *msg, pv_param_t *param, int op, pv_value_t *val);
int pv_parse_sdp_name(pv_spec_p sp, const str *in);

int pv_get_sdp_line(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_sdp_line(struct sip_msg *msg, pv_param_t *param, int op, pv_value_t *val);
int pv_parse_sdp_line_name(pv_spec_p sp, const str *in);

int pv_get_sdp_stream(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_sdp_stream(struct sip_msg *msg, pv_param_t *param, int op, pv_value_t *val);
int pv_parse_sdp_stream_name(pv_spec_p sp, const str *in);

int pv_get_sdp_session(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_sdp_session(struct sip_msg *msg, pv_param_t *param, int op, pv_value_t *val);
int pv_parse_sdp_session_name(pv_spec_p sp, const str *in);

#endif /* __SDP_OPS_H__ */
