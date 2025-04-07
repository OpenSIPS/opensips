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

struct sdp_body_part_ops {
	str content_type;
	str sdp;

	int flags;  /* e.g. SDP_OPS_FL_DIRTY */
};

void free_sdp_ops(struct sdp_body_part_ops *ops);

int pv_set_sdp(struct sip_msg *msg, pv_param_t *param, int op, pv_value_t *val);

#endif /* __SDP_OPS_H__ */
