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

#include "pvar.h"
#include "sdp_ops.h"
#include "ut.h"
#include "parser/sdp/sdp.h"

int pv_set_sdp(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	struct sdp_body_part_ops *ops;
	int null_before = 0;

	if (!msg || !param) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (!msg->sdp_ops) {
		ops = pkg_malloc(sizeof *ops);
		if (!ops) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(ops, 0, sizeof *ops);
		msg->sdp_ops = ops;
	} else {
		ops = msg->sdp_ops;
	}

	if (!val) {
		LM_ERR("sdp-set: NULL\n");
		ops->flags |= SDP_OPS_FL_NULL;
		if (msg->body) {
			free_sip_body(msg->body);
			msg->body = NULL;
		}

	} else {
		LM_ERR("sdp-set: non-NULL!\n");

		if (!(val->flags & PV_VAL_STR) || val->rs.len <= 0) {
			LM_ERR("non-empty str value required to set SDP body\n");
			goto error;
		}

		if (pkg_str_sync(&ops->sdp, &val->rs) != 0) {
			LM_ERR("oom\n");
			return -1;
		}

		if (ops->flags & SDP_OPS_FL_NULL) {
			null_before = 1;
			ops->flags &= ~SDP_OPS_FL_NULL;
		}

		if (msg->body) {
			free_sip_body(msg->body);
			msg->body = NULL;
		}

		if (parse_sip_body(msg) != 0) {
			LM_ERR("bad body provided (%.*s ...), refusing to set in SIP msg\n",
			        val->rs.len>=40 ? 40:val->rs.len, val->rs.s);
			pkg_free(ops->sdp.s);
			ops->sdp = STR_NULL;
			if (null_before)
				ops->flags |= SDP_OPS_FL_NULL;
			return -1;
		}

		if (!parse_sdp(msg)) {
			LM_ERR("bad SDP provided (%.*s ...), refusing to set in SIP msg\n",
			        val->rs.len>=40 ? 40:val->rs.len, val->rs.s);
			free_sip_body(msg->body);
			msg->body = NULL;
			pkg_free(ops->sdp.s);
			ops->sdp = STR_NULL;
			if (null_before)
				ops->flags |= SDP_OPS_FL_NULL;
			return -1;
		}

		ops->flags &= ~SDP_OPS_FL_NULL;
	}

	return 0;
error:
	return -1;
}


void free_sdp_ops(struct sdp_body_part_ops *ops)
{
	if (!ops)
		return;

	pkg_free(ops->sdp.s);
	pkg_free(ops);
}
