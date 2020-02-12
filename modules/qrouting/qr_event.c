/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../../str.h"
#include "../../ipc.h"
#include "../../evi/evi_modules.h"

#include "qr_stats.h"
#include "qr_event.h"

str qr_event_bdst = str_init("E_QROUTING_BAD_DST");
event_id_t qr_event_bdst_id;

struct qr_event_bdst_param {
	int rule_id;
	str part;
	str dst_name;
};

static ipc_rpc_f _qr_raise_event_bad_dst;

void qr_raise_event_bad_dst(int rule_id, const str *part, const str *dst_name)
{
	struct qr_event_bdst_param *bdp;

	bdp = shm_malloc(sizeof *bdp + part->len + dst_name->len);
	if (!bdp) {
		LM_ERR("oom\n");
		return;
	}

	bdp->rule_id = rule_id;

	bdp->part.s = (char *)(bdp + 1);
	str_cpy(&bdp->part, part);

	bdp->dst_name.s = bdp->part.s + part->len;
	str_cpy(&bdp->dst_name, dst_name);

	if (ipc_dispatch_rpc(_qr_raise_event_bad_dst, bdp) != 0)
		LM_ERR("failed to raise %.*s event!\n",
		       qr_event_bdst.len, qr_event_bdst.s);
}

int qr_init_events(void)
{
	qr_event_bdst_id = evi_publish_event(qr_event_bdst);
	if (qr_event_bdst_id == EVI_ERROR) {
	    LM_ERR("cannot register %.*s event\n",
		       qr_event_bdst.len, qr_event_bdst.s);
	    return -1;
	}

	return 0;
}

void _qr_raise_event_bad_dst(int _, void *param)
{
	struct qr_event_bdst_param *bdp = (struct qr_event_bdst_param *)param;
	evi_params_p params;

	if (qr_event_bdst_id == EVI_ERROR || !evi_probe_event(qr_event_bdst_id))
		goto error0;

	params = evi_get_params();
	if (!params) {
		LM_ERR("cannot create event params\n");
		goto error0;
	}

	if (evi_param_add_str(params, &qr_param_part, &bdp->part) < 0) {
		LM_ERR("failed to prepare partition param\n");
		goto error;
	}

	if (evi_param_add_int(params, &qr_param_rule_id, &bdp->rule_id) < 0) {
		LM_ERR("failed to prepare rule_id param\n");
		goto error;
	}

	if (evi_param_add_str(params, &qr_param_dst_name, &bdp->dst_name) < 0) {
		LM_ERR("failed to prepare dst_name param\n");
		goto error;
	}

	if (evi_raise_event(qr_event_bdst_id, params))
		LM_ERR("failed to raise %.*s event\n",
		       qr_event_bdst.len, qr_event_bdst.s);

	shm_free(bdp);
	return;

error:
	evi_free_params(params);
error0:
	shm_free(bdp);
}
