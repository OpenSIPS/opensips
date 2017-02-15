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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * history:
 * ---------
 *  2017-02-15 created by Jeremy Martinez
 */

#include "../../ip_addr.h"
#include "../../ut.h"
#include "prefix_tree.h"
#include "dr_partitions.h"
#include "dr_replication.h"

str repl_dr_module_name = str_init("drouting");
struct clusterer_binds clusterer_api;

void replicate_dr_gw_status_event(pgw_t *gw, int cluster_id)
{
	if (bin_init(&repl_dr_module_name, REPL_GW_STATUS_UPDATE, BIN_VERSION) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_int(clusterer_api.get_my_id());

	bin_push_str(&gw->id);
	bin_push_int(gw->flags);

	if (clusterer_api.send_to(cluster_id, PROTO_BIN) < 0) {
		LM_ERR("replicate dr_gw_status send failed\n");
 	}
}

int replicate_gw_status_update(struct head_db * head_db_ref)
{
	static str id;
	int flags;
	pgw_t *gw;

	bin_pop_str(&id);
	bin_pop_int(&flags);

	lock_start_read(head_db_ref->ref_lock);

	gw = get_gw_by_id( (*head_db_ref->rdata)->pgw_tree, &id);
	if (gw && (gw->flags != flags))
	{
		gw->flags = flags;
		lock_stop_read(head_db_ref->ref_lock);
		return 0;
	}

	lock_stop_read(head_db_ref->ref_lock);

	return -1;
}
