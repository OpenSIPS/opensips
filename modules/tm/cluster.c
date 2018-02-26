/*
 * Copyright (C) 2018 OpenSIPS Project
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
 */

#include "cluster.h"
#include "../../ut.h"

str tm_cid;
int tm_repl_cluster = 0;
str tm_cluster_param = str_init(TM_CLUSTER_DEFAULT_PARAM);
static str tm_repl_cap = str_init("tm-repl");

struct clusterer_binds cluster_api;

static void receive_tm_repl(bin_packet_t *packet)
{
	if (packet->type != TM_CLUSTER_TYPE) {
		LM_WARN("Invalid tm binary packet command: %d (from node: %d in cluster: %d)\n",
			packet->type, packet->src_id, tm_repl_cluster);
		return;
	}
}

int tm_init_cluster(void)
{
	str cid;

	if (tm_repl_cluster == 0) {
		LM_DBG("tm_replication_cluster not set - not engaging!\n");
		return 0;
	}

	/* fix clusterer param */
	tm_cluster_param.len = strlen(tm_cluster_param.s);

	if (tm_repl_cluster < 0) {
		LM_ERR("Invalid value for tm_replication_cluster must be "
			"a positive cluster id\n");
		return -1;
	}

	if (load_clusterer_api(&cluster_api) < 0) {
		LM_WARN("failed to load clusterer API - is the clusterer module loaded?\n");
		return -1;
	}
	if (cluster_api.register_capability(&tm_repl_cap, receive_tm_repl, NULL,
			tm_repl_cluster) < 0) {
		LM_ERR("cannot register tm bin processing function\n");
		/* overwrite structure to disable clusterer */
		goto cluster_error;
	}

	/* build the via param */
	cid.s = int2str(tm_repl_cluster, &cid.len);
	tm_cid.s = pkg_malloc(1/*;*/ + tm_cluster_param.len + 1/*=*/ + cid.len);
	if (!tm_cid.s) {
		LM_ERR("out of pkg memory!\n");
		goto cluster_error;
	}
	tm_cid.len = 0;
	tm_cid.s[tm_cid.len++] = ';';
	memcpy(tm_cid.s + tm_cid.len, tm_cluster_param.s, tm_cluster_param.len);
	tm_cid.len += tm_cluster_param.len;
	tm_cid.s[tm_cid.len++] = '=';
	memcpy(tm_cid.s + tm_cid.len, cid.s, cid.len);
	tm_cid.len += cid.len;

	return 0;

cluster_error:
	cluster_api.register_capability = 0;
	return -1;
}
