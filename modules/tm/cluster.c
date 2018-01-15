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
int tm_replicate_cluster;
int tm_accept_cluster;
str tm_cluster_param = str_init(TM_CLUSTER_DEFAULT_PARAM);

struct clusterer_binds cluster_api;

int tm_init_cluster(void)
{
	str cid;

	/* fix clusterer param */
	tm_cluster_param.len = strlen(tm_cluster_param.s);

	if (tm_accept_cluster < 0) {
		LM_ERR("Invalid value for tm_accept_cluster, must be "
			"a positive cluster id\n");
		return -1;
	}

	if (tm_replicate_cluster < 0) {
		LM_ERR("Invalid value for tm_replicate_cluster, must be "
			"a positive cluster id\n");
		return -1;
	}

	if (!tm_accept_cluster && !tm_replicate_cluster)
		return 0;

	if (load_clusterer_api(&cluster_api) < 0) {
		LM_WARN("failed to load clusterer API - is the clusterer module loaded?\n");
		return -1;
	}
	if (cluster_api.register_module("tm", NULL, 0, &tm_accept_cluster, 1) < 0) {
		LM_ERR("cannot register bin processing function\n");
		/* overwrite structure to disable clusterer */
		goto cluster_error;
	}

	/* build the via param */
	cid.s = int2str(tm_replicate_cluster, &cid.len);
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
	cluster_api.register_module = 0;
	return -1;
}
