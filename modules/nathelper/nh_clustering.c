/*
 * Copyright (C) 2019 OpenSIPS Project
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "nh_clustering.h"

#define BIN_VERSION 1

/* the cluster ID  */
int nh_cluster_id = 0;

str nh_cluster_shtag = {NULL,0};

static struct clusterer_binds c_api;


int nh_cluster_shtag_is_active(void)
{
	if ( nh_cluster_id<=0 || nh_cluster_shtag.s ==NULL ||
	c_api.shtag_get(&nh_cluster_shtag,nh_cluster_id)==SHTAG_STATE_ACTIVE )
		/* no clustering support or sharing tag found active */
		return 1;

	return 0;
}


int nh_init_cluster(void)
{
	if (load_clusterer_api(&c_api)!=0) {
		LM_ERR("failed to find clusterer API - is clusterer "
			"module loaded?\n");
		return -1;
	}

	/* "register" the sharing tag */
	if (nh_cluster_shtag.s) {
		nh_cluster_shtag.len = strlen(nh_cluster_shtag.s);
		if (c_api.shtag_get( &nh_cluster_shtag, nh_cluster_id)<0) {
			LM_ERR("failed to initialized the sharing tag <%.*s>\n",
				nh_cluster_shtag.len, nh_cluster_shtag.s);
			return -1;
		}
	} else {
		nh_cluster_shtag.len = 0;
	}

	return 0;
}


