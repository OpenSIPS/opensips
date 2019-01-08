/*
 * load balancer module - complex call load balancing
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 *
 */

#include "../../dprint.h"
#include "../tm/tm_load.h"
#include "lb_prober.h"
#include "lb_clustering.h"


extern str lb_probe_method;
extern str lb_probe_from;
extern struct tm_binds lb_tmb;


void set_dst_state_from_rplcode( int id, int code);



static void lb_probing_callback( struct cell *t, int type,
		struct tmcb_params *ps )
{
	int id;

	if (!*ps->param) {
		LM_CRIT("BUG - reply to a LB probe with no ID (code=%d)\n", ps->code);
		return;
	}
	id = (int)(long)(*ps->param);

	set_dst_state_from_rplcode( id, ps->code);

	return;
}



void lb_do_probing(struct lb_data *data)
{
	struct lb_dst *dst;

	if ( !lb_cluster_shtag_is_active() )
		return;

	/* go through all destinations */
	for( dst = data->dsts ; dst ; dst=dst->next ) {
		/* dst requires probing ? */
		if ( dst->flags&LB_DST_STAT_NOEN_FLAG
			|| !( (dst->flags&LB_DST_PING_PERM_FLAG)  ||  /*permanent probing*/
					( !(dst->flags&LB_DST_PING_DSBL_FLAG)
					&& dst->flags&LB_DST_STAT_DSBL_FLAG  /*probing on disable*/
					)
				)
			)
			continue;

		if (lb_tmb.t_request( &lb_probe_method, &dst->uri, &dst->uri,
		&lb_probe_from, NULL, NULL, NULL, lb_probing_callback,
		(void*)(long)dst->id, NULL) < 0) {
			LM_ERR("probing failed\n");
		}


	}

}
