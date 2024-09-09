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


typedef struct lb_param_prob_callback {
	unsigned int  id;
}lb_param_prob_callback_t;


static void lb_probing_callback( struct cell *t, int type,
		struct tmcb_params *ps )
{
	int id;

	if (!*ps->param) {
		LM_CRIT("BUG - reply to a LB probe with no ID (code=%d)\n", ps->code);
		return;
	}
	id = ((lb_param_prob_callback_t*)*ps->param)->id;

	set_dst_state_from_rplcode( id, ps->code);

	return;
}



void lb_do_probing(struct lb_data *data)
{
	struct gw_prob_pack {
		/* IMPORTANT, this member must be the first, as we use its pointer
		 * to free the whole structure here */
		lb_param_prob_callback_t params;

		str uri;

		struct gw_prob_pack *next;
	};
	struct lb_dst *dst;
	struct gw_prob_pack *pack, *pack_last, *pack_head;

	if ( !lb_cluster_shtag_is_active() )
		return;

	pack_last = pack_head = NULL;

	lock_start_read( ref_lock );

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

		/* build its pack, so we can build and send the prob later */
		pack = shm_malloc(sizeof(struct gw_prob_pack)+dst->uri.len);
		if( pack==0 ) {
			LM_ERR("no more shm memory!\n");
			/* send whatever probs we have so far */
			break;
		}

		pack->uri.s = (char*)(pack+1);
		memcpy(pack->uri.s, dst->uri.s, dst->uri.len);
		pack->uri.len = dst->uri.len;
		pack->next = NULL;

		pack->params.id = dst->id;

		if (pack_head==NULL) {
			pack_head = pack_last = pack;
		} else {
			pack_last->next = pack;
			pack_last = pack;
		}

	}

	lock_stop_read( ref_lock );

	/* now send all the probs, outside the lock */
	for( pack = pack_head ; pack ; pack=pack_last ) {

		pack_last = pack->next;

		if (lb_tmb.t_request( &lb_probe_method, &pack->uri, &pack->uri,
		&lb_probe_from, NULL, NULL, NULL, lb_probing_callback,
		(void*)(long)pack, osips_shm_free) < 0) {
			LM_ERR("probing failed\n");
			shm_free(pack);
		}

	}

}
