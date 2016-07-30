/*
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2005-08-02  first version (bogdan)
 */

/*!
 * \file
 * \brief Route & Record-Route module, callback API
 * \ingroup rr
 */

#include "../../mem/mem.h"
#include "rr_cb.h"


struct rr_callback* rrcb_hl = 0;  /* head list */



void destroy_rrcb_lists(void)
{
	struct rr_callback *cbp, *cbp_tmp;

	for( cbp=rrcb_hl; cbp ; ) {
		cbp_tmp = cbp;
		cbp = cbp->next;
		pkg_free( cbp_tmp );
	}
}


int register_rrcb( rr_cb_t f, void *param, short prior )
{
	struct rr_callback *cbp, *rcbp;

	/* build a new callback structure */
	if (!(cbp=pkg_malloc( sizeof( struct rr_callback)))) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	if (prior < 0) {
		LM_ERR("negative priority not allowed\n");
		return -1;
	}

	/* fill it up */
	cbp->callback = f;
	cbp->param = param;
	cbp->id = prior;

	if (!rrcb_hl || !prior || (prior < rrcb_hl->id)) {
		/* link it at the beginning of the list */
		cbp->next = rrcb_hl;
		rrcb_hl = cbp;
	} else {
		rcbp = rrcb_hl;
		while (rcbp->next && rcbp->next->id < prior)
			rcbp = rcbp->next;
		cbp->next = rcbp->next;
		rcbp->next = cbp;
	}

	return 0;
}


void run_rr_callbacks( struct sip_msg *req, str *rr_params )
{
	str l_param;
	struct rr_callback *cbp;

	for ( cbp=rrcb_hl ; cbp ; cbp=cbp->next ) {
		l_param = *rr_params;
		LM_DBG("callback id %d entered with <%.*s>\n",
			cbp->id , l_param.len,l_param.s);
		cbp->callback( req, &l_param, cbp->param );
	}
}



