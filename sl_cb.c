/*
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-02-01  first version (bogdan)
 */


#include "mem/mem.h"
#include "sl_cb.h"


struct sl_callback {
	sl_cb_t* callback;         /* callback function */
	unsigned int fmask;        /* bitmask to match msg_flags */
	struct sl_callback* next;  /* next callback element*/
};

struct sl_callback* slcb_hl[SLCB_LAST];  /* heads of lists (per type) */



void destroy_slcb_lists(void)
{
	struct sl_callback *cbp, *cbp_tmp;
	unsigned int i;

	for( i=0 ; i<SLCB_LAST ; i++) {
		for( cbp=slcb_hl[i]; cbp ; ) {
			cbp_tmp = cbp;
			cbp = cbp->next;
			pkg_free( cbp_tmp );
		}
	}
}


int register_slcb(enum sl_cb_type type, unsigned int fmask, sl_cb_t f)
{
	struct sl_callback *cbp;

	/* build a new callback structure */
	if (!(cbp=pkg_malloc( sizeof( struct sl_callback)))) {
		LM_ERR("out of pkg. mem\n");
		return -1;
	}

	/* fill it up */
	cbp->callback = f;
	cbp->fmask = fmask;
	/* link it at the beginning of the list */
	cbp->next = slcb_hl[type];
	slcb_hl[type] = cbp;

	return 0;
}


void slcb_run_reply_out(struct sip_msg *req, str *buffer,
									union sockaddr_union *dst, int rpl_code)
{
	struct sl_callback *cbp;

	for ( cbp=slcb_hl[SLCB_REPLY_OUT] ; cbp ; cbp=cbp->next ) {
		if (cbp->fmask==0 || cbp->fmask&req->msg_flags) {
			cbp->callback( req, buffer, rpl_code, dst, NULL, 0);
		}
	}
}


void slcb_run_ack_in(struct sip_msg *req)
{
	struct sl_callback *cbp;

	for ( cbp=slcb_hl[SLCB_ACK_IN] ; cbp ; cbp=cbp->next ) {
		if (cbp->fmask==0 || cbp->fmask&req->msg_flags) {
			cbp->callback( req, NULL, 0, NULL, NULL, 0);
		}
	}
}


void slcb_run_req_out(struct sip_msg *req, str *buffer,
			union sockaddr_union *dst, struct socket_info *sock, int proto)
{
	struct sl_callback *cbp;

	for ( cbp=slcb_hl[SLCB_REQUEST_OUT] ; cbp ; cbp=cbp->next ) {
		if (cbp->fmask==0 || cbp->fmask&req->msg_flags) {
			cbp->callback( req, buffer, 0, dst, sock, proto);
		}
	}
}


