/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * ----------
 * 2003-04-14  checking if a reply sent before cancel is initiated
 *             moved here (jiri)
 * 2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 * 2004-02-13  timer_link.payload removed (bogdan)
 */

#include "t_funcs.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "t_reply.h"
#include "t_fwd.h"
#include "t_cancel.h"
#include "t_msgbuilder.h"
#include "t_lookup.h" /* for t_lookup_callid in fifo_uac_cancel */


str _extra_cancel_hdrs = {NULL,0};


/* determine which branches should be canceled; do it
   only from within REPLY_LOCK, otherwise collisions
   could occur (e.g., two 200 for two branches processed
   by two processes might concurrently try to generate
   a CANCEL for the third branch, resulting in race conditions
   during writing to cancel buffer
*/


void which_cancel( struct cell *t, branch_bm_t *cancel_bm )
{
	int i;

	for( i=t->first_branch ; i<t->nr_of_outgoings ; i++ ) {
		if (should_cancel_branch(t, i))
			*cancel_bm |= 1<<i ;

	}
}


/* cancel branches scheduled for deletion */
void cancel_uacs( struct cell *t, branch_bm_t cancel_bm )
{
	int i;

	/* cancel pending client transactions, if any */
	for( i=0 ; i<t->nr_of_outgoings ; i++ )
		if (cancel_bm & (1<<i)) {
			/* any reply actually received on this branch */
			if (t->uac[i].last_received!=0) {
				/* send a cancel out */
				cancel_branch(t, i);
			} else {
				/* if no reply received on this branch, do not send out
				 * a CANCEL as it is against RFC3261. We will eventually send
				 * one out IF we receive later a reply on this branch, so let's
				 * flag it for catching (and cancelling) such delaied replies
				 */
				t->uac[i].flags |= T_UAC_TO_CANCEL_FLAG;
			}
		}
}


void cancel_branch( struct cell *t, int branch )
{
	char *cancel;
	unsigned int len;
	struct retr_buf *crb, *irb;

	crb=&t->uac[branch].local_cancel;
	irb=&t->uac[branch].request;

#	ifdef EXTRA_DEBUG
	if (crb->buffer.s!=0 && crb->buffer.s!=BUSY_BUFFER) {
		LM_CRIT("attempt to rewrite cancel buffer failed\n");
		abort();
	}
#	endif


	cancel=build_cancel(t, branch, &len);
	if (!cancel) {
		LM_ERR("attempt to build a CANCEL failed\n");
		return;
	}
	/* install cancel now */
	crb->buffer.s=cancel;
	crb->buffer.len=len;
	crb->dst=irb->dst;
	crb->branch=branch;
	/* label it as cancel so that FR timer can better now how
	 * to deal with it */
	crb->activ_type=TYPE_LOCAL_CANCEL;

	if ( has_tran_tmcbs( t, TMCB_REQUEST_BUILT) ) {
		set_extra_tmcb_params( &crb->buffer, &crb->dst);
		run_trans_callbacks( TMCB_REQUEST_BUILT,
			t, t->uas.request, 0, 0);
	}

	LM_DBG("sending cancel...\n");
	if (t->uac[branch].br_flags & tcp_no_new_conn_bflag)
		tcp_no_new_conn = 1;
	if (SEND_BUFFER( crb )==0) {
		if ( has_tran_tmcbs( t, TMCB_MSG_SENT_OUT) ) {
			set_extra_tmcb_params( &crb->buffer, &crb->dst);
			run_trans_callbacks( TMCB_MSG_SENT_OUT,
				t, t->uas.request, 0, 0);
		}
	}
	tcp_no_new_conn = 0;

	/*sets and starts the FINAL RESPONSE timer */
	start_retr( crb );
}


char *build_cancel(struct cell *Trans,unsigned int branch,
	unsigned int *len )
{
	str method = str_init(CANCEL);
	str reason = str_init(CANCEL_REASON_200);
	str *extra = NULL;

	/* add the reason hdr, as per RFC 3326 */
	if (is_invite(Trans) && Trans->uas.status==200) {
		extra = &reason;
	} else if (_extra_cancel_hdrs.s) {
		extra = &_extra_cancel_hdrs;
	}
	return build_local( Trans, branch, &method, extra,
		NULL /*reply*/ , len );
	/* ^^^^ when CANCELing, there are 0 chances to have a reply stored into
	 * transaction ; set it NULL to avoid using the temporary stored reply 
	 * (by t_should_relay_response) which may lead into races ( building the
	 * cancel versus handling a final response in a different process )*/
}


