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
 * ---------
 *  2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 */


#ifndef _CANCEL_H
#define _CANCEL_H

/* a buffer is empty but cannot be used by anyone else;
   particularly, we use this value in the buffer pointer
   in local_buffer to tell "a process is already scheduled
   to generate a CANCEL, other processes are not supposed to"
   (which might happen if for example in a three-branch forking,
   two 200 would enter separate processes and compete for
   canceling the third branch); note that to really avoid
   race conditions, the value must be set in REPLY_LOCK
*/

#define BUSY_BUFFER ((char *)-1)

#define CANCEL_REASON_200  \
	"Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\"" CRLF


void which_cancel( struct cell *t, branch_bm_t *cancel_bm );
void cancel_uacs( struct cell *t, branch_bm_t cancel_bm );
void cancel_branch( struct cell *t, int branch );

int unixsock_uac_cancel(str* msg);

typedef int (*tcanceltrans_f)(struct cell *t, str *hdrs);

char *build_cancel(struct cell *Trans,unsigned int branch,
	unsigned int *len );

inline static short should_cancel_branch( struct cell *t, int b )
{
	/* cancel only if provisional received and no one else
	   attempted to cancel yet; also skip PHONY branches
	   (they have no signaling, so no canceling */
	if ( t->uac[b].local_cancel.buffer.s==NULL &&
	(t->uac[b].flags & T_UAC_IS_PHONY)==0 ) {
		if ( t->uac[b].last_received<200 ) {
			/* we'll cancel -- label it so that no one else
			(e.g. another 200 branch) will try to do the same */
			t->uac[b].local_cancel.buffer.s=BUSY_BUFFER;
			return 1;
		}
	}
	return 0;
}

extern str _extra_cancel_hdrs;

static inline void set_cancel_extra_hdrs( char *s, int l)
{
	_extra_cancel_hdrs.s = s;
	_extra_cancel_hdrs.len = l;
}


#endif
