/*
 * transaction maintenance functions
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 *  2003-03-31  200 for INVITE/UAS resent even for UDP (jiri)
 *               info only if compiling w/ -DEXTRA_DEBUG (andrei)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-13  send_pr_buffer is called w/ file/function/line debugging
 *  2003-03-01  start_retr changed to retransmit only for UDP
 *  2003-02-13  modified send_pr_buffer to use msg_send & rb->dst (andrei)
 *  2003-04-14  use protocol from uri (jiri)
 *  2003-04-25  do it (^) really everywhere (jiri)
 *  2003-04-26  do it (^) really really really everywhere (jiri)
 *  2003-07-07  added get_proto calls when proxy!=0 (andrei)
 *  2004-02-13  t->is_invite and t->local replaced with flags (bogdan)
 *  2005-02-16  fr_*_timer acceps full AVP specifications; empty AVP
 *              desable variable timer feature (bogdan)
 *  2007-01-25  DNS failover at transaction level added (bogdan)
 */

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "../../dprint.h"
#include "../../hash_func.h"
#include "../../dset.h"
#include "../../mem/mem.h"
#include "t_funcs.h"
#include "t_fwd.h"
#include "t_msgbuilder.h"
#include "t_lookup.h"
#include "config.h"
#include "../../context.h"

static str relay_reason_100 = str_init("Giving a try");


/* ----------------------------------------------------- */
int send_pr_buffer( struct retr_buf *rb, void *buf, int len,
#ifdef EXTRA_DEBUG
					char* file, const char *function, int line,
#endif
					void* ctx)
{
	if (buf && len && rb )
		return msg_send( rb->dst.send_sock, rb->dst.proto, &rb->dst.to,
				         rb->dst.proto_reserved1, buf, len, ctx);
	else {
#ifdef EXTRA_DEBUG
		LM_CRIT("sending an empty buffer from %s: %s (%d)\n",file,
				function, line);
#else
		LM_CRIT("attempt to send an empty buffer\n");
#endif
		return -1;
	}
}



void tm_shutdown(void)
{

	LM_DBG("tm_shutdown : start\n");
	unlink_timer_lists();

	/* destroy the hash table */
	LM_DBG("emptying hash table\n");
	free_hash_table( );
	LM_DBG("releasing timers\n");
	free_timer_table();
	LM_DBG("removing semaphores\n");
	lock_cleanup();
	LM_DBG("destroying callback lists\n");
	destroy_tmcb_lists();
	LM_DBG("tm_shutdown : done\n");
}


/*   returns 1 if everything was OK or -1 for error
*/
int t_release_transaction( struct cell *trans )
{
	set_kr(REQ_RLSD);

	reset_timer( & trans->uas.response.fr_timer );
	reset_timer( & trans->uas.response.retr_timer );

	cleanup_uac_timers( trans );

	put_on_wait( trans );
	return 1;
}


/* -----------------------HELPER FUNCTIONS----------------------- */


/*
  */
void put_on_wait(  struct cell  *Trans  )
{

#ifdef EXTRA_DEBUG
	LM_DBG("put on WAIT \n");
#endif


	/* we put the transaction on wait timer; we do it only once
	   in transaction's timelife because putting it multiple-times
	   might result in a second instance of a wait timer to be
	   set after the first one fired; on expiration of the second
	   instance, the transaction would be re-deleted

			PROCESS1		PROCESS2		TIMER PROCESS
		0. 200/INVITE rx;
		   put_on_wait
		1.					200/INVITE rx;
		2.									WAIT fires; transaction
											about to be deleted
		3.					avoid putting
							on WAIT again
		4.									WAIT timer executed,
											transaction deleted
	*/
	set_1timer( &Trans->wait_tl, WT_TIMER_LIST, 0 );
}



static int kill_transaction( struct cell *trans )
{
	char err_buffer[128];
	int sip_err;
	int reply_ret;
	int ret;
	str reason;

	/*  we reply statefully and enter WAIT state since error might
		have occurred in middle of forking and we do not
		want to put the forking burden on upstream client;
		however, it may fail too due to lack of memory */

	ret=err2reason_phrase( ser_error, &sip_err,
		err_buffer, sizeof(err_buffer), "TM" );
	if (ret>0) {
		reason.s = err_buffer;
		reason.len = ret;
		reply_ret=t_reply( trans, trans->uas.request, sip_err, &reason);
		/* t_release_transaction( T ); */
		return reply_ret;
	} else {
		LM_ERR("err2reason failed\n");
		return -1;
	}
}



int t_relay_to( struct sip_msg  *p_msg , struct proxy_l *proxy, int flags)
{
	int ret;
	int new_tran;
	int reply_ret;
	struct cell *t;
	context_p ctx_backup;

	ret=0;

	new_tran = t_newtran( p_msg, 1/*full UAS cloning*/ );

	/* parsing error, memory alloc, whatever ... */
	if (new_tran<0) {
		ret =  new_tran;
		goto done;
	}
	/* if that was a retransmission, break from script */
	if (new_tran==0) {
		goto done;
	}

	/* new transaction */

	/* ACKs do not establish a transaction and are fwd-ed statelessly */
	if ( p_msg->REQ_METHOD==METHOD_ACK) {
		LM_DBG("forwarding ACK\n");
		/* send it out */
		if (proxy==0) {
			proxy=uri2proxy(GET_NEXT_HOP(p_msg),
				p_msg->force_send_socket ?
				p_msg->force_send_socket->proto : PROTO_NONE );
			if (proxy==0) {
					ret=E_BAD_ADDRESS;
					goto done;
			}
			ret=forward_request( p_msg , proxy);
			if (ret>=0) ret=1;
			free_proxy( proxy );
			pkg_free( proxy );
		} else {
			ret=forward_request( p_msg , proxy);
			if (ret>=0) ret=1;
		}
		goto done;
	}

	/* if replication flag is set, mark the transaction as local
	   so that replies will not be relaied */
	t=get_t();
	if (flags&TM_T_REPLY_repl_FLAG) t->flags|=T_IS_LOCAL_FLAG;
	if (flags&TM_T_REPLY_nodnsfo_FLAG) t->flags|=T_NO_DNS_FAILOVER_FLAG;
	if (flags&TM_T_REPLY_reason_FLAG) t->flags|=T_CANCEL_REASON_FLAG;

	/* INVITE processing might take long, particularly because of DNS
	   look-ups -- let upstream know we're working on it */
	if ( p_msg->REQ_METHOD==METHOD_INVITE &&
	!(flags&(TM_T_REPLY_no100_FLAG|TM_T_REPLY_repl_FLAG)) ) {
		ctx_backup = current_processing_ctx;
		current_processing_ctx = NULL;
		t_reply( t, p_msg , 100 , &relay_reason_100);
		current_processing_ctx = ctx_backup;
	}

	/* now go ahead and forward ... */
	ret=t_forward_nonack( t, p_msg, proxy);
	if (ret<=0) {
		LM_DBG("t_forward_nonack returned error \n");
		/* we don't want to pass upstream any reply regarding replicating
		 * a request; replicated branch must stop at us*/
		if (!(flags&(TM_T_REPLY_repl_FLAG|TM_T_REPLY_noerr_FLAG))) {
			reply_ret = kill_transaction( t );
			if (reply_ret>0) {
				/* we have taken care of all -- do nothing in
				script */
				LM_DBG("generation of a stateful reply on error succeeded\n");
				ret=0;
			}  else {
				LM_DBG("generation of a stateful reply on error failed\n");
			}
		}
	} else {
		LM_DBG("new transaction fwd'ed\n");
	}

done:
	return ret;
}

inline void _set_fr_retr( struct retr_buf *rb, int retr )
{
	utime_t timer;

	if (retr && !rb->retr_timer.deleted) {
		rb->retr_list=RT_T1_TO_1;
		set_timer( &rb->retr_timer, RT_T1_TO_1, NULL );
	}

	if (!rb->my_T || !is_timeout_set(rb->my_T->fr_timeout))
		set_1timer(&rb->fr_timer, FR_TIMER_LIST, NULL);
	else {
		timer = rb->my_T->fr_timeout;
		set_1timer(&rb->fr_timer, FR_TIMER_LIST, &timer);
	}
}


inline void start_retr(struct retr_buf *rb)
{
	_set_fr_retr(rb, rb->dst.proto==PROTO_UDP);
}


inline void force_retr(struct retr_buf *rb)
{
	_set_fr_retr(rb, 1);
}
