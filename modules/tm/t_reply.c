/*
 * Copyright (C) 2010-2014 OpenSIPS Solutions
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
 * --------
 *  2003-01-19  faked lump list created in on_reply handlers
 *  2003-01-27  next baby-step to removing ZT - PRESERVE_ZT (jiri)
 *  2003-02-13  updated to use rb->dst (andrei)
 *  2003-02-18  replaced TOTAG_LEN w/ TOTAG_VALUE_LEN (TOTAG_LEN was defined
 *               twice with different values!)  (andrei)
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-03-01  kr set through a function now (jiri)
 *  2003-03-06  saving of to-tags for ACK/200 matching introduced,
 *              voicemail changes accepted, updated to new callback
 *              names (jiri)
 *  2003-03-10  fixed new to tag bug/typo (if w/o {})  (andrei)
 *  2003-03-16  removed _TOTAG (jiri)
 *  2003-03-31  200 for INVITE/UAS resent even for UDP (jiri)
 *  2003-03-31  removed msg->repl_add_rm (andrei)
 *  2003-04-05  s/reply_route/failure_route, onreply_route introduced (jiri)
 *  2003-04-14  local acks generated before reply processing to avoid
 *              delays in length reply processing (like opening TCP
 *              connection to an unavailable destination) (jiri)
 *  2003-09-11  updates to new build_res_buf_from_sip_req() interface (bogdan)
 *  2003-09-11  t_reply_with_body() reshaped to use reply_lumps +
 *              build_res_buf_from_sip_req() instead of
 *              build_res_buf_with_body_from_sip_req() (bogdan)
 *  2003-11-05  flag context updated from failure/reply handlers back
 *              to transaction context (jiri)
 *  2003-11-11: build_lump_rpl() removed, add_lump_rpl() has flags (bogdan)
 *  2003-12-04  global TM callbacks switched to per transaction callbacks
 *              (bogdan)
 *  2004-02-06: support for user pref. added - destroy_avps (bogdan)
 *  2003-11-05  flag context updated from failure/reply handlers back
 *              to transaction context (jiri)
 *  2003-11-11: build_lump_rpl() removed, add_lump_rpl() has flags (bogdan)
 *  2004-02-13: t->is_invite and t->local replaced with flags (bogdan)
 *  2004-02-18  fifo_t_reply imported from vm module (bogdan)
 *  2004-08-23  avp list is available from failure/on_reply routes (bogdan)
 *  2004-10-01  added a new param.: restart_fr_on_each_reply (andrei)
 *  2005-03-01  force for statefull replies the incoming interface of
 *              the request (bogdan)
 *  2005-03-01  local ACK sent to same address as INVITE ->
 *              all [build|send]_[local]_ack functions merged into
 *              send_ack() (bogdan)
 *  2007-01-25  DNS failover at transaction level added (bogdan)
 */


#include "../../hash_func.h"
#include "../../dprint.h"
#include "../../config.h"
#include "../../parser/parser_f.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../error.h"
#include "../../action.h"
#include "../../dset.h"
#include "../../tags.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../usr_avp.h"
#include "../../receive.h"
#include "../../msg_callbacks.h"

#include "h_table.h"
#include "t_hooks.h"
#include "t_funcs.h"
#include "t_reply.h"
#include "t_cancel.h"
#include "t_msgbuilder.h"
#include "t_lookup.h"
#include "t_fwd.h"
#include "fix_lumps.h"
#include "t_stats.h"
#include "uac.h"


/* restart fr timer on each provisional reply, default yes */
int restart_fr_on_each_reply=1;
int onreply_avp_mode = 0;

/* disable the 6xx fork-blocking - default no (as per RFC3261) */
int disable_6xx_block = 0;

/* flag for marking minor branches */
int minor_branch_flag = -1;
char *minor_branch_flag_str = 0;

/* private place where we create to-tags for replies */
char tm_tags[TOTAG_VALUE_LEN];
static str  tm_tag = {tm_tags,TOTAG_VALUE_LEN};
char *tm_tag_suffix;

static int picked_branch=-1;

/* where to go if there is no positive reply */
static int goto_on_negative=0;
/* where to go on receipt of reply */
static int goto_on_reply=0;

/* currently processed branch */
extern int _tm_branch_index;



/* returns the picked branch */
int t_get_picked_branch(void)
{
	return picked_branch;
}


/* we store the reply_route # in private memory which is
   then processed during t_relay; we cannot set this value
   before t_relay creates transaction context or after
   t_relay when a reply may arrive after we set this
   value; that's why we do it how we do it, i.e.,
   *inside*  t_relay using hints stored in private memory
   before t_relay is called
*/


void t_on_negative( unsigned int go_to )
{
	struct cell *t = get_t();

	/* in MODE_REPLY and MODE_ONFAILURE T will be set to current transaction;
	 * in MODE_REQUEST T will be set only if the transaction was already
	 * created; if not -> use the static variable */
	if (!t || t==T_UNDEFINED )
		goto_on_negative=go_to;
	else
		t->on_negative = go_to;
}


void t_on_reply( unsigned int go_to )
{
	struct cell *t = get_t();

	/* in MODE_REPLY and MODE_ONFAILURE T will be set to current transaction;
	 * in MODE_REQUEST T will be set only if the transaction was already
	 * created; if not -> use the static variable */
	if (!t || t==T_UNDEFINED ) {
		goto_on_reply=go_to;
	} else {
		if (route_type==BRANCH_ROUTE) {
			t->uac[_tm_branch_index].on_reply = go_to;
		} else {
			t->on_reply = go_to;
		}
	}
}


unsigned int get_on_negative(void)
{
	return goto_on_negative;
}
unsigned int get_on_reply(void)
{
	return goto_on_reply;
}

void tm_init_tags(void)
{
	init_tags(tm_tags, &tm_tag_suffix,
		"OpenSIPS-TM/tags", TM_TAG_SEPARATOR );
}

/* returns 0 if the message was previously acknowledged
 * (i.e., no E2EACK callback is needed) and one if the
 * callback shall be executed */
int unmatched_totag(struct cell *t, struct sip_msg *ack)
{
	struct totag_elem *i;
	str *tag;

	if (parse_headers(ack, HDR_TO_F,0)==-1 ||
				!ack->to ) {
		LM_ERR("To invalid\n");
		return 1;
	}
	tag=&get_to(ack)->tag_value;
	for (i=t->fwded_totags; i; i=i->next) {
		if (i->tag.len==tag->len
				&& memcmp(i->tag.s, tag->s, tag->len)==0) {
			LM_DBG("totag for e2e ACK found: %d\n", i->acked);
			/* to-tag recorded, and an ACK has been received for it */
			if (i->acked) return 0;
			/* to-tag recorded, but this ACK came for the first time */
			i->acked=1;
			return 1;
		}
	}
	/* surprising: to-tag never sighted before */
	return 1;
}

static inline void update_local_tags(struct cell *trans,
				struct bookmark *bm, char *dst_buffer,
				char *src_buffer /* to which bm refers */)
{
	if (bm->to_tag_val.s) {
		trans->uas.local_totag.s=bm->to_tag_val.s-src_buffer+dst_buffer;
		trans->uas.local_totag.len=bm->to_tag_val.len;
	}
}


/* append a newly received tag from a 200/INVITE to
 * transaction's set; (only safe if called from within
 * a REPLY_LOCK); it returns 1 if such a to tag already
 * exists
 */
inline static int update_totag_set(struct cell *t, struct sip_msg *ok)
{
	struct totag_elem *i, *n;
	str *tag;
	char *s;

	if (!ok->to || !ok->to->parsed) {
		LM_ERR("to not parsed\n");
		return 0;
	}
	tag=&get_to(ok)->tag_value;
	if (!tag->s) {
		LM_DBG("no tag in to\n");
		return 0;
	}

	for (i=t->fwded_totags; i; i=i->next) {
		if (i->tag.len==tag->len
				&& memcmp(i->tag.s, tag->s, tag->len) ==0 ){
			/* to tag already recorded */
#ifdef XL_DEBUG
			LM_CRIT("totag retransmission\n");
#else
			LM_DBG("totag retransmission\n");
#endif
			return 1;
		}
	}

	/* that's a new to-tag -- record it */
	shm_lock();
	n = shm_malloc_bulk(sizeof *n);
	s = shm_malloc_bulk(tag->len);
	shm_unlock();

	if (!s || !n) {
		LM_ERR("no more share memory \n");
		if (n) shm_free(n);
		if (s) shm_free(s);
		return 0;
	}
	memset(n, 0, sizeof(struct totag_elem));
	memcpy(s, tag->s, tag->len );
	n->tag.s=s;n->tag.len=tag->len;
	n->next=t->fwded_totags;
	t->fwded_totags=n;
	LM_DBG("new totag \n");
	return 0;
}


/*
 * Build and send an ACK to a negative reply
 */
static int send_ack(struct sip_msg* rpl, struct cell *trans, int branch)
{
	str method = str_init(ACK);
	str to;
	str ack_buf;

	if(parse_headers(rpl,is_local(trans)?HDR_EOH_F:(HDR_TO_F|HDR_FROM_F),0)==-1
	|| !rpl->to || !rpl->from ) {
		LM_ERR("failed to generate a HBH ACK if key HFs in reply missing\n");
		goto error;
	}
	to.s=rpl->to->name.s;
	to.len=rpl->to->len;

	ack_buf.s = is_local(trans)?
		build_dlg_ack(rpl, trans, branch, &to, (unsigned int*)&ack_buf.len):
		build_local( trans, branch, &method, NULL, rpl, (unsigned int*)&ack_buf.len );
	if (ack_buf.s==0) {
		LM_ERR("failed to build ACK\n");
		goto error;
	}

	if (trans->uac[branch].br_flags & tcp_no_new_conn_bflag)
		tcp_no_new_conn = 1;

	if(SEND_PR_BUFFER(&trans->uac[branch].request, ack_buf.s, ack_buf.len)==0){
		/* successfully sent out */
		if ( has_tran_tmcbs( trans, TMCB_MSG_SENT_OUT) ) {
			set_extra_tmcb_params( &ack_buf, &trans->uac[branch].request.dst);
			run_trans_callbacks( TMCB_MSG_SENT_OUT,
				trans, trans->uas.request, 0, 0);
		}
	}

	tcp_no_new_conn = 0;

	shm_free(ack_buf.s);

	return 0;
error:
	return -1;
}


static int _reply_light( struct cell *trans, char* buf, unsigned int len,
			 unsigned int code, char *to_tag, unsigned int to_tag_len,
			 int lock, struct bookmark *bm)
{
	struct retr_buf *rb;
	unsigned int buf_len;
	branch_bm_t cancel_bitmap = 0;
	str cb_s;

	if (!buf)
	{
		LM_DBG("response building failed\n");
		/* determine if there are some branches to be canceled */
		if ( is_invite(trans) ) {
			if (lock) LOCK_REPLIES( trans );
			which_cancel(trans, &cancel_bitmap );
			if (lock) UNLOCK_REPLIES( trans );
		}
		/* and clean-up, including cancellations, if needed */
		goto error;
	}

	if (lock) LOCK_REPLIES( trans );
	if (trans->uas.status>=200) {
		LM_ERR("failed to generate %d reply when a final %d was sent out\n",
				code, trans->uas.status);
		goto error2;
	}
	if ( is_invite(trans) && code>=200 )
		which_cancel(trans, &cancel_bitmap );


	rb = & trans->uas.response;
	rb->activ_type=code;

	trans->uas.status = code;
	buf_len = rb->buffer.s ? len : len + REPLY_OVERBUFFER_LEN;
	rb->buffer.s = shm_realloc( rb->buffer.s, buf_len );
	/* puts the reply's buffer to uas.response */
	if (! rb->buffer.s ) {
			LM_ERR("failed to allocate shmem buffer\n");
			goto error3;
	}
	update_local_tags(trans, bm, rb->buffer.s, buf);

	rb->buffer.len = len ;
	memcpy( rb->buffer.s , buf , len );
	/* needs to be protected too because what timers are set depends
	   on current transactions status */
	/* t_update_timers_after_sending_reply( rb ); */
	trans->relaied_reply_branch=-2;
	if (lock) UNLOCK_REPLIES( trans );

	/* do UAC cleanup procedures in case we generated
	   a final answer whereas there are pending UACs */
	if (code>=200) {
		if ( is_local(trans) ) {
			LM_DBG("local transaction completed\n");
			if ( has_tran_tmcbs(trans, TMCB_LOCAL_COMPLETED) ) {
				run_trans_callbacks( TMCB_LOCAL_COMPLETED, trans,
					0, FAKED_REPLY, code);
			}
		} else {
			/* run the PRE send callbacks */
			if ( has_tran_tmcbs(trans, TMCB_RESPONSE_PRE_OUT) ) {
				cb_s.s = buf;
				cb_s.len = len;
				set_extra_tmcb_params( &cb_s, &rb->dst);
				if (lock)
					run_trans_callbacks_locked( TMCB_RESPONSE_PRE_OUT, trans,
						trans->uas.request, FAKED_REPLY, code);
				else
					run_trans_callbacks( TMCB_RESPONSE_PRE_OUT, trans,
						trans->uas.request, FAKED_REPLY, code);
			}
		}

		if (!is_hopbyhop_cancel(trans)) {
			cleanup_uac_timers( trans );
			if (is_invite(trans)) cancel_uacs( trans, cancel_bitmap );
			/* for auth related replies, we do not do retransmission
			   (via set_final_timer()), but only wait for a final
			   reply (put_on_wait() ) - see RFC 3261 (26.3.2.4 DoS Protection) */
			if ((code != 401) && (code != 407))
				set_final_timer(  trans );
			else
				put_on_wait(trans);
		}
	}

	/* send it out : response.dst.send_sock is valid all the time now,
	 * as it's taken from original request -bogdan */
	if (!trans->uas.response.dst.send_sock) {
		LM_CRIT("send_sock is NULL\n");
	}

	if(trans->uas.request && trans->uas.request->flags&tcp_no_new_conn_rplflag)
		tcp_no_new_conn = 1;

	if ( SEND_PR_BUFFER( rb, buf, len )==0 ) {
		LM_DBG("reply sent out. buf=%p: %.9s..., "
			"shmem=%p: %.9s\n", buf, buf, rb->buffer.s, rb->buffer.s );

		if (has_tran_tmcbs(trans, TMCB_MSG_SENT_OUT) ) {
			cb_s.s = buf;
			cb_s.len = len;
			set_extra_tmcb_params( &cb_s, &rb->dst);
			run_trans_callbacks( TMCB_MSG_SENT_OUT, trans,
				NULL, FAKED_REPLY, code);
		}
		stats_trans_rpl( code, 1 /*local*/ );
	}

	tcp_no_new_conn = 0;

	/* run the POST send callbacks */
	if (code>=200&&!is_local(trans)&&has_tran_tmcbs(trans,TMCB_RESPONSE_OUT)){
		cb_s.s = buf;
		cb_s.len = len;
		set_extra_tmcb_params( &cb_s, &rb->dst);
		if (lock)
			run_trans_callbacks_locked( TMCB_RESPONSE_OUT, trans,
				trans->uas.request, FAKED_REPLY, code);
		else
			run_trans_callbacks( TMCB_RESPONSE_OUT, trans,
				trans->uas.request, FAKED_REPLY, code);
	}

	pkg_free( buf ) ;
	LM_DBG("finished\n");
	return 1;

error3:
error2:
	if (lock) UNLOCK_REPLIES( trans );
	pkg_free ( buf );
error:
	/* do UAC cleanup */
	cleanup_uac_timers( trans );
	if ( is_invite(trans) ) cancel_uacs( trans, cancel_bitmap );
	/* we did not succeed -- put the transaction on wait */
	put_on_wait(trans);
	return -1;
}


/* send a UAS reply
 * returns 1 if everything was OK or -1 for error
 */
static int _reply( struct cell *trans, struct sip_msg* p_msg,
									unsigned int code, str *text, int lock )
{
	unsigned int len;
	char * buf, *dset;
	struct bookmark bm;
	int dset_len;

	if (code>=200) set_kr(REQ_RPLD);
	/* compute the buffer in private memory prior to entering lock;
	 * create to-tag if needed */

	/* if that is a redirection message, dump current message set to it */
	if (code>=300 && code<400) {
		dset=print_dset(p_msg, &dset_len);
		if (dset) {
			add_lump_rpl(p_msg, dset, dset_len, LUMP_RPL_HDR);
		}
	}

	/* check if the UAS retranmission port needs to be updated */
	if ( (p_msg->msg_flags ^ trans->uas.request->msg_flags) & FL_FORCE_RPORT )
		su_setport( &trans->uas.response.dst.to, p_msg->rcv.src_port );

	if (code>=180 && p_msg->to
				&& (get_to(p_msg)->tag_value.s==0
			    || get_to(p_msg)->tag_value.len==0)) {
		calc_tag_suffix( p_msg, tm_tag_suffix );
		buf = build_res_buf_from_sip_req(code,text, &tm_tag, p_msg, &len, &bm);
		return _reply_light( trans, buf, len, code,
			tm_tag.s, TOTAG_VALUE_LEN, lock, &bm);
	} else {
		buf = build_res_buf_from_sip_req(code,text, 0 /*no to-tag*/,
			p_msg, &len, &bm);

		return _reply_light(trans,buf,len,code, 0, 0 /* no to-tag */,
			lock, &bm);
	}
}

/*if msg is set -> it will fake the env. vars conforming with the msg; if NULL
 * the env. will be restore to original */
static inline void faked_env( struct cell *t,struct sip_msg *msg)
{
	static struct cell *backup_t;
	static struct usr_avp **backup_list;
	static struct socket_info* backup_si;
	static int backup_route_type;

	if (msg) {
		swap_route_type( backup_route_type, FAILURE_ROUTE);
		/* tm actions look in beginning whether transaction is
		 * set -- whether we are called from a reply-processing
		 * or a timer process, we need to set current transaction;
		 * otherwise the actions would attempt to look the transaction
		 * up (unnecessary overhead, refcounting)
		 */
		/* backup */
		backup_t = get_t();
		/* fake transaction */
		set_t(t);
		/* make available the avp list from transaction */
		backup_list = set_avp_list( &t->user_avps );
		/* set default send address to the saved value */
		backup_si = bind_address;
		bind_address = t->uac[0].request.dst.send_sock;
	} else {
		/* restore original environment */
		set_t(backup_t);
		set_route_type( backup_route_type );
		/* restore original avp list */
		set_avp_list( backup_list );
		bind_address = backup_si;
	}
}


/* return 1 if a failure_route processes */
static inline int run_failure_handlers(struct cell *t)
{
	static struct sip_msg faked_req;
	struct sip_msg *shmem_msg;
	struct ua_client *uac;
	int on_failure;
	int old_route_type;

	shmem_msg = t->uas.request;
	uac = &t->uac[picked_branch];

	/* failure_route for a local UAC? */
	if (!shmem_msg || REQ_LINE(shmem_msg).method_value==METHOD_CANCEL ) {
		LM_WARN("no UAC or CANCEL support (%d, %d) \n",
				t->on_negative, t->tmcb_hl.reg_types);
		return 0;
	}

	/* don't start faking anything if we don't have to */
	if ( !has_tran_tmcbs( t, TMCB_ON_FAILURE) && !t->on_negative ) {
		LM_WARN("no negative handler (%d, %d)\n",t->on_negative,
			t->tmcb_hl.reg_types);
		return 1;
	}

	if (!fake_req(&faked_req, shmem_msg, &t->uas, NULL)) {
		LM_ERR("fake_req failed\n");
		return 0;
	}
	/* fake also the env. conforming to the fake msg */
	faked_env( t, &faked_req);

	/* DONE with faking ;-) -> run the failure handlers */
	if ( has_tran_tmcbs( t, TMCB_ON_FAILURE) ) {
		run_trans_callbacks( TMCB_ON_FAILURE, t, &faked_req,
				uac->reply, uac->last_received);
	}
	if (t->on_negative) {
		/* update flags in transaction if changed by callbacks */
		shmem_msg->flags = faked_req.flags;
		/* avoid recursion -- if failure_route forwards, and does not
		 * set next failure route, failure_route will not be reentered
		 * on failure */
		on_failure = t->on_negative;
		t->on_negative=0;
		/* run a reply_route action if some was marked */
		swap_route_type(old_route_type, FAILURE_ROUTE);
		run_top_route(sroutes->failure[on_failure].a, &faked_req);
		set_route_type(old_route_type);
	}

	/* restore original environment and free the fake msg */
	faked_env( t, 0);
	free_faked_req(&faked_req,t);

	/* if failure handler changed flag, update transaction context */
	shmem_msg->flags = faked_req.flags;
	/* branch flags do not need to be updated as this branch will be never
	 * used again */
	return 1;
}


static inline int is_3263_failure(struct cell *t)
{
	/* is is a DNS failover scenario? - according to RFC 3263
	 * and RFC 3261, this means 503 reply with Retr-After hdr
	 * or timeout with no reply */
	LM_DBG("dns-failover test: branch=%d, last_recv=%d, flags=%X\n",
		picked_branch, t->uac[picked_branch].last_received,
		t->uac[picked_branch].flags);

	switch (t->uac[picked_branch].last_received) {
		case 408:
			return ((t->uac[picked_branch].flags&T_UAC_HAS_RECV_REPLY)==0);
		case 503:
			if (t->uac[picked_branch].reply==NULL ||
			t->uac[picked_branch].reply==FAKED_REPLY)
				return 0;
			/* we do not care about the Retry-After header in 503
			 * as following discussion on sip-implementers list :
			 * with or without a RA header, a 503 should fire DNS
			 * based failover - bogdan
			 */
			return 1;
	}
	return 0;
}


static inline int do_dns_failover(struct cell *t)
{
	static struct sip_msg faked_req;
	struct sip_msg *shmem_msg;
	struct sip_msg *req;
	struct ua_client *uac;
	dlg_t dialog;
	int ret, sip_msg_len;

	uac = &t->uac[picked_branch];

	/* check if the DNS resolver can get at least one new IP */
	if ( get_next_su( uac->proxy, &uac->request.dst.to, 1)!=0 )
		return -1;

	LM_DBG("new destination available\n");

	if (t->uas.request==NULL) {
		if (!is_local(t)) {
			LM_CRIT("BUG: proxy transaction without UAS request :-/\n");
			return -1;
		}
		/* create the cloned SIP msg -> first create a new SIP msg */
		memset( &dialog, 0, sizeof(dialog));
		dialog.send_sock = uac->request.dst.send_sock;
		dialog.hooks.next_hop = &uac->uri;
		req = buf_to_sip_msg(uac->request.buffer.s, uac->request.buffer.len,
			&dialog);
		if (req==NULL) {
			LM_ERR("failed to generate SIP msg from previous buffer\n");
			return -1;
		}
		/* now do the actual cloning of the SIP message */
		t->uas.request = sip_msg_cloner( req, &sip_msg_len, 1);
		if (t->uas.request==NULL) {
			LM_ERR("cloning failed\n");
			free_sip_msg(req);
			pkg_free(req);
			return -1;
		}
		t->uas.end_request = ((char*)t->uas.request) + sip_msg_len;
		/* free the actual SIP message, keep the clone only */
		free_sip_msg(req);
		pkg_free(req);
	}
	shmem_msg = t->uas.request;

	if (!fake_req(&faked_req, shmem_msg, &t->uas, uac)) {
		LM_ERR("fake_req failed\n");
		return -1;
	}
	/* fake also the env. conforming to the fake msg */
	faked_env( t, &faked_req);
	ret = -1;

	/* set info as current destination */
	if ( set_ruri( &faked_req, &uac->uri)!= 0)
		goto done;

	setb0flags( &faked_req, uac->br_flags );
	faked_req.force_send_socket = shmem_msg->force_send_socket;

	/* send it out */
	if (t_forward_nonack( t, &faked_req, uac->proxy,1/*reset*/,1/*locked*/)==1)
		ret = 0;

done:
	/* restore original environment and free the fake msg */
	faked_env( t, 0);
	free_faked_req(&faked_req,t);
	return ret;
}


static inline int branch_prio( short ret_code, unsigned int is_cancelled)
{
	int first_digit;

	first_digit = ret_code / 100;

	switch(first_digit){
		case 1:                    /* 100 - 199 */
		case 2:                    /* 200 - 299 */
			return ret_code;
		case 6:
			return ret_code - 300; /* 300 - 399 */
		case 3:
			return ret_code + 100; /* 400 - 499 */
		case 5:
			if (ret_code==503)
				return 801;        /* 801 */
			return ret_code + 200; /* 700 - 799 */
		case 4:
			switch(ret_code){
				case 401:
					return 500;    /* 500 - 599 */
				case 407:
					return 501;
				case 415:
					return 502;
				case 420:
					return 503;
				case 484:
					return 504;
				case 408:
					return 800;   /* 800 */
				case 487:
					if(is_cancelled)
						return 0;
				default: /* the rest of ret codes in the 4xx class */
					return ret_code + 200; /* 600 - 699 */
			}
		default:
			return ret_code + 200; /* > 900 */
		}
}


/* select a branch for forwarding; returns:
 * 0..X ... branch number
 * -1   ... error
 * -2   ... can't decide yet -- incomplete branches present
 */
static inline int t_pick_branch( struct cell *t, int *res_code, int *do_cancel)
{
	int lowest_b, lowest_s, b, prio;
	unsigned int cancelled;

	lowest_b=-1; lowest_s=999;
	cancelled = was_cancelled(t);
	*do_cancel = 0;
	for ( b=t->first_branch; b<t->nr_of_outgoings ; b++ ) {
		/* skip PHONY branches if the transaction was canceled by UAC;
		 * a phony branch is used just to force the transaction to wait for
		 * more branches, but if canceled, it makes no sense to wait anymore;
		 * Exception - do not ignore the branch if there is reply pushed
		 * on that branch, like an internal timeout or so */
		if ( (t->uac[b].flags & T_UAC_IS_PHONY) &&
		(t->flags & T_WAS_CANCELLED_FLAG) &&
		t->uac[b].last_received<299 )
			continue;
		/* skip 'empty branches' */
		if (!t->uac[b].request.buffer.s) continue;
		/* there is still an unfinished UAC transaction; wait now! */
		if ( t->uac[b].last_received<200 ) {
			if (t->uac[b].br_flags & minor_branch_flag) {
				*do_cancel = 1;
				continue; /* if last branch, lowest_b remains -1 */
			}
			return -2;
		}
		/* compare against the priority of the current branch */
		prio = branch_prio(t->uac[b].last_received,cancelled);
		if ( (lowest_b==-1) || (prio<lowest_s) ) {
			lowest_b = b;
			lowest_s = prio;
		}
	} /* find lowest branch */
	LM_DBG("picked branch %d, code %d (prio=%d)\n",
		lowest_b,lowest_b==-1 ? -1 : t->uac[lowest_b].last_received,lowest_s);

	*res_code=lowest_s;
	return lowest_b;
}


/* Quick and harmless test to see if the transaction still has 
   pending branches */
static inline int tran_is_completed( struct cell *t )
{
	int i;

	for( i=t->first_branch ; i<t->nr_of_outgoings ; i++ )
		if ( t->uac[i].last_received<200 )
			return 0;

	return 1;
}


/* This is the neurological point of reply processing -- called
 * from within a REPLY_LOCK, t_should_relay_response decides
 * how a reply shall be processed and how transaction state is
 * affected.
 *
 * Checks if the new reply (with new_code status) should be sent or not
 *  based on the current
 * transaction status.
 * Returns 	- branch number (0,1,...) which should be relayed
 *         -1 if nothing to be relayed
 */
static enum rps t_should_relay_response( struct cell *Trans , int new_code,
	int branch , int *should_store, int *should_relay,
	branch_bm_t *cancel_bitmap, struct sip_msg *reply )
{
	int branch_cnt;
	int picked_code;
	int inv_through;
	int do_cancel;

	/* note: this code never lets replies to CANCEL go through;
	   we generate always a local 200 for CANCEL; 200s are
	   not relayed because it's not an INVITE transaction;
	   >= 300 are not relayed because 200 was already sent
	   out
	*/
	LM_DBG("T_code=%d, new_code=%d\n", Trans->uas.status,new_code);

	/* a final reply after 200 OK on a transaction with multi branch 200 OK */
	if ( is_invite(Trans) && new_code>=200
	&& Trans->flags&T_MULTI_200OK_FLAG
	&& Trans->uas.status>=200 && Trans->uas.status<300) {
		*should_store=0;
		picked_branch=-1;
		Trans->uac[branch].last_received=new_code;
		if (new_code>=300) {
			/* negative reply, we simply discard (no relay, no save) */
			*should_relay = -1;
			return RPS_DISCARDED;
		}
		/* 2xx reply - is this the last branch to complete?? */
		if (tran_is_completed(Trans)) {
			/* last branch gets also a 200OK, no more pending branches */
			*should_relay = branch;
			return RPS_COMPLETED;
		} else {
			/* 200 OK, but still having ongoing branches */
			*should_relay = branch;
			return RPS_RELAY;
		}
	}

	inv_through=new_code>=200 && new_code<300 && is_invite(Trans);
	/* if final response sent out, allow only INVITE 2xx  */
	if ( Trans->uas.status >= 200 ) {
		if (inv_through) {
			LM_DBG("200 OK for INVITE after final sent\n");
			*should_store=0;
			Trans->uac[branch].last_received=new_code;
			*should_relay=branch;
			return RPS_PUSHED_AFTER_COMPLETION;
		}
		if ( is_hopbyhop_cancel(Trans) && new_code>=200) {
			*should_store=0;
			*should_relay=-1;
			picked_branch=-1;
			return RPS_COMPLETED;
		}
		/* except the exception above, too late  messages will
		   be discarded */
		goto discard;
	}

	/* if final response received at this branch, allow only INVITE 2xx */
	if (Trans->uac[branch].last_received>=200
			&& !(inv_through && Trans->uac[branch].last_received<300)) {
#ifdef EXTRA_DEBUG
		/* don't report on retransmissions */
		if (Trans->uac[branch].last_received==new_code) {
			LM_DBG("final rely retransmission\n");
		} else
		/* if you FR-timed-out, faked a local 408 and 487 came, don't
		 * report on it either */
		if (Trans->uac[branch].last_received==408 && new_code==487) {
			LM_DBG("487 reply came for a timed-out branch\n");
		} else {
		/* this looks however how a very strange status rewrite attempt;
		 * report on it */
			LM_DBG("status rewrite by UAS: stored: %d, received: %d\n",
				Trans->uac[branch].last_received, new_code );
		}
#endif
		goto discard;
	}

	/* no final response sent yet */
	/* negative replies subject to fork picking */
	if (new_code >=300 ) {

		Trans->uac[branch].last_received=new_code;
		/* also append the current reply to the transaction to
		 * make it available in failure routes - a kind of "fake"
		 * save of the final reply per branch */
		Trans->uac[branch].reply = reply;

		if (new_code>=600 && !disable_6xx_block) {
			/* this is a winner and close all branches */
			which_cancel( Trans, cancel_bitmap );
			picked_branch=branch;
			/* no more new branches should be added to this transaction */
			Trans->flags |= T_NO_NEW_BRANCHES_FLAG;
		} else {
			/* if all_final return lowest */
			picked_branch = t_pick_branch( Trans, &picked_code, &do_cancel);
			if (picked_branch==-2) { /* branches open yet */
				*should_store=1;
				*should_relay=-1;
				picked_branch=-1;
				Trans->uac[branch].reply = 0;
				return RPS_STORE;
			}
			if (picked_branch==-1) {
				LM_CRIT("pick_branch failed (lowest==-1) for code %d\n",new_code);
				Trans->uac[branch].reply = 0;
				goto discard;
			}
			if (do_cancel) {
				branch_bm_t cb = 0;
				which_cancel( Trans, &cb );
				cleanup_uac_timers(Trans);
				cancel_uacs( Trans, cb);
			}
		}

		/* no more pending branches -- try if that changes after
		 * a callback; save branch count to be able to determine
		 * later if new branches were initiated */
		branch_cnt=Trans->nr_of_outgoings;
		reset_kr();

		if ( !(Trans->flags&T_NO_DNS_FAILOVER_FLAG) &&
		Trans->uac[picked_branch].proxy!=NULL ) {
			/* is is a DNS failover scenario, according to RFC 3263 ? */
			if (is_3263_failure(Trans)) {
				LM_DBG("trying DNS-based failover\n");
				/* do DNS failover -> add new branches */
				if (do_dns_failover( Trans )!=0) {
					/* skip the failed added branches */
					branch_cnt = Trans->nr_of_outgoings;
				}
			}
		}

		/* run ON_FAILURE handlers ( route and callbacks) */
		if ( branch_cnt==Trans->nr_of_outgoings &&
		(has_tran_tmcbs( Trans, TMCB_ON_FAILURE) || Trans->on_negative) ) {
			run_failure_handlers( Trans );
		}

		/* now reset it; after the failure logic, the reply may
		 * not be stored any more and we don't want to keep into
		 * transaction some broken reference */
		Trans->uac[branch].reply = 0;

		/* look if the callback perhaps replied transaction; it also
		   covers the case in which a transaction is replied localy
		   on CANCEL -- then it would make no sense to proceed to
		   new branches bellow
		*/
		if (Trans->uas.status >= 200) {
			*should_store=0;
			*should_relay=-1;
			/* this might deserve an improvement -- if something
			   was already replied, it was put on wait and then,
			   returning RPS_COMPLETED will make t_on_reply
			   put it on wait again; perhaps splitting put_on_wait
			   from send_reply or a new RPS_ code would be healthy
			*/
			picked_branch=-1;
			return RPS_COMPLETED;
		}
		/* look if the callback/failure_route introduced new branches ... */
		if (branch_cnt<Trans->nr_of_outgoings && get_kr()==REQ_FWDED)  {
			/* await then result of new branches */
			*should_store=1;
			*should_relay=-1;
			picked_branch=-1;
			return RPS_STORE;
		}

		/* really no more pending branches -- return selected code */
		*should_store=0;
		*should_relay=picked_branch;
		picked_branch=-1;
		return RPS_COMPLETED;
	}

	/* not >=300 ... it must be 2xx or provisional 1xx */
	if (new_code>=100) {
		/* 1xx and 2xx except 100 will be relayed */
		Trans->uac[branch].last_received=new_code;
		*should_store=0;
		*should_relay= new_code==100? -1 : branch;
		if (new_code>=200 ) {
			/* if a a multi-200OK transaction, prevent the transaction
			   completion if we still have pending branches */
			if (Trans->flags&T_MULTI_200OK_FLAG) {
				if (tran_is_completed(Trans))
					return RPS_COMPLETED;
				else
					return RPS_RELAY;
			}
			which_cancel( Trans, cancel_bitmap );
			return RPS_COMPLETED;
		} else return RPS_PROVISIONAL;
	}

discard:
	*should_store=0;
	*should_relay=-1;
	return RPS_DISCARDED;
}

/* Retransmits the last sent inbound reply.
 * input: p_msg==request for which I want to retransmit an associated reply
 * Returns  -1 - error
 *           1 - OK
 */
int t_retransmit_reply( struct cell *t )
{
	static char b[BUF_SIZE];
	int len;
	str cb_s;

	/* we need to lock the transaction as messages from
	   upstream may change it continuously */
	LOCK_REPLIES( t );

	if (!t->uas.response.buffer.s) {
		LM_DBG("nothing to retransmit\n");
		goto error;
	}

	/* response.dst.send_sock should be valid all the time now, as it's taken
	   from original request -bogdan */
	if (t->uas.response.dst.send_sock==0) {
		LM_CRIT("something to retransmit, but send_sock is NULL\n");
		goto error;
	}

	len=t->uas.response.buffer.len;
	if ( len==0 || len>BUF_SIZE )  {
		LM_DBG("zero length or too big to retransmit: %d\n", len);
		goto error;
	}
	memcpy( b, t->uas.response.buffer.s, len );
	UNLOCK_REPLIES( t );

	/* send the buffer out */
	if (t->uas.request && t->uas.request->flags & tcp_no_new_conn_rplflag)
		tcp_no_new_conn = 1;

	if (SEND_PR_BUFFER( & t->uas.response, b, len )==0) {
		/* success */
		LM_DBG("buf=%p: %.9s..., shmem=%p: %.9s\n",b, b,
			t->uas.response.buffer.s, t->uas.response.buffer.s );
		if (has_tran_tmcbs( t, TMCB_MSG_SENT_OUT) ) {
			cb_s.s = b;
			cb_s.len = len;
			set_extra_tmcb_params( &cb_s, &t->uas.response.dst);
			run_trans_callbacks( TMCB_MSG_SENT_OUT, t,
					NULL, FAKED_REPLY, t->uas.status);
		}
	}

	tcp_no_new_conn = 0;

	return 1;

error:
	UNLOCK_REPLIES(t);
	return -1;
}


int t_reply( struct cell *t, struct sip_msg* p_msg, unsigned int code,
	str * text )
{
	return _reply( t, p_msg, code, text, 1 /* lock replies */ );
}


int t_reply_unsafe( struct cell *t, struct sip_msg* p_msg, unsigned int code,
	str * text )
{
	return _reply( t, p_msg, code, text, 0 /* don't lock replies */ );
}


int t_gen_totag(struct sip_msg *msg, str *totag)
{
	calc_tag_suffix( msg, tm_tag_suffix );
	*totag = tm_tag;

	return 1;
}


void set_final_timer( /* struct s_table *h_table, */ struct cell *t )
{
	if ( !is_local(t) && t->uas.request->REQ_METHOD==METHOD_INVITE ) {
		/* crank timers for negative replies */
		if (t->uas.status>=300) {
			start_retr(&t->uas.response);
			return;
		}
		/* local UAS retransmits too */
		if (t->relaied_reply_branch==-2 && t->uas.status>=200) {
			/* we retransmit 200/INVs regardless of transport --
			   even if TCP used, UDP could be used upstream and
			   loose the 200, which is not retransmitted by proxies
			*/
			force_retr( &t->uas.response );
			return;
		}
	}
	put_on_wait(t);
}

void cleanup_uac_timers( struct cell *t )
{
	int i;

	/* reset FR/retransmission timers */
	for (i=t->first_branch; i<t->nr_of_outgoings; i++ )  {
		reset_timer( &t->uac[i].request.retr_timer );
		reset_timer( &t->uac[i].request.fr_timer );
	}
	LM_DBG("RETR/FR timers reset\n");
}

static int store_reply( struct cell *trans, int branch, struct sip_msg *rpl)
{
#		ifdef EXTRA_DEBUG
		if (trans->uac[branch].reply) {
			LM_ERR("replacing stored reply; aborting\n");
			abort();
		}
#		endif

		/* when we later do things such as challenge aggregation,
	   	   we should parse the message here before we conserve
		   it in shared memory; -jiri
		*/
		if (rpl==FAKED_REPLY)
			trans->uac[branch].reply=FAKED_REPLY;
		else
			trans->uac[branch].reply = sip_msg_cloner( rpl, 0, 0 );

		if (! trans->uac[branch].reply ) {
			LM_ERR("failed to alloc' clone memory\n");
			return 0;
		}

		return 1;
}

/* this is the code which decides what and when shall be relayed
   upstream; note well -- it assumes it is entered locked with
   REPLY_LOCK and it returns unlocked!
*/
enum rps relay_reply( struct cell *t, struct sip_msg *p_msg, int branch,
	unsigned int msg_status, branch_bm_t *cancel_bitmap )
{
	int relay;
	int save_clone;
	char *buf;
	/* length of outbound reply */
	unsigned int res_len;
	int relayed_code;
	struct sip_msg *relayed_msg;
	struct bookmark bm;
	int totag_retr;
	enum rps reply_status;
	/* retransmission structure of outbound reply and request */
	struct retr_buf *uas_rb;
	str cb_s;
	str text;

	/* keep compiler warnings about use of uninit vars silent */
	res_len=0;
	buf=0;
	relayed_msg=0;
	relayed_code=0;
	totag_retr=0;


	/* remember, what was sent upstream to know whether we are
	 * forwarding a first final reply or not */

	/* *** store and relay message as needed *** */
	reply_status = t_should_relay_response(t, msg_status, branch,
		&save_clone, &relay, cancel_bitmap, p_msg );
	LM_DBG("T_state=%d, branch=%d, save=%d, relay=%d, cancel_BM=%X\n",
		reply_status, branch, save_clone, relay, *cancel_bitmap );

	/* store the message if needed */
	if (save_clone) /* save for later use, typically branch picking */
	{
		if (!store_reply( t, branch, p_msg ))
			goto error01;
	}

	uas_rb = & t->uas.response;
	if (relay >= 0 ) {
		/* initialize sockets for outbound reply */
		uas_rb->activ_type=msg_status;

		t->relaied_reply_branch = relay;

		/* try building the outbound reply from either the current
		 * or a stored message */
		relayed_msg = branch==relay ? p_msg :  t->uac[relay].reply;
		if (relayed_msg==FAKED_REPLY) {
			relayed_code = branch==relay
				? msg_status : t->uac[relay].last_received;

			text.s = error_text(relayed_code);
			text.len = strlen(text.s); /* FIXME - bogdan*/

			if (relayed_code>=180 && t->uas.request->to
					&& (get_to(t->uas.request)->tag_value.s==0
					|| get_to(t->uas.request)->tag_value.len==0)) {
				calc_tag_suffix( t->uas.request, tm_tag_suffix );
				buf = build_res_buf_from_sip_req(
						relayed_code,
						&text,
						&tm_tag,
						t->uas.request, &res_len, &bm );
			} else {
				buf = build_res_buf_from_sip_req( relayed_code,
					&text, 0/* no to-tag */,
					t->uas.request, &res_len, &bm );
			}

		} else {
			/* run callbacks for all types of responses -
			 * even if they are shmem-ed or not */
			if (has_tran_tmcbs(t,TMCB_RESPONSE_FWDED) ) {
				run_trans_callbacks( TMCB_RESPONSE_FWDED, t, t->uas.request,
					relayed_msg, msg_status );
			}
			relayed_code=relayed_msg->REPLY_STATUS;
			buf = build_res_buf_from_sip_res( relayed_msg, &res_len,
							uas_rb->dst.send_sock,0);
			/* remove all lumps which are not in shm
			 * added either by build_res_buf_from_sip_res, or by
			 * the callbacks that have been called with shmem-ed messages - vlad */
			if (branch!=relay) {
				del_notflaged_lumps( &(relayed_msg->add_rm), LUMPFLAG_SHMEM);
				del_notflaged_lumps( &(relayed_msg->body_lumps), LUMPFLAG_SHMEM);
			}
		}
		if (!buf) {
			LM_ERR("no mem for outbound reply buffer\n");
			goto error02;
		}

		/* attempt to copy the message to UAS's shmem:
		   - copy to-tag for ACK matching as well
		   -  allocate little a bit more for provisional as
		      larger messages are likely to follow and we will be
		      able to reuse the memory frag
		*/
		uas_rb->buffer.s = shm_realloc( uas_rb->buffer.s, res_len +
			(msg_status<200 ?  REPLY_OVERBUFFER_LEN : 0));
		if (!uas_rb->buffer.s) {
			LM_ERR("no more share memory\n");
			goto error03;
		}
		uas_rb->buffer.len = res_len;
		memcpy( uas_rb->buffer.s, buf, res_len );
		if (relayed_msg==FAKED_REPLY) { /* to-tags for local replies */
			update_local_tags(t, &bm, uas_rb->buffer.s, buf);
		}
		stats_trans_rpl( relayed_code, (relayed_msg==FAKED_REPLY)?1:0 );

		/* update the status ... */
		t->uas.status = relayed_code;

		if (is_invite(t) && relayed_msg!=FAKED_REPLY
		&& relayed_code>=200 && relayed_code < 300
		&& has_tran_tmcbs( t,
		TMCB_RESPONSE_OUT|TMCB_RESPONSE_PRE_OUT)) {
			totag_retr=update_totag_set(t, relayed_msg);
		}
	}; /* if relay ... */

	UNLOCK_REPLIES( t );

	/* Setup retransmission timer _before_ the reply is sent
	 * to avoid race conditions
	 */
	if (reply_status == RPS_COMPLETED) {
		/* for auth related replies, we do not do retransmission
		   (via set_final_timer()), but only wait for a final
		   reply (put_on_wait() ) - see RFC 3261 (26.3.2.4 DoS Protection) */
		if ((relayed_code != 401) && (relayed_code != 407))
			set_final_timer(t);
		else
			put_on_wait(t);
	}

	/* send it now (from the private buffer) */
	if (relay >= 0) {
		/* run the PRE sending out callback */
		if (!totag_retr && has_tran_tmcbs(t, TMCB_RESPONSE_PRE_OUT) ) {
			cb_s.s = buf;
			cb_s.len = res_len;
			set_extra_tmcb_params( &cb_s, &uas_rb->dst);
			run_trans_callbacks_locked(TMCB_RESPONSE_PRE_OUT,t,t->uas.request,
				relayed_msg, relayed_code);
		}

		if (t->uas.request && t->uas.request->flags & tcp_no_new_conn_rplflag)
			tcp_no_new_conn = 1;

		/* send it out*/
		if (SEND_PR_BUFFER( uas_rb, buf, res_len)==0) {
			/* success */
			LM_DBG("sent buf=%p: %.9s..., shmem=%p: %.9s\n",
				buf, buf, uas_rb->buffer.s, uas_rb->buffer.s );

			if (has_tran_tmcbs( t, TMCB_MSG_SENT_OUT) ) {
				cb_s.s = buf;
				cb_s.len = res_len;
				set_extra_tmcb_params( &cb_s, &uas_rb->dst);
				run_trans_callbacks( TMCB_MSG_SENT_OUT, t,
					NULL, relayed_msg, relayed_code);
			}
		}

		tcp_no_new_conn = 0;

		/* run the POST sending out callback */
		if (!totag_retr && has_tran_tmcbs(t, TMCB_RESPONSE_OUT) ) {
			cb_s.s = buf;
			cb_s.len = res_len;
			set_extra_tmcb_params( &cb_s, &uas_rb->dst);
			run_trans_callbacks_locked( TMCB_RESPONSE_OUT, t, t->uas.request,
				relayed_msg, relayed_code);
		}
		pkg_free( buf );
	}

	/* success */
	return reply_status;

error03:
	pkg_free( buf );
error02:
	if (save_clone) {
		if (t->uac[branch].reply!=FAKED_REPLY)
			free_cloned_msg( t->uac[branch].reply );
		t->uac[branch].reply = NULL;
	}
error01:
	text.s = "Reply processing error";
	text.len = sizeof("Reply processing error")-1;
	t_reply_unsafe( t, t->uas.request, 500, &text );
	UNLOCK_REPLIES(t);
	if (is_invite(t)) cancel_uacs( t, *cancel_bitmap );
	/* a serious error occurred -- attempt to send an error reply;
	   it will take care of clean-ups  */

	/* failure */
	return RPS_ERROR;
}

/* this is the "UAC" above transaction layer; if a final reply
   is received, it triggers a callback; note well -- it assumes
   it is entered locked with REPLY_LOCK and it returns unlocked!
*/
enum rps local_reply( struct cell *t, struct sip_msg *p_msg, int branch,
	unsigned int msg_status, branch_bm_t *cancel_bitmap)
{
	/* how to deal with replies for local transaction */
	int local_store, local_winner;
	enum rps reply_status;
	struct sip_msg *winning_msg;
	int winning_code;
	int totag_retr;
	/* branch_bm_t cancel_bitmap; */

	/* keep warning 'var might be used un-inited' silent */
	winning_msg=0;
	winning_code=0;
	totag_retr=0;

	*cancel_bitmap=0;

	reply_status=t_should_relay_response( t, msg_status, branch,
		&local_store, &local_winner, cancel_bitmap, p_msg );
	LM_DBG("branch=%d, save=%d, winner=%d\n",
		branch, local_store, local_winner );
	if (local_store) {
		if (!store_reply(t, branch, p_msg))
			goto error;
	}
	if (local_winner>=0) {
		winning_msg= branch==local_winner
			? p_msg :  t->uac[local_winner].reply;
		if (winning_msg==FAKED_REPLY) {
			winning_code = branch==local_winner
				? msg_status : t->uac[local_winner].last_received;
		} else {
			winning_code=winning_msg->REPLY_STATUS;
		}
		t->uas.status = winning_code;
		stats_trans_rpl( winning_code, (winning_msg==FAKED_REPLY)?1:0 );
		if (is_invite(t) && winning_msg!=FAKED_REPLY
		&& winning_code>=200 && winning_code <300
		&& has_tran_tmcbs(t,
		TMCB_RESPONSE_OUT|TMCB_RESPONSE_PRE_OUT) )  {
			totag_retr=update_totag_set(t, winning_msg);
		}
	}
	UNLOCK_REPLIES(t);

	if ( local_winner >= 0 ) {
		if (winning_code < 200) {
			if (!totag_retr && has_tran_tmcbs(t,TMCB_LOCAL_RESPONSE_OUT)) {
				LM_DBG("Passing provisional reply %d to FIFO application\n",
						winning_code);
				run_trans_callbacks( TMCB_LOCAL_RESPONSE_OUT, t, 0,
					winning_msg, winning_code);
			}
		} else {
			LM_DBG("local transaction completed\n");
			if (!totag_retr && has_tran_tmcbs(t,TMCB_LOCAL_COMPLETED) ) {
				run_trans_callbacks( TMCB_LOCAL_COMPLETED, t, t->uas.request,
					winning_msg, winning_code );
			}
		}
	}
	return reply_status;

error:
	which_cancel(t, cancel_bitmap);
	UNLOCK_REPLIES(t);
	cleanup_uac_timers(t);
	if ( get_cseq(p_msg)->method_id==METHOD_INVITE )
		cancel_uacs( t, *cancel_bitmap );
	put_on_wait(t);
	return RPS_ERROR;
}


/*  This function is called whenever a reply for our module is received;
  * we need to register  this function on module initialization;
  *  Returns :   0 - core router stops
  *              1 - core router relay statelessly
  */
int reply_received( struct sip_msg  *p_msg )
{
	int msg_status;
	int last_uac_status;
	int branch;
	int reply_status;
	utime_t timer;
	/* has the transaction completed now and we need to clean-up? */
	branch_bm_t cancel_bitmap;
	struct ua_client *uac;
	struct cell *t;
	struct usr_avp **backup_list;
	unsigned int has_reply_route;
	int old_route_type;

	set_t(T_UNDEFINED);

	/* make sure we know the associated transaction ... */
	switch (t_check(p_msg, &branch )) {
		case -1: goto not_found;
		case -2: return 0; /* reply forwarded elsewhere */
	}

	/*... if there is none, tell the core router to fwd statelessly */
	t = get_t();
	if ((t == 0) || (t == T_UNDEFINED)) goto not_found;

	cancel_bitmap=0;
	msg_status=p_msg->REPLY_STATUS;

	uac=&t->uac[branch];
	LM_DBG("org. status uas=%d, uac[%d]=%d local=%d is_invite=%d)\n",
		t->uas.status, branch, uac->last_received,
		is_local(t), is_invite(t));
	last_uac_status=uac->last_received;
	if_update_stat( tm_enable_stats, tm_rcv_rpls , 1);

	/* it's a cancel which is not e2e ? */
	if ( get_cseq(p_msg)->method_id==METHOD_CANCEL && is_invite(t) ) {
		/* ... then just stop timers */
		reset_timer( &uac->local_cancel.retr_timer);
		if ( msg_status >= 200 ) {
				reset_timer( &uac->local_cancel.fr_timer);
		}
		LM_DBG("reply to local CANCEL processed\n");

		if (has_tran_tmcbs( t, TMCB_MSG_MATCHED_IN) )
			run_trans_callbacks( TMCB_MSG_MATCHED_IN, t, 0,
				p_msg, p_msg->REPLY_STATUS);

		goto done;
	}

	/* *** stop timers *** */
	/* stop retransmission */
	reset_timer(&uac->request.retr_timer);

	/* stop final response timer only if I got a final response */
	if ( msg_status >= 200 ) {
		reset_timer( &uac->request.fr_timer);
	}

	/* acknowledge negative INVITE replies (do it before detailed
	 * on_reply processing, which may take very long, like if it
	 * is attempted to establish a TCP connection to a fail-over dst */
	if (is_invite(t) && ((msg_status >= 300) ||
	(is_local(t) && !no_autoack(t) && msg_status >= 200) )) {
		if (send_ack(p_msg, t, branch)!=0)
			LM_ERR("failed to send ACK (local=%s)\n", is_local(t)?"yes":"no");
	}

	_tm_branch_index = branch;

	if (has_tran_tmcbs( t, TMCB_MSG_MATCHED_IN) )
		run_trans_callbacks( TMCB_MSG_MATCHED_IN, t, 0,
			p_msg, p_msg->REPLY_STATUS);

	if (!is_local(t))
		run_trans_callbacks( TMCB_RESPONSE_IN, t, t->uas.request, p_msg,
			p_msg->REPLY_STATUS);

	/* processing of on_reply block */
	has_reply_route = (t->on_reply) || (t->uac[branch].on_reply);
	if (has_reply_route) {
		if (onreply_avp_mode) {
			/* lock the reply*/
			LOCK_REPLIES( t );
			/* set the as avp_list the one from transaction */
			backup_list = set_avp_list(&t->user_avps);
		} else {
			backup_list = 0;
		}
		/* transfer transaction flag to branch context */
		p_msg->flags = t->uas.request ? t->uas.request->flags : 0;
		setb0flags( p_msg, t->uac[branch].br_flags);

		swap_route_type(old_route_type, ONREPLY_ROUTE);
		/* run block - first per branch and then global one */
		if ( t->uac[branch].on_reply &&
		(run_top_route(sroutes->onreply[t->uac[branch].on_reply].a,p_msg)
		&ACT_FL_DROP) && (msg_status<200) ) {
			set_route_type(old_route_type);
			if (onreply_avp_mode) {
				UNLOCK_REPLIES( t );
				set_avp_list( backup_list );
			}
			LM_DBG("dropping provisional reply %d\n", msg_status);
			goto done;
		}
		if(t->on_reply && (run_top_route(sroutes->onreply[t->on_reply].a,p_msg)
		&ACT_FL_DROP) && (msg_status<200) ) {
			set_route_type(old_route_type);
			if (onreply_avp_mode) {
				UNLOCK_REPLIES( t );
				set_avp_list( backup_list );
			}
			LM_DBG("dropping provisional reply %d\n", msg_status);
			goto done;
		}
		set_route_type(old_route_type);
		/* transfer current message context back to t */
		t->uac[branch].br_flags = getb0flags(p_msg);
		if (t->uas.request)
			t->uas.request->flags = p_msg->flags;
		if (onreply_avp_mode)
			/* restore original avp list */
			set_avp_list( backup_list );
	}

	if (!onreply_avp_mode || !has_reply_route)
		/* lock the reply*/
		LOCK_REPLIES( t );

	/* mark that the UAC received replies */
	uac->flags |= T_UAC_HAS_RECV_REPLY;

	/* we fire a cancel on spot if (a) branch is marked "to be canceled" or (b)
	 * the whole transaction was canceled (received cancel) and no cancel sent
	 * yet on this branch; and of course, only if a provisional reply :) */
	if (t->uac[branch].flags&T_UAC_TO_CANCEL_FLAG ||
	((t->flags&T_WAS_CANCELLED_FLAG) && !t->uac[branch].local_cancel.buffer.s)) {
		if ( msg_status < 200 )
			/* reply for an UAC with a pending cancel -> do cancel now */
			cancel_branch(t, branch);
		/* reset flag */
		t->uac[branch].flags &= ~(T_UAC_TO_CANCEL_FLAG);
	}

	if (is_local(t)) {
		reply_status = local_reply(t,p_msg, branch,msg_status,&cancel_bitmap);
		if (reply_status == RPS_COMPLETED) {
			cleanup_uac_timers(t);
			if (is_invite(t)) cancel_uacs(t, cancel_bitmap);
			/* There is no need to call set_final_timer because we know
			 * that the transaction is local */
			put_on_wait(t);
		}
	} else {
		reply_status = relay_reply(t,p_msg,branch,msg_status,&cancel_bitmap);
		/* clean-up the transaction when transaction completed */
		if (reply_status == RPS_COMPLETED) {
			/* no more UAC FR/RETR (if I received a 2xx, there may
			 * be still pending branches ...
			 */
			cleanup_uac_timers(t);
			if (is_invite(t)) cancel_uacs(t, cancel_bitmap);
			/* FR for negative INVITES, WAIT anything else */
			/* set_final_timer(t); */
		}
	}

	if (reply_status!=RPS_PROVISIONAL)
		goto done;

	/* update FR/RETR timers on provisional replies */
	if (msg_status < 200 && (restart_fr_on_each_reply ||
	((last_uac_status<msg_status) &&
	((msg_status >= 180) || (last_uac_status == 0)))
	) ) { /* provisional now */
		if (is_invite(t)) {
			/* invite: change FR to longer FR_INV, do not
			 * attempt to restart retransmission any more
			 */
			timer = is_timeout_set(t->fr_inv_timeout) ?
				t->fr_inv_timeout :
				timer_id2timeout[FR_INV_TIMER_LIST];

			LM_DBG("FR_INV_TIMER = %lld\n", timer);
			set_timer(&uac->request.fr_timer, FR_INV_TIMER_LIST, &timer);
		} else {
			/* non-invite: restart retransmissions (slow now) */
			uac->request.retr_list = RT_T2;
			set_timer(&uac->request.retr_timer, RT_T2, 0);
		}
	} /* provisional replies */

done:
	/* we are done with the transaction, so unref it - the reference
	 * was incremented by t_check() function -bogdan*/
	t_unref(p_msg);
	/* don't try to relay statelessly neither on success
	 * (we forwarded statefully) nor on error; on troubles,
	 * simply do nothing; that will make the other party to
	 * retransmit; hopefuly, we'll then be better off
	 */
	_tm_branch_index = 0;
	return 0;
not_found:
	set_t(T_UNDEFINED);
	return 1;
}

static int _reply_with_body( struct cell *trans, unsigned int code, str *text,
						str *body, str *new_header, str *to_tag, int lock_replies)
{
	struct lump_rpl *hdr_lump;
	struct lump_rpl *body_lump;
	str  rpl;
	int  ret;
	struct bookmark bm;
	struct sip_msg* p_msg = trans->uas.request;
	str to_tag_rpl= {0, 0};

	/* add the lumps for new_header and for body (by bogdan) */
	if (new_header && new_header->len) {
		hdr_lump = add_lump_rpl( p_msg, new_header->s,
			new_header->len, LUMP_RPL_HDR );
		if ( !hdr_lump ) {
			LM_ERR("failed to add hdr lump\n");
			goto error;
		}
	} else {
		hdr_lump = 0;
	}

	/* body lump */
	if(body && body->len) {
		body_lump = add_lump_rpl( p_msg, body->s, body->len,
			LUMP_RPL_BODY );
		if (body_lump==0) {
			LM_ERR("failed add body lump\n");
			goto error_1;
		}
	} else {
		body_lump = 0;
	}

	if(to_tag && to_tag->len) {
		rpl.s = build_res_buf_from_sip_req(code, text, to_tag, p_msg,
		 	(unsigned int*)&rpl.len, &bm);
		to_tag_rpl = *to_tag;
	}
	else
	if (code>=180 && p_msg->to && (get_to(p_msg)->tag_value.s==0
			|| get_to(p_msg)->tag_value.len==0)) {
		calc_tag_suffix( p_msg, tm_tag_suffix );
		rpl.s = build_res_buf_from_sip_req(code,text, &tm_tag, p_msg,
				(unsigned int*)&rpl.len, &bm);
		to_tag_rpl.s = tm_tag.s;
		to_tag_rpl.len = TOTAG_VALUE_LEN;
	} else {
		rpl.s = build_res_buf_from_sip_req(code,text, 0 /*no to-tag*/,
			p_msg, (unsigned int*)&rpl.len, &bm);
	}

	/* since the msg (trans->uas.request) is a clone into shm memory, to avoid
	 * memory leak or crashing (lumps are create in private memory) I will
	 * remove the lumps by myself here (bogdan) */
	if ( hdr_lump ) {
		unlink_lump_rpl( p_msg, hdr_lump);
		free_lump_rpl( hdr_lump );
	}
	if( body_lump ) {
		unlink_lump_rpl( p_msg, body_lump);
		free_lump_rpl( body_lump );
	}

	if (rpl.s==0) {
		LM_ERR("failed in doing build_res_buf_from_sip_req()\n");
		goto error;
	}
	ret=_reply_light( trans, rpl.s, rpl.len, code, to_tag_rpl.s, to_tag_rpl.len,
			lock_replies, &bm );

	/* mark the transaction as replied */
	if (code>=200) set_kr(REQ_RPLD);

	return ret;
error_1:
	if ( hdr_lump ) {
		unlink_lump_rpl( p_msg, hdr_lump);
		free_lump_rpl( hdr_lump );
	}
error:
	return -1;
}


int w_t_reply_body(struct sip_msg* msg, unsigned int* code, str *text,
				str *body)
{
	struct cell *t;
	int r, lock_replies = 1;

	if (msg->REQ_METHOD==METHOD_ACK) {
		LM_DBG("ACKs are not replied\n");
		return 0;
	}

	switch (route_type) {
		case FAILURE_ROUTE:
			t=get_t();
			if ( t==0 || t==T_UNDEFINED ) {
				LM_BUG("no transaction found in Failure Route\n");
				return -1;
			}
			lock_replies = 0;
			break;
		case REQUEST_ROUTE:
			t=get_t();
			if ( t==0 || t==T_UNDEFINED ) {
				/* t_reply_with_body() is a bit of a weird function as it is
				 * receiving as parameter the actual msg, but the transaction
				 * (and uses the saved msg from transaction).
				 * So we need to take care and save everything into transaction,
				 * otherwise we will loose the rpl lumps. --bogdan */
				r = t_newtran( msg, 1/*full uas cloning*/ );
				if (r==0) {
					/* retransmission -> break the script */
					return 0;
				} else if (r<0) {
					LM_ERR("could not create a new transaction\n");
					return -1;
				}
				t=get_t();
			} else {
				update_cloned_msg_from_msg( t->uas.request, msg);
			}
			break;
		default:
			LM_CRIT("unsupported route_type (%d)\n", route_type);
			return -1;
	}
	return _reply_with_body(t, *code, text, body, 0, 0, lock_replies);
}


int t_reply_with_body( struct cell *trans, unsigned int code, str *text,
									str *body, str *new_header, str *to_tag)
{
	return _reply_with_body(trans, code, text, body, new_header,
			to_tag, 1 /* lock replies */);
}
