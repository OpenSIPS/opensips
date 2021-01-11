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
 * -------
 *  2003-02-13  proto support added (andrei)
 *  2003-02-24  s/T_NULL/T_NULL_CELL/ to avoid redefinition conflict w/
 *              nameser_compat.h (andrei)
 *  2003-03-01  kr set through a function now (jiri)
 *  2003-03-06  callbacks renamed; "blind UAC" introduced, which makes
 *              transaction behave as if it was forwarded even if it was
 *              not -- good for local UAS, like VM (jiri)
 *  2003-03-19  replaced all the mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-30  we now watch downstream delivery and if it fails, send an
 *              error message upstream (jiri)
 *  2003-04-14  use protocol from uri (jiri)
 *  2003-12-04  global TM callbacks switched to per transaction callbacks
 *              (bogdan)
 *  2004-02-13: t->is_invite and t->local replaced with flags (bogdan)
 *  2007-01-25  DNS failover at transaction level added (bogdan)
 */

#include "../../dprint.h"
#include "../../config.h"
#include "../../ut.h"
#include "../../dset.h"
#include "../../timer.h"
#include "../../hash_func.h"
#include "../../globals.h"
#include "../../action.h"
#include "../../data_lump.h"
#include "../../blacklists.h"
#include "../../usr_avp.h"
#include "../../mem/mem.h"
#include "../../parser/parser_f.h"
#include "../../parser/parse_body.h"
#include "t_funcs.h"
#include "t_hooks.h"
#include "t_msgbuilder.h"
#include "ut.h"
#include "t_cancel.h"
#include "t_lookup.h"
#include "t_fwd.h"
#include "fix_lumps.h"
#include "config.h"
#include "cluster.h"
#include "../usrloc/ul_evi.h"
#include "../../msg_callbacks.h"
#include "../../mod_fix.h"

#define NO_BODY_CLONE_MARKER ((struct sip_msg_body*)-1)

/* route to execute for the branches */
static int goto_on_branch;
int _tm_branch_index = 0;

void t_on_branch( unsigned int go_to )
{
	struct cell *t = get_t();

	/* in MODE_REPLY and MODE_ONFAILURE T will be set to current transaction;
	 * in MODE_REQUEST T will be set only if the transaction was already
	 * created; if not -> use the static variable */
	if (route_type==BRANCH_ROUTE || !t || t==T_UNDEFINED )
		goto_on_branch=go_to;
	else
		t->on_branch = go_to;
}


unsigned int get_on_branch(void)
{
	return goto_on_branch;
}


static inline int pre_print_uac_request( struct cell *t, int branch,
					struct sip_msg *request, struct sip_msg_body **body_clone)
{
	int backup_route_type;
	struct usr_avp **backup_list;
	char *p;

	/* ... we calculate branch ... */
	if (!t_calc_branch(t, branch, request->add_to_branch_s,
			&request->add_to_branch_len ))
	{
		LM_ERR("branch computation failed\n");
		goto error;
	}

	/* from now on, flag all new lumps with LUMPFLAG_BRANCH flag in order to
	 * be able to remove them later --bogdan */
	set_init_lump_flags(LUMPFLAG_BRANCH);

	/* copy path vector into branch */
	if (request->path_vec.len) {
		t->uac[branch].path_vec.s =
			shm_realloc(t->uac[branch].path_vec.s, request->path_vec.len+1);
		if (t->uac[branch].path_vec.s==NULL) {
			LM_ERR("shm_realloc failed\n");
			goto error;
		}
		t->uac[branch].path_vec.len = request->path_vec.len;
		memcpy( t->uac[branch].path_vec.s, request->path_vec.s,
			request->path_vec.len+1);
	}

	/* do the same for the advertised port & address */
	if (request->set_global_address.len) {
		t->uac[branch].adv_address.s = shm_realloc(t->uac[branch].adv_address.s,
			request->set_global_address.len+1);
		if (t->uac[branch].adv_address.s==NULL) {
			LM_ERR("shm_realloc failed for storing the advertised address "
				"(len=%d)\n",request->set_global_address.len);
			goto error;
		}
		t->uac[branch].adv_address.len = request->set_global_address.len;
		memcpy( t->uac[branch].adv_address.s, request->set_global_address.s,
			request->set_global_address.len+1);
	}
	if (request->set_global_port.len) {
		t->uac[branch].adv_port.s = shm_realloc(t->uac[branch].adv_port.s,
			request->set_global_port.len+1);
		if (t->uac[branch].adv_port.s==NULL) {
			LM_ERR("shm_realloc failed for storing the advertised port "
				"(len=%d)\n",request->set_global_port.len);
			goto error;
		}
		t->uac[branch].adv_port.len = request->set_global_port.len;
		memcpy( t->uac[branch].adv_port.s, request->set_global_port.s,
			request->set_global_port.len+1);
	}


	/********** run route & callback ************/

	/* run branch route, if any; run it before RURI's DNS lookup
	 * to allow to be changed --bogdan */
	if (t->on_branch) {
		/* need to pkg_malloc the dst_uri */
		if ( request->dst_uri.s && request->dst_uri.len>0 ) {
			if ( (p=pkg_malloc(request->dst_uri.len))==0 ) {
				LM_ERR("no more pkg mem\n");
				ser_error=E_OUT_OF_MEM;
				goto error;
			}
			memcpy( p, request->dst_uri.s, request->dst_uri.len);
			request->dst_uri.s = p;
		}
		/* need to pkg_malloc the new_uri */
		if ( (p=pkg_malloc(request->new_uri.len))==0 ) {
			LM_ERR("no more pkg mem\n");
			ser_error=E_OUT_OF_MEM;
			goto error;
		}
		memcpy( p, request->new_uri.s, request->new_uri.len);
		request->new_uri.s = p;
		request->parsed_uri_ok = 0;
		/* make a clone of the original body, to restore it later */
		if (clone_sip_msg_body( request, NULL, body_clone, 0)!=0) {
			LM_ERR("faile to clone the body, branch route changes will be"
				" preserved\n");
		}
		/* make available the avp list from transaction */
		backup_list = set_avp_list( &t->user_avps );
		/* run branch route */
		swap_route_type( backup_route_type, BRANCH_ROUTE);

		_tm_branch_index = branch;
		if(run_top_route(sroutes->branch[t->on_branch].a,request)&ACT_FL_DROP){
			LM_DBG("dropping branch <%.*s>\n", request->new_uri.len,
					request->new_uri.s);
			_tm_branch_index = 0;
			/* restore the route type */
			set_route_type( backup_route_type );
			/* restore original avp list */
			set_avp_list( backup_list );
			goto error;
		}

		_tm_branch_index = 0;
		/* restore the route type */
		set_route_type( backup_route_type );
		/* restore original avp list */
		set_avp_list( backup_list );
	}

	/* run the specific callbacks for this transaction */
	_tm_branch_index = branch;
	run_trans_callbacks( TMCB_REQUEST_FWDED, t, request, 0,
			-request->REQ_METHOD);
	_tm_branch_index = 0;

	/* copy dst_uri into branch (after branch route possible updated it) */
	if (request->dst_uri.len) {
		t->uac[branch].duri.s =
			shm_realloc(t->uac[branch].duri.s, request->dst_uri.len);
		if (t->uac[branch].duri.s==NULL) {
			LM_ERR("shm_realloc failed\n");
			goto error;
		}
		t->uac[branch].duri.len = request->dst_uri.len;
		memcpy( t->uac[branch].duri.s,request->dst_uri.s,request->dst_uri.len);
	}

	return 0;
error:
	return -1;
}

/* be aware and use it *all* the time between pre_* and post_* functions! */
static inline char *print_uac_request(struct sip_msg *i_req, unsigned int *len,
		struct socket_info *send_sock, enum sip_protos proto )
{
	char *buf;
	str *cid = NULL;

	if (1/* TODO: check if the cid should be used */)
		cid = tm_via_cid();

	/* build the shm buffer now */
	buf=build_req_buf_from_sip_req( i_req, len, send_sock, proto,
			cid, MSG_TRANS_SHM_FLAG);
	if (!buf) {
		LM_ERR("no more shm_mem\n");
		ser_error=E_OUT_OF_MEM;
		return NULL;
	}

	return buf;
}


static inline void post_print_uac_request(struct sip_msg *request,
			const str *org_uri, str *org_dst, struct sip_msg_body *body_clone)
{
	reset_init_lump_flags();
	/* delete inserted branch lumps */
	del_flaged_lumps( &request->add_rm, LUMPFLAG_BRANCH);
	del_flaged_lumps( &request->body_lumps, LUMPFLAG_BRANCH);
	/* free any potential new uri */
	if (request->new_uri.s!=org_uri->s) {
		pkg_free(request->new_uri.s);
		/* and just to be sure */
		request->new_uri.s = 0;
		request->new_uri.len = 0;
		request->parsed_uri_ok = 0;
	}
	/* free any potential dst uri */
	if (request->dst_uri.s!=org_dst->s) {
		pkg_free(request->dst_uri.s);
		/* and just to be sure */
		request->dst_uri.s = 0;
		request->dst_uri.len = 0;
	}
	/* if cloned, restore the original body to the msg */
	if (body_clone!=NO_BODY_CLONE_MARKER) {
		free_sip_body(request->body);
		request->body = body_clone;
	}
}


/* introduce a new uac, which is blind -- it only creates the
   data structures and starts FR timer, but that's it; it does
   not print messages and send anything anywhere; that is good
   for FIFO apps -- the transaction must look operationally
   and FR must be ticking, whereas the request is "forwarded"
   using a non-SIP way and will be replied the same way
*/
int add_blind_uac(void)  /*struct cell *t*/
{
	unsigned short branch;
	struct cell *t;

	t=get_t();
	if (t==T_UNDEFINED || !t ) {
		LM_ERR("no transaction context\n");
		return -1;
	}

	branch=t->nr_of_outgoings;
	if (branch==MAX_BRANCHES) {
		LM_ERR("maximum number of branches exceeded\n");
		return -1;
	}

	t->nr_of_outgoings++;
	/* start FR timer -- protocol set by default to PROTO_NONE,
	   which means retransmission timer will not be started */
	start_retr(&t->uac[branch].request);
	/* we are on a timer -- don't need to put on wait on script
	   clean-up */
	set_kr(REQ_FWDED);

	return 1; /* success */
}


static inline int update_uac_dst( struct sip_msg *request,
													struct ua_client *uac )
{
	struct socket_info* send_sock;
	char *shbuf;
	unsigned int len;

	send_sock = get_send_socket( request, &uac->request.dst.to ,
			uac->request.dst.proto );
	if (send_sock==0) {
		LM_ERR("failed to fwd to af %d, proto %d "
			" (no corresponding listening socket)\n",
			uac->request.dst.to.s.sa_family, uac->request.dst.proto );
		ser_error=E_NO_SOCKET;
		return -1;
	}

	if (send_sock!=uac->request.dst.send_sock) {
		/* rebuild */
		shbuf = print_uac_request( request, &len, send_sock,
			uac->request.dst.proto);
		if (!shbuf) {
			ser_error=E_OUT_OF_MEM;
			return -1;
		}

		if (uac->request.buffer.s)
			shm_free(uac->request.buffer.s);

		/* things went well, move ahead and install new buffer! */
		uac->request.dst.send_sock = send_sock;
		uac->request.dst.proto_reserved1 = 0;
		uac->request.buffer.s = shbuf;
		uac->request.buffer.len = len;
	}

	return 0;
}


static inline unsigned int count_local_rr(struct sip_msg *req)
{
	unsigned int cnt = 0;
	struct lump *r;

	/* we look for the RR anchors only
	 * in the main list (no after or before) */
	for( r=req->add_rm ; r ; r=r->next )
		if ( r->type==HDR_RECORDROUTE_T && r->op==LUMP_NOP && r->after) {
			/* only the master RR anchor has "after" */
			if (r->after->op==LUMP_ADD_OPT &&
			r->after->u.cond==COND_IF_DIFF_REALMS) {
				/* conditional second RR hdr (when doing double RR) */
				if (r->after->flags&LUMPFLAG_COND_TRUE) {
					cnt++;
				}
			} else {
				/* mandatory first RR hdr */
				cnt++;
			}
		}

	return cnt;
}


/* introduce a new uac to transaction; returns its branch id (>=0)
   or error (<0); it doesn't send a message yet -- a reply to it
   might interfere with the processes of adding multiple branches

   NOTICE: do NOT provide (str *) buffers pointing to @request itself, as this
   may break the function logic!
*/
static int add_uac( struct cell *t, struct sip_msg *request, const str *uri,
		str* next_hop, unsigned int bflags, str* path, struct proxy_l *proxy)
{
	unsigned short branch;
	struct sip_msg_body *body_clone=NO_BODY_CLONE_MARKER;
	int do_free_proxy;
	int ret;

	branch=t->nr_of_outgoings;
	if (branch==MAX_BRANCHES) {
		LM_ERR("maximum number of branches exceeded\n");
		ret=E_CFG;
		goto error;
	}

	/* check existing buffer -- rewriting should never occur */
	if (t->uac[branch].request.buffer.s) {
		LM_CRIT("buffer rewrite attempt\n");
		ret=ser_error=E_BUG;
		goto error;
	}

	/* set proper RURI to request to reflect the branch */
	request->new_uri=*uri;
	request->parsed_uri_ok=0;
	request->dst_uri=*next_hop;
	request->path_vec=*path;
	request->ruri_bflags=bflags;

	if ( pre_print_uac_request( t, branch, request, &body_clone)!= 0 ) {
		ret = -1;
		goto error01;
	}

	/* check DNS resolution */
	if (proxy){
		do_free_proxy = 0;
	}else {
		proxy=uri2proxy( request->dst_uri.len ?
			&request->dst_uri:&request->new_uri,
			request->force_send_socket ?
				request->force_send_socket->proto : PROTO_NONE );
		if (proxy==0)  {
			ret=E_BAD_ADDRESS;
			goto error01;
		}
		do_free_proxy = 1;
	}

	msg_callback_process(request, REQ_PRE_FORWARD, (void *)proxy);

	if ( !(t->flags&T_NO_DNS_FAILOVER_FLAG) ) {
		t->uac[branch].proxy = shm_clone_proxy( proxy , do_free_proxy );
		if (t->uac[branch].proxy==NULL) {
			ret = E_OUT_OF_MEM;
			goto error02;
		}
	}

	/* use the first address */
	hostent2su( &t->uac[branch].request.dst.to,
		&proxy->host, proxy->addr_idx, proxy->port ? proxy->port:SIP_PORT);
	t->uac[branch].request.dst.proto = proxy->proto;

	/* do print of the uac request */
	if ( update_uac_dst( request, &t->uac[branch] )!=0) {
		ret = ser_error;
		goto error02;
	}

	/* things went well, move ahead */
	t->uac[branch].uri.s=t->uac[branch].request.buffer.s+
		request->first_line.u.request.method.len+1;
	t->uac[branch].uri.len=request->new_uri.len;
	t->uac[branch].br_flags = request->ruri_bflags;
	t->uac[branch].added_rr = count_local_rr( request );
	t->nr_of_outgoings++;

	/* done! */
	ret=branch;

error02:
	if(do_free_proxy) {
		free_proxy( proxy );
		pkg_free( proxy );
	}
error01:
	post_print_uac_request( request, uri, next_hop, body_clone);
	if (ret < 0) {
		/* destroy all the bavps added, the path vector and the destination,
		 * since this branch will never be properly added to
		 * the UAC list, otherwise we'll have memory leaks - razvanc */
		clean_branch(t->uac[branch]);
		memset(&t->uac[branch], 0, sizeof(t->uac[branch]));
		init_branch(&t->uac[branch], branch, t->wait_tl.set, t);
	}
error:
	return ret;
}


int add_phony_uac( struct cell *t)
{
	str dummy_buffer = str_init("DUMMY");
	unsigned short branch;
	utime_t timer;

	branch=t->nr_of_outgoings;
	if (branch==MAX_BRANCHES) {
		LM_ERR("maximum number of branches exceeded\n");
		return E_CFG;
	}

	/* check existing buffer -- rewriting should never occur */
	if (t->uac[branch].request.buffer.s) {
		LM_CRIT("buffer rewrite attempt\n");
		ser_error=E_BUG;
		return E_BUG;
	}

	/* we attach a dummy buffer just to pass all the "tests" for a 
	 * valid branch */
	t->uac[branch].request.buffer.s = (char*)shm_malloc(dummy_buffer.len);
	if (t->uac[branch].request.buffer.s==NULL) {
		LM_ERR("failed to alloc dummy buffer for phony branch\n");
		/* there is nothing to reset on the branch */
		return E_OUT_OF_MEM;
	}
	memcpy( t->uac[branch].request.buffer.s, dummy_buffer.s, dummy_buffer.len);
	t->uac[branch].request.buffer.len = dummy_buffer.len;

	t->uac[branch].request.my_T = t;
	t->uac[branch].request.branch = branch;
	t->uac[branch].flags = T_UAC_IS_PHONY;

	/* in invalid proto will prevent adding this retransmission buffer
	 * to the retransmission timer (there is nothing to retransmit here :P */
	t->uac[branch].request.dst.proto = PROTO_NONE;

	t->nr_of_outgoings++;

	/* we set here only FR (final response) timer, to be sure this branch
	 * comes to an end - as timeout value we use exactly the same value the
	 * transaction has set as FR_INV_TIMEOUT */
	if (is_timeout_set(t->fr_inv_timeout)) {
		timer = t->fr_inv_timeout;
		set_1timer(&t->uac[branch].request.fr_timer, FR_INV_TIMER_LIST,&timer);
	} else {
		set_1timer(&t->uac[branch].request.fr_timer, FR_INV_TIMER_LIST, NULL);
	}

	set_kr(REQ_FWDED);

	return 0;
}


static int _reason_avp_id = 0;

int t_set_reason(struct sip_msg *msg, str *val)
{
	str avp_name = str_init("_reason_avp_internal");
	int_str reason;

	if (_reason_avp_id==0) {
		if (parse_avp_spec( &avp_name, &_reason_avp_id) ) {
			LM_ERR("failed to init the internal AVP\n");
			return -1;
		}
	}

	reason.s = *val;
	if (add_avp( AVP_VAL_STR, _reason_avp_id, reason)!=0) {
		LM_ERR("failed to add the internal reason AVP\n");
		return -1;
	}
	return 1;
}


int t_add_reason(struct sip_msg *msg, str *reason)
{
	return t_set_reason(msg, reason);
}

void get_cancel_reason(struct sip_msg *msg, int flags, str *reason)
{
#define CANCEL_REASON_SIP_487  \
	"Reason: SIP;cause=487;text=\"ORIGINATOR_CANCEL\"" CRLF
	int_str avp_reason;
	struct hdr_field *hdr;

	reason->s = NULL;
	reason->len = 0;

	if (search_first_avp( AVP_VAL_STR, _reason_avp_id, &avp_reason, NULL)) {
		*reason = avp_reason.s;
	} else {
		/* propagate the REASON flag ? */
		if ( flags&T_CANCEL_REASON_FLAG ) {
			/* look for the Reason header */
			if (parse_headers(msg, HDR_EOH_F, 0)<0) {
				LM_ERR("failed to parse all hdrs - ignoring Reason hdr\n");
				} else {
				hdr = get_header_by_static_name(msg, "Reason");
				if (hdr!=NULL) {
					reason->s = hdr->name.s;
					reason->len = hdr->len;
				}
			}
		}
	}

	/* if no reason, use NORMAL CLEARING */
	if (reason->s == NULL) {
		reason->s = CANCEL_REASON_SIP_487;
		reason->len = sizeof(CANCEL_REASON_SIP_487) - 1;
	}
}

void cancel_invite(struct sip_msg *cancel_msg,
					struct cell *t_cancel, struct cell *t_invite, int locked)
{

	branch_bm_t cancel_bitmap;
	str reason;

	cancel_bitmap=0;

	/* send back 200 OK as per RFC3261 */
	reason.s = CANCELING;
	reason.len = sizeof(CANCELING)-1;
	if (locked)
		t_reply_unsafe( t_cancel, cancel_msg, 200, &reason );
	else
		t_reply( t_cancel, cancel_msg, 200, &reason );

	get_cancel_reason(cancel_msg, t_cancel->flags, &reason);

	LOCK_REPLIES(t_invite);
	/* we need to check which branches should be canceled under lock to avoid
	 * concurrency with replies that are coming in the same time */
	/* generate local cancels for all branches */
	which_cancel(t_invite, &cancel_bitmap );
	UNLOCK_REPLIES(t_invite);

	set_cancel_extra_hdrs( reason.s, reason.len);
	cancel_uacs(t_invite, cancel_bitmap );
	set_cancel_extra_hdrs( NULL, 0);

	/* Do not do anything about branches with no received reply;
	 * continue the retransmission hoping to get something back;
	 * if still not, we will generate the 408 Timeout based on FR
	 * timer; this helps with better coping with missed/lated provisional
	 * replies in the context of cancelling the transaction
	 */

	 /* Handle a special case here, when there is only one PHONY
	  * branch (not a real signaling branch, just a fake one
	  * to force keeping the transaction alive) - if the case,
	  * it means there are no other real signaling branches, 
	  * so we can force a 487 reply on the PHONY branch, in order
	  * to terminate the whole transaction on the spot */
	if ( (t_invite->nr_of_outgoings-t_invite->first_branch)==1 &&
	(t_invite->uac[t_invite->first_branch].flags & T_UAC_IS_PHONY) ) {
		relay_reply( t_invite, FAKED_REPLY, t_invite->first_branch,
			487, &cancel_bitmap);
	}
#if 0
	/* internally cancel branches with no received reply */
	for (i=t_invite->first_branch; i<t_invite->nr_of_outgoings; i++) {
		if (t_invite->uac[i].last_received==0){
			/* reset the "request" timers */
			reset_timer(&t_invite->uac[i].request.retr_timer);
			reset_timer(&t_invite->uac[i].request.fr_timer);
			LOCK_REPLIES( t_invite );
			relay_reply(t_invite,FAKED_REPLY,i,487,&dummy_bm);
		}
	}
#endif
}



/* function returns:
 *       1 - forward successful
 *      -1 - error during forward
 */
int t_forward_nonack( struct cell *t, struct sip_msg* p_msg ,
						struct proxy_l * proxy, int reset_bcounter, int locked)
{
	str reply_reason_487 = str_init("Request Terminated");
	str backup_uri;
	str backup_dst;
	int branch_ret, lowest_ret;
	str current_uri;
	branch_bm_t  added_branches;
	int i, q;
	struct cell *t_invite;
	int success_branch;
	str dst_uri;
	struct socket_info *bk_sock;
	unsigned int br_flags, bk_bflags;
	int idx;
	str path;
	str bk_path;

	/* before doing enything, update the t flags from msg */
	t->uas.request->flags = p_msg->flags;

	if (p_msg->REQ_METHOD==METHOD_CANCEL) {
		t_invite=t_lookupOriginalT(  p_msg );
		if (t_invite!=T_NULL_CELL) {
			t_invite->flags |= T_WAS_CANCELLED_FLAG;
			cancel_invite( p_msg, t, t_invite, locked );
			return 1;
		}
	}

	/* do not forward requests which were already cancelled*/
	if (no_new_branches(t)) {
		LM_INFO("discarding fwd for a 6xx transaction\n");
		ser_error = E_NO_DESTINATION;
		return -1;
	}
	if (was_cancelled(t)) {
		/* is this the first attempt of sending a branch out ? */
		if (t->nr_of_outgoings==0) {
			/* if no other signalling was performed on the transaction
			 * and the transaction was already canceled, better
			 * internally generate the 487 reply here */
			if (locked)
				t_reply_unsafe( t, p_msg , 487 , &reply_reason_487);
			else
				t_reply( t, p_msg , 487 , &reply_reason_487);
		}
		LM_INFO("discarding fwd for a cancelled transaction\n");
		ser_error = E_NO_DESTINATION;
		return -1;
	}

	/* backup current uri, sock and flags... add_uac changes it */
	backup_uri = p_msg->new_uri;
	backup_dst = p_msg->dst_uri;
	bk_sock = p_msg->force_send_socket;
	bk_path = p_msg->path_vec;
	bk_bflags = p_msg->ruri_bflags;
	/* advertised address/port are not changed */

	/* check if the UAS retranmission port needs to be updated */
	if ( (p_msg->msg_flags ^ t->uas.request->msg_flags) & FL_FORCE_RPORT )
		su_setport( &t->uas.response.dst.to, p_msg->rcv.src_port );

	/* if no more specific error code is known, use this */
	lowest_ret=E_BUG;
	/* branches added */
	added_branches=0;
	/* branch to begin with */
	if (reset_bcounter) {
		t->first_branch=t->nr_of_outgoings;
		/* check if the previous branch is a PHONY one and if yes
		 * keep it in the set of active branches; that means the 
		 * transaction had a t_wait_for_new_branches() call prior to relay() */
		if ( t->first_branch>0 &&
		(t->uac[t->first_branch-1].flags & T_UAC_IS_PHONY) )
			t->first_branch--;
	}

	current_uri = *GET_RURI(p_msg); /* separate storage required! */

	/* as first branch, use current R-URI, bflags, etc. */
	branch_ret = add_uac( t, p_msg, &current_uri, &backup_dst,
		getb0flags(p_msg), &p_msg->path_vec, proxy);
	if (branch_ret>=0)
		added_branches |= 1<<branch_ret;
	else
		lowest_ret=branch_ret;

	/* ....and now add the remaining additional branches */
	for( idx=0; (current_uri.s=get_branch( idx, &current_uri.len, &q,
	&dst_uri, &path, &br_flags, &p_msg->force_send_socket))!=0 ; idx++ ) {
		branch_ret = add_uac( t, p_msg, &current_uri, &dst_uri,
			br_flags, &path, proxy);
		/* pick some of the errors in case things go wrong;
		   note that picking lowest error is just as good as
		   any other algorithm which picks any other negative
		   branch result */
		if (branch_ret>=0)
			added_branches |= 1<<branch_ret;
		else
			lowest_ret=branch_ret;
	}
	/* consume processed branches */
	clear_branches();

	/* restore original stuff */
	p_msg->new_uri=backup_uri;
	p_msg->parsed_uri_ok = 0;/* just to be sure; add_uac may parse other uris*/
	p_msg->dst_uri = backup_dst;
	p_msg->force_send_socket = bk_sock;
	p_msg->path_vec = bk_path;
	p_msg->ruri_bflags = bk_bflags;

	/* update on_branch, _only_ if modified, otherwise it overwrites
	 * whatever it is already in the transaction */
	if (get_on_branch())
		t->on_branch = get_on_branch();

	/* update flags, if changed in branch route */
	t->uas.request->flags = p_msg->flags;

	/* things went wrong ... no new branch has been fwd-ed at all */
	if (added_branches==0) {
		LM_ERR("failure to add branches\n");
		ser_error = lowest_ret;
		return lowest_ret;
	}

	/* send them out now */
	success_branch=0;
	for (i=t->first_branch; i<t->nr_of_outgoings; i++) {
		if (added_branches & (1<<i)) {

			if (t->uac[i].br_flags & tcp_no_new_conn_bflag)
				tcp_no_new_conn = 1;

			/* successfully sent out -> run callbacks */
			if ( has_tran_tmcbs( t, TMCB_REQUEST_BUILT) ) {
				set_extra_tmcb_params( &t->uac[i].request.buffer,
					&t->uac[i].request.dst);
				run_trans_callbacks( TMCB_REQUEST_BUILT, t,
					p_msg, 0, 0);
			}

			do {
				if (check_blacklists( t->uac[i].request.dst.proto,
				&t->uac[i].request.dst.to,
				t->uac[i].request.buffer.s,
				t->uac[i].request.buffer.len)) {
					LM_DBG("blocked by blacklists\n");
					ser_error=E_IP_BLOCKED;
				} else {
					set_extra_tmcb_params( &t->uac[i].request.buffer,
							&t->uac[i].request.dst);
					run_trans_callbacks(TMCB_PRE_SEND_BUFFER, t, p_msg, 0, i);

					if (SEND_BUFFER( &t->uac[i].request)==0) {
						ser_error = 0;
						break;
					}

					LM_ERR("sending request failed\n");
					ser_error=E_SEND;
				}
				/* get next dns entry */
				if ( t->uac[i].proxy==0 ||
				get_next_su( t->uac[i].proxy, &t->uac[i].request.dst.to,
				(ser_error==E_IP_BLOCKED)?0:1)!=0 )
					break;
				t->uac[i].request.dst.proto = t->uac[i].proxy->proto;
				/* update branch */
				if ( update_uac_dst( p_msg, &t->uac[i] )!=0)
					break;
			}while(1);

			tcp_no_new_conn = 0;

			if (ser_error) {
				shm_free(t->uac[i].request.buffer.s);
				t->uac[i].request.buffer.s = NULL;
				t->uac[i].request.buffer.len = 0;
				continue;
			}

			success_branch++;

			start_retr( &t->uac[i].request );
			set_kr(REQ_FWDED);

			/* successfully sent out -> run callbacks */
			if ( has_tran_tmcbs( t, TMCB_MSG_SENT_OUT) ) {
				set_extra_tmcb_params( &t->uac[i].request.buffer,
					&t->uac[i].request.dst);
				run_trans_callbacks( TMCB_MSG_SENT_OUT, t,
					p_msg, 0, 0);
			}

		}
	}

	return (success_branch>0)?1:-1;
}


static int ul_contact_event_to_msg(struct sip_msg *req)
{
	static enum ul_attrs { UL_URI, UL_RECEIVED, UL_PATH, UL_QVAL,
		UL_SOCKET, UL_BFLAGS, UL_MAX } ul_attr;
	static str ul_names[UL_MAX]= {str_init(UL_EV_PARAM_CT_URI),
	                              str_init(UL_EV_PARAM_CT_RCV),
	                              str_init(UL_EV_PARAM_CT_PATH),
	                              str_init(UL_EV_PARAM_CT_QVAL),
	                              str_init(UL_EV_PARAM_CT_SOCK),
	                              str_init(UL_EV_PARAM_CT_BFL) };
	static int avp_ids[UL_MAX] = { -1, -1, -1, -1, -1, -1 };
	int_str vals[UL_MAX];
	int proto, port;
	str host;
	str path_dst;

	if (avp_ids[0]==-1) {
		/* init the avp IDs mapping us on the UL event */
		for( ul_attr=0 ; ul_attr<UL_MAX ; ul_attr++ ){
			if (parse_avp_spec( &ul_names[ul_attr], &avp_ids[ul_attr])<0) {
				LM_ERR("failed to init UL AVP %d/%s\n",
					ul_attr,ul_names[ul_attr].s);
				avp_ids[0] = -1;
				return -1;
			}
		}
	}

	/* fetch the AVP values one by one */
	for( ul_attr=0 ; ul_attr<UL_MAX ; ul_attr++ ) {
		if (search_first_avp(0, avp_ids[ul_attr], &vals[ul_attr], NULL)==NULL){
			LM_ERR("cannot find AVP(%d) for event attr %d/%s\n",
				avp_ids[ul_attr], ul_attr, ul_names[ul_attr].s);
			return -1;
		}
	}

	/* OK, we have the values, lets inject them into the SIP msg */
	LM_DBG("injecting new branch: uri=<%.*s>, received=<%.*s>,"
		"path=<%.*s>, qval=%d, socket=<%.*s>, bflags=%X\n",
		vals[UL_URI].s.len, vals[UL_URI].s.s,
		vals[UL_RECEIVED].s.len, vals[UL_RECEIVED].s.s,
		vals[UL_PATH].s.len, vals[UL_PATH].s.s,
		vals[UL_QVAL].n,
		vals[UL_SOCKET].s.len, vals[UL_SOCKET].s.s,
		vals[UL_BFLAGS].n);

	/* contact URI goes as RURI */
	if (set_ruri( req, &vals[UL_URI].s)<0) {
		LM_ERR("failed to set new RURI\n");
		return -1;
	}

	/* contact PATH goes as path */
	if (vals[UL_PATH].s.len) {
		if (get_path_dst_uri(&vals[UL_PATH].s, &path_dst) < 0) {
			LM_ERR("failed to get dst_uri for Path\n");
			return -1;
		}
		if (set_dst_uri( req, &path_dst) < 0) {
			LM_ERR("failed to set dst_uri of Path\n");
			return -1;
		}

		if (set_path_vector( req, &vals[UL_PATH].s)<0) {
			LM_ERR("failed to set PATH\n");
			return -1;
		}
	} else
	/* contact RECEIVED goes as DURI */
	if (vals[UL_RECEIVED].s.len) {
		if (set_dst_uri( req, &vals[UL_RECEIVED].s)<0) {
			LM_ERR("failed to set DST URI\n");
			return -1;
		}
	}

	/* contact Qval goes as RURI Qval */
	set_ruri_q( req, vals[UL_QVAL].n);

	/* contact BFLAGS goes as RURI bflags */
	setb0flags( req, vals[UL_BFLAGS].n);

	/* socket info */
	if (vals[UL_SOCKET].s.len) {
		if ( parse_phostport( vals[UL_SOCKET].s.s, vals[UL_SOCKET].s.len,
		&host.s, &host.len, &port, &proto) < 0) {
			LM_ERR("failed to parse socket from Event attr <%.*s>\n",
				vals[UL_SOCKET].s.len, vals[UL_SOCKET].s.s);
		} else {
			req->force_send_socket = grep_sock_info( &host,
				(unsigned short)port, (unsigned short)proto);
		}
	}

	return 0;
}


static int dst_to_msg(struct sip_msg *s_msg, struct sip_msg *d_msg)
{
	/* move RURI */
	if (set_ruri( d_msg, GET_RURI(s_msg))<0) {
		LM_ERR("failed to set new RURI\n");
		return -1;
	}

	/* move DURI (empty is accepted as reset) */
	if (set_dst_uri( d_msg, &s_msg->dst_uri)<0) {
		LM_ERR("failed to set DST URI\n");
		return -1;
	}

	/* move PATH  (empty is accepted as reset) */
	if (set_path_vector( d_msg, & s_msg->path_vec)<0) {
		LM_ERR("failed to set PATH\n");
		return -1;
	}

	/* Qval */
	set_ruri_q( d_msg, get_ruri_q(s_msg) );

	/* BFLAGS */
	setb0flags( d_msg, getb0flags(s_msg) );

	/* socket info */
	d_msg->force_send_socket = s_msg->force_send_socket;

	return 0;
}


int t_inject_branch( struct cell *t, struct sip_msg *msg, int flags)
{
	static struct sip_msg faked_req;
	branch_bm_t cancel_bm = 0;
	str reason = str_init(CANCEL_REASON_200);
	int rc;

	/* does the transaction state still accept new branches ? */
	if (t->uas.status >= 200) {
		LM_DBG("cannot add branches to a transaction with %d UAS\n",
			t->uas.status);
		return -2;
	}

	if (!fake_req( &faked_req, t->uas.request, &t->uas, NULL)) {
		LM_ERR("fake_req failed\n");
		return -1;
	}

	/* do we have the branches to be injected ? */
	if (flags&TM_INJECT_SRC_EVENT) {
		/* get the branch from Event AVPs, as populated by EVI/EBR */
		if (ul_contact_event_to_msg( &faked_req )<0) {
			LM_ERR("failed to grab new branch from Event\n");
			goto error;
		}
	} else {
		/* use the RURI+dset array as destinations to be injected */
		if (msg->first_line.type==SIP_REQUEST) {
			/* take the RURI branch from the script msg and move it
			 * into the faked msg (that will be used by t_fwd function) */
			if (dst_to_msg( msg, &faked_req )<0) {
				LM_ERR("failed to grab new branch from Event\n");
				goto error;
			}
		} else {
			/* current message is a reply, so take the first branch from dset
			 * and move it into the faked msg (that will be used by t_fwd 
			 * function)*/
			if (move_branch_to_ruri( 0, &faked_req)<0) {
				LM_ERR("no branch found to be moved as new destination\n");
				goto error;
			}
			/* remove it from set */
			remove_branch(0);
		}
	}

	/* do we have to cancel the existing branches before injecting new ones? */
	if (flags&TM_INJECT_FLAG_CANCEL) {
		which_cancel( t, &cancel_bm );
	}

	/* generated the new branches, without branch counter reset */
	rc = t_forward_nonack( t, &faked_req , NULL, 0, 1/*locked*/ );

	/* do we have to cancel the existing branches before injecting new ones? */
	if (flags&TM_INJECT_FLAG_CANCEL) {
		set_cancel_extra_hdrs( reason.s, reason.len);
		cancel_uacs( t, cancel_bm );
		set_cancel_extra_hdrs( NULL, 0);
	}

	/* cleanup the faked request */
	free_faked_req( &faked_req, t);

	return (rc==1)?1:-3;

error:
	/* cleanup the faked request */
	free_faked_req( &faked_req, t);
	return -1;
}


int t_replicate(struct sip_msg *p_msg, str *dst, int flags)
{
	/* this is a quite horrible hack -- we just take the message
	   as is, including Route-s, Record-route-s, and Vias ,
	   forward it downstream and prevent replies received
	   from relaying by setting the replication/local_trans bit;

		nevertheless, it should be good enough for the primary
		customer of this function, REGISTER replication

		if we want later to make it thoroughly, we need to
		introduce delete lumps for all the header fields above
	*/
	struct cell *t;

	if ( set_dst_uri( p_msg, dst)!=0 ) {
		LM_ERR("failed to set dst uri\n");
		return -1;
	}

	if ( branch_uri2dset( GET_RURI(p_msg) )!=0 ) {
		LM_ERR("failed to convert uri to dst\n");
		return -1;
	}

	t=get_t();

	if (!t || t==T_UNDEFINED) {
		/* no transaction yet */
		if (route_type==FAILURE_ROUTE) {
			LM_CRIT("BUG - undefined transaction in failure route\n");
			return -1;
		}
		return t_relay_to( p_msg, NULL, flags|TM_T_RELAY_repl_FLAG);
	} else {
		/* transaction already created */
		if (p_msg->REQ_METHOD==METHOD_ACK)
			/* local ACK */
			return -1;

		t->flags|=T_IS_LOCAL_FLAG;

		return t_forward_nonack( t, p_msg, NULL, 1/*reset*/, 0/*unlocked*/);
	}
}


int get_branch_index(void)
{
	return _tm_branch_index;
}


int t_inject_ul_event_branch(void)
{
	return w_t_inject_branches(NULL,
	            (void *)(unsigned long)TM_INJECT_SRC_EVENT, (void *)0);
}
