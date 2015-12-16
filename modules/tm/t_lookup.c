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
 * 2003-01-23  options for disabling r-uri matching introduced (jiri)
 *              nameser_compat.h (andrei)
 * 2003-01-27  next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2003-01-28  scratchpad removed (jiri)
 * 2003-02-13  init_rb() is proto indep. & it uses struct dest_info (andrei)
 * 2003-02-24  s/T_NULL/T_NULL_CELL/ to avoid redefinition conflict w/
 * 2003-02-27  3261 ACK/200 consumption bug removed (jiri)
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-03-01  kr set through a function now (jiri)
 * 2003-03-06  dialog matching introduced for ACKs -- that's important for
 *             INVITE UAS (like INVITE) and 200/ACK proxy matching (jiri)
 * 2003-03-29  optimization: e2e ACK matching only if callback installed
 *             (jiri)
 * 2003-03-30  set_kr for requests only (jiri)
 * 2003-04-04  bug_fix: RESPONSE_IN callback not called for local
 *             UAC transactions (jiri)
 * 2003-04-07  new transactions inherit on_negative and on_relpy from script
 *             variables on instantiation (jiri)
 * 2003-04-30  t_newtran clean up (jiri)
 * 2003-08-21  request lookups fixed to skip UAC transactions,
 *             thanks Ed (jiri)
 * 2003-12-04  global TM callbacks switched to per transaction callbacks
 *             (bogdan)
 * 2004-02-11  FIFO/CANCEL + alignments (hash=f(callid,cseq)) (uli+jiri)
 * 2004-02-13: t->is_invite and t->local replaced with flags (bogdan)
 * 2004-10-10: use of mhomed disabled for replies (jiri)
 * 2005-02-01: use the incoming request interface for sending the replies
 *             - changes in init_rb() (bogdan)
 *
 *
 * This C-file takes care of matching requests and replies with
 * existing transactions. Note that we do not do SIP-compliant
 * request matching as asked by SIP spec. We do bitwise matching of
 * all header fields in requests which form a transaction key.
 * It is much faster and it works pretty well -- we haven't
 * had any interop issue neither in lab nor in bake-offs. The reason
 * is that retransmissions do look same as original requests
 * (it would be really silly if they would be mangled). The only
 * exception is we parse To as To in ACK is compared to To in
 * reply and both  of them are constructed by different software.
 *
 * As for reply matching, we match based on branch value -- that is
 * faster too. There are two versions .. with SYNONYMs #define
 * enabled, the branch includes ordinal number of a transaction
 * in a synonym list in hash table and is somewhat faster but
 * not reboot-resilient. SYNONYMs turned off are little slower
 * but work across reboots as well.
 *
 * The branch parameter is formed as follows:
 * SYNONYMS  on: hash.synonym.branch
 * SYNONYMS off: hash.md5.branch
 */

#include "../../dprint.h"
#include "../../parser/parser_f.h"
#include "../../parser/parse_from.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../hash_func.h"
#include "../../forward.h"
#include "t_funcs.h"
#include "config.h"
#include "sip_msg.h"
#include "t_hooks.h"
#include "t_lookup.h"
#include "dlg.h" /* for t_lookup_callid */
#include "t_msgbuilder.h" /* for t_lookup_callid */
#include "t_fwd.h" /* for get_on_branch */

#define EQ_VIA_LEN(_via)\
	( (p_msg->via1->bsize-(p_msg->_via->name.s-(p_msg->_via->hdr.s+p_msg->_via->hdr.len)))==\
	  	(t_msg->via1->bsize-(t_msg->_via->name.s-(t_msg->_via->hdr.s+t_msg->_via->hdr.len))) )



#define EQ_LEN(_hf) (t_msg->_hf->body.len==p_msg->_hf->body.len)
#define EQ_REQ_URI_LEN\
	(p_msg->first_line.u.request.uri.len==t_msg->first_line.u.request.uri.len)

#define EQ_STR(_hf) (memcmp(t_msg->_hf->body.s,\
	p_msg->_hf->body.s, \
	p_msg->_hf->body.len)==0)
#define EQ_REQ_URI_STR\
	( memcmp( t_msg->first_line.u.request.uri.s,\
	p_msg->first_line.u.request.uri.s,\
	p_msg->first_line.u.request.uri.len)==0)
#define EQ_VIA_STR(_via)\
	( memcmp( t_msg->_via->name.s,\
	 p_msg->_via->name.s,\
	 (t_msg->via1->bsize-(t_msg->_via->name.s-(t_msg->_via->hdr.s+t_msg->_via->hdr.len)))\
	)==0 )
#define EQ_STRS( _s1, _s2 ) \
	( (_s1).len==(_s2).len && memcmp((_s1).s,(_s2).s,(_s2).len)==0)


#define HF_LEN(_hf) ((_hf)->len)

/* should be request-uri matching used as a part of pre-3261
 * transaction matching, as the standard wants us to do so
 * (and is reasonable to do so, to be able to distinguish
 * spirals)? turn only off for better interaction with
 * devices that are broken and send different r-uri in
 * CANCEL/ACK than in original INVITE
 */
int ruri_matching=1;
int via1_matching=1;

/* this is a global variable which keeps pointer to
   transaction currently processed by a process; it it
   set by t_lookup_request or t_reply_matching; don't
   dare to change it anywhere else as it would
   break ref_counting
*/

static struct cell *T;

/* simillar to T, but it is used for the cancelled invite
 * transaction (when processing a CANCEL)
 */
static struct cell *cancelled_T;

/* simillar to T, but it is used for the ack-ed invite
 * transaction (when processing a end-to-end 200 ACK )
 */
static struct cell *e2eack_T;


struct cell *get_t(void) { return T; }
void set_t(struct cell *t) { T=t; }
void init_t(void) {set_t(T_UNDEFINED);}

struct cell *get_cancelled_t(void) { return cancelled_T; }
void set_cancelled_t(struct cell* t) { cancelled_T=t; }
void reset_cancelled_t(void) { cancelled_T=T_UNDEFINED; }

struct cell *get_e2eack_t(void) { return e2eack_T; }
void set_e2eack_t(struct cell* t) { e2eack_T=t; }
void reset_e2eack_t(void) { e2eack_T=T_UNDEFINED; }



static inline int parse_dlg( struct sip_msg *msg )
{
	if (parse_headers(msg, HDR_FROM_F | HDR_CSEQ_F | HDR_TO_F, 0)==-1) {
		LM_ERR("From or Cseq or To invalid\n");
		return 0;
	}
	if ((msg->from==0)||(msg->cseq==0)||(msg->to==0)) {
		LM_ERR("missing From or Cseq or To\n");
		return 0;
	}

	if (parse_from_header(msg)<0) {
		LM_ERR("From broken\n");
		return 0;
	}
	/* To is automatically parsed through HDR_TO in parse bitmap,
	 * we don't need to worry about it now
	if (parse_to_header(msg)==-1) {
		LM_ERR("To broken\n");
		return 0;
	}
	*/
	return 1;
}

/* is the ACK (p_msg) in p_msg dialog-wise equal to the INVITE (t_msg)
 * except to-tags? */
static inline int partial_dlg_matching(struct sip_msg *t_msg, struct sip_msg *p_msg)
{
	struct to_body *inv_from;

	if (!EQ_LEN(callid)) return 0;
	if (get_cseq(t_msg)->number.len!=get_cseq(p_msg)->number.len)
		return 0;
	inv_from=get_from(t_msg);
	if (!inv_from) {
		LM_ERR("INV/From not parsed\n");
		return 0;
	}
	if (inv_from->tag_value.len!=get_from(p_msg)->tag_value.len)
		return 0;
	if (!EQ_STR(callid))
		return 0;
	if (memcmp(get_cseq(t_msg)->number.s, get_cseq(p_msg)->number.s,
			get_cseq(p_msg)->number.len)!=0)
		return 0;
	if (memcmp(inv_from->tag_value.s, get_from(p_msg)->tag_value.s,
			get_from(p_msg)->tag_value.len)!=0)
		return 0;
	return 1;
}

/* are to-tags in ACK/200 same as those we sent out? */
static inline int dlg_matching(struct cell *p_cell, struct sip_msg *ack )
{
	if (get_to(ack)->tag_value.len!=p_cell->uas.local_totag.len)
		return 0;
	if (memcmp(get_to(ack)->tag_value.s,p_cell->uas.local_totag.s,
				p_cell->uas.local_totag.len)!=0)
		return 0;
	return 1;
}

static inline int ack_matching(struct cell *p_cell, struct sip_msg *p_msg)
{
	/* partial dialog matching -- no to-tag, only from-tag,
	 * callid, cseq number ; */
	if (!partial_dlg_matching(p_cell->uas.request, p_msg))
		return 0;

	/* if this transaction is proxied (as opposed to UAS) we're
	 * done now -- we ignore to-tags; the ACK simply belongs to
	 * this UAS part of dialog, whatever to-tag it gained
	 */
	if (p_cell->relaied_reply_branch!=-2) {
		return 2; /* e2e proxied ACK */
	}
	/* it's a local dialog -- we wish to verify to-tags too */
	if (dlg_matching(p_cell, p_msg)) {
		return 2;
	}
	return 0;
}

/* branch-based transaction matching */
static inline int via_matching( struct via_body *inv_via,
				struct via_body *ack_via )
{
	if (inv_via->tid.len!=ack_via->tid.len)
		return 0;
	if (memcmp(inv_via->tid.s, ack_via->tid.s,
				ack_via->tid.len)!=0)
		return 0;
	/* ok, tid matches -- now make sure that the
	 * originator matches too to avoid confusion with
	 * different senders generating the same tid
	 */
	if (inv_via->host.len!=ack_via->host.len)
		return 0;;
	if (memcmp(inv_via->host.s, ack_via->host.s,
			ack_via->host.len)!=0)
		return 0;
	if (inv_via->port!=ack_via->port)
		return 0;
	if (inv_via->transport.len!=ack_via->transport.len)
		return 0;
	if (memcmp(inv_via->transport.s, ack_via->transport.s,
			ack_via->transport.len)!=0)
		return 0;
	/* everything matched -- we found it */
	return 1;
}


/* transaction matching a-la RFC-3261 using transaction ID in branch
   (the function assumes there is magic cookie in branch)
   It returns:
	 2 if e2e ACK for a proxied transaction found
     1  if found (covers ACK for local UAS)
	 0  if not found (trans undefined)
*/

static int matching_3261( struct sip_msg *p_msg, struct cell **trans,
			enum request_method skip_method)
{
	struct cell *p_cell;
	struct sip_msg  *t_msg;
	struct via_body *via1;
	int is_ack;
	int dlg_parsed;
	int ret = 0;
	struct cell *e2e_ack_trans;

	e2e_ack_trans=0;
	via1=p_msg->via1;
	is_ack=p_msg->REQ_METHOD==METHOD_ACK;
	dlg_parsed=0;
	/* update parsed tid */
	via1->tid.s=via1->branch->value.s+MCOOKIE_LEN;
	via1->tid.len=via1->branch->value.len-MCOOKIE_LEN;

	for ( p_cell = get_tm_table()->entrys[p_msg->hash_index].first_cell;
		p_cell; p_cell = p_cell->next_cell )
	{
		t_msg=p_cell->uas.request;
		if (!t_msg) continue;  /* don't try matching UAC transactions */
		if (skip_method & t_msg->REQ_METHOD) continue;

		/* here we do an exercise which will be removed from future code
		 * versions: we try to match end-2-end ACKs if they appear at our
		 * server. This allows some applications bound to TM via callbacks
		 * to correlate the e2e ACKs with transaction context, e.g., for
		 * purpose of accounting. We think it is a bad place here, among
		 * other things because it is not reliable. If a transaction loops
		 * via OpenSIPS the ACK can't be matched to proper INVITE transaction
		 * (it is a separate transactino with its own branch ID) and it
		 * matches all transaction instances in the loop dialog-wise.
		 * Eventually, regardless to which transaction in the loop the
		 * ACK belongs, only the first one will match.
		 */

		/* dialog matching needs to be applied for ACK/200s */
		if (is_ack && e2e_ack_trans==0 &&
		p_cell->uas.status>=200 && p_cell->uas.status<300) {
			/* make sure we have parsed all things we need for dialog
			 * matching */
			if (!dlg_parsed) {
				dlg_parsed=1;
				if (!parse_dlg(p_msg)) {
					LM_ERR("dlg parsing failed\n");
					return 0;
				}
			}
			ret=ack_matching(p_cell /* t w/invite */, p_msg /* ack */);
			if (ret>0) {
				e2e_ack_trans=p_cell;
				continue;
			}
			/* this ACK is neither local "negative" one, nor a proxied
			 * end-2-end one, nor an end-2-end one for a UAS transaction
			 * -- we failed to match */
			continue;
		}
		/* now real tid matching occurs  for negative ACKs and any
	 	 * other requests */
		if (!via_matching(t_msg->via1 /* inv via */, via1 /* ack */ ))
			continue;
		/* all matched -- we found the transaction ! */
		LM_DBG("RFC3261 transaction matched, tid=%.*s\n",
			via1->tid.len, via1->tid.s);

		*trans=p_cell;
		return 1;
	}
	/* :-( ... we didn't find any */

	/* just check if it we found an e2e ACK previously */
	if (e2e_ack_trans) {
		*trans=e2e_ack_trans;
		return ret;
	}
	LM_DBG("RFC3261 transaction matching failed\n");
	return 0;
}


/* function returns:
 *      negative - transaction wasn't found
 *      -2       -  possibly e2e ACK matched
 *      positive - transaction found
 */

int t_lookup_request( struct sip_msg* p_msg , int leave_new_locked )
{
	struct cell         *p_cell;
	unsigned int       isACK;
	struct sip_msg  *t_msg;
	struct via_param *branch;
	int match_status;

	isACK = p_msg->REQ_METHOD==METHOD_ACK;

	if (isACK) {
		if (e2eack_T==NULL)
			return -1;
		if (e2eack_T!=T_UNDEFINED)
			return -2;
	}

	/* parse all*/
	if (check_transaction_quadruple(p_msg)==0) {
		LM_ERR("too few headers\n");
		set_t(0);
		/* stop processing */
		return 0;
	}

	/* start searching into the table */
	if (!p_msg->hash_index)
		p_msg->hash_index=tm_hash( p_msg->callid->body ,
			get_cseq(p_msg)->number ) ;
	LM_DBG("start searching: hash=%d, isACK=%d\n",
		p_msg->hash_index,isACK);


	/* first of all, look if there is RFC3261 magic cookie in branch; if
	 * so, we can do very quick matching and skip the old-RFC bizzar
	 * comparison of many header fields
	 */
	if (!p_msg->via1) {
		LM_ERR("no via\n");
		set_t(0);
		return 0;
	}
	branch=p_msg->via1->branch;
	if (branch && branch->value.s && branch->value.len>MCOOKIE_LEN
			&& memcmp(branch->value.s,MCOOKIE,MCOOKIE_LEN)==0) {
		/* huhuhu! the cookie is there -- let's proceed fast */
		LOCK_HASH(p_msg->hash_index);
		match_status=matching_3261(p_msg,&p_cell,
				/* skip transactions with different method; otherwise CANCEL
				 * would match the previous INVITE trans.  */
				isACK ? ~METHOD_INVITE: ~p_msg->REQ_METHOD);
		switch(match_status) {
				case 0:	goto notfound;	/* no match */
				case 1:	goto found; 	/* match */
				case 2:	goto e2e_ack;	/* e2e proxy ACK */
		}
	}

	/* ok -- it's ugly old-fashioned transaction matching -- it is
	 * a bit simplified to be fast -- we don't do all the comparisons
	 * of parsed uri, which was simply too bloated */
	LM_DBG("proceeding to pre-RFC3261 transaction matching\n");

	/* lock the whole entry*/
	LOCK_HASH(p_msg->hash_index);

	/* all the transactions from the entry are compared */
	for ( p_cell = get_tm_table()->entrys[p_msg->hash_index].first_cell;
		  p_cell; p_cell = p_cell->next_cell )
	{
		t_msg = p_cell->uas.request;

		if (!t_msg) continue; /* skip UAC transactions */

		if (!isACK) {
			/* compare lengths first */
			if (!EQ_LEN(callid)) continue;
			if (!EQ_LEN(cseq)) continue;
			if (!EQ_LEN(from)) continue;
			if (!EQ_LEN(to)) continue;
			if (ruri_matching && !EQ_REQ_URI_LEN) continue;
			if (via1_matching && !EQ_VIA_LEN(via1)) continue;

			/* length ok -- move on */
			if (!EQ_STR(callid)) continue;
			if (!EQ_STR(cseq)) continue;
			if (!EQ_STR(from)) continue;
			if (!EQ_STR(to)) continue;
			if (ruri_matching && !EQ_REQ_URI_STR) continue;
			if (via1_matching && !EQ_VIA_STR(via1)) continue;

			/* request matched ! */
			LM_DBG("non-ACK matched\n");
			goto found;
		} else { /* it's an ACK request*/
			/* ACK's relate only to INVITEs - and we look only for 2 types of
			 * INVITEs : (a) negative INVITEs or (b) pozitive UAS INVITEs */
			if ( t_msg->REQ_METHOD!=METHOD_INVITE || !(p_cell->uas.status>=300
			|| (p_cell->nr_of_outgoings==0 && p_cell->uas.status>=200)) )
				continue;

			/* From|To URI , CallID, CSeq # must be always there */
			/* compare lengths now */
			if (!EQ_LEN(callid)) continue;
			/* CSeq only the number without method ! */
			if (get_cseq(t_msg)->number.len!=get_cseq(p_msg)->number.len)
				continue;
			if (! EQ_LEN(from)) continue;
			/* To only the uri -- to many UACs screw up tags  */
			if (get_to(t_msg)->uri.len!=get_to(p_msg)->uri.len)
				continue;
			if (!EQ_STR(callid)) continue;
			if (memcmp(get_cseq(t_msg)->number.s, get_cseq(p_msg)->number.s,
				get_cseq(p_msg)->number.len)!=0) continue;
			if (!EQ_STR(from)) continue;
			if (memcmp(get_to(t_msg)->uri.s, get_to(p_msg)->uri.s,
				get_to(t_msg)->uri.len)!=0) continue;

			if (p_cell->uas.status<300) {
				/* it's a 2xx local UAS transaction */
				if (dlg_matching(p_cell, p_msg))
					goto e2e_ack;
				continue;
			}

			/* it is not an e2e ACK/200 -- perhaps it is
			 * local negative case; in which case we will want
			 * more elements to match: r-uri and via; allow
			 * mismatching r-uri as an config option for broken
			 * UACs */
			if (ruri_matching && !EQ_REQ_URI_LEN ) continue;
			if (via1_matching && !EQ_VIA_LEN(via1)) continue;
			if (ruri_matching && !EQ_REQ_URI_STR) continue;
			if (via1_matching && !EQ_VIA_STR(via1)) continue;

			/* wow -- we survived all the check! we matched! */
			LM_DBG("non-2xx ACK matched\n");
			goto found;
		} /* ACK */
	} /* synonym loop */

notfound:
	/* no transaction found */
	set_t(0);
	e2eack_T = NULL;
	if (!leave_new_locked || isACK) {
		UNLOCK_HASH(p_msg->hash_index);
	}
	LM_DBG("no transaction found\n");
	return -1;

e2e_ack:
	REF_UNSAFE( p_cell );
	UNLOCK_HASH(p_msg->hash_index);
	e2eack_T = p_cell;
	set_t(0);
	LM_DBG("e2e proxy ACK found\n");
	return -2;

found:
	set_t(p_cell);
	REF_UNSAFE( T );
	set_kr(REQ_EXIST);
	UNLOCK_HASH( p_msg->hash_index );
	LM_DBG("transaction found (T=%p)\n",T);
	return 1;
}



/* function lookups transaction being canceled by CANCEL in p_msg;
 * it returns:
 *       0 - transaction wasn't found
 *       T - transaction found
 */
struct cell* t_lookupOriginalT(  struct sip_msg* p_msg )
{
	struct cell     *p_cell;
	unsigned int     hash_index;
	struct sip_msg  *t_msg;
	struct via_param *branch;
	int ret;

	/* already looked for it? */
	if (cancelled_T!=T_UNDEFINED)
		return cancelled_T;

	/* start searching in the table */
	hash_index = p_msg->hash_index;
	LM_DBG("searching on hash entry %d\n",hash_index );


	/* first of all, look if there is RFC3261 magic cookie in branch; if
	 * so, we can do very quick matching and skip the old-RFC bizzar
	 * comparison of many header fields
	 */
	if (!p_msg->via1) {
		LM_ERR("no via\n");
		cancelled_T = NULL;
		return 0;
	}
	branch=p_msg->via1->branch;
	if (branch && branch->value.s && branch->value.len>MCOOKIE_LEN
			&& memcmp(branch->value.s,MCOOKIE,MCOOKIE_LEN)==0) {
		/* huhuhu! the cookie is there -- let's proceed fast */
		LOCK_HASH(hash_index);
		ret=matching_3261(p_msg, &p_cell,
				/* we are seeking the original transaction --
				 * skip CANCEL transactions during search
				 */
				METHOD_CANCEL);
		if (ret==1) goto found; else goto notfound;
	}

	/* no cookies --proceed to old-fashioned pre-3261 t-matching */

	LOCK_HASH(hash_index);

	/* all the transactions from the entry are compared */
	for (p_cell=get_tm_table()->entrys[hash_index].first_cell;
		p_cell; p_cell = p_cell->next_cell )
	{
		t_msg = p_cell->uas.request;

		if (!t_msg) continue; /* skip UAC transactions */

		/* we don't cancel CANCELs ;-) */
		if (t_msg->REQ_METHOD==METHOD_CANCEL)
			continue;

		/* check lengths now */
		if (!EQ_LEN(callid))
			continue;
		if (get_cseq(t_msg)->number.len!=get_cseq(p_msg)->number.len)
			continue;
		if (!EQ_LEN(from))
			continue;
#ifdef CANCEL_TAG
		if (!EQ_LEN(to))
			continue;
#else
		/* relaxed matching -- we don't care about to-tags anymore,
		 * many broken UACs screw them up and ignoring them does not
		 * actually hurt
		 */
		if (get_to(t_msg)->uri.len!=get_to(p_msg)->uri.len)
			continue;
#endif
		if (ruri_matching && !EQ_REQ_URI_LEN)
			continue;
		if (via1_matching && !EQ_VIA_LEN(via1))
			continue;

		/* check the content now */
		if (!EQ_STR(callid))
			continue;
		if (memcmp(get_cseq(t_msg)->number.s,
			get_cseq(p_msg)->number.s,get_cseq(p_msg)->number.len)!=0)
			continue;
		if (!EQ_STR(from))
			continue;
#ifdef CANCEL_TAG
		if (!EQ_STR(to))
			continue;
#else
		if (memcmp(get_to(t_msg)->uri.s, get_to(p_msg)->uri.s,
					get_to(t_msg)->uri.len)!=0)
			continue;
#endif
		if (ruri_matching && !EQ_REQ_URI_STR)
			continue;
		if (via1_matching && !EQ_VIA_STR(via1))
			continue;

		/* found */
		goto found;
	}

notfound:
	/* no transaction found */
	LM_DBG("no CANCEL matching found! \n" );
	UNLOCK_HASH(hash_index);
	cancelled_T = NULL;
	LM_DBG("t_lookupOriginalT completed\n");
	return 0;

found:
	LM_DBG("canceled transaction found (%p)! \n",p_cell );
	cancelled_T = p_cell;
	REF_UNSAFE( p_cell );
	UNLOCK_HASH(hash_index);
	/* run callback */
	run_trans_callbacks( TMCB_TRANS_CANCELLED, cancelled_T, p_msg, 0,0);
	LM_DBG("t_lookupOriginalT completed\n");
	return p_cell;
}




/* Returns 0 - nothing found
 *         1  - T found
 */
int t_reply_matching( struct sip_msg *p_msg , int *p_branch )
{
	struct cell*  p_cell;
	int hash_index   = 0;
	int entry_label  = 0;
	int branch_id    = 0;
	char  *hashi, *branchi, *p, *n;
	int hashl, branchl;
	int scan_space;
	struct cseq_body *cseq;

	char *loopi;
	int loopl;
	char *syni;
	int synl;

	/* make compiler warnings happy */
	loopi=0;
	loopl=0;
	syni=0;
	synl=0;

	/* split the branch into pieces: loop_detection_check(ignored),
	 hash_table_id, synonym_id, branch_id */

	if (!(p_msg->via1 && p_msg->via1->branch && p_msg->via1->branch->value.s))
		goto nomatch2;

	/* we do RFC 3261 tid matching and want to see first if there is
	 * magic cookie in branch */
	if (p_msg->via1->branch->value.len<=MCOOKIE_LEN)
		goto nomatch2;
	if (memcmp(p_msg->via1->branch->value.s, MCOOKIE, MCOOKIE_LEN)!=0)
		goto nomatch2;

	p=p_msg->via1->branch->value.s+MCOOKIE_LEN;
	scan_space=p_msg->via1->branch->value.len-MCOOKIE_LEN;


	/* hash_id */
	n=eat_token2_end( p, p+scan_space, BRANCH_SEPARATOR);
	hashl=n-p;
	scan_space-=hashl;
	if (!hashl || scan_space<2 || *n!=BRANCH_SEPARATOR) goto nomatch2;
	hashi=p;
	p=n+1;scan_space--;

	if (!syn_branch) {
		/* md5 value */
		n=eat_token2_end( p, p+scan_space, BRANCH_SEPARATOR );
		loopl = n-p;
		scan_space-= loopl;
		if (n==p || scan_space<2 || *n!=BRANCH_SEPARATOR)
			goto nomatch2;
		loopi=p;
		p=n+1; scan_space--;
	} else {
		/* synonym id */
		n=eat_token2_end( p, p+scan_space, BRANCH_SEPARATOR);
		synl=n-p;
		scan_space-=synl;
		if (!synl || scan_space<2 || *n!=BRANCH_SEPARATOR)
			goto nomatch2;
		syni=p;
		p=n+1;scan_space--;
	}

	/* branch id  -  should exceed the scan_space */
	n=eat_token_end( p, p+scan_space );
	branchl=n-p;
	if (!branchl ) goto nomatch2;
	branchi=p;

	/* sanity check */
	if ((hash_index=reverse_hex2int(hashi, hashl))<0
		||hash_index>=TM_TABLE_ENTRIES
		|| (branch_id=reverse_hex2int(branchi, branchl))<0
		||branch_id>=MAX_BRANCHES
		|| (syn_branch ? (entry_label=reverse_hex2int(syni, synl))<0
			: loopl!=MD5_LEN )
	) {
		LM_DBG("poor reply labels %d label %d branch %d\n",
				hash_index, entry_label, branch_id );
		goto nomatch2;
	}

	LM_DBG("hash %d label %d branch %d\n",hash_index, entry_label, branch_id);

	cseq = get_cseq(p_msg);

	/* search the hash table list at entry 'hash_index'; lock the
	   entry first */
	LOCK_HASH(hash_index);

	for (p_cell = get_tm_table()->entrys[hash_index].first_cell; p_cell;
		p_cell=p_cell->next_cell) {

		/* first look if branch matches */
		if (syn_branch) {
			if (p_cell->label != entry_label)
				continue;
		} else {
			if ( memcmp(p_cell->md5, loopi,MD5_LEN)!=0)
					continue;
		}

		/* sanity check ... too high branch ? */
		if ( branch_id>=p_cell->nr_of_outgoings )
			continue;

		/* does method match ? (remember -- CANCELs have the same branch
		   as canceled transactions) */
		if (!( /* it's a local cancel */
			(cseq->method_id==METHOD_CANCEL && is_invite(p_cell)
				&& p_cell->uac[branch_id].local_cancel.buffer.len )
			/* method match */
			|| ((cseq->method_id!=METHOD_OTHER && p_cell->uas.request)?
				(cseq->method_id==REQ_LINE(p_cell->uas.request).method_value)
				:(EQ_STRS(cseq->method,p_cell->method)))
		))
			continue;

		/* we passed all disqualifying factors .... the transaction has been
		   matched !
		*/
		set_t(p_cell);
		*p_branch = branch_id;
		REF_UNSAFE( T );
		UNLOCK_HASH(hash_index);
		LM_DBG("reply matched (T=%p)!\n",T);
		/* if this is a 200 for INVITE, we will wish to store to-tags to be
		 * able to distinguish retransmissions later and not to call
 		 * TMCB_RESPONSE_OUT uselessly; we do it only if callbacks are
		 * enabled -- except callback customers, nobody cares about
		 * retransmissions of multiple 200/INV or ACK/200s
		 */
		if (is_invite(p_cell) && p_msg->REPLY_STATUS>=200
		&& p_msg->REPLY_STATUS<300
		&& ( (!is_local(p_cell) &&
				has_tran_tmcbs(p_cell,
				TMCB_RESPONSE_OUT|TMCB_RESPONSE_PRE_OUT) )
			|| (is_local(p_cell)&&has_tran_tmcbs(p_cell,TMCB_LOCAL_COMPLETED))
		)) {
			if (parse_headers(p_msg, HDR_TO_F, 0)==-1) {
				LM_ERR("to parsing failed\n");
			}
		}
		if (!is_local(p_cell) &&
		!(cseq->method_id==METHOD_CANCEL && is_invite(p_cell)) ) {
			run_trans_callbacks( TMCB_RESPONSE_IN, T, T->uas.request, p_msg,
				p_msg->REPLY_STATUS);
		}
		return 1;
	} /* for cycle */

	/* nothing found */
	UNLOCK_HASH(hash_index);
	LM_DBG("no matching transaction exists\n");

nomatch2:
	LM_DBG("failure to match a transaction\n");
	*p_branch = -1;
	set_t(0);
	return -1;
}




/* Determine current transaction
 *
 *                   Found      Not Found     Error (e.g. parsing)
 *  Return Value     1          0             -1
 *  T                ptr        0             T_UNDEFINED
 */
int t_check( struct sip_msg* p_msg , int *param_branch )
{
	int local_branch;

	/* is T still up-to-date ? */
	LM_DBG("start=%p\n", T);
	if ( T==T_UNDEFINED )
	{
		/* transaction lookup */
		if ( p_msg->first_line.type==SIP_REQUEST ) {
			/* force parsing all the needed headers*/
			if (parse_headers(p_msg, HDR_EOH_F, 0 )==-1) {
				LM_ERR("parsing error\n");
				return -1;
			}
			/* in case, we act as UAS for INVITE and reply with 200,
			 * we will need to run dialog-matching for subsequent
			 * ACK, for which we need From-tag; We also need from-tag
			 * in case people want to have proxied e2e ACKs accounted
			 */
			if (p_msg->REQ_METHOD==METHOD_INVITE
							&& parse_from_header(p_msg)<0) {
				LM_ERR("from parsing failed\n");
				return -1;
			}
			t_lookup_request( p_msg , 0 /* unlock before returning */ );
		} else {
			/* we need Via for branch and Cseq method to distinguish
			   replies with the same branch/cseqNr (CANCEL)
			*/
			if ( parse_headers(p_msg, HDR_VIA1_F|HDR_CSEQ_F, 0 )==-1
			|| !p_msg->via1 || !p_msg->cseq ) {
				LM_ERR("reply cannot be parsed\n");
				return -1;
			}

			/* if that is an INVITE, we will also need to-tag
			   for later ACK matching */
			if ( get_cseq(p_msg)->method_id==METHOD_INVITE ) {
					if (parse_headers(p_msg, HDR_TO_F, 0)==-1 || !p_msg->to)  {
						LM_ERR("INVITE reply cannot be parsed\n");
						return -1;
					}
			}

			t_reply_matching( p_msg ,
				param_branch!=0?param_branch:&local_branch );

		}
#ifdef EXTRA_DEBUG
		if ( T && T!=T_UNDEFINED && T->damocles) {
			LM_ERR("transaction %p scheduled for deletion "
				"and called from t_check\n", T);
			abort();
		}
#endif
		LM_DBG("end=%p\n",T);
	} else {
		if (T)
			LM_DBG("transaction already found!\n");
		else
			LM_DBG("transaction previously sought and not found\n");
	}

	return T ? (T==T_UNDEFINED ? -1 : 1 ) : 0;
}

int init_rb( struct retr_buf *rb, struct sip_msg *msg)
{
	int proto;

	update_sock_struct_from_ip( &rb->dst.to, msg );
	proto=msg->rcv.proto;
	rb->dst.proto=proto;
	rb->dst.proto_reserved1=msg->rcv.proto_reserved1;
	/* use for sending replies the incoming interface of the request -bogdan */
	rb->dst.send_sock=msg->rcv.bind_address;
	return 1;
}


static inline void init_new_t(struct cell *new_cell, struct sip_msg *p_msg)
{
	struct sip_msg *shm_msg;

	shm_msg=new_cell->uas.request;
	new_cell->from.s=shm_msg->from->name.s;
	new_cell->from.len=HF_LEN(shm_msg->from);
	new_cell->to.s=shm_msg->to->name.s;
	new_cell->to.len=HF_LEN(shm_msg->to);
	new_cell->callid.s=shm_msg->callid->name.s;
	new_cell->callid.len=HF_LEN(shm_msg->callid);
	new_cell->cseq_n.s=shm_msg->cseq->name.s;
	new_cell->cseq_n.len=get_cseq(shm_msg)->number.s
		+get_cseq(shm_msg)->number.len
		-shm_msg->cseq->name.s;

	new_cell->method=new_cell->uas.request->first_line.u.request.method;
	if (p_msg->REQ_METHOD==METHOD_INVITE) new_cell->flags |= T_IS_INVITE_FLAG;
	new_cell->on_negative=get_on_negative();
	new_cell->on_reply=get_on_reply();
	new_cell->on_branch=get_on_branch();
}

static inline int new_t(struct sip_msg *p_msg, int full_uas)
{
	struct cell *new_cell;

	/* for ACK-dlw-wise matching, we want From-tags */
	if (p_msg->REQ_METHOD==METHOD_INVITE && parse_from_header(p_msg)<0) {
			LM_ERR("no valid From in INVITE\n");
			return E_BAD_REQ;
	}
	/* make sure uri will be parsed before cloning */
	if (parse_sip_msg_uri(p_msg)<0) {
		LM_ERR("uri invalid\n");
		return E_BAD_REQ;
	}

	/* add new transaction */
	new_cell = build_cell( p_msg , full_uas) ;
	if  ( !new_cell ){
		LM_ERR("out of mem\n");
		return E_OUT_OF_MEM;
	}

	insert_into_hash_table_unsafe( new_cell, p_msg->hash_index );
	INIT_REF_UNSAFE(T);
	/* init pointers to headers needed to construct local
	   requests such as CANCEL/ACK
	*/
	init_new_t(new_cell, p_msg);
	return 1;
}


/* atomic "new_tran" construct; it returns:

	<0	on error

	+1	if a request did not match a transaction
		- it that was an ack, the calling function
		  shall forward statelessly
		- otherwise it means, a new transaction was
		  introduced and the calling function
		  shall reply/relay/whatever_appropriate

	0 on retransmission
*/
int t_newtran( struct sip_msg* p_msg, int full_uas )
{
	int lret, my_err;

	/* is T still up-to-date ? */
	LM_DBG("transaction on entrance=%p\n",T);

	if ( T && T!=T_UNDEFINED  ) {
		LM_DBG("transaction already in process %p\n", T );
		return E_SCRIPT;
	}

	T = T_UNDEFINED;
	/* first of all, parse everything -- we will store in shared memory
	   and need to have all headers ready for generating potential replies
	   later; parsing later on demand is not an option since the request
	   will be in shmem and applying parse_headers to it would intermix
	   shmem with pkg_mem
	*/

	if (parse_headers(p_msg, HDR_EOH_F, 0 )<0) {
		LM_ERR("parse_headers failed\n");
		return E_BAD_REQ;
	}
	if ((p_msg->parsed_flag & HDR_EOH_F)!=HDR_EOH_F) {
			LM_ERR("EoH not parsed\n");
			return E_OUT_OF_MEM;
	}
	/* t_lookup_requests attempts to find the transaction;
	   it also calls check_transaction_quadruple -> it is
	   safe to assume we have from/callid/cseq/to
	*/
	lret = t_lookup_request( p_msg, 1 /* leave locked if not found */ );

	/* on error, pass the error in the stack ... nothing is locked yet
	   if 0 is returned */
	if (lret==0) return E_BAD_TUPEL;

	/* transaction found, it's a retransmission  */
	if (lret>0) {
		if (p_msg->REQ_METHOD==METHOD_ACK) {
			t_release_transaction(T);
		} else {
			t_retransmit_reply(T);
		}
		/* things are done -- return from script */
		return 0;
	}

	/* from now on, be careful -- hash table is locked */

	if (lret==-2) { /* was it an e2e ACK ? if so, trigger a callback */
		if (e2eack_T->relaied_reply_branch==-2) {
			/* if a ACK for a local replied transaction, release the
			 INVITE transaction and break the script -> simply absorb
			 the ACK request */
			t_release_transaction(e2eack_T);
			return 0;
		}
		LM_DBG("building branch for end2end ACK - flags=%X\n",e2eack_T->flags);
		/* to ensure unigueness acros time and space, compute the ACK
		 * branch in the same maner as for INVITE, but put a t->branch
		 * value that cannot exist for that INVITE - as it is compute as
		 * an INVITE, it will not overlapp with other INVITEs or requests.
		 * But the faked value for t->branch guarantee no overalap with
		 * corresponding INVITE  --bogdan */
		if (!t_calc_branch(e2eack_T, e2eack_T->nr_of_outgoings+1,
		p_msg->add_to_branch_s, &p_msg->add_to_branch_len )) {
			LM_ERR("ACK branch computation failed\n");
		}

		return 1;
	}

	/* transaction not found, it's a new request (lret<0, lret!=-2);
	   establish a new transaction ... */
	if (p_msg->REQ_METHOD==METHOD_ACK) /* ... unless it is in ACK */
		return 1;

	my_err=new_t(p_msg, full_uas);
	if (my_err<0) {
		LM_ERR("new_t failed\n");
		goto new_err;
	}


	UNLOCK_HASH(p_msg->hash_index);
	/* now, when the transaction state exists, check if
	   there is a meaningful Via and calculate it; better
	   do it now than later: state is established so that
	   subsequent retransmissions will be absorbed and will
	  not possibly block during Via DNS resolution; doing
	   it later would only burn more CPU as if there is an
	   error, we cannot relay later whatever comes out of the
	   the transaction
	*/
	if (!init_rb( &T->uas.response, p_msg)) {
		LM_ERR("unresolvable via1\n");
		put_on_wait( T );
		t_unref(p_msg);
		return E_BAD_VIA;
	}

	return 1;
new_err:
	UNLOCK_HASH(p_msg->hash_index);
	return my_err;

}


int t_unref( struct sip_msg* p_msg  )
{
	enum kill_reason kr;

	if (T==T_UNDEFINED)
		return -1;
	if (T!=T_NULL_CELL) {
		if (p_msg->first_line.type==SIP_REQUEST){
			kr=get_kr();
			if (kr==0 ||(p_msg->REQ_METHOD==METHOD_ACK && !(kr & REQ_RLSD)))
				t_release_transaction(T);
		}
		UNREF( T );
	}
	set_t(T_UNDEFINED);
	return 1;
}

void t_ref_cell(struct cell *c)
{
	REF(c);
}

void t_unref_cell(struct cell *c)
{
	UNREF(c);
}

int t_get_trans_ident(struct sip_msg* p_msg, unsigned int* hash_index,
															unsigned int* label)
{
	struct cell* t;
	if(t_check(p_msg,0) != 1){
		LM_ERR("no transaction found\n");
		return -1;
	}
	t = get_t();
	if(!t){
		LM_ERR("transaction found is NULL\n");
		return -1;
	}

	*hash_index = t->hash_index;
	*label = t->label;

	return 1;
}



int t_lookup_ident(struct cell ** trans, unsigned int hash_index,
															unsigned int label)
{
	struct cell* p_cell;

	if(hash_index >= TM_TABLE_ENTRIES){
		LM_ERR("invalid hash_index=%u\n",hash_index);
		return -1;
	}

	LOCK_HASH(hash_index);

	/* all the transactions from the entry are compared */
	for ( p_cell = get_tm_table()->entrys[hash_index].first_cell;
		p_cell; p_cell = p_cell->next_cell )
	{
		if(p_cell->label == label){
			REF_UNSAFE(p_cell);
			UNLOCK_HASH(hash_index);
			set_t(p_cell);
			*trans=p_cell;
			LM_DBG("transaction found\n");
			return 1;
		}
	}

	UNLOCK_HASH(hash_index);
	set_t(0);
	*trans=p_cell;

	LM_DBG("transaction not found\n");
	return -1;
}



int t_is_local(struct sip_msg* p_msg)
{
	struct cell* t;
	if(t_check(p_msg,0) != 1){
		LM_ERR("no transaction found\n");
		return -1;
	}
	t = get_t();
	if(!t){
		LM_ERR("transaction found is NULL\n");
		return -1;
	}

	return is_local(t);
}



/* lookup a transaction by callid and cseq, parameters are pure
 * header field content only, e.g. "123@10.0.0.1" and "11"
 */
int t_lookup_callid(struct cell ** trans, str callid, str cseq) {
	struct cell* p_cell;
	unsigned int hash_index;

	/* I use MAX_HEADER, not sure if this is a good choice... */
	char callid_header[MAX_HEADER];
	char cseq_header[MAX_HEADER];
	/* save return value of print_* functions here */
	char* endpos;
	UNUSED(endpos);

	/* need method, which is always INVITE in our case */
	/* CANCEL is only useful after INVITE */
	str invite_method;
	char* invite_string = INVITE;

	invite_method.s = invite_string;
	invite_method.len = INVITE_LEN;

	/* lookup the hash index where the transaction is stored */
	hash_index=tm_hash(callid, cseq);

	if(hash_index >= TM_TABLE_ENTRIES){
		LM_ERR("invalid hash_index=%u\n",hash_index);
		return -1;
	}

	/* create header fields the same way tm does itself, then compare headers */
	endpos = print_callid_mini(callid_header, callid);
	LM_DBG("created comparable call_id header field: >%.*s<\n",
			(int)(endpos - callid_header), callid_header);

	endpos = print_cseq_mini(cseq_header, &cseq, &invite_method);
	LM_DBG("created comparable cseq header field: >%.*s<\n",
			(int)(endpos - cseq_header), cseq_header);

	LOCK_HASH(hash_index);

	/* all the transactions from the entry are compared */
	p_cell = get_tm_table()->entrys[hash_index].first_cell;
	for ( ; p_cell; p_cell = p_cell->next_cell ) {

		/* compare complete header fields, casecmp to make sure invite=INVITE */
		LM_DBG(" <%.*s>  <%.*s>\n", p_cell->callid.len, p_cell->callid.s,
			p_cell->cseq_n.len,p_cell->cseq_n.s);
		if ( (strncmp(callid_header, p_cell->callid.s, p_cell->callid.len) == 0)
			&& (strncasecmp(cseq_header, p_cell->cseq_n.s, p_cell->cseq_n.len) == 0) ) {
			LM_DBG("we have a match: callid=>>%.*s<< cseq=>>%.*s<<\n",
				p_cell->callid.len,p_cell->callid.s, p_cell->cseq_n.len,
				p_cell->cseq_n.s);
			REF_UNSAFE(p_cell);
			UNLOCK_HASH(hash_index);
			set_t(p_cell);
			*trans=p_cell;
			LM_DBG("transaction found.\n");
			return 1;
		}
		LM_DBG("NO match: callid=%.*s cseq=%.*s\n",
			p_cell->callid.len, p_cell->callid.s,
			p_cell->cseq_n.len, p_cell->cseq_n.s);
	}

	UNLOCK_HASH(hash_index);
	LM_DBG("transaction not found.\n");

	return -1;
}

