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
 * --------
 * 2003-03-16 : backwards-compatibility callback names introduced (jiri)
 * 2003-03-06 : old callbacks renamed, new one introduced (jiri)
 * 2003-12-04 : global callbacks moved into transaction callbacks;
 *              multiple events per callback added; single list per
 *              transaction for all its callbacks (bogdan)
 * 2006-03-29 : added transaction callbacks: TMCB_REQUEST_BUILT and
 *              TMCB_REQUEST_DELETED (bogdan)
 */


#ifndef _HOOKS_H
#define _HOOKS_H

struct sip_msg;
struct cell;


#define TMCB_REQUEST_IN         (1<<0)
#define TMCB_RESPONSE_IN        (1<<1)
#define TMCB_REQUEST_FWDED      (1<<2)
#define TMCB_RESPONSE_FWDED     (1<<3)
#define TMCB_ON_FAILURE         (1<<5)
#define TMCB_RESPONSE_PRE_OUT   (1<<6)
#define TMCB_RESPONSE_OUT       (1<<7)
#define TMCB_LOCAL_COMPLETED    (1<<8)
#define TMCB_LOCAL_RESPONSE_OUT (1<<9)
#define TMCB_REQUEST_BUILT      (1<<10)
#define TMCB_TRANS_CANCELLED    (1<<11)
#define TMCB_TRANS_DELETED      (1<<12)
#define TMCB_PRE_SEND_BUFFER	(1<<13)
#define TMCB_MAX                ((1<<14)-1)

/*
 *  Caution: most of the callbacks work with shmem-ized messages
 *  which you can no more change (e.g., lumps are fixed). Most
 *  reply-processing callbacks are also called from a mutex,
 *  which may cause deadlock if you are not careful. Also, reply
 *  callbacks may pass the value of FAKED_REPLY messages, which
 *  is a non-dereferencable pointer indicating that no message
 *  was received and a timer hit instead.
 *
 *  All callbacks excepting the TMCB_REQUEST_IN are associates to a
 *  transaction. It means they will be run only when the event will hint
 *  the transaction the callbacks were register for.
 *  TMCB_REQUEST_IN is a global callback - it means it will be run for
 *  all transactions.
 *
 *
 *  Callback description:
 *  ---------------------
 *
 * TMCB_REQUEST_IN -- a brand-new request was received and is
 *  about to establish transaction; it is not yet cloned and
 *  lives in pkg mem -- your last chance to mangle it before
 *  it gets shmem-ized (then, it's read-only); it's called from
 *  HASH_LOCK, so be careful. It is guaranteed not to be
 *  a retransmission. The transactional context is mostly
 *  incomplete -- this callback is called in very early stage
 *  before the message is shmem-ized (so that you can work
 *  with it).
 *
 * TMCB_RESPONSE_IN -- a brand-new reply was received which matches
 *  an existing transaction. It may or may not be a retransmission.
 *
 * TMCB_RESPONSE_PRE_OUT -- a final reply is about to be sent out
 *  (either local or proxied); you cannnot change the reply, but
 *  it is useful to update your state before putting the reply on
 *  the network and to avoid any races (receiving an ACK before
 *  updating with the status of the reply)
 *
 * TMCB_RESPONSE_OUT -- a final reply was sent out (either local
 *  or proxied) -- there is nothing more you can change from
 *  the callback, it is good for accounting-like uses.
 *
 *    Note: the message passed to callback may also have
 *    value FAKED_REPLY (like other reply callbacks) which
 *    indicates a pseudo_reply caused by a timer. Check for
 *    this value before deferring -- you will cause a segfault
 *    otherwise. Check for t->uas.request validity too if you
 *    need it ... locally initiated UAC transactions set it to 0.
 *
 * (obsolete) TMCB_ON_FAILURE_RO -- called on receipt of a reply or timer;
 *  it means all branches completed with a failure; the callback
 *  function MUST not change anything in the transaction (READONLY)
 *  that's a chance for doing ACC or stuff like this
 *
 * TMCB_ON_FAILURE -- called on receipt of a reply or timer;
 *  it means all branches completed with a failure; that's
 *  a chance for example to add new transaction branches
 *
 * TMCB_RESPONSE_FWDED -- called when a reply is about to be
 *  forwarded; it is called after a message is received but before
 *  a message is sent out: it is called when the decision is
 *  made to forward a reply; it is parametrized by pkg message
 *  which caused the transaction to complete (which is not
 *  necessarily the same which will be forwarded). As forwarding
 *  has not been executed and may fail, there is no guarantee
 *  a reply will be successfully sent out at this point of time.
 *
 *     Note: TMCB_REPLY_ON_FAILURE and TMCB_REPLY_FWDED are
 *     called from reply mutex which is used to deterministically
 *     process multiple replies received in parallel. A failure
 *     to set the mutex again or stay too long in the callback
 *     may result in deadlock.
 *
 *     Note: the reply callbacks will not be evoked if "silent
 *     C-timer hits". That's a feature to clean transactional
 *     state from a proxy quickly -- transactions will then
 *     complete statelessly. If you wish to disable this
 *     feature, either set the global option "noisy_ctimer"
 *     to 1, or set t->noisy_ctimer for selected transaction.
 *
 * TMCB_REQUEST_FWDED -- request is being forwarded out. It is
 *  called before a message is forwarded and it is your last
 *  chance to change its shape.
 *
 * TMCB_LOCAL_COMPLETED -- final reply for localy initiated
 *  transaction arrived. Message may be FAKED_REPLY.
 *
 *
 * IMPORTANT NOTES:
 *
 * 1) that callbacks MUST be installed before forking
 *  (callback lists do not live in shmem and have no access
 *  protection), i.e., at best from mod_init functions.
 *
 * 2) the callback's param MUST be in shared memory and will
 *  NOT be freed by TM; you must do it yourself from the
 *  callback function if necessary.
*/


/* pack structure with all params passed to callback function */
struct tmcb_params {
	struct sip_msg* req;
	struct sip_msg* rpl;
	int code;
	void **param;
	void *extra1;
	void *extra2;
};

/* callback function prototype */
typedef void (transaction_cb) (struct cell* t, int type, struct tmcb_params*);
/* function to release the callback param */
typedef void (release_tmcb_param) (void *param);
/* register callback function prototype */
typedef int (*register_tmcb_f)(struct sip_msg* p_msg, struct cell *t,
		int cb_types, transaction_cb f, void *param, release_tmcb_param func);


struct tm_callback {
	int id;                      /* id of this callback - useless */
	int types;                   /* types of events that trigger the callback*/
	transaction_cb* callback;    /* callback function */
	void *param;                 /* param to be passed to callback function */
	release_tmcb_param *release; /* function to release the callback param when the callback is deleted */
	struct tm_callback* next;
};

struct tmcb_head_list {
	struct tm_callback *first;
	int reg_types;
};


extern struct tmcb_head_list*  req_in_tmcb_hl;

extern struct tmcb_head_list tmcb_pending_hl;
extern unsigned int tmcb_pending_id;

#define has_tran_tmcbs(_T_, _types_) \
	( ((_T_)->tmcb_hl.reg_types)&(_types_) )
#define has_reqin_tmcbs() \
	( req_in_tmcb_hl->first!=0 )


void empty_tmcb_list(struct tmcb_head_list *head);

int init_tmcb_lists(void);

void destroy_tmcb_lists(void);


/* register a callback for several types of events */
int register_tmcb( struct sip_msg* p_msg, struct cell *t, int types,
				  transaction_cb f, void *param, release_tmcb_param release_func );

/* inserts a callback into the a callback list */
int insert_tmcb(struct tmcb_head_list *cb_list, int types,
				transaction_cb f, void *param, release_tmcb_param release_func );

/* set extra params for callbacks */
void set_extra_tmcb_params(void *extra1, void *extra2);

/* run all transaction callbacks for an event type */
void run_trans_callbacks( int type , struct cell *trans,
						struct sip_msg *req, struct sip_msg *rpl, int code );

void run_trans_callbacks_locked( int type , struct cell *trans,
						struct sip_msg *req, struct sip_msg *rpl, int code );

/* run all REQUEST_IN callbacks */
void run_reqin_callbacks( struct cell *trans, struct sip_msg *req, int code );


typedef int (*ctx_load_register_func)(void*);

#endif
