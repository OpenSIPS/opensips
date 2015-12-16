/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2007 Voice Sistem SRL
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
 *  2003-06-27  timers are not unlinked if timerlist is 0 (andrei)
 *  2004-02-13  t->is_invite, t->local, t->noisy_ctimer replaced;
 *              timer_link.payload removed (bogdan)
 *  2007-02-02  retransmission timers have milliseconds resolution;
 *              adde faster timers (shortcuts based on timeout) (bogdan)
 */



/*
  timer.c is where we implement TM timers. It has been designed
  for high performance using some techniques of which timer users
  need to be aware.

	One technique is "fixed-timer-length". We maintain separate
	timer lists, all of them include elements of the same time
	to fire. That allows *appending* new events to the list as
	opposed to inserting them by time, which is costly due to
	searching time spent in a mutex. The performance benefit is
	noticeable. The limitation is you need a new timer list for
	each new timer length.

	Another technique is the timer process slices off expired elements
	from the list in a mutex, but executes the timer after the mutex
	is left. That saves time greatly as whichever process wants to
	add/remove a timer, it does not have to wait until the current
	list is processed. However, be aware the timers may hit in a delayed
	manner; you have no guarantee in your process that after resetting a timer,
	it will no more hit. It might have been removed by timer process,
    and is waiting to be executed.  The following example shows it:

			PROCESS1				TIMER PROCESS

	0.								timer hits, it is removed from queue and
									about to be executed
	1.	process1 decides to
		reset the timer
	2.								timer is executed now
	3.	if the process1 naively
		thinks the timer could not
		have been executed after
		resetting the timer, it is
		WRONG -- it was (step 2.)

	So be careful when writing the timer handlers. Currently defined timers
	don't hurt if they hit delayed, I hope at least. Retransmission timer
	may results in a useless retransmission -- not too bad. FR timer not too
	bad either as timer processing uses a REPLY mutex making it safe to other
	processing affecting transaction state. Wait timer not bad either -- processes
	putting a transaction on wait don't do anything with it anymore.

		Example when it does not hurt:

			P1						TIMER
	0.								RETR timer removed from list and
									scheduled for execution
	1. 200/BYE received->
	   reset RETR, put_on_wait
	2.								RETR timer executed -- too late but it does
									not hurt
	3.								WAIT handler executed

	The rule of thumb is don't touch data you put under a timer. Create data,
    put them under a timer, and let them live until they are safely destroyed from
    wait/delete timer.  The only safe place to manipulate the data is
    from timer process in which delayed timers cannot hit (all timers are
    processed sequentially).

	A "bad example" -- rewriting content of retransmission buffer
	in an unprotected way is bad because a delayed retransmission timer might
	hit. Thats why our reply retransmission procedure is enclosed in
	a REPLY_LOCK.

*/


#include "config.h"
#include "h_table.h"
#include "timer.h"
#include "../../dprint.h"
#include "lock.h"

#include "../../hash_func.h"
#include "../../dprint.h"
#include "../../config.h"
#include "../../parser/parser_f.h"
#include "../../ut.h"
#include "../../context.h"
#include "t_funcs.h"
#include "t_reply.h"
#include "t_cancel.h"


static struct timer_table *timertable=0;
static unsigned int timer_sets = 0;
static struct timer detached_timer; /* just to have a value to compare with*/

#define DETACHED_LIST (&detached_timer)

#define is_in_timer_list2(_tl) ( (_tl)->timer_list &&  \
									((_tl)->timer_list!=DETACHED_LIST) )



int timer_group[NR_OF_TIMER_LISTS] =
{
	TG_FR, TG_FR,
	TG_WT,
	TG_DEL,
	TG_RT, TG_RT, TG_RT, TG_RT
};

/* default values of timeouts for all the timer list
   (see timer.h for enumeration of timer lists)
*/
unsigned int timer_id2timeout[NR_OF_TIMER_LISTS] = {
	FR_TIME_OUT, 		/* FR_TIMER_LIST */
	INV_FR_TIME_OUT, 	/* FR_INV_TIMER_LIST */
	WT_TIME_OUT, 		/* WT_TIMER_LIST */
	DEL_TIME_OUT,		/* DELETE_LIST */
	RETR_T1, 			/* RT_T1_TO_1 */
	0, 					/* RT_T1_TO_2 */
	0, 					/* RT_T1_TO_3 */
	RETR_T2 			/* RT_T2 */
						/* NR_OF_TIMER_LISTS */
};

#define UTIME_TYPE 1

static unsigned int timer_id2type[NR_OF_TIMER_LISTS] = {
	0, 				/* FR_TIMER_LIST */
	0, 				/* FR_INV_TIMER_LIST */
	0, 				/* WT_TIMER_LIST */
	0, 				/* DELETE_LIST */
	UTIME_TYPE, 	/* RT_T1_TO_1 */
	UTIME_TYPE, 	/* RT_T1_TO_2 */
	UTIME_TYPE, 	/* RT_T1_TO_3 */
	UTIME_TYPE  	/* RT_T2 */
					/* NR_OF_TIMER_LISTS */
};


/******************** handlers ***************************/


static void unlink_timers( struct cell *t );

static void delete_cell( struct cell *p_cell, int unlock )
{
#ifdef EXTRA_DEBUG
	int i;
#endif

	/* there may still be FR/RETR timers, which have been reset
	   (i.e., time_out==TIMER_DELETED) but are stilled linked to
	   timer lists and must be removed from there before the
	   structures are released
	*/
	unlink_timers( p_cell );

#ifdef EXTRA_DEBUG
	if (is_in_timer_list2(& p_cell->wait_tl )) {
		LM_ERR("transaction %p scheduled for deletion and still on WAIT,"
				" timeout=%lld\n",p_cell, p_cell->wait_tl.time_out);
		abort();
	}
	if (is_in_timer_list2(& p_cell->uas.response.retr_timer )) {
		LM_ERR("transaction %p scheduled for deletion and still on RETR (rep),"
			"timeout=%lld\n",p_cell, p_cell->uas.response.retr_timer.time_out);
		abort();
	}
	if (is_in_timer_list2(& p_cell->uas.response.fr_timer )) {
		LM_ERR("transaction %p scheduled for deletion and still on FR (rep),"
			" timeout=%lld\n", p_cell,p_cell->uas.response.fr_timer.time_out);
		abort();
	}
	for (i=0; i<p_cell->nr_of_outgoings; i++) {
		if (is_in_timer_list2(& p_cell->uac[i].request.retr_timer)) {
			LM_ERR("transaction %p scheduled for deletion and still on RETR "
				"(req %d), timeout %lld\n", p_cell, i,
				p_cell->uac[i].request.retr_timer.time_out);
			abort();
		}
		if (is_in_timer_list2(& p_cell->uac[i].request.fr_timer)) {
			LM_ERR("transaction %p scheduled for deletion and"
				" still on FR (req %d), timeout %lld\n", p_cell, i,
				p_cell->uac[i].request.fr_timer.time_out);
			abort();
		}
		if (is_in_timer_list2(& p_cell->uac[i].local_cancel.retr_timer)) {
			LM_ERR("transaction %p scheduled for deletion and"
				" still on RETR/cancel (req %d), timeout %lld\n", p_cell, i,
				p_cell->uac[i].request.retr_timer.time_out);
			abort();
		}
		if (is_in_timer_list2(& p_cell->uac[i].local_cancel.fr_timer)) {
			LM_ERR("transaction %p scheduled for deletion and"
				" still on FR/cancel (req %d), timeout %lld\n", p_cell, i,
				p_cell->uac[i].request.fr_timer.time_out);
			abort();
		}
	}
	/* reset_retr_timers( hash__XX_table, p_cell ); */
#endif
	/* still in use ... don't delete */
	if ( IS_REFFED_UNSAFE(p_cell) ) {
		LM_DBG("delete_cell %p: can't delete -- still reffed (%d)\n",
			p_cell, p_cell->ref_count);
		if (unlock) UNLOCK_HASH(p_cell->hash_index);
		/* set to NULL so that set_timer will work */
		p_cell->dele_tl.timer_list= NULL;
		/* it's added to del list for future del */
		set_timer( &(p_cell->dele_tl), DELETE_LIST, 0 );
	} else {
		if (unlock) UNLOCK_HASH(p_cell->hash_index);
		LM_DBG("delete transaction %p\n", p_cell );
		free_cell( p_cell );
	}
}


static void fake_reply(struct cell *t, int branch, int code )
{
	static context_p my_ctx = NULL;
	context_p old_ctx;
	branch_bm_t cancel_bitmap;
	short do_cancel_branch;
	enum rps reply_status;

	/* as this processing is outside the scope of other messages (it is
	   trigger from timer), a processing context must be attached to it */
	old_ctx = current_processing_ctx;
	if (my_ctx==NULL) {
		my_ctx = context_alloc(CONTEXT_GLOBAL);
		if (my_ctx==NULL) {
			LM_ERR("failed to alloc new ctx in pkg\n");
		}
	}
	memset( my_ctx, 0, context_size(CONTEXT_GLOBAL) );
	current_processing_ctx = my_ctx;

	do_cancel_branch = is_invite(t) && should_cancel_branch(t, branch);

	cancel_bitmap=do_cancel_branch ? 1<<branch : 0;
	if ( is_local(t) ) {
		reply_status=local_reply( t, FAKED_REPLY, branch,
					  code, &cancel_bitmap );
		if (reply_status==RPS_COMPLETED) {
			put_on_wait(t);
		}
	} else {
		reply_status=relay_reply( t, FAKED_REPLY, branch, code,
			&cancel_bitmap );
	}

	if (current_processing_ctx==NULL)
		my_ctx=NULL;
	else
		context_destroy(CONTEXT_GLOBAL, my_ctx);

	/* switch back to the old context */
	current_processing_ctx = old_ctx;
}





inline static void retransmission_handler( struct timer_link *retr_tl )
{
	struct retr_buf* r_buf ;
	enum lists id;

	r_buf = get_retr_timer_payload(retr_tl);
#ifdef EXTRA_DEBUG
	if (r_buf->my_T->damocles) {
		LM_ERR("transaction %p scheduled for deletion and"
			" called from RETR timer\n",r_buf->my_T);
		abort();
	}
#endif

	/* the transaction is already removed from RETRANSMISSION_LIST by timer*/
	/* retransmission */
	if ( r_buf->activ_type==TYPE_LOCAL_CANCEL
		|| r_buf->activ_type==TYPE_REQUEST ) {
			LM_DBG("retransmission_handler : request resending"
				" (t=%p, %.9s ... )\n", r_buf->my_T, r_buf->buffer.s);
			set_t(r_buf->my_T);
			SEND_BUFFER( r_buf );
			/*if (SEND_BUFFER( r_buf )==-1) {
				reset_timer( &r_buf->fr_timer );
				fake_reply(r_buf->my_T, r_buf->branch, 503 );
				return;
			}*/
			set_t(T_UNDEFINED);
	} else {
			LM_DBG("retransmission_handler : reply resending "
				"(t=%p, %.9s ... )\n", r_buf->my_T, r_buf->buffer.s);
			set_t(r_buf->my_T);
			t_retransmit_reply(r_buf->my_T);
			set_t(T_UNDEFINED);
	}

	id = r_buf->retr_list;
	r_buf->retr_list = id < RT_T2 ? id + 1 : RT_T2;

	retr_tl->timer_list= NULL; /* set to NULL so that set_timer will work */
	set_timer( retr_tl, id < RT_T2 ? id + 1 : RT_T2, 0 );

	LM_DBG("retransmission_handler : done\n");
}




inline static void final_response_handler( struct timer_link *fr_tl )
{
#define CANCEL_REASON_SIP_480  \
	"Reason: SIP;cause=480;text=\"NO_ANSWER\"" CRLF

	struct retr_buf* r_buf;
	struct cell *t;

	if (fr_tl==0){
		/* or BUG?, ignoring it for now */
		LM_CRIT("final_response_handler(0) called\n");
		return;
	}
	r_buf = get_fr_timer_payload(fr_tl);
	t=r_buf->my_T;

#	ifdef EXTRA_DEBUG
	if (t->damocles)
	{
		LM_ERR("transaction %p scheduled for deletion and"
			" called from FR timer\n",r_buf->my_T);
		abort();
	}
#	endif

	reset_timer(  &(r_buf->retr_timer) );

	/* the transaction is already removed from FR_LIST by the timer */

	/* FR for local cancels.... */
	if (r_buf->activ_type==TYPE_LOCAL_CANCEL)
	{
		LM_DBG("stop retr for Local Cancel\n");
		return;
	}

	/* FR for replies (negative INVITE replies) */
	if (r_buf->activ_type>0) {
#		ifdef EXTRA_DEBUG
		if (t->uas.request->REQ_METHOD!=METHOD_INVITE
			|| t->uas.status < 200 ) {
			LM_ERR("unknown type reply buffer\n");
			abort();
		}
#		endif
		put_on_wait( t );
		return;
	};

	/* out-of-lock do the cancel I/O */
	if (is_invite(t) && should_cancel_branch(t, r_buf->branch) ) {
		set_cancel_extra_hdrs( CANCEL_REASON_SIP_480, sizeof(CANCEL_REASON_SIP_480)-1);
		cancel_branch(t, r_buf->branch );
		set_cancel_extra_hdrs( NULL, 0);
	}
	/* lock reply processing to determine how to proceed reliably */
	LOCK_REPLIES( t );
	LM_DBG("Cancel sent out, sending 408 (%p)\n", t);
	fake_reply(t, r_buf->branch, 408 );

	LM_DBG("done\n");
}



void cleanup_localcancel_timers( struct cell *t )
{
	int i;
	for (i=0; i<t->nr_of_outgoings; i++ )  {
		reset_timer(  &t->uac[i].local_cancel.retr_timer );
		reset_timer(  &t->uac[i].local_cancel.fr_timer );
	}
}


inline static void wait_handler( struct timer_link *wait_tl )
{
	struct cell *p_cell;

	p_cell = get_wait_timer_payload( wait_tl );
#ifdef EXTRA_DEBUG
	if (p_cell->damocles) {
		LM_ERR("transaction %p scheduled for deletion and"
			" called from WAIT timer\n",p_cell);
		abort();
	}
	LM_DBG("WAIT timer hit\n");
#endif

	/* stop cancel timers if any running */
	if ( is_invite(p_cell) ) cleanup_localcancel_timers( p_cell );

	/* the transaction is already removed from WT_LIST by the timer */
	/* remove the cell from the hash table */
	LM_DBG("removing %p from table \n", p_cell );
	LOCK_HASH( p_cell->hash_index );
	remove_from_hash_table_unsafe(  p_cell );
	/* jku: no more here -- we do it when we put a transaction on wait */
#ifdef EXTRA_DEBUG
	p_cell->damocles = 1;
#endif
	/* delete (returns with UNLOCK-ed_HASH) */
	delete_cell( p_cell, 1 /* unlock on return */ );
	LM_DBG("done\n");
}



inline static void delete_handler( struct timer_link *dele_tl )
{
	struct cell *p_cell;

	p_cell = get_dele_timer_payload( dele_tl );
	LM_DBG("removing %p \n", p_cell );
#ifdef EXTRA_DEBUG
	if (p_cell->damocles==0) {
		LM_ERR("transaction %p not scheduled for deletion"
			" and called from DELETE timer\n",p_cell);
		abort();
	}
#endif

	/* we call delete now without any locking on hash/ref_count;
	   we can do that because delete_handler is only entered after
	   the delete timer was installed from wait_handler, which
	   removed transaction from hash table and did not destroy it
	   because some processes were using it; that means that the
	   processes currently using the transaction can unref and no
	   new processes can ref -- we can wait until ref_count is
	   zero safely without locking
	*/
	delete_cell( p_cell, 0 /* don't unlock on return */ );
	LM_DBG("done\n");
}


/***********************************************************/

struct timer_table *get_timertable(void)
{
	return timertable;
}


void unlink_timer_lists(void)
{
	struct timer_link  *tl, *end, *tmp;
	enum lists i;
	unsigned int set;

	if (timertable==0)
		return; /* nothing to do */

	for ( set=0 ; set<timer_sets ; set++) {
		/* remember the DELETE LIST */
		tl = timertable[set].timers[DELETE_LIST].first_tl.next_tl;
		end = & timertable[set].timers[DELETE_LIST].last_tl;
		/* unlink the timer lists */
		for( i=0; i<NR_OF_TIMER_LISTS ; i++ )
			reset_timer_list( set, i );
		LM_DBG("emptying DELETE list for set %d\n",set);
		/* deletes all cells from DELETE_LIST list 
		   (they are no more accessible from entrys) */
		while (tl!=end) {
			tmp=tl->next_tl;
			free_cell( get_dele_timer_payload(tl) );
			tl=tmp;
		}
	}

}



struct timer_table *tm_init_timers( unsigned int sets )
{
	enum lists i;
	unsigned int set;

	LM_DBG("creating %d parallel timer structures\n", timer_sets);

	timertable = (struct timer_table *)shm_malloc
		( sets * sizeof(struct timer_table));
	if (!timertable) {
		LM_ERR("no more share memory\n");
		goto error0;
	}
	memset(timertable, 0, sets * sizeof(struct timer_table));
	timer_sets = sets;

	/* check the timeout values */
	if ( timer_id2timeout[FR_TIMER_LIST]<MIN_TIMER_VALUE ) {
		LM_ERR("FR_TIMER must be at least %d\n",
			MIN_TIMER_VALUE);
		goto error0;
	}

	if ( timer_id2timeout[FR_INV_TIMER_LIST]<MIN_TIMER_VALUE ) {
		LM_ERR("FR_INV_TIMER must be at least %d\n",
			MIN_TIMER_VALUE);
		goto error0;
	}

	if ( timer_id2timeout[WT_TIMER_LIST]<MIN_TIMER_VALUE ) {
		LM_ERR("WT_TIMER must be at least %d\n",
			MIN_TIMER_VALUE);
		goto error0;
	}

	if ( timer_id2timeout[DELETE_LIST]<MIN_TIMER_VALUE ) {
		LM_ERR("DELETE_TIMER must be at least %d\n",
			MIN_TIMER_VALUE);
		goto error0;
	}

	if ( timer_id2timeout[RT_T2]<=timer_id2timeout[RT_T1_TO_1] ) {
		LM_ERR("T2 must be greater than T1\n");
		goto error0;
	}

	/* generate timeouts for retransmissions */
	timer_id2timeout[RT_T1_TO_1] *=1000;
	timer_id2timeout[RT_T2] *=1000;

	if ( (timer_id2timeout[RT_T1_TO_1]<<1) < timer_id2timeout[RT_T2] )
		timer_id2timeout[RT_T1_TO_2] = timer_id2timeout[RT_T1_TO_1]<<1;
	else
		timer_id2timeout[RT_T1_TO_2] = timer_id2timeout[RT_T2];

	if ( (timer_id2timeout[RT_T1_TO_1]<<2) < timer_id2timeout[RT_T2] )
		timer_id2timeout[RT_T1_TO_3] = timer_id2timeout[RT_T1_TO_1]<<2;
	else
		timer_id2timeout[RT_T1_TO_3] = timer_id2timeout[RT_T2];

	/* init all timer sets */
	for( set=0 ; set<timer_sets ; set++) {

		/* inits the timers*/
		for(  i=0 ; i<NR_OF_TIMER_LISTS ; i++ )
			init_timer_list( set, i );

		/* init. timer lists */
		timertable[set].timers[RT_T1_TO_1].id = RT_T1_TO_1;
		timertable[set].timers[RT_T1_TO_2].id = RT_T1_TO_2;
		timertable[set].timers[RT_T1_TO_3].id = RT_T1_TO_3;
		timertable[set].timers[RT_T2].id      = RT_T2;
		timertable[set].timers[FR_TIMER_LIST].id     = FR_TIMER_LIST; 
		timertable[set].timers[FR_INV_TIMER_LIST].id = FR_INV_TIMER_LIST;
		timertable[set].timers[WT_TIMER_LIST].id     = WT_TIMER_LIST;
		timertable[set].timers[DELETE_LIST].id       = DELETE_LIST;
	}

	return timertable;

error0:
	return 0;
}

void free_timer_table(void)
{
	enum lists i;

	if (timertable) {
		/* the mutexs for sync the lists are released*/
		for ( i=0 ; i<timer_sets*NR_OF_TIMER_LISTS ; i++ )
			release_timerlist_lock( &timertable->timers[i] );
		shm_free(timertable);
	}
}


void reset_timer_list(unsigned int set, enum lists list_id)
{
	timertable[set].timers[list_id].first_tl.next_tl =
		&(timertable[set].timers[list_id].last_tl );
	timertable[set].timers[list_id].last_tl.prev_tl =
		&(timertable[set].timers[list_id].first_tl );
	timertable[set].timers[list_id].first_tl.prev_tl =
		timertable[set].timers[list_id].last_tl.next_tl = NULL;
	timertable[set].timers[list_id].last_tl.time_out = -1;
}


void init_timer_list(unsigned int set, enum lists list_id)
{
	reset_timer_list( set, list_id );
	init_timerlist_lock( set, list_id );
}




void print_timer_list(unsigned int set, enum lists list_id)
{
	struct timer* timer_list=&(timertable[set].timers[ list_id ]);
	struct timer_link *tl ;

	tl = timer_list->first_tl.next_tl;
	while (tl!=& timer_list->last_tl)
	{
		LM_DBG("[%d]: %p, next=%p \n",
			list_id, tl, tl->next_tl);
		tl = tl->next_tl;
	}
}



#ifdef TM_TIMER_DEBUG
static void check_timer_list( struct timer* timer_list, char *txt)
{
	struct timer_link *tl ;
	struct timer_link *tl1 ;

	if (list_id<0 || list_id>=NR_OF_TIMER_LISTS) {
			LM_CRIT("TM TIMER list [%d] bug [%s]\n",timer_list->id, txt);
			abort();
	}

	tl = timer_list->last_tl.prev_tl;
	while (tl!=&timer_list->first_tl) {
		if (tl->prev_tl==0) {
			LM_CRIT("TM TIMER list [%d] prev_tl==0 [%s]\n",timer_list->id, txt);
			abort();
		}
		tl = tl->prev_tl;
	}

	tl = timer_list->first_tl.next_tl;
	while (tl!=&timer_list->last_tl) {
		if (tl->next_tl==0) {
			LM_CRIT("TM TIMER list [%d] next_tl==0 [%s]\n",timer_list->id, txt);
			abort();
		}
		tl = tl->next_tl;
	}

	tl = timer_list->first_tl.next_tl;
	while (tl!=&timer_list->last_tl) {
		if (tl->ld_tl==0) {
			LM_CRIT("TM TIMER list [%d] currupted - ld=0 [%s]\n",
				timer_list->id, txt);
			abort();
		}
		if (tl->ld_tl->ld_tl!=tl) {
			LM_CRIT("TM TIMER list [%d] currupted - ld cycle broken [%s]\n",
				timer_list->id, txt);
			abort();
		}

		if (tl->ld_tl!=tl) {
			tl1 = tl->next_tl;
			while(tl1!=tl->ld_tl) {
				if (tl1->ld_tl) {
					LM_CRIT("TM TIMER list [%d] currupted - ld!=0 inside "
						"cycle [%s]\n", timer_list->id, txt);
					abort();
				}
				tl1 = tl1->next_tl;
			}
		}

		tl = tl->ld_tl->next_tl;
	}
}
#endif


static void remove_timer_unsafe(  struct timer_link* tl )
{
#ifdef EXTRA_DEBUG
	if (tl && is_in_timer_list2(tl) &&
		tl->timer_list->last_tl.prev_tl==0) {
		LM_CRIT("Oh no, zero link in trailing timer element\n");
		abort();
	};
#endif
	if (is_in_timer_list2( tl )) {
#ifdef EXTRA_DEBUG
		LM_DBG("unlinking timer: tl=%p, timeout=%lld, group=%d\n",
			tl, tl->time_out, tl->tg);
#endif
#ifdef TM_TIMER_DEBUG
		check_timer_list( tl->timer_list, "before remove" );
#endif
		if (tl->ld_tl && tl->ld_tl!=tl) {
			if (tl->time_out==tl->prev_tl->time_out) {
				tl->prev_tl->ld_tl = tl->ld_tl;
				tl->ld_tl->ld_tl = tl->prev_tl;
			} else {
				tl->next_tl->ld_tl = tl->ld_tl;
				tl->ld_tl->ld_tl = tl->next_tl;
			}
		}
		tl->prev_tl->next_tl = tl->next_tl;
		tl->next_tl->prev_tl = tl->prev_tl;
#ifdef TM_TIMER_DEBUG
		check_timer_list( tl->timer_list, "after remove" );
#endif
		tl->next_tl = 0;
		tl->prev_tl = 0;
		tl->ld_tl = 0;
		tl->timer_list = NULL;
	}
}


/* put a new linker into a timer_list */
static void insert_timer_unsafe( struct timer *timer_list,
									struct timer_link *tl, utime_t time_out )
{
	struct timer_link* ptr;

	tl->time_out = time_out;
	tl->timer_list = timer_list;
	tl->deleted = 0;

#ifdef TM_TIMER_DEBUG
	check_timer_list( timer_list, "before insert" );
#endif
	ptr = timer_list->last_tl.prev_tl;
	for( ; ptr != &timer_list->first_tl ; ptr = ptr->ld_tl->prev_tl) {
		if ( ptr->time_out<=time_out )
			break;
	}

	/* insert "tl" after "ptr" */
	tl->prev_tl = ptr;
	tl->next_tl = ptr->next_tl;
	tl->prev_tl->next_tl = tl;
	tl->next_tl->prev_tl = tl;

	if (tl->time_out==ptr->time_out) {
		tl->ld_tl = ptr->ld_tl;
		ptr->ld_tl = 0;
		tl->ld_tl->ld_tl = tl;
	} else {
		tl->ld_tl = tl;
	}
#ifdef TM_TIMER_DEBUG
	check_timer_list( timer_list, "after insert" );
#endif

	LM_DBG("[%d]: %p (%lld)\n",timer_list->id,
		tl,tl->time_out);
}



/* detach items passed by the time from timer list */
static struct timer_link  *check_and_split_time_list( struct timer *timer_list,
		utime_t time )
{
	struct timer_link *tl , *end, *ret;


	/* quick check whether it is worth entering the lock */
	if (timer_list->first_tl.next_tl==&timer_list->last_tl
			|| ( /* timer_list->first_tl.next_tl
				&& */ timer_list->first_tl.next_tl->time_out > time) )
		return NULL;

	/* the entire timer list is locked now -- noone else can manipulate it */
	lock(timer_list->mutex);

#ifdef TM_TIMER_DEBUG
	check_timer_list( timer_list, "before split" );
#endif
	end = &timer_list->last_tl;
	tl = timer_list->first_tl.next_tl;
	while( tl!=end && tl->time_out <= time)
		tl=tl->ld_tl->next_tl;

	/* nothing to delete found */
	if (tl->prev_tl==&(timer_list->first_tl)) {
		ret = NULL;
	} else { /* we did find timers to be fired! */
		/* the detached list begins with current beginning */
		ret = timer_list->first_tl.next_tl;
		/* and we mark the end of the split list */
		tl->prev_tl->next_tl = NULL;
		/* the shortened list starts from where we suspended */
		timer_list->first_tl.next_tl = tl;
		tl->prev_tl = & timer_list->first_tl;

		for( tl=ret ; tl ; tl=tl->next_tl )
			tl->timer_list = DETACHED_LIST;
	}
#ifdef TM_TIMER_DEBUG
	check_timer_list( timer_list, "after split" );
#endif

#ifdef EXTRA_DEBUG
	if (timer_list->last_tl.prev_tl==0) {
		LM_CRIT("Oh no, zero link in trailing timer element\n");
		abort();
	};
#endif

	/* give the list lock away */
	unlock(timer_list->mutex);

	return ret;
}



/* stop timer
 * WARNING: a reset'ed timer will be lost forever
 *  (successive set_timer won't work unless you're lucky
 *   an catch the race condition, the idea here is there is no
 *   guarantee you can do anything after a timer_reset)*/
void reset_timer( struct timer_link* tl )
{
	/* disqualify this timer from execution by setting its time_out
	   to zero; it will stay in timer-list until the timer process
	   starts removing outdated elements; then it will remove it
	   but not execute; there is a race condition, though -- see
	   timer.c for more details
	*/
	tl->deleted = 1;
#ifdef EXTRA_DEBUG
	LM_DBG("(group %d, tl=%p)\n", tl->tg, tl );
#endif
}




/* determine timer length and put on a correct timer list
 * WARNING: - don't try to use it to "move" a timer from one list
 *            to another, you'll run into races
 *          - reset_timer; set_timer might not work, a reset'ed timer
 *             has no set_timer guarantee, it might be lost;
 *             same for an expired timer: only it's handler can
 *             set it again, an external set_timer has no guarantee
 */
void set_timer( struct timer_link *new_tl, enum lists list_id,
												utime_t* ext_timeout )
{
	utime_t timeout;
	struct timer* list;

	if (list_id>=NR_OF_TIMER_LISTS) {
		LM_CRIT("unknown list: %d\n", list_id);
#ifdef EXTRA_DEBUG
		abort();
#endif
		return;
	}

	if (!ext_timeout) {
		timeout = timer_id2timeout[ list_id ];
	} else {
		timeout = *ext_timeout;
	}
	LM_DBG("relative timeout is %lld\n",timeout);

	list= &(timertable[new_tl->set].timers[ list_id ]);

	lock(list->mutex);
	/* check first if we are on the "detached" timer_routine list,
	 * if so do nothing, the timer is not valid anymore
	 * (sideffect: reset_timer ; set_timer is not safe, a reseted timer
	 *  might be lost, depending on this race condition ) */
	if (new_tl->timer_list==DETACHED_LIST){
		LM_CRIT("set_timer for %d list called on a \"detached\" "
			"timer -- ignoring: %p\n", list_id, new_tl);
		goto end;
	}
	/* make sure I'm not already on a list */
	remove_timer_unsafe( new_tl );

	insert_timer_unsafe( list, new_tl, timeout +
			((timer_id2type[list_id]==UTIME_TYPE)?get_uticks():get_ticks()));
end:
	unlock(list->mutex);
}



/* similar to set_timer, except it allows only one-time
   timer setting and all later attempts are ignored */
void set_1timer( struct timer_link *new_tl, enum lists list_id,
												utime_t* ext_timeout )
{
	utime_t timeout;
	struct timer* list;


	if (list_id>=NR_OF_TIMER_LISTS) {
		LM_CRIT("unknown list: %d\n", list_id);
#ifdef EXTRA_DEBUG
		abort();
#endif
		return;
	}

	if (!ext_timeout) {
		timeout = timer_id2timeout[ list_id ];
	} else {
		timeout = *ext_timeout;
	}

	list= &(timertable[new_tl->set].timers[ list_id ]);

	lock(list->mutex);
	if (!new_tl->time_out) {
		insert_timer_unsafe( list, new_tl, timeout +
			((timer_id2type[list_id]==UTIME_TYPE)?get_uticks():get_ticks()));
	}
	unlock(list->mutex);
}



/* should be called only from timer process context,
 * else it's unsafe */
static void unlink_timers( struct cell *t )
{
	int i;
	int remove_fr, remove_retr;
	unsigned short set;

	remove_fr=0; remove_retr=0;

	/* first look if we need to remove timers and play with
	   costly locks at all

	    note that is_in_timer_list2 is unsafe but it does not
	    hurt -- transaction is already dead (wait state) so that
	    noone else will install a FR/RETR timer and it can only
	    be removed from timer process itself -> it is safe to
	    use it without any protection
	*/
	if (is_in_timer_list2(&t->uas.response.fr_timer)) remove_fr=1;
	else for (i=0; i<t->nr_of_outgoings; i++)
		if (is_in_timer_list2(&t->uac[i].request.fr_timer)
			|| is_in_timer_list2(&t->uac[i].local_cancel.fr_timer)) {
				remove_fr=1;
				break;
		}
	if (is_in_timer_list2(&t->uas.response.retr_timer)) remove_retr=1;
	else for (i=0; i<t->nr_of_outgoings; i++)
		if (is_in_timer_list2(&t->uac[i].request.retr_timer)
			|| is_in_timer_list2(&t->uac[i].local_cancel.retr_timer)) {
				remove_retr=1;
				break;
		}

	set = t->wait_tl.set;

	/* do what we have to do....*/
	if (remove_retr) {
		/* RT_T1 lock is shared by all other RT timer
		   lists -- we can safely lock just one
		*/
		lock(timertable[set].timers[RT_T1_TO_1].mutex);
		remove_timer_unsafe(&t->uas.response.retr_timer);
		for (i=0; i<t->nr_of_outgoings; i++) {
			remove_timer_unsafe(&t->uac[i].request.retr_timer);
			remove_timer_unsafe(&t->uac[i].local_cancel.retr_timer);
		}
		unlock(timertable[set].timers[RT_T1_TO_1].mutex);
	}
	if (remove_fr) {
		/* FR lock is shared by all other FR timer
		   lists -- we can safely lock just one
		*/
		lock(timertable[set].timers[FR_TIMER_LIST].mutex);
		remove_timer_unsafe(&t->uas.response.fr_timer);
		for (i=0; i<t->nr_of_outgoings; i++) {
			remove_timer_unsafe(&t->uac[i].request.fr_timer);
			remove_timer_unsafe(&t->uac[i].local_cancel.fr_timer);
		}
		unlock(timertable[set].timers[FR_TIMER_LIST].mutex);
	}
}




#define run_handler_for_each( _tl , _handler ) \
	while ((_tl))\
	{\
		/* reset the timer list linkage */\
		tmp_tl = (_tl)->next_tl;\
		(_tl)->next_tl = (_tl)->prev_tl = 0;\
		LM_DBG("timer routine:%d,tl=%p next=%p, timeout=%lld\n",\
			id,(_tl),tmp_tl,(_tl)->time_out);\
		if ( !(_tl)->deleted ) \
			(_handler)( _tl );\
		(_tl) = tmp_tl;\
	}




void timer_routine(unsigned int ticks , void *set)
{
	struct timer_link *tl, *tmp_tl;
	int                id;

	for( id=0 ; id<RT_T1_TO_1 ; id++ )
	{
		/* to waste as little time in lock as possible, detach list
		   with expired items and process them after leaving the lock */
		tl=check_and_split_time_list( &timertable[(long)set].timers[ id ], ticks);
		/* process items now */
		switch (id)
		{
			case FR_TIMER_LIST:
			case FR_INV_TIMER_LIST:
				run_handler_for_each(tl,final_response_handler);
				break;
			case WT_TIMER_LIST:
				run_handler_for_each(tl,wait_handler);
				break;
			case DELETE_LIST:
				run_handler_for_each(tl,delete_handler);
				break;
		}
	}
}



void utimer_routine(utime_t uticks , void *set)
{
	struct timer_link *tl, *tmp_tl;
	int                id;

	for( id=RT_T1_TO_1 ; id<NR_OF_TIMER_LISTS ; id++ )
	{
		/* to waste as little time in lock as possible, detach list
		   with expired items and process them after leaving the lock */
		tl=check_and_split_time_list( &timertable[(long)set].timers[ id ], uticks);
		/* process items now */
		switch (id)
		{
			case RT_T1_TO_1:
			case RT_T1_TO_2:
			case RT_T1_TO_3:
			case RT_T2:
				run_handler_for_each(tl,retransmission_handler);
				break;
		}
	}
}

