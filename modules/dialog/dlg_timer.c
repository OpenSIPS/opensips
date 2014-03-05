/*
 * $Id$
 *
 * Copyright (C) 2006 Voice System SRL
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
 * --------
 * 2006-04-14  initial version (bogdan)
 * 2007-03-06  to avoid races, tests on timer links are done under locks
 *             (bogdan)
 */


#include "../../mem/shm_mem.h"
#include "../../timer.h"
#include "dlg_timer.h"
#include "dlg_hash.h"
#include "dlg_req_within.h"

struct dlg_timer *d_timer = 0;
dlg_timer_handler timer_hdl = 0;

struct dlg_ping_timer *ping_timer=0;
str options_str=str_init("OPTIONS");

/* for the dlg timer, there are 3 possible states :
 * prev=next=0 -> dialog not in timer list
 * prev=0 -> dialog expired
 * otherwise - dialog still in timer list
 */
#define FAKE_DIALOG_TL ((struct dlg_tl*)-1)

int init_dlg_timer( dlg_timer_handler hdl )
{
	d_timer = (struct dlg_timer*)shm_malloc(sizeof(struct dlg_timer));
	if (d_timer==0) {
		LM_ERR("no more shm mem\n");
		return -1;
	}
	memset( d_timer, 0, sizeof(struct dlg_timer) );

	d_timer->first.next = d_timer->first.prev = &(d_timer->first);

	d_timer->lock = lock_alloc();
	if (d_timer->lock==0) {
		LM_ERR("failed to alloc lock\n");
		goto error0;
	}

	if (lock_init(d_timer->lock)==0) {
		LM_ERR("failed to init lock\n");
		goto error1;
	}

	timer_hdl = hdl;
	return 0;
error1:
	lock_dealloc(d_timer->lock);
error0:
	shm_free(d_timer);
	d_timer = 0;
	return -1;
}

#ifdef EXTRA_DEBUG
#define tl_get_dlg(_tl_)  ((struct dlg_cell*)((char *)(_tl_)- \
		(unsigned long)(&((struct dlg_cell*)0)->tl)))
void debug_detached_timer_list(struct dlg_tl *detached)
{
	struct dlg_cell *dlg;

	LM_DBG("Debugging detached timer list\n");

	/* check the detached list is not circular */
	while (detached != FAKE_DIALOG_TL) {
		if (detached->prev != NULL || detached->visited==1) {
			dlg = tl_get_dlg(detached);
			LM_ERR("Detected something wrong with dialog %p [%.*s]. Aborting. Visited = %d \n",
					dlg,dlg->callid.len,dlg->callid.s,detached->visited);
			abort();
		}
		detached->visited = 1;
		detached = detached->next;
	}

}

/* assumed to be always called under timer lock */
void debug_main_timer_list(void)
{
	struct dlg_tl *start,*finish;
	int visited=1;

	start = finish = &(d_timer->first);
	LM_DBG("testing forward loop with visited = %d\n",visited);

	/* check the main list is circular in both directions from start to end,
	 * with no loops in the middle */
	while (start) {
		start->visited=visited;
		start = start->next;

		if (start == finish)
			break;

		if (start == NULL || start->visited == visited) {
			LM_ERR("Detected something wrong with main timer list on forward linking for entry %p \n",start);
			abort();
		}
	}

	visited++;
	start = &(d_timer->first);

	LM_DBG("testing backward loop with visited = %d\n",visited);

	while (start) {
		start->visited=visited;
		start = start->prev;

		if (start == finish)
			break;

		if (start == NULL || start->visited == visited) {
			LM_ERR("Detected something wrong with main timer list on backward linking for entry %p \n",start);
			abort();
		}
	}
}

#endif

int init_dlg_ping_timer(void)
{
	ping_timer = (struct dlg_ping_timer*)shm_malloc(sizeof(struct dlg_timer));
	if (ping_timer==0) {
		LM_ERR("no more shm mem\n");
		return -1;
	}

	memset(ping_timer,0,sizeof(struct dlg_ping_timer));
	ping_timer->lock = lock_alloc();
	if (ping_timer->lock == 0) {
		LM_ERR("failed to alloc lock\n");
		goto error0;
	}

	if (lock_init(ping_timer->lock) == 0) {
		LM_ERR("failed to init lock\n");
		goto error1;
	}

	return 0;

error1:
	lock_dealloc(ping_timer->lock);
error0:
	shm_free(ping_timer);
	ping_timer=0;
	return -1;
}

void destroy_ping_timer(void)
{
	if (ping_timer ==0)
		return;

	lock_destroy(ping_timer->lock);
	lock_dealloc(ping_timer->lock);

	shm_free(ping_timer);
	ping_timer=0;
}


void destroy_dlg_timer(void)
{
	if (d_timer==0)
		return;

	lock_destroy(d_timer->lock);
	lock_dealloc(d_timer->lock);

	shm_free(d_timer);
	d_timer = 0;
}



static inline void insert_dlg_timer_unsafe(struct dlg_tl *tl)
{
	struct dlg_tl* ptr;

#ifdef EXTRA_DEBUG
	debug_main_timer_list();
#endif

	for(ptr = d_timer->first.prev; ptr != &d_timer->first ; ptr = ptr->prev) {
		if ( ptr->timeout <= tl->timeout )
			break;
	}

	LM_DBG("inserting %p for %d\n", tl,tl->timeout);
	tl->prev = ptr;
	tl->next = ptr->next;
	tl->prev->next = tl;
	tl->next->prev = tl;

#ifdef EXTRA_DEBUG
	debug_main_timer_list();
#endif
}

int insert_dlg_timer(struct dlg_tl *tl, int interval)
{
	lock_get( d_timer->lock);

	if (tl->next!=0 || tl->prev!=0) {
		lock_release( d_timer->lock);
		LM_CRIT("Trying to insert a bogus dlg tl=%p tl->next=%p tl->prev=%p\n",
			tl, tl->next, tl->prev);
		return -1;
	}
	tl->timeout = get_ticks()+interval;

	insert_dlg_timer_unsafe( tl );

	lock_release( d_timer->lock);

	return 0;
}

int insert_ping_timer(struct dlg_cell* dlg)
{
	struct dlg_ping_list *node;

	node = shm_malloc(sizeof(struct dlg_ping_list));
	if (node == 0) {
		LM_ERR("no more shm mem\n");
		return -1;
	}

	node->dlg = dlg;
	node->next = 0;
	node->prev = 0;

	lock_get( ping_timer->lock );

	dlg->pl = node;

	if (ping_timer->first == 0)
		ping_timer->first = node;
	else {
		node->next = ping_timer->first;
		ping_timer->first->prev = node;
		ping_timer->first = node;
	}

	dlg->legs[DLG_CALLER_LEG].reply_received = 1;
	dlg->legs[callee_idx(dlg)].reply_received = 1;


	lock_release( ping_timer->lock);
	LM_DBG("Inserted dlg [%p] in ping timer list\n",dlg);

	return 0;
}

static inline void remove_dlg_timer_unsafe(struct dlg_tl *tl)
{
#ifdef EXTRA_DEBUG
	debug_main_timer_list();
#endif

	tl->prev->next = tl->next;
	tl->next->prev = tl->prev;

#ifdef EXTRA_DEBUG
	debug_main_timer_list();
#endif
}



/* returns:
      0 - dialog OK and removed from timer list
      1 - dialog OK but not found in timer list
     -1 - dialog not OK
 */
int remove_dlg_timer(struct dlg_tl *tl)
{
	lock_get( d_timer->lock);

	if (tl->prev==NULL && tl->timeout==0) {
		/* dialog is not in timer list; either it is completly removed
		   (prev=next=timeout=0), either is in process by timeout routine
		   (prev=timeout=0;next!=0) */
		lock_release( d_timer->lock);
		return 1;
	}

	if (tl->prev==NULL || tl->next==NULL) {
		LM_CRIT("bogus tl=%p tl->prev=%p tl->next=%p\n",
			tl, tl->prev, tl->next);
		lock_release( d_timer->lock);
		return -1;
	}

	remove_dlg_timer_unsafe(tl);
	tl->next = NULL;
	tl->prev = NULL;
	tl->timeout = 0;

	lock_release( d_timer->lock);
	return 0;
}

static inline void detach_node_unsafe(struct dlg_ping_list *it)
{
	if (it->next && it->prev) {
		it->prev->next = it->next;
		it->next->prev = it->prev;
	}
	else if (it->next) {
		it->next->prev = 0;
		ping_timer->first = it->next;
	}
	else if (it->prev) {
		it->prev->next = 0;
	}
	else
		ping_timer->first = 0;

	it->next = it->prev = 0;
}

/* returns:
 * 0 if removed succesfully
 * 1 if dlg not found in list
 */
int remove_ping_timer(struct dlg_cell *dlg)
{
	lock_get(ping_timer->lock);
	if (dlg->pl)
	{
		detach_node_unsafe(dlg->pl);
		shm_free(dlg->pl);
		dlg->pl = 0;
		lock_release(ping_timer->lock);
		return 0;
	}

	lock_release(ping_timer->lock);
	return 1;
}

/* returns :
     0 - dialog was inserted in timer list with the new timeout
    -1 - failure (dialog is expired, so it cannot be added again) */
int update_dlg_timer( struct dlg_tl *tl, int timeout )
{
	lock_get( d_timer->lock);

	if ( tl->next ) {
		if (tl->prev==0) {
			lock_release( d_timer->lock);
			return -1;
		}
		remove_dlg_timer_unsafe(tl);
	}

	tl->timeout = get_ticks()+timeout;
	insert_dlg_timer_unsafe( tl );

	lock_release( d_timer->lock);
	return 0;
}

static inline struct dlg_tl* get_expired_dlgs(unsigned int time)
{
	struct dlg_tl *tl , *end, *ret;

	lock_get( d_timer->lock);

	if (d_timer->first.next==&(d_timer->first)
	|| d_timer->first.next->timeout > time ) {
		lock_release( d_timer->lock);
		return FAKE_DIALOG_TL;
	}

#ifdef EXTRA_DEBUG
	debug_main_timer_list();
#endif

	end = &d_timer->first;
	tl = d_timer->first.next;
	LM_DBG("start with tl=%p tl->prev=%p tl->next=%p (%d) at %d "
		"and end with end=%p end->prev=%p end->next=%p\n",
		tl,tl->prev,tl->next,tl->timeout,time,
		end,end->prev,end->next);
	while( tl!=end && tl->timeout <= time) {
		LM_DBG("getting tl=%p tl->prev=%p tl->next=%p with %d\n",
			tl,tl->prev,tl->next,tl->timeout);
		tl->prev = 0;
		tl->timeout = 0;
		tl=tl->next;
	}
	LM_DBG("end with tl=%p tl->prev=%p tl->next=%p and "
		"d_timer->first.next->prev=%p\n",
		tl,tl->prev,tl->next,d_timer->first.next->prev);

	if (tl==end && d_timer->first.next->prev) {
		LM_DBG("no dialog to return\n");
		ret = FAKE_DIALOG_TL;
	} else {
		ret = d_timer->first.next;
		tl->prev->next = FAKE_DIALOG_TL;
		d_timer->first.next = tl;
		tl->prev = &d_timer->first;
	}

#ifdef EXTRA_DEBUG
	debug_main_timer_list();
#endif

	lock_release( d_timer->lock);

#ifdef EXTRA_DEBUG
	debug_detached_timer_list(ret);
#endif
	return ret;
}

void dlg_timer_routine(unsigned int ticks , void * attr)
{
	struct dlg_tl *tl, *ctl;

	tl = get_expired_dlgs( ticks );

	while (tl != FAKE_DIALOG_TL) {
		ctl = tl;
		tl = tl->next;
		/* keep dialog as expired (next is still set) */
		ctl->next = FAKE_DIALOG_TL;
		LM_DBG("tl=%p next=%p\n", ctl, tl);
		timer_hdl( ctl );
	}
}

/* removes expired dlgs from main ping_timer list
 * and links them back into a new list */
void get_timeout_dlgs(struct dlg_ping_list **expired,
					struct dlg_ping_list **to_be_deleted)
{
	struct dlg_ping_list *exp = NULL,*del=NULL,*it=NULL,*next=NULL;
	struct dlg_cell *current;
	int detached;

	lock_get(ping_timer->lock);

	for (it=ping_timer->first;it;it=next) {
		current = it->dlg;
		next = it->next;
		detached = 0;

		if (current->state == DLG_STATE_DELETED) {
			/* the dialog has terminated - we remove it as well
			 * since we also have a ref */
			detach_node_unsafe(it);
			it->dlg->pl = 0;

			if (del == NULL)
				del = it;
			else {
				it->next = del;
				del = it;
			}

			continue;
		}

		if (current->flags & DLG_FLAG_PING_CALLER) {
			if (current->legs[DLG_CALLER_LEG].reply_received == 0) {
				detach_node_unsafe(it);
				detached=1;
				it->dlg->pl = 0;

				if (exp == NULL)
					exp = it;
				else {
					it->next = exp;
					exp = it;
				}
			}
		}

		if (detached == 0) {
			if (current->flags & DLG_FLAG_PING_CALLEE) {
				if (current->legs[callee_idx(current)].reply_received == 0) {
					detach_node_unsafe(it);
					it->dlg->pl = 0;

					if (exp == NULL)
						exp = it;
					else {
						it->next = exp;
						exp = it;
					}
				}
			}
		}
	}

	lock_release(ping_timer->lock);

	*to_be_deleted = del;
	*expired = exp;
}

void reply_from_caller(struct cell* t, int type, struct tmcb_params* ps)
{
	struct sip_msg *rpl;
	int statuscode;
	struct dlg_cell *dlg;

	if(ps == NULL || ps->rpl == NULL)
	{
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if( ps->param== NULL )
	{
			LM_ERR("Null callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	dlg = *(ps->param);

	LM_DBG("Status Code received =  [%d]\n", statuscode);

	if (rpl == FAKED_REPLY || statuscode == 408) {
		/* timeout occured, nothing else to do now
		 * next time timer fires, it will detect ping reply was not received
		 */
		LM_INFO("terminating dialog ( due to timeout ) "
					"with callid = [%.*s] \n",dlg->callid.len,dlg->callid.s);
		return;
	}

	if (statuscode == 481)
	{
		/* call/transaction does not exist
		 * terminate the dialog */
		LM_INFO("terminating dialog ( due to 481 ) "
				"with callid = [%.*s] \n",dlg->callid.len,dlg->callid.s);

		return;
	}

	dlg->legs[DLG_CALLER_LEG].reply_received = 1;
}

/* Duplicate code for the sake of quickly knowing where the reply came from,
 * without any further checks */
void reply_from_callee(struct cell* t, int type, struct tmcb_params* ps)
{
	struct sip_msg *rpl;
	int statuscode;
	struct dlg_cell *dlg;

	if(ps == NULL || ps->rpl == NULL)
	{
			LM_ERR("Wrong tmcb params\n");
			return;
	}
	if( ps->param== NULL )
	{
			LM_ERR("Null callback parameter\n");
			return;
	}

	rpl = ps->rpl;
	statuscode = ps->code;
	dlg = *(ps->param);

	LM_DBG("Status Code received =  [%d]\n", statuscode);

	if (rpl == FAKED_REPLY || statuscode == 408) {
		/* timeout occured, nothing else to do now
		 * next time timer fires, it will detect ping reply was not received
		 */
		LM_INFO("terminating dialog ( due to timeout ) "
					"with callid = [%.*s] \n",dlg->callid.len,dlg->callid.s);
		return;
	}

	if (statuscode == 481)
	{
		/* call/transaction does not exist
		 * terminate the dialog */
		LM_INFO("terminating dialog ( due to 481 ) "
				"with callid = [%.*s] \n",dlg->callid.len,dlg->callid.s);
		return;
	}

	dlg->legs[callee_idx(dlg)].reply_received = 1;
}

void unref_dlg_cb(void *dlg)
{
	if (!d_table)
		return;
	unref_dlg((struct dlg_cell*)dlg,1);
}

void dlg_ping_routine(unsigned int ticks , void * attr)
{
	struct dlg_ping_list *expired,*to_be_deleted,*it,*curr;
	struct dlg_cell *dlg;

	get_timeout_dlgs(&expired,&to_be_deleted);

	it = expired;
	while (it) {
		dlg = it->dlg;
		LM_DBG("dialog %p-%.*s has expired\n",dlg,dlg->callid.len,dlg->callid.s);
		curr = it->next;
		shm_free(it);
		it = curr;

		init_dlg_term_reason(dlg,"Ping Timeout",sizeof("Ping Timeout")-1);
		/* FIXME - maybe better not to send BYE both ways as we know for
		 * sure one end in down . */
		dlg_end_dlg(dlg,0);

		/* no longer reffed in list */
		unref_dlg(dlg,1);
	}

	it = to_be_deleted;
	while (it) {
		dlg = it->dlg;
		LM_DBG("dialog %p-%.*s has terminated\n",dlg,dlg->callid.len,dlg->callid.s);
		curr = it->next;
		/* if marked as to be deleted, we let it go
		 * for the ping timer list as well */
		unref_dlg(dlg,1);
		shm_free(it);
		it = curr;
	}

#ifdef USE_TCP
		tcp_no_new_conn = 1;
#endif

	/* ping_timer->first now contains all active dialogs */
	it = ping_timer->first;
	while (it) {
		dlg = it->dlg;

		/* do not ping ended dialogs - we might have missed them earlier or
		 * might have terminated in the mean time - we'll clean them up on
		 * our next iteration */
		if (dlg->state != DLG_STATE_DELETED) {
			if (dlg->flags & DLG_FLAG_PING_CALLER) {
				ref_dlg(dlg,1);
				if (send_leg_msg(dlg,&options_str,callee_idx(dlg),
				DLG_CALLER_LEG,0,0,reply_from_caller,dlg,unref_dlg_cb) < 0) {
					LM_ERR("failed to ping caller\n");
					unref_dlg(dlg,1);
				}
			}

			if (dlg->flags & DLG_FLAG_PING_CALLEE) {
				ref_dlg(dlg,1);
				if (send_leg_msg(dlg,&options_str,DLG_CALLER_LEG,
				callee_idx(dlg),0,0,reply_from_callee,dlg,unref_dlg_cb) < 0) {
					LM_ERR("failed to ping callee\n");
					unref_dlg(dlg,1);
				}
			}
		}
		it = it->next;
	}

#ifdef USE_TCP
		tcp_no_new_conn = 0;
#endif

}
