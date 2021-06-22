/*
 * Copyright (C) 2009-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include "../../mem/shm_mem.h"
#include "../../timer.h"
#include "dlg_timer.h"
#include "dlg_hash.h"
#include "dlg_req_within.h"
#include "dlg_replication.h"

struct dlg_timer *d_timer = 0;
dlg_timer_handler timer_hdl = 0;

struct dlg_ping_timer *ping_timer=0;
struct dlg_reinvite_ping_timer *reinvite_ping_timer=0;
str options_str=str_init("OPTIONS");
str invite_str=str_init("INVITE");

extern int reinvite_ping_interval;
extern int options_ping_interval;

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

int init_dlg_reinvite_ping_timer(void)
{
	reinvite_ping_timer = (struct dlg_reinvite_ping_timer*)shm_malloc(sizeof(struct dlg_timer));
	if (reinvite_ping_timer==0) {
		LM_ERR("no more shm mem\n");
		return -1;
	}

	memset(reinvite_ping_timer,0,sizeof(struct dlg_reinvite_ping_timer));
	reinvite_ping_timer->lock = lock_alloc();
	if (reinvite_ping_timer->lock == 0) {
		LM_ERR("failed to alloc lock\n");
		goto error0;
	}

	if (lock_init(reinvite_ping_timer->lock) == 0) {
		LM_ERR("failed to init lock\n");
		goto error1;
	}

	return 0;

error1:
	lock_dealloc(reinvite_ping_timer->lock);
error0:
	shm_free(reinvite_ping_timer);
	reinvite_ping_timer=0;
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

void unsafe_insert_ping_timer(struct dlg_ping_list *node,int new_timeout)
{
	struct dlg_ping_list *it;

	node->timeout = get_ticks() + new_timeout;

	if (ping_timer->first == 0) {
		ping_timer->first = node;
		ping_timer->last = node;
	} else {
		/* quick optimisation, always check if our timeout is bigger than last
		if not, lookup our position, might be useful in the future if we want
		to set different ping intervals per dialog */
		if (node->timeout >= ping_timer->last->timeout) {
			node->prev = ping_timer->last;
			ping_timer->last->next = node;
			ping_timer->last = node;
		} else {
			for (it=ping_timer->first;it;it=it->next) {
				if (it->timeout >= node->timeout)
					break;
			}

			/* we need to insert ourselves before the found node */
			if (it == NULL) {
				/* we're going to be the last node 
				should never get here due to the above optimisation ... paranoia */
				node->prev = ping_timer->last;
				ping_timer->last->next = node;
				ping_timer->last = node;
			} else {
				it->prev->next=node;
				node->prev = it->prev;
				node->next = it;
				it->prev = node;
			}

		}
	}
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

	unsafe_insert_ping_timer(node,options_ping_interval);
	dlg->pl = node;

	dlg->legs[DLG_CALLER_LEG].reply_received = DLG_PING_SUCCESS;
	dlg->legs[callee_idx(dlg)].reply_received = DLG_PING_SUCCESS;

	lock_release( ping_timer->lock);
	LM_DBG("Inserted dlg [%p] in ping timer list\n",dlg);

	return 0;
}

void unsafe_insert_reinvite_ping_timer(struct dlg_ping_list *node,int new_timeout)
{
	struct dlg_ping_list *it;

	node->timeout = get_ticks() + new_timeout;

	if (reinvite_ping_timer->first == 0) {
		reinvite_ping_timer->first = node;
		reinvite_ping_timer->last = node;
	} else {
		/* quick optimisation, always check if our timeout is bigger than last
		if not, lookup our position, might be useful in the future if we want
		to set different ping intervals per dialog */
		if (node->timeout >= reinvite_ping_timer->last->timeout) {
			node->prev = reinvite_ping_timer->last;
			reinvite_ping_timer->last->next = node;
			reinvite_ping_timer->last = node;
		} else {
			for (it=reinvite_ping_timer->first;it;it=it->next) {
				if (it->timeout >= node->timeout)
					break;
			}

			/* we need to insert ourselves before the found node */
			if (it == NULL) {
				/* we're going to be the last node 
				should never get here due to the above optimisation ... paranoia */
				node->prev = reinvite_ping_timer->last;
				reinvite_ping_timer->last->next = node;
				reinvite_ping_timer->last = node;
			} else {
				it->prev->next=node;
				node->prev = it->prev;
				node->next = it;
				it->prev = node;
			}
		}
	}
}

int insert_reinvite_ping_timer(struct dlg_cell* dlg)
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

	lock_get( reinvite_ping_timer->lock );

	unsafe_insert_reinvite_ping_timer(node,reinvite_ping_interval);
	dlg->reinvite_pl = node;

	dlg->legs[DLG_CALLER_LEG].reinvite_confirmed = DLG_PING_SUCCESS;
	dlg->legs[callee_idx(dlg)].reinvite_confirmed = DLG_PING_SUCCESS;

	lock_release( reinvite_ping_timer->lock);
	LM_DBG("Inserted dlg [%p] in reinvite ping timer list\n",dlg);

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

	if (tl->prev==NULL || tl->next==NULL || tl->next == FAKE_DIALOG_TL) {
		LM_CRIT("bogus tl=%p tl->prev=%p tl->next=%p\n",
			tl, tl->prev, tl->next);
		lock_release( d_timer->lock);
		return -1;
	}

	remove_dlg_timer_unsafe(tl);
	/* mark that this dialog was one a part of the timer list */
	tl->next = FAKE_DIALOG_TL;
	tl->prev = NULL;
	tl->timeout = 0;

	lock_release( d_timer->lock);
	return 0;
}

static inline void detach_ping_node_unsafe(struct dlg_ping_list *it,int reinvite)
{
	if (it->next && it->prev) {
		it->prev->next = it->next;
		it->next->prev = it->prev;
	}
	else if (it->next) {
		it->next->prev = 0;
		if (reinvite)
			reinvite_ping_timer->first = it->next;
		else
			ping_timer->first = it->next;
	} else if (it->prev) {
		it->prev->next = 0;
		if (reinvite)
			reinvite_ping_timer->last = it->prev;
		else
			ping_timer->last = it->prev;
	} else {
		if (reinvite) {
			reinvite_ping_timer->first = 0;
			reinvite_ping_timer->last = 0;
		} else {
			ping_timer->first = 0;
			ping_timer->last = 0;
		}
	}

	it->next = it->prev = 0;
}

/* returns :
     0 - dialog was inserted in timer list with the new timeout
     1 - dialog was inserted in timer list with the new timeout 
    -1 - failure (dialog is expired, so it cannot be added again) */
int update_dlg_timer( struct dlg_tl *tl, int timeout )
{
	int ret;

	lock_get( d_timer->lock);

	if ( tl->next == FAKE_DIALOG_TL ) {
		/* previously removed from timer list - we will not add it again */
		lock_release( d_timer->lock);
		return 0;
	}

	if ( tl->next ) {
		if (tl->prev==0) {
			lock_release( d_timer->lock);
			return -1;
		}
		remove_dlg_timer_unsafe(tl);
		ret = 0;
	} else {
		ret = 1;
	}

	tl->timeout = get_ticks()+timeout;
	insert_dlg_timer_unsafe( tl );

	lock_release( d_timer->lock);
	return ret;
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
		struct dlg_ping_list **to_be_deleted,int reinvite)
{
	struct dlg_ping_list *exp = NULL,*del=NULL,*it=NULL,*next=NULL;
	struct dlg_cell *current;

	if (reinvite)
		lock_get(reinvite_ping_timer->lock);
	else
		lock_get(ping_timer->lock);

	for (it=reinvite?reinvite_ping_timer->first:ping_timer->first;it;it=next) {
		/* FIXME - optimisation needed here : only iterate on the nodes that we need to
		eg. where pinging is in progress */

		current = it->dlg;
		next = it->next;

		if (current->state == DLG_STATE_DELETED) {
			/* the dialog has terminated - we remove it as well
			 * since we also have a ref */
			detach_ping_node_unsafe(it,reinvite);
			if (reinvite)
				it->dlg->reinvite_pl = 0;
			else
				it->dlg->pl = 0;

			if (del == NULL)
				del = it;
			else {
				it->next = del;
				del = it;
			}

			continue;
		}

		/* if pinging failed on any leg: detach the timer and end the dialog */
		if ((reinvite &&
		        ((current->flags & DLG_FLAG_REINVITE_PING_CALLER
		            && current->legs[DLG_CALLER_LEG].reinvite_confirmed == DLG_PING_FAIL)
		        || (current->flags & DLG_FLAG_REINVITE_PING_CALLEE
		            && current->legs[callee_idx(current)].reinvite_confirmed == DLG_PING_FAIL)))

		    || (!reinvite &&
		        ((current->flags & DLG_FLAG_PING_CALLER
		            && current->legs[DLG_CALLER_LEG].reply_received == DLG_PING_FAIL)
		        || (current->flags & DLG_FLAG_PING_CALLEE
		            && current->legs[callee_idx(current)].reply_received == DLG_PING_FAIL)))) {

			detach_ping_node_unsafe(it,reinvite);

			if (reinvite)
				it->dlg->reinvite_pl = 0;
			else
				it->dlg->pl = 0;

			if (exp == NULL)
				exp = it;
			else {
				it->next = exp;
				exp = it;
			}

			continue;
		}
	}

	if (reinvite)
		lock_release(reinvite_ping_timer->lock);
	else
		lock_release(ping_timer->lock);

	*to_be_deleted = del;
	*expired = exp;
}

int dlg_handle_seq_reply(struct dlg_cell *dlg, struct sip_msg* rpl,
		int statuscode, int leg, int is_reinvite_rpl)
{
	str ack = str_init("ACK");
	char *ping_status = is_reinvite_rpl ? &dlg->legs[leg].reinvite_confirmed :
	                                      &dlg->legs[leg].reply_received;

	LM_DBG("Status Code received =  [%d]\n", statuscode);

	if (rpl == FAKED_REPLY || statuscode == 408) {
		/* timeout occurred, nothing else to do now
		 * next time timer fires, it will detect ping reply was not received
		 */
		LM_INFO("terminating dialog due to ping timeout on %s leg, "
		        "ci: [%.*s]\n", leg == DLG_CALLER_LEG ? "caller" : "callee",
		        dlg->callid.len, dlg->callid.s);
		*ping_status = DLG_PING_FAIL;
		return -1;
	}

	if (statuscode == 481)
	{
		/* call/transaction does not exist
		 * terminate the dialog */
		LM_INFO("terminating dialog due to 481 ping reply on %s leg, "
		        "ci: [%.*s]\n", leg == DLG_CALLER_LEG ? "caller" : "callee",
		        dlg->callid.len, dlg->callid.s);

		*ping_status = DLG_PING_FAIL;
		return -1;
	}

	*ping_status = DLG_PING_SUCCESS;
	if (is_reinvite_rpl && statuscode < 300 && send_leg_msg(dlg, &ack,
			other_leg(dlg, leg), leg, NULL, NULL, NULL, NULL, NULL, NULL) < 0)
		LM_ERR("cannot send ACK message!\n");
	return 0;
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

	dlg_handle_seq_reply(dlg, rpl, statuscode, DLG_CALLER_LEG, 0);
}

void reinvite_reply_from_caller(struct cell* t, int type, struct tmcb_params* ps)
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

	dlg_handle_seq_reply(dlg, rpl, statuscode, DLG_CALLER_LEG, 1);
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

	dlg_handle_seq_reply(dlg, rpl, statuscode, callee_idx(dlg), 0);
}

/* Duplicate code for the sake of quickly knowing where the reply came from,
 * without any further checks */
void reinvite_reply_from_callee(struct cell* t, int type, struct tmcb_params* ps)
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

	dlg_handle_seq_reply(dlg, rpl, statuscode, callee_idx(dlg), 1);
}

void unref_dlg_cb(void *dlg)
{
	unref_dlg_destroy_safe((struct dlg_cell*)dlg,1);
}

void dlg_options_routine(unsigned int ticks , void * attr)
{
	struct dlg_ping_list *expired,*to_be_deleted,*it,*curr,*next;
	struct dlg_cell *dlg;
	int current_ticks;

	get_timeout_dlgs(&expired,&to_be_deleted,0);

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
		dlg_end_dlg(dlg,0,1);

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

	tcp_no_new_conn = 1;

	current_ticks = get_ticks();
	/* ping_timer->first now contains all active dialogs
	ping all dialogs with a lower timeout than now */
	lock_get(ping_timer->lock);
	it = ping_timer->first;
	while (it) {
		/* iterated across all the nodes that need pinging now */
		if (it->timeout > current_ticks)
			break;

		dlg = it->dlg;
		next=it->next;

		if (dialog_repl_cluster && get_shtag_state(dlg) == SHTAG_STATE_BACKUP) {
			it = next;
			continue;
		}

		/* do not ping ended dialogs - we might have missed them earlier or
		 * might have terminated in the mean time - we'll clean them up on
		 * our next iteration */
		if (dlg->state != DLG_STATE_DELETED && it->timeout <= current_ticks) {
			if (dlg->flags & DLG_FLAG_PING_CALLER &&
			        dlg->legs[DLG_CALLER_LEG].reply_received == DLG_PING_SUCCESS) {
				ref_dlg(dlg,1);
				if (send_leg_msg(dlg,&options_str,callee_idx(dlg),
				DLG_CALLER_LEG,0,0,reply_from_caller,dlg,unref_dlg_cb,
				&dlg->legs[DLG_CALLER_LEG].reply_received) < 0) {
					LM_ERR("failed to ping caller\n");
					unref_dlg(dlg,1);
				}
			}

			if (dlg->flags & DLG_FLAG_PING_CALLEE &&
			        dlg->legs[callee_idx(dlg)].reply_received == DLG_PING_SUCCESS) {
				ref_dlg(dlg,1);
				if (send_leg_msg(dlg,&options_str,DLG_CALLER_LEG,
				callee_idx(dlg),0,0,reply_from_callee,dlg,unref_dlg_cb,
				&dlg->legs[callee_idx(dlg)].reply_received) < 0) {
					LM_ERR("failed to ping callee\n");
					unref_dlg(dlg,1);
				}
			}

			/* we've pinged, now update the timeout & move the entry further down the list */
			detach_ping_node_unsafe(it,0);
			unsafe_insert_ping_timer(it,options_ping_interval);
		}
		it = next;
	}

	lock_release(ping_timer->lock);
	tcp_no_new_conn = 0;
}

void dlg_reinvite_routine(unsigned int ticks , void * attr)
{
	static str content_type = str_init("application/sdp");
	struct dlg_ping_list *expired,*to_be_deleted,*it,*curr,*next;
	struct dlg_cell *dlg;
	str extra_headers;
	str *sdp;
	int current_ticks;

	get_timeout_dlgs(&expired,&to_be_deleted,1);

	it = expired;
	while (it) {
		dlg = it->dlg;
		LM_DBG("dialog %p-%.*s has expired\n",dlg,dlg->callid.len,dlg->callid.s);
		curr = it->next;
		shm_free(it);
		it = curr;

		init_dlg_term_reason(dlg,"ReINVITE Ping Timeout",sizeof("ReINVITE Ping Timeout")-1);
		/* FIXME - maybe better not to send BYE both ways as we know for
		 * sure one end in down . */
		dlg_end_dlg(dlg,0,1);

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

	tcp_no_new_conn = 1;

	current_ticks = get_ticks();
	/* reinvite_ping_timer->first now contains all active dialogs
	ping all dialogs with a lower timeout than now */
	lock_get(reinvite_ping_timer->lock);
	it = reinvite_ping_timer->first;
	while (it) {
		/* iterated across all the nodes that need pinging now */
		if (it->timeout > current_ticks)
			break;

		dlg = it->dlg;
		next=it->next;

		if (dialog_repl_cluster && get_shtag_state(dlg) == SHTAG_STATE_BACKUP) {
			it = next;
			continue;
		}

		/* do not ping ended dialogs - we might have missed them earlier or
		 * might have terminated in the mean time - we'll clean them up on
		 * our next iteration */
		if (dlg->state != DLG_STATE_DELETED && it->timeout <= current_ticks) {
			if (dlg->flags & DLG_FLAG_REINVITE_PING_CALLER &&
			        dlg->legs[DLG_CALLER_LEG].reinvite_confirmed == DLG_PING_SUCCESS) {

				if (!dlg_get_leg_hdrs(dlg, callee_idx(dlg),
						DLG_CALLER_LEG, &content_type, NULL, &extra_headers)) {
					LM_ERR("No more pkg for extra headers \n");
					it = it->next;
					continue;
				}
				sdp = (dlg->legs[DLG_CALLER_LEG].out_sdp.s?
						&dlg->legs[DLG_CALLER_LEG].out_sdp:
						&dlg->legs[callee_idx(dlg)].in_sdp);
				
				ref_dlg(dlg,1);
				if (send_leg_msg(dlg,&invite_str,callee_idx(dlg),
				DLG_CALLER_LEG,&extra_headers,sdp,
				reinvite_reply_from_caller,dlg,unref_dlg_cb,
				&dlg->legs[DLG_CALLER_LEG].reinvite_confirmed) < 0) {
					LM_ERR("failed to ping caller\n");
					unref_dlg(dlg,1);
				}

				pkg_free(extra_headers.s);
			}

			if (dlg->flags & DLG_FLAG_REINVITE_PING_CALLEE &&
			        dlg->legs[callee_idx(dlg)].reinvite_confirmed == DLG_PING_SUCCESS) {

				if (!dlg_get_leg_hdrs(dlg, DLG_CALLER_LEG,
						callee_idx(dlg), &content_type, NULL, &extra_headers)) {
					LM_ERR("No more pkg for extra headers \n");
					it = it->next;
					continue;
				}
				sdp = (dlg->legs[callee_idx(dlg)].out_sdp.s?
						&dlg->legs[callee_idx(dlg)].out_sdp:
						&dlg->legs[DLG_CALLER_LEG].in_sdp);

				ref_dlg(dlg,1);
				if (send_leg_msg(dlg,&invite_str,DLG_CALLER_LEG, callee_idx(dlg),
				&extra_headers,sdp,reinvite_reply_from_callee, dlg,unref_dlg_cb,
				&dlg->legs[callee_idx(dlg)].reinvite_confirmed) < 0) {
					LM_ERR("failed to ping callee\n");
					unref_dlg(dlg,1);
				}

				pkg_free(extra_headers.s);
			}

			/* we've pinged, now update the timeout & move the entry further down the list */
			detach_ping_node_unsafe(it,1);
			unsafe_insert_reinvite_ping_timer(it,reinvite_ping_interval);
		}
		it = next;
	}

	lock_release(reinvite_ping_timer->lock);
	tcp_no_new_conn = 0;
}
