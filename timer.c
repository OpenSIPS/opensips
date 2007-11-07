/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2007 Voice Sistem SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
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
 *  2003-03-19  replaced all the mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-29  cleaning pkg_mallocs introduced (jiri)
 *  2007-02-02  timer with resolution of microseconds added (bogdan)
 */

#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "timer.h"
#include "dprint.h"
#include "error.h"
#include "pt.h"
#include "config.h"
#include "sr_module.h"
#include "mem/mem.h"
#ifdef SHM_MEM
#include "mem/shm_mem.h"
#endif

#include <stdlib.h>

struct sr_timer_process {
	unsigned int flags;
	struct sr_timer *timer_list;
	struct sr_timer *utimer_list;
	struct sr_timer_process *next;
};


static struct sr_timer_process *timer_proc_list = 0;

static unsigned int *jiffies=0;
static utime_t      *ujiffies=0;
static unsigned int  timer_id=0;



static struct sr_timer_process* new_timer_process_list(unsigned int flags)
{
	struct sr_timer_process *tpl;
	struct sr_timer_process *tpl_it;

	tpl = pkg_malloc( sizeof(struct sr_timer_process) );
	if (tpl==NULL) {
		LM_ERR("no more pkg memory\n");
		return 0;
	}
	memset( tpl, 0, sizeof(struct sr_timer_process));
	tpl->flags = flags;

	if (timer_proc_list==NULL) {
		timer_proc_list = tpl;
	} else {
		for(tpl_it=timer_proc_list ; tpl_it->next ; tpl_it=tpl_it->next);
		tpl_it->next = tpl;
	}

	return tpl;
}



/* ret 0 on success, <0 on error*/
int init_timer(void)
{
#ifdef SHM_MEM
	jiffies  = shm_malloc(sizeof(unsigned int));
	ujiffies = shm_malloc(sizeof(utime_t));
#else
	/* in this case get_ticks won't work! */
	LM_WARN("no shared memory support compiled-> get_ticks won't work\n");
	jiffies = pkg_malloc(sizeof(int));
	ujiffies = pkg_malloc(sizeof(utime_t));
#endif
	if (jiffies==0 || ujiffies==0){
		LM_CRIT("could not init jiffies\n");
		return E_OUT_OF_MEM;
	}

	if (UTIMER_TICK>TIMER_TICK*1000000) {
		LM_CRIT("UTIMER > TIMER!!\n");
		return E_CFG;
	}

	if ( ((TIMER_TICK*1000000) % UTIMER_TICK)!=0 ) {
		LM_CRIT("TIMER must be multiple of UTIMER!!\n");
		return E_CFG;
	}

	*jiffies=0;
	*ujiffies=0;

	/* create the default time process list */
	if (new_timer_process_list(TIMER_PROC_INIT_FLAG)==NULL) {
		LM_ERR("failed to create default timer process list\n");
		return E_OUT_OF_MEM;
	}

	return 0;
}



void destroy_timer(void)
{
	if (jiffies){
#ifdef SHM_MEM
		shm_free(jiffies); jiffies=0;
		shm_free(ujiffies); ujiffies=0;
#else
		pkg_free(jiffies); jiffies=0;
		pkg_free(ujiffies); ujiffies=0;
#endif
	}
}



static inline struct sr_timer* new_sr_timer(timer_function f, 
										void* param, unsigned int interval)
{
	struct sr_timer* t;

	t=pkg_malloc(sizeof(struct sr_timer));
	if (t==0){
		LM_ERR("out of pkg memory\n");
		return NULL;
	}
	t->id=timer_id++;
	t->u.timer_f=f;
	t->t_param=param;
	t->interval=interval;
	t->expires=*jiffies+interval;
	return t;
}



/*register a periodic timer;
 * ret: <0 on error
 * Hint: if you need it in a module, register it from mod_init or it 
 * won't work otherwise*/
int register_timer(timer_function f, void* param, unsigned int interval)
{
	struct sr_timer* t;

	t = new_sr_timer( f, param, interval);
	if (t==NULL)
		return E_OUT_OF_MEM;
	/* insert it into the default timer process list*/
	t->next = timer_proc_list->timer_list;
	timer_proc_list->timer_list = t;
	return t->id;
}



int register_utimer(utimer_function f, void* param, unsigned int interval)
{
	struct sr_timer* t;

	t = new_sr_timer((timer_function*)f, param, interval);
	if (t==NULL)
		return E_OUT_OF_MEM;
	/* insert it into the list*/
	t->next = timer_proc_list->utimer_list;
	timer_proc_list->utimer_list = t;
	return t->id;
}



int register_timer_process(timer_function f,void* param,unsigned int interval,
															unsigned int flags)
{
	struct sr_timer* t;
	struct sr_timer_process* tpl;

	/* create new process list */
	tpl = new_timer_process_list(flags);
	if (tpl==NULL)
		return E_OUT_OF_MEM;

	t = new_sr_timer(f, param, interval);
	if (t==NULL)
		return E_OUT_OF_MEM;
	/* insert it into the list*/
	t->next = tpl->timer_list;
	tpl->timer_list = t;
	return t->id;
}



unsigned int get_ticks(void)
{
	if (jiffies==0){
		LM_CRIT("bug -> jiffies not initialized\n");
		return 0;
	}
#ifndef SHM_MEM
	LM_WARN("no shared memory support compiled in"
			", returning 0 (probably wrong)");
	return 0;
#endif
	return *jiffies;
}



utime_t get_uticks(void)
{
	if (ujiffies==0){
		LM_CRIT("bug -> ujiffies not initialized\n");
		return 0;
	}
#ifndef SHM_MEM
	LM_WARN("no shared memory support compiled in"
			", returning 0 (probably wrong)");
	return 0;
#endif
	return *ujiffies;
}



static inline void timer_ticker(struct sr_timer *timer_list)
{
	struct sr_timer* t;
	unsigned int prev_jiffies;

	prev_jiffies=*jiffies;
	*jiffies+=TIMER_TICK;
	/* test for overflow (if tick= 1s =>overflow in 136 years)*/
	if (*jiffies<prev_jiffies){ 
		/*force expire & update every timer, a little buggy but it 
		 * happens once in 136 years :) */
		for(t=timer_list;t;t=t->next){
			t->expires=*jiffies+t->interval;
			t->u.timer_f(*jiffies, t->t_param);
		}
		return;
	}
	
	for (t=timer_list;t; t=t->next){
		if (*jiffies>=t->expires){
			t->expires=*jiffies+t->interval;
			t->u.timer_f(*jiffies, t->t_param);
		}
	}
}



static inline void utimer_ticker(struct sr_timer *utimer_list)
{
	struct sr_timer* t;

	*ujiffies+=UTIMER_TICK;
	/* no overflow test as even if we go for 1 microsecond tick, this will
	 * happen in 14038618 years :P */

	for ( t=utimer_list ; t ; t=t->next){
		if (*ujiffies>=t->expires){
			t->expires=*ujiffies+t->interval;
			t->u.utimer_f(*ujiffies, t->t_param);
		}
	}
}



static void run_timer_process(struct sr_timer_process *tpl, int do_jiffies)
{
	unsigned int local_jiffies=0;
	utime_t      local_ujiffies=0;
	unsigned int multiple;
	unsigned int cnt;
	struct timeval o_tv;
	struct timeval tv;

	if ( (tpl->utimer_list==NULL) || ((TIMER_TICK*1000000) == UTIMER_TICK) ) {
		o_tv.tv_sec = TIMER_TICK;
		o_tv.tv_usec = 0;
		multiple = 1;
	} else {
		o_tv.tv_sec = UTIMER_TICK / 1000000;
		o_tv.tv_usec = UTIMER_TICK % 1000000;
		multiple = (( TIMER_TICK * 1000000 ) / UTIMER_TICK ) / 1000000;
	}

	LM_DBG("tv = %ld, %ld , m=%d\n",
		o_tv.tv_sec,o_tv.tv_usec,multiple);

	if (!do_jiffies) {
		jiffies = &local_jiffies;
		ujiffies = &local_ujiffies;
	}

	if (tpl->utimer_list==NULL) {
		for( ; ; ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			timer_ticker(tpl->timer_list);
		}

	} else
	if (tpl->timer_list==NULL) {
		for( ; ; ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			utimer_ticker(tpl->utimer_list);
		}

	} else
	if (multiple==1) {
		for( ; ; ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			timer_ticker(tpl->timer_list);
			utimer_ticker(tpl->utimer_list);
		}

	} else {
		for( cnt=1 ; ; cnt++ ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			utimer_ticker(tpl->utimer_list);
			if (cnt==multiple) {
				timer_ticker(tpl->timer_list);
				cnt = 0;
			}
		}
	}
}



int start_timer_processes(void)
{
	struct sr_timer_process *tpl;
	pid_t pid;
	unsigned int first;

	for( tpl=timer_proc_list, first=1 ; tpl ; tpl=tpl->next,first=0 ) {
		if (tpl->timer_list==NULL && tpl->utimer_list==NULL)
			continue;
		/* fork a new process */
		if ( (pid=openser_fork("timer"))<0 ) {
			LM_CRIT("cannot fork timer process\n");
			goto error;
		} else if (pid==0) {
			/* new process */
			/* run init if required */
			if ( tpl->flags&TIMER_PROC_INIT_FLAG && init_child(PROC_TIMER)<0 ){
				LM_ERR("init_child failed for timer proc\n");
				exit(-1);
			}
			run_timer_process( tpl, first);
			exit(-1);
		}
	}

	return 0;
error:
	return -1;
}


/* Counts the timer processes that needs to be created */
int count_timer_procs(void)
{
	struct sr_timer_process *tpl;
	int n;

	n = 0;
	for( tpl=timer_proc_list; tpl ; tpl=tpl->next ) {
		if (tpl->timer_list==NULL && tpl->utimer_list==NULL)
			continue;
		n++;
	}

	return n;
}

