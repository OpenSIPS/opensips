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
#include "config.h"
#include "mem/mem.h"
#ifdef SHM_MEM
#include "mem/shm_mem.h"
#endif

#include <stdlib.h>


static struct sr_timer *timer_list=0;
static struct sr_timer *utimer_list=0;

static unsigned int *jiffies=0;
static utime_t      *ujiffies=0;
static unsigned int  timer_id=0;


int has_timers()
{
	return timer_list || utimer_list;
}


/* ret 0 on success, <0 on error*/
int init_timer()
{
#ifdef SHM_MEM
	jiffies  = shm_malloc(sizeof(unsigned int));
	ujiffies = shm_malloc(sizeof(utime_t));
#else
	/* in this case get_ticks won't work! */
	LOG(L_INFO, "WARNING: no shared memory support compiled in"
				" get_ticks won't work\n");
	jiffies = pkg_malloc(sizeof(int));
	ujiffies = pkg_malloc(sizeof(utime_t));
#endif
	if (jiffies==0 || ujiffies==0){
		LOG(L_CRIT, "ERROR: init_timer: could not init jiffies\n");
		return E_OUT_OF_MEM;
	}

	if (UTIMER_TICK>TIMER_TICK*1000000) {
		LOG(L_ERR,"ERROR: init_timer: UTIMER > TIMER!!\n");
		return E_CFG;
	}

	if ( ((TIMER_TICK*1000000) % UTIMER_TICK)!=0 ) {
		LOG(L_ERR,"ERROR: init_timer: TIMER must be multiple of UTIMER!!\n");
		return E_CFG;
	}

	*jiffies=0;
	*ujiffies=0;
	return 0;
}



void destroy_timer()
{
	struct sr_timer* t, *foo;

	if (jiffies){
#ifdef SHM_MEM
		shm_free(jiffies); jiffies=0;
		shm_free(ujiffies); ujiffies=0;
#else
		pkg_free(jiffies); jiffies=0;
		pkg_free(ujiffies); ujiffies=0;
#endif
	}

	t=timer_list;
	while(t) {
		foo=t->next;
		pkg_free(t);
		t=foo;
	}
}



/*register a periodic timer;
 * ret: <0 on error
 * Hint: if you need it in a module, register it from mod_init or it 
 * won't work otherwise*/
int register_timer(timer_function f, void* param, unsigned int interval)
{
	struct sr_timer* t;

	t=pkg_malloc(sizeof(struct sr_timer));
	if (t==0){
		LOG(L_ERR, "ERROR: register_timer: out of memory\n");
		goto error;
	}
	t->id=timer_id++;
	t->u.timer_f=f;
	t->t_param=param;
	t->interval=interval;
	t->expires=*jiffies+interval;
	/* insert it into the list*/
	t->next=timer_list;
	timer_list=t;
	return t->id;

error:
	return E_OUT_OF_MEM;
}


int register_utimer(utimer_function f, void* param, unsigned int interval)
{
	struct sr_timer* t;

	t=pkg_malloc(sizeof(struct sr_timer));
	if (t==0){
		LOG(L_ERR, "ERROR: register_utimer: out of memory\n");
		goto error;
	}
	t->id=timer_id++;
	t->u.utimer_f=f;
	t->t_param=param;
	t->interval=interval;
	t->expires=*ujiffies+interval;
	/* insert it into the list*/
	t->next=utimer_list;
	utimer_list=t;
	return t->id;

error:
	return E_OUT_OF_MEM;
	return 0;
}


unsigned int get_ticks()
{
	if (jiffies==0){
		LOG(L_CRIT, "BUG: get_ticks: jiffies not initialized\n");
		return 0;
	}
#ifndef SHM_MEM
	LOG(L_CRIT, "WARNING: get_ticks: no shared memory support compiled in"
			", returning 0 (probably wrong)");
	return 0;
#endif
	return *jiffies;
}


utime_t get_uticks()
{
	if (ujiffies==0){
		LOG(L_CRIT, "BUG: uget_ticks: jiffies not initialized\n");
		return 0;
	}
#ifndef SHM_MEM
	LOG(L_CRIT, "WARNING: uget_ticks: no shared memory support compiled in"
			", returning 0 (probably wrong)");
	return 0;
#endif
	return *ujiffies;
}



static inline void timer_ticker()
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



static inline void utimer_ticker()
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



void run_timer()
{
	unsigned int multiple;
	unsigned int cnt;
	struct timeval o_tv;
	struct timeval tv;

	if ( (utimer_list==NULL) || ((TIMER_TICK*1000000) == UTIMER_TICK) ) {
		o_tv.tv_sec = TIMER_TICK;
		o_tv.tv_usec = 0;
		multiple = 1;
	} else {
		o_tv.tv_sec = UTIMER_TICK / 1000000;
		o_tv.tv_usec = UTIMER_TICK % 1000000;
		multiple = (( TIMER_TICK * 1000000 ) / UTIMER_TICK ) / 1000000;
	}

	DBG("DBUG:run_timer: tv = %ld, %ld , m=%d\n",
		o_tv.tv_sec,o_tv.tv_usec,multiple);

	if (utimer_list==NULL) {
		for( ; ; ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			timer_ticker();
		}

	} else
	if (timer_list==NULL) {
		for( ; ; ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			utimer_ticker();
		}

	} else
	if (multiple==1) {
		for( ; ; ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			timer_ticker();
			utimer_ticker();
		}

	} else {
		for( cnt=1 ; ; cnt++ ) {
			tv = o_tv;
			select( 0, 0, 0, 0, &tv);
			utimer_ticker();
			if (cnt==multiple) {
				timer_ticker();
				cnt = 0;
			}
		}
	}
}
