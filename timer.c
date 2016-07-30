/*
 * Copyright (C) 2014 OpenSIPS Solutions
 * Copyright (C) 2007 Voice Sistem SRL
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
 *  2003-03-19  replaced all the mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-29  cleaning pkg_mallocs introduced (jiri)
 *  2007-02-02  timer with resolution of microseconds added (bogdan)
 *  2014-09-11  timer tasks distributed via reactors (bogdan)
 *  2014-10-03  drop all timer processes (aside keeper) (bogdan)
 */

/*!
 * \file
 * \brief Timer handling
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "action.h"
#include "timer.h"
#include "dprint.h"
#include "error.h"
#include "pt.h"
#include "config.h"
#include "sr_module.h"
#include "daemonize.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"

#include <stdlib.h>

/* list with all the registered timers */
static struct os_timer *timer_list = NULL;

/* list with all the registered utimers */
static struct os_timer *utimer_list = NULL;

static unsigned int  *jiffies=0;
static utime_t       *ujiffies=0;
static utime_t       *ijiffies=0;
static unsigned short timer_id=0;
static int            timer_pipe[2];

int timer_fd_out = -1 ;


/* ret 0 on success, <0 on error*/
int init_timer(void)
{
	int optval;

	jiffies  = shm_malloc(sizeof(unsigned int));
	ujiffies = shm_malloc(sizeof(utime_t));
	ijiffies = shm_malloc(sizeof(utime_t));

	if (jiffies==0 || ujiffies==0 || ijiffies==0 ){
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
	*ijiffies=0;

	/* create the pipe for dispatching the timer jobs */
	if ( pipe(timer_pipe)!=0 ) {
		LM_ERR("failed to create time pipe (%s)!\n",strerror(errno));
		return E_UNSPEC;
	}
	/* make reading fd non-blocking */
	optval=fcntl(timer_pipe[0], F_GETFL);
	if (optval==-1){
		LM_ERR("fcntl failed: (%d) %s\n", errno, strerror(errno));
		return E_UNSPEC;
	}
	if (fcntl(timer_pipe[0],F_SETFL,optval|O_NONBLOCK)==-1){
		LM_ERR("set non-blocking failed: (%d) %s\n",
			errno, strerror(errno));
		return E_UNSPEC;
	}
	/* make visible the "read" part of the pipe */
	timer_fd_out = timer_pipe[0];

	return 0;
}



void destroy_timer(void)
{
	if (jiffies){
		shm_free(jiffies); jiffies=0;
		shm_free(ujiffies); ujiffies=0;
	}
}



static inline struct os_timer* new_os_timer(char *label, unsigned short flags,
						timer_function f, void* param, unsigned int interval)
{
	struct os_timer* t;

	if (label==NULL)
		label = "n/a";

	t=shm_malloc( sizeof(struct os_timer) + strlen(label)+1 );
	if (t==0){
		LM_ERR("out of pkg memory\n");
		return NULL;
	}
	t->id=timer_id++;
	t->flags = flags;
	t->label = (char*)(t+1);
	strcpy( t->label, label);
	t->u.timer_f=f;
	t->t_param=param;
	t->interval=interval;
	t->expires=*jiffies+interval;
	t->trigger_time = 0;
	t->time = 0;
	return t;
}


/*register a periodic timer;
 * ret: <0 on error
 * Hint: if you need it in a module, register it from mod_init or it
 * won't work otherwise*/
int register_timer(char *label, timer_function f, void* param,
								unsigned int interval, unsigned short flags)
{
	struct os_timer* t;

	flags = flags & (~TIMER_FLAG_IS_UTIMER); /* just to be sure */
	t = new_os_timer( label, flags, f, param, interval);
	if (t==NULL)
		return E_OUT_OF_MEM;
	/* insert it into the timer list*/
	t->next = timer_list;
	timer_list = t;
	return t->id;
}


int register_utimer(char *label, utimer_function f, void* param,
								unsigned int interval, unsigned short flags)
{
	struct os_timer* t;

	flags = flags | TIMER_FLAG_IS_UTIMER; /* just to be sure */
	t = new_os_timer( label, 1, (timer_function*)f, param, interval);
	if (t==NULL)
		return E_OUT_OF_MEM;
	/* insert it into the utimer list*/
	t->next = utimer_list;
	utimer_list = t;
	return t->id;
}


void route_timer_f(unsigned int ticks, void* param)
{
	struct action* a = (struct action*)param;
	static struct sip_msg* req= NULL;

	if(req == NULL)
	{
		req = (struct sip_msg*)pkg_malloc(sizeof(struct sip_msg));
		if(req == NULL)
		{
			LM_ERR("No more memory\n");
			return;
		}
		memset(req, 0, sizeof(struct sip_msg));
		req->first_line.type = SIP_REQUEST;
		req->first_line.u.request.method.s= "DUMMY";
		req->first_line.u.request.method.len= 5;
		req->first_line.u.request.uri.s= "sip:user@domain.com";
		req->first_line.u.request.uri.len= 19;
		req->rcv.src_ip.af = AF_INET;
		req->rcv.dst_ip.af = AF_INET;
	}

	if(a == NULL) {
		LM_ERR("NULL action\n");
		return;
	}

	run_top_route(a, req);

	/* clean whatever extra structures were added by script functions */
	free_sip_msg(req);
	/* remove all added AVP - here we use all the time the default AVP list */
	reset_avps( );
}


int register_route_timers(void)
{
	struct os_timer* t;
	int i;

	if(timer_rlist[0].a == NULL)
		return 0;

	/* register the routes */
	for(i = 0; i< TIMER_RT_NO; i++)
	{
		if(timer_rlist[i].a == NULL)
			return 0;
		t = new_os_timer( "timer_route", 0, route_timer_f, timer_rlist[i].a,
				timer_rlist[i].interval);
		if (t==NULL)
			return E_OUT_OF_MEM;

		/* insert it into the list*/
		t->next = timer_list;
		timer_list = t;
	}

	return 1;
}


unsigned int have_ticks(void) {
	return jiffies==NULL ? 0 : 1;
}

unsigned int have_uticks(void) {
	return ujiffies==NULL ? 0 : 1;
}

unsigned int get_ticks(void)
{
	return *jiffies;
}


utime_t get_uticks(void)
{
	return *ujiffies;
}



static inline void timer_ticker(struct os_timer *timer_list)
{
	struct os_timer* t;
	unsigned int j;
	ssize_t l;

	/* we need to store the original time as while executing the
	   the handlers, the time may pass, affecting the way we
	   calculate the new expire (expire will include the time
	   taken to run handlers) -bogdan */
	j = *jiffies;

	for (t=timer_list;t; t=t->next){
		if (j>=t->expires){
			if (t->trigger_time) {
				LM_WARN("timer task <%s> already scheduled for %lld ms"
					" (now %lld ms), it may overlap..\n",
					t->label, (utime_t)(t->trigger_time/1000),
					((utime_t)*ijiffies/1000) );
				if (t->flags&TIMER_FLAG_SKIP_ON_DELAY) {
					/* skip this execution of the timer handler */
					t->expires = j + t->interval;
					continue;
				} else if (t->flags&TIMER_FLAG_DELAY_ON_DELAY) {
					/* delay the execution of the timer handler
					   until the prev one is done */
					continue;
				} else {
					/* launch the task now, even if overlapping with the
					   already running one */
				}
			}
			t->expires = j + t->interval;
			t->trigger_time = *ijiffies;
			t->time = j;
			/* push the jobs for execution */
again:
			l = write( timer_pipe[1], &t, sizeof(t));
			if (l==-1) {
				if (errno==EAGAIN || errno==EINTR || errno==EWOULDBLOCK )
					goto again;
				LM_ERR("writing failed:[%d] %s, skipping job <%s> at %d s\n",
					errno, strerror(errno),t->label, j);
			}
		}
	}
}



static inline void utimer_ticker(struct os_timer *utimer_list)
{
	struct os_timer* t;
	utime_t uj;
	ssize_t l;

	/* see comment on timer_ticket */
	uj = *ujiffies;

	for ( t=utimer_list ; t ; t=t->next){
		if (uj>=t->expires){
			if (t->trigger_time) {
				LM_WARN("utimer task <%s> already scheduled for %lld ms"
					" (now %lld ms), it may overlap..\n",
					t->label, (utime_t)(t->trigger_time/1000),
					((utime_t)*ijiffies/1000) );
				if (t->flags&TIMER_FLAG_SKIP_ON_DELAY) {
					/* skip this execution of the timer handler */
					t->expires = uj + t->interval;
					continue;
				} else if (t->flags&TIMER_FLAG_DELAY_ON_DELAY) {
					/* delay the execution of the timer handler
					   until the prev one is done */
					continue;
				} else {
					/* launch the task now, even if overlapping with the
					   already running one */
				}
			}
			t->expires = uj + t->interval;
			t->trigger_time = *ijiffies;
			t->time = uj;
			/* push the jobs for execution */
again:
			l = write( timer_pipe[1], &t, sizeof(t));
			if (l==-1) {
				if (errno==EAGAIN || errno==EINTR || errno==EWOULDBLOCK )
					goto again;
				LM_ERR("writing failed:[%d] %s, skipping job <%s> at %lld us\n",
					errno, strerror(errno),t->label, uj);
			}
		}
	}
}


static void run_timer_process( void )
{
	unsigned int multiple;
	unsigned int cnt;
	struct timeval o_tv;
	struct timeval tv, comp_tv;
	utime_t  drift;
	utime_t  uinterval;
	utime_t  wait;
	utime_t  ij;

/* timer re-calibration to compensate drifting */
#define compute_wait_with_drift(_tv) \
	do {                                                         \
		if ( drift > ITIMER_TICK ) {                             \
			wait = (drift >= uinterval) ? 0 : uinterval-drift;   \
			_tv.tv_sec = wait / 1000000;                         \
			_tv.tv_usec = wait % 1000000;                        \
			drift -= uinterval-wait;                             \
		} else {                                                 \
			_tv = o_tv;                                          \
		}                                                        \
	}while(0)


	if ( (utimer_list==NULL) || ((TIMER_TICK*1000000) == UTIMER_TICK) ) {
		o_tv.tv_sec = TIMER_TICK;
		o_tv.tv_usec = 0;
		multiple = 1;
	} else {
		o_tv.tv_sec = UTIMER_TICK / 1000000;
		o_tv.tv_usec = UTIMER_TICK % 1000000;
		multiple = (( TIMER_TICK * 1000000 ) / UTIMER_TICK ) / 1000000;
	}

	LM_DBG("tv = %ld, %ld , m=%d\n",
		(long)o_tv.tv_sec,(long)o_tv.tv_usec,multiple);

	drift = 0;
	uinterval = o_tv.tv_sec * 1000000 + o_tv.tv_usec;

	if (utimer_list==NULL) {
		/* only TIMERs, ticking at TIMER_TICK */
		for( ; ; ) {
			ij = *ijiffies;
			compute_wait_with_drift(comp_tv);
			tv = comp_tv;
			select( 0, 0, 0, 0, &tv);
			timer_ticker( timer_list);

			drift += ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec > (*ijiffies-ij)) ?
					0 : *ijiffies-ij - ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec);
		}

	} else
	if (timer_list==NULL) {
		/* only UTIMERs, ticking at UTIMER_TICK */
		for( ; ; ) {
			ij = *ijiffies;
			compute_wait_with_drift(comp_tv);
			tv = comp_tv;
			select( 0, 0, 0, 0, &tv);
			utimer_ticker( utimer_list);

			drift += ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec > (*ijiffies-ij)) ?
					0 : *ijiffies-ij - ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec);
		}

	} else
	if (multiple==1) {
		/* TIMERs and UTIMERs, ticking together TIMER_TICK (synced) */
		for( ; ; ) {
			ij = *ijiffies;
			compute_wait_with_drift(comp_tv);
			tv = comp_tv;
			select( 0, 0, 0, 0, &tv);
			timer_ticker( timer_list);
			utimer_ticker( utimer_list);

			drift += ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec > (*ijiffies-ij)) ?
					0 : *ijiffies-ij - ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec);
		}

	} else {
		/* TIMERs and UTIMERs, TIMER_TICK is multiple of UTIMER_TICK */
		for( cnt=1 ; ; cnt++ ) {
			ij = *ijiffies;
			compute_wait_with_drift(comp_tv);
			tv = comp_tv;
			select( 0, 0, 0, 0, &tv);
			utimer_ticker(utimer_list);
			if (cnt==multiple) {
				timer_ticker(timer_list);
				cnt = 0;
			}

			drift += ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec > (*ijiffies-ij)) ?
					0 : *ijiffies-ij - ((utime_t)comp_tv.tv_sec*1000000+comp_tv.tv_usec);
		}
	}
}

static void run_timer_process_jif(void)
{
	unsigned int multiple;
	unsigned int umultiple;
	unsigned int cnt;
	unsigned int ucnt;
	struct timeval o_tv;
	struct timeval tv;
	struct timeval sync_ts, last_ts;
	utime_t interval, drift;
	utime_t last_ticks, last_sync = 0;

	o_tv.tv_sec = 0;
	o_tv.tv_usec = ITIMER_TICK; /* internal timer */
	multiple  = ((TIMER_TICK*1000000)) / (UTIMER_TICK);
	umultiple = (UTIMER_TICK) / (ITIMER_TICK);

	LM_DBG("tv = %ld, %ld , m=%d, mu=%d\n",
		(long)o_tv.tv_sec,(long)o_tv.tv_usec,multiple,umultiple);

	gettimeofday(&last_ts, 0);
	last_ticks = *ijiffies;

	for( cnt=1,ucnt=1 ; ; ucnt++ ) {
		tv = o_tv;
		select( 0, 0, 0, 0, &tv);

		/* update internal timer */
		*(ijiffies)+=ITIMER_TICK;

		/* update public utimer */
		if (ucnt==umultiple) {
			*(ujiffies)+=UTIMER_TICK;
			/* no overflow test as even if we go for 1 microsecond tick,
			 * this will happen in 14038618 years :P */
			ucnt = 0;

			cnt++;
			/* update public timer */
			if (cnt==multiple) {
				*(jiffies)+=TIMER_TICK;
				/* test for overflow (if tick= 1s =>overflow in 136 years)*/
				cnt = 0;
			}
		}

		/* synchronize with system time if needed */
		if (*ijiffies - last_sync >= TIMER_SYNC_TICKS) {
			last_sync = *ijiffies;

			gettimeofday(&sync_ts, 0);
			interval = (utime_t)sync_ts.tv_sec*1000000 + sync_ts.tv_usec
						- (utime_t)last_ts.tv_sec*1000000 - last_ts.tv_usec;

			drift = interval - (*ijiffies - last_ticks);

			/* protect against sudden time changes */
			if (interval < 0 || drift < 0 || drift > TIMER_SYNC_TICKS) {
				last_ts = sync_ts;
				last_ticks = *ijiffies;
				LM_DBG("System time changed, ignoring...\n");
				continue;
			}

			if (drift > TIMER_MAX_DRIFT_TICKS) {
				*(ijiffies) += (drift / ITIMER_TICK) * ITIMER_TICK;

				ucnt += drift / ITIMER_TICK;
				*(ujiffies) += (ucnt / umultiple) * (UTIMER_TICK);
				ucnt = ucnt % umultiple;

				cnt += (unsigned int)(drift / (UTIMER_TICK));
				*(jiffies) += (cnt / multiple) * TIMER_TICK;
				cnt = cnt % multiple;
			}
		}
	}
}


int start_timer_processes(void)
{
	pid_t pid;

	/*
	 * A change of the way timers were run. In the pre-1.5 times,
	 * all timer processes had their own jiffies and just the first
	 * one was doing the global ones. Now, there's a separate process
	* that increases jiffies - run_timer_process_jif(), and the rest
	 * just use that one.
	 *
	 * The main reason for this change was when a function that relied
	 * on jiffies for its timeouts got called from the timer thread and
	 * was unable to detect timeouts.
	 */

	if ( (pid=internal_fork("time_keeper"))<0 ) {
		LM_CRIT("cannot fork time keeper process\n");
		goto error;
	} else if (pid==0) {
		/* new process */
		clean_write_pipeend();

		run_timer_process_jif();
		exit(-1);
	}

	/* fork a timer-trigger process */
	if ( (pid=internal_fork("timer"))<0 ) {
		LM_CRIT("cannot fork timer process\n");
		goto error;
	} else if (pid==0) {
		/* new process */
		clean_write_pipeend();

		run_timer_process( );
		exit(-1);
	}

	return 0;
error:
	return -1;
}


void handle_timer_job(void)
{
	struct os_timer *t;
	ssize_t l;

	/* read one "os_timer" pointer from the pipe (non-blocking) */
	l = read( timer_fd_out, &t, sizeof(t) );
	if (l==-1) {
		if (errno==EAGAIN || errno==EINTR || errno==EWOULDBLOCK )
			return;
		LM_ERR("read failed:[%d] %s\n", errno, strerror(errno));
		return;
	}

	/* run the handler */
	if (t->flags&TIMER_FLAG_IS_UTIMER) {

		if (t->trigger_time<(*ijiffies-ITIMER_TICK) )
			LM_WARN("utimer job <%s> has a %lld us delay in execution\n",
				t->label, *ijiffies-t->trigger_time);
		t->u.utimer_f( t->time , t->t_param);
		t->trigger_time = 0;

	} else {

		if (t->trigger_time<(*ijiffies-ITIMER_TICK) )
			LM_WARN("timer job <%s> has a %lld us delay in execution\n",
				t->label, *ijiffies-t->trigger_time);
		t->u.timer_f( (unsigned int)t->time , t->t_param);
		t->trigger_time = 0;

	}

	return;
}

