/*
 * timer related functions
 *
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
 *  2007-02-02  timer with resolution of microseconds added (bogdan)
 *  2014-09-11  timer tasks are distributed via reactor (bogdan)
 *  2014-10-03  drop all timer processes (aside keeper and trigger) (bogdan)
 */


/*!
 * \file
 * \brief Timer related functions
 */


#ifndef timer_h
#define timer_h

typedef unsigned long long utime_t;
typedef long long stime_t;

typedef void (timer_function)(unsigned int ticks, void* param);
typedef void (utimer_function)(utime_t uticks, void* param);

/* define internal timer to 10 milliseconds */
#define ITIMER_TICK 10000

#define TIMER_FLAG_IS_UTIMER       (1<<0)
#define TIMER_FLAG_SKIP_ON_DELAY   (1<<1)
#define TIMER_FLAG_DELAY_ON_DELAY  (1<<2)

/* try to synchronize with system time every 5 seconds */
#define TIMER_SYNC_TICKS 5000000
/* synchronize if drift is greater than internal timer tick */
#define TIMER_MAX_DRIFT_TICKS ITIMER_TICK

struct os_timer{
	/* unique ID in the list of timer handlers - not really used */
	unsigned short id;
	/* is utimer or timer? */
	unsigned short flags;
	/* string label identifying the handler (what module and what for was registered) */
	char *label;
	/* handler function */
	union {
		timer_function* timer_f;
		utimer_function* utimer_f;
	}u;
	/* parameter to the handler function (does not change during runtime) */
	void* t_param;
	/* triggering interval for the handler (does not change during runtime) */
	unsigned int interval;
	/* internal time for the next triggering */
	utime_t expires;
	/* time of the current triggering (based on ITIMER_TICKs) */
	utime_t trigger_time;
	/* UTICKs or TICKs of the triggering */
	utime_t time;
	/* next element in the timer list */
	struct os_timer* next;
};


extern int timer_fd_out;

extern char *timer_auto_scaling_profile;

extern int timer_workers_no;

int timer_count_processes(unsigned int *extra);

int init_timer(void);

void destroy_timer(void);

/*! \brief register a periodic timer;
 * ret: <0 on error*/
int register_timer(char *label, timer_function f, void* param,
		unsigned int interval, unsigned short flags);

int register_utimer(char *label, utimer_function f, void* param,
		unsigned int interval, unsigned short flags);

unsigned int have_ticks(void);

unsigned int have_uticks(void);

unsigned int get_ticks(void);

utime_t get_uticks(void);

int start_timer_processes(void);

int start_timer_extra_processes(int *chd_rank);

int register_route_timers(void);

void handle_timer_job(void);

#endif
