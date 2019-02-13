/*
 * Copyright (C) 2018 OpenSIPS Solutions
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


#ifndef _CORE_PT_LOAD_H
#define _CORE_PT_LOAD_H

#include "statistics.h"
#include "timer.h"

/* for the short-term/realtime load computation, the window time unit is
 * 1ms (counting 1us) and the total window size is 1s */
#define ST_WINDOW_TIME    (1000000)         // sample 1s
#define ST_WINDOW_UNIT       (1000)         // unit sample is 1ms
#define ST_WINDOW_SIZE (ST_WINDOW_TIME/ST_WINDOW_UNIT) // size of the window

/* for the long-term load computation, the window time unit is
 * 1s (counting 1us) and the window size is 10 mins -> 600 units */
#define LT_WINDOW_TIME        (10*60*1000000)    // sample 10mins
#define LT_WINDOW_UNIT              (1000000)    // unit sample is 1s
#define LT_WINDOW_SIZE (LT_WINDOW_TIME/LT_WINDOW_UNIT) // size of the window
#define LT_1m_RATIO           (0.1)


struct proc_load_info {
	/* sampling array for the Short Time load calculation (real time
	 * load or 1 second time-window load)*/
	unsigned short ST_window[ST_WINDOW_SIZE];
	/* sampling array for the Long Time load calculation (10 and 1 minute
	 * time-window load) */
	unsigned int   LT_window[LT_WINDOW_SIZE];

	/* the system time (usecs) when the process did the last load 
	 * update (when switching to idle/busy) */
	utime_t last_time;

	/* set to 1 when the process switched to busy; set on 0 if idle */
	unsigned char is_busy;

};

void pt_become_active(void);
void pt_become_idle(void);

unsigned int pt_get_rt_load(int _);
unsigned int pt_get_1m_load(int _);
unsigned int pt_get_10m_load(int _);

unsigned int pt_get_rt_loadall(int _);
unsigned int pt_get_1m_loadall(int _);
unsigned int pt_get_10m_loadall(int _);


unsigned int pt_get_rt_proc_load(int pid);
unsigned int pt_get_1m_proc_load(int pid);
unsigned int pt_get_10m_proc_load(int pid);

/* OpenSIPS startup */
int register_processes_load_stats(int procs_no);

#endif
