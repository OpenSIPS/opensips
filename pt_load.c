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


#include <string.h>
#include <sys/time.h>
#include <stdio.h>

#include "dprint.h"
#include "pt_load.h"
#include "pt.h"
#include "ut.h"

#define PT_LOAD(_pno)    pt[_pno].load

#define MY_LOAD          PT_LOAD(process_no)

#define FOR_ALL_INDEXES(_it, _old, _new, _TYPE) \
	for( _it=(_old+1)%_TYPE##_WINDOW_SIZE ; _it!=_new ;\
		_it=(_it+1)%_TYPE##_WINDOW_SIZE )


#define MARK_AS_IDLE( _now, _TYPE) \
	do { \
		/* check if entire time window was idle */ \
		if (_now-MY_LOAD.last_time >= _TYPE##_WINDOW_TIME) { \
			/* all was idle, so make it zero */ \
			MY_LOAD._TYPE##_window[0] = 0; \
			FOR_ALL_INDEXES( i, 0, 0, _TYPE) \
				MY_LOAD._TYPE##_window[i] = 0; \
		} else { \
			/* get the index inside window for the last time update */ \
			idx_old = (MY_LOAD.last_time / _TYPE##_WINDOW_UNIT) % \
				_TYPE##_WINDOW_SIZE; \
			idx_new = (_now / _TYPE##_WINDOW_UNIT) % _TYPE##_WINDOW_SIZE; \
			if (idx_old!=idx_new) { \
				FOR_ALL_INDEXES( i, idx_old, idx_new, _TYPE) { \
					MY_LOAD._TYPE##_window[i] = 0; \
				} \
				MY_LOAD._TYPE##_window[idx_new] = 0; \
			}\
		} \
	}while(0)


void pt_become_active(void)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, i;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;
	if (usec_now==MY_LOAD.last_time) {
		MY_LOAD.is_busy = 1;
		return;
	}

	MARK_AS_IDLE( usec_now, ST);
	MARK_AS_IDLE( usec_now, LT);

	MY_LOAD.last_time = usec_now;
	MY_LOAD.is_busy = 1;
}


#define MARK_AS_ACTIVE( _now, _TYPE) \
	do { \
		/* check if the entire time window was active */ \
		if ((_now-MY_LOAD.last_time) >= _TYPE##_WINDOW_TIME) { \
			/* all was busy, so make it "full" */ \
			MY_LOAD._TYPE##_window[0] = _TYPE##_WINDOW_UNIT; \
			FOR_ALL_INDEXES( i, 0, 0, _TYPE) \
				MY_LOAD._TYPE##_window[i] = _TYPE##_WINDOW_UNIT; \
		} else { \
			/* get the index inside window for the last time update */ \
			idx_old = (MY_LOAD.last_time / _TYPE##_WINDOW_UNIT) % \
				_TYPE##_WINDOW_SIZE; \
			idx_new = (_now / _TYPE##_WINDOW_UNIT) % \
				_TYPE##_WINDOW_SIZE; \
			if (idx_old!=idx_new) { \
				/* do partial update on the last used index */ \
				MY_LOAD._TYPE##_window[idx_old] += _TYPE##_WINDOW_UNIT - \
					(MY_LOAD.last_time % _TYPE##_WINDOW_UNIT); \
				/* update the fully used */ \
				FOR_ALL_INDEXES( i, idx_old, idx_new, _TYPE) { \
					MY_LOAD._TYPE##_window[i] = _TYPE##_WINDOW_UNIT; \
				} \
				/* do partial update on the last used index */ \
				MY_LOAD._TYPE##_window[i] = _now % _TYPE##_WINDOW_UNIT; \
			} else { \
				MY_LOAD._TYPE##_window[idx_old] += \
					(_now % _TYPE##_WINDOW_UNIT) \
					 - \
					(MY_LOAD.last_time % _TYPE##_WINDOW_UNIT); \
			} \
		} \
	}while(0)

void pt_become_idle(void)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, i;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;
	if (usec_now==MY_LOAD.last_time) {
		MY_LOAD.is_busy = 0;
		return;
	}

	MARK_AS_ACTIVE( usec_now, ST);
	MARK_AS_ACTIVE( usec_now, LT);

	MY_LOAD.last_time = usec_now;
	MY_LOAD.is_busy = 0;
}


#define SUM_UP_LOAD(_now, _pno, _TYPE, _ratio) \
	do { \
		/* check if the entire time window has the same status */ \
		if (((long long)_now-(long long)PT_LOAD(_pno).last_time) >= \
				(_TYPE##_WINDOW_TIME)*(_ratio)){\
			/* nothing recorded in the last time window */ \
			used += PT_LOAD(_pno).is_busy?_TYPE##_WINDOW_TIME*_ratio:0; \
		} else { \
			/* get the index inside window for the last time update */ \
			idx_old = (PT_LOAD(_pno).last_time / _TYPE##_WINDOW_UNIT) % \
				_TYPE##_WINDOW_SIZE; \
			idx_new = (_now / _TYPE##_WINDOW_UNIT) % \
				_TYPE##_WINDOW_SIZE; \
			/* ajust the index where we start counting the past used-time \
			 * based on the "ratio" option, if present */  \
			if (_ratio!=1) { \
				idx_start = (idx_new+(int)(_TYPE##_WINDOW_SIZE*(1-_ratio))) % \
					_TYPE##_WINDOW_SIZE; \
				/* the start is between [new,old], so no used recorded yet */ \
				if (idx_start>=idx_old && idx_start<=idx_new) {\
					used+= PT_LOAD(_pno).is_busy?_TYPE##_WINDOW_TIME*_ratio:0;\
					break; \
				}\
			} else { \
				idx_start = idx_new; \
			}\
			/* sum up the already accounted used time */ \
			FOR_ALL_INDEXES( i, idx_start, idx_old, _TYPE) { \
				used += PT_LOAD(_pno)._TYPE##_window[i]; \
			} \
			/* add what is not accounted since last update */ \
			if (PT_LOAD(_pno).is_busy) { \
				if (idx_old!=idx_new) { \
					/* count the last used index (existing + new) */ \
					used += PT_LOAD(_pno)._TYPE##_window[idx_old] + \
						(_TYPE##_WINDOW_UNIT - \
						(PT_LOAD(_pno).last_time % _TYPE##_WINDOW_UNIT)); \
					/* update the fully used */ \
					FOR_ALL_INDEXES( i, idx_old, idx_new, _TYPE) { \
						used += _TYPE##_WINDOW_UNIT; \
					} \
					/* do partial update on current index */ \
					used += _now % _TYPE##_WINDOW_UNIT; \
				} else { \
					used += \
						(_now % _TYPE##_WINDOW_UNIT) \
						 - \
						(PT_LOAD(_pno).last_time % _TYPE##_WINDOW_UNIT); \
				} \
			} \
		} \
	} while(0)

unsigned int pt_get_rt_proc_load( int pno )
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	SUM_UP_LOAD( usec_now, pno, ST, 1);

	return (used*100/ST_WINDOW_TIME);
}


unsigned int pt_get_1m_proc_load( int pno )
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	SUM_UP_LOAD( usec_now, pno, LT, LT_1m_RATIO);

	return (used*100/(LT_WINDOW_TIME*LT_1m_RATIO));
}


unsigned int pt_get_10m_proc_load( int pno )
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	SUM_UP_LOAD( usec_now, pno, LT, 1);

	return (used*100/LT_WINDOW_TIME);
}


unsigned int pt_get_rt_load(int _)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned int n, summed_procs=0;
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	for( n=0 ; n<counted_max_processes; n++)
		if ( is_process_running(n) &&
		(pt[n].flags&(OSS_PROC_NO_LOAD|OSS_PROC_IS_EXTRA))==0 ) {
			SUM_UP_LOAD( usec_now, n, ST, 1);
			summed_procs++;
		}
	if (!summed_procs)
		return 0;

	return (used*100/(ST_WINDOW_TIME*summed_procs));
}


unsigned int pt_get_1m_load(int _)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned int n, summed_procs=0;
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	for( n=0 ; n<counted_max_processes; n++)
		if ( is_process_running(n) &&
		(pt[n].flags&(OSS_PROC_NO_LOAD|OSS_PROC_IS_EXTRA))==0 ) {
			SUM_UP_LOAD( usec_now, n, LT, LT_1m_RATIO);
			summed_procs++;
		}
	if (!summed_procs)
		return 0;

	return (used*100/((long long)LT_WINDOW_TIME*summed_procs*LT_1m_RATIO));
}


unsigned int pt_get_10m_load(int _)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned int n, summed_procs=0;
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	for( n=0 ; n<counted_max_processes; n++)
		if ( is_process_running(n) &&
		(pt[n].flags&(OSS_PROC_NO_LOAD|OSS_PROC_IS_EXTRA))==0 ) {
			SUM_UP_LOAD( usec_now, n, LT, 1);
			summed_procs++;
		}
	if (!summed_procs)
		return 0;

	return (used*100/((long long)LT_WINDOW_TIME*summed_procs));
}


unsigned int pt_get_rt_loadall(int _)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned int n, summed_procs=0;
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	for( n=0 ; n<counted_max_processes; n++)
		if ( is_process_running(n) && (pt[n].flags&OSS_PROC_NO_LOAD)==0 ) {
			SUM_UP_LOAD( usec_now, n, ST, 1);
			summed_procs++;
		}
	if (!summed_procs)
		return 0;

	return (used*100/((long long)ST_WINDOW_TIME*summed_procs));
}


unsigned int pt_get_1m_loadall(int _)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned int n, summed_procs=0;
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	for( n=0 ; n<counted_max_processes; n++)
		if ( is_process_running(n) && (pt[n].flags&OSS_PROC_NO_LOAD)==0 ) {
			SUM_UP_LOAD( usec_now, n, LT, LT_1m_RATIO);
			summed_procs++;
		}
	if (!summed_procs)
		return 0;

	return (used*100/((long long)LT_WINDOW_TIME*summed_procs*LT_1m_RATIO));
}


unsigned int pt_get_10m_loadall(int _)
{
	utime_t usec_now;
	struct timeval tv;
	int idx_old, idx_new, idx_start, i; /* used inside the macro */
	unsigned int n, summed_procs=0;
	unsigned long long used = 0;

	gettimeofday( &tv, NULL);
	usec_now = ((utime_t)(tv.tv_sec)) * 1000000 + tv.tv_usec;

	for( n=0 ; n<counted_max_processes; n++)
		if ( is_process_running(n) && (pt[n].flags&OSS_PROC_NO_LOAD)==0 ) {
			SUM_UP_LOAD( usec_now, n, LT, 1);
			summed_procs++;
		}
	if (!summed_procs)
		return 0;

	return (used*100/((long long)LT_WINDOW_TIME*summed_procs));
}


int register_processes_load_stats(int procs_no)
{
	char *stat_name;
	str stat_prefix;
	char *pno_s;
	str name;
	int pno;

	/* build the stats and register them for each potential process
	 * skipp the attendant, id 0 */
	for( pno=1 ; pno<procs_no ; pno++) {

		pno_s = int2str( (unsigned int)pno, NULL);

		stat_prefix.s = "load-proc";
		stat_prefix.len = sizeof("load-proc")-1;
		if ( (stat_name = build_stat_name( &stat_prefix, pno_s)) == 0 ||
		register_stat2( "load", stat_name, (stat_var**)pt_get_rt_proc_load,
		STAT_IS_FUNC, (void*)(long)pno, 0) != 0) {
			LM_ERR("failed to add RT load stat for process %d\n",pno);
		return -1;
		}
		name.s = stat_name;
		name.len = strlen(stat_name);
		pt[pno].load_rt = get_stat(&name);
		pt[pno].load_rt->flags |= STAT_HIDDEN;

		stat_prefix.s = "load1m-proc";
		stat_prefix.len = sizeof("load1m-proc")-1;
		if ( (stat_name = build_stat_name( &stat_prefix, pno_s)) == 0 ||
		register_stat2( "load", stat_name, (stat_var**)pt_get_1m_proc_load,
		STAT_IS_FUNC, (void*)(long)pno, 0) != 0) {
			LM_ERR("failed to add RT load stat for process %d\n",pno);
			return -1;
		}
		name.s = stat_name;
		name.len = strlen(stat_name);
		pt[pno].load_1m = get_stat(&name);
		pt[pno].load_1m->flags |= STAT_HIDDEN;

		stat_prefix.s = "load10m-proc";
		stat_prefix.len = sizeof("load10m-proc")-1;
		if ( (stat_name = build_stat_name( &stat_prefix, pno_s)) == 0 ||
		register_stat2( "load", stat_name, (stat_var**)pt_get_10m_proc_load,
		STAT_IS_FUNC, (void*)(long)pno, 0) != 0) {
			LM_ERR("failed to add RT load stat for process %d\n",pno);
			return -1;
		}
		name.s = stat_name;
		name.len = strlen(stat_name);
		pt[pno].load_10m = get_stat(&name);
		pt[pno].load_10m->flags |= STAT_HIDDEN;

	}

	return 0;
}
