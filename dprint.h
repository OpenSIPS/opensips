/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 */



#ifndef dprint_h
#define dprint_h

#include <syslog.h>
#include <time.h>

#define L_ALERT -3
#define L_CRIT  -2
#define L_ERR   -1
#define L_WARN   1
#define L_NOTICE 2
#define L_INFO   3
#define L_DBG    4


#define DP_PREFIX  "%s [%d] "

#define DP_ALERT_PREFIX  DP_PREFIX "ALERT:"
#define DP_CRIT_PREFIX   DP_PREFIX "CRITICAL:"
#define DP_ERR_PREFIX    DP_PREFIX "ERROR:"
#define DP_WARN_PREFIX   DP_PREFIX "WARNING:"
#define DP_NOTICE_PREFIX DP_PREFIX "NOTICE:"
#define DP_INFO_PREFIX   DP_PREFIX "INFO:"
#define DP_DBG_PREFIX    DP_PREFIX "DBG:"

#define DPRINT_LEV   L_ERR

#ifndef MOD_NAME
	#define MOD_NAME "core"
#endif

#define LOG_PREFIX  MOD_NAME ": "

#ifndef NO_DEBUG
	#undef NO_LOG
#endif

/* vars:*/

#if CHANGEABLE_DEBUG_LEVEL
extern int *debug;
#else
extern int debug;
#endif
extern int log_stderr;
extern int log_facility;
extern char* log_name;


int dp_my_pid();

void dprint (char* format, ...);

int str2facility(char *s);

void set_proc_debug_level(int level);

void reset_proc_debug_level();

inline static char* dp_time()
{
	time_t ltime;
	char *p;

	time(&ltime);
	p = ctime(&ltime);
	p[20] = 0; /* remove year*/

	return p+4;  /* remove name of day*/
}



#if CHANGEABLE_DEBUG_LEVEL
	#define is_printable(_level)  ((*debug)>=(_level))
#else
	#define is_printable(_level)  (debug>=(_level))
#endif


#ifdef NO_LOG

	#ifdef __SUNPRO_C
		#define LOG(lev, ...)
		#define LM_ALERT( ...)
		#define LM_CRIT( ...)
		#define LM_ERR( ...)
		#define LM_WARN( ...)
		#define LM_NOTICE( ...)
		#define LM_INFO( ...)
		#define LM_DBG( ...)
	#else
		#define LOG(lev, fmt, args...)
		#define LM_ALERT(fmt, args...)
		#define LM_CRIT(fmt, args...)
		#define LM_ERR(fmt, args...)
		#define LM_WARN(fmt, args...)
		#define LM_NOTICE(fmt, args...)
		#define LM_INFO(fmt, args...)
		#define LM_DBG(fmt, args...)
	#endif

#else /* NO_LOG */

	#ifdef __SUNPRO_C

		#define MY_DPRINT( ...) \
				dprint( __VA_ARGS__ ) \

		#define LOG(lev, ...) \
			do { \
				if (is_printable(lev)){ \
					if (log_stderr) dprint (__VA_ARGS__); \
					else { \
						switch(lev){ \
							case L_CRIT: \
								syslog(LOG_CRIT|log_facility, __VA_ARGS__); \
								break; \
							case L_ALERT: \
								syslog(LOG_ALERT|log_facility, __VA_ARGS__); \
								break; \
							case L_ERR: \
								syslog(LOG_ERR|log_facility, __VA_ARGS__); \
								break; \
							case L_WARN: \
								syslog(LOG_WARNING|log_facility, __VA_ARGS__);\
								break; \
							case L_NOTICE: \
								syslog(LOG_NOTICE|log_facility, __VA_ARGS__); \
								break; \
							case L_INFO: \
								syslog(LOG_INFO|log_facility, __VA_ARGS__); \
								break; \
							case L_DBG: \
								syslog(LOG_DEBUG|log_facility, __VA_ARGS__); \
								break; \
						} \
					} \
				} \
			}while(0)

		#define LM_ALERT( ...) \
			do { \
				if (is_printable(L_ALERT)){ \
					if (log_stderr)\
						MY_DPRINT( DP_ALERT_PREFIX __VA_ARGS__);\
					else \
						syslog( LOG_ALERT|log_facility, \
							LOG_PREFIX __VA_ARGS__);\
				} \
			}while(0)

		#define LM_CRIT( ...) \
			do { \
				if (is_printable(L_CRIT)){ \
					if (log_stderr)\
						MY_DPRINT( DP_CRIT_PREFIX __VA_ARGS__);\
					else \
						syslog( LOG_CRIT|log_facility, \
							LOG_PREFIX __VA_ARGS__);\
				} \
			}while(0)

		#define LM_ERR( ...) \
			do { \
				if (is_printable(L_ERR)){ \
					if (log_stderr)\
						MY_DPRINT( DP_ERR_PREFIX __VA_ARGS__);\
					else \
						syslog( LOG_ERR|log_facility, \
							LOG_PREFIX __VA_ARGS__);\
				} \
			}while(0)

		#define LM_WARN( ...) \
			do { \
				if (is_printable(L_WARN)){ \
					if (log_stderr)\
						MY_DPRINT( DP_WARN_PREFIX __VA_ARGS__);\
					else \
						syslog( LOG_WARNING|log_facility, \
							LOG_PREFIX __VA_ARGS__);\
				} \
			}while(0)

		#define LM_NOTICE( ...) \
			do { \
				if (is_printable(L_NOTICE)){ \
					if (log_stderr)\
						MY_DPRINT( DP_NOTICE_PREFIX __VA_ARGS__);\
					else \
						syslog( LOG_NOTICE|log_facility, \
							LOG_PREFIX __VA_ARGS__);\
				} \
			}while(0)

		#define LM_INFO( ...) \
			do { \
				if (is_printable(L_INFO)){ \
					if (log_stderr)\
						MY_DPRINT( DP_INFO_PREFIX __VA_ARGS__);\
					else \
						syslog( LOG_INFO|log_facility, \
							LOG_PREFIX _VA_ARGS__);\
				} \
			}while(0)

		#ifdef NO_DEBUG
			#define LM_DBG( ...)
		#else
			#define LM_DBG( ...) \
				do { \
					if (is_printable(L_DBG)){ \
						if (log_stderr)\
							MY_DPRINT( DP_DBG_PREFIX __VA_ARGS__);\
						else \
							syslog( LOG_DEBUG|log_facility, \
								LOG_PREFIX __VA_ARGS__);\
					} \
				}while(0)
		#endif /*NO_DEBUG*/

	#else /*SUN_PRO_C*/

		#define MY_DPRINT( _prefix, _fmt, args...) \
				dprint( _prefix LOG_PREFIX _fmt, dp_time(), \
					dp_my_pid(), ## args) \

		#define LOG(lev, fmt, args...) \
			do { \
				if (is_printable(lev)){ \
					if (log_stderr) dprint ( fmt, ## args); \
					else { \
						switch(lev){ \
							case L_CRIT: \
								syslog(LOG_CRIT|log_facility, fmt, ##args); \
								break; \
							case L_ALERT: \
								syslog(LOG_ALERT|log_facility, fmt, ##args); \
								break; \
							case L_ERR: \
								syslog(LOG_ERR|log_facility, fmt, ##args); \
								break; \
							case L_WARN: \
								syslog(LOG_WARNING|log_facility, fmt, ##args);\
								break; \
							case L_NOTICE: \
								syslog(LOG_NOTICE|log_facility, fmt, ##args); \
								break; \
							case L_INFO: \
								syslog(LOG_INFO|log_facility, fmt, ##args); \
								break; \
							case L_DBG: \
								syslog(LOG_DEBUG|log_facility, fmt, ##args); \
								break; \
						} \
					} \
				} \
			}while(0)

		#define LM_ALERT( fmt, args...) \
			do { \
				if (is_printable(L_ALERT)){ \
					if (log_stderr)\
						MY_DPRINT( DP_ALERT_PREFIX, fmt, ##args);\
					else \
						syslog( LOG_ALERT|log_facility, \
							LOG_PREFIX fmt, ##args);\
				} \
			}while(0)

		#define LM_CRIT( fmt, args...) \
			do { \
				if (is_printable(L_CRIT)){ \
					if (log_stderr)\
						MY_DPRINT( DP_CRIT_PREFIX, fmt, ##args);\
					else \
						syslog( LOG_CRIT|log_facility, \
							LOG_PREFIX fmt, ##args);\
				} \
			}while(0)

		#define LM_ERR( fmt, args...) \
			do { \
				if (is_printable(L_ERR)){ \
					if (log_stderr)\
						MY_DPRINT( DP_ERR_PREFIX, fmt, ##args);\
					else \
						syslog( LOG_ERR|log_facility, \
							LOG_PREFIX fmt, ##args);\
				} \
			}while(0)

		#define LM_WARN( fmt, args...) \
			do { \
				if (is_printable(L_WARN)){ \
					if (log_stderr)\
						MY_DPRINT( DP_WARN_PREFIX, fmt, ##args);\
					else \
						syslog( LOG_WARNING|log_facility, \
							LOG_PREFIX fmt, ##args);\
				} \
			}while(0)

		#define LM_NOTICE( fmt, args...) \
			do { \
				if (is_printable(L_NOTICE)){ \
					if (log_stderr)\
						MY_DPRINT( DP_NOTICE_PREFIX, fmt, ##args);\
					else \
						syslog( LOG_NOTICE|log_facility, \
							LOG_PREFIX fmt, ##args);\
				} \
			}while(0)

		#define LM_INFO( fmt, args...) \
			do { \
				if (is_printable(L_INFO)){ \
					if (log_stderr)\
						MY_DPRINT( DP_INFO_PREFIX, fmt, ##args);\
					else \
						syslog( LOG_INFO|log_facility, \
							LOG_PREFIX fmt, ##args);\
				} \
			}while(0)

		#ifdef NO_DEBUG
			#define LM_DBG( fmt, args...)
		#else
			#define LM_DBG( fmt, args...) \
				do { \
					if (is_printable(L_DBG)){ \
						if (log_stderr)\
							MY_DPRINT( DP_DBG_PREFIX, fmt, ##args);\
						else \
							syslog( LOG_DEBUG|log_facility, \
								LOG_PREFIX fmt, ##args);\
					} \
				}while(0)
		#endif /*NO_DEBUG*/
	#endif /*SUN_PRO_C*/
#endif




#ifdef NO_DEBUG
	#ifdef __SUNPRO_C
		#define DBG(...)
	#else
		#define DBG(fmt, args...)
	#endif
#else
	#ifdef __SUNPRO_C
		#define DBG(...) LOG(L_DBG, __VA_ARGS__)
	#else
		#define DBG(fmt, args...) LOG(L_DBG, fmt, ## args)
	#endif
#endif

#endif /* ifndef dprint_h */
