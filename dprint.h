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


#define L_ALERT -3
#define L_CRIT  -2
#define L_ERR   -1
#define L_WARN   1
#define L_NOTICE 2
#define L_INFO   3
#define L_DBG    4

#define DPRINT_LEV   L_ERR


/* vars:*/

#if CHANGEABLE_DEBUG_LEVEL
extern int *debug;
#else
extern int debug;
#endif
extern int log_stderr;
extern int log_facility;
extern char* log_name;



void dprint (char* format, ...);

int str2facility(char *s);

#if CHANGEABLE_DEBUG_LEVEL
	#define is_printable(_level)  ((*debug)>=(_level))
#else
	#define is_printable(_level)  (debug>=(_level))
#endif


#ifndef NO_DEBUG
	#undef NO_LOG
#endif

#ifdef NO_LOG
	#ifdef __SUNPRO_C
		#define LOG(lev, ...)
	#else
		#define LOG(lev, fmt, args...)
	#endif
#else
	#ifdef __SUNPRO_C
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
	#else
		#define LOG(lev, fmt, args...) \
			do { \
				if (is_printable(lev)){ \
					if (log_stderr) dprint (fmt, ## args); \
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
