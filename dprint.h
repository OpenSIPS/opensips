/*
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
 */

/*!
 * \file
 * \brief OpenSIPS Debug console print functions
 * \see syslog.h
 */


/*! \page DebugLogFunction Description of the logging functions:
 *
 *  A) macros to log on a predefine log level and with standard prefix
 *     for with additional info: [time]
 *     No dynamic FMT is accepted (due macro processing).
 *       LM_ALERT( fmt, ....)
 *       LM_CRIT( fmt, ....)
 *       LM_ERR( fmt, ...)
 *       LM_WARN( fmt, ...)
 *       LM_NOTICE( fmt, ...)
 *       LM_INFO( fmt, ...)
 *       LM_DBG( fmt, ...)
 *  B) macros for generic logging ; no additional information is added;
 *     Works with dynamic FMT.
 *       LM_GEN1( log_level, fmt, ....)
 *       LM_GEN2( log_facility, log_level, fmt, ...)
 */



#ifndef dprint_h
#define dprint_h

#include <syslog.h>
#include <time.h>

#define L_ALERT -3	/*!< Alert level */
#define L_CRIT  -2	/*!< Critical level */
#define L_ERR   -1	/*!< Error level */
#define L_WARN   1	/*!< Warning level */
#define L_NOTICE 2	/*!< Notice level */
#define L_INFO   3	/*!< Info level */
#define L_DBG    4	/*!< Debug level */


#ifdef __SUNPRO_C
	#define DP_PREFIX
#else
	#define DP_PREFIX  "%s [%d] "
#endif

#define DP_ALERT_TEXT    "ALERT:"
#define DP_CRIT_TEXT     "CRITICAL:"
#define DP_ERR_TEXT      "ERROR:"
#define DP_WARN_TEXT     "WARNING:"
#define DP_NOTICE_TEXT   "NOTICE:"
#define DP_INFO_TEXT     "INFO:"
#define DP_DBG_TEXT      "DBG:"

#define DP_ALERT_PREFIX  DP_PREFIX DP_ALERT_TEXT
#define DP_CRIT_PREFIX   DP_PREFIX DP_CRIT_TEXT
#define DP_ERR_PREFIX    DP_PREFIX DP_ERR_TEXT
#define DP_WARN_PREFIX   DP_PREFIX DP_WARN_TEXT
#define DP_NOTICE_PREFIX DP_PREFIX DP_NOTICE_TEXT
#define DP_INFO_PREFIX   DP_PREFIX DP_INFO_TEXT
#define DP_DBG_PREFIX    DP_PREFIX DP_DBG_TEXT

#define DPRINT_LEV   L_ERR

#ifndef MOD_NAME
	#define MOD_NAME core
#endif

#ifndef NO_DEBUG
	#undef NO_LOG
#endif

/* vars:*/

extern int *log_level;
extern int log_stderr;
extern int log_facility;
extern char* log_name;
extern char ctime_buf[];

/*
 * must be called after init_multi_proc_support()
 * must be called once for each OpenSIPS process
 */
int init_log_level(void);

/* must be called once, before the "pt" process table is freed */
void cleanup_log_level(void);

int dp_my_pid(void);

void dprint (char* format, ...);

int str2facility(char *s);

void __set_proc_log_level(int proc_idx, int level);

void __set_proc_default_log_level(int proc_idx, int level);

/* set the current and default log levels for all OpenSIPS processes */
void set_global_log_level(int level);

/* set the log level of the current process */
void set_proc_log_level(int level);

/* changes the logging level to the default value for the current process */
void reset_proc_log_level(void);

static inline char* dp_time(void)
{
	time_t ltime;

	time(&ltime);
	ctime_r( &ltime, ctime_buf);
	ctime_buf[19] = 0; /* remove year*/

	return ctime_buf+4;  /* remove name of day*/
}

#define is_printable(_level)  (((int)(*log_level)) >= ((int)(_level)))

#if defined __GNUC__
	#define __DP_FUNC  __FUNCTION__
#elif defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
	#define __DP_FUNC  __func__
#else
	#define __DP_FUNC  ((__const char *) 0)
#endif


#ifdef NO_LOG

	#ifdef __SUNPRO_C
		#define LM_GEN2(facility, lev, ...)
		#define LM_GEN1(lev, ...)
		#define LM_ALERT( ...)
		#define LM_CRIT( ...)
		#define LM_ERR( ...)
		#define LM_WARN( ...)
		#define LM_NOTICE( ...)
		#define LM_INFO( ...)
		#define LM_DBG( ...)
	#else
		#define LM_GEN2(facility, lev, fmt, args...)
		#define LM_GEN1(lev, fmt, args...)
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
		#define LOG_PREFIX_UTIL2(_n) #_n
		#define LOG_PREFIX_UTIL(_n)  LOG_PREFIX_UTIL2(_n)
		#define LOG_PREFIX  LOG_PREFIX_UTIL(MOD_NAME) ": "

		#define MY_DPRINT( ...) \
				dprint( LOG_PREFIX __VA_ARGS__ ) \

		#define MY_SYSLOG( _log_level, ...) \
				syslog( (_log_level)|log_facility, \
							LOG_PREFIX __VA_ARGS__);\

		#define LM_GEN1(_lev, ...) \
			LM_GEN2( log_facility, _lev, __VA_ARGS__)

		#define LM_GEN2( _facility, _lev, ...) \
			do { \
				if (is_printable(_lev)){ \
					if (log_stderr) \
						dprint( DP_PREFIX fmt, dp_time(), \
							dp_my_pid(), __VA_ARGS__ ); \
					else { \
						switch(_lev){ \
							case L_CRIT: \
								syslog(LOG_CRIT|_facility, __VA_ARGS__); \
								break; \
							case L_ALERT: \
								syslog(LOG_ALERT|_facility, __VA_ARGS__); \
								break; \
							case L_ERR: \
								syslog(LOG_ERR|_facility, __VA_ARGS__); \
								break; \
							case L_WARN: \
								syslog(LOG_WARNING|_facility, __VA_ARGS__);\
								break; \
							case L_NOTICE: \
								syslog(LOG_NOTICE|_facility, __VA_ARGS__); \
								break; \
							case L_INFO: \
								syslog(LOG_INFO|_facility, __VA_ARGS__); \
								break; \
							case L_DBG: \
								syslog(LOG_DEBUG|_facility, __VA_ARGS__); \
								break; \
							default: \
								if (_lev > L_DBG) \
									syslog(LOG_DEBUG|_facility, __VA_ARGS__); \
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
						MY_SYSLOG( LOG_ALERT, DP_ALERT_TEXT __VA_ARGS__);\
				} \
			}while(0)

		#define LM_CRIT( ...) \
			do { \
				if (is_printable(L_CRIT)){ \
					if (log_stderr)\
						MY_DPRINT( DP_CRIT_PREFIX __VA_ARGS__);\
					else \
						MY_SYSLOG( LOG_CRIT, DP_CRIT_TEXT __VA_ARGS__);\
				} \
			}while(0)

		#define LM_ERR( ...) \
			do { \
				if (is_printable(L_ERR)){ \
					if (log_stderr)\
						MY_DPRINT( DP_ERR_PREFIX __VA_ARGS__);\
					else \
						MY_SYSLOG( LOG_ERR, DP_ERR_TEXT __VA_ARGS__);\
				} \
			}while(0)

		#define LM_WARN( ...) \
			do { \
				if (is_printable(L_WARN)){ \
					if (log_stderr)\
						MY_DPRINT( DP_WARN_PREFIX __VA_ARGS__);\
					else \
						MY_SYSLOG( LOG_WARNING, DP_WARN_TEXT __VA_ARGS__);\
				} \
			}while(0)

		#define LM_NOTICE( ...) \
			do { \
				if (is_printable(L_NOTICE)){ \
					if (log_stderr)\
						MY_DPRINT( DP_NOTICE_PREFIX __VA_ARGS__);\
					else \
						MY_SYSLOG( LOG_NOTICE, DP_NOTICE_TEXT __VA_ARGS__);\
				} \
			}while(0)

		#define LM_INFO( ...) \
			do { \
				if (is_printable(L_INFO)){ \
					if (log_stderr)\
						MY_DPRINT( DP_INFO_PREFIX __VA_ARGS__);\
					else \
						MY_SYSLOG( LOG_INFO, DP_INFO_TEXT __VA_ARGS__);\
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
							MY_SYSLOG( LOG_DEBUG, DP_DBG_TEXT __VA_ARGS__);\
					} \
				}while(0)
		#endif /*NO_DEBUG*/

	#else /*SUN_PRO_C*/

		#define LOG_PREFIX_UTIL2(_n) #_n
		#define LOG_PREFIX_UTIL(_n)  LOG_PREFIX_UTIL2(_n)
		#define LOG_PREFIX  LOG_PREFIX_UTIL(MOD_NAME) ":%s: "

		#define MY_DPRINT( _prefix, _fmt, args...) \
				dprint( _prefix LOG_PREFIX _fmt, dp_time(), \
					dp_my_pid(), __DP_FUNC, ## args) \

		#define MY_SYSLOG( _log_level, _prefix, _fmt, args...) \
				syslog( (_log_level)|log_facility, \
							_prefix LOG_PREFIX _fmt, __DP_FUNC, ##args);\

		#define LM_GEN1(_lev, args...) \
			LM_GEN2( log_facility, _lev, ##args)

		#define LM_GEN2( _facility, _lev, fmt, args...) \
			do { \
				if (is_printable(_lev)){ \
					if (log_stderr) \
						dprint( DP_PREFIX fmt, dp_time(), \
							dp_my_pid(), ## args); \
					else { \
						switch(_lev){ \
							case L_CRIT: \
								syslog(LOG_CRIT|_facility, fmt, ##args); \
								break; \
							case L_ALERT: \
								syslog(LOG_ALERT|_facility, fmt, ##args); \
								break; \
							case L_ERR: \
								syslog(LOG_ERR|_facility, fmt, ##args); \
								break; \
							case L_WARN: \
								syslog(LOG_WARNING|_facility, fmt, ##args);\
								break; \
							case L_NOTICE: \
								syslog(LOG_NOTICE|_facility, fmt, ##args); \
								break; \
							case L_INFO: \
								syslog(LOG_INFO|_facility, fmt, ##args); \
								break; \
							case L_DBG: \
								syslog(LOG_DEBUG|_facility, fmt, ##args); \
								break; \
							default: \
								if (_lev > L_DBG) \
									syslog(LOG_DEBUG|_facility, fmt, ##args); \
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
						MY_SYSLOG( LOG_ALERT, DP_ALERT_TEXT, fmt, ##args);\
				} \
			}while(0)

		#define LM_CRIT( fmt, args...) \
			do { \
				if (is_printable(L_CRIT)){ \
					if (log_stderr)\
						MY_DPRINT( DP_CRIT_PREFIX, fmt, ##args);\
					else \
						MY_SYSLOG( LOG_CRIT, DP_CRIT_TEXT, fmt, ##args);\
				} \
			}while(0)

		#define LM_ERR( fmt, args...) \
			do { \
				if (is_printable(L_ERR)){ \
					if (log_stderr)\
						MY_DPRINT( DP_ERR_PREFIX, fmt, ##args);\
					else \
						MY_SYSLOG( LOG_ERR, DP_ERR_TEXT, fmt, ##args);\
				} \
			}while(0)

		#define LM_WARN( fmt, args...) \
			do { \
				if (is_printable(L_WARN)){ \
					if (log_stderr)\
						MY_DPRINT( DP_WARN_PREFIX, fmt, ##args);\
					else \
						MY_SYSLOG( LOG_WARNING, DP_WARN_TEXT, fmt, ##args);\
				} \
			}while(0)

		#define LM_NOTICE( fmt, args...) \
			do { \
				if (is_printable(L_NOTICE)){ \
					if (log_stderr)\
						MY_DPRINT( DP_NOTICE_PREFIX, fmt, ##args);\
					else \
						MY_SYSLOG( LOG_NOTICE, DP_NOTICE_TEXT, fmt, ##args);\
				} \
			}while(0)

		#define LM_INFO( fmt, args...) \
			do { \
				if (is_printable(L_INFO)){ \
					if (log_stderr)\
						MY_DPRINT( DP_INFO_PREFIX, fmt, ##args);\
					else \
						MY_SYSLOG( LOG_INFO, DP_INFO_TEXT, fmt, ##args);\
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
							MY_SYSLOG( LOG_DEBUG, DP_DBG_TEXT, fmt, ##args);\
					} \
				}while(0)
		#endif /*NO_DEBUG*/
	#endif /*SUN_PRO_C*/
#endif

#define LM_BUG(format, args...) \
	do { \
		LM_CRIT("\n>>> " format"\nIt seems you have hit a programming bug.\n" \
				"Please help us make OpenSIPS better by reporting it at " \
				"https://github.com/OpenSIPS/opensips/issues\n\n", ##args); \
	} while (0)

#endif /* ifndef dprint_h */
