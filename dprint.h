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
 *  A) macros to log on a predefine log level, with a standard prefix
 *      such as: "time [pid] level:module:function: <my-msg>"
 *       LM_ALERT( fmt, ....)
 *       LM_CRIT( fmt, ....)
 *       LM_ERR( fmt, ...)
 *       LM_WARN( fmt, ...)
 *       LM_NOTICE( fmt, ...)
 *       LM_INFO( fmt, ...)
 *       LM_DBG( fmt, ...)
 *
 *  B) macros for generic logging
 *       LM_GEN( log_level, fmt, ...) - same standard prefix as above
 *
 *       LM_GEN1( log_level, fmt, ....) - no additional info added
 *       LM_GEN2( log_facility, log_level, fmt, ...)
 */



#ifndef dprint_h
#define dprint_h

#include <syslog.h>
#include <time.h>
#include <stdarg.h>

#include "str.h"

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
	#define DP_PREFIX  (char *)"%s [%d] "
#endif

#define DP_ALERT_STR    "ALERT"
#define DP_CRIT_STR     "CRITICAL"
#define DP_ERR_STR      "ERROR"
#define DP_WARN_STR     "WARNING"
#define DP_NOTICE_STR   "NOTICE"
#define DP_INFO_STR     "INFO"
#define DP_DBG_STR      "DBG"

#define DP_ALERT_TEXT    DP_ALERT_STR ":"
#define DP_CRIT_TEXT     DP_CRIT_STR ":"
#define DP_ERR_TEXT      DP_ERR_STR ":"
#define DP_WARN_TEXT     DP_WARN_STR ":"
#define DP_NOTICE_TEXT   DP_NOTICE_STR ":"
#define DP_INFO_TEXT     DP_INFO_STR ":"
#define DP_DBG_TEXT      DP_DBG_STR ":"

#define DP_ALERT_PREFIX  DP_PREFIX "%s" DP_ALERT_TEXT
#define DP_CRIT_PREFIX   DP_PREFIX "%s" DP_CRIT_TEXT
#define DP_ERR_PREFIX    DP_PREFIX "%s" DP_ERR_TEXT
#define DP_WARN_PREFIX   DP_PREFIX "%s" DP_WARN_TEXT
#define DP_NOTICE_PREFIX DP_PREFIX "%s" DP_NOTICE_TEXT
#define DP_INFO_PREFIX   DP_PREFIX "%s" DP_INFO_TEXT
#define DP_DBG_PREFIX    DP_PREFIX "%s" DP_DBG_TEXT

#define DPRINT_LEV   L_ERR

#ifndef MOD_NAME
	#define MOD_NAME core
#endif

#ifndef NO_DEBUG
	#undef NO_LOG
#endif

#define MAX_LOG_CONS_NO 3

#define STDERR_CONSUMER_NAME "stderror"
#define SYSLOG_CONSUMER_NAME "syslog"
#define EVENT_CONSUMER_NAME  "event"

#define LOG_PLAIN_NAME    "plain_text"
#define LOG_JSON_NAME     "json"
#define LOG_JSON_CEE_NAME "json_cee"

enum log_format {
	LOG_FORMAT_PLAIN,
	LOG_FORMAT_JSON,
	LOG_FORMAT_JSON_CEE
};

/* vars:*/

extern int *log_level;
extern char *log_prefix;
extern int log_stdout;
extern int stderr_enabled, syslog_enabled;
extern int log_event_enabled;
extern int log_facility;
extern char* log_name;
extern char ctime_buf[];
extern enum log_format stderr_log_format, syslog_log_format;
extern int log_event_level_filter;
extern int log_json_buf_size;
extern int log_msg_buf_size;

extern str log_cee_hostname;

/*
 * must be called after init_multi_proc_support()
 * must be called once for each OpenSIPS process
 */
int init_log_level(void);

/* must be called once, before the "pt" process table is freed */
void cleanup_log_level(void);

int init_log_cons_shm_table(void);
void cleanup_log_cons_shm_table(void);

int init_log_json_buf(int realloc);
int init_log_msg_buf(int realloc);

int init_log_cee_hostname(void);

int init_log_event_cons();
int set_log_event_cons_cfg_state(void);
void distroy_log_event_cons();

int set_log_consumer_mute_state(str *name, int state);
int get_log_consumer_mute_state(str *name, int *state);

int set_log_consumer_level_filter(str *name, int level);
int get_log_consumer_level_filter(str *name, int *level_filter);

int parse_log_format(str *format);
int dp_my_pid(void);

void stderr_dprint_tmp(char *format, ...);

void dprint(int log_level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
	__attribute__ ((__format__ (__printf__, 5, 8)));

int str2facility(char *s);

void __set_proc_log_level(int proc_idx, int level);

void __set_proc_default_log_level(int proc_idx, int level);

/* set the current and default log levels for all OpenSIPS processes */
void set_global_log_level(int level);

/* set the log level of the current process */
void set_proc_log_level(int level);

/* changes the logging level to the default value for the current process */
void reset_proc_log_level(void);

/* suppress the E_CORE_LOG event for new logs (useful when handling the event
 * itself in an event consumer) */
void suppress_proc_log_event(void);

void reset_proc_log_event(void);

static inline char* dp_time(void)
{
	time_t ltime;

	time(&ltime);
	ctime_r( &ltime, ctime_buf);
	ctime_buf[19] = 0; /* remove year*/

	return ctime_buf+4;  /* remove name of day*/
}

static inline const char *dp_log_level_str(int log_level)
{
	const char *level_str;

	switch (log_level) {
	case L_ALERT:
		level_str = DP_ALERT_STR;
		break;
	case L_CRIT:
		level_str = DP_CRIT_STR;
		break;
	case L_ERR:
		level_str = DP_ERR_STR;
		break;
	case L_WARN:
		level_str = DP_WARN_STR;
		break;
	case L_NOTICE:
		level_str = DP_NOTICE_STR;
		break;
	case L_INFO:
		level_str = DP_INFO_STR;
		break;
	case L_DBG:
	default:
		level_str = DP_DBG_STR;
	}

	return level_str;
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
		#define LM_GEN(lev, ...)
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
		#define LM_GEN(lev, fmt, args...)
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

		#define stderr_dprint_tmp_err(fmt, ...) \
				stderr_dprint_tmp(DP_ERR_PREFIX LOG_PREFIX fmt __VA_ARGS__)

		#define MY_DPRINT(_log_level, _log_facility, _stderr_prefix, \
					_syslog_prefix, _fmt, ...) \
				dprint(_log_level, _log_facility, \
					LOG_PREFIX_UTIL(MOD_NAME), NULL, \
					_stderr_prefix LOG_PREFIX _fmt, \
					"%s" _prefix LOG_PREFIX _fmt, \
					_fmt, \
					dp_time(), dp_my_pid(), log_prefix __VA_ARGS__ ) \

		#define LM_GEN(_lev, fmt, ...) \
			do { \
				if (is_printable(_lev)){ \
					switch(_lev){ \
					case L_CRIT: \
						MY_DPRINT(L_CRIT, log_facility, DP_CRIT_PREFIX, \
							DP_CRIT_TEXT, fmt __VA_ARGS__); \
						break; \
					case L_ALERT: \
						MY_DPRINT(L_ALERT, log_facility, DP_ALERT_PREFIX, \
							DP_ALERT_TEXT, fmt __VA_ARGS__); \
						break; \
					case L_ERR: \
						MY_DPRINT(L_ERR, log_facility, DP_ERR_PREFIX, \
							DP_ERR_TEXT, fmt __VA_ARGS__); \
						break; \
					case L_WARN: \
						MY_DPRINT(L_WARN, log_facility, DP_WARN_PREFIX, \
							DP_WARN_TEXT, fmt __VA_ARGS__); \
						break; \
					case L_NOTICE: \
						MY_DPRINT(L_NOTICE, log_facility, DP_NOTICE_PREFIX, \
							DP_NOTICE_TEXT, fmt __VA_ARGS__); \
						break; \
					case L_INFO: \
						MY_DPRINT(L_INFO, log_facility, DP_INFO_PREFIX, \
							DP_INFO_TEXT, fmt __VA_ARGS__); \
						break; \
					case L_DBG: \
						MY_DPRINT(L_DBG, log_facility, DP_DBG_PREFIX, \
							DP_DBG_TEXT, fmt __VA_ARGS__); \
						break; \
					default: \
						if (_lev > L_DBG) \
							MY_DPRINT(L_DBG, log_facility, DP_DBG_PREFIX, \
							DP_DBG_TEXT, fmt __VA_ARGS__); \
						break; \
					} \
				} \
			}while(0)

		#define LM_GEN1(_lev, ...) \
			LM_GEN2( log_facility, _lev, __VA_ARGS__)

		#define LM_GEN2( _facility, _lev, fmt, ...) \
			do { \
				if (is_printable(_lev)){ \
					switch(_lev){ \
					case L_CRIT: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_CRIT_PREFIX fmt, "%s" DP_CRIT_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					case L_ALERT: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_ALERT_PREFIX fmt, "%s" DP_ALERT_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					case L_ERR: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_ERR_PREFIX fmt, "%s" DP_ERR_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					case L_WARN: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_WARN_PREFIX fmt, "%s" DP_WARN_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					case L_NOTICE: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_NOTICE_PREFIX fmt, "%s" DP_NOTICE_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					case L_INFO: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_INFO_PREFIX fmt, "%s" DP_INFO_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					case L_DBG: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_DBG_PREFIX fmt, "%s" DP_DBG_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					default: \
						if (_lev > L_DBG) \
							dprint(_lev, _facility, NULL, NULL, \
								DP_DBG_PREFIX fmt, "%s" DP_DBG_TEXT fmt, fmt, \
								dp_time(), dp_my_pid(), log_prefix __VA_ARGS__) \
						break; \
					} \
				} \
			}while(0)

		#define LM_ALERT( fmt, ...) \
			do { \
				if (is_printable(L_ALERT)) \
					MY_DPRINT(L_ALERT, log_facility, DP_ALERT_PREFIX, \
						DP_ALERT_TEXT, fmt __VA_ARGS__); \
			}while(0)

		#define LM_CRIT( fmt, ...) \
			do { \
				if (is_printable(L_CRIT)) \
					MY_DPRINT(L_CRIT, log_facility, DP_CRIT_PREFIX, \
						DP_CRIT_TEXT, fmt __VA_ARGS__); \
			}while(0)

		#define LM_ERR( fmt, ...) \
			do { \
				if (is_printable(L_ERR)) \
					MY_DPRINT(L_ERR, log_facility, DP_ERR_PREFIX, \
						DP_ERR_TEXT, fmt __VA_ARGS__); \
			}while(0)

		#define LM_WARN( fmt, ...) \
			do { \
				if (is_printable(L_WARN)) \
					MY_DPRINT(L_WARN, log_facility, DP_WARN_PREFIX, \
						DP_WARN_TEXT, fmt __VA_ARGS__); \
			}while(0)

		#define LM_NOTICE( fmt, ...) \
			do { \
				if (is_printable(L_NOTICE)) \
					MY_DPRINT(L_NOTICE, log_facility, DP_NOTICE_PREFIX, \
						DP_NOTICE_TEXT, fmt __VA_ARGS__); \
			}while(0)

		#define LM_INFO( fmt, ...) \
			do { \
				if (is_printable(L_INFO)) \
					MY_DPRINT(L_INFO, log_facility, DP_INFO_PREFIX, \
						DP_INFO_TEXT, fmt __VA_ARGS__); \
			}while(0)

		#ifdef NO_DEBUG
			#define LM_DBG( fmt, ...)
		#else
			#define LM_DBG( fmt, ...) \
				do { \
					if (is_printable(L_DBG)) \
						MY_DPRINT(L_DBG, log_facility, DP_DBG_PREFIX, \
							DP_DBG_TEXT, fmt __VA_ARGS__); \
				}while(0)
		#endif /*NO_DEBUG*/

	#else /*SUN_PRO_C*/

		#define LOG_PREFIX_UTIL2(_n) #_n
		#define LOG_PREFIX_UTIL(_n)  LOG_PREFIX_UTIL2(_n)
		#define LOG_PREFIX  LOG_PREFIX_UTIL(MOD_NAME) ":%s: "

		#define stderr_dprint_tmp_err(_fmt, args...) \
				stderr_dprint_tmp(DP_ERR_PREFIX LOG_PREFIX _fmt, \
				dp_time(), dp_my_pid(), log_prefix, __DP_FUNC, ## args) \

		#define MY_DPRINT(_log_level, _log_facility, _stderr_prefix, \
					_syslog_prefix, _fmt, args...) \
				dprint(_log_level, _log_facility, \
					LOG_PREFIX_UTIL(MOD_NAME), __DP_FUNC, \
					_stderr_prefix LOG_PREFIX _fmt, \
					(char *)"%s" _syslog_prefix LOG_PREFIX _fmt, \
					(char *)_fmt, \
					dp_time(), dp_my_pid(), log_prefix, __DP_FUNC, ## args) \

		#define LM_GEN(_lev, fmt, args...) \
			do { \
				if (is_printable(_lev)){ \
					switch(_lev){ \
					case L_CRIT: \
						MY_DPRINT(L_CRIT, log_facility, DP_CRIT_PREFIX, \
							DP_CRIT_TEXT, fmt, ##args); \
						break; \
					case L_ALERT: \
						MY_DPRINT(L_ALERT, log_facility, DP_ALERT_PREFIX, \
							DP_ALERT_TEXT, fmt, ##args); \
						break; \
					case L_ERR: \
						MY_DPRINT(L_ERR, log_facility, DP_ERR_PREFIX, \
							DP_ERR_TEXT, fmt, ##args); \
						break; \
					case L_WARN: \
						MY_DPRINT(L_WARN, log_facility, DP_WARN_PREFIX, \
							DP_WARN_TEXT, fmt, ##args); \
						break; \
					case L_NOTICE: \
						MY_DPRINT(L_NOTICE, log_facility, DP_NOTICE_PREFIX, \
							DP_NOTICE_TEXT, fmt, ##args); \
						break; \
					case L_INFO: \
						MY_DPRINT(L_INFO, log_facility, DP_INFO_PREFIX, \
							DP_INFO_TEXT, fmt, ##args); \
						break; \
					case L_DBG: \
						MY_DPRINT(L_DBG, log_facility, DP_DBG_PREFIX, \
							DP_DBG_TEXT, fmt, ##args); \
						break; \
					default: \
						if (_lev > L_DBG) \
							MY_DPRINT(L_DBG, log_facility, DP_DBG_PREFIX, \
								DP_DBG_TEXT, fmt, ##args); \
						break; \
					} \
				} \
			}while(0)

		#define LM_GEN1(_lev, args...) \
			LM_GEN2( log_facility, _lev, ##args)

		#define LM_GEN2( _facility, _lev, fmt, args...) \
			do { \
				if (is_printable(_lev)){ \
					switch(_lev){ \
					case L_CRIT: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_CRIT_PREFIX fmt, "%s" DP_CRIT_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					case L_ALERT: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_ALERT_PREFIX fmt, "%s" DP_ALERT_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					case L_ERR: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_ERR_PREFIX fmt, "%s" DP_ERR_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					case L_WARN: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_WARN_PREFIX fmt, "%s" DP_WARN_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					case L_NOTICE: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_NOTICE_PREFIX fmt, "%s" DP_NOTICE_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					case L_INFO: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_INFO_PREFIX fmt, "%s" DP_INFO_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					case L_DBG: \
						dprint(_lev, _facility, NULL, NULL, \
							DP_DBG_PREFIX fmt, "%s" DP_DBG_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					default: \
						if (_lev > L_DBG) \
							dprint(_lev, _facility, NULL, NULL, \
							DP_DBG_PREFIX fmt, "%s" DP_DBG_TEXT fmt, fmt, \
							dp_time(), dp_my_pid(), log_prefix, ## args); \
						break; \
					} \
				} \
			}while(0)

		#define LM_ALERT( fmt, args...) \
			do { \
				if (is_printable(L_ALERT)) \
					MY_DPRINT(L_ALERT, log_facility, DP_ALERT_PREFIX, \
						DP_ALERT_TEXT, fmt, ##args); \
			}while(0)

		#define LM_CRIT( fmt, args...) \
			do { \
				if (is_printable(L_CRIT)) \
					MY_DPRINT(L_CRIT, log_facility, DP_CRIT_PREFIX, \
						DP_CRIT_TEXT, fmt, ##args); \
			}while(0)

		#define LM_ERR( fmt, args...) \
			do { \
				if (is_printable(L_ERR)) \
					MY_DPRINT(L_ERR, log_facility, DP_ERR_PREFIX, \
						DP_ERR_TEXT, fmt, ##args); \
			}while(0)

		#define LM_WARN( fmt, args...) \
			do { \
				if (is_printable(L_WARN)) \
					MY_DPRINT(L_WARN, log_facility, DP_WARN_PREFIX, \
						DP_WARN_TEXT, fmt, ##args); \
			}while(0)

		#define LM_NOTICE( fmt, args...) \
			do { \
				if (is_printable(L_NOTICE)) \
					MY_DPRINT(L_NOTICE, log_facility, DP_NOTICE_PREFIX, \
						DP_NOTICE_TEXT, fmt, ##args); \
			}while(0)

		#define LM_INFO( fmt, args...) \
			do { \
				if (is_printable(L_INFO)) \
					MY_DPRINT(L_INFO, log_facility, DP_INFO_PREFIX, \
						DP_INFO_TEXT, fmt, ##args); \
			}while(0)

		#ifdef NO_DEBUG
			#define LM_DBG( fmt, args...)
		#else
			#define LM_DBG( fmt, args...) \
				do { \
					if (is_printable(L_DBG)) \
						MY_DPRINT(L_DBG, log_facility, DP_DBG_PREFIX, \
							DP_DBG_TEXT, fmt, ##args); \
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

#define CASE_PRINTENUM(em) \
	CASE_FPRINTENUM(stdout, em)
#define CASE_FPRINTENUM(file, em) \
        case em: printf(# em "\n"); break

#endif /* ifndef dprint_h */
