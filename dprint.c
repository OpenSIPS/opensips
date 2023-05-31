/*
 * debug print
 *
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
 */

/*!
 * \file
 * \brief OpenSIPS Debug console print functions
 */


#include "dprint.h"
#include "log_interface.h"
#include "globals.h"
#include "pt.h"

#include <stdarg.h>
#include <stdio.h>
#include <strings.h>

/* used internally by the log interface */
typedef void (*log_print_pre_fmt_f)(log_print_f gen_print_func, int log_level,
	int facility, char *module, const char *func,
	char *stderr_plain_fmt, char *syslog_plain_fmt, char *format, va_list ap);

struct log_consumer_t {
	str name;
	log_print_f gen_print_func;
	log_print_pre_fmt_f pre_fmt_print_func;
	int level_filter;
	int muted;
};

static int log_level_holder = L_NOTICE;
enum log_format stderr_log_format = LOG_FORMAT_PLAIN;
enum log_format syslog_log_format = LOG_FORMAT_PLAIN;

/* current logging level for this process */
int *log_level = &log_level_holder;
char *log_prefix = "";

/* used when resetting the logging level of this process */
static int *default_log_level;

static char *log_json_buf = NULL;
int log_json_buf_size = 6144;
static char *log_msg_buf = NULL;
int log_msg_buf_size = 4096;

str log_cee_hostname;

static void stderr_dprint(int log_level, int facility, char *module, const char *func,
	char *format, va_list ap);
static void syslog_dprint(int log_level, int facility, char *module, const char *func,
	char *format, va_list ap);

static void stderr_pre_fmt_func(log_print_f gen_print_func, int log_level,
	int facility, char *module, const char *func,
	char *stderr_plain_fmt, char *syslog_plain_fmt, char *format, va_list ap);
static void syslog_pre_fmt_func(log_print_f gen_print_func, int log_level,
	int facility, char *module, const char *func,
	char *stderr_plain_fmt, char *syslog_plain_fmt, char *format, va_list ap);

/* static consumer table to be used until a shm one is alloc'ed;
 * only stderror is enabled initially */
static struct log_consumer_t default_log_consumers[2] ={
	{str_init(STDERR_CONSUMER_NAME), stderr_dprint, stderr_pre_fmt_func, 0, 0},
	{str_init(SYSLOG_CONSUMER_NAME), syslog_dprint, syslog_pre_fmt_func, 0, 1}
};

struct log_consumer_t *log_consumers = default_log_consumers;
int log_consumers_no = 2;

int log_event_enabled = 0;
int log_event_level_filter = 0;
static str evi_log_name = str_init("E_CORE_LOG");
static event_id_t evi_log_id;

static char* str_fac[]={"LOG_AUTH","LOG_CRON","LOG_DAEMON",
					"LOG_KERN","LOG_LOCAL0","LOG_LOCAL1",
					"LOG_LOCAL2","LOG_LOCAL3","LOG_LOCAL4","LOG_LOCAL5",
					"LOG_LOCAL6","LOG_LOCAL7","LOG_LPR","LOG_MAIL",
					"LOG_NEWS","LOG_USER","LOG_UUCP",
#ifndef __OS_solaris
					"LOG_AUTHPRIV","LOG_FTP","LOG_SYSLOG",
#endif
					0};
static int int_fac[]={LOG_AUTH ,  LOG_CRON , LOG_DAEMON ,
					LOG_KERN , LOG_LOCAL0 , LOG_LOCAL1 ,
					LOG_LOCAL2 , LOG_LOCAL3 , LOG_LOCAL4 , LOG_LOCAL5 ,
					LOG_LOCAL6 , LOG_LOCAL7 , LOG_LPR , LOG_MAIL ,
					LOG_NEWS , LOG_USER , LOG_UUCP
#ifndef __OS_solaris
					,LOG_AUTHPRIV,LOG_FTP,LOG_SYSLOG
#endif
					};

char ctime_buf[256];

int str2facility(char *s)
{
	int i;

	for( i=0; str_fac[i] ; i++) {
		if (!strcasecmp(s,str_fac[i]))
			return int_fac[i];
	}
	return -1;
}


int dp_my_pid(void)
{
	return my_pid();
}

int parse_log_format(str *format)
{
	if (str_match(format, (&str_init(LOG_PLAIN_NAME))))
		return LOG_FORMAT_PLAIN;
	else if (str_match(format, (&str_init(LOG_JSON_NAME))))
		return LOG_FORMAT_JSON;
	else if (str_match(format, (&str_init(LOG_JSON_CEE_NAME))))
		return LOG_FORMAT_JSON_CEE;
	else
		return -1;
}

void stderr_dprint_tmp(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr,format,ap);
	fflush(stderr);
	va_end(ap);
}

int init_log_cee_hostname(void)
{
	struct addrinfo hints, *info = NULL;
	char hostname[HOST_NAME_MAX+1];
	int rc;
	str cname;

	if (log_cee_hostname.s)
		return 0;

	gethostname (hostname, HOST_NAME_MAX);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	rc = getaddrinfo(hostname, 0, &hints, &info);
	if (!rc && info) {
		init_str(&cname, info->ai_canonname);
		if (pkg_str_dup(&log_cee_hostname, &cname) < 0) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
	}

	if (info)
		freeaddrinfo(info);

	return 0;
}

#define append_string(_d,_s,_len) \
	do{\
		memcpy((_d),(_s),(_len));\
		(_d) += (_len);\
		len += (_len);\
	}while(0)

#define append_string_st(_d,_s) \
	do{\
		memcpy((_d),(_s),sizeof(_s) - 1);\
		(_d) += sizeof(_s) - 1;\
		len += sizeof(_s) - 1;\
	}while(0)

#define S_LEN(_s) (sizeof(_s) - 1)

#define DP_JSON_TIME_KEY      "{\"time\": \""
#define DP_JSON_PID_KEY       "\", \"pid\": "
#define DP_JSON_LEVEL_KEY     ", \"level\": \""
#define DP_JSON_MODULE_KEY    "\", \"module\": \""
#define DP_JSON_FUNC_KEY      "\", \"function\": \""
#define DP_JSON_PREFIX_QT_KEY "\", \"prefix\": \""
#define DP_JSON_PREFIX_KEY    ", \"prefix\": \""
#define DP_JSON_MSG_QT_KEY    "\", \"message\": \""
#define DP_JSON_MSG_KEY       ", \"message\": \""

#define DP_JSON_CEE_AT_PREFIX    "@cee: "
#define DP_JSON_CEE_TIME_KEY     "{\"time\": \""
#define DP_JSON_CEE_PID_KEY      "\", \"proc\": {\"id\": \""
#define DP_JSON_CEE_LEVEL_KEY    "\"}, \"pri\": \""
#define DP_JSON_CEE_MODULE_KEY   "\", \"subsys\": \""
#define DP_JSON_CEE_FUNC_KEY     "\", \"native\": {\"function\": \""
#define DP_JSON_CEE_PREFIX_KEY   "\", \"log_prefix\": \""
#define DP_JSON_CEE_PREFIX_O_KEY "\"}, \"native\": {\"log_prefix\": \""
#define DP_JSON_CEE_MSG_KEY      "\"}, \"msg\": \""
#define DP_JSON_CEE_PNAME_KEY    "\", \"pname\": \""
#define DP_JSON_CEE_PNAME_VAL    "opensips"
#define DP_JSON_CEE_HOST_KEY     "\", \"hostname\": \""

#define DP_JSON_MSG_END       "\"}"

static int log_escape_json_buf(char *src, int src_len, char *dst, int dst_max_len)
{
	int i, j = 0;
	int rlen = 0;

	/* calculate the required length in the dst buffer */
	for (i=0; i<src_len; i++) {
		rlen++;

		switch (src[i]) {
		case '\\':
		case '\"':
		case '\b':
		case '\f':
		case '\n':
		case '\r':
		case '\t':
			rlen++;  /* +1 for the backslash */
		    break;
		default:
			if (src[i] < 32)
				rlen += 6;  /* +6 for \uXXXX */
		}
	}

	if (rlen>dst_max_len) {
		stderr_dprint_tmp("error: buffer too small! needed: %d\n", rlen);
		return -1;
	} else if (rlen == src_len) {
		/* nothing needs to be escaped */
		memcpy(dst, src, src_len);
		return src_len;
	}

	for (i=0; i<src_len; i++) {
		if (src[i] > 31 && src[i] != '\\' && src[i] != '\"') {
			dst[j++] = src[i];
		} else {
			dst[j++] = '\\';

			switch (src[i]) {
			case '\\':
				dst[j++] = '\\';
				break;
			case '\"':
				dst[j++] = '\"';
				break;
			case '\b':
				dst[j++] = 'b';
				break;
			case '\f':
				dst[j++] = 'f';
				break;
			case '\n':
				dst[j++] = 'n';
				break;
			case '\r':
				dst[j++] = 'r';
				break;
			case '\t':
				dst[j++] = 't';
				break;
			default:
				/* escape and print as unicode codepoint */
				sprintf(dst+j, "u%04x", src[i]);
				j += 5;
			}
		}
	}

	return j;
}

enum log_json_format {
	LOG_JSON_SCHEMA_BASIC,
	LOG_JSON_SCHEMA_CEE,
	LOG_JSON_SCHEMA_CEE_PREFIX  /* for syslog, JSON prefixed with "@cee: " */
};

static int log_print_json(str *buf, enum log_json_format json_fmt, char *time,
	int pid, char *prefix, char *level, char *module, const char *func,
	char *format, va_list ap)
{
	char *p, *tmp;
	int len = 0, rlen;
	int l;

	if (json_fmt > LOG_JSON_SCHEMA_BASIC) {
		if (json_fmt == LOG_JSON_SCHEMA_CEE_PREFIX) {
			rlen = S_LEN(DP_JSON_CEE_PNAME_KEY) + (log_name ? strlen(log_name) :
				S_LEN(DP_JSON_CEE_PNAME_VAL)) + S_LEN(DP_JSON_CEE_HOST_KEY) +
				log_cee_hostname.len + S_LEN(DP_JSON_MSG_END) + 1;

			len = S_LEN(DP_JSON_CEE_AT_PREFIX);
		} else {
			rlen = S_LEN(DP_JSON_MSG_END) + 1;
		}

		len += S_LEN(DP_JSON_CEE_TIME_KEY) + strlen(time) +
			S_LEN(DP_JSON_CEE_PID_KEY) + INT2STR_MAX_LEN +
			(module && func ? S_LEN(DP_JSON_CEE_LEVEL_KEY) + strlen(level) +
			S_LEN(DP_JSON_CEE_MODULE_KEY) + strlen(module) +
			S_LEN(DP_JSON_CEE_FUNC_KEY) + strlen(func) : 0) +
			S_LEN(DP_JSON_CEE_PREFIX_O_KEY) + strlen(prefix) +
			S_LEN(DP_JSON_MSG_KEY) + rlen;
	} else {
		rlen = S_LEN(DP_JSON_MSG_END) + 1;

		len = S_LEN(DP_JSON_TIME_KEY) + strlen(time) + S_LEN(DP_JSON_PID_KEY) +
			INT2STR_MAX_LEN + S_LEN(DP_JSON_LEVEL_KEY) + strlen(level) +
			(module && func ? S_LEN(DP_JSON_MODULE_KEY) + strlen(module) +
			S_LEN(DP_JSON_FUNC_KEY) + strlen(func) : 0) +
			S_LEN(DP_JSON_PREFIX_QT_KEY) + strlen(prefix) +
			S_LEN(DP_JSON_MSG_QT_KEY) + rlen;
	}

	if (len >= buf->len) {
		stderr_dprint_tmp("error: buffer too small! needed: %d\n", len);
		return -1;
	}

	len = 0;
	p = buf->s;

	if (json_fmt > LOG_JSON_SCHEMA_BASIC) {
		if (json_fmt == LOG_JSON_SCHEMA_CEE_PREFIX)
			append_string_st(p, DP_JSON_CEE_AT_PREFIX);

		append_string_st(p, DP_JSON_CEE_TIME_KEY);
		append_string(p, time, strlen(time));

		append_string_st(p, DP_JSON_CEE_PID_KEY);
		tmp = int2str(pid, &l);
		append_string(p, tmp, l);

		if (module && func) {
			append_string_st(p, DP_JSON_CEE_LEVEL_KEY);
			append_string(p, level, strlen(level));

			append_string_st(p, DP_JSON_CEE_MODULE_KEY);
			append_string(p, module, strlen(module));

			append_string_st(p, DP_JSON_CEE_FUNC_KEY);
			append_string(p, func, strlen(func));
		}

		if (strlen(prefix) != 0) {
			if (module && func)
				append_string_st(p, DP_JSON_CEE_PREFIX_KEY);
			else
				append_string_st(p, DP_JSON_CEE_PREFIX_O_KEY);
			append_string(p, prefix, strlen(prefix)-1/*skip the ':'*/);
		}

		append_string_st(p, DP_JSON_CEE_MSG_KEY);
	} else {
		append_string_st(p, DP_JSON_TIME_KEY);
		append_string(p, time, strlen(time));

		append_string_st(p, DP_JSON_PID_KEY);
		tmp = int2str(pid, &l);
		append_string(p, tmp, l);

		if (module && func) {
			append_string_st(p, DP_JSON_LEVEL_KEY);
			append_string(p, level, strlen(level));

			append_string_st(p, DP_JSON_MODULE_KEY);
			append_string(p, module, strlen(module));

			append_string_st(p, DP_JSON_FUNC_KEY);
			append_string(p, func, strlen(func));
		}

		if (strlen(prefix) != 0) {
			if (module && func)
				append_string_st(p, DP_JSON_PREFIX_QT_KEY);
			else
				append_string_st(p, DP_JSON_PREFIX_KEY);
			append_string(p, prefix, strlen(prefix)-1/*skip the ':'*/);
		}

		if ((module && func) || strlen(prefix) != 0)
			append_string_st(p, DP_JSON_MSG_QT_KEY);
		else
			append_string_st(p, DP_JSON_MSG_KEY);
	}

	l = vsnprintf(log_msg_buf, log_msg_buf_size, format, ap);
	if (l < 0) {
		stderr_dprint_tmp("error: vsnprintf() failed!\n");
		return -1;
	}
	if (l >= log_msg_buf_size) {
		stderr_dprint_tmp("warning: buffer too small, log message truncated\n");
		l = log_msg_buf_size;
	}

	l = log_escape_json_buf(log_msg_buf, l, p,
		buf->len - len - rlen - 1);
	if (l < 0) {
		stderr_dprint_tmp("error: failed to escape log message!\n",l);
		return -1;
	}

	p += l;
	len += l;

	if (json_fmt == LOG_JSON_SCHEMA_BASIC) {
		append_string_st(p, DP_JSON_MSG_END);
	} else {
		append_string_st(p, DP_JSON_CEE_PNAME_KEY);
		if (log_name)
			append_string(p, log_name, strlen(log_name));
		else
			append_string_st(p, DP_JSON_CEE_PNAME_VAL);

		append_string_st(p, DP_JSON_CEE_HOST_KEY);
		append_string(p, log_cee_hostname.s, log_cee_hostname.len);

		append_string_st(p, DP_JSON_MSG_END);
	}

	*p = '\0';

	return len;
}

static void stderr_dprint(int log_level, int facility, char *module, const char *func,
	char *format, va_list ap)
{
	char *time;
	int pid;
	char *prefix;
	int len;
	str buf = {log_json_buf, log_json_buf_size};

	if (stderr_log_format != LOG_FORMAT_PLAIN) {
		time = va_arg(ap, char *);
		pid = va_arg(ap, int);
		prefix = va_arg(ap, char *);
		if (module && func)
			va_arg(ap, char *);

		if ((len = log_print_json(&buf, stderr_log_format==LOG_FORMAT_JSON_CEE ?
			LOG_JSON_SCHEMA_CEE : LOG_JSON_SCHEMA_BASIC,
			time, pid, prefix, dp_log_level_str(log_level), module, func,
			format, ap)) < 0) {
			stderr_dprint_tmp("error: failed to print JSON log!\n");
			return;
		}

		fprintf(stderr, "%.*s\n", len, log_json_buf);
		fflush(stderr);
	} else {
		vfprintf(stderr,format,ap);
		fflush(stderr);
	}
}

static void syslog_dprint(int log_level, int facility, char *module, const char *func,
	char *format, va_list ap)
{
	int level;
	char *time;
	int pid;
	char *prefix;
	int len;
	str buf = {log_json_buf, log_json_buf_size};

	switch (log_level) {
	case L_ALERT:
		level = LOG_ALERT;
		break;
	case L_CRIT:
		level = LOG_CRIT;
		break;
	case L_ERR:
		level = LOG_ERR;
		break;
	case L_WARN:
		level = LOG_WARNING;
		break;
	case L_NOTICE:
		level = LOG_NOTICE;
		break;
	case L_INFO:
		level = LOG_INFO;
		break;
	case L_DBG:
	default:
		level = LOG_DEBUG;
	}

	if (syslog_log_format != LOG_FORMAT_PLAIN) {
		time = va_arg(ap, char *);
		pid = va_arg(ap, int);
		prefix = va_arg(ap, char *);
		if (module && func)
			va_arg(ap, char *);

		if ((len = log_print_json(&buf, syslog_log_format==LOG_FORMAT_JSON_CEE ?
			LOG_JSON_SCHEMA_CEE_PREFIX : LOG_JSON_SCHEMA_BASIC,
			time, pid, prefix, dp_log_level_str(log_level), module, func,
			format, ap)) < 0) {
			stderr_dprint_tmp("error: failed to print JSON log!\n");
			return;
		}

		syslog(level|facility, "%.*s\n", len, log_json_buf);
	} else {
		/* skip the time and pid arguments from va_list */
		va_arg(ap, char *);
	    va_arg(ap, int);

		vsyslog(level|facility, format, ap);
	}
}

static str evi_time_str = str_init("time");
static str evi_pid_str = str_init("pid");
static str evi_level_str = str_init("level");
static str evi_module_str = str_init("module");
static str evi_func_str = str_init("function");
static str evi_prefix_str = str_init("prefix");
static str evi_msg_str = str_init("message");

static void event_dprint(int log_level, int facility, char *module, const char *func,
	char *format, va_list ap)
{
	evi_params_p list = NULL;
	str s;
	int n;
	static char in_progress = 0;

	/* prevent reentry from the same process */
	if (in_progress)
		return;

	in_progress = 1;

	if (!evi_probe_event(evi_log_id)) {
		in_progress = 0;
		return;
	}

	if (!(list = evi_get_params())) {
		in_progress = 0;
		return;
	}

	init_str(&s, dp_time());
	if (evi_param_add_str(list, &evi_time_str, &s)) {
		stderr_dprint_tmp("error: unable to add event parameter\n");
		goto end_free;
	}
	n = dp_my_pid();
	if (evi_param_add_int(list, &evi_pid_str, &n)) {
		stderr_dprint_tmp("error: unable to add event parameter\n");
		goto end_free;
	}
	init_str(&s, dp_log_level_str(log_level));
	if (evi_param_add_str(list, &evi_level_str, &s)) {
		stderr_dprint_tmp("error: unable to add event parameter\n");
		goto end_free;
	}

	if (module && func) {
		init_str(&s, module);
		if (evi_param_add_str(list, &evi_module_str, &s)) {
			stderr_dprint_tmp("error: unable to add event parameter\n");
			goto end_free;
		}
		init_str(&s, func);
		if (evi_param_add_str(list, &evi_func_str, &s)) {
			stderr_dprint_tmp("error: unable to add event parameter\n");
			goto end_free;
		}
	}

	init_str(&s, log_prefix);
	if (s.len) {
		if (evi_param_add_str(list, &evi_prefix_str, &s)) {
			stderr_dprint_tmp("error: unable to add event parameter\n");
			goto end_free;
		}
	}

	s.len = vsnprintf(log_msg_buf, log_msg_buf_size, format, ap);
	if (s.len < 0) {
		stderr_dprint_tmp("error: vsnprintf() failed!\n");
		goto end_free;
	}
	if (s.len>=log_msg_buf_size) {
		stderr_dprint_tmp("warning: log message truncated\n");
		s.len = log_msg_buf_size;
	}

	/* try to strip \n from the end of the "message" param */
	if (log_msg_buf[s.len-1] == '\n') {
		log_msg_buf[s.len-1] = '\0';
		s.len--;
	}

	s.s = log_msg_buf;
	if (evi_param_add_str(list, &evi_msg_str, &s)) {
		stderr_dprint_tmp("error: unable to add event parameter\n");
		goto end_free;
	}

	if (evi_raise_event(evi_log_id, list)) {
		stderr_dprint_tmp("error: unable to raise '%.*s' event\n",
			evi_log_name.len, evi_log_name.s);
	}

	in_progress = 0;

	return;
end_free:
	evi_free_params(list);
	in_progress = 0;
}

/* generic consumer that registers to the log interface */
static void gen_consumer_pre_fmt_func(log_print_f gen_print_func, int log_level,
	int facility, char *module, const char *func,
	char *stderr_plain_fmt, char *syslog_plain_fmt, char *format, va_list ap)
{
	/* skip the time, pid, prefix and function arguments from va_list */
	va_arg(ap, char *);
    va_arg(ap, int);
    va_arg(ap, char *);
    if (module && func)
		va_arg(ap, char *);

	gen_print_func(log_level, facility, module, func, format, ap);
}

static void stderr_pre_fmt_func(log_print_f gen_print_func, int log_level,
	int facility, char *module, const char *func,
	char *stderr_plain_fmt, char *syslog_plain_fmt, char *format, va_list ap)
{
	char *fmt = stderr_log_format == LOG_FORMAT_PLAIN ? stderr_plain_fmt : format;

	gen_print_func(log_level, facility, module, func, fmt, ap);
}

static void syslog_pre_fmt_func(log_print_f gen_print_func, int log_level,
	int facility, char *module, const char *func,
	char *stderr_plain_fmt, char *syslog_plain_fmt, char *format, va_list ap)
{
	char *fmt = syslog_log_format == LOG_FORMAT_PLAIN ? syslog_plain_fmt : format;

	gen_print_func(log_level, facility, module, func, fmt, ap);
}

void dprint(int log_level, int facility, char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap, ap_copy;
	int i;

	va_start(ap, format);

	for (i=0; i<log_consumers_no; i++)
		if (!log_consumers[i].muted && (!log_consumers[i].level_filter ||
			log_consumers[i].level_filter >= log_level)) {
			va_copy(ap_copy, ap);
			log_consumers[i].pre_fmt_print_func(log_consumers[i].gen_print_func,
				log_level, facility, module, func, stderr_fmt, syslog_fmt,
				format, ap_copy);
			va_end(ap_copy);
		}

	va_end(ap);
}

int register_log_consumer(char *name, log_print_f print_func,
	int level_filter, int muted)
{
	if (log_consumers_no == MAX_LOG_CONS_NO) {
		LM_ERR("Maximum number of logging consumers already registered\n");
		return -1;
	}

	init_str(&log_consumers[log_consumers_no].name, name);
	log_consumers[log_consumers_no].gen_print_func = print_func;
	log_consumers[log_consumers_no].pre_fmt_print_func = gen_consumer_pre_fmt_func;
	log_consumers[log_consumers_no].level_filter = level_filter;
	log_consumers[log_consumers_no].muted = muted;

	log_consumers_no++;

	return 0;
}

int init_log_json_buf(int realloc)
{
	if (realloc && log_json_buf) {
		log_json_buf = pkg_realloc(log_json_buf, log_json_buf_size+1);
		if (!log_json_buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	} else if (!log_json_buf) {
		log_json_buf = pkg_malloc(log_json_buf_size+1);
		if (!log_json_buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	}

	return 0;
}

int init_log_msg_buf(int realloc)
{
	if (realloc && log_msg_buf) {
		log_msg_buf = pkg_realloc(log_msg_buf, log_msg_buf_size+1);
		if (!log_msg_buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	} else if (!log_msg_buf) {
		log_msg_buf = pkg_malloc(log_msg_buf_size+1);
		if (!log_msg_buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	}

	return 0;
}

/* replaces the default consumer table with a shm allocated one */
int init_log_cons_shm_table(void)
{
	struct log_consumer_t *cons;

	cons = shm_malloc(MAX_LOG_CONS_NO * sizeof(struct log_consumer_t));
	if (!cons) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(cons, 0, MAX_LOG_CONS_NO * sizeof(struct log_consumer_t));

	cons[0] = log_consumers[0];
	cons[1] = log_consumers[1];

	log_consumers = cons;

	return 0;
}

int init_log_event_cons(void)
{
	evi_log_id = evi_publish_event(evi_log_name);
	if (evi_log_id == EVI_ERROR) {
		LM_ERR("cannot register '%.*s' event\n",
			evi_log_name.len, evi_log_name.s);
		return -1;
	}

	log_msg_buf = pkg_malloc(log_msg_buf_size+1);
	if (!log_msg_buf) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	if (register_log_consumer(EVENT_CONSUMER_NAME, event_dprint,
		log_event_level_filter, 1) < 0) {
		LM_ERR("Failed to register 'event' log consumer\n");
		return -1;
	}

	return 0;
}

static struct log_consumer_t *get_log_consumer_by_name(str *name)
{
	int i;

	for (i=0; i<log_consumers_no; i++)
		if (str_match(&log_consumers[i].name, name))
			return log_consumers+i;

	return NULL;
}

int set_log_consumer_level_filter(str *name, int level)
{
	struct log_consumer_t *cons;

	cons = get_log_consumer_by_name(name);
	if (!cons) {
		LM_ERR("Unknown consumer: %.*s\n", name->len, name->s);
		return -1;
	}

	cons->level_filter = level;

	return 0;
}

int get_log_consumer_level_filter(str *name, int *level_filter)
{
	struct log_consumer_t *cons;

	cons = get_log_consumer_by_name(name);
	if (!cons) {
		LM_ERR("Unknown consumer: %.*s\n", name->len, name->s);
		return -1;
	}

	*level_filter = cons->level_filter;

	return 0;
}

int set_log_consumer_mute_state(str *name, int state)
{
	struct log_consumer_t *cons;

	cons = get_log_consumer_by_name(name);
	if (!cons) {
		LM_ERR("Unknown consumer: %.*s\n", name->len, name->s);
		return -1;
	}

	cons->muted = state;

	return 0;
}

int get_log_consumer_mute_state(str *name, int *state)
{
	struct log_consumer_t *cons;

	cons = get_log_consumer_by_name(name);
	if (!cons) {
		LM_ERR("Unknown consumer: %.*s\n", name->len, name->s);
		return -1;
	}

	*state = cons->muted;

	return 0;
}

int set_log_event_cons_cfg_state(void)
{
	if (set_log_consumer_mute_state(&str_init(EVENT_CONSUMER_NAME),
		!log_event_enabled) < 0) {
		LM_ERR("Failed to set mute state for event consumer\n");
		return -1;
	}

	return 0;
}

void distroy_log_event_cons(void)
{
	set_log_consumer_mute_state(&str_init(EVENT_CONSUMER_NAME), 1);
}

int init_log_level(void)
{
	log_level = &pt[process_no].log_level;
	*log_level = log_level_holder;
	default_log_level = &pt[process_no].default_log_level;
	*default_log_level = log_level_holder;

	return 0;
}

/* call before pt is freed */
void cleanup_log_level(void)
{
	static int my_log_level;

	my_log_level = *log_level;
	log_level = &my_log_level;
}


void reset_proc_log_level(void)
{
	*log_level = *default_log_level;
}

/*
 * set the (default) log level of a given process
 *
 * Note: the index param is not validated!
 */
void __set_proc_log_level(int proc_idx, int level)
{
	pt[proc_idx].log_level = level;
}

void __set_proc_default_log_level(int proc_idx, int level)
{
	pt[proc_idx].default_log_level = level;
}

/* set the current and default log levels for all OpenSIPS processes */
void set_global_log_level(int level)
{
	int i;

	for (i = 0; i < counted_max_processes; i++) {
		__set_proc_default_log_level(i, level);
		__set_proc_log_level(i, level);
	}
}

/* set the log level of the current process */
void set_proc_log_level(int level)
{
	__set_proc_log_level(process_no, level);
}


