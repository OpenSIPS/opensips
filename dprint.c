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
#include "globals.h"
#include "pt.h"

#include <stdarg.h>
#include <stdio.h>
#include <strings.h>

static int log_level_holder = L_NOTICE;

/* current logging level for this process */
int *log_level = &log_level_holder;

/* used when resetting the logging level of this process */
static int *default_log_level;

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


void dprint(char * format, ...)
{
	va_list ap;

	//fprintf(stderr, "%2d(%d) ", process_no, my_pid());
	va_start(ap, format);
	vfprintf(stderr,format,ap);
	fflush(stderr);
	va_end(ap);
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


