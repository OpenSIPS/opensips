/*
 * Copyright (C) 2023 OpenSIPS Solutions
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

#ifndef __OSS_PROFILING_H__
#define __OSS_PROFILING_H__

#include <stdio.h>
#include <string.h>

#include "../../pt.h"
#include "../../dprint.h"

#ifdef PROFILING
#include <gperftools/profiler.h>
static inline void _ProfilerStart(pid_t pid, const char *proc_desc)
{
	char fname[50];

	LM_NOTICE("START profiling in process %s (%d)\n",
	          proc_desc, pid);

	if (pid == 0) {
		ProfilerStart("gperf-attendant.prof");
		return;
	}

	if (!strcmp(proc_desc, "UDP receiver"))
		sprintf(fname, "gperf-udp-%d.prof", getpid());
	else if (!strcmp(proc_desc, "Timer handler"))
		sprintf(fname, "gperf-timer-%d.prof", getpid());
	else
		sprintf(fname, "gperf-%d.prof", getpid());

	ProfilerStart(fname);
}

static inline void _ProfilerStop(void)
{
	ProfilerStop();

	LM_NOTICE("STOP profiling in process %s (%d)\n",
	          pt[process_no].desc, pt[process_no].pid);
}
#else
	#define ProfilerStart(...)
	#define _ProfilerStart(...)
	#define ProfilerStop(...)
	#define _ProfilerStop(...)
#endif

#endif /* __OSS_PROFILING_H__ */
