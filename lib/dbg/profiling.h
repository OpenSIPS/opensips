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

static inline int _ProfilerStart(pid_t pid, const char *proc_desc)
{
	char fname[50];
	int rval;

	LM_NOTICE("START profiling in process %s (%d)\n",
	          proc_desc, pid);

	if (pid == 0) {
		rval = ProfilerStart("gperf-attendant.prof") == 0 ? -1 : 0;
		return rval;
	}

	if (!strcmp(proc_desc, "UDP receiver"))
		sprintf(fname, "gperf-udp-%d.prof", getpid());
	else if (!strcmp(proc_desc, "Timer handler"))
		sprintf(fname, "gperf-timer-%d.prof", getpid());
	else
		sprintf(fname, "gperf-%d.prof", getpid());

	return ProfilerStart(fname) == 0 ? -1 : 0;
}

static int _ProfilerStart_child(const struct internal_fork_params *ifpp)
{
	if (_ProfilerStart(pt[process_no].pid, ifpp->proc_desc) != 0) {
		LM_CRIT("failed to start profiler for process %d", process_no);
		return -1;
	}
	return 0;
}

static inline void _ProfilerStop(void)
{
	ProfilerStop();

	LM_NOTICE("STOP profiling in process %s (%d)\n",
	          pt ? pt[process_no].desc : "<none>",
	          pt ? pt[process_no].pid : -1);
}
#else
static inline int _ProfilerStart(pid_t pid, const char *proc_desc) { return 0; }
static inline int _ProfilerStart_child(const struct internal_fork_params *ifpp) { return 0; }
	#define ProfilerStart(...)
	#define ProfilerStop(...)
	#define _ProfilerStop(...)
#endif

#endif /* __OSS_PROFILING_H__ */
