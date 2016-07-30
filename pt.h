/*
 * Process Table
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
 *
 * History:
 * --------
 *  2003-04-15  added tcp_disable support (andrei)
 */


#ifndef _PT_H
#define _PT_H

#include <sys/types.h>
#include <unistd.h>

struct stat_var_;

#define MAX_PT_DESC	128

struct process_table {
	int pid;
	int unix_sock; /* unix socket on which tcp main listens */
	int idx;       /* tcp child index, -1 for other processes */
	char desc[MAX_PT_DESC];

	int default_log_level; /* used when resetting the log level */
	int log_level;         /* logging level of this process */

	struct stat_var_ *load;
};

typedef void(*forked_proc_func)(int i);

extern struct process_table *pt;
extern int process_no;
extern unsigned int counted_processes;

int   init_multi_proc_support();
void  set_proc_attrs( char *fmt, ...);
pid_t internal_fork(char *proc_desc);
int count_init_children(int flags);

/* @return: -1 or the index of the given process */
int id_of_pid(pid_t pid);

/* return processes pid */
inline static int my_pid(void)
{
	return pt ? pt[process_no].pid : getpid();
}


#endif
