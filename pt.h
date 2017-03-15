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
	/* the UNIX pid of this process */
	int pid;
	/* name/description of the process (null terminated) */
	char desc[MAX_PT_DESC];

	/* pipe used by the process to receive designated jobs (used by IPC)
	 * [1] for writting into by other process,
	 * [0] to listen on by this process */
	int ipc_pipe[2];

	/* unix socket on which TCP MAIN listens */
	int unix_sock;
	/* tcp child index, -1 for other processes */
	int idx;

	/* logging level of this process */
	int log_level;
	/* used when resetting the log level */
	int default_log_level;

	/* the load statistic of this process */
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
