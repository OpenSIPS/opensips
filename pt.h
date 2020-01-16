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

#include "pt_load.h"

#define MAX_PT_DESC	128

struct process_table {
	/* the UNIX pid of this process */
	int pid;
	/* name/description of the process (null terminated) */
	char desc[MAX_PT_DESC];

	/* various flags describing properties of this process */
	unsigned int flags;

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
	struct proc_load load;
};

typedef void(*forked_proc_func)(int i);

extern struct process_table *pt;
extern int process_no;
extern unsigned int counted_processes;

int count_child_processes(void);
int   init_multi_proc_support();
void  set_proc_attrs( char *fmt, ...);
int   count_init_children(int flags);

#define OSS_FORK_NO_IPC        (1<<0)
#define OSS_FORK_NO_LOAD       (1<<1)
#define OSS_FORK_IS_EXTRA      (1<<2)
#define OSS_TAKING_A_DUMP      (1<<3) /* this process is writing a corefile */

pid_t internal_fork(char *proc_desc, unsigned int flags);

/* return processes pid */
inline static int my_pid(void)
{
	return pt ? pt[process_no].pid : getpid();
}

/* Get the process internal ID based on its PID 
 * @return: -1 or the index of the given process */
inline static int get_process_ID_by_PID(pid_t pid)
{
	int i;

	for( i=0 ; i<counted_processes ; i++ )
		if (pt[i].pid==pid)
			return i;

	return -1;
}

#endif
