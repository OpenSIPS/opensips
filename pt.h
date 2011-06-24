/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2003-04-15  added tcp_disable support (andrei)
 */


#ifndef _PT_H
#define _PT_H

#include <sys/types.h>
#include <unistd.h>

#include "globals.h"
#include "timer.h"
#include "socket_info.h"
#include "atomic.h"

#define MAX_PT_DESC	128

struct process_table {
	int pid;
#ifdef USE_TCP
	int unix_sock; /* unix socket on which tcp main listens */
	int idx; /* tcp child index, -1 for other processes */
#endif
	char desc[MAX_PT_DESC];
	atomic_t *load;
};

typedef void(*forked_proc_func)(int i);

extern struct process_table *pt;
extern int process_no;
extern unsigned int counted_processes;

int   init_multi_proc_support();
void  set_proc_attrs( char *fmt, ...);
pid_t internal_fork(char *proc_desc);
int count_init_children(void);

/* return processes pid */
inline static int my_pid(void)
{
	return pt ? pt[process_no].pid : getpid();
}


#endif
