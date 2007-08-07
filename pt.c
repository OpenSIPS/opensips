/*
 * $Id$
 *
 * Copyright (C) 2007 Voice Sistem SRL
 * 
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
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
 * 2007-06-07 - created to contain process handling functions (bogdan)
 */





#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "mem/shm_mem.h"
#include "socket_info.h"
#include "sr_module.h"
#include "dprint.h"
#include "pt.h"


/* array with children pids, 0= main proc,
 * alloc'ed in shared mem if possible */
struct process_table *pt=0;

/* variable keeping the number of created processes READONLY!! */
unsigned int counted_processes = 0;


int init_multi_proc_support()
{
	unsigned short proc_no;
	struct socket_info* si;

	proc_no = 0;

	/* count how many processes we will have in core */
	if (dont_fork) {
		/* only one UDP listener */
		proc_no = 1;
	} else {
		#ifdef USE_SCTP
		/* SCTP listeners */
		for (si=sctp_listen; si; si=si->next)
			proc_no+=children_no;
		#endif
		/* UDP listeners */
		for (si=udp_listen; si; si=si->next)
			proc_no+=children_no;
		#ifdef USE_TCP
		proc_no += ((!tcp_disable)?( 1/* tcp main */ + tcp_children_no ):0);
		#endif
		/* attendent */
		proc_no++;
	}
	/* timer process */
	proc_no++;

	/* count the processes requested by modules */
	proc_no += count_module_procs();

	/* allocate the PID table */
	pt = shm_malloc(sizeof(struct process_table)*proc_no);
	if (pt==0){
		LM_ERR("out of memory\n");
		return -1;
	}
	memset(pt, 0, sizeof(struct process_table)*proc_no);

	counted_processes = proc_no;

	return 0;
}


void set_proc_attrs( char *fmt, ...)
{
	va_list ap;

	/* description */
	va_start(ap, fmt);
	vsnprintf( pt[process_no].desc, MAX_PT_DESC, fmt, ap);
	va_end(ap);

	/* pid */
	pt[process_no].pid=getpid();

	/* disable all TCP attrs by default */
	#ifdef USE_TCP
	if(!tcp_disable){
		pt[process_no].unix_sock=-1;
		pt[process_no].idx=-1; /* this is not a "tcp" process*/
		unix_tcp_sock=-1;
	}
	#endif

}



/* This function is to be called only by the main process!
 * */
pid_t openser_fork(char *proc_desc)
{
	#define CHILD_COUNTER_STOP  656565656
	static int process_counter = 1;
	pid_t pid;
	unsigned int seed;

	if (process_counter==CHILD_COUNTER_STOP) {
		LM_CRIT("buggy call from non-main process!!!");
		return -1;
	}

	seed = rand();

	LM_DBG("forking new process \"%s\"\n",proc_desc);

	if ( (pid=fork())<0 ){
		LM_CRIT("cannot fork \"%s\" process\n",proc_desc);
		return -1;
	}

	if (pid==0){
		/* child process */
		is_main = 0; /* should already be 0, but to be sure */
		process_no = process_counter;
		process_counter = CHILD_COUNTER_STOP;
		/* each children need a unique seed */
		seed_child(seed);
		/* set attributes */
		set_proc_attrs(proc_desc);
		return 0;
	}else{
		/* parent process */
		pt[process_no].pid = pid;
		process_counter++;
		return pid;
	}
}
