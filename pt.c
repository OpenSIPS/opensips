/*
 * Copyright (C) 2007 Voice Sistem SRL
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
 * 2007-06-07 - created to contain process handling functions (bogdan)
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "mem/shm_mem.h"
#include "net/net_tcp.h"
#include "net/net_udp.h"
#include "socket_info.h"
#include "sr_module.h"
#include "dprint.h"
#include "pt.h"
#include "bin_interface.h"


/* array with children pids, 0= main proc,
 * alloc'ed in shared mem if possible */
struct process_table *pt=0;

/* variable keeping the number of created processes READONLY!! */
unsigned int counted_processes = 0;


int init_multi_proc_support(void)
{
	unsigned short proc_no;
	unsigned int i;

	proc_no = 0;

	/* UDP based listeners */
	proc_no += udp_count_processes();
	/* TCP based listeners */
	proc_no += tcp_count_processes();
	/* attendent */
	proc_no++;

	/* info packet UDP receivers */

	/* timer processes */
	proc_no += 3 /* timer keeper + timer trigger + dedicated */;

	/* count the processes requested by modules */
	proc_no += count_module_procs();

	/* allocate the PID table */
	pt = shm_malloc(sizeof(struct process_table)*proc_no);
	if (pt==0){
		LM_ERR("out of memory\n");
		return -1;
	}
	memset(pt, 0, sizeof(struct process_table)*proc_no);

	for( i=0 ; i<proc_no ; i++ ) {
		pt[i].unix_sock = -1;
		pt[i].idx = -1;
		pt[i].pid = -1;
		pt[i].ipc_pipe[0] = pt[i].ipc_pipe[1] = -1;
	}

	/* set the pid for the starter process */
	set_proc_attrs("starter");

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
}



/* This function is to be called only by the main process!
 * */
pid_t internal_fork(char *proc_desc)
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

	/* set TCP communication */
	if (tcp_pre_connect_proc_to_tcp_main(process_counter)<0){
		LM_ERR("failed to connect future proc %d to TCP main\n",
			process_no);
		return -1;
	}

	/* create the IPC pipe */
	if (pipe(pt[process_counter].ipc_pipe)<0) {
		LM_ERR("failed to create IPC pipe for process %d, err %d/%s\n",
			process_counter, errno, strerror(errno));
		return -1;
	}

	pt[process_counter].pid = 0;

	if ( (pid=fork())<0 ){
		LM_CRIT("cannot fork \"%s\" process (%d: %s)\n",proc_desc,
				errno, strerror(errno));
		return -1;
	}

	if (pid==0){
		/* child process */
		is_main = 0; /* a child is not main process */
		/* set uid and pid */
		process_no = process_counter;
		pt[process_no].pid = getpid();
		process_counter = CHILD_COUNTER_STOP;
		/* each children need a unique seed */
		seed_child(seed);
		init_log_level();

		/* set attributes */
		set_proc_attrs(proc_desc);
		tcp_connect_proc_to_tcp_main( process_no, 1);
		return 0;
	}else{
		/* parent process */
		/* Do not set PID for child in the main process. Let the child do
		 * that as this will act as a marker to tell us that the init 
		 * sequance of the child proc was completed.
		 * pt[process_counter].pid = pid; */
		tcp_connect_proc_to_tcp_main( process_counter, 0);
		process_counter++;
		return pid;
	}
}

/* returns the number of child processes
 * filter all processes that have set the flags set
 *
 * used for proper status return code
 */
int count_init_children(int flags)
{
	int ret=0,i;
	struct sr_module *m;

	/* listening children */
	ret += udp_count_processes();
	ret += tcp_count_processes();

	/* attendent */
	ret++;

	/* dedicated timer */
	ret++;

	/* count number of module procs going to be initialised */
	for (m=modules;m;m=m->next) {
		if (m->exports->procs==NULL)
			continue;
		for (i=0;m->exports->procs[i].name;i++) {
			if (!m->exports->procs[i].no || !m->exports->procs[i].function)
				continue;

			if (!flags || (m->exports->procs[i].flags & flags))
				ret+=m->exports->procs[i].no;
		}
	}

	LM_DBG("%d children are going to be inited\n",ret);
	return ret;
}

int id_of_pid(pid_t pid)
{
	int i;

	for (i = 0; i < counted_processes; i++)
		if (pt[i].pid == pid)
			return i;

	return -1;
}
