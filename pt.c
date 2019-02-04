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
#include "ipc.h"


/* array with children pids, 0= main proc,
 * alloc'ed in shared mem if possible */
struct process_table *pt=0;

/* variable keeping the number of created processes READONLY!! */
unsigned int *counted_processes_p = NULL;

unsigned int counted_max_processes = 0;



int init_multi_proc_support(void)
{
	unsigned int proc_no;
	unsigned int proc_extra_no;
	unsigned int extra;
	unsigned int i;

	/* allocate the number of proc variable in shm  */
	counted_processes_p = shm_malloc(sizeof(unsigned int));
	if (counted_processes_p==NULL){
		LM_ERR("out of memory\n");
		return -1;
	}

	proc_no = 0;
	proc_extra_no = 0;

	/* UDP based listeners */
	proc_no += udp_count_processes( &extra );
	proc_extra_no += extra;
	/* TCP based listeners */
	proc_no += tcp_count_processes( &extra );
	proc_extra_no += extra;
	/* attendent */
	proc_no++;

	/* info packet UDP receivers */

	/* timer processes */
	proc_no += 3 /* timer keeper + timer trigger + dedicated */;
	proc_extra_no += 0; /* the dedicated proc may turn into multiple */;

	/* count the processes requested by modules */
	proc_no += count_module_procs(0);

	/* for the beginning, count only the processes we are starting with */
	*counted_processes_p = proc_no;

	counted_max_processes = proc_no + proc_extra_no;


	/* allocate the PID table to accomodate the maximum possible number of
	 * process we may have during runtime (covering extra procs created 
	 * due auto-scaling) */
	pt = shm_malloc(sizeof(struct process_table)*counted_max_processes);
	if (pt==0){
		LM_ERR("out of memory\n");
		return -1;
	}
	memset(pt, 0, sizeof(struct process_table)*counted_max_processes);

	for( i=0 ; i<counted_max_processes ; i++ ) {
		pt[i].unix_sock = -1;
		pt[i].idx = -1;
		pt[i].pid = -1;
		pt[i].ipc_pipe[0] = pt[i].ipc_pipe[1] = -1;
	}


	/* create the IPC pipes for all possible procs */
	if (create_ipc_pipes( counted_max_processes )<0) {
		LM_ERR("failed to create IPC pipes, aborting\n");
		return -1;
	}

	/* set the pid for the starter process */
	set_proc_attrs("starter");

	/* register the stats for the global load */
	if ( register_stat2( "load", "load", (stat_var**)pt_get_rt_load,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load1m", (stat_var**)pt_get_1m_load,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load10m", (stat_var**)pt_get_10m_load,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	/* register the stats for the extended global load */
	if ( register_stat2( "load", "load-all", (stat_var**)pt_get_rt_loadall,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load1m-all", (stat_var**)pt_get_1m_loadall,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

	if ( register_stat2( "load", "load10m-all", (stat_var**)pt_get_10m_loadall,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add RT global load stat\n");
		return -1;
	}

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


static int register_process_stats(int process_no)
{
	if (register_process_load_stats(process_no) != 0) {
		LM_ERR("failed to create load stats\n");
		return -1;
	}

	return 0;
}


/* This function is to be called only by the main process!
 * */
pid_t internal_fork(char *proc_desc, unsigned int flags,
												enum process_type type)
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

	/* check the IPC pipe */
	if ( (flags & OSS_FORK_NO_IPC) ) {
		/* close the listening end */
		close(pt[process_counter].ipc_pipe[0]);
		/* advertise no IPC to the rest of the procs */
		pt[process_counter].ipc_pipe[0] = -1;
		pt[process_counter].ipc_pipe[1] = -1;
		/* NOTE: the IPC fds will remain open in the other processes,
		 * but they will not be known */
	}

	if (register_process_stats(process_counter)<0) {
		LM_ERR("failed to create stats for future proc %d\n", process_no);
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
		pt[process_no].flags = flags;
		pt[process_no].type = type;
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


/* counts the number of processes created by OpenSIPS at startup. processes
 * that also do child_init() (the per-process module init)
 *
 * used for proper status return code
 */
int count_init_child_processes(void)
{
	int ret=0;

	/* listening children to be create at startup */
	ret += udp_count_processes(NULL);
	ret += tcp_count_processes(NULL);

	/* attendent */
	ret++;

	/* dedicated timer */
	ret++;

	/* count number of module procs going to be initialised */
	ret += count_module_procs(PROC_FLAG_INITCHILD);

	LM_DBG("%d children are going to be inited\n",ret);
	return ret;
}


struct process_group {
	enum process_type type;
	struct socket_info *si_filter;
	fork_new_process_f *fork_func;
	unsigned int max_procs;
	unsigned int min_procs;
	struct process_group *next;
};

struct process_group *pg_head = NULL;

int create_process_group(enum process_type type,
						struct socket_info *si_filter,
						unsigned int min_procs, unsigned int max_procs,
						fork_new_process_f *f)
{
	struct process_group *pg, *it;

	pg = (struct process_group*)shm_malloc( sizeof(struct process_group) );
	if (pg==NULL) {
		LM_ERR("failed to allocate memory for a new process group\n");
		return -1;
	}

	LM_DBG("registering group of processes type %d, socket filter %p, "
		"process range [%d,%d]\n", type, si_filter, min_procs, max_procs );

	pg->type = type;
	pg->si_filter = si_filter;
	pg->max_procs = max_procs;
	pg->min_procs = min_procs;
	pg->fork_func = f;
	pg->next = NULL;

	/* add at the end of list, to avoid changing the head of the list due
	 * forking */
	for( it=pg_head ; it && it->next ; it=it->next);
	if (it==NULL)
		pg_head = pg;
	else
		it->next = pg;

	return 0;
}
