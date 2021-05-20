/*
 * Copyright (C) 2007 Voice Sistem SRL
 * Copyright (C) 2008-2019 OpenSIPS Project
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

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "mem/shm_mem.h"
#include "net/net_tcp.h"
#include "net/net_udp.h"
#include "db/db_insertq.h"
#include "sr_module.h"
#include "dprint.h"
#include "pt.h"
#include "bin_interface.h"
#include "core_stats.h"


/* array with children pids, 0= main proc,
 * alloc'ed in shared mem if possible */
struct process_table *pt = NULL;

/* The maximum number of processes that will ever exist in OpenSIPS. This is
 * actually the size of the process table
 * This is READONLY!! */
unsigned int counted_max_processes = 0;

/* flag per process to control the termination stages */
int _termination_in_progress = 0;


static unsigned long count_running_processes(void *x)
{
	int i,cnt=0;

	if (pt)
		for ( i=0 ; i<counted_max_processes ; i++ )
			if (is_process_running(i))
				cnt++;

	return cnt;
}


int init_multi_proc_support(void)
{
	int i;
	/* at this point we know exactly the possible number of processes, since
	 * all the other modules already adjusted their extra numbers */
	counted_max_processes = count_child_processes();

#ifdef UNIT_TESTS
#include "mem/test/test_malloc.h"
	counted_max_processes += TEST_MALLOC_PROCS - 1;
#endif

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
		/* reset fds to prevent bogus ops */
		pt[i].unix_sock = -1;
		pt[i].pid = -1;
		pt[i].ipc_pipe[0] = pt[i].ipc_pipe[1] = -1;
		pt[i].ipc_sync_pipe[0] = pt[i].ipc_sync_pipe[1] = -1;
	}

	/* create the load-related stats (initially marked as hidden */
	/* until the proc starts) */
	if (register_processes_load_stats( counted_max_processes ) != 0) {
		LM_ERR("failed to create load stats\n");
		return -1;
	}

	/* create the IPC pipes for all possible procs */
	if (create_ipc_pipes( counted_max_processes )<0) {
		LM_ERR("failed to create IPC pipes, aborting\n");
		return -1;
	}

	/* create the IPC pipes for all possible procs */
	if (tcp_create_comm_proc_socks( counted_max_processes )<0) {
		LM_ERR("failed to create TCP layer communication, aborting\n");
		return -1;
	}

	/* create the pkg_mem stats */
	#ifdef PKG_MALLOC
	if (init_pkg_stats(counted_max_processes)!=0) {
		LM_ERR("failed to init stats for pkg\n");
		return -1;
	}
	#endif

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

	if ( register_stat2( "load", "processes_number",
	(stat_var**)count_running_processes,
	STAT_IS_FUNC, NULL, 0) != 0) {
		LM_ERR("failed to add processes_number stat\n");
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

	/* for sure the process is running */
	pt[process_no].flags |= OSS_PROC_IS_RUNNING;
}


/* Resets all the values in the process table for a given id (a slot) so that
 * it can be reused later 
 * WARNING: this should be called only by main process and when it is 100% 
 *  that the process mapped on this slot is not running anymore */
void reset_process_slot( int p_id )
{
	if (is_main==0) {
		LM_BUG("buggy call from non-main process!!!");
		return;
	}

	/* we cannot simply do a memset here, as we need to preserve the holders
	 * with the inter-process communication fds */
	pt[p_id].pid = -1;
	pt[p_id].type = TYPE_NONE;
	pt[p_id].pg_filter = NULL;
	pt[p_id].desc[0] = 0;
	pt[p_id].flags = 0;

	pt[p_id].ipc_pipe[0] = pt[p_id].ipc_pipe[1] = -1;
	pt[p_id].ipc_sync_pipe[0] = pt[p_id].ipc_sync_pipe[1] = -1;
	pt[p_id].unix_sock = -1;

	pt[p_id].log_level = pt[p_id].default_log_level = 0; /*not really needed*/

	/* purge all load-related data */
	memset( &pt[p_id].load, 0, sizeof(struct proc_load_info));
	/* hide the load stats */
	pt[p_id].load_rt->flags |= STAT_HIDDEN;
	pt[p_id].load_1m->flags |= STAT_HIDDEN;
	pt[p_id].load_10m->flags |= STAT_HIDDEN;
	#ifdef PKG_MALLOC
	pt[p_id].pkg_total->flags |= STAT_HIDDEN;
	pt[p_id].pkg_used->flags |= STAT_HIDDEN;
	pt[p_id].pkg_rused->flags |= STAT_HIDDEN;
	pt[p_id].pkg_mused->flags |= STAT_HIDDEN;
	pt[p_id].pkg_free->flags |= STAT_HIDDEN;
	pt[p_id].pkg_frags->flags |= STAT_HIDDEN;
	#endif
}


/* This function is to be called only by the main process!
 * Returns, on success, the ID (non zero) in the process table of the
 * newly forked procees.
 * */
int internal_fork(char *proc_desc, unsigned int flags,
												enum process_type type)
{
	int new_idx;
	pid_t pid;
	unsigned int seed;

	if (is_main==0) {
		LM_BUG("buggy call from non-main process!!!");
		return -1;
	}

	new_idx = 1; /* start from 1 as 0 (attendent) is always running */
	for( ; new_idx<counted_max_processes ; new_idx++)
		if ( (pt[new_idx].flags&OSS_PROC_IS_RUNNING)==0 ) break;
	if (new_idx==counted_max_processes) {
		LM_BUG("no free process slot found while trying to fork again\n");
		return -1;
	}

	seed = rand();

	LM_DBG("forking new process \"%s\" on slot %d\n", proc_desc, new_idx);

	/* set TCP communication */
	if (tcp_activate_comm_proc_socks(new_idx)<0){
		LM_ERR("failed to connect future proc %d to TCP main\n",
			process_no);
		return -1;
	}

	/* set the IPC pipes */
	if ( (flags & OSS_PROC_NO_IPC) ) {
		/* advertise no IPC to the rest of the procs */
		pt[new_idx].ipc_pipe[0] = -1;
		pt[new_idx].ipc_pipe[1] = -1;
		pt[new_idx].ipc_sync_pipe[0] = -1;
		pt[new_idx].ipc_sync_pipe[1] = -1;
		/* NOTE: the IPC fds will remain open in the other processes,
		 * but they will not be known */
	} else {
		/* activate the IPC pipes */
		pt[new_idx].ipc_pipe[0]=pt[new_idx].ipc_pipe_holder[0];
		pt[new_idx].ipc_pipe[1]=pt[new_idx].ipc_pipe_holder[1];
		pt[new_idx].ipc_sync_pipe[0]=pt[new_idx].ipc_sync_pipe_holder[0];
		pt[new_idx].ipc_sync_pipe[1]=pt[new_idx].ipc_sync_pipe_holder[1];
	}

	pt[new_idx].pid = 0;
	pt[new_idx].flags = OSS_PROC_IS_RUNNING;

	if ( (pid=fork())<0 ){
		LM_CRIT("cannot fork \"%s\" process (%d: %s)\n",proc_desc,
				errno, strerror(errno));
		reset_process_slot( new_idx );
		return -1;
	}

	if (pid==0){
		/* child process */
		is_main = 0; /* a child is not main process */
		/* set uid and pid */
		process_no = new_idx;
		pt[process_no].pid = getpid();
		pt[process_no].flags |= flags;
		pt[process_no].type = type;
		/* activate its load & pkg statistics */
		pt[process_no].load_rt->flags &= (~STAT_HIDDEN);
		pt[process_no].load_1m->flags &= (~STAT_HIDDEN);
		pt[process_no].load_10m->flags &= (~STAT_HIDDEN);
		#ifdef PKG_MALLOC
		pt[process_no].pkg_total->flags &= (~STAT_HIDDEN);
		pt[process_no].pkg_used->flags &= (~STAT_HIDDEN);
		pt[process_no].pkg_rused->flags &= (~STAT_HIDDEN);
		pt[process_no].pkg_mused->flags &= (~STAT_HIDDEN);
		pt[process_no].pkg_free->flags &= (~STAT_HIDDEN);
		pt[process_no].pkg_frags->flags &= (~STAT_HIDDEN);
		#endif
		/* each children need a unique seed */
		seed_child(seed);
		init_log_level();

		/* set attributes */
		set_proc_attrs(proc_desc);
		tcp_connect_proc_to_tcp_main( process_no, 1);

		/* free the script if not needed */
		if (!(flags&OSS_PROC_NEEDS_SCRIPT) && sroutes) {
			free_route_lists(sroutes);
			sroutes = NULL;
		}
		return 0;
	}else{
		/* parent process */
		/* Do not set PID for child in the main process. Let the child do
		 * that as this will act as a marker to tell us that the init 
		 * sequance of the child proc was completed.
		 * pt[new_idx].pid = pid; */
		tcp_connect_proc_to_tcp_main( new_idx, 0);
		return new_idx;
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
	ret += timer_count_processes(NULL) - 2/*for keeper & trigger*/;

	/* attendent */
	ret++;

	/* count number of module procs going to be initialised */
	ret += count_module_procs(PROC_FLAG_INITCHILD);

	LM_DBG("%d children are going to be inited\n",ret);
	return ret;
}

/* counts the number of processes known by OpenSIPS at startup.
 * Note that the number of processes might change during init, if one of the
 * module decides that it will no longer use a process (ex; rtpproxy timeout
 * process)
 */
int count_child_processes(void)
{
	unsigned int proc_no;
	unsigned int proc_extra_no;
	unsigned int extra;

	proc_no = 0;
	proc_extra_no = 0;

	/* UDP based listeners */
	proc_no += udp_count_processes( &extra );
	proc_extra_no += extra;

	/* TCP based listeners */
	proc_no += tcp_count_processes( &extra );
	proc_extra_no += extra;

	/* Timer related processes */
	proc_no += timer_count_processes( &extra );
	proc_extra_no += extra;

	/* attendent */
	proc_no++;

	/* count the processes requested by modules */
	proc_no += count_module_procs(0);

	return proc_no + proc_extra_no;
}


void dynamic_process_final_exit(void)
{
	/* prevent any more IPC */
	pt[process_no].ipc_pipe[0] = -1;
	pt[process_no].ipc_pipe[1] = -1;
	pt[process_no].ipc_sync_pipe[0] = -1;
	pt[process_no].ipc_sync_pipe[1] = -1;

	/* clear the per-process connection from the DB queues */
	ql_force_process_disconnect(process_no);

	/* if a TCP proc by chance, reset the tcp-related data */
	tcp_reset_worker_slot();

	/* mark myself as DYNAMIC (just in case) to have an err-less termination */
	pt[process_no].flags |= OSS_PROC_SELFEXIT;
	LM_INFO("doing self termination\n");

	/* the process slot in the proc table will be purge on SIGCHLD by main */
	exit(0);
}
