/*
 * $Id$
 *
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
#include "timer.h"
#include "pt.h"


/* array with children pids, 0= main proc,
 * alloc'ed in shared mem if possible */
struct process_table *pt=0;

/* variable keeping the number of created processes READONLY!! */
unsigned int counted_processes = 0;


int init_multi_proc_support(void)
{
	unsigned short proc_no;
	struct socket_info* si;
	#ifdef USE_TCP
	unsigned int i;
	#endif

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
	/* timer processes */
	proc_no += count_timer_procs();

	/* count the processes requested by modules */
	proc_no += count_module_procs();

	/* allocate the PID table */
	pt = shm_malloc(sizeof(struct process_table)*proc_no);
	if (pt==0){
		LM_ERR("out of memory\n");
		return -1;
	}
	memset(pt, 0, sizeof(struct process_table)*proc_no);

	#ifdef USE_TCP
	for( i=0 ; i<proc_no ; i++ ) {
		pt[i].unix_sock = -1;
		pt[i].idx = -1;
	}
	#endif

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
	#ifdef USE_TCP
	int sockfd[2];
	#endif

	if (process_counter==CHILD_COUNTER_STOP) {
		LM_CRIT("buggy call from non-main process!!!");
		return -1;
	}

	seed = rand();

	LM_DBG("forking new process \"%s\"\n",proc_desc);

	#ifdef USE_TCP
	if(!tcp_disable){
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd)<0){
			LM_ERR("socketpair failed: %s\n", strerror(errno));
			return -1;
		}
	}
	#endif

	if ( (pid=fork())<0 ){
		LM_CRIT("cannot fork \"%s\" process\n",proc_desc);
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
		/* set attributes */
		set_proc_attrs(proc_desc);
		/* set TCP communication */
		#ifdef USE_TCP
		if (!tcp_disable){
			close(sockfd[0]);
			unix_tcp_sock=sockfd[1];
			pt[process_no].unix_sock=sockfd[0];
		}
		#endif
		return 0;
	}else{
		/* parent process */
		pt[process_counter].pid = pid;
		#ifdef USE_TCP
		if (!tcp_disable) {
			close(sockfd[1]);
			/* set the fd also in parent to be eliminate any
			 * races between the parent and child */
			pt[process_counter].unix_sock=sockfd[0];
		}
		#endif
		process_counter++;
		return pid;
	}
}

/* returns the number of child processes
 * that are going to run child_init()
 *
 * used for proper status return code
 */
int count_init_children(void)
{
	int ret=0,i;
	struct sr_module *m;
	struct socket_info* si;

	if (dont_fork) 
		goto skip_listeners;

	/* UDP listening children */
	for (si=udp_listen;si;si=si->next)
		ret+=children_no;

	#ifdef USE_SCTP
	for (si=sctp_listen;si;si=si->next)
		ret+=children_no;
	#endif

	#ifdef USE_TCP
	ret += ((!tcp_disable)?( 1/* tcp main */ + tcp_children_no ):0);
	#endif

	/* attendent */
	ret++;

skip_listeners:

	/* count number of module procs going to be initialised */
	for (m=modules;m;m=m->next) {
		if (m->exports->procs==NULL)
			continue;
		for (i=0;m->exports->procs[i].name;i++) {
			if (!m->exports->procs[i].no || !m->exports->procs[i].function)
				continue;
			
			if (m->exports->procs[i].flags & PROC_FLAG_INITCHILD)
				ret+=m->exports->procs[i].no;
		}
	}

	LM_DBG("%d children are going to be inited\n",ret);
	return ret;
}
