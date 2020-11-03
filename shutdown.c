/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2005-2006 Voice Sistem S.R.L
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
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "config.h"
#include "dprint.h"
#include "daemonize.h"
#include "globals.h"
#include "pt.h"
#include "route.h"
#include "script_cb.h"
#include "blacklists.h"
#include "mem/shm_mem.h"
#include "db/db_insertq.h"
#include "net/net_udp.h"
#include "net/net_tcp.h"
#include "shutdown.h"

/**
 * Clean up on exit. This should be called before exiting.
 * \param show_status set to one to display the mem status
 */
void cleanup(int show_status)
{
	LM_INFO("cleanup\n");

	/*clean-up*/

	/* hack: force-unlock the shared memory lock(s) in case
	   		 some process crashed and let it locked; this will
	   		 allow an almost gracious shutdown */
	if (0
#if defined F_MALLOC || defined Q_MALLOC
		|| mem_lock
#endif
#ifdef HP_MALLOC
		|| mem_locks
#endif
	) {
#if defined HP_MALLOC && (defined F_MALLOC || defined Q_MALLOC)
		if (mem_allocator_shm == MM_HP_MALLOC ||
		        mem_allocator_shm == MM_HP_MALLOC_DBG) {
			int i;

			for (i = 0; i < HP_HASH_SIZE; i++)
				lock_release(&mem_locks[i]);
		} else {
			shm_unlock();
		}
#elif defined HP_MALLOC
		int i;

		for (i = 0; i < HP_HASH_SIZE; i++)
			lock_release(&mem_locks[i]);
#else
		shm_unlock();
#endif
	}

	handle_ql_shutdown();
	destroy_modules();
	udp_destroy();
	tcp_destroy();
	destroy_timer();
	destroy_stats_collector();
	destroy_script_cb();
	pv_free_extra_list();
	tr_free_extra_list();
	destroy_argv_list();
	destroy_black_lists();
	free_route_lists(sroutes); // this is just for testing purposes
#ifdef PKG_MALLOC
	if (show_status){
		LM_GEN1(memdump, "Memory status (pkg):\n");
		pkg_status();
	}
#endif
	cleanup_log_level();

	if (pt && (0
#if defined F_MALLOC || defined Q_MALLOC
		|| mem_lock
#endif
#ifdef HP_MALLOC
		|| mem_locks
#endif
		))
		shm_free(pt);
	pt=0;
	if (show_status){
			LM_GEN1(memdump, "Memory status (shm):\n");
			shm_status();
	}

	/* zero all shmem alloc vars that we still use */
	shm_mem_destroy();
	if (pid_file) unlink(pid_file);
	if (pgid_file) unlink(pgid_file);
}


/**
 * Send a signal to all child processes
 * \param signum signal for killing the children
 */
void kill_all_children(int signum)
{
	int r;

	if (!pt)
		return;

	for (r = 1; r < counted_max_processes; r++) {
		if (pt[r].pid == -1 || (pt[r].flags & OSS_PROC_DOING_DUMP))
			continue;

		/* as the PIDs are filled in by child processes, a 0 PID means
		 * an un-initalized procees; killing an uninitialized proc is
		 * very dangerous, so better wait for it to finish its init
		 * sequence by blocking until the pid is populated */
		while (pt[r].pid == 0)
			usleep(1000);

		kill(pt[r].pid, signum);
	}
}


/**
 * SIGALRM "timeout" handler during the attendant's final cleanup,
 * try to leave a core for future diagnostics.
 */
static void sig_alarm_abort(int signo)
{
	/* LOG is not signal safe, but who cares, we are abort-ing anyway :-) */
	LM_CRIT("BUG - shutdown timeout triggered, dying...\n");
	abort();
}


/* RPC function send by main process to all worker processes supporting
 * IPC in order to force a gracefull termination
 */
static void rpc_process_terminate(int sender_id, void *code)
{
	#ifdef PKG_MALLOC
	LM_GEN1(memdump, "Memory status (pkg):\n");
	pkg_status();
	#endif

	/* simply terminate the process */
	LM_DBG("Process %d exiting with code %d...\n",
		process_no, (int)(long)code);

	exit( (int)(long)code );
}


/* Implements full shutdown sequence (terminate processes and cleanup)
 * To be called ONLY from MAIN process, not from workers !!!
 */
void shutdown_opensips( int status )
{
	pid_t  proc;
	int i, n, p;
	int chld_status;

	set_osips_state( STATE_TERMINATING );

	/* terminate all processes */

	/* first we try to terminate the processes via the IPC channel */
	for( i=1,n=0 ; i<counted_max_processes; i++) {
		/* Depending on the processes status, its PID may be:
		 *   -1 - process not forked yet
		 *    0 - process forked but not fully configured by core
		 *   >0 - process fully running
		 */
		if (pt[i].pid!=-1) {
			/* use IPC (if avaiable) for a graceful termination */
			if ( IPC_FD_WRITE(i)>0 ) {
				LM_DBG("Asking process %d [%s] to terminate\n", i, pt[i].desc);
				if (ipc_send_rpc( i, rpc_process_terminate, (void*)0)<0) {
					LM_ERR("failed to trigger RPC termination for "
						"process %d\n", i );
				}
			} else {
				while (pt[i].pid==0) usleep(1000);
				kill(pt[i].pid, SIGTERM);
			}
			n++;
		}
	}

	/* now wait for the processes to finish */
	i = GRACEFUL_SHUTDOWN_TIMEOUT * 100;
	while( i && n ) {
		proc = waitpid( -1, &chld_status, WNOHANG);
		if (proc<=0) {
			/* no process exited so far, do a small sleep before retry */
			usleep(10000);
			i--;
		} else {
			if ( (p=get_process_ID_by_PID(proc)) == -1 ) {
				LM_DBG("unknown child process %d ended. Ignoring\n",proc);
			} else {
				LM_INFO("process %d(%d) [%s] terminated, "
					"still waiting for %d more\n", p, proc, pt[p].desc, n-1);
				/* mark the child process as terminated / not running */
				pt[p].pid = -1;
				status |= chld_status;
				n--;
			}
		}
	}

	if (i==0 && n!=0) {
		LM_DBG("force termination for all processes\n");
		kill_all_children(SIGKILL);
	}

	/* Only one process is running now. Clean up and return overall status */
	signal(SIGALRM, sig_alarm_abort);
	alarm(SHUTDOWN_TIMEOUT - i / 100);
	cleanup(1);
	alarm(0);
	signal(SIGALRM, SIG_IGN);

	dprint("Thank you for running " NAME "\n");
	exit( status );
}
