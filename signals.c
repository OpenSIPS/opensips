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
#include <signal.h>

#include "dprint.h"
#include "daemonize.h"
#include "pt.h"
#include "shutdown.h"
#include "signals.h"

/* last signal received */
static int sig_flag = 0;

/* the initial SIGSEGV handler, provided by the OS */
static struct sigaction sa_sys_segv;
static char sa_sys_is_valid;

/**
 * Signal handler for the server.
 */
void handle_sigs(void)
{
	pid_t  chld;
	int    chld_status,overall_status=0;
	int    i;
	int    do_exit;

	switch(sig_flag){
		case 0: break; /* do nothing*/
		case SIGPIPE:
				/* SIGPIPE might be rarely received on use of
				   exec module; simply ignore it
				 */
		case SIGUSR1:
		case SIGUSR2:
		case SIGHUP:
				/* ignoring it*/
				break;
		case SIGINT:
		case SIGTERM:
			/* we end the program in all these cases */
			if (sig_flag==SIGINT)
				LM_DBG("SIGINT received, program terminates\n");
			else
				LM_DBG("SIGTERM received, program terminates\n");

			shutdown_opensips( 0/*status*/ );
			break;

		case SIGCHLD:
			do_exit = 0;
			while ((chld=waitpid( -1, &chld_status, WNOHANG ))>0) {
				/* is it a process we know about? */
				if ( (i=get_process_ID_by_PID( chld )) == -1 ) {
					LM_DBG("unknown child process %d ended. Ignoring\n",chld);
					continue;
				}
				if (pt[i].flags & OSS_PROC_SELFEXIT) {
					LM_NOTICE("process %d/%d did selfexit with "
						"status %d\n", i, chld,  WTERMSIG(chld_status));
					reset_process_slot(i);
					continue;
				}
				do_exit = 1;
				/* process the signal */
				overall_status |= chld_status;
				LM_DBG("OpenSIPS exit status = %d\n",overall_status);

				if (WIFEXITED(chld_status))
					LM_INFO("child process %d exited normally,"
							" status=%d\n", chld,
							WEXITSTATUS(chld_status));
				else if (WIFSIGNALED(chld_status)) {
					LM_INFO("child process %d exited by a signal"
							" %d\n", chld, WTERMSIG(chld_status));
#ifdef WCOREDUMP
					LM_INFO("core was %sgenerated\n",
							 WCOREDUMP(chld_status) ?  "" : "not " );
#endif
				}else if (WIFSTOPPED(chld_status))
					LM_INFO("child process %d stopped by a"
								" signal %d\n", chld,
								 WSTOPSIG(chld_status));

				/* mark the child process as terminated / not running */
				pt[i].pid = -1;
			}
			if (!do_exit)
				break;
			LM_INFO("terminating due to SIGCHLD\n");
			/* exit */
			shutdown_opensips( overall_status );
			break;

		default:
			LM_CRIT("unhandled signal %d\n", sig_flag);
	}
	sig_flag=0;
}

static inline int restore_segv_handler(void)
{
	LM_DBG("restoring SIGSEGV handler...\n");

	if (!sa_sys_is_valid)
		return 1;

	if (sigaction(SIGSEGV, &sa_sys_segv, NULL) < 0) {
		LM_ERR("failed to restore system SIGSEGV handler\n");
		return -1;
	}

	LM_DBG("successfully restored system SIGSEGV handler\n");

	return 0;
}


/**
 * Exit regulary on a specific signal.
 * This is good for profiling which only works if exited regularly
 * and not by default signal handlers
 * \param signo The signal that should be handled
 */
static void sig_usr(int signo)
{
	int status;
	pid_t pid;
	UNUSED(pid);

	if (is_main){
		if (signo == SIGSEGV) {
			LM_CRIT("segfault in attendant (starter) process!\n");
			if (restore_segv_handler() != 0)
				exit(-1);
			return;
		}

		if (sig_flag == 0)
			sig_flag = signo;
		else /*  previous sig. not processed yet, ignoring? */
			return;
	}else{
		/* process the important signals */
		switch(signo){
			case SIGPIPE:
			case SIGINT:
			case SIGUSR1:
			case SIGUSR2:
			case SIGHUP:
					/* ignored*/
					break;
			case SIGTERM:
					/* ignore any SIGTERM if not in shutdown sequance (this 
					 * is marked by the attendent process) */
					if (get_osips_state()!=STATE_TERMINATING)
						return;
					/* if some shutdown already in progress, ignore this one */
					if (sig_flag==0) sig_flag=signo;
					else return;
					/* do the termination */
					LM_INFO("signal %d received\n", signo);
					/* print memory stats for non-main too */
					#ifdef PKG_MALLOC
					LM_GEN1(memdump, "Memory status (pkg):\n");
					pkg_status();
					#endif
					exit(0);
					break;
			case SIGCHLD:
					while ( (pid = waitpid(-1, &status, WNOHANG))>0 );
					break;
			case SIGSEGV:
					/* looks like we ate some spicy SIP */
					LM_CRIT("segfault in process pid: %d, id: %d\n",
					        pt[process_no].pid, process_no);
					pt[process_no].flags |= OSS_PROC_DOING_DUMP;
					if (restore_segv_handler() != 0)
						exit(-1);
					pkg_status();
		}
	}
}


/**
 * Install the signal handlers.
 * \return 0 on success, -1 on error
 */
int install_sigs(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof act);

	act.sa_handler = sig_usr;
	if (sigaction(SIGSEGV, &act, &sa_sys_segv) < 0) {
		LM_INFO("failed to install custom SIGSEGV handler -- corefiles must "
		        "now be written within %d sec to avoid truncation!\n",
		        GRACEFUL_SHUTDOWN_TIMEOUT);
	} else {
		LM_DBG("override SIGSEGV handler: success\n");
		sa_sys_is_valid = 1;
	}

	if (signal(SIGINT, sig_usr) == SIG_ERR ) {
		LM_ERR("no SIGINT signal handler can be installed\n");
		goto error;
	}
	/* if we debug and write to a pipe, we want to exit nicely too */
	if (signal(SIGPIPE, sig_usr) == SIG_ERR ) {
		LM_ERR("no SIGINT signal handler can be installed\n");
		goto error;
	}

	if (signal(SIGUSR1, sig_usr)  == SIG_ERR ) {
		LM_ERR("no SIGUSR1 signal handler can be installed\n");
		goto error;
	}
	if (signal(SIGCHLD , sig_usr)  == SIG_ERR ) {
		LM_ERR("no SIGCHLD signal handler can be installed\n");
		goto error;
	}
	if (signal(SIGTERM , sig_usr)  == SIG_ERR ) {
		LM_ERR("no SIGTERM signal handler can be installed\n");
		goto error;
	}
	if (signal(SIGHUP , sig_usr)  == SIG_ERR ) {
		LM_ERR("no SIGHUP signal handler can be installed\n");
		goto error;
	}
	if (signal(SIGUSR2 , sig_usr)  == SIG_ERR ) {
		LM_ERR("no SIGUSR2 signal handler can be installed\n");
		goto error;
	}
	return 0;
error:
	return -1;
}
