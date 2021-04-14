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
 * History:
 * -------
 *  2002-01-29  argc/argv globalized via my_{argc|argv} (jiri)
 *  2003-01-23  mhomed added (jiri)
 *  2003-03-19  replaced all malloc/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-03-29  pkg cleaners for fifo and script callbacks introduced (jiri)
 *  2003-03-31  removed snmp part (obsolete & no place in core) (andrei)
 *  2003-04-06  child_init called in all processes (janakj)
 *  2003-04-08  init_mallocs split into init_{pkg,shm}_mallocs and
 *               init_shm_mallocs called after cmd. line parsing (andrei)
 *  2003-04-15  added tcp_disable support (andrei)
 *  2003-05-09  closelog() before openlog to force opening a new fd
 *              (needed on solaris) (andrei)
 *  2003-06-11  moved all signal handlers init. in install_sigs and moved it
 *              after daemonize (so that we won't catch anymore our own
 *              SIGCHLD generated when becoming session leader) (andrei)
 *              changed is_main default value to 1 (andrei)
 *  2003-06-28  kill_all_children is now used instead of kill(0, sig)
 *              see comment above it for explanations. (andrei)
 *  2003-06-29  replaced port_no_str snprintf w/ int2str (andrei)
 *  2003-10-10  added switch for config check (-c) (andrei)
 *  2003-10-24  converted to the new socket_info lists (andrei)
 *  2004-03-30  core dump is enabled by default
 *              added support for increasing the open files limit    (andrei)
 *  2004-04-28  sock_{user,group,uid,gid,mode} added
 *              user2uid() & user2gid() added  (andrei)
 *  2004-09-11  added timeout on children shutdown and final cleanup
 *               (if it takes more than 60s => something is definitely wrong
 *                => kill all or abort)  (andrei)
 *              force a shm_unlock before cleaning-up, in case we have a
 *               crashed childvwhich still holds the lock  (andrei)
 *  2004-12-02  removed -p, extended -l to support [proto:]address[:port],
 *               added parse_phostport, parse_proto (andrei)
 *  2005-06-16  always record the pid in pt[process_no].pid twice: once in the
 *               parent & once in the child to avoid a short window when one
 *               of them might use it "unset" (andrei)
 *  2005-12-22  added tos configurability (thanks to Andreas Granig)
 *  2006-04-26  2-stage TLS init: before and after config file parsing (klaus)
 */

/*!
 * \file main.c
 * \brief Command line parsing, initializiation and server startup.
 *
 * Contains methods for parsing the command line, the initialization of
 * the execution environment (signals, config file parsing) and forking
 * the TCP, UDP, timer and fifo children.
 */

#include "reactor_defs.h" /*keep this first*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <time.h>
#include <locale.h>

#include <sys/ioctl.h>
#include <net/if.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#include "help_msg.h"
#include "config.h"
#include "cfg_pp.h"
#include "cfg_reload.h"
#include "dprint.h"
#include "daemonize.h"
#include "route.h"
#include "bin_interface.h"
#include "globals.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"
#include "mem/rpm_mem.h"
#include "sr_module.h"
#include "timer.h"
#include "ipc.h"
#include "parser/msg_parser.h"
#include "ip_addr.h"
#include "resolve.h"
#include "parser/parse_hname2.h"
#include "parser/digest/digest_parser.h"
#include "name_alias.h"
#include "hash_func.h"
#include "pt.h"
#include "script_cb.h"
#include "dset.h"
#include "blacklists.h"
#include "xlog.h"
#include "ipc.h"

#include "pt.h"
#include "ut.h"
#include "serialize.h"
#include "statistics.h"
#include "core_stats.h"
#include "pvar.h"
#include "poll_types.h"
#include "net/net_tcp.h"
#include "net/net_udp.h"

#include "version.h"
#include "mi/mi_core.h"
#include "db/db_insertq.h"
#include "cachedb/cachedb.h"
#include "net/trans.h"

#include "test/unit_tests.h"

#include "ssl_tweaks.h"

/*
 * when enabled ("-T <module>" cmdline param), OpenSIPS will behave as follows:
 *   - enable debug mode
 *   - fork workers normally
 *   - run all currently enabled unit tests
 *     (if module != "core", the modules/<module>/test/ suite is ran,
 *      otherwise the core's ./test/ suite)
 *   - print the unit test summary
 *   - exit with 0 on success, non-zero otherwise
 */
int testing_framework;
char *testing_module = "core";

static char* version=OPENSIPS_FULL_VERSION;
static char* flags=OPENSIPS_COMPILE_FLAGS;
#ifdef VERSION_NODATE
char compiled[] =  "" ;
#else
#ifdef VERSION_DATE
const char compiled[] =  VERSION_DATE ;
#else
const char compiled[] =  __TIME__ " " __DATE__ ;
#endif
#endif

/**
 * Print compile-time constants
 */
void print_ct_constants(void)
{
#ifdef ADAPTIVE_WAIT
	printf("ADAPTIVE_WAIT_LOOPS=%d, ", ADAPTIVE_WAIT_LOOPS);
#endif
	printf("MAX_RECV_BUFFER_SIZE %d, MAX_LISTEN %d,"
			" MAX_URI_SIZE %d, BUF_SIZE %d\n",
		MAX_RECV_BUFFER_SIZE, MAX_LISTEN, MAX_URI_SIZE,
		BUF_SIZE );
	printf("poll method support: %s.\n", poll_support);
#ifdef VERSIONTYPE
	printf("%s revision: %s\n", VERSIONTYPE, THISREVISION);
#endif
}

/* global vars */

int own_pgid = 0; /* whether or not we have our own pgid (and it's ok
					 to use kill(0, sig) */
char* cfg_file = 0;
char *preproc = NULL;
unsigned int maxbuffer = MAX_RECV_BUFFER_SIZE; /* maximum buffer size we do
												  not want to exceed during the
												  auto-probing procedure; may
												  be re-configured */
/* number of UDP workers processing requests */
int udp_workers_no = UDP_WORKERS_NO;
/* the global UDP auto scaling profile */
char *udp_auto_scaling_profile = NULL;
/* if the auto-scaling engine is enabled or not - this is autodetected */
int auto_scaling_enabled = 0;
/* auto-scaling sampling and checking time cycle is 1 sec by default */
int auto_scaling_cycle = 1;
/*!< by default choose the best method */
enum poll_types io_poll_method=0;
/* last signal received */
int sig_flag = 0;

/* activate debug mode */
int debug_mode = 0;
/* do not become daemon, stay attached to the console */
int no_daemon_mode = 0;
/* assertion statements in script. disabled by default */
int enable_asserts = 0;
/* abort process on failed assertion. disabled by default */
int abort_on_assert = 0;
/* start by logging to stderr */
int log_stderr = 1;
/* log facility (see syslog(3)) */
int log_facility = LOG_DAEMON;
/* the id to be printed in syslog */
char *log_name = 0;
int config_check = 0;
/* check if reply first via host==us */
int check_via =  0;
/* debugging level for memory stats */
int memlog = L_DBG + 11;
int memdump = L_DBG + 10;
/* debugging in case msg processing takes. too long disabled by default */
int execmsgthreshold = 0;
/* debugging in case dns takes too long. disabled by default */
int execdnsthreshold = 0;
/* debugging in case tcp stuff take too long. disabled by default */
int tcpthreshold = 0;
/* should replies include extensive warnings? by default yes,
   good for trouble-shooting
*/
int sip_warning = 0;
/* should localy-generated messages include server's signature? */
int server_signature=1;
/* Server header to be used when proxy generates a reply as UAS.
   Default is to use SERVER_HDR CRLF (assigned later).
*/
str server_header = {SERVER_HDR,sizeof(SERVER_HDR)-1};
/* User-Agent header to be used when proxy generates request as UAC.
   Default is to use USER_AGENT CRLF (assigned later).
*/
str user_agent_header = {USER_AGENT,sizeof(USER_AGENT)-1};
/* should opensips try to locate outbound interface on multihomed
 * host? by default not -- too expensive
 */
int mhomed=0;
/* use dns and/or rdns or to see if we need to add
   a ;received=x.x.x.x to via: */
int received_dns = 0;
char* working_dir = 0;
char* chroot_dir = 0;
char* user=0;
char* group=0;
int user_id = 0;
int group_id = 0;

/* more config stuff */
int disable_core_dump=0; /* by default enabled */
int open_files_limit=-1; /* don't touch it by default */

#ifdef USE_MCAST
int mcast_loopback = 0;
int mcast_ttl = -1; /* if -1, don't touch it, use the default (usually 1) */
#endif /* USE_MCAST */

int tos = IPTOS_LOWDELAY; // lgtm [cpp/short-global-name]

struct socket_info* bind_address=0; /* pointer to the crt. proc.
									 listening address*/


/* if aliases should be automatically discovered and added
 * during fixing listening sockets */
int auto_aliases=0;

/* if the stateless forwarding support in core should be
 * disabled or not */
int sl_fwd_disabled=-1;

/* process number - 0 is the main process */
int process_no = 0;

/* cfg parsing */
int cfg_errors=0;

/* start-up time */
time_t startup_time = 0;

/* shared memory (in MB) */
unsigned long shm_mem_size=SHM_MEM_SIZE * 1024 * 1024;
unsigned int shm_hash_split_percentage = DEFAULT_SHM_HASH_SPLIT_PERCENTAGE;
unsigned int shm_secondary_hash_size = DEFAULT_SHM_SECONDARY_HASH_SIZE;

/* packaged memory (in MB) */
unsigned long pkg_mem_size=PKG_MEM_SIZE * 1024 * 1024;


/* export command-line to anywhere else */
int my_argc;
char **my_argv;

int is_main = 1; /* flag = is this the  "main" process? */

/* flag = is this an initial, pre-daemon process ? */
int is_pre_daemon = 1;

char* pid_file = 0; /* filename as asked by user */
char* pgid_file = 0;


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
static void kill_all_children(int signum)
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
static void shutdown_opensips( int status )
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

/* the initial SIGSEGV handler, provided by the OS */
static struct sigaction sa_sys_segv;
static char sa_sys_is_valid;

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


/**
 * Main loop, forks the children, bind to addresses,
 * handle signals.
 * \return don't return on sucess, -1 on error
 */
static int main_loop(void)
{
	static int chd_rank;
	int* startup_done = NULL;
	utime_t last_check = 0;
	int rc;

	chd_rank=0;

	if (start_module_procs()!=0) {
		LM_ERR("failed to fork module processes\n");
		goto error;
	}

	if(sroutes->startup.a) {/* if a startup route was defined */
		startup_done = (int*)shm_malloc(sizeof(int));
		if(startup_done == NULL) {
			LM_ERR("No more shared memory\n");
			goto error;
		}
		*startup_done = 0;
	}

	/* fork for the timer process*/
	if (start_timer_processes()!=0) {
		LM_CRIT("cannot start timer process(es)\n");
		goto error;
	}

	/* fork all processes required by UDP network layer */
	if (udp_start_processes( &chd_rank, startup_done)<0) {
		LM_CRIT("cannot start UDP processes\n");
		goto error;
	}

	/* fork all processes required by TCP network layer */
	if (tcp_start_processes( &chd_rank, startup_done)<0) {
		LM_CRIT("cannot start TCP processes\n");
		goto error;
	}

	/* fork for the extra timer processes */
	if (start_timer_extra_processes( &chd_rank )!=0) {
		LM_CRIT("cannot start timer extra process(es)\n");
		goto error;
	}

	/* fork the TCP listening process */
	if (tcp_start_listener()<0) {
		LM_CRIT("cannot start TCP listener process\n");
		goto error;
	}

	/* this is the main process -> it shouldn't send anything */
	bind_address=0;

	if (startup_done) {
		if (*startup_done==0)
			LM_CRIT("BUG: startup route defined, but not run :( \n");
		shm_free(startup_done);
	}

	set_osips_state( STATE_RUNNING );

	/* main process left */
	is_main=1;
	set_proc_attrs("attendant");
	pt[process_no].flags |= OSS_PROC_NO_IPC|OSS_PROC_NO_LOAD;

	if (testing_framework) {
		if (init_child(1) < 0) {
			LM_ERR("error in init_child for First Worker\n");
			report_failure_status();
			goto error;
		}

		rc = run_unit_tests();
		shutdown_opensips(rc);
	}

	report_conditional_status( (!no_daemon_mode), 0);

	if (auto_scaling_enabled) {
		/* re-create the status pipes to collect the status of the
		 * dynamically forked processes */
		if (create_status_pipe() < 0) {
			LM_ERR("failed to create status pipe\n");
			goto error;
		}
		/* keep both ends on the status pipe as we will keep forking 
		 * processes, so we will need to pass write-end to the new children;
		 * of course, we will need the read-end, here in the main proc */
		last_check = get_uticks();
	}

	for(;;){
			handle_sigs();
			if (auto_scaling_enabled) {
				sleep( auto_scaling_cycle );
				if ( (get_uticks()-last_check) >= (utime_t)auto_scaling_cycle*1000000) {
					do_workers_auto_scaling();
					last_check = get_uticks();
				} else {
					sleep_us( last_check + auto_scaling_cycle*1000000 -
						get_uticks() );
				}
			} else
				pause();
	}

	/*return 0; */
error:
	is_main=1;  /* if we are here, we are the "main process",
				  any forked children should exit with exit(-1) and not
				  ever use return */
	report_failure_status();
	return -1;

}



/**
 * Main routine, start of the program execution.
 * \param argc the number of arguments
 * \param argv pointer to the arguments array
 * \return don't return on sucess, -1 on error
 * \see main_loop
 */
int main(int argc, char** argv)
{
	/* configure by default logging to syslog */
	int cfg_log_stderr = 1;
	int c,r;
	char *tmp;
	int tmp_len;
	int port;
	int proto;
	int protos_no;
	char *options;
	int ret;
	unsigned int seed;
	int rfd;

	/*init*/
	ret=-1;
	my_argc=argc; my_argv=argv;

	/* process pkg mem size from command line */
	opterr=0;

	options="f:cCm:M:b:l:n:N:rRvdDFEVhw:t:u:g:p:P:G:W:o:a:k:s:"
#ifdef UNIT_TESTS
	"T:"
#endif
	;

	while((c=getopt(argc,argv,options))!=-1){
		switch(c){
			case 'M':
					pkg_mem_size=strtol(optarg, &tmp, 10) * 1024 * 1024;
					if (tmp &&(*tmp)){
						LM_ERR("bad pkgmem size number: -m %s\n", optarg);
						goto error00;
					}
					break;
			case 'm':
					shm_mem_size=strtol(optarg, &tmp, 10) * 1024 * 1024;
					if (tmp &&(*tmp)){
						LM_ERR("bad shmem size number: -m %s\n", optarg);
						goto error00;
					}
					break;
			case 'd':
					*log_level = *log_level + 1;
					break;
			case 'u':
					user=optarg;
					break;
			case 'g':
					group=optarg;
					break;
			case 'a':
					if (set_global_mm(optarg) < 0) {
						LM_ERR("current build does not support "
						       "this allocator (-a %s)\n", optarg);
						goto error00;
					}
					break;
			case 'k':
					if (set_pkg_mm(optarg) < 0) {
						LM_ERR("current build does not support "
						       "this allocator (-k %s)\n", optarg);
						goto error00;
					}
					break;
			case 's':
					if (set_shm_mm(optarg) < 0) {
						LM_ERR("current build does not support "
						       "this allocator (-s %s)\n", optarg);
						goto error00;
					}
					break;
			case 'e':
					if (set_rpm_mm(optarg) < 0) {
						LM_ERR("current build does not support "
						       "this allocator (-e %s)\n", optarg);
						goto error00;
					}
					break;
		}
	}

	/* get uid/gid */
	if (user){
		if (user2uid(&user_id, &group_id, user)<0){
			LM_ERR("bad user name/uid number: -u %s\n", user);
			goto error00;
		}
	}
	if (group){
		if (group2gid(&group_id, group)<0){
			LM_ERR("bad group name/gid number: -u %s\n", group);
			goto error00;
		}
	}

	/*init pkg mallocs (before parsing cfg but after parsing cmd line !)*/
	if (init_pkg_mallocs()==-1)
		goto error00;

	if ( (sroutes=new_sroutes_holder())==NULL )
		goto error00;

	/* we want to be sure that from now on, all the floating numbers are 
	 * using the dot as separator. This is a real issue when printing the
	 * floats for SQL ops, where the dot must be used */
	setlocale( LC_NUMERIC, "POSIX");

	/* process command line (get port no, cfg. file path etc) */
	/* first reset getopt */
	optind = 1;
	while((c=getopt(argc,argv,options))!=-1){
		switch(c){
			case 'f':
					cfg_file=optarg;
					break;
			case 'C':
					config_check |= 2;
			case 'c':
					if (config_check==3)
						break;
					config_check |= 1;
					cfg_log_stderr=1; /* force stderr logging */
					break;
			case 'm':
			case 'M':
			case 'd':
			case 'a':
			case 'k':
			case 's':
			case 'e':
					/* ignoring, parsed previously */
					break;
			case 'b':
					maxbuffer=strtol(optarg, &tmp, 10);
					if (tmp &&(*tmp)){
						LM_ERR("bad max buffer size number: -b %s\n", optarg);
						goto error00;
					}
					break;
			case 'l':
					if (parse_phostport(optarg, strlen(optarg), &tmp, &tmp_len,
											&port, &proto)<0){
						LM_ERR("bad -l address specifier: %s\n", optarg);
						goto error00;
					}
					tmp[tmp_len]=0; /* null terminate the host */
					/* add a new addr. to our address list */
					if (add_cmd_listening_socket(tmp, port, proto)!=0){
						LM_ERR("failed to add new listen address\n");
						goto error00;
					}
					break;
			case 'n':
					udp_workers_no=strtol(optarg, &tmp, 10);
					if ((tmp==0) ||(*tmp)){
						LM_ERR("bad UDP workers number: -n %s\n", optarg);
						goto error00;
					}
					break;
			case 'v':
					check_via=1;
					break;
			case 'r':
					received_dns|=DO_DNS;
					break;
			case 'R':
					received_dns|=DO_REV_DNS;
				    break;
			case 'D':
					debug_mode=1;
					*log_level = L_DBG;
					break;
			case 'F':
					no_daemon_mode=1;
					break;
			case 'E':
					cfg_log_stderr=1;
					break;
			case 'N':
					tcp_workers_no=strtol(optarg, &tmp, 10);
					if ((tmp==0) ||(*tmp)){
						LM_ERR("bad TCP workers number: -N %s\n", optarg);
						goto error00;
					}
					break;
			case 'W':
					io_poll_method=get_poll_type(optarg);
					if (io_poll_method==POLL_NONE){
						LM_ERR("bad poll method name: -W %s\ntry "
							"one of %s.\n", optarg, poll_support);
						goto error00;
					}
					break;
			case 'V':
					printf("version: %s\n", version);
					printf("flags: %s\n", flags );
					print_ct_constants();
					printf("%s compiled on %s with %s\n", __FILE__,
							compiled, COMPILER );
					exit(0);
					break;
			case 'h':
					printf("version: %s\n", version);
					printf("%s",help_msg);
					exit(0);
					break;
			case 'w':
					working_dir=optarg;
					break;
			case 't':
					chroot_dir=optarg;
					break;
			case 'u':
					/* ignoring it, parsed previously */
					break;
			case 'g':
					/* ignoring it, parsed previously */
					break;
			case 'p':
					preproc=optarg;
					break;
			case 'P':
					pid_file=optarg;
					break;
			case 'G':
					pgid_file=optarg;
					break;
			case 'o':
					if (add_arg_var(optarg) < 0)
						LM_ERR("cannot add option %s\n", optarg);
					break;
#ifdef UNIT_TESTS
			case 'T':
					LM_INFO("running in testing framework mode, for '%s'\n", optarg);
					testing_framework = 1;
					testing_module = optarg;
					if (strcmp(testing_module, "core")) {
						cfg_file = malloc(100);
						snprintf(cfg_file, 100, "modules/%s/test/opensips.cfg",
						         testing_module);
					}
					break;
#endif
			case '?':
					if (isprint(optopt))
						LM_ERR("Unknown option `-%c`.\n", optopt);
					else
						LM_ERR("Unknown option character `\\x%x`.\n", optopt);
					goto error00;
			case ':':
					LM_ERR("Option `-%c` requires an argument.\n", optopt);
					goto error00;
			default:
					abort();
		}
	}

	log_stderr = cfg_log_stderr;

	/* seed the prng, try to use /dev/urandom if possible */
	/* no debugging information is logged, because the standard
	   log level prior the config file parsing is L_NOTICE */
	seed=0;
	if ((rfd=open("/dev/urandom", O_RDONLY))!=-1){
try_again:
		if (read(rfd, (void*)&seed, sizeof(seed))==-1){
			if (errno==EINTR) goto try_again; /* interrupted by signal */
			LM_WARN("could not read from /dev/urandom (%d)\n", errno);
		}
		LM_DBG("initialize the pseudo random generator from "
			"/dev/urandom\n");
		LM_DBG("read %u from /dev/urandom\n", seed);
			close(rfd);
	}else{
		LM_WARN("could not open /dev/urandom (%d)\n", errno);
		LM_WARN("using a unsafe seed for the pseudo random number generator");
	}
	seed+=getpid()+time(0);
	LM_DBG("seeding PRNG with %u\n", seed);
	srand(seed);
	LM_DBG("test random number %u\n", rand());

	/*register builtin  modules*/
	register_builtin_modules();

	/* init avps */
	if (init_global_avps() != 0) {
		LM_ERR("error while initializing avps\n");
		goto error;
	}

	/*  init shm mallocs
	 *  this must be here
	 *     -to allow setting shm mem size from the command line
	 *     -it must be also before init_timer and init_tcp
	 *     -it must be after we know uid (so that in the SYSV sems case,
	 *        the sems will have the correct euid)
	 * --andrei */
	if (init_shm_mallocs()==-1)
		goto error;

	if (init_stats_collector() < 0) {
		LM_ERR("failed to initialize statistics\n");
		goto error;
	}

	set_osips_state( STATE_STARTING );

	if ((!testing_framework || strcmp(testing_module, "core"))
	        && parse_opensips_cfg(cfg_file, preproc, NULL) < 0) {
		LM_ERR("failed to parse config file %s\n", cfg_file);
		goto error00;
	}

	/* shm statistics, module stat groups, memory warming */
	init_shm_post_yyparse();

	if (config_check>1 && check_rls()!=0) {
		LM_ERR("bad function call in config file\n");
		return ret;
	}

	if (solve_module_dependencies(modules) != 0) {
		LM_ERR("failed to solve module dependencies\n");
		return -1;
	}

	/* init the resolver, before fixing the config */
	if (resolv_init() != 0) {
		LM_ERR("failed to init DNS resolver\n");
		return -1;
	}

	fix_poll_method( &io_poll_method );

	/* fix temporary listening sockets added in the cmd line */
	if (fix_cmd_listening_sockets() < 0) {
		LM_ERR("cannot add temproray listeners\n");
		return ret;
	}

	/* load transport protocols */
	protos_no = trans_load();
	if (protos_no < 0) {
		LM_ERR("cannot load transport protocols\n");
		goto error;
	} else if (protos_no == 0 && !testing_framework) {
		LM_ERR("no transport protocol loaded\n");
		goto error;
	} else
		LM_DBG("Loaded %d transport protocols\n", protos_no);

	/* fix parameters */
	if (working_dir==0) working_dir="/";

	if (fix_all_socket_lists()!=0){
		LM_ERR("failed to initialize list addresses\n");
		goto error00;
	}
	/* print all the listen addresses */
	printf("Listening on \n");
	print_all_socket_lists();
	printf("Aliases: \n");
	/*print_aliases();*/
	print_aliases();
	printf("\n");

	if (config_check){
		LM_NOTICE("config file ok, exiting...\n");
		return 0;
	}

	time(&startup_time);

	/*init UDP networking layer*/
	if (udp_init()<0){
		LM_CRIT("could not initialize tcp\n");
		goto error;
	}
	/*init TCP networking layer*/
	if (tcp_init()<0){
		LM_CRIT("could not initialize tcp\n");
		goto error;
	}

	if (create_status_pipe() < 0) {
		LM_ERR("failed to create status pipe\n");
		goto error;
	}

	if (testing_framework)
		debug_mode = 1;

	if (debug_mode) {
		LM_NOTICE("DEBUG MODE activated\n");
		if (no_daemon_mode==0) {
			LM_NOTICE("disabling daemon mode (found enabled)\n");
			no_daemon_mode = 1;
		}
		if (log_stderr==0) {
			LM_NOTICE("enabling logging to standard error (found disabled)\n");
			log_stderr = 1;
		}
		if (*log_level < L_DBG && (!testing_framework ||
		                           !strcmp(testing_module, "core"))) {
			LM_NOTICE("setting logging to debug level (found on %d)\n",
				*log_level);
			*log_level = L_DBG;
		}
		if (disable_core_dump) {
			LM_NOTICE("enabling core dumping (found off)\n");
			disable_core_dump = 0;
		}
		if (udp_count_processes(NULL)!=0) {
			if (udp_workers_no!=2) {
				LM_NOTICE("setting UDP children to 2 (found %d)\n",
					udp_workers_no);
				udp_workers_no = 2;
			}
		}
		if (tcp_count_processes(NULL)!=0) {
			if (tcp_workers_no!=2) {
				LM_NOTICE("setting TCP children to 2 (found %d)\n",
					tcp_workers_no);
				tcp_workers_no = 2;
			}
		}

	} else { /* debug_mode */
		/* init_daemon */
		if ( daemonize((log_name==0)?argv[0]:log_name, &own_pgid) <0 )
			goto error;
	}

	/* install signal handlers */
	if (install_sigs() != 0){
		LM_ERR("could not install the signal handlers\n");
		goto error;
	}

	if (disable_core_dump) set_core_dump(0, 0);
	else set_core_dump(1, shm_mem_size+pkg_mem_size+4*1024*1024);
	if (open_files_limit>0) {
		if(set_open_fds_limit()<0){
			LM_ERR("ERROR: error could not increase file limits\n");
			goto error;
		}
	}

	/* print OpenSIPS version to log for history tracking */
	LM_NOTICE("version: %s\n", version);

	/* print some data about the configuration */
	LM_NOTICE("using %ld MB of shared memory, allocator: %s\n",
	          shm_mem_size/1024/1024, mm_str(mem_allocator_shm));
#if defined(PKG_MALLOC)
	LM_NOTICE("using %ld MB of private process memory, allocator: %s\n",
	          pkg_mem_size/1024/1024, mm_str(mem_allocator_pkg));
#else
	LM_NOTICE("using system memory for private process memory\n");
#endif

	/* init async reactor */
	if (init_reactor_size()<0) {
		LM_CRIT("failed to init internal reactor, exiting...\n");
		goto error;
	}

	/* init timer */
	if (init_timer()<0){
		LM_CRIT("could not initialize timer, exiting...\n");
		goto error;
	}

	/* init IPC */
	if (init_ipc()<0){
		LM_CRIT("could not initialize IPC support, exiting...\n");
		goto error;
	}

	/* init serial forking engine */
	if (init_serialization()!=0) {
		LM_ERR("failed to initialize serialization\n");
		goto error;
	}
	/* Init MI */
	if (init_mi_core()<0) {
		LM_ERR("failed to initialize MI core\n");
		goto error;
	}

	/* Register core events */
	if (evi_register_core() != 0) {
		LM_ERR("failed register core events\n");
		goto error;
	}

	/* init black list engine */
	if (init_black_lists()!=0) {
		LM_CRIT("failed to init blacklists\n");
		goto error;
	}
	/* init resolver's blacklist */
	if (resolv_blacklist_init()!=0) {
		LM_CRIT("failed to create DNS blacklist\n");
		goto error;
	}

	if (init_dset() != 0) {
		LM_ERR("failed to initialize SIP forking logic!\n");
		goto error;
	}

	/* init SQL DB support */
	if (init_db_support() != 0) {
		LM_ERR("failed to initialize SQL database support\n");
		goto error;
	}

	/* init CacheDB support */
	if (init_cdb_support() != 0) {
		LM_ERR("failed to initialize CacheDB support\n");
		goto error;
	}

	/* init modules */
	if (init_modules() != 0) {
		LM_ERR("error while initializing modules\n");
		goto error;
	}

	/* init xlog */
	if (init_xlog() < 0) {
		LM_ERR("error while initializing xlog!\n");
		goto error;
	}

	/* register route timers */
	if(register_route_timers() < 0) {
		LM_ERR("Failed to register timer\n");
		goto error;
	}

	/* init pseudo-variable support */
	if (init_pvar_support() != 0) {
		LM_ERR("failed to init pvar support\n");
		goto error;
	}

	/* init multi processes support */
	if (init_multi_proc_support()!=0) {
		LM_ERR("failed to init multi-proc support\n");
		goto error;
	}

	/* init avps */
	if (init_extra_avps() != 0) {
		LM_ERR("error while initializing avps\n");
		goto error;
	}

	/* fix routing lists */
	if ( (r=fix_rls())!=0){
		LM_ERR("failed to fix configuration with err code %d\n", r);
		goto error;
	}

	if (init_log_level() != 0) {
		LM_ERR("failed to init logging levels\n");
		goto error;
	}

	if (trans_init_all_listeners()<0) {
		LM_ERR("failed to init all SIP listeners, aborting\n");
		goto error;
	}

	if (init_script_reload()<0) {
		LM_ERR("failed to init cfg reload ctx, aborting\n");
		goto error;
	}

	/* all processes should have access to all the sockets (for sending)
	 * so we open all first*/
	if (do_suid(user_id, group_id)==-1)
		goto error;

	ret = main_loop();

error:
	/*kill everything*/
	kill_all_children(SIGTERM);
	/*clean-up*/
	cleanup(0);
error00:
	LM_NOTICE("Exiting....\n");
	return ret;
}
