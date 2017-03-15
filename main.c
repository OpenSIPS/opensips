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

#include <sys/ioctl.h>
#include <net/if.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#include "help_msg.h"
#include "config.h"
#include "dprint.h"
#include "daemonize.h"
#include "route.h"
#include "bin_interface.h"
#include "globals.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"
#include "sr_module.h"
#include "timer.h"
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
#include "net/trans.h"

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
unsigned int maxbuffer = MAX_RECV_BUFFER_SIZE; /* maximum buffer size we do
												  not want to exceed during the
												  auto-probing procedure; may
												  be re-configured */
int children_no = CHILD_NO;		/* number of children processing requests */
enum poll_types io_poll_method=0; 	/*!< by default choose the best method */
int sig_flag = 0;              /* last signal received */

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
int memlog = L_DBG + 10;
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
/* Server header to be used when proxy generates request as UAS.
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
int uid = 0;
int gid = 0;

/* more config stuff */
int disable_core_dump=0; /* by default enabled */
int open_files_limit=-1; /* don't touch it by default */

#ifdef USE_MCAST
int mcast_loopback = 0;
int mcast_ttl = -1; /* if -1, don't touch it, use the default (usually 1) */
#endif /* USE_MCAST */

int tos = IPTOS_LOWDELAY;

struct socket_info* bind_address=0; /* pointer to the crt. proc.
									 listening address*/


/* if aliases should be automatically discovered and added
 * during fixing listening sockets */
int auto_aliases=1;

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

extern FILE* yyin;
extern int yyparse();
#ifdef DEBUG_PARSER
extern int yydebug;
#endif


int is_main = 1; /* flag = is this the  "main" process? */

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

	/* hack: force-unlock the shared memory lock in case
	   		 some process crashed and let it locked; this will
	   		 allow an almost gracious shutdown */
	if (mem_lock)
#ifdef HP_MALLOC
	{
		int i;

		for (i = 0; i < HP_HASH_SIZE; i++)
			shm_unlock(i);
	}
#else
		shm_unlock();
#endif

	handle_ql_shutdown();
	destroy_modules();
	udp_destroy();
	tcp_destroy();
	destroy_timer();
	destroy_stats_collector();
	destroy_script_cb();
	pv_free_extra_list();
	destroy_argv_list();
	destroy_black_lists();
#ifdef PKG_MALLOC
	if (show_status){
		LM_GEN1(memdump, "Memory status (pkg):\n");
		pkg_status();
	}
#endif
	cleanup_log_level();

	if (mem_lock && pt)
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
 * Tries to send a signal to all our processes
 * If daemonized  is ok to send the signal to all the process group,
 * however if not daemonized we might end up sending the signal also
 * to the shell which launched us => most signals will kill it if
 * it's not in interactive mode and we don't want this. The non-daemonized
 * case can occur when an error is encountered before daemonize is called
 * (e.g. when parsing the config file) or when opensips is started in
 * "don't-fork" mode.
 * \param signum signal for killing the children
 */
static void kill_all_children(int signum)
{
	int r;
	if (own_pgid) {
		/* check that all processes initialized properly */
		for (r=1; r<counted_processes; r++) {
			while (pt[r].pid==0){
				usleep(1000);
			}
		}
		kill(0, signum);
	} else if (pt)
		for (r=1; r<counted_processes; r++) {
			if (pt[r].pid==-1) continue;
			/* as the PIDs are filled in by child processes, a 0 PID means
			 * an un-initalized procees; killing an uninitialized proc is
			 * very dangerous, so better wait for it to finish its init
			 * sequance by checking when the pid is populated */
			while (pt[r].pid==0) usleep(1000);
			kill(pt[r].pid, signum);
		}
}



/**
 * Timeout handler during wait for children exit.
 * If this handler is called, a critical timeout has occurred while
 * waiting for the children to finish => we should kill everything and exit
 * \param signo signal for killing the children
 */
static void sig_alarm_kill(int signo)
{
	kill_all_children(SIGKILL); /* this will kill the whole group
								  including "this" process;
								  for debugging replace with SIGABRT
								  (but warning: it might generate lots
								   of cores) */
}


/**
 * Timeout handler during wait for children exit.
 * like sig_alarm_kill, but the timeout has occurred when cleaning up,
 * try to leave a core for future diagnostics
 * \param signo signal for killing the children
 * \see sig_alarm_kill
 */
static void sig_alarm_abort(int signo)
{
	/* LOG is not signal safe, but who cares, we are abort-ing anyway :-) */
	LM_CRIT("BUG - shutdown timeout triggered, dying...");
	abort();
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
	const unsigned int shutdown_time = 60; /* one minute close timeout */

	switch(sig_flag){
		case 0: break; /* do nothing*/
		case SIGPIPE:
				/* SIGPIPE might be rarely received on use of
				   exec module; simply ignore it
				 */
				LM_WARN("SIGPIPE received and ignored\n");
				break;
		case SIGINT:
		case SIGTERM:
			/* we end the program in all these cases */
			if (sig_flag==SIGINT)
				LM_DBG("INT received, program terminates\n");
			else
				LM_DBG("SIGTERM received, program terminates\n");

			/* first of all, kill the children also */
			kill_all_children(SIGTERM);
			if (signal(SIGALRM, sig_alarm_kill) == SIG_ERR ) {
				LM_ERR("could not install SIGALARM handler\n");
				/* continue, the process will die anyway if no
				 * alarm is installed which is exactly what we want */
			}
			alarm(shutdown_time);
			while(wait(0) > 0); /* Wait for all the children to terminate */
			signal(SIGALRM, sig_alarm_abort);

			cleanup(1); /* cleanup & show status*/
			alarm(0);
			signal(SIGALRM, SIG_IGN);
			dprint("Thank you for flying " NAME "\n");
			exit(0);
			break;

		case SIGUSR1:
#ifdef PKG_MALLOC
			LM_GEN1(memdump, "Memory status (pkg):\n");
			pkg_status();
#endif
			LM_GEN1(memdump, "Memory status (shm):\n");
			shm_status();
			break;

		case SIGUSR2:
#ifdef PKG_MALLOC
			set_pkg_stats( get_pkg_status_holder(process_no) );
#endif
			break;

		case SIGCHLD:
			do_exit = 0;
			while ((chld=waitpid( -1, &chld_status, WNOHANG ))>0) {
				/* is it a process we know about? */
				for( i=0 ; i<counted_processes ; i++ )
					if (pt[i].pid==chld) break;
				if (i==counted_processes) {
					LM_DBG("unknown child process %d ended. Ignoring\n",chld);
					continue;
				}
				do_exit = 1;
				/* process the signal */
				overall_status |= chld_status;
				LM_DBG("status = %d\n",overall_status);

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
			}
			if (!do_exit)
				break;
			LM_INFO("terminating due to SIGCHLD\n");
			/* exit */
			kill_all_children(SIGTERM);
			if (signal(SIGALRM, sig_alarm_kill) == SIG_ERR ) {
				LM_ERR("could not install SIGALARM handler\n");
				/* continue, the process will die anyway if no
				 * alarm is installed which is exactly what we want */
			}
			alarm(shutdown_time);
			while(wait(0) > 0); /* wait for all the children to terminate*/
			signal(SIGALRM, sig_alarm_abort);
			cleanup(1); /* cleanup & show status*/
			alarm(0);
			signal(SIGALRM, SIG_IGN);
			LM_DBG("terminating due to SIGCHLD\n");
			exit(overall_status ? -1 : 0);
			break;

		case SIGHUP: /* ignoring it*/
			LM_DBG("SIGHUP received, ignoring it\n");
			break;
		default:
			LM_CRIT("unhandled signal %d\n", sig_flag);
	}
	sig_flag=0;
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
		if (sig_flag==0) sig_flag=signo;
		else /*  previous sig. not processed yet, ignoring? */
			return; ;
	}else{
		/* process the important signals */
		switch(signo){
			case SIGPIPE:
					LM_INFO("signal %d received\n", signo);
				break;
			case SIGINT:
			case SIGTERM:
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
			case SIGUSR1:
					/* statistics -> show only pkg mem */
					#ifdef PKG_MALLOC
					LM_GEN1(memdump, "Memory status (pkg):\n");
					pkg_status();
					#endif
					break;
			case SIGUSR2:
					#ifdef PKG_MALLOC
					set_pkg_stats( get_pkg_status_holder(process_no) );
					#endif
					break;
			case SIGHUP:
					/* ignored*/
					break;
			case SIGCHLD:
					pid = waitpid(-1, &status, WNOHANG);
					LM_DBG("SIGCHLD received from %ld (status=%d), ignoring\n",
						(long)pid,status);
		}
	}
}



/**
 * Install the signal handlers.
 * \return 0 on success, -1 on error
 */
int install_sigs(void)
{
	/* added by jku: add exit handler */
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

	chd_rank=0;

	if (start_module_procs()!=0) {
		LM_ERR("failed to fork module processes\n");
		goto error;
	}

	if(startup_rlist.a) {/* if a startup route was defined */
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

	/* main process left */
	is_main=1;
	set_proc_attrs("attendant");

	if (init_child(PROC_MAIN) < 0) {
		LM_ERR("error in init_child for PROC_MAIN\n");
		report_failure_status();
		goto error;
	}

	report_conditional_status( (!no_daemon_mode), 0);

	for(;;){
			handle_sigs();
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
	FILE* cfg_stream;
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
	options="f:cCm:M:b:l:n:N:rRvdDFETSVhw:t:u:g:P:G:W:o:";

	while((c=getopt(argc,argv,options))!=-1){
		switch(c){
			case 'M':
					pkg_mem_size=strtol(optarg, &tmp, 10) * 1024 * 1024;
					if (tmp &&(*tmp)){
						LM_ERR("bad pkgmem size number: -m %s\n", optarg);
						goto error00;
					};

					break;
			case 'm':
					shm_mem_size=strtol(optarg, &tmp, 10) * 1024 * 1024;
					if (tmp &&(*tmp)){
						LM_ERR("bad shmem size number: -m %s\n", optarg);
						goto error00;
					};
					break;
			case 'u':
					user=optarg;
					break;
			case 'g':
					group=optarg;
					break;
		}
	}

	/* get uid/gid */
	if (user){
		if (user2uid(&uid, &gid, user)<0){
			LM_ERR("bad user name/uid number: -u %s\n", user);
			goto error00;
		}
	}
	if (group){
		if (group2gid(&gid, group)<0){
			LM_ERR("bad group name/gid number: -u %s\n", group);
			goto error00;
		}
	}

	/*init pkg mallocs (before parsing cfg but after parsing cmd line !)*/
	if (init_pkg_mallocs()==-1)
		goto error00;

	init_route_lists();

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
					/* ignoring it, parsed previously */
					break;
			case 'M':
					/* ignoring it, parsed previously */
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
					if (add_cmd_listener(tmp, port, proto)!=0){
						LM_ERR("failed to add new listen address\n");
						goto error00;
					}
					break;
			case 'n':
					children_no=strtol(optarg, &tmp, 10);
					if ((tmp==0) ||(*tmp)){
						LM_ERR("bad process number: -n %s\n", optarg);
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
			case 'd':
					*log_level = debug_mode ? L_DBG : (*log_level)+1;
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
					tcp_children_no=strtol(optarg, &tmp, 10);
					if ((tmp==0) ||(*tmp)){
						LM_ERR("bad process number: -N %s\n", optarg);
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

	/* fill missing arguments with the default values*/
	if (cfg_file==0) cfg_file=CFG_FILE;

	/* load config file or die */
	cfg_stream=fopen (cfg_file, "r");
	if (cfg_stream==0){
		LM_ERR("loading config file(%s): %s\n", cfg_file,
				strerror(errno));
		goto error00;
	}

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

	/* used for parser debugging */
#ifdef DEBUG_PARSER
	yydebug = 1;
#endif

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

	/* parse the config file, prior to this only default values
	   e.g. for debugging settings will be used */
	yyin=cfg_stream;
	if ((yyparse()!=0)||(cfg_errors)){
		LM_ERR("bad config file (%d errors)\n", cfg_errors);
		goto error00;
	}

	if (config_check>1 && check_rls()!=0) {
		LM_ERR("bad function call in config file\n");
		return ret;
	}

	if (solve_module_dependencies(modules) != 0) {
		LM_ERR("failed to solve module dependencies\n");
		return -1;
	}

	/* init the resolver, before fixing the config */
	resolv_init();

	fix_poll_method( &io_poll_method );

	/* fix temporary listeners added in the cmd line */
	if (fix_cmd_listeners() < 0) {
		LM_ERR("cannot add temproray listeners\n");
		return ret;
	}

	/* load transport protocols */
	protos_no = trans_load();
	if (protos_no < 0) {
		LM_ERR("cannot load transport protocols\n");
		goto error;
	} else if (protos_no == 0) {
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

	/* Init statistics */
	init_shm_statistics();

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
		if (*log_level<L_DBG) {
			LM_NOTICE("setting logging to debug level (found on %d)\n",
				*log_level);
			*log_level = L_DBG;
		}
		if (disable_core_dump) {
			LM_NOTICE("enabling core dumping (found off)\n");
			disable_core_dump = 0;
		}
		if (udp_count_processes()!=0) {
			if (children_no!=2) {
				LM_NOTICE("setting UDP children to 2 (found %d)\n",
					children_no);
				children_no = 2;
			}
		}
		if (tcp_count_processes()!=0) {
			if (tcp_children_no!=2) {
				LM_NOTICE("setting TCP children to 2 (found %d)\n",
					tcp_children_no);
				tcp_children_no = 2;
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
	LM_INFO("using %ld Mb shared memory\n", ((shm_mem_size/1024)/1024));
	LM_INFO("using %ld Mb private memory per process\n",
		((pkg_mem_size/1024)/1024));

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

	/* check pv context list */
	if(pv_contextlist_check() != 0) {
		LM_ERR("used pv context that was not defined\n");
		goto error;
	}

	/* init query list now in shm
	 * so all processes that will be forked from now on
	 * will have access to it
	 *
	 * if it fails, give it a try and carry on */
	if (init_ql_support() != 0) {
		LM_ERR("failed to initialise buffering query list\n");
		query_buffer_size = 0;
		*query_list = NULL;
	}

	/* init multi processes support */
	if (init_multi_proc_support()!=0) {
		LM_ERR("failed to init multi-proc support\n");
		goto error;
	}

	#ifdef PKG_MALLOC
	/* init stats support for pkg mem */
	if (init_pkg_stats(counted_processes)!=0) {
		LM_ERR("failed to init stats for pkg\n");
		goto error;
	}
	#endif

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

	/* all processes should have access to all the sockets (for sending)
	 * so we open all first*/
	if (do_suid(uid, gid)==-1)
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
