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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <syslog.h>
#include <stdarg.h>
#include <stddef.h>
#include <time.h>

#include "config.h"

#include "poll_types.h"
#include "ip_addr.h"
#include "str.h"
#include "globals.h"

/* global vars */

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

/* activate debug mode */
int debug_mode = 0;
/* do not become daemon, stay attached to the console */
int no_daemon_mode = 0;
/* assertion statements in script. disabled by default */
int enable_asserts = 0;
/* abort process on failed assertion. disabled by default */
int abort_on_assert = 0;
/* start by only logging to stderr */
int log_stdout = 0, log_stderr = 1;
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
str * const server_header = &str_init(SERVER_HDR);
/* User-Agent header to be used when proxy generates request as UAC.
   Default is to use USER_AGENT CRLF (assigned later).
*/
str * const user_agent_header = &str_init(USER_AGENT);
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

/* more config stuff */
int disable_core_dump=0; /* by default enabled */
int open_files_limit=-1; /* don't touch it by default */

#ifdef USE_MCAST
int mcast_loopback = 0;
int mcast_ttl = -1; /* if -1, don't touch it, use the default (usually 1) */
#endif /* USE_MCAST */

int tos = IPTOS_LOWDELAY; // lgtm [cpp/short-global-name]

struct socket_info* bind_address=NULL; /* pointer to the crt. proc.
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
