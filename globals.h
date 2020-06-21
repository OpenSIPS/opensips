/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 */

/*!
 * \file
 * \brief Global variables
 */


#ifndef globals_h
#define globals_h

#include "ip_addr.h"
#include "str.h"
#include "poll_types.h"

#define DO_DNS     1
#define DO_REV_DNS 2

extern int testing_framework;
extern char *testing_module;

extern char * cfg_file;
extern char *preproc;
extern int config_check;
extern char *stat_file;

extern char* pid_file;
extern char* pgid_file;

extern struct socket_info* bind_address; /*!< pointer to the crt. proc.  listening address */

extern int auto_aliases;

extern unsigned int maxbuffer;
extern int udp_workers_no;
extern char *udp_auto_scaling_profile;
extern enum poll_types io_poll_method;
extern int auto_scaling_enabled;
extern int auto_scaling_cycle;

/* TCP network layer related parameters */
extern char* tcp_auto_scaling_profile;
extern int tcp_workers_no;
extern int tcp_disable;
extern int tcp_accept_aliases;
extern int tcp_connect_timeout;
extern int tcp_con_lifetime; /*!< connection lifetime */
extern int tcp_socket_backlog;
extern int tcp_max_fd_no;
extern int tcp_max_connections;
extern int tcp_keepalive;
extern int tcp_keepcount;
extern int tcp_keepidle;
extern int tcp_keepinterval;
extern int tcp_max_msg_time;
extern int tcp_no_new_conn;
extern int tcp_no_new_conn_bflag;
extern int tcp_no_new_conn_rplflag;

extern int no_daemon_mode;
extern int debug_mode;
extern int check_via;
extern int received_dns;
extern int sip_warning;
extern int server_signature;
extern str server_header;
extern str user_agent_header;
extern char* user;
extern char* group;
extern char* sock_user;
extern char* sock_group;
extern int sock_uid;
extern int sock_gid;
extern int sock_mode;
extern char* chroot_dir;
extern char* working_dir;

#ifdef USE_MCAST
extern int mcast_loopback;
extern int mcast_ttl;
#endif /* USE_MCAST */

extern int tos;

extern int disable_dns_failover;
extern int disable_dns_blacklist;

extern int cfg_errors;

extern unsigned long shm_mem_size;
extern unsigned int shm_hash_split_percentage;
extern unsigned int shm_hash_split_factor;
extern unsigned int shm_secondary_hash_size;
extern unsigned long pkg_mem_size;

extern int reply_to_via;

extern int is_main;
extern int is_pre_daemon;

extern int memlog;  /*!< debugging level for printing memory debugs */
extern int memdump; /*!< debugging level for dumping memory status */
extern int execmsgthreshold;  /*!< Maximum number of microseconds a SIP msg processing can last
						before triggering Warning log */
extern int execdnsthreshold;
extern int tcpthreshold;
extern int mhomed; /*!< looking up outbound interface ? */

extern int my_argc; /*!< command-line arguments */
extern char **my_argv;

extern str default_global_address; /*!< pre-set addresses */
extern str default_global_port; /*!< pre-ser ports */

extern int disable_core_dump; /*!< core dump limits */
extern int open_files_limit; /*!< file limits */

extern int dns_retr_time; /*!< DNS resolver: Retry time */
extern int dns_retr_no; /*!< DNS resolver : Retry # */
extern int dns_servers_no; /*!< DNS resolver: Server no  */
extern int dns_search_list; /*!< DNS resolver: Search list */

extern int max_while_loops;

extern int sl_fwd_disabled;

extern time_t startup_time;

extern char *db_version_table;
extern char *db_default_url;
extern int db_max_async_connections;

extern int disable_503_translation;

extern int enable_asserts;
extern int abort_on_assert;
#endif
