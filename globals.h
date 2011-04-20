/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

extern char * cfg_file;
extern int config_check;
extern char *stat_file;
extern unsigned short port_no;

extern char* pid_file;
extern char* pgid_file;

extern struct socket_info* bind_address; /*!< pointer to the crt. proc.  listening address */
extern struct socket_info* sendipv4; /*!< ipv4 socket to use when msg.  comes from ipv6*/
extern struct socket_info* sendipv6; /*!< same as above for ipv6 */
#ifdef USE_TCP
extern struct socket_info* sendipv4_tcp; /*!< ipv4 socket to use when msg.  comes from ipv6*/
extern struct socket_info* sendipv6_tcp; /*!< same as above for ipv6 */
extern int unix_tcp_sock; /*!< socket used for communication with tcp main*/
#endif
#ifdef USE_TLS
extern struct socket_info* sendipv4_tls; /*!< ipv4 socket to use when msg.  comes from ipv6*/
extern struct socket_info* sendipv6_tls; /*!< same as above for ipv6 */
#endif
#ifdef USE_SCTP
extern struct socket_info* sendipv4_sctp; /*!< ipv4 socket to use when msg.  comes from ipv6*/
extern struct socket_info* sendipv6_sctp; /*!< same as above for ipv6 */
#endif

extern int auto_aliases;

extern unsigned int maxbuffer;
extern int children_no;
#ifdef USE_TCP
extern int tcp_children_no;
extern int tcp_disable;
extern int tcp_accept_aliases;
extern int tcp_connect_timeout;
extern int tcp_send_timeout;
extern int tcp_con_lifetime; /*!< connection lifetime */
extern enum poll_types tcp_poll_method;
extern int tcp_max_fd_no;
extern int tcp_max_connections;
extern int tcp_crlf_pingpong;
#endif
#ifdef USE_TLS
extern int tls_disable;
extern unsigned short tls_port_no;
#endif
#ifdef USE_SCTP
extern int sctp_disable;
#endif
extern int dont_fork;
extern int check_via;
extern int received_dns;
/* extern int process_no; */
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

extern int reply_to_via;

extern int is_main;

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

extern int disable_503_translation;
#endif
