/*
 * $Id$
 *
 * global variables
 *
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */



#ifndef globals_h
#define globals_h

#include "types.h"
#include "ip_addr.h"
#include "str.h"

#define NO_DNS     0
#define DO_DNS     1
#define DO_REV_DNS 2



extern char * cfg_file;
extern char *stat_file;
extern struct socket_info sock_info[]; /* all addresses we listen/send from*/
extern int sock_no; /* number of addresses/open sockets*/
extern unsigned short port_no;
/*
extern char port_no_str[];
extern int port_no_str_len;
*/
/*
extern char * names[];
extern int names_len[];
extern struct ip_addr addresses[];
extern int addresses_no;
*/
extern struct socket_info* bind_address; /* pointer to the crt. proc.
											listening address */
extern int bind_idx; /* same as above but index in the bound[] array */
extern struct socket_info* sendipv4; /* ipv4 socket to use when msg.
										comes from ipv6*/
extern struct socket_info* sendipv6; /* same as above for ipv6 */

extern unsigned int maxbuffer;
extern int children_no;
extern int dont_fork;
extern int check_via;
extern int received_dns;
extern int syn_branch;
/* extern int process_no; */
extern int sip_warning;
extern int server_signature;
/*
 * debug & log_stderr moved to dprint.h*/

/* extern process_bm_t process_bit; */
/* extern int *pids; -moved to pt.h */

extern int cfg_errors;
extern unsigned int msg_no;

extern unsigned int shm_mem_size;

/* FIFO server config */
char extern *fifo; /* FIFO name */
extern int fifo_mode;

/* moved to pt.h
extern int *pids;
extern int process_no;
*/

extern int reply_to_via;

extern int is_main;

/* debugging level for dumping memory status */
extern int memlog;

#endif
