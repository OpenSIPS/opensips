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
 * \brief Functions for daemonizing on various platforms
 */


#ifndef _daemonize_h
#define _daemonize_h

extern char *startup_wdir;

int daemonize(char* name, int * own_pgid);
int do_suid(const int uid, const int gid);
int set_open_fds_limit(void);
int set_core_dump(int enable, unsigned int size);

int send_status_code(char val);
void clean_read_pipeend(void);
void clean_write_pipeend(void);
int create_status_pipe(void);
int wait_for_one_child(void);
int wait_for_all_children(void);

enum opensips_states {STATE_NONE, STATE_STARTING,
	STATE_RUNNING, STATE_TERMINATING};

void set_osips_state(enum opensips_states);
enum opensips_states get_osips_state(void);

#define report_failure_status() \
	do { \
		if (send_status_code(-1) < 0) \
			LM_ERR("failed to send -1 status code\n"); \
		clean_write_pipeend(); \
	}while(0)

#define report_conditional_status(_cond,_status) \
	do { \
		if ( (_cond) && send_status_code(_status) < 0) \
			LM_ERR("failed to send %d status code\n",_status); \
		clean_write_pipeend(); \
	}while(0)

#endif
