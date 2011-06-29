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
 * \brief Functions for daemonizing on various platforms
 */


#ifndef _daemonize_h
#define _daemonize_h

int daemonize(char* name, int * own_pgid);
int do_suid(const int uid, const int gid);
int increase_open_fds(unsigned int target);
int set_core_dump(int enable, unsigned int size);

int send_status_code(char val);
void clean_write_pipeend(void);
int create_status_pipe(void);
int wait_for_all_children(void);
inline void inc_init_timer(void);
#endif
