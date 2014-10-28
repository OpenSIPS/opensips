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


#ifndef _KILL_H
#define _KILL_H

struct timer_link {
	struct timer_link *next_tl;
	struct timer_link *prev_tl;
	volatile unsigned int time_out;
	int pid;
};

struct timer_list
{
	struct timer_link  first_tl;
	struct timer_link  last_tl;
};

extern unsigned int time_to_kill;

void destroy_kill();
int initialize_kill();
int schedule_to_kill( int pid );

/**
 * __popen - a wrapper function over execvp
 *
 * @cmd:    the command string to be executed
 * @type:   denotes a read-only or write-only stream
 * @stream: stream to be returned to the caller
 */
pid_t __popen(const char *cmd, const char *type, FILE **stream);
pid_t ___popen(const char *cmd, FILE **, FILE**, FILE**);


#endif

