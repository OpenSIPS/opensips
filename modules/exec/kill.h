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
 * __popen3 - a wrapper function over execl
 *
 * @cmd:    the command string to be executed
 * @strm_w: stream to STDIN of cmd process
 * @strm_r: stream to STDOUT of cmd process
 * @strm_w: stream to STDERR of cmd process
 */
pid_t __popen3(const char *cmd, FILE **strm_w, FILE** strm_r, FILE** strm_e);


#endif

