/*
 * Copyright (C) 2021 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _CORE_REACTOR_PROC
#define _CORE_REACTOR_PROC

/* This is a framework that allows the custom processes (requested by the
 * module) to use an I/O reactor for FD management. Beside re-usage, this also
 * helps with IPC support - this framework also comes (transparent for the
 * customer process) with IPC support - this will ensure a better integration
 * of this process into OpenSIPS, as the IPC will allow the access to 
 * load and pkg stats, will allow running scripting and proper shutdown.
 */

#define REACTOR_PROC_TIMEOUT  1

typedef int (*reactor_proc_cb_f) (int fd, void *param, int was_timeout);

struct reactor_proc_cb {
	reactor_proc_cb_f func;
	void *param;
};

int reactor_proc_init(char *name);

int reactor_proc_add_fd(int fd, reactor_proc_cb_f func, void *param);

int reactor_proc_loop(void);

#endif
