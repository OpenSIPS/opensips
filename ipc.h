/*
 * Copyright (C) 2017 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#ifndef _CORE_IPC_H
#define _CORE_IPC_H

#include "pt.h"

typedef struct _ipc_job {
	/* the ID (internal) of the process sending the job */
	int snd_proc;
	/* the type pf the job */
	int type;
	/* the payload of the job, just a pointer */
	void *payload;
} ipc_job;



#define IPC_FD_READ(_proc_no)   pt[_proc_no].ipc_pipe[0]
#define IPC_FD_WRITE(_proc_no)  pt[_proc_no].ipc_pipe[1]
#define IPC_FD_READ_SELF        IPC_FD_READ(process_no)

typedef void (ipc_handler_f)(int sender, void *payload);

int ipc_register_handler( ipc_handler_f *hdl, char *name);

int ipc_send_job(int dst_proc, int type, void *payload);

void ipc_handle_job(void);

#endif

