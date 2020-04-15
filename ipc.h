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


typedef short ipc_handler_type;
extern int ipc_shared_fd_read;
#define IPC_TYPE_NONE (-1)
#define ipc_bad_handler_type(htype) ((htype) < 0)

#define IPC_FD_READ(_proc_no)   pt[_proc_no].ipc_pipe[0]
#define IPC_FD_WRITE(_proc_no)  pt[_proc_no].ipc_pipe[1]
#define IPC_FD_READ_SELF        IPC_FD_READ(process_no)
#define IPC_FD_READ_SHARED      ipc_shared_fd_read
#define IPC_FD_SYNC_READ(_proc_no)   pt[_proc_no].ipc_sync_pipe[0]
#define IPC_FD_SYNC_WRITE(_proc_no)  pt[_proc_no].ipc_sync_pipe[1]
#define IPC_FD_SYNC_READ_SELF        IPC_FD_SYNC_READ(process_no)

/* prototype of IPC handler - function called by the IPC engine
 * when the a job with the correspoding type was received */
typedef void (ipc_handler_f)(int sender, void *payload);

/* prototype of a Remotely Executed Function (RPC) via IPC - function
 * to be passed via an IPC job in order to be executed in a different process*/
typedef void (ipc_rpc_f)(int sender, void *param);


/*
 * Register a new IPC handler type, associated with "name" and "hdl".
 * Must be called in the pre-fork phase.
 *
 * Returned value: validate with BAD_HANDLER_TYPE()
 */
ipc_handler_type ipc_register_handler(ipc_handler_f *hdl, char *name);


/*
 * Push a job for "dst_proc" and quickly return
 *
 * Return: 0 on success, -1 on failure
 */
int ipc_send_job(int dst_proc, ipc_handler_type type, void *payload);


/*
 * Push the execution of a function, remotely, on the "dst_proc" process
 * and quickly return
 *
 * Return: 0 on success, -1 on failure
 */
int ipc_send_rpc(int dst_proc, ipc_rpc_f *rpc, void *param);


/*
 * Send a synchronous message to a specific "dst_proc" process
 * Use this command when you are sure that the "dst_proc" is waiting only for
 * this specific "response", and cannot overlap with a different task
 *
 * Return: 0 on success, -1 on failure
 */
int ipc_send_sync_reply(int dst_proc, void *param);


/*
 * Wait for a message sent by a different process synchronously using the
 * ipc_send_sync_reply() function.
 *
 * Return: 0 on success, -1 on failure
 */
int ipc_recv_sync_reply(void **param);


/*
 * Push a job for the next available OpenSIPS worker and quickly return
 *
 * Return: 0 on success, -1 on failure
 */
int ipc_dispatch_job(ipc_handler_type type, void *payload);


/*
 * Push the execution of a function, remotely, to next available OpenSIPS
 * worker process and quickly return
 *
 * Return: 0 on success, -1 on failure
 */
int ipc_dispatch_rpc( ipc_rpc_f *rpc, void *param);


/*
 * default handler for F_IPC reactor jobs. Copy-paste its code and improve
 * if this is not enough for you
 */
void ipc_handle_job(int fd);


/*
 * reads and execute all the jobs available on the pipe, without blocking
 */
void ipc_handle_all_pending_jobs(int fd);


/* internal functions */
int init_ipc(void);


int create_ipc_pipes(int proc_no);


/* required by the IPC PIPE macros */
#include "pt.h"

#endif
