/*
 * Inter-process communication primitives
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __FS_IPC__
#define __FS_IPC__

#include "fs_api.h"

typedef struct _fs_ipc_esl_cmd {
	fs_evs *sock;
	str fs_cmd;
	unsigned long esl_reply_id;
} fs_ipc_esl_cmd;

typedef struct _fs_ipc_esl_event {
	fs_evs *sock;
	str name;
	char *body;
} fs_ipc_esl_event;

int fs_ipc_init(void);
unsigned long fs_ipc_send_esl_cmd(fs_evs *sock, const str *fs_cmd);
int fs_ipc_dispatch_esl_event(fs_evs *sock, const str *name,
                              const char *body, ipc_handler_type ipc_type);

#endif /* __FS_IPC__ */
