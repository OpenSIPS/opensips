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

#ifndef __FSS_IPC__
#define __FSS_IPC__

#include "../../ipc.h"

typedef struct _fss_ipc_cli_cmd {
	char *content;
} fss_ipc_cli_cmd;

int fss_ipc_init(void);
int fs_ipc_send_cli_cmd(fss_ipc_cli_cmd *fs_cmd);

#endif /* __FSS_IPC__ */
