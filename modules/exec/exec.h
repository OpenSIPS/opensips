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

#ifndef _EXEC_H
#define _EXEC_H

#include "../../pvar.h"
#include "../../locking.h"

typedef struct _exec_cmd {
	char *cmd;
	str input;
	int pid;
	struct _exec_cmd *next;
} exec_cmd_t;

typedef struct _exec_list {
	int active_childs;
	gen_lock_t *lock;
	exec_cmd_t *first, *last;
} exec_list_t, *exec_list_p;

typedef struct _exec_async_param {
	pv_spec_t *outvar;
	char *buf;
	int buf_len;
} exec_async_param;

/* list head */
extern exec_list_p exec_async_list;

/* process that waits for asynchronous executions */
void exec_async_proc(int rank);
int exec_async(struct sip_msg *msg, char *cmd, str* input );

int exec_sync(struct sip_msg* msg, str* command, str* input,
		pv_spec_t *outvar, pv_spec_t *errvar);
int start_async_exec(struct sip_msg* msg, str* command, str* input,
		pv_spec_t *outvar, int *fd);
int resume_async_exec(int fd, struct sip_msg *msg, void *param);

#endif

