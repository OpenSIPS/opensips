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

#include "fs_ipc.h"

#include "../../dprint.h"
#include "../../ut.h"
#include "../../ipc.h"

static ipc_handler_type ipc_hdl_run_esl;

extern void fs_run_esl_command(int sender, void *fs_cmd);

extern unsigned int *conn_mgr_process_no;

int fs_ipc_init(void)
{
	LM_DBG("registering IPC handler\n");

	ipc_hdl_run_esl = ipc_register_handler(fs_run_esl_command, "Run FS esl");
	if (ipc_bad_handler_type(ipc_hdl_run_esl)) {
		LM_ERR("failed to register 'Run FS esl' IPC handler\n");
		return -1;
	}

	return 0;
}

int fs_ipc_dispatch_esl_event(fs_evs *sock, const str *name,
                              const char *body, ipc_handler_type ipc_type)
{
	fs_ipc_esl_event *cmd;

	cmd = shm_malloc(sizeof *cmd);
	if (!cmd)
		goto out_oom;
	memset(cmd, 0, sizeof *cmd);

	cmd->sock = sock;
	if (shm_nt_str_dup(&cmd->name, name) != 0) {
		goto out_oom;
	}

	cmd->body = shm_strdup(body);
	if (!cmd->body) {
		shm_free(cmd->name.s);
		goto out_oom;
	}

	return ipc_dispatch_job(ipc_type, cmd);

out_oom:
	shm_free(cmd);
	LM_ERR("oom\n");
	return -1;
}


/*
 * Returned values:
 *  > 0 (success): a FS esl reply id to wait for
 *    0 (failure): internal error
 */
unsigned long fs_ipc_send_esl_cmd(fs_evs *sock, const str *fs_cmd)
{
	fs_ipc_esl_cmd *cmd;
	unsigned long esl_reply_id;

	cmd = shm_malloc(sizeof *cmd);
	if (!cmd) {
		LM_ERR("oom\n");
		return 0;
	}
	memset(cmd, 0, sizeof *cmd);

	cmd->sock = sock;

	lock_start_write(sock->lists_lk);
	cmd->esl_reply_id = sock->esl_reply_id++;
	lock_stop_write(sock->lists_lk);

	if (shm_nt_str_dup(&cmd->fs_cmd, fs_cmd) != 0) {
		shm_free(cmd);
		LM_ERR("oom\n");
		return 0;
	}

	esl_reply_id = cmd->esl_reply_id;

	if (ipc_send_job(*conn_mgr_process_no, ipc_hdl_run_esl, cmd) != 0) {
		/* we failed to send a pointer -> partial writes are ok -> free it */
		shm_free(cmd->fs_cmd.s);
		shm_free(cmd);
		LM_ERR("IPC send failed\n");
		return 0;
	}

	return esl_reply_id;
}
