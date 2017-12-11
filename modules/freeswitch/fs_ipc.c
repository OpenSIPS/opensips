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
#include "../freeswitch_scripting/fss_api.h"

#include "../../dprint.h"
#include "../../ipc.h"

static ipc_handler_type ipc_hdl_run_cli;
static struct fss_binds fss_api;

void fs_ipc_run_cli(int sender, void *payload);

int fs_ipc_init(void)
{
	ipc_hdl_run_cli = ipc_register_handler(fs_ipc_run_cli, "Run FS cli");
	if (ipc_bad_handler_type(ipc_hdl_run_cli)) {
		LM_ERR("failed to register 'Run FS cli' IPC handler\n");
		return -1;
	}

	/* just a soft dependency */
	if (load_fss_api(&fss_api) != 0)
		LM_DBG("failed to find freeswitch_scripting module\n");

	return 0;
}

int fs_ipc_dispatch_esl_event(fs_ipc_esl_event *fs_event)
{
	return ipc_dispatch_job(fss_api.get_ipc_dispatch_hdl_type(), fs_event);
}

void fs_ipc_run_cli(int sender, void *fs_event)
{

}
