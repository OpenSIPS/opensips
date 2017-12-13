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

#include "../../dprint.h"
#include "../freeswitch/fs_ipc.h"

#include "fss_ipc.h"

ipc_handler_type ipc_hdl_rcv_event;

void fss_ipc_rcv_event(int sender, void *fs_event);

int fss_ipc_init(void)
{
	ipc_hdl_rcv_event = ipc_register_handler(fss_ipc_rcv_event,
	                                         "Receive FS event");
	if (ipc_bad_handler_type(ipc_hdl_rcv_event)) {
		LM_ERR("failed to register 'Receive FS event' IPC handler\n");
		return -1;
	}

	return 0;
}

void fss_ipc_rcv_event(int sender, void *fs_event)
{

}

