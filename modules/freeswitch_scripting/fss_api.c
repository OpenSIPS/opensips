/*
 * Minimal API which exposes the "Receive FS event" IPC job type
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

#include "fss_api.h"

extern ipc_handler_type ipc_hdl_rcv_event;

ipc_handler_type get_ipc_dispatch_hdl_type(void)
{
	return ipc_hdl_rcv_event;
}

int fss_bind(struct fss_binds *fss_api)
{
	memset(fss_api, 0, sizeof *fss_api);

	fss_api->get_ipc_dispatch_hdl_type = get_ipc_dispatch_hdl_type;

	return 0;
}
