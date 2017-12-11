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

#ifndef __FSS_API__
#define __FSS_API__

#include "../../sr_module.h"
#include "../../ipc.h"

typedef ipc_handler_type (*get_ipc_dispatch_hdl_type_f) (void);

struct fss_binds {
	get_ipc_dispatch_hdl_type_f get_ipc_dispatch_hdl_type;
};

typedef int (*bind_fss_f) (struct fss_binds *fss_api);
int fss_bind(struct fss_binds *fss_api);

static inline int load_fss_api(struct fss_binds *fss_api)
{
	bind_fss_f bind_fss;

	bind_fss = (bind_fss_f)find_export("fss_bind", 0, 0);
	if (!bind_fss) {
		LM_DBG("failed to find bind_fss\n");
		return -1;
	}

	if (bind_fss(fss_api) == -1)
		return -1;

	return 0;
}

#endif /* __FSS_API__ */
