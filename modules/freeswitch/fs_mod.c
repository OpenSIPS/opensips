/*
 * Client for the FreeSWITCH ESL (Event Socket Layer)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2017-01-19 initial version (liviu)
 */

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../mod_fix.h"
#include "../../parser/msg_parser.h"

#include "fs_api.h"

static int mod_init(void);

static cmd_export_t cmds[] = {
	{ "fs_bind", (cmd_function)fs_bind, 1, NULL, NULL, 0 },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{ 0,0,0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"mid_registrar",        /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	NULL,               /* exported async functions */
	mod_params,      /* param exports */
	NULL,       /* exported statistics */
	NULL,         /* exported MI functions */
	NULL,       /* exported pseudo-variables */
	NULL,               /* extra processes */
	mod_init,        /* module initialization function */
	NULL,               /* reply processing function */
	NULL,
	NULL       /* per-child init function */
};

static int mod_init(void)
{
	
	return 0;
}

int fs_bind(fs_api_t *fapi)
{
	return 0;
}
