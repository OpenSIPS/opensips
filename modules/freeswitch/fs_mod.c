/*
 * Driver and API to command and control FreeSWITCH ESL connections
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

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../mod_fix.h"
#include "../../parser/msg_parser.h"
#include "../../mem/mem.h"
#include "../../lib/osips_malloc.h"
#include "../../lib/csv.h"
#include "../../lib/url.h"
#include "../../lib/list.h"

#include "fs_api.h"
#include "fs_proc.h"
#include "fs_ipc.h"

/* this correlates with FreeSWITCH's "event-heartbeat-interval" setting,
 * located in autoload_configs/switch.conf.xml. The default there is 20s,
 * but we're using a more granular value, just to be on the safe side */
unsigned int event_heartbeat_interval = 1; /* s */
unsigned int fs_connect_timeout = 5000;    /* ms */
unsigned int esl_cmd_timeout = 5000;       /* ms */
unsigned int esl_cmd_polling_itv = 1000;   /* us */

static int mod_init(void);

extern int fs_api_init(void);
int fs_api_wait_init(void);

static cmd_export_t cmds[] = {
	{"fs_bind", (cmd_function)fs_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[] = {
	{"event_heartbeat_interval", INT_PARAM,         &event_heartbeat_interval},
	{"esl_connect_timeout",      INT_PARAM,               &fs_connect_timeout},
	{"esl_cmd_timeout",          INT_PARAM,                  &esl_cmd_timeout},
	{"esl_cmd_polling_itv",      INT_PARAM,              &esl_cmd_polling_itv},
	{0, 0, 0}
};

static proc_export_t procs[] = {
	{ "FS Manager", NULL, fs_api_wait_init, fs_conn_mgr_loop, 1,
		PROC_FLAG_HAS_IPC },
	{ 0, 0, 0, 0, 0, 0 },
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
	"freeswitch",     /* module's name */
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,				  /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	NULL,             /* exported async functions */
	mod_params,       /* param exports */
	NULL,             /* exported statistics */
	NULL,             /* exported MI functions */
	NULL,             /* exported pseudo-variables */
	NULL,			 	  /* exported transformations */
	procs,            /* extra processes */
	0,                /* module pre-initialization function */
	mod_init,         /* module initialization function */
	NULL,             /* reply processing function */
	NULL,
	NULL,             /* per-child init function */
	NULL              /* reload confirm function */
};

static int mod_init(void)
{
	cJSON_Hooks hooks;

	if (fs_ipc_init() != 0) {
		LM_ERR("failed to init IPC, oom?\n");
		return -1;
	}

	if (fs_api_init() != 0) {
		LM_ERR("failed to init API internals, oom?\n");
		return -1;
	}

	hooks.malloc_fn = osips_pkg_malloc;
	hooks.free_fn = osips_pkg_free;
	cJSON_InitHooks(&hooks);

	return 0;
}
