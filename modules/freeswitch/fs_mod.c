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
#include "../../mem/mem.h"
#include "../../lib/osips_malloc.h"
#include "../../lib/csv.h"
#include "../../lib/url.h"

#include "fs_api.h"
#include "fs_proc.h"

extern struct list_head *fs_boxes;
extern rw_lock_t *box_lock;

/* this correlates with FreeSWITCH's "event-heartbeat-interval" param,
 * located in autoload_configs/switch.conf.xml. The default there is 20s,
 * but we're using a more granular default, just to be on the safe side */
int event_heartbeat_interval = 1;

static int mod_init(void);

int fs_bind(struct fs_binds *fapi);
int modparam_sub_evs(modparam_t type, void *string);

static cmd_export_t cmds[] = {
	{ "fs_bind", (cmd_function)fs_bind, 1, NULL, NULL, 0 },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{"event_heartbeat_interval", INT_PARAM, &event_heartbeat_interval},
	{"fs_subscribe",      STR_PARAM|USE_FUNC_PARAM, modparam_sub_evs },
	{0, 0, 0}
};

static proc_export_t procs[] = {
	{ "fs_stats", NULL, NULL, fs_stats_loop, 1, 0 },
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
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	NULL,             /* exported async functions */
	mod_params,       /* param exports */
	NULL,             /* exported statistics */
	NULL,             /* exported MI functions */
	NULL,             /* exported pseudo-variables */
	NULL,			 	  /* exported transformations */
	procs,            /* extra processes */
	mod_init,         /* module initialization function */
	NULL,             /* reply processing function */
	NULL,
	NULL              /* per-child init function */
};

static int mod_init(void)
{
	cJSON_Hooks hooks;

	fs_boxes = shm_malloc(sizeof *fs_boxes);
	if (!fs_boxes) {
		LM_ERR("out of mem\n");
		return -1;
	}
	INIT_LIST_HEAD(fs_boxes);

	box_lock = shm_malloc(sizeof *box_lock);
	if (!box_lock) {
		LM_ERR("out of mem\n");
		return -1;
	}

	box_lock = lock_init_rw();

	hooks.malloc_fn = osips_pkg_malloc;
	hooks.free_fn = osips_pkg_free;
	cJSON_InitHooks(&hooks);

	return 0;
}

int modparam_sub_evs(modparam_t type, void *string)
{
	struct url *url;
	str st = {string, strlen(string)};

	url = parse_url(&st, URL_REQ_SCHEME|URL_REQ_PASS, 0);
	if (!url) {
		LM_ERR("failed to parse FS URL '%.*s'\n", st.len, st.s);
		return 0;
	}

	print_url(url);

	return 0;
}
