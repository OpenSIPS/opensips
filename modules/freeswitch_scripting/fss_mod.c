/*
 * Script and MI utilities for custom FreeSWITCH interactions
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
#include "../../str.h"
#include "../../lib/url.h"
#include "../../ipc.h"

#include "fss_api.h"
#include "fss_ipc.h"
#include "fss_evs.h"

static int mod_init(void);

static int fs_cli(struct sip_msg *msg, char *cmd, char *url);
static int modparam_sub_evs(modparam_t type, void *string);

struct mi_root *mi_fs_subscribe(struct mi_root *cmd, void *param);
struct mi_root *mi_fs_unsubscribe(struct mi_root *cmd, void *param);
struct mi_root *mi_fs_reload(struct mi_root *cmd, void *param);

static cmd_export_t cmds[] = {
	{ "fss_bind", (cmd_function)fss_bind, 1, NULL, NULL,          0 },
	{ "fs_cli", (cmd_function)fs_cli,     2, NULL, NULL, ALL_ROUTES },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{ "fs_subscribe",           STR_PARAM|USE_FUNC_PARAM,   modparam_sub_evs },
	{ 0, 0, 0 }
};

static mi_export_t mi_cmds[] = {
	{ "fs_subscribe",       0, mi_fs_subscribe,   0,  0,  0 },
	{ "fs_unsubscribe",     0, mi_fs_unsubscribe, 0,  0,  0 },
	{ "fs_reload",          0, mi_fs_reload,      0,  0,  0 },
	{ 0, 0, 0, 0, 0, 0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "freeswitch", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"freeswitch_scripting",     /* module's name */
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	NULL,             /* exported async functions */
	mod_params,       /* param exports */
	NULL,             /* exported statistics */
	mi_cmds,             /* exported MI functions */
	NULL,             /* exported pseudo-variables */
	NULL,             /* exported transformations */
	NULL,             /* extra processes */
	mod_init,         /* module initialization function */
	NULL,             /* reply processing function */
	NULL,
	NULL              /* per-child init function */
};

static int mod_init(void)
{
	if (fss_ipc_init() != 0) {
		LM_ERR("failed to init IPC\n");
		return -1;
	}

	if (load_fs_api(&fs_api) != 0) {
		LM_ERR("failed to load the FreeSWITCH API - is freeswitch loaded?\n");
		return -1;
	}

	return 0;
}

static int modparam_sub_evs(modparam_t type, void *string)
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

static int fs_cli(struct sip_msg *msg, char *cmd, char *url)
{
	return 0;
}

struct mi_root *mi_fs_subscribe(struct mi_root *cmd, void *param)
{
	return NULL;
}

struct mi_root *mi_fs_unsubscribe(struct mi_root *cmd, void *param)
{
	return NULL;
}

struct mi_root *mi_fs_reload(struct mi_root *cmd, void *param)
{
	return NULL;
}
