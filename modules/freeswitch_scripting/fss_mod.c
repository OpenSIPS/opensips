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
#include "../../ut.h"
#include "../../mod_fix.h"

#include "../freeswitch/fs_api.h"
#include "fss_api.h"
#include "fss_ipc.h"
#include "fss_evs.h"

static int mod_init(void);

static int fs_cli(struct sip_msg *msg, char *cmd, char *url, char *out_pv);
static int fixup_fs_cli(void **param, int param_no);

static int fs_sub_add_url(modparam_t type, void *string);

struct mi_root *mi_fs_subscribe(struct mi_root *cmd, void *param);
struct mi_root *mi_fs_unsubscribe(struct mi_root *cmd, void *param);
struct mi_root *mi_fs_reload(struct mi_root *cmd, void *param);

static cmd_export_t cmds[] = {
	{ "fss_bind", (cmd_function)fss_bind, 1, NULL,            NULL,          0 },
	{ "fs_cli", (cmd_function)fs_cli,     2, fixup_fs_cli, NULL, ALL_ROUTES },
	{ "fs_cli", (cmd_function)fs_cli,     3, fixup_fs_cli, NULL, ALL_ROUTES },
	{ NULL, NULL, 0, NULL, NULL, 0 }
};

static param_export_t mod_params[] = {
	{ "fs_subscribe",           STR_PARAM|USE_FUNC_PARAM,   fs_sub_add_url },
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

/* temporarily dup the URL modparams in shm until mod_init() runs */
struct list_head startup_fs_subs;
static int fs_sub_add_url(modparam_t type, void *string)
{
	struct str_dlist *strl;
	str url = {string, strlen(string)};

	if (!startup_fs_subs.next)
		INIT_LIST_HEAD(&startup_fs_subs);

	strl = shm_malloc(sizeof *strl);
	if (!strl) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(strl, 0, sizeof *strl);

	if (shm_str_dup(&strl->s, &url) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	list_add_tail(&strl->list, &startup_fs_subs);

	return 0;
}

static int mod_init(void)
{
	if (fss_ipc_init() != 0) {
		LM_ERR("failed to init IPC\n");
		return -1;
	}

	fss_sockets = shm_malloc(sizeof *fss_sockets);
	if (!fss_sockets) {
		LM_ERR("oom\n");
		return -1;
	}
	INIT_LIST_HEAD(fss_sockets);

	if (load_fs_api(&fs_api) != 0) {
		LM_ERR("failed to load the FreeSWITCH API - is freeswitch loaded?\n");
		return -1;
	}

	if (subscribe_to_fs_urls(&startup_fs_subs) != 0)
		LM_ERR("ignored one or more broken FS URL modparams (or oom!)\n");

	free_shm_str_dlist(&startup_fs_subs);

	return 0;
}

static int fixup_fs_cli(void **param, int param_no)
{
	switch (param_no) {
	case 1:
	case 2:
		return fixup_spve(param);
	case 3:
		return fixup_pvar(param);
	default:
		LM_BUG("fs_cli() called with > 3 params!\n");
		return -1;
	}
}

static int fs_cli(struct sip_msg *msg, char *cmd_gp, char *url_gp,
                  char *reply_pvs)
{
	fs_evs *sock;
	pv_value_t reply_val;
	str url, cmd, reply;
	int ret = 0;

	if (fixup_get_svalue(msg, (gparam_p)cmd_gp, &cmd) != 0) {
		LM_ERR("failed to print cmd parameter!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)url_gp, &url) != 0) {
		LM_ERR("failed to print url parameter!\n");
		return -1;
	}

	sock = fs_api.get_evs_by_url(&url);
	if (!sock) {
		LM_ERR("failed to get a socket for FS URL %.*s\n", url.len, url.s);
		return -1;
	}

	LM_DBG("running '%.*s' on %s:%d\n", cmd.len, cmd.s,
	       sock->host.s, sock->port);

	if (fs_api.fs_cli(sock, &cmd, &reply) != 0) {
		LM_ERR("failed to run fs_cli cmd '%*s.' on %s:%d\n", cmd.len, cmd.s,
		       sock->host.s, sock->port);
		ret = -1;
		goto out;
	}

	LM_DBG("success, output is: '%.*s'\n", reply.len, reply.s);

	reply_val.flags = PV_VAL_STR;
	reply_val.rs = reply;

	if (pv_set_value(msg, (pv_spec_p)reply_pvs, 0, &reply_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		ret = -1;
	}

out:
	if (reply.s)
		shm_free(reply.s);
	fs_api.put_evs(sock);
	return ret;
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
