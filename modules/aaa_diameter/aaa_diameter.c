/**
 * Copyright (C) 2021 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <freeDiameter/extension.h>

#include "../../sr_module.h"

#include "aaa_impl.h"
#include "peer.h"

int mod_init(void);
void mod_destroy(void);

extern struct fifo * fd_g_outgoing;

int aaa_diameter_bind_api(aaa_prot *api);

int fd_log_level = FD_LOG_NOTICE;

static cmd_export_t cmds[]= {
	{"aaa_bind_api", (cmd_function) aaa_diameter_bind_api, {{0, 0, 0}}, 0},
	{0,0,{{0,0,0}},0}
};

static proc_export_t procs[] = {
	{ "diameter-peer", NULL, NULL, diameter_peer_loop, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 },
};

static param_export_t params[] =
{
	{ "fd_log_level",          INT_PARAM, &fd_log_level         },
	{ NULL, 0, NULL },
};

static mi_export_t mi_cmds[] = {
	{ "fd_log_level", 0, 0, 0, {
		{NULL, {"log_level", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports =
{
	"aaa_diameter",   /* module's name */
	MOD_TYPE_AAA,     /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	NULL,             /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	NULL,             /* exported async functions */
	params,           /* param exports */
	NULL,             /* exported statistics */
	mi_cmds,          /* exported MI functions */
	NULL,             /* exported pseudo-variables */
	NULL,             /* exported transformations */
	procs,            /* extra processes */
	NULL,             /* module pre-initialization function */
	mod_init,         /* module initialization function */
	NULL,             /* reply processing function */
	mod_destroy,      /* shutdown function */
	NULL,             /* per-child init function */
	NULL              /* reload confirm function */
};


int mod_init(void)
{
	LM_DBG("initializing module...\n");

	return 0;
}


void mod_destroy(void)
{
	int rc;

	rc = fd_core_shutdown();
	LM_DBG("libfdcore shutdown, rc: %d\n", rc);
}


int aaa_diameter_bind_api(aaa_prot *api)
{
	if (!api)
		return -1;

	memset(api, 0, sizeof *api);

	api->create_aaa_message = dm_create_message;
	api->destroy_aaa_message = dm_destroy_message;
	api->send_aaa_request = dm_send_message;
	api->init_prot = NULL;
	api->dictionary_find = NULL;
	api->avp_add = dm_avp_add;
	api->avp_get = NULL;

	return 0;
}
