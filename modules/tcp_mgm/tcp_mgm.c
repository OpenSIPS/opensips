/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
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

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../net/tcp_conn_profile.h"

#include "tcp_path.h"
#include "tcp_db.h"
#include "tcp_mi.h"

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

static param_export_t params[] = {
	{"db_url",   STR_PARAM, &tcp_db_url.s},
	{"db_table", STR_PARAM, &tcp_db_table.s},
	{"id_col",              STR_PARAM, &tcp_mgm_cols[0].name.s},
	{"proto_col",           STR_PARAM, &tcp_mgm_cols[1].name.s},
	{"remote_addr_col",	    STR_PARAM, &tcp_mgm_cols[2].name.s},
	{"remote_port_col",	    STR_PARAM, &tcp_mgm_cols[3].name.s},
	{"local_addr_col",      STR_PARAM, &tcp_mgm_cols[4].name.s},
	{"local_port_col",      STR_PARAM, &tcp_mgm_cols[5].name.s},
	{"direction_col",       STR_PARAM, &tcp_mgm_cols[6].name.s},
	{"priority_col",        STR_PARAM, &tcp_mgm_cols[7].name.s},
	{"connect_timeout_col", STR_PARAM, &tcp_mgm_cols[8].name.s},
	{"con_lifetime_col",    STR_PARAM, &tcp_mgm_cols[9].name.s},
	{"msg_read_timeout_col",STR_PARAM, &tcp_mgm_cols[10].name.s},
	{"send_threshold_col",  STR_PARAM, &tcp_mgm_cols[11].name.s},
	{"no_new_conn_col",     STR_PARAM, &tcp_mgm_cols[12].name.s},
	{"alias_mode_col",      STR_PARAM, &tcp_mgm_cols[13].name.s},
	{"keepalive_col",       STR_PARAM, &tcp_mgm_cols[14].name.s},
	{"keepcount_col",       STR_PARAM, &tcp_mgm_cols[15].name.s},
	{"keepidle_col",        STR_PARAM, &tcp_mgm_cols[16].name.s},
	{"keepinterval_col",    STR_PARAM, &tcp_mgm_cols[17].name.s},
	{0, 0, 0}
};

static cmd_export_t cmds[] = {
	{0,0,{{0,0,0}},0}
};

/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
	{ "tcp_reload", "re-cache all TCP profiles from the database", 0, 0, {
		{tcp_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	//{ "tcp_list_profiles", "list all cached TCP profiles", 0, 0, {
	//	{tcp_list_profiles, {0}},
	//	{EMPTY_MI_RECIPE}}
	//},
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

struct module_exports exports = {
	"tcp_mgm",       /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	NULL,            /* exported async functions */
	params,          /* module parameters */
	NULL,            /* exported statistics */
	mi_cmds,         /* exported MI functions */
	NULL,            /* exported pseudo-variables */
	NULL,			 /* exported transformations */
	NULL,            /* extra processes */
	NULL,            /* module pre-initialization function */
	mod_init,        /* module initialization function */
	NULL,            /* response function */
	mod_destroy,     /* destroy function */
	child_init,      /* per-child init function */
	NULL             /* reload confirm function */
};


static int mod_init(void)
{
	int i;

	init_db_url(tcp_db_url, 0);
	tcp_db_table.len = strlen(tcp_db_table.s);

	for (i = 0; i < NO_DB_COLS; i++)
		tcp_mgm_cols[i].name.len = strlen(tcp_mgm_cols[i].name.s);

	if (!tcp_path_init()) {
		LM_ERR("failed to init internal structures\n");
		return -1;
	}

	/* cache all DB data straight away */
	if (!tcp_db_init()) {
		LM_ERR("failed to initialize and/or load DB data\n");
		return -1;
	}

	tcp_con_get_profile = tcp_mgm_get_profile;
	LM_INFO("successfully installed our callback in the TCP core\n");
	return 0;
}


static int child_init(int rank)
{
	if (!(is_worker_proc(rank) || rank == PROC_MODULE))
		return 0;

	/* init DB connection */
	if (!(db_hdl = db.init(&tcp_db_url))) {
		LM_ERR("failed to initialize database connection\n");
		return -1;
	}

	return 0;
}


static void mod_destroy(void)
{
	tcp_path_destroy();
}
