/*
 * Copyright (C) 2007-2008 1&1 Internet AG
 *
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
 */

/**
 * @file carrierroute.c
 * @brief Contains the functions exported by the module.
 */

#include "../../sr_module.h"
#include "../../str.h"
#include "../../dset.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../../error.h"
#include "../../prime_hash.h"
#include "../../db/db.h"
#include "carrierroute.h"
#include "load_data.h"
#include "route_fifo.h"
#include "carrier_tree.h"
#include "route_func.h"


str db_url = {NULL, 0};
str db_table = str_init("carrierroute");
str db_failure_table = str_init("carrierfailureroute");
str subscriber_table = str_init("subscriber");
str carrier_table = str_init("route_tree");

static str id_col = str_init("id");
static str carrier_col = str_init("carrier");
static str domain_col = str_init("domain");
static str scan_prefix_col = str_init("scan_prefix");
static str flags_col = str_init("flags");
static str mask_col = str_init("mask");
static str prob_col = str_init("prob");
static str rewrite_host_col = str_init("rewrite_host");
static str strip_col = str_init("strip");
static str rewrite_prefix_col = str_init("rewrite_prefix");
static str rewrite_suffix_col = str_init("rewrite_suffix");
static str comment_col = str_init("description");
static str username_col = str_init("username");
static str cr_preferred_carrier_col = str_init("cr_preferred_carrier");
static str subscriber_domain_col = str_init("domain");
static str carrier_id_col = str_init("id");
static str carrier_name_col = str_init("carrier");
static str failure_id_col = str_init("id");
static str failure_carrier_col = str_init("carrier");
static str failure_domain_col = str_init("domain");
static str failure_scan_prefix_col = str_init("scan_prefix");
static str failure_host_name_col = str_init("host_name");
static str failure_reply_code_col = str_init("reply_code");
static str failure_flags_col = str_init("flags");
static str failure_mask_col = str_init("mask");
static str failure_next_domain_col = str_init("next_domain");
static str failure_comment_col = str_init("description");


str * columns[COLUMN_NUM] = {
	&id_col,
	&carrier_col,
	&domain_col,
	&scan_prefix_col,
	&flags_col,
	&mask_col,
	&prob_col,
	&rewrite_host_col,
	&strip_col,
	&rewrite_prefix_col,
	&rewrite_suffix_col,
	&comment_col,
};

str * subscriber_columns[SUBSCRIBER_COLUMN_NUM] = {
	&username_col,
	&domain_col,
	&cr_preferred_carrier_col,
};

str * carrier_columns[CARRIER_COLUMN_NUM] = {
	&id_col,
	&carrier_col,
};

str * failure_columns[FAILURE_COLUMN_NUM] = {
	&failure_id_col,
	&failure_carrier_col,
	&failure_domain_col,
	&failure_scan_prefix_col,
	&failure_host_name_col,
	&failure_reply_code_col,
	&failure_flags_col,
	&failure_mask_col,
	&failure_next_domain_col,
	&failure_comment_col
};

char * config_source = "file";
char * config_file = CFG_DIR"carrierroute.conf";

str default_tree = str_init("default");
const str SP_EMPTY_PREFIX = str_init("null");

int mode = 0;
int use_domain = 0;

int fallback_default = 1;


/************* Declaration of Interface Functions **************************/
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);
static int fixup_check_avp(void ** param);
static int domain_fixup(void ** param);
static int carrier_fixup(void ** param);
static int hash_fixup(void ** param);


/************* Module Exports **********************************************/
static cmd_export_t cmds[]={
	{"cr_user_carrier",          (cmd_function)cr_load_user_carrier, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"cr_route",                 (cmd_function)cr_route, {
		{CMD_PARAM_STR, carrier_fixup, 0},
		{CMD_PARAM_STR, domain_fixup, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR, hash_fixup, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"cr_prime_route",                 (cmd_function)cr_prime_route, {
		{CMD_PARAM_STR, carrier_fixup, 0},
		{CMD_PARAM_STR, domain_fixup, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR, hash_fixup, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{"cr_next_domain",                 (cmd_function)cr_load_next_domain, {
		{CMD_PARAM_STR, carrier_fixup, 0},
		{CMD_PARAM_STR, domain_fixup, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE | FAILURE_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[]= {
	{"db_url",                     STR_PARAM, &db_url.s },
	{"db_table",                   STR_PARAM, &db_table.s },
	{"db_failure_table",           STR_PARAM, &db_failure_table.s },
	{"carrier_table",              STR_PARAM, &carrier_table.s },
	{"subscriber_table",           STR_PARAM, &subscriber_table.s },
	{"id_column",                  STR_PARAM, &id_col.s },
	{"carrier_column",             STR_PARAM, &carrier_col.s },
	{"domain_column",              STR_PARAM, &domain_col.s },
	{"scan_prefix_column",         STR_PARAM, &scan_prefix_col.s },
	{"flags_column",               STR_PARAM, &flags_col.s },
	{"mask_column",                STR_PARAM, &mask_col.s },
	{"prob_column",                STR_PARAM, &prob_col.s },
	{"rewrite_host_column",        STR_PARAM, &rewrite_host_col.s },
	{"strip_column",               STR_PARAM, &strip_col.s },
	{"rewrite_prefix_column",      STR_PARAM, &rewrite_prefix_col.s },
	{"rewrite_suffix_column",      STR_PARAM, &rewrite_suffix_col.s },
	{"comment_column",             STR_PARAM, &comment_col.s },
	{"failure_id_column",          STR_PARAM, &failure_id_col.s },
	{"failure_carrier_column",     STR_PARAM, &failure_carrier_col.s },
	{"failure_domain_column",      STR_PARAM, &failure_domain_col.s },
	{"failure_scan_prefix_column", STR_PARAM, &failure_scan_prefix_col.s },
	{"failure_host_name_column",   STR_PARAM, &failure_host_name_col.s },
	{"failure_reply_code_column",  STR_PARAM, &failure_reply_code_col.s },
	{"failure_flags_column",       STR_PARAM, &failure_flags_col.s },
	{"failure_mask_column",        STR_PARAM, &failure_mask_col.s },
	{"failure_next_domain_column", STR_PARAM, &failure_next_domain_col.s },
	{"failure_comment_column",     STR_PARAM, &failure_comment_col.s },
	{"subscriber_user_col",        STR_PARAM, &username_col.s },
	{"subscriber_domain_col",      STR_PARAM, &subscriber_domain_col.s },
	{"subscriber_carrier_col",     STR_PARAM, &cr_preferred_carrier_col.s },
	{"carrier_id_col",             STR_PARAM, &carrier_id_col.s },
	{"carrier_name_col",           STR_PARAM, &carrier_name_col.s },
	{"config_source",              STR_PARAM, &config_source },
	{"default_tree",               STR_PARAM, &default_tree.s },
	{"config_file",                STR_PARAM, &config_file },
	{"use_domain",                 INT_PARAM, &use_domain },
	{"fallback_default",           INT_PARAM, &fallback_default },
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ "cr_reload_routes", 0, 0, 0, {
		{reload_fifo, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cr_dump_routes", 0, 0, 0, {
		{dump_fifo, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cr_replace_host", 0, 0, 0, {
		{replace_host, {"options", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cr_deactivate_host", 0, 0, 0, {
		{deactivate_host, {"options", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cr_activate_host", 0, 0, 0, {
		{activate_host, {"options", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cr_add_host", 0, 0, 0, {
		{add_host, {"options", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cr_delete_host", 0, 0, 0, {
		{delete_host, {"options", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"carrierroute",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version*/
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Export parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* Module pre-initialization function */
	mod_init,   /* Module initialization function */
	0,          /* Response function */
	mod_destroy,/* Destroy function */
	child_init, /* Child initialization function */
	0           /* reload confirm function */
};


/************* Helper Functions ********************************************/

/**
 * Fixes the hash source to enum values
 *
 * @param my_hash_source the hash source as string
 *
 * @return the enum value on success, -1 on failure
 */
static int hash_fixup(void ** param)
{
	static str cid_s = str_init("call_id");
	static str fr_s = str_init("from_uri");
	static str fu_s = str_init("from_user");
	static str tr_s = str_init("to_uri");
	static str tu_s = str_init("to_user");
	enum hash_source my_hash_source;

	if (str_strcasecmp(&cid_s, (str*)*param) == 0) {
		my_hash_source = shs_call_id;
	} else if (str_strcasecmp(&fr_s, (str*)*param) == 0) {
		my_hash_source = shs_from_uri;
	} else if (str_strcasecmp(&fu_s, (str*)*param) == 0) {
		my_hash_source = shs_from_user;
	} else if (str_strcasecmp(&tr_s, (str*)*param) == 0) {
		my_hash_source = shs_to_uri;
	} else if (str_strcasecmp(&tu_s, (str*)*param) == 0) {
		my_hash_source = shs_to_user;
	} else {
		LM_ERR("invalid hash source\n");
		return -1;
	}

	*param = (void *)my_hash_source;

	return 0;
}


/************* Interface Functions *****************************************/

/**
 * Initializes the module, i.e. it binds the necessary API functions
 * and registers the fifo commands
 *
 * @return 0 on success, -1 on failure
 */
static int mod_init(void) {

	init_db_url( db_url , 0 /*cannot be null*/);
	db_table.len = strlen(db_table.s);
	carrier_table.len = strlen(carrier_table.s);
	subscriber_table.len = strlen(subscriber_table.s);
	id_col.len = strlen(id_col.s);
	carrier_col.len = strlen(carrier_col.s);
	domain_col.len = strlen(domain_col.s);
	scan_prefix_col.len = strlen(scan_prefix_col.s);
	flags_col.len = strlen(flags_col.s);
	mask_col.len = strlen(mask_col.s);
	prob_col.len = strlen(prob_col.s);
	rewrite_host_col.len = strlen(rewrite_host_col.s);
	strip_col.len = strlen(strip_col.s);
	rewrite_prefix_col.len = strlen(rewrite_prefix_col.s);
	rewrite_suffix_col.len = strlen(rewrite_suffix_col.s);
	comment_col.len = strlen(comment_col.s);
	username_col.len = strlen(username_col.s);
	subscriber_domain_col.len = strlen(subscriber_domain_col.s);
	cr_preferred_carrier_col.len = strlen(cr_preferred_carrier_col.s);
	carrier_id_col.len = strlen(carrier_id_col.s);
	carrier_name_col.len = strlen(carrier_name_col.s);
	failure_id_col.len = strlen(failure_id_col.s);
	failure_carrier_col.len = strlen(failure_carrier_col.s);
	failure_domain_col.len = strlen(failure_domain_col.s);
	failure_scan_prefix_col.len = strlen(failure_scan_prefix_col.s);
	failure_host_name_col.len = strlen(failure_host_name_col.s);
	failure_reply_code_col.len = strlen(failure_reply_code_col.s);
	failure_flags_col.len = strlen(failure_flags_col.s);
	failure_mask_col.len = strlen(failure_mask_col.s);
	failure_next_domain_col.len = strlen(failure_next_domain_col.s);
	failure_comment_col.len = strlen(failure_comment_col.s);
	default_tree.len = strlen(default_tree.s);

	if (init_route_data(config_source) < 0) {
		LM_ERR("could not init route data\n");
		return -1;
	}
	if (prepare_route_tree() == -1) {
		LM_ERR("could not prepare route tree\n");
		return -1;
	}
	if(data_main_finalize() < 0) {
		return -1;
	}
	LM_INFO("module initialized, pid [%d]\n", getpid());
	return 0;
}


/**
 * fixes the module functions' parameters with generic pseudo variable support.
 *
 * @param param the parameter
 *
 * @return 0 on success, -1 on failure
 */
/**
 * fixes the module functions' parameter if it is a carrier.
 */
static int carrier_fixup(void ** param) {
	if ((*param = (void *)(unsigned long)find_tree((str*)*param)) < 0) {
		LM_ERR("could not find carrier tree '%.*s'\n",
			((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}
	LM_DBG("carrier tree %.*s has id %d\n",
		((str*)*param)->len, ((str*)*param)->s, (int)(unsigned long)*param);

	return 0;
}


/**
 * fixes the module functions' parameter if it is a domain.
 */
static int domain_fixup(void ** param) {
	if ((*param = (void*)(unsigned long)add_domain((str*)*param)) < 0) {
		LM_ERR("could not add domain\n");
		return -1;
	}

	return 0;
}


/**
 * fixes the module functions' parameters in case of AVP names.
 *
 * @param param the parameter
 *
 * @return 0 on success, -1 on failure
 */
static int fixup_check_avp(void ** param) {
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}

static int child_init(int rank) {
	return data_child_init();
}


static void mod_destroy(void) {
	destroy_route_data();
}
