/*
 * Copyright (C) 2023 Five9 Inc.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 */

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "ld_ops.h"

static int mod_init(void);
static int child_init(int);

static int fixup_check_avp(void** param);

static int w_ld_feature_enabled(struct sip_msg *sip_msg, str *feat, str *user,
		pv_spec_t *user_extra_avp, int* fallback);

static char *ld_log_level_s = "LD_LOG_WARNING";


static const param_export_t mod_params[] = {
	{"sdk_key", STR_PARAM, &sdk_key},
	{"ld_log_level", STR_PARAM, &ld_log_level_s},
	{"connect_wait", INT_PARAM, &connect_wait},
	{"re_init_interval", INT_PARAM, &re_init_interval},
	{0,0,0}
};

static const cmd_export_t cmds[] = {
	{"ld_feature_enabled",(cmd_function)w_ld_feature_enabled, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports = {
	"launch_darkly",			/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,						/* load function */
	NULL,						/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	NULL,						/* exported async functions */
	mod_params,					/* exported parameters */
	NULL,						/* exported statistics */
	NULL,						/* exported MI functions */
	NULL,						/* exported pseudo-variables */
	NULL,						/* exported transformations */
	NULL,						/* extra processes */
	NULL,						/* module pre-initialization function */
	mod_init,					/* module initialization function */
	NULL,						/* response handling function */
	NULL,						/* destroy function */
	child_init,					/* per-child init function */
	NULL						/* reload confirm function */
};


static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("the return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}


static int mod_init(void)
{
	if (sdk_key == NULL) {
		LM_ERR("SDK key not configured via modparam!\n");
		return -1;
	}

	set_ld_log_level(ld_log_level_s);

	return 0;
}


static int child_init(int rank)
{
	if (ld_init_child() < 0) {
		LM_ERR("cannot init writing pipe\n");
		return -1;
	}

	return 0;
}

static int w_ld_feature_enabled(struct sip_msg *sip_msg, str *feat, str *user,
								pv_spec_t *user_extra_avp, int *fallback)
{
	return ld_feature_enabled( feat, user,
		user_extra_avp ? user_extra_avp->pvp.pvn.u.isname.name.n : -1,
		fallback ? *fallback :  -1 );
}

