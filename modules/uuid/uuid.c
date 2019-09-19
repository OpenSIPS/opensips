/*
 * Copyright (C) 2019 OpenSIPS Solutions
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

#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../dprint.h"

#include <uuid/uuid.h>

#define UUID_STR_BUFSIZE 37

#define RET_OK     1
#define RET_UNSAFE 2

enum uuid_gen_vers {
	UUID_VERS_0 = 0,  /* generate either RFC verison 1 or 4 */
	UUID_VERS_1 = 1,
	UUID_VERS_4 = 4,
};

static uuid_t uuid;
static char uuid_str[UUID_STR_BUFSIZE];

static int fixup_check_var(void** param);
static int w_uuid(struct sip_msg *msg, pv_spec_t *out_var, int *vers_param);

static int pv_get_uuid(struct sip_msg *msg, pv_param_t *param,
						pv_value_t *res);

static pv_export_t mod_items[] = {
	{{"uuid", sizeof("uuid")-1}, 1000, pv_get_uuid, 0, 0, 0, 0, 0},
	{{0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

static cmd_export_t cmds[] = {
	{"uuid", (cmd_function)w_uuid, {
		{CMD_PARAM_VAR, fixup_check_var, 0},
		{CMD_PARAM_INT | CMD_PARAM_OPT, 0, 0}, {0,0,0}},
	ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports= {
	"uuid",        	 /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	0,               /* OpenSIPS module dependencies */
	cmds,            /* exported functions */
	0,               /* exported async functions */
	0,      		 /* param exports */
	0,       		 /* exported statistics */
	0,         		 /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,        		 /* module pre-initialization function */
	0,        		 /* module initialization function */
	0,               /* reply processing function */
	0,
	0,       		 /* per-child init function */
	0
};

static int gen_uuid(enum uuid_gen_vers vers, pv_value_t *res)
{
	int rc = RET_OK;

	switch (vers) {
	case UUID_VERS_0:
		uuid_generate(uuid);
		break;
	case UUID_VERS_1:
		rc = uuid_generate_time_safe(uuid) ? RET_UNSAFE : RET_OK;
		break;
	case UUID_VERS_4:
		uuid_generate_random(uuid);
		break;
	default:
		LM_BUG("Bad UUID generation algorithm selected\n");
		return -1;
	}

	LM_DBG("Generated UUID version: %d\n", uuid_type(uuid));

	uuid_unparse(uuid, uuid_str);
	res->rs.s = uuid_str;
	res->rs.len = UUID_STR_BUFSIZE-1;
	res->flags = PV_VAL_STR;

	return rc;
}

static int pv_get_uuid(struct sip_msg *msg, pv_param_t *param,
						pv_value_t *res)
{
	if (gen_uuid(UUID_VERS_0, res) == RET_UNSAFE)
		LM_DBG("Version 2 UUID generated unsafely\n");

	return 0;
}

static int fixup_check_var(void** param)
{
	if (((pv_spec_t*)*param)->setf==NULL) {
		LM_ERR("Output parameter is not a writable variable\n");
		return E_SCRIPT;
	}

	return 0;
}

static int w_uuid(struct sip_msg *msg, pv_spec_t *out_var, int *vers_param)
{
	int vers = UUID_VERS_0;
	int rc;
	pv_value_t out_val;

	if (vers_param)
		vers = *vers_param;

	switch (vers) {
	case 2:
	case 3:
	case 5:
		LM_WARN("UUID version: %d not supported! Using default algorithm\n",
			vers);
		vers = UUID_VERS_0;
		break;
	case UUID_VERS_0:
	case UUID_VERS_1:
	case UUID_VERS_4:
		break;
	default:
		LM_ERR("Bad UUID version: %d\n", vers);
		return -1;
	}

	if ((rc = gen_uuid(vers, &out_val)) == RET_UNSAFE)
		LM_DBG("Version 1 UUID generated unsafely\n");

	if (pv_set_value(msg, (pv_spec_t*)out_var, 0, &out_val) != 0) {
		LM_ERR("failed to set the output variable!\n");
		return -1;
	}

	return rc;
}
