/*
 * Copyright (C) 2022 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */


#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../status_report.h"
#include "../../mem/mem.h"

static int add_sr_group( modparam_t type, void* val);
static int mod_init(void);
static void mod_destroy(void);
static int w_set_status(struct sip_msg *msg, void *srg,
	int *status, str* txt);
static int w_add_report(struct sip_msg *msg, void *srg,
	str *report);


static const cmd_export_t cmds[]={
	{"sr_set_status", (cmd_function)w_set_status, {
		{CMD_PARAM_STR, fixup_sr_group, 0},
		{CMD_PARAM_INT, 0, 0}, {0,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}},
		ALL_ROUTES},
	{"sr_add_report", (cmd_function)w_add_report, {
		{CMD_PARAM_STR, fixup_sr_group, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static const param_export_t mod_params[]={
	{ "script_sr_group",  STR_PARAM|USE_FUNC_PARAM, (void*)add_sr_group },
	{ 0,0,0 }
};


struct module_exports exports= {
	"status_report",		/* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	NULL,				/* load function */
	NULL,				/* OpenSIPS module dependencies */
	cmds,				/* exported functions */
	NULL,				/* exported async functions */
	mod_params,			/* param exports */
	NULL,				/* exported statistics */
	NULL,				/* exported MI functions */
	NULL,				/* exported pseudo-variables */
	NULL,				/* exported transformations */
	NULL,				/* extra processes */
	NULL,				/* module pre-initialization function */
	mod_init,			/* module initialization function */
	0,					/* reply processing function */
	mod_destroy,		/* module destroy function */
	0,					/* per-child init function */
	0					/* reload confirm function */
};


static int add_sr_group( modparam_t type, void* val)
{
	str name;

	name.s = (char*)val;
	name.len = strlen(name.s);
	trim( &name );

	if ( sr_register_group_with_identifier( name.s, name.len ,
	1/*public*/, CHAR_INT_NULL/*identifier*/,
	SR_STATUS_READY, CHAR_INT_NULL /*txt*/, 50 /*reports*/)==NULL ) {
		LM_ERR("failed to register new 'status-report' group |%.*s|\n",
			name.len, name.s);
		return -1;
	}

	return 0;
}


static int mod_init(void)
{
	return 0;
}


static void mod_destroy(void)
{
	return;
}


static int w_add_report(struct sip_msg *msg, void *srg,
		str *report)
{
	int rc;

	rc = sr_add_report( srg, CHAR_INT_NULL,
		report->s, report->len, 1/*public access*/);

	return (rc>=0)?1:-1;
}


static int w_set_status(struct sip_msg *msg, void *srg,
		int *status, str *txt)
{
	if (txt)
		return sr_set_status( srg, CHAR_INT_NULL,
			*status, txt->s, txt->len, 1/*public access*/);
	else
		return sr_set_status( srg, CHAR_INT_NULL,
			*status, CHAR_INT_NULL, 1/*public access*/);
}


