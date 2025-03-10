/*
 * Copyright (C) 2024 OpenSIPS Solutions
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"

/* needed for cachedb functionality */
#include "../../cachedb/cachedb.h"

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

static int example_cmd(struct sip_msg *msg);
static int example_cmd_str(struct sip_msg *msg, str *param);
static int example_cmd_int(struct sip_msg *msg, int *param);

static const cmd_export_t cmds[] =
{
	{"example",			 (cmd_function)example_cmd, {
		{0, 0, 0}}, ALL_ROUTES},
	{"example_str",		 (cmd_function)example_cmd_str, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}}, ALL_ROUTES},
	{"example_int",		 (cmd_function)example_cmd_int, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static str example_str_def = str_init("");
static int example_int_def = 0;

static const param_export_t params[]={
	{ "default_str",	STR_PARAM, &example_str_def.s},
	{ "default_int",	INT_PARAM, &example_int_def},
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"example",					/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	0,							/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported asynchronous functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,	/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload-ack function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing example module ...\n");
	example_str_def.len = strlen(example_str_def.s);
	return 0;
}

static int child_init(int rank)
{
	LM_NOTICE("initializing example child ...\n");
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroying example module ...\n");
}

static int example_cmd(struct sip_msg *msg)
{
	LM_DBG("example command called with no parameters!\n");
	return 1;
}

static int example_cmd_str(struct sip_msg *msg, str *param)
{
	if (param)
		LM_DBG("example command called with '%.*s' string  parameter!\n",
				param->len, param->s);
	else
		LM_DBG("example command called with default string parameter '%.*s'!\n",
				example_str_def.len, example_str_def.s);
	return 1;
}

static int example_cmd_int(struct sip_msg *msg, int *param)
{
	if (param)
		LM_DBG("example command called with %d integer  parameter!\n", *param);
	else
		LM_DBG("example command called with default integer parameter %d!\n",
				example_int_def);
	return 1;
}
