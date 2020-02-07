/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */

#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "media_exchange.h"

struct tm_binds media_tm;
struct dlg_binds media_dlg;
struct b2b_api media_b2b;
struct rtpproxy_binds media_rtp;

static int mod_init(void);
static int media_send_to_uri(struct sip_msg *msg, str *uri, int leg, str *body, str *headers);
static int media_send_from_call(struct sip_msg *msg, str *callid, int leg);
static int media_fetch_from_uri(struct sip_msg *msg, str *uri, int leg,
		str *body, str *headers, int *nohold);
static int media_fetch_to_call(struct sip_msg *msg, str *callid, int leg, int *nohold);
static int media_terminate(struct sip_msg *msg, int leg, int *nohold);
static int fixup_media_leg(void **param);
static int fixup_media_leg_both(void **param);

/* modules dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "rtpproxy", DEP_SILENT }, /* only used for streaming */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{
		{ NULL, NULL },
	},
};

/* exported commands */
static cmd_export_t cmds[] = {
	{"media_send_to_uri",(cmd_function)media_send_to_uri, {
		{CMD_PARAM_STR,0,0}, /* uri */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg_both,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* body */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* headers */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_send_from_call",(cmd_function)media_send_from_call, {
		{CMD_PARAM_STR,0,0}, /* callid */
		{CMD_PARAM_STR,fixup_media_leg_both,0}, /* leg */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_fetch_from_uri",(cmd_function)media_fetch_from_uri, {
		{CMD_PARAM_STR,0,0}, /* uri */
		{CMD_PARAM_STR|CMD_PARAM_OPT,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* body */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* headers */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_fetch_to_call",(cmd_function)media_fetch_to_call, {
		{CMD_PARAM_STR,0,0}, /* callid */
		{CMD_PARAM_STR,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE},
	{"media_terminate",(cmd_function)media_terminate, {
		{CMD_PARAM_STR,fixup_media_leg,0}, /* leg */
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, /* nohold */
		{0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/* exported parameters */
static param_export_t params[] = {
	{0, 0, 0}
};

/* module exports */
struct module_exports exports = {
	"media_exchange",				/* module name */
	MOD_TYPE_DEFAULT,				/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,				/* dlopen flags */
	0,								/* load function */
	&deps,							/* OpenSIPS module dependencies */
	cmds,							/* exported functions */
	0,								/* exported async functions */
	params,							/* exported parameters */
	0,								/* exported statistics */
	0,								/* exported MI functions */
	0,								/* exported pseudo-variables */
	0,								/* extra processes */
	0,								/* extra transformations */
	0,								/* module pre-initialization function */
	mod_init,						/* module initialization function */
	NULL,							/* response handling function */
	NULL,							/* destroy function */
	NULL,							/* per-child init function */
	0								/* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_DBG("initializing siprec module ...\n");

	if (load_dlg_api(&media_dlg) != 0) {
		LM_ERR("dialog module not loaded! Cannot use media bridging module\n");
		return -1;
	}

	if (load_tm_api(&media_tm) != 0) {
		LM_ERR("tm module not loaded! Cannot use media bridging module\n");
		return -1;
	}

	if (load_b2b_api(&media_b2b) != 0) {
		LM_ERR("b2b_entities module not loaded! "
				"Cannot use media bridging module\n");
		return -1;
	}

	if (load_rtpproxy_api(&media_rtp) != 0)
		LM_DBG("rtpproxy module not loaded! Cannot use streaming functions\n");

	return 0;
}

static int fixup_media_leg(void **param)
{
	str *s = *param;
	if (s->len != 6)
		goto unknown;
	if (!strncasecmp(s->s, "caller", 6)) {
		*param = (void *)(unsigned long)MEDIA_LEG_CALLER;
		return 0;
	} else if (!strncasecmp(s->s, "callee", 6)) {
		*param = (void *)(unsigned long)MEDIA_LEG_CALLEE;
		return 0;
	}
unknown:
	LM_ERR("unsupported leg '%.*s'\n", s->len, s->s);
	return E_CFG;
}

static int fixup_media_leg_both(void **param)
{
	str *s = *param;
	if (s->len == 4 && strncasecmp(s->s, "both", 4) == 0) {
		*param = (void *)(unsigned long)MEDIA_LEG_BOTH;
		return 0;
	}
	return fixup_media_leg(param);
}

static int media_send_to_uri(struct sip_msg *msg, str *uri, int leg, str *body, str *headers)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int media_send_from_call(struct sip_msg *msg, str *callid, int leg)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int media_fetch_from_uri(struct sip_msg *msg, str *uri, int leg,
		str *body, str *headers, int *nohold)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int media_fetch_to_call(struct sip_msg *msg, str *callid, int leg, int *nohold)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}

static int media_terminate(struct sip_msg *msg, int leg, int *nohold)
{
	LM_WARN("not implemented yet!\n");
	return -1;
}
