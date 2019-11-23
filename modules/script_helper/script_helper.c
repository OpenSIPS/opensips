/**
 * script_helper module - embedded scripting logic
 *	> record routing
 *	> dialog creation, matching and message validation
 *	> sequential request routing
 *
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * History:
 * --------
 *  2014-03-01 initial version (liviu)
 */

#include <stdio.h>

#include "../../sr_module.h"
#include "../../route.h"
#include "../../script_cb.h"
#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../sl/sl_api.h"
#include "../rr/api.h"

static int use_dialog;
static int create_dialog_flags;
static char *seq_route;
static int seq_route_id;

struct tm_binds tm_api;
struct dlg_binds dlg_api;
struct rr_binds rr_api;
struct sl_binds sl_api;

int run_helper_logic(struct sip_msg *msg, void *param);
int parse_dlg_flags(modparam_t type, void *val);

int mod_init(void);

static param_export_t params[] =
{
	{ "sequential_route", STR_PARAM, &seq_route },
	{ "use_dialog", INT_PARAM, &use_dialog },
	{ "create_dialog_flags", STR_PARAM|USE_FUNC_PARAM, parse_dlg_flags },
	{ NULL, 0, NULL },
};

static module_dependency_t *get_deps_use_dialog(param_export_t *param)
{
	if (*(int *)param->param_pointer == 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "dialog", DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "rr", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "sl", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "use_dialog", get_deps_use_dialog },
		{ NULL, NULL },
	},
};

struct module_exports exports =
{
	"script_helper",
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,
	&deps,            /* OpenSIPS module dependencies */
	NULL,
	NULL,
	params,
	NULL,
	NULL,
	NULL,
	NULL,			  /* exported transformations */
	NULL,
	NULL,
	mod_init,
	NULL,
	NULL,
	NULL,
	NULL              /* reload confirm function */
};

int mod_init(void)
{
	LM_DBG("initializing module...\n");

	if (seq_route) {
		seq_route_id = get_script_route_ID_by_name(seq_route,
			sroutes->request, RT_NO);
		if (seq_route_id == -1)
			LM_ERR("route \"%s\" does not exist! ignoring\n", seq_route);
	}

	if (load_tm_api(&tm_api) != 0) {
		LM_ERR("failed to load tm API\n");
		return -1;
	}

	if (use_dialog && load_dlg_api(&dlg_api) != 0) {
		LM_ERR("failed to load dialog API\n");
		return -1;
	}

	if (load_rr_api(&rr_api) != 0) {
		LM_ERR("failed to load rr API\n");
		return -1;
	}

	if (load_sl_api(&sl_api) != 0) {
		LM_ERR("failed to load sl API\n");
		return -1;
	}

	if (__register_script_cb(run_helper_logic,
	                         PRE_SCRIPT_CB|REQ_TYPE_CB, NULL, -1) != 0) {
		LM_ERR("cannot register script callback\n");
		return -1;
	}

	return 0;
}

int run_helper_logic(struct sip_msg *msg, void *param)
{
	str totag;
	str status_404 = str_init("Not Here");
	str status_500 = str_init("Server Internal Error");
	int rc, seq_request = 0;

	LM_DBG("running script helper for <%.*s>\n",
	       msg->first_line.u.request.method.len,
	       msg->first_line.u.request.method.s);

	if (parse_headers(msg, HDR_TO_F|HDR_CALLID_F, 0) == -1 ||
			!msg->to || !msg->callid) {
		LM_ERR("failed to parse To/Call-ID header\n");
		return SCB_DROP_MSG;
	}

	totag = get_to(msg)->tag_value;

	/* sequential request */
	if (totag.s && totag.len > 0) {
		seq_request = 1;

		if (msg->REQ_METHOD == METHOD_INVITE)
			rr_api.record_route(msg, NULL);

		/* if not RR_DRIVEN */
		if (rr_api.loose_route(msg) < 0) {

			/* attempt a full dialog search (not the usual quick did lookup) */
			if (use_dialog && dlg_api.match_dialog(msg, SEQ_MATCH_DEFAULT) < 0)
				LM_DBG("failed to match dialog for <%.*s>, ci '%.*s'\n",
				       msg->first_line.u.request.method.len,
				       msg->first_line.u.request.method.s,
				       msg->callid->body.len, msg->callid->body.s);

			if (msg->REQ_METHOD == METHOD_ACK) {
				rc = tm_api.t_check_trans(msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
				if (rc > 0)
					tm_api.t_relay(msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

				return SCB_RUN_POST_CBS;
			}

			sl_api.reply(msg, 404, &status_404, NULL);
			return SCB_RUN_POST_CBS;
		}
	}

	if (msg->REQ_METHOD == METHOD_CANCEL) {
		seq_request = 1;

		rc = tm_api.t_check_trans(msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		if (rc > 0)
			tm_api.t_relay(msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		return SCB_RUN_POST_CBS;
	}

	if (tm_api.t_check_trans(msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == 0)
		return SCB_RUN_POST_CBS;

	/**
	 * for sequential requests:
	 * - optionally run a given route
	 * - relay them and do not trigger the request route at all
	 */
	if (seq_request) {
		if (seq_route_id > 0) {
			LM_DBG("running seq route '%s'\n", seq_route);
			if (run_top_route(sroutes->request[seq_route_id].a, msg) & ACT_FL_DROP) {
				LM_DBG("script exited in the seq route\n");

				return SCB_RUN_POST_CBS;
			}
		}

		if (tm_api.t_relay(msg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) < 0)
			sl_api.reply(msg, 500, &status_500, NULL);

		return SCB_RUN_POST_CBS;
	}

	/* record-routing for initial requests */
	if (!(msg->REQ_METHOD & (METHOD_REGISTER|METHOD_MESSAGE)))
		rr_api.record_route(msg, NULL);

	if (use_dialog && msg->REQ_METHOD & METHOD_INVITE)
		dlg_api.create_dlg(msg, create_dialog_flags);

	return SCB_RUN_ALL;
}

int parse_dlg_flags(modparam_t type, void *val)
{
	str input;

	input.s = val;
	input.len = strlen(val);

	create_dialog_flags = parse_create_dlg_flags(&input);

	return 1;
}
