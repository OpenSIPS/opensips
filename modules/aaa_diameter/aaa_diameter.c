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
#include "../../lib/list.h"
#include "../../ut.h"

#include "aaa_impl.h"
#include "peer.h"

static int mod_init(void);
static int child_init(int rank);
static int dm_check_config(void);
static void mod_destroy(void);

char *dm_conf_filename = "freeDiameter.conf";
char *extra_avps_file;

static int dm_send_request(struct sip_msg *msg, int *app_id, int *cmd_code,
				str *avp_json);
static int dm_bind_api(aaa_prot *api);

int fd_log_level = FD_LOG_NOTICE;
str dm_realm = str_init("diameter.test");
str dm_peer_identity = str_init("server"); /* a.k.a. server.diameter.test */

static cmd_export_t cmds[]= {
	{"dm_send_request", (cmd_function)dm_send_request, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		ALL_ROUTES},

	{"aaa_bind_api", (cmd_function) dm_bind_api, {{0, 0, 0}}, 0},
	{0,0,{{0,0,0}},0}
};

static proc_export_t procs[] = {
	{ "diameter-peer", NULL, NULL, diameter_peer_loop, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 },
};

static param_export_t params[] =
{
	{ "fd_log_level",    INT_PARAM, &fd_log_level     },
	{ "realm",           STR_PARAM, &dm_realm.s       },
	{ "peer_identity",   STR_PARAM, &dm_peer_identity.s   },
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
	child_init,       /* per-child init function */
	NULL              /* reload confirm function */
};


int mod_init(void)
{
	LM_DBG("initializing module...\n");

	if (dm_check_config() != 0) {
		LM_ERR("bad modparam configuration\n");
		return -1;
	}

	/* perform only a minimal amount of library initialization, just so modules
	 * can look up Diameter AVPs through the API, but without neither changing
	 * the internal library state nor forking any threads yet! */
	if (dm_init_minimal() != 0) {
		LM_ERR("failed to init freeDiameter global dictionary\n");
		return -1;
	}

	if (dm_init_peer() != 0) {
		LM_ERR("failed to init the local Diameter peer\n");
		return -1;
	}

	return 0;
}


static int child_init(int rank)
{
	if (dm_init_reply_cond(rank) != 0) {
		LM_ERR("failed to init cond variable for replies\n");
		return -1;
	}

	return 0;
}


static int dm_check_config(void)
{
	if (!dm_realm.s) {
		LM_ERR("the 'realm' modparam is not set\n");
		return -1;
	}
	dm_realm.len = strlen(dm_realm.s);

	if (!dm_peer_identity.s) {
		LM_ERR("the 'peer_identity' modparam is not set\n");
		return -1;
	}
	dm_peer_identity.len = strlen(dm_peer_identity.s);
	if (dm_peer_identity.len == 0) {
		LM_ERR("the 'peer_identity' modparam cannot be empty\n");
		return -1;
	}

	return 0;
}


static void mod_destroy(void)
{
	int rc;

	rc = fd_core_shutdown();
	LM_DBG("libfdcore shutdown, rc: %d\n", rc);
	dm_destroy();
}


static int dm_bind_api(aaa_prot *api)
{
	if (!api)
		return -1;

	memset(api, 0, sizeof *api);

	api->create_aaa_message = dm_create_message;
	api->destroy_aaa_message = dm_destroy_message;
	api->send_aaa_request = dm_send_message;
	api->init_prot = dm_init_prot;
	api->dictionary_find = dm_find;
	api->avp_add = dm_avp_add;
	api->avp_get = NULL;

	return 0;
}


static int dm_send_request(struct sip_msg *msg, int *app_id, int *cmd_code,
				str *avp_json)
{
	aaa_message *dmsg;
	struct dict_object *req;
	cJSON *avps, *_avp;

	if (fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_R,
	      cmd_code, &req, ENOENT) == ENOENT) {
		LM_ERR("unrecognized Request command code: %d\n", *cmd_code);
		LM_ERR("to fix this, you can define the Request/Answer format in the "
		       "'extra-avps-file' config file\n");
		return -1;
	}

	LM_DBG("found a matching dict entry for command code %d\n", *cmd_code);

	if (!avp_json || !avp_json->s) {
		LM_ERR("NULL JSON input\n");
		return -1;
	}

	avps = cJSON_Parse(avp_json->s);
	if (!avps) {
		LM_ERR("failed to parse input JSON ('%.*s' ..., total: %d)\n",
		       avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp_json->len);
		return -1;
	}

	if (avps->type != cJSON_Array) {
		LM_ERR("bad JSON type: must be Array ('%.*s' ..., total: %d)\n",
		       avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp_json->len);
		return -1;
	}

	dmsg = _dm_create_message(NULL, AAA_CUSTOM, *app_id, *cmd_code);
	if (!dmsg) {
		LM_ERR("oom\n");
		return -1;
	}

	for (_avp = avps->child; _avp; _avp = _avp->next) {
		if (_avp->type != cJSON_Object) {
			LM_ERR("bad JSON type in Array: AVPs must be Objects ('%.*s' "
			       "..., total: %d)\n", avp_json->len > 512 ? 512 : avp_json->len,
			       avp_json->s, avp_json->len);
			return -1;
		}

		cJSON *avp = _avp->child; // only work with child #0
		struct dict_avp_data dm_avp;
		struct dict_object *obj;
		char *name;
		unsigned int code;

		// TODO: allow dict too
		if (!(avp->type & (cJSON_String|cJSON_Number))) {
			LM_ERR("bad AVP value: only String allowed ('%.*s' ..., key: %s)\n",
		       avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp->string);
			return -1;
		}

		if (_isdigit(avp->string[0])) {
			str st;

			init_str(&st, avp->string);
			if (str2int(&st, &code) != 0) {
				LM_ERR("bad AVP key: cannot start with a digit ('%.*s' ..., key: %s)\n",
				   avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp->string);
				return -1;
			}

			LM_DBG("AVP:: searching AVP by int: %d\n", code);
			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE,
				&code, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &dm_avp));

			name = dm_avp.avp_name;
		} else {
			LM_DBG("AVP:: searching AVP by string: %s\n", avp->string);

			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
				avp->string, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &dm_avp));

			name = avp->string;
			code = dm_avp.avp_code;
		}

		aaa_map my_avp = {.name = name};

		if (avp->type & cJSON_String) {
			LM_DBG("dbg::: AVP %d (name: '%s', str-val: %s)\n", code, name, avp->valuestring);
			if (dm_avp_add(NULL, dmsg, &my_avp, avp->valuestring,
			        strlen(avp->valuestring), 0) != 0) {
				LM_ERR("failed to add AVP %d, aborting request\n", code);
				return -1;
			}
		} else {
			LM_DBG("dbg::: AVP %d (name: '%s', int-val: %d)\n", code, name, avp->valueint);
			if (dm_avp_add(NULL, dmsg, &my_avp, &avp->valueint, -1, 0) != 0) {
				LM_ERR("failed to add AVP %d, aborting request\n", code);
				return -1;
			}
		}
	}

	if (dm_send_message(NULL, dmsg, NULL) != 0) {
		LM_ERR("failed to queue Diameter request for sending\n");
		return -1;
	}

	cJSON_Delete(avps);
	return 1;
}
