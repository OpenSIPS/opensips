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
#include "../../async.h"
#include "../../ut.h"

#include "dm_impl.h"
#include "dm_evi.h"
#include "dm_peer.h"

static int mod_init(void);
static int child_init(int rank);
static int dm_check_config(void);
static void mod_destroy(void);

char *dm_conf_filename = "freeDiameter.conf";
char *extra_avps_file;

static int dm_send_request(struct sip_msg *msg, int *app_id, int *cmd_code,
				str *avp_json, pv_spec_t *rpl_avps_pv);
static int dm_send_request_async(struct sip_msg *msg, async_ctx *ctx,
				int *app_id, int *cmd_code, str *avp_json, pv_spec_t *rpl_avps_pv);
static int dm_send_answer(struct sip_msg *msg, str *avp_json);
static int dm_bind_api(aaa_prot *api);

int fd_log_level = FD_LOG_NOTICE;
str dm_realm = str_init("diameter.test");
str dm_peer_identity = str_init("server"); /* a.k.a. server.diameter.test */
static str dm_aaa_url = {NULL, 0};
int dm_answer_timeout = 2000; /* ms */
int dm_server_autoreply_error; /* ensures we always reply with *something* */

static const cmd_export_t cmds[]= {
	{"dm_send_request", (cmd_function)dm_send_request, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},

	{"dm_send_answer", (cmd_function)dm_send_answer, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		EVENT_ROUTE},

	{"aaa_bind_api", (cmd_function) dm_bind_api, {{0, 0, 0}}, 0},
	{0,0,{{0,0,0}},0}
};

static const acmd_export_t acmds[]= {
	{"dm_send_request", (acmd_function)dm_send_request_async, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}}},
	{0,0,{{0,0,0}}}
};

static const proc_export_t procs[] = {
	{ "diameter-peer", NULL, NULL, dm_peer_loop, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 },
};

static const param_export_t params[] =
{
	{ "fd_log_level",    INT_PARAM, &fd_log_level     },
	{ "realm",           STR_PARAM, &dm_realm.s       },
	{ "peer_identity",   STR_PARAM, &dm_peer_identity.s  },
	{ "aaa_url",         STR_PARAM, &dm_aaa_url.s        },
	{ "answer_timeout",   INT_PARAM, &dm_answer_timeout  },
	{ NULL, 0, NULL },
};

static const mi_export_t mi_cmds[] = {
	{ "fd_log_level", 0, 0, 0, {
		{NULL, {"log_level", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
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
	RTLD_NOW | RTLD_GLOBAL,  /* dlopen flags */
	NULL,             /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* exported functions */
	acmds,            /* exported async functions */
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

	if (dm_init_evi() != 0) {
		LM_ERR("failed to init the Diameter event\n");
		return -1;
	}

	if (dm_init_peer() != 0) {
		LM_ERR("failed to init the local Diameter peer\n");
		return -1;
	}

	if (dm_aaa_url.s) {
		dm_aaa_url.len = strlen(dm_aaa_url.s);
		if (!dm_init_prot(&dm_aaa_url)) {
			LM_ERR("failed to init Diameter AAA connection\n");
			return -1;
		}
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

	LM_INFO("Diameter server support enabled\n");

	if (get_script_route_ID_by_name_str(
	        &str_init(DMEV_REQ_NAME), sroutes->event, EVENT_RT_NO) < 0) {
		LM_NOTICE("Diameter server event "DMEV_REQ_NAME" not used in opensips script"
		        ", auto-replying error code 3001 to any Diameter request\n");
		dm_server_autoreply_error = 1;
	} else if (!is_script_func_used("dm_send_answer", -1)) {
		LM_NOTICE("Diameter 'dm_send_answer()' function not used in opensips script"
		        ", auto-replying error code 3001 to any Diameter request\n");
		dm_server_autoreply_error = 1;
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
				str *avp_json, pv_spec_t *rpl_avps_pv)
{
	aaa_message *dmsg = NULL;
	struct dict_object *req;
	cJSON *avps;
	int rc;
	char *rpl_avps = NULL;

	if ((rc = fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND,CMD_BY_CODE_R,
	      cmd_code, &req, ENOENT)) != 0) {
		LM_ERR("unrecognized Request command code: %d (errno: %d)\n", *cmd_code, rc);
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
		goto error;
	}

	dmsg = _dm_create_message(NULL, AAA_CUSTOM_REQ, *app_id, *cmd_code, NULL);
	if (!dmsg) {
		LM_ERR("oom\n");
		goto error;
	}

	if (dm_build_avps(&((struct dm_message *)(dmsg->avpair))->avps,
	                     avps->child) != 0) {
		LM_ERR("failed to unpack JSON ('%.*s' ..., total: %d)\n",
		       avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp_json->len);
		goto error;
	}

	rc = _dm_send_message(NULL, dmsg, NULL, &rpl_avps);

	if (rpl_avps_pv && rpl_avps) {
		pv_value_t val = {(str){rpl_avps, strlen(rpl_avps)}, 0, PV_VAL_STR};
		if (pv_set_value(msg, rpl_avps_pv, 0, &val) != 0)
			LM_ERR("failed to set output rpl_avps pv to: %s\n", rpl_avps);
	}

	if (rc < 0) {
		LM_ERR("Diameter request failed (rc: %d)\n", rc);
		cJSON_Delete(avps);
		return rc;
	}

	cJSON_Delete(avps);
	return 1;

error:
	if (rpl_avps_pv) {
		pv_value_t val = {STR_NULL, 0, PV_VAL_NULL};
		if (pv_set_value(msg, rpl_avps_pv, 0, &val) != 0)
			LM_ERR("failed to set output rpl_avps pv to NULL\n");
	}

	_dm_destroy_message(dmsg);
	cJSON_Delete(avps);
	return -1;
}


static int dm_send_answer(struct sip_msg *msg, str *avp_json)
{
	aaa_message *dmsg = NULL;
	cJSON *avps;
	pv_param_t evp;
	pv_value_t res;
	str sessid;
	int appid, cmdcode, rc;
	unsigned long fd_req;

	if (route_type != EVENT_ROUTE) {
		LM_ERR("can only run 'dm_send_answer()' inside an EVENT_ROUTE\n");
		return -1;
	}

	if (ZSTRP(avp_json)) {
		LM_ERR("unable to build reply (NULL 'avps_json' input)\n");
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
		goto error;
	}

	/* Here, we know 100% that we're inside an event_route, so we can pull the
	 * Diameter request info (Session-ID, App, Code) using the "params" API */
	memset(&evp, 0, sizeof evp);
	evp.pvn.type = PV_NAME_INTSTR;
	evp.pvn.u.isname.type = AVP_NAME_STR;

	evp.pvn.u.isname.name.s = dmev_req_pname_appid;
	route_params_run(msg, &evp, &res);
	if (!pvv_is_int(&res)) {
		LM_ERR("failed to fetch Application ID\n");
		appid = 0;
	} else {
		appid = res.ri;
	}

	evp.pvn.u.isname.name.s = dmev_req_pname_cmdcode;
	route_params_run(msg, &evp, &res);
	if (!pvv_is_int(&res)) {
		LM_ERR("failed to fetch Command Code\n");
		cmdcode = 0;
	} else {
		cmdcode = res.ri;
	}

	evp.pvn.u.isname.name.s = dmev_req_pname_fdmsg;
	route_params_run(msg, &evp, &res);
	if (!pvv_is_str(&res)) {
		LM_ERR("failed to fetch FD Message\n");
		goto error;
	} else {
		reverse_hex2int64(res.rs.s, res.rs.len, 1, &fd_req);
	}

	dmsg = _dm_create_message(NULL, AAA_CUSTOM_RPL, appid, cmdcode, (void *)fd_req);
	if (!dmsg) {
		LM_ERR("oom\n");
		goto error;
	}

	if (dm_build_avps(&((struct dm_message *)(dmsg->avpair))->avps,
	                     avps->child) != 0) {
		LM_ERR("failed to unpack JSON ('%.*s' ..., total: %d)\n",
		       avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp_json->len);
		goto error;
	}

	rc = _dm_send_message(NULL, dmsg, NULL, NULL);
	if (rc < 0) {
		evp.pvn.u.isname.name.s = dmev_req_pname_sessid;
		route_params_run(msg, &evp, &res);
		if (ZSTR(res.rs) || !pvv_is_str(&res)) {
			LM_DBG("failed to fetch the unique session ID\n");
			sessid = STR_NULL;
		} else {
			sessid = res.rs;
		}

		LM_ERR("failed to send Diameter reply (sess: %.*s, app: %d, cmd: %d)\n",
		        sessid.len, sessid.s, appid, cmdcode);
		cJSON_Delete(avps);
		return rc;
	}

	cJSON_Delete(avps);
	return 0;

error:
	_dm_destroy_message(dmsg);
	cJSON_Delete(avps);
	return -1;
}


struct dm_async_msg {
	pv_spec_p ret;
	struct dm_cond *cond;
};

static struct dm_async_msg *dm_get_async_msg(pv_spec_t *rpl_avps_pv, aaa_message *dmsg)
{
	struct dm_async_msg *msg = pkg_malloc(sizeof *msg);
	if (!msg)
		return NULL;
	memset(msg, 0, sizeof *msg);
	msg->ret = rpl_avps_pv;
	msg->cond = ((struct dm_message *)(dmsg->avpair))->reply_cond;
	return msg;
}

static void dm_free_sync_msg(struct dm_async_msg *amsg)
{
	if (amsg->cond)
		shm_free(amsg->cond);
	pkg_free(amsg);
}

static int dm_send_request_async_reply(int fd,
		struct sip_msg *msg, void *param)
{
	int ret;
	unsigned long r;
	char *rpl_avps;
	pv_value_t val = {STR_NULL, 0, PV_VAL_NULL};
	struct dm_async_msg *amsg = (struct dm_async_msg *)param;

	do {
		ret = read(fd, &r, sizeof r);
	} while(ret < 0 && (errno == EINTR || errno == EAGAIN));
	async_status = ASYNC_DONE_CLOSE_FD;
	if (ret < 0) {
		LM_ERR("could not resume async route!\n");
		goto error;
	}
	ret = _dm_get_message_response(amsg->cond, &rpl_avps);
	if (ret > 0 && amsg->ret && rpl_avps) {
		val.rs.s = rpl_avps;
		val.rs.len = strlen(rpl_avps);
		val.flags = PV_VAL_STR;
	}
error:
	if (pv_set_value(msg, amsg->ret, 0, &val) != 0)
		LM_ERR("failed to set output rpl_avps pv to NULL\n");
	dm_free_sync_msg(amsg);
	return ret;
}

static int dm_send_request_async_tout(int fd,
		struct sip_msg *msg, void *param)
{
	struct dm_async_msg *amsg = (struct dm_async_msg *)param;
	pv_value_t val = {STR_NULL, 0, PV_VAL_NULL};

	if (pv_set_value(msg, amsg->ret, 0, &val) != 0)
		LM_ERR("failed to set output rpl_avps pv to NULL\n");

	dm_free_sync_msg(amsg);
	return -2;
}

static int dm_send_request_async(struct sip_msg *msg, async_ctx *ctx,
				int *app_id, int *cmd_code, str *avp_json, pv_spec_t *rpl_avps_pv)
{
	aaa_message *dmsg = NULL;
	struct dict_object *req;
	cJSON *avps;
	struct dm_async_msg *amsg;

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
		goto error;
	}

	dmsg = _dm_create_message(NULL, AAA_CUSTOM_REQ, *app_id, *cmd_code, NULL);
	if (!dmsg) {
		LM_ERR("oom\n");
		goto error;
	}

	if (dm_build_avps(&((struct dm_message *)(dmsg->avpair))->avps,
	                     avps->child) != 0) {
		LM_ERR("failed to unpack JSON ('%.*s' ..., total: %d)\n",
		       avp_json->len > 512 ? 512 : avp_json->len, avp_json->s, avp_json->len);
		goto error;
	}
	if (_dm_send_message_async(NULL, dmsg, &async_status) < 0) {
		LM_ERR("cannot send async message!\n");
		goto error;
	}

	amsg = dm_get_async_msg(rpl_avps_pv, dmsg);
	if (!amsg)
		goto error;

	ctx->resume_f = dm_send_request_async_reply;
	ctx->resume_param = amsg;
	ctx->timeout_s = dm_answer_timeout / 1000;
	ctx->timeout_f = dm_send_request_async_tout;

	cJSON_Delete(avps);
	return 1;

error:
	cJSON_Delete(avps);
	return -1;
}
