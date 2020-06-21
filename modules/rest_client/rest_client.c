/*
 * Copyright (C) 2013-2015 OpenSIPS Solutions
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
 * -------
 * 2013-02-28: Created (Liviu)
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "../../async.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"
#include "../../lib/list.h"
#include "../../trace_api.h"

#include "../tls_mgm/api.h"

#include "rest_methods.h"
#include "../../ssl_init_tweaks.h"
#include "../../pt.h"

/*
 * Module parameters
 */
long connection_timeout = 20; /* s */
long connect_poll_interval = 20; /* ms */
long connection_timeout_ms;
int max_async_transfers = 100;
long curl_timeout = 20;
char *ssl_capath;

/*
 * curl_multi_perform() may indicate a "try again" response even
 * when resuming transfers with pending data
 */
int _async_resume_retr_timeout = 500000; /* us */
int _async_resume_retr_itv = 100; /* us */

/* libcurl enables these by default */
int ssl_verifypeer = 1;
int ssl_verifyhost = 1;

int enable_expect_100;

struct tls_mgm_binds tls_api;

/* trace parameters for this module */
#define REST_TRACE_API_MODULE "proto_hep"
int rest_proto_id;
trace_proto_t tprot;
static char* rest_id_s = "rest";

/*
 * Module initialization and cleanup
 */
static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/*
 * Fixup functions
 */
static int fixup_rest_get(void **param, int param_no);
static int fixup_rest_post(void **param, int param_no);
static int fixup_rest_put(void **param, int param_no);

/*
 * Function headers
 */
static int w_rest_get(struct sip_msg *msg, char *gp_url, char *body_pv,
				char *ctype_pv, char *code_pv);
static int w_rest_post(struct sip_msg *msg, char *gp_url, char *gp_body,
				char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv);
static int w_rest_put(struct sip_msg *msg, char *gp_url, char *gp_body,
				char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv);

static int w_async_rest_get(struct sip_msg *msg, async_ctx *ctx, char *gp_url,
					 char *body_pv, char *ctype_pv, char *code_pv);
static int w_async_rest_post(struct sip_msg *msg, async_ctx *ctx,
					 char *gp_url, char *gp_body, char *gp_ctype,
					 char *body_pv, char *ctype_pv, char *code_pv);
static int w_async_rest_put(struct sip_msg *msg, async_ctx *ctx,
					 char *gp_url, char *gp_body, char *gp_ctype,
					 char *body_pv, char *ctype_pv, char *code_pv);

static int w_rest_append_hf(struct sip_msg *msg, char *gp_hfv);
static int w_rest_init_client_tls(struct sip_msg *msg, char *gp_tls_dom);

/* module dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "siptrace", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 }
	},
	{ /* modparam dependencies */
		{ NULL, NULL}
	}
};

static acmd_export_t acmds[] = {
	{ "rest_get",  (acmd_function)w_async_rest_get,  2, fixup_rest_get },
	{ "rest_get",  (acmd_function)w_async_rest_get,  3, fixup_rest_get },
	{ "rest_get",  (acmd_function)w_async_rest_get,  4, fixup_rest_get },
	{ "rest_post", (acmd_function)w_async_rest_post, 4, fixup_rest_post },
	{ "rest_post", (acmd_function)w_async_rest_post, 5, fixup_rest_post },
	{ "rest_post", (acmd_function)w_async_rest_post, 6, fixup_rest_post },
	{ "rest_put",  (acmd_function)w_async_rest_put,  4, fixup_rest_put },
	{ "rest_put",  (acmd_function)w_async_rest_put,  5, fixup_rest_put },
	{ "rest_put",  (acmd_function)w_async_rest_put,  6, fixup_rest_put },
	{ 0, 0, 0, 0 }
};

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{ "rest_get",(cmd_function)w_rest_get, 2, fixup_rest_get, 0, ALL_ROUTES },
	{ "rest_get",(cmd_function)w_rest_get, 3, fixup_rest_get, 0, ALL_ROUTES },
	{ "rest_get",(cmd_function)w_rest_get, 4, fixup_rest_get, 0, ALL_ROUTES },
	{ "rest_post",(cmd_function)w_rest_post, 4, fixup_rest_post, 0, ALL_ROUTES },
	{ "rest_post",(cmd_function)w_rest_post, 5, fixup_rest_post, 0, ALL_ROUTES },
	{ "rest_post",(cmd_function)w_rest_post, 6, fixup_rest_post, 0, ALL_ROUTES },
	{ "rest_put",(cmd_function)w_rest_put, 4, fixup_rest_put, 0, ALL_ROUTES },
	{ "rest_put",(cmd_function)w_rest_put, 5, fixup_rest_put, 0, ALL_ROUTES },
	{ "rest_put",(cmd_function)w_rest_put, 6, fixup_rest_put, 0, ALL_ROUTES },
	{ "rest_append_hf",(cmd_function)w_rest_append_hf, 1, fixup_spve_null, 0,
		ALL_ROUTES },
	{ "rest_init_client_tls",(cmd_function)w_rest_init_client_tls, 1,
		fixup_spve_null, 0, ALL_ROUTES },
	{ 0, 0, 0, 0, 0, 0 }
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{ "connection_timeout",	INT_PARAM, &connection_timeout	},
	{ "connect_poll_interval", INT_PARAM, &connect_poll_interval },
	{ "max_async_transfers", INT_PARAM, &max_async_transfers },
	{ "curl_timeout",		INT_PARAM, &curl_timeout		},
	{ "ssl_capath",			STR_PARAM, &ssl_capath			},
	{ "ssl_verifypeer",		INT_PARAM, &ssl_verifypeer		},
	{ "ssl_verifyhost",		INT_PARAM, &ssl_verifyhost		},
	{ "enable_expect_100",	INT_PARAM, &enable_expect_100	},
	{ 0, 0, 0 }
};


/*
 * Module parameter variables
 */
struct module_exports exports = {
	"rest_client",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	acmds,    /* Exported async functions */
	params,   /* Exported parameters */
	NULL,     /* exported statistics */
	NULL,     /* exported MI functions */
	NULL,     /* exported pseudo-variables */
	NULL,	  /* exported transformations */
	NULL,     /* extra processes */
	NULL,     /* module pre-initialization function */
	mod_init, /* module initialization function */
	NULL,     /* response function*/
	mod_destroy,
	child_init, /* per-child init function */
};

static int mod_init(void)
{
	LM_DBG("Initializing...\n");

	connection_timeout_ms = connection_timeout * 1000L;

	if (connect_poll_interval < 0) {
		LM_ERR("Bad connect_poll_interval (%ldms), setting to 20ms\n",
		       connect_poll_interval);
		connect_poll_interval = 20;
	}

	if (connection_timeout > curl_timeout) {
		LM_WARN("'connection_timeout' must be less than or equal "
		        "to 'curl_timeout'! setting it to %ld...\n", curl_timeout);
		connection_timeout = curl_timeout;
	}

	INIT_LIST_HEAD(&multi_pool);

	/* try loading the trace api */
	if (register_trace_type) {
		rest_proto_id = register_trace_type(rest_id_s);
		if ( global_trace_api ) {
			memcpy(&tprot, global_trace_api, sizeof tprot);
		} else {
			memset(&tprot, 0, sizeof tprot);
			if (trace_prot_bind( REST_TRACE_API_MODULE, &tprot))
				LM_DBG("Can't bind <%s>!\n", REST_TRACE_API_MODULE);
		}
	} else {
		memset(&tprot, 0, sizeof tprot);
	}

	if (is_script_func_used("rest_init_client_tls", -1)) {
		if (load_tls_mgm_api(&tls_api) != 0) {
			LM_ERR("failed to load the tls_mgm API! "
			       "Is the tls_mgm module loaded?\n");
			return -1;
		}
	}

	/* we need to initialize the curl library now, otherwise, if we do it in
	 * child_init(), in curl_easy_init(), the init handler will be run multiple times in parallel */
	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		LM_ERR("could not initialize curl!\n");
		return -1;
	}

	LM_INFO("Module initialized!\n");

	return 0;
}

static int child_init(int rank)
{
	if (init_sync_handle() != 0) {
		LM_ERR("failed to init sync handle\n");
		return -1;
	}

	return 0;
}


static void mod_destroy(void)
{
	curl_global_cleanup();
}

/**************************** Fixup functions *******************************/


static int fixup_rest_get(void **param, int param_no)
{
	switch (param_no) {
	case 1:
		return fixup_spve(param);
	case 2:
	case 3:
	case 4:
		return fixup_pvar(param);

	default:
		LM_ERR("Too many parameters!\n");
		return -1;
	}
}

static int fixup_rest_post(void **param, int param_no)
{
	switch (param_no) {
	case 1:
	case 2:
	case 3:
		return fixup_spve(param);
	case 4:
	case 5:
	case 6:
		return fixup_pvar(param);

	default:
		LM_ERR("Too many parameters!\n");
		return -1;
	}
}

static int fixup_rest_put(void **param, int param_no)
{
	switch (param_no) {
	case 1:
	case 2:
	case 3:
		return fixup_spve(param);
	case 4:
	case 5:
	case 6:
		return fixup_pvar(param);

	default:
		LM_ERR("Too many parameters!\n");
		return -1;
	}
}

/**************************** Module functions *******************************/

static int w_rest_get(struct sip_msg *msg, char *gp_url, char *body_pv,
                      char *ctype_pv, char *code_pv)
{
	str url;

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	return rest_sync_transfer(REST_CLIENT_GET, msg, url.s, NULL, NULL,
	                          (pv_spec_p)body_pv, (pv_spec_p)ctype_pv,
	                          (pv_spec_p)code_pv);
}

static int w_rest_post(struct sip_msg *msg, char *gp_url, char *gp_body,
                   char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv)
{
	str url, body, ctype = { NULL, 0 };

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)gp_body, &body) != 0) {
		LM_ERR("Invalid HTTP POST body pseudo variable!\n");
		return -1;
	}

	if (gp_ctype && fixup_get_svalue(msg, (gparam_p)gp_ctype, &ctype) != 0) {
		LM_ERR("Invalid HTTP POST content type pseudo variable!\n");
		return -1;
	}

	return rest_sync_transfer(REST_CLIENT_POST, msg, url.s, &body, &ctype,
	                          (pv_spec_p)body_pv, (pv_spec_p)ctype_pv,
	                          (pv_spec_p)code_pv);
}

static int w_rest_put(struct sip_msg *msg, char *gp_url, char *gp_body,
                   char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv)
{
	str url, body, ctype = { NULL, 0 };

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)gp_body, &body) != 0) {
		LM_ERR("Invalid HTTP PUT body pseudo variable!\n");
		return -1;
	}

	if (gp_ctype && fixup_get_svalue(msg, (gparam_p)gp_ctype, &ctype) != 0) {
			LM_ERR("Invalid HTTP PUT content type pseudo variable!\n");
			return -1;
	}

	return rest_sync_transfer(REST_CLIENT_PUT, msg, url.s, &body, &ctype,
	                          (pv_spec_p)body_pv, (pv_spec_p)ctype_pv,
	                          (pv_spec_p)code_pv);
}

int async_rest_method(enum rest_client_method method, struct sip_msg *msg,
                      char *url, str *body, str *ctype, async_ctx *ctx,
                      pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv)
{
	rest_async_param *param;
	pv_value_t val;
	long http_rc;
	int read_fd, rc;

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("no more shm\n");
		return RCL_INTERNAL_ERR;
	}
	memset(param, '\0', sizeof *param);

	rc = start_async_http_req(msg, method, url, body, ctype,
			param, &param->body, ctype_pv ? &param->ctype : NULL, &read_fd);

	/* error occurred; no transfer done */
	if (read_fd == ASYNC_NO_IO) {
		ctx->resume_param = NULL;
		ctx->resume_f = NULL;
		if (code_pv) {
			val.flags = PV_VAL_INT|PV_TYPE_INT;
			val.ri = 0;
			if (pv_set_value(msg, (pv_spec_p)code_pv, 0, &val) != 0)
				LM_ERR("failed to set output code pv\n");
		}

		/* keep default async status of NO_IO */
		pkg_free(param);
		return rc;

	/* no need for async - transfer already completed! */
	} else if (read_fd == ASYNC_SYNC) {
		if (code_pv) {
			curl_easy_getinfo(param->handle, CURLINFO_RESPONSE_CODE, &http_rc);
			LM_DBG("HTTP response code: %ld\n", http_rc);

			val.flags = PV_VAL_INT|PV_TYPE_INT;
			val.ri = (int)http_rc;
			if (pv_set_value(msg, (pv_spec_p)code_pv, 0, &val) != 0) {
				LM_ERR("failed to set output code pv\n");
				return RCL_INTERNAL_ERR;
			}
		}

		val.flags = PV_VAL_STR;
		val.rs = param->body;
		if (pv_set_value(msg, (pv_spec_p)body_pv, 0, &val) != 0) {
			LM_ERR("failed to set output body pv\n");
			return RCL_INTERNAL_ERR;
		}

		if (ctype_pv) {
			val.rs = param->ctype;
			if (pv_set_value(msg, (pv_spec_p)ctype_pv, 0, &val) != 0) {
				LM_ERR("failed to set output ctype pv\n");
				return RCL_INTERNAL_ERR;
			}
		}

		pkg_free(param->body.s);
		if (ctype_pv && param->ctype.s)
			pkg_free(param->ctype.s);
		curl_easy_cleanup(param->handle);
		pkg_free(param);

		async_status = ASYNC_SYNC;
		return rc;
	}

	ctx->resume_f = resume_async_http_req;

	param->method = method;
	param->body_pv = (pv_spec_p)body_pv;
	param->ctype_pv = (pv_spec_p)ctype_pv;
	param->code_pv = (pv_spec_p)code_pv;
	ctx->resume_param = param;

	/* async started with success */
	async_status = read_fd;
	return 1;
}

static int w_async_rest_get(struct sip_msg *msg, async_ctx *ctx,
					char *gp_url, char *body_pv, char *ctype_pv, char *code_pv)
{
	str url;

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	LM_DBG("async rest get %.*s %p %p %p\n", url.len, url.s,
			body_pv, ctype_pv, code_pv);

	return async_rest_method(REST_CLIENT_GET, msg, url.s, NULL, NULL, ctx,
				(pv_spec_p)body_pv, (pv_spec_p)ctype_pv, (pv_spec_p)code_pv);
}

static int w_async_rest_post(struct sip_msg *msg, async_ctx *ctx,
							 char *gp_url, char *gp_body, char *gp_ctype,
							 char *body_pv, char *ctype_pv, char *code_pv)
{
	str url, body, ctype = { NULL, 0 };

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)gp_body, &body) != 0) {
		LM_ERR("Invalid HTTP POST body pseudo variable!\n");
		return -1;
	}

	if (gp_ctype && fixup_get_svalue(msg, (gparam_p)gp_ctype, &ctype) != 0) {
		LM_ERR("Invalid HTTP POST content type pseudo variable!\n");
		return -1;
	}

	LM_DBG("async rest post '%.*s' %p %p %p\n", url.len, url.s,
			body_pv, ctype_pv, code_pv);

	return async_rest_method(REST_CLIENT_POST, msg, url.s, &body, &ctype, ctx,
				(pv_spec_p)body_pv, (pv_spec_p)ctype_pv, (pv_spec_p)code_pv);
}

static int w_async_rest_put(struct sip_msg *msg, async_ctx *ctx,
							char *gp_url, char *gp_body, char *gp_ctype,
							char *body_pv, char *ctype_pv, char *code_pv)
{
	str url, body, ctype = { NULL, 0 };

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)gp_body, &body) != 0) {
		LM_ERR("Invalid HTTP PUT body pseudo variable!\n");
		return -1;
	}

	if (gp_ctype && fixup_get_svalue(msg, (gparam_p)gp_ctype, &ctype) != 0) {
		LM_ERR("Invalid HTTP PUT content type pseudo variable!\n");
		return -1;
	}

	LM_DBG("async rest put '%.*s' %p %p %p\n",
		url.len, url.s, body_pv, ctype_pv, code_pv);

	return async_rest_method(REST_CLIENT_PUT, msg, url.s, &body, &ctype, ctx,
				(pv_spec_p)body_pv, (pv_spec_p)ctype_pv, (pv_spec_p)code_pv);
}

static int w_rest_append_hf(struct sip_msg *msg, char *gp_hfv)
{
	str hfv;

	if (fixup_get_svalue(msg, (gparam_p)gp_hfv, &hfv) != 0) {
		LM_ERR("cannot retrieve header field value\n");
		return -1;
	}

	return rest_append_hf_method(msg, &hfv);
}

static int w_rest_init_client_tls(struct sip_msg *msg, char *gp_tls_dom)
{
	str tls_client_dom;

	if (fixup_get_svalue(msg, (gparam_p)gp_tls_dom, &tls_client_dom) != 0) {
		LM_ERR("cannot retrieve header field value\n");
		return -1;
	}

	return rest_init_client_tls(msg, &tls_client_dom);
}
