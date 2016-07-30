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


#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "../../async.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"

#include "rest_methods.h"

/*
 * Module parameters
 */
long connection_timeout = 20;
long connection_timeout_ms;
long curl_timeout = 20;

char *ssl_capath;

/* libcurl enables these by default */
int ssl_verifypeer = 1;
int ssl_verifyhost = 1;

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

/*
 * Function headers
 */
static int w_rest_get(struct sip_msg *msg, char *gp_url, char *body_pv,
				char *ctype_pv, char *code_pv);
static int w_rest_post(struct sip_msg *msg, char *gp_url, char *gp_body,
				char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv);

static int w_async_rest_get(struct sip_msg *msg, async_resume_module **resume_f,
							void **resume_param, char *gp_url,
							char *body_pv, char *ctype_pv, char *code_pv);
static int w_async_rest_post(struct sip_msg *msg, async_resume_module **resume_f,
					 void **resume_param, char *gp_url, char *gp_body,
					 char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv);

static int w_rest_append_hf(struct sip_msg *msg, char *gp_hfv);

static acmd_export_t acmds[] = {
	{ "rest_get",  (acmd_function)w_async_rest_get,  2, fixup_rest_get },
	{ "rest_get",  (acmd_function)w_async_rest_get,  3, fixup_rest_get },
	{ "rest_get",  (acmd_function)w_async_rest_get,  4, fixup_rest_get },
	{ "rest_post",  (acmd_function)w_async_rest_post,  4, fixup_rest_post },
	{ "rest_post",  (acmd_function)w_async_rest_post,  5, fixup_rest_post },
	{ "rest_post",  (acmd_function)w_async_rest_post,  6, fixup_rest_post },
	{ 0, 0, 0, 0 }
};

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{ "rest_get",(cmd_function)w_rest_get, 2, fixup_rest_get, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_get",(cmd_function)w_rest_get, 3, fixup_rest_get, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_get",(cmd_function)w_rest_get, 4, fixup_rest_get, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_post",(cmd_function)w_rest_post, 4, fixup_rest_post, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_post",(cmd_function)w_rest_post, 5, fixup_rest_post, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_post",(cmd_function)w_rest_post, 6, fixup_rest_post, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_append_hf",(cmd_function)w_rest_append_hf, 1, fixup_spve_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ 0, 0, 0, 0, 0, 0 }
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{ "connection_timeout",	INT_PARAM, &connection_timeout	},
	{ "curl_timeout",		INT_PARAM, &curl_timeout		},
	{ "ssl_capath",			STR_PARAM, &ssl_capath			},
	{ "ssl_verifypeer",		INT_PARAM, &ssl_verifypeer		},
	{ "ssl_verifyhost",		INT_PARAM, &ssl_verifyhost		},
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
	NULL,            /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	acmds,    /* Exported async functions */
	params,   /* Exported parameters */
	NULL,     /* exported statistics */
	NULL,     /* exported MI functions */
	NULL,     /* exported pseudo-variables */
	NULL,     /* extra processes */
	mod_init, /* module initialization function */
	NULL,     /* response function*/
	mod_destroy,
	child_init,/* per-child init function */
};

static void *osips_malloc(size_t size)
{
	void *p = pkg_malloc(size);

	return p;
}

static void *osips_calloc(size_t nmemb, size_t size)
{
	void *p = pkg_malloc(nmemb * size);
	if (p)
		memset(p, '\0', nmemb * size);

	return p;
}

static void *osips_realloc(void *ptr, size_t size)
{
	void *p = pkg_realloc(ptr, size);

	return p;
}

static char *osips_strdup(const char *cp)
{
	char *rval;
	int len;

	len = strlen(cp) + 1;
	rval = pkg_malloc(len);
	if (!rval)
		return NULL;

	memcpy(rval, cp, len);
	return rval;
}

static void osips_free(void *ptr)
{
	if (ptr)
		pkg_free(ptr);
}

static int mod_init(void)
{
	LM_DBG("Initializing...\n");

	connection_timeout_ms = connection_timeout * 1000L;

	curl_global_init_mem(CURL_GLOBAL_ALL,
						 osips_malloc,
						 osips_free,
						 osips_realloc,
						 osips_strdup,
						 osips_calloc);

	multi_handle = curl_multi_init();

	LM_INFO("Module initialized!\n");

	return 0;
}

static int child_init(int rank)
{
	if (rank <= PROC_MAIN)
		return 0;

	multi_handle = curl_multi_init();
	if (!multi_handle) {
		LM_ERR("failed to init CURLM handle\n");
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

/**************************** Module functions *******************************/

static int w_rest_get(struct sip_msg *msg, char *gp_url, char *body_pv,
                      char *ctype_pv, char *code_pv)
{
	str url;

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	return rest_get_method(msg, url.s, (pv_spec_p)body_pv, (pv_spec_p)ctype_pv,
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

	return rest_post_method(msg, url.s, body.s, ctype.s, (pv_spec_p)body_pv,
	                        (pv_spec_p)ctype_pv, (pv_spec_p)code_pv);
}

static void set_output_pv_params(struct sip_msg *msg, str *body_in, pv_spec_p body_pv, str *ctype_in,
								 pv_spec_p ctype_pv, CURL *handle, pv_spec_p code_pv)
{
	pv_value_t val;
	long http_rc;
	CURLcode rc;

	val.flags = PV_VAL_STR;
	val.rs = *body_in;

	if (pv_set_value(msg, (pv_spec_p)body_pv, 0, &val) != 0)
		LM_ERR("failed to set output body pv\n");

	if (ctype_pv) {
		val.rs = *ctype_in;
		if (pv_set_value(msg, (pv_spec_p)ctype_pv, 0, &val) != 0)
			LM_ERR("failed to set output ctype pv\n");
	}

	if (code_pv) {
		rc = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_rc);
		if (rc != CURLE_OK)
			LM_ERR("curl_easy_getinfo: %s\n", curl_easy_strerror(rc));

		LM_DBG("Last response code: %ld\n", http_rc);

		val.flags = PV_VAL_INT|PV_TYPE_INT;
		val.ri = (int)http_rc;
		if (pv_set_value(msg, (pv_spec_p)code_pv, 0, &val) != 0)
			LM_ERR("failed to set output code pv\n");
	}
}

static int w_async_rest_get(struct sip_msg *msg, async_resume_module **resume_f,
							void **resume_param, char *gp_url,
							char *body_pv, char *ctype_pv, char *code_pv)
{
	rest_async_param *param;
	str url;
	int read_fd;

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	LM_DBG("async rest get %.*s %p %p %p\n", url.len, url.s, body_pv, ctype_pv, code_pv);

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("no more shm\n");
		return -1;
	}
	memset(param, '\0', sizeof *param);

	read_fd = start_async_http_req(msg, REST_CLIENT_GET, url.s, NULL, NULL,
				&param->handle, &param->body, ctype_pv ? &param->ctype : NULL);

	/* error occurred; no transfer done */
	if (read_fd == ASYNC_NO_IO) {
		*resume_param = NULL;
		*resume_f = NULL;
		/* keep default async status of NO_IO */
		return -1;

	/* no need for async - transfer already completed! */
	} else if (read_fd == ASYNC_SYNC) {
		set_output_pv_params(msg, &param->body, (pv_spec_p)body_pv,
							 &param->ctype, (pv_spec_p)ctype_pv,
							 param->handle, (pv_spec_p)code_pv);

		pkg_free(param->body.s);
		if (ctype_pv && param->ctype.s)
			pkg_free(param->ctype.s);
		curl_easy_cleanup(param->handle);
		pkg_free(param);

		return ASYNC_SYNC;
	}

	*resume_f = resume_async_http_req;

	param->method = REST_CLIENT_GET;
	param->body_pv = (pv_spec_p)body_pv;
	param->ctype_pv = (pv_spec_p)ctype_pv;
	param->code_pv = (pv_spec_p)code_pv;
	*resume_param = param;
	/* async started with success */
	async_status = read_fd;

	return 1;
}

static int w_async_rest_post(struct sip_msg *msg, async_resume_module **resume_f,
					 void **resume_param, char *gp_url, char *gp_body,
					 char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv)
{
	rest_async_param *param;
	str url, body, ctype = { NULL, 0 };
	int read_fd;

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

	LM_DBG("async rest post '%.*s' %p %p %p\n", url.len, url.s, body_pv, ctype_pv, code_pv);

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("no more shm\n");
		return -1;
	}
	memset(param, '\0', sizeof *param);

	read_fd = start_async_http_req(msg, REST_CLIENT_POST, url.s, body.s, ctype.s,
				&param->handle, &param->body, ctype_pv ? &param->ctype : NULL);

	/* error occurred; no transfer done */
	if (read_fd == ASYNC_NO_IO) {
		*resume_param = NULL;
		*resume_f = NULL;
		/* keep default async status of NO_IO */
		return -1;

	/* no need for async - transfer already completed! */
	} else if (read_fd == ASYNC_SYNC) {
		set_output_pv_params(msg, &param->body, (pv_spec_p)body_pv,
							 &param->ctype, (pv_spec_p)ctype_pv,
							 param->handle, (pv_spec_p)code_pv);

		pkg_free(param->body.s);
		if (ctype_pv && param->ctype.s)
			pkg_free(param->ctype.s);
		curl_easy_cleanup(param->handle);
		pkg_free(param);

		return ASYNC_SYNC;
	}

	*resume_f = resume_async_http_req;

	param->method = REST_CLIENT_POST;
	param->body_pv = (pv_spec_p)body_pv;
	param->ctype_pv = (pv_spec_p)ctype_pv;
	param->code_pv = (pv_spec_p)code_pv;
	*resume_param = param;
	/* async started with success */
	async_status = read_fd;

	return 1;
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
