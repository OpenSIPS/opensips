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
#include "rest_client.h"
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

/* see curl.h or https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_VERSION.html */
int curl_http_version = CURL_HTTP_VERSION_NONE;

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
static int cfg_validate(void);

/*
 * Function headers
 */
static int w_rest_get(struct sip_msg *msg, str *url, pv_spec_t *body_pv,
                      pv_spec_t *ctype_pv, pv_spec_t *code_pv);
static int w_rest_post(struct sip_msg *msg, str *url, str *body, str *_ctype,
					pv_spec_t *body_pv, pv_spec_t *ctype_pv, pv_spec_t *code_pv);
static int w_rest_put(struct sip_msg *msg, str *url, str *body, str *_ctype,
					pv_spec_t *body_pv, pv_spec_t *ctype_pv, pv_spec_t *code_pv);

static int w_async_rest_get(struct sip_msg *msg, async_ctx *ctx, str *url,
				pv_spec_t *body_pv, pv_spec_t *ctype_pv, pv_spec_t *code_pv);
static int w_async_rest_post(struct sip_msg *msg, async_ctx *ctx,
			str *url, str *body, str *_ctype, pv_spec_t *body_pv,
			pv_spec_t *ctype_pv, pv_spec_t *code_pv);
static int w_async_rest_put(struct sip_msg *msg, async_ctx *ctx,
			str *url, str *body, str *_ctype, pv_spec_t *body_pv,
			pv_spec_t *ctype_pv, pv_spec_t *code_pv);

static int w_rest_append_hf(struct sip_msg *msg, str *hfv);
static int w_rest_init_client_tls(struct sip_msg *msg, str *tls_client_dom);
int validate_curl_http_version(const int *http_version);

/* module dependencies */
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tracer", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 }
	},
	{ /* modparam dependencies */
		{ NULL, NULL}
	}
};

static acmd_export_t acmds[] = {
	{"rest_get",(acmd_function)w_async_rest_get, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}}},
	{"rest_post",(acmd_function)w_async_rest_post, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}}},
	{"rest_put",(acmd_function)w_async_rest_put, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}}},
	{0,0,{{0,0,0}}}
};

/*
 * Exported functions
 */

static cmd_export_t cmds[] = {
	{"rest_get",(cmd_function)w_rest_get, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"rest_post",(cmd_function)w_rest_post, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"rest_put",(cmd_function)w_rest_put, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"rest_append_hf",(cmd_function)w_rest_append_hf, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{"rest_init_client_tls",(cmd_function)w_rest_init_client_tls, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported transformations
 */
int tr_rest_parse(str* in, trans_t *t);
int tr_rest_eval(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

static trans_export_t trans[] = {
	{str_init("rest"), tr_rest_parse, tr_rest_eval},
	{{0,0},0,0}
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
	{ "curl_http_version",	INT_PARAM, &curl_http_version	},
	{ "enable_expect_100",	INT_PARAM, &enable_expect_100	},
	{ 0, 0, 0 }
};


/*
 * Module parameter variables
 */
struct module_exports exports = {
	"rest_client",
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,   /* module version */
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,				  /* load function */
	&deps,            /* OpenSIPS module dependencies */
	cmds,             /* Exported functions */
	acmds,            /* Exported async functions */
	params,           /* Exported parameters */
	NULL,             /* exported statistics */
	NULL,             /* exported MI functions */
	NULL,             /* exported pseudo-variables */
	trans,	          /* exported transformations */
	NULL,             /* extra processes */
	NULL,             /* module pre-initialization function */
	mod_init,         /* module initialization function */
	NULL,             /* response function*/
	mod_destroy,      /* module destroy/cleanup function */
	child_init,       /* per-child init function */
	cfg_validate      /* reload confirm function */
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

	if (!validate_curl_http_version(&curl_http_version))
		return -1;

	/* we need to initialize the curl library now, otherwise, if we do it in
	 * child_init(), in curl_easy_init(), the init handler will be run multiple times in parallel */
	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
		LM_ERR("could not initialize curl!\n");
		return -1;
	}

	LM_INFO("Module initialized!\n");

	return 0;
}


static int cfg_validate(void)
{
	/* if TLS_MGM was already load, we are fine */
	if (tls_api.find_server_domain)
		return 1;

	if (is_script_func_used("rest_init_client_tls", -1)) {
		LM_ERR("rest_init_client_tls() was found, but module started "
			"without TLS support, better restart\n");
		return 0;
	}

	return 1;
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


int validate_curl_http_version(const int *http_version)
{
	switch (*http_version) {
	case CURL_HTTP_VERSION_NONE:
	case CURL_HTTP_VERSION_1_0:
	case CURL_HTTP_VERSION_1_1:
		break;
#if (LIBCURL_VERSION_NUM >= 0x072100)
	case CURL_HTTP_VERSION_2_0:
		break;
#endif
#if (LIBCURL_VERSION_NUM >= 0x072f00)
	case CURL_HTTP_VERSION_2TLS:
		break;
#endif
#if (LIBCURL_VERSION_NUM >= 0x073100)
	case CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE:
		break;
#endif
	default:
		LM_ERR("invalid or unsupported libcurl http version (%d)\n",
		       *http_version);
		return 0;
	}

	return 1;
}

/**************************** Transformations ********************************/

/**
 * tr_rest_parse - Prepare to URL encode a string value
 * @in:		        raw parameter list (braces removed, module name truncated) i.e. "escape"
 * @t:		        transformation parameters, will return transformation subtype
 *
 * @return:
 *  0 - success
 * -1 - error
*/
int tr_rest_parse(str* in, trans_t *t)
{
	char *p;
	str name;

	if(in == NULL || in->s == NULL || t == NULL)
		return -1;

	p = in->s;
	name.s = in->s;
	
	/* scan parameter list - expect a transformation name only, reject anything else */
	while (*p && *p != TR_PARAM_MARKER && *p != TR_RBRACKET) p++;
	if (*p == TR_PARAM_MARKER) {
		LM_ERR("transformation supports single parameter only: %.*s\n", in->len, in->s);
		return -1;
	}

	name.len = p - name.s;

	/* Validate that this is a known transformation */
	if (name.len == 6 && !memcmp(name.s, "escape", 6)) {
		t->subtype = TR_REST_ESCAPE;
	} else if (name.len == 8 && !memcmp(name.s, "unescape", 8)) {
		t->subtype = TR_REST_UNESCAPE;
	} else {
		LM_ERR("unknown transformation: <%.*s>\n", name.len, name.s);
		return -1;
	}

	return 0;
}

/**
 * tr_rest_eval - Perform URL encode on a string value
 * @msg:		        sip message struct
 * @tp:     		    transformation parameters
 * @subtype:            transformation mode (see: parse) (TR_REST_ESCAPE/TR_REST_UNESCAPE)
 * @val:		        i/o, on success as (un)escaped by libcurl, else NULL
 *
 * @return:
 *  0 - success
 * -1 - error
*/
int tr_rest_eval(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	str input_str;
	static str output_buf;
	char *curl_out;

	if (!val)
		return -1;

	if (val->flags & PV_VAL_NULL)
		return 0;

	if((!(val->flags & PV_VAL_STR)) || val->rs.len <= 0)
		goto error;

	input_str = val->rs;

	if (subtype == TR_REST_ESCAPE) {

#if ( LIBCURL_VERSION_NUM >= 0x071504 )
		curl_out = curl_easy_escape(sync_handle, input_str.s, input_str.len);
		if (!curl_out) {
			LM_ERR("failed to execute curl_easy_escape on '%.*s'\n",
			       input_str.len, input_str.s);
			goto error;
		}

		LM_DBG("curl_easy_escape '%.*s' returns '%s'\n", input_str.len,
		input_str.s, curl_out);
#else
		curl_out = curl_escape(input_str.s, input_str.len);
		if (!curl_out) {
			LM_ERR("failed to execute curl_escape on '%.*s'\n",
			       input_str.len, input_str.s);
			goto error;
		}

		LM_DBG("curl_escape '%.*s' returns '%s'\n", input_str.len,
		       input_str.s, curl_out);
#endif

		// Ensure the output buffer can accommodate the response value
		if (pkg_str_extend(&output_buf, strlen(curl_out)+1) != 0) {
			LM_ERR("oom\n");
			curl_free(curl_out);
			goto error;
		}
		LM_DBG("extended output_buf to %d (%p)\n", output_buf.len, output_buf.s);

		// Capture and free the result
		str_cpy(&output_buf, _str(curl_out));
		curl_free(curl_out);

		if (pv_get_strval(msg, NULL, val, &output_buf) != 0) {
			LM_ERR("transform escape failed to set output pvar!\n");
			goto error;
		}

	} else if (subtype == TR_REST_UNESCAPE) {

#if ( LIBCURL_VERSION_NUM >= 0x071504 )
		curl_out = curl_easy_unescape(sync_handle, input_str.s, input_str.len, NULL);
		if (!curl_out) {
			LM_ERR("failed to execute curl_easy_unescape on '%.*s'\n",
			       input_str.len, input_str.s);
			goto error;
		}

		LM_DBG("curl_easy_unescape '%.*s' returns '%s'\n", input_str.len,
		input_str.s, curl_out);
#else
		curl_out = curl_unescape(input_str.s, input_str.len);
		if (!curl_out) {
			LM_ERR("failed to execute curl_unescape on '%.*s'\n",
			       input_str.len, input_str.s);
			goto error;
		}

		LM_DBG("curl_unescape '%.*s' returns '%s'\n", input_str.len,
		       input_str.s, curl_out);
#endif

		// Ensure the output buffer can accommodate the response value
		if (pkg_str_extend(&output_buf, strlen(curl_out)+1) != 0) {
			LM_ERR("oom\n");
			curl_free(curl_out);
			goto error;
		}
		LM_DBG("extended output_buf to %d (%p)\n", output_buf.len, output_buf.s);

		// Capture and free the result
		str_cpy(&output_buf, _str(curl_out));
		curl_free(curl_out);

		if (pv_get_strval(msg, NULL, val, &output_buf) != 0) {
			LM_ERR("transform unescape failed to set output pvar!\n");
			goto error;
		}

	} else {
		LM_BUG("unknown transformation subtype [%d]\n", subtype);
		goto error;
	}

	return 0;

error:
	val->flags = PV_VAL_NULL;
	return -1;
}

/**************************** Module functions *******************************/

static int w_rest_get(struct sip_msg *msg, str *url, pv_spec_t *body_pv,
                      pv_spec_t *ctype_pv, pv_spec_t *code_pv)
{
	str url_nt;
	int rc;

	if (pkg_nt_str_dup(&url_nt, url) < 0) {
		LM_ERR("No more pkg memory\n");
		return RCL_INTERNAL_ERR;
	}

	rc = rest_sync_transfer(REST_CLIENT_GET, msg, url_nt.s, NULL, NULL,
	                          body_pv, ctype_pv, code_pv);

	pkg_free(url_nt.s);
	return rc;
}

static int w_rest_post(struct sip_msg *msg, str *url, str *body, str *_ctype,
					pv_spec_t *body_pv, pv_spec_t *ctype_pv, pv_spec_t *code_pv)
{
	str ctype = { NULL, 0 };
	str url_nt;
	int rc;

	if (pkg_nt_str_dup(&url_nt, url) < 0) {
		LM_ERR("No more pkg memory\n");
		return RCL_INTERNAL_ERR;
	}

	if (_ctype)
		ctype = *_ctype;

	rc = rest_sync_transfer(REST_CLIENT_POST, msg, url_nt.s, body, &ctype,
	                          body_pv, ctype_pv, code_pv);

	pkg_free(url_nt.s);
	return rc;
}

static int w_rest_put(struct sip_msg *msg, str *url, str *body, str *_ctype,
					pv_spec_t *body_pv, pv_spec_t *ctype_pv, pv_spec_t *code_pv)
{
	str ctype = { NULL, 0 };
	str url_nt;
	int rc;

	if (pkg_nt_str_dup(&url_nt, url) < 0) {
		LM_ERR("No more pkg memory\n");
		return RCL_INTERNAL_ERR;
	}

	if (_ctype)
		ctype = *_ctype;

	rc = rest_sync_transfer(REST_CLIENT_PUT, msg, url_nt.s, body, &ctype,
	                          body_pv, ctype_pv, code_pv);

	pkg_free(url_nt.s);
	return rc;
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

static int w_async_rest_get(struct sip_msg *msg, async_ctx *ctx, str *url,
				pv_spec_t *body_pv, pv_spec_t *ctype_pv, pv_spec_t *code_pv)
{
	str url_nt;
	int rc;

	if (pkg_nt_str_dup(&url_nt, url) < 0) {
		LM_ERR("No more pkg memory\n");
		return RCL_INTERNAL_ERR;
	}

	LM_DBG("async rest get %.*s %p %p %p\n", url->len, url->s,
			body_pv, ctype_pv, code_pv);

	rc = async_rest_method(REST_CLIENT_GET, msg, url_nt.s, NULL, NULL, ctx,
				body_pv, ctype_pv, code_pv);

	pkg_free(url_nt.s);
	return rc;
}

static int w_async_rest_post(struct sip_msg *msg, async_ctx *ctx,
			str *url, str *body, str *_ctype, pv_spec_t *body_pv,
			pv_spec_t *ctype_pv, pv_spec_t *code_pv)
{
	str ctype = { NULL, 0 };
	str url_nt;
	int rc;

	if (pkg_nt_str_dup(&url_nt, url) < 0) {
		LM_ERR("No more pkg memory\n");
		return RCL_INTERNAL_ERR;
	}

	if (_ctype)
		ctype = *_ctype;

	LM_DBG("async rest post '%.*s' %p %p %p\n", url->len, url->s,
			body_pv, ctype_pv, code_pv);

	rc = async_rest_method(REST_CLIENT_POST, msg, url_nt.s, body, &ctype, ctx,
							body_pv, ctype_pv, code_pv);

	pkg_free(url_nt.s);
	return rc;
}

static int w_async_rest_put(struct sip_msg *msg, async_ctx *ctx,
			str *url, str *body, str *_ctype, pv_spec_t *body_pv,
			pv_spec_t *ctype_pv, pv_spec_t *code_pv)
{
	str ctype = { NULL, 0 };
	str url_nt;
	int rc;

	if (pkg_nt_str_dup(&url_nt, url) < 0) {
		LM_ERR("No more pkg memory\n");
		return RCL_INTERNAL_ERR;
	}

	if (_ctype)
		ctype = *_ctype;

	LM_DBG("async rest put '%.*s' %p %p %p\n",
		url->len, url->s, body_pv, ctype_pv, code_pv);

	rc = async_rest_method(REST_CLIENT_PUT, msg, url_nt.s, body, &ctype, ctx,
						body_pv, ctype_pv, code_pv);

	pkg_free(url_nt.s);
	return rc;
}

static int w_rest_append_hf(struct sip_msg *msg, str *hfv)
{
	return rest_append_hf_method(msg, hfv);
}

static int w_rest_init_client_tls(struct sip_msg *msg, str *tls_client_dom)
{
	return rest_init_client_tls(msg, tls_client_dom);
}
