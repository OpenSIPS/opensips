/*
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * History:
 * ---------
 *  2013-03-04  first version (osas)
 */

#include <stdlib.h>

#include "../../globals.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../httpd/httpd_load.h"
#include "http_fnc.h"
#include "../../mi/mi_trace.h"

/* module functions */
static int mod_init();
static int destroy(void);
int mi_json_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t mi_json_flush_data(void *cls, uint64_t pos, char *buf,
		size_t max);

str http_root = str_init("mi");
httpd_api_t httpd_api;

static str trace_destination_name = {NULL, 0};
trace_dest t_dst;

/* formated JSON response printing, disabled by default */
int pretty_print;

/* tracing is disabled by default */
int mi_trace_mod_id = -1;
char* mi_trace_bwlist_s;

static const str MI_HTTP_U_ERROR = str_init("Internal Server Error");
static const str MI_HTTP_ACCEPTED = str_init("202 Accepted");
static const str MI_HTTP_U_METHOD = str_init("405 Method Not Allowed");
static const str MI_HTTP_U_BAD_REQ = str_init("400 Bad Request");

static const char *unknown_method = "unknown";

static str backend = str_init("json");
static union sockaddr_union* sv_socket = NULL;


/* module parameters */
static param_export_t mi_params[] = {
	{"root",      STR_PARAM, &http_root.s},
	{"trace_destination", STR_PARAM, &trace_destination_name.s},
	{"trace_bwlist",        STR_PARAM,    &mi_trace_bwlist_s  },
	{"pretty_printing",		INT_PARAM,	&pretty_print},
	{0,0,0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "httpd", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/* module exports */
struct module_exports exports = {
	"mi_http",					/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	&deps,						/* OpenSIPS module dependencies */
	NULL,						/* exported functions */
	NULL,						/* exported async functions */
	mi_params,					/* exported parameters */
	NULL,						/* exported statistics */
	NULL,						/* exported MI functions */
	NULL,						/* exported PV */
	NULL,						/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,		/* response handling function */
	(destroy_function) destroy,	/* destroy function */
	NULL,						/* per-child init function */
	NULL						/* reload confirm function */
};


void proc_init(void)
{
	/* Build async lock */
	if (mi_json_init_async_lock() != 0)
		exit(-1);

	/* if tracing enabled init correlation id */
	if ( t_dst ) {
		if ( load_correlation_id() < 0 ) {
			LM_ERR("can't find correlation id params!\n");
			exit(-1);
		}

		if ( mi_trace_api && mi_trace_bwlist_s ) {
			if ( parse_mi_cmd_bwlist( mi_trace_mod_id,
						mi_trace_bwlist_s, strlen(mi_trace_bwlist_s) ) < 0 ) {
				LM_ERR("invalid bwlist <%s>!\n", mi_trace_bwlist_s);
				exit(-1);
			}
		}
	}

	return;
}

static int mod_init(void)
{
	http_root.len = strlen(http_root.s);

	/* Load httpd api */
	if(load_httpd_api(&httpd_api)<0) {
		LM_ERR("Failed to load httpd api\n");
		return -1;
	}

	/* Load httpd hooks */
	httpd_api.register_httpdcb(exports.name, &http_root,
				&mi_json_answer_to_connection,
				&mi_json_flush_data,
				HTTPD_APPLICATION_JSON_CNT_TYPE,
				&proc_init);

	if (trace_destination_name.s) {
		trace_destination_name.len = strlen( trace_destination_name.s);

		try_load_trace_api();
		if (mi_trace_api && mi_trace_api->get_trace_dest_by_name) {
			t_dst = mi_trace_api->get_trace_dest_by_name(&trace_destination_name);
		}

		mi_trace_mod_id = register_mi_trace_mod();
	}

	return 0;
}


int destroy(void)
{
	mi_json_destroy_async_lock();
	return 0;
}



static ssize_t mi_json_flush_data(void *cls, uint64_t pos, char *buf,
																	size_t max)
{
	/* if no content for the response, just inform httpd */
	return -1;
}

#define MI_JSON_MAX_WAIT       2*60*4
static inline mi_response_t *mi_json_wait_async_reply(struct mi_handler *hdl)
{
	mi_json_async_resp_data_t *async_resp_data =
		(mi_json_async_resp_data_t*)(hdl+1);
	mi_response_t *mi_resp;
	int i;
	int x;

	for( i=0 ; i<MI_JSON_MAX_WAIT ; i++ ) {
		if (hdl->param)
			break;
		sleep_us(1000*500);
	}

	if (i==MI_JSON_MAX_WAIT) {
		/* no more waiting ....*/
		lock_get(async_resp_data->lock);
		if (hdl->param==NULL) {
			hdl->param = MI_JSON_ASYNC_EXPIRED;
			x = 0;
		} else {
			x = 1;
		}
		lock_release(async_resp_data->lock);
		if (x==0) {
			LM_INFO("exiting before receiving reply\n");
			return NULL;
		}
	}

	mi_resp = (mi_response_t *)hdl->param;
	if (mi_resp==MI_JSON_ASYNC_FAILED)
		mi_resp = NULL;

	/* free the async handler*/
	shm_free(hdl);

	return mi_resp;
}

#define MI_HTTP_OK_CODE				200
#define MI_HTTP_ACCEPTED_CODE		202
#define MI_HTTP_BAD_REQUEST_CODE	400
#define MI_HTTP_METHOD_ERR_CODE		405
#define MI_HTTP_INTERNAL_ERR_CODE	500

static inline void trace_json_err(union sockaddr_union* cl_socket, str* message)
{
	char *req_method = (char *)unknown_method;

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	mi_trace_request(cl_socket, sv_socket, req_method, strlen(req_method),
		NULL, &backend, t_dst);

	mi_trace_reply( sv_socket, cl_socket, message, t_dst);
}

void trace_json_request(struct mi_cmd* f, char *req_method,
					union sockaddr_union* cl_socket, mi_item_t *params)
{
	if (!req_method)
		req_method = (char *)unknown_method;

	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	mi_trace_request(cl_socket, sv_socket, req_method, strlen(req_method),
		params, &backend, t_dst);
}

static inline void trace_json_reply(struct mi_cmd* f,
								union sockaddr_union* cl_socket, str* message)
{
	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	mi_trace_reply(sv_socket, cl_socket, message, t_dst);
}

int mi_json_answer_to_connection (void *cls, void *connection,
	const char *url, const char *method,
	const char *version, const char *upload_data,
	size_t upload_data_size, void **con_cls,
	str *buffer, str *page, union sockaddr_union* cl_socket)
{
	const char **parse_end = NULL;
	char *req_nt;
	char *req_method = NULL;
	mi_request_t request;
	mi_response_t *response;
	struct mi_handler *async_hdl;
	struct mi_cmd *cmd = NULL;
	int rc, ret_code;
	int is_shm = 0;

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
			"version=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)upload_data_size, upload_data, *con_cls);

	page->s = NULL;
	page->len = 0;

	if (strncmp(method, "POST", 4)) {
		LM_ERR("unexpected http method [%s]\n", method);
		trace_json_err(cl_socket, (str *)&MI_HTTP_U_METHOD);

		return MI_HTTP_METHOD_ERR_CODE;
	}

	if (upload_data_size == 0) {
		LM_ERR("empty request\n");
		trace_json_err(cl_socket, (str *)&MI_HTTP_U_BAD_REQ);

		return MI_HTTP_BAD_REQUEST_CODE;
	}

	req_nt = pkg_malloc(upload_data_size + 1);
	if (!req_nt) {
		LM_ERR("oom!\n");
		trace_json_err(cl_socket, (str *)&MI_HTTP_U_ERROR);

		return MI_HTTP_INTERNAL_ERR_CODE;
	}
	memcpy(req_nt, upload_data, upload_data_size);
	req_nt[upload_data_size] = 0;

	memset(&request, 0, sizeof request);
	parse_mi_request(req_nt, parse_end, &request);

	req_method = mi_get_req_method(&request);
	if (req_method)
		cmd = lookup_mi_cmd(req_method, strlen(req_method));

	response = mi_http_run_mi_cmd(cmd, req_method, &request,
					cl_socket, &async_hdl);

	if (response == MI_ASYNC_RPL) {
		LM_DBG("got an async reply\n");
		response = mi_json_wait_async_reply(async_hdl);
		is_shm = 1;
	}

	if (response == NULL) {
		LM_ERR("failed to build response\n");
		trace_json_reply(cmd, cl_socket, (str *)&MI_HTTP_U_ERROR);

		ret_code = MI_HTTP_INTERNAL_ERR_CODE;
	} else {
		LM_DBG("building on page\n");

		rc = print_mi_response(response, request.id, buffer, pretty_print);

		if (rc == MI_NO_RPL) {
			LM_DBG("No reply for jsonrpc notification\n");
			trace_json_reply(cmd, cl_socket, (str *)&MI_HTTP_ACCEPTED);

			ret_code = MI_HTTP_ACCEPTED_CODE;
		} else if (rc < 0) {
			LM_ERR("failed to print json response\n");
			trace_json_reply(cmd, cl_socket, (str *)&MI_HTTP_U_ERROR);

			ret_code = MI_HTTP_INTERNAL_ERR_CODE;
		} else {
			page->s = buffer->s;
			page->len = strlen(buffer->s);
			trace_json_reply(cmd, cl_socket, page);

			ret_code = MI_HTTP_OK_CODE;
		}

		if (is_shm)
			free_shm_mi_response(response);
		else
			free_mi_response(response);
	}

	free_mi_request_parsed(&request);
	pkg_free(req_nt);

	return ret_code;
}
