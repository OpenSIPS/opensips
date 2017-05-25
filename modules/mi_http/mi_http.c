/*
 * Copyright (C) 2011-2013 VoIP Embedded Inc.
 *
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
 *  2011-09-20  first version (osas)
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
int mi_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t mi_http_flush_data(void *cls, uint64_t pos, char *buf, size_t max);

str http_root = str_init("mi");
int http_method = 0;

httpd_api_t httpd_api;

static str trace_destination_name = {NULL, 0};
trace_dest t_dst;
extern http_mi_cmd_t* http_mi_cmds;

int mi_trace_mod_id;
char* mi_trace_bwlist_s;


static const str MI_HTTP_U_ERROR = str_init("<html><body>"
"Internal server error!</body></html>");
static const str MI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str MI_HTTP_U_METHOD = str_init("<html><body>"
"Unexpected method (only GET is accepted)!</body></html>");

static str MI_HTTP_U_ERROR_REASON = str_init("Internal server error!");
static str MI_HTTP_U_URL_REASON = str_init("Unable to parse URL!");
static str MI_HTTP_U_METHOD_REASON = str_init("Unexpected method! Only GET is accepted!");


/* module parameters */
static param_export_t mi_params[] = {
	{"mi_http_root",   STR_PARAM, &http_root.s},
	{"mi_http_method", INT_PARAM, &http_method},
	{"trace_destination", STR_PARAM, &trace_destination_name.s},
	{"trace_bwlist",        STR_PARAM,    &mi_trace_bwlist_s  },
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
	"mi_http",                          /* module name */
	MOD_TYPE_DEFAULT,                   /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,                    /* dlopen flags */
	&deps,                              /* OpenSIPS module dependencies */
	0,                                  /* exported functions */
	0,                                  /* exported async functions */
	mi_params,                          /* exported parameters */
	0,                                  /* exported statistics */
	0,                                  /* exported MI functions */
	0,                                  /* exported PV */
	0,									/* exported transformations */
	0,                                  /* extra processes */
	mod_init,                           /* module initialization function */
	(response_function) 0,              /* response handling function */
	(destroy_function) destroy,         /* destroy function */
	NULL                                /* per-child init function */
};


void proc_init(void)
{
	/* Build a cache of all mi commands */
	if (0!=mi_http_init_cmds())
		exit(-1);

	/* Build async lock */
	if (mi_http_init_async_lock() != 0)
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

	if (http_method<0 || http_method>1) {
		LM_ERR("mi_http_method can be between [0,1]\n");
		return -1;
	}
	/* Load httpd api */
	if(load_httpd_api(&httpd_api)<0) {
		LM_ERR("Failed to load httpd api\n");
		return -1;
	}
	/* Load httpd hooks */
	httpd_api.register_httpdcb(exports.name, &http_root,
				&mi_http_answer_to_connection,
				&mi_http_flush_data,
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
	mi_http_destroy_async_lock();
	return 0;
}



static ssize_t mi_http_flush_data(void *cls, uint64_t pos, char *buf, size_t max)
{
	struct mi_handler *hdl = (struct mi_handler*)cls;
	gen_lock_t *lock;
	mi_http_async_resp_data_t *async_resp_data;
	str page = {NULL, 0};

	if (hdl==NULL) {
		LM_ERR("Unexpected NULL mi handler!\n");
		return -1;
	}
	LM_DBG("hdl=[%p], hdl->param=[%p], pos=[%d], buf=[%p], max=[%d]\n",
		 hdl, hdl->param, (int)pos, buf, (int)max);

	if (pos){
		LM_DBG("freeing hdl=[%p]: hdl->param=[%p], "
			" pos=[%d], buf=[%p], max=[%d]\n",
			 hdl, hdl->param, (int)pos, buf, (int)max);
		shm_free(hdl);
		return -1;
	}
	async_resp_data =
		(mi_http_async_resp_data_t*)((char*)hdl+sizeof(struct mi_handler));
	lock = async_resp_data->lock;
	lock_get(lock);
	if (hdl->param) {
		if (*(struct mi_root**)hdl->param) {
			page.s = buf;
			LM_DBG("tree=[%p]\n", *(struct mi_root**)hdl->param);
			if (mi_http_build_page(&page, max,
						async_resp_data->mod,
						async_resp_data->cmd,
						*(struct mi_root**)hdl->param)!=0){
				LM_ERR("Unable to build response\n");
				shm_free(*(void**)hdl->param);
				*(void**)hdl->param = NULL;
				lock_release(lock);
				memcpy(buf, MI_HTTP_U_ERROR.s, MI_HTTP_U_ERROR.len);
				return MI_HTTP_U_ERROR.len;
			} else {
				shm_free(*(void**)hdl->param);
				*(void**)hdl->param = NULL;
				lock_release(lock);
				return page.len;
			}
		} else {
			LM_DBG("data not ready yet\n");
			lock_release(lock);
			return 0;
		}
	} else {
		lock_release(lock);
		LM_ERR("Invalid async reply\n");
		memcpy(buf, MI_HTTP_U_ERROR.s, MI_HTTP_U_ERROR.len);
		return MI_HTTP_U_ERROR.len;
	}
	lock_release(lock);
	LM_CRIT("done?\n");
	shm_free(hdl);
	return -1;
}

#define MI_HTTP_OK				200
#define MI_HTTP_NOT_ACCEPTABLE	406
#define MI_HTTP_INTERNAL_ERROR	500

#define MI_HTTP_MAX_WAIT       2*60*4
static inline struct mi_root* mi_http_wait_async_reply(struct mi_handler *hdl)
{
	mi_http_async_resp_data_t *async_resp_data =
		(mi_http_async_resp_data_t*)(hdl+1);
	struct mi_root *mi_rpl;
	int i;
	int x;

	for( i=0 ; i<MI_HTTP_MAX_WAIT ; i++ ) {
		if (hdl->param)
			break;
		sleep_us(1000*500);
	}

	if (i==MI_HTTP_MAX_WAIT) {
		/* no more waiting ....*/
		lock_get(async_resp_data->lock);
		if (hdl->param==NULL) {
			hdl->param = MI_HTTP_ASYNC_EXPIRED;
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

	mi_rpl = (struct mi_root *)hdl->param;
	if (mi_rpl==MI_HTTP_ASYNC_FAILED)
		mi_rpl = NULL;

	/* free the async handler*/
	shm_free(hdl);

	return mi_rpl;
}

static inline void trace_http( union sockaddr_union* cl_socket, char* url,
		struct mi_root* mi_req, str* error, int code, str* message)
{

	char* command;

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	if ( url )
		command = url;
	else
		command = "";

	mi_trace_request( cl_socket, sv_socket, command,
									strlen(command), mi_req, &backend, t_dst);

	mi_trace_reply( sv_socket, cl_socket, code, error, message, t_dst);
}


int mi_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket)
{
	int mod = -1;
	int cmd = -1;
	str arg = {NULL, 0};
	struct mi_root *tree = NULL;
	struct mi_handler *async_hdl;
	int ret_code = MI_HTTP_OK;
	int is_shm = 0, is_cmd_traced=0;

	static const str ok_trace_reason = str_init("OK");

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)*upload_data_size, upload_data, *con_cls);
	if (strncmp(method, "GET", 3)==0 || strncmp(method, "POST", 4)==0) {
		if(0 == mi_http_parse_url(url, &mod, &cmd)) {
			httpd_api.lookup_arg(connection, "arg", *con_cls, &arg);
			if (mod>=0 && cmd>=0 && arg.s) {
				LM_DBG("arg [%p]->[%.*s]\n", arg.s, arg.len, arg.s);
				tree = mi_http_run_mi_cmd(mod, cmd, &arg,
							page, buffer, &async_hdl, cl_socket, &is_cmd_traced);
				if (tree == MI_ROOT_ASYNC_RPL) {
					LM_DBG("got an async reply\n");
					tree = mi_http_wait_async_reply(async_hdl);
					async_hdl = NULL;
					is_shm = 1;
				}

				if (tree == NULL) {
					LM_ERR("no reply\n");
					*page = MI_HTTP_U_ERROR;
					ret_code = MI_HTTP_INTERNAL_ERROR;

					if ( is_cmd_traced )
						trace_http( cl_socket, http_mi_cmds[mod].cmds[cmd].name.s,
							0, &MI_HTTP_U_ERROR_REASON, MI_HTTP_INTERNAL_ERROR, 0);
				} else {
					LM_DBG("building on page [%p:%d]\n",
						page->s, page->len);

					if(0!=mi_http_build_page(page,buffer->len,mod,cmd,tree)){
						LM_ERR("unable to build response"
							"for cmd [%d] w/ args [%.*s]\n",
							cmd, arg.len, arg.s);
						*page = MI_HTTP_U_ERROR;
						ret_code = MI_HTTP_INTERNAL_ERROR;

						/* already traced the request; trace the reply only */
						if ( is_cmd_traced )
							mi_trace_reply( sv_socket, cl_socket,
								MI_HTTP_INTERNAL_ERROR, &MI_HTTP_U_ERROR_REASON,
								0, t_dst);
					} else {
						ret_code = tree->code;

						if ( is_cmd_traced )
							mi_trace_reply( sv_socket, cl_socket,
								tree->code, &tree->reason, page, t_dst);
					}
				}
			} else {
				page->s = buffer->s;
				if(0 != mi_http_build_page(page, buffer->len,
							mod, cmd, tree)) {
					LM_ERR("unable to build response\n");
					*page = MI_HTTP_U_ERROR;
					ret_code = MI_HTTP_INTERNAL_ERROR;

					trace_http( cl_socket, http_mi_cmds[mod].cmds[cmd].name.s, 0,
							&MI_HTTP_U_ERROR_REASON, MI_HTTP_INTERNAL_ERROR, 0);
				}
				/* trace only mi commands */
				if (mod > 0 && cmd > 0) {
					trace_http( cl_socket, http_mi_cmds[mod].cmds[cmd].name.s, 0,
							(str *)&ok_trace_reason, MI_HTTP_OK, page);
				}
			}
			if (tree) {
				is_shm?free_shm_mi_tree(tree):free_mi_tree(tree);
				tree = NULL;
			}
		} else {
			LM_ERR("unable to parse URL [%s]\n", url);
			*page = MI_HTTP_U_URL;
			ret_code = MI_HTTP_NOT_ACCEPTABLE;

			trace_http( cl_socket, (char *)url, 0, &MI_HTTP_U_URL_REASON,
										MI_HTTP_NOT_ACCEPTABLE, 0);
		}
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		*page = MI_HTTP_U_METHOD;
		ret_code = MI_HTTP_INTERNAL_ERROR;

		trace_http( cl_socket, (char *)url, 0, &MI_HTTP_U_METHOD_REASON,
									MI_HTTP_INTERNAL_ERROR, 0);
	}

	return ret_code;
}

