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

#define MI_JSON_ERROR_BUF_MAX_LEN 512

/* module functions */
static int mod_init();
static int destroy(void);
int mi_json_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t mi_json_flush_data(void *cls, uint64_t pos, char *buf,
		size_t max);

str http_root = str_init("json");
httpd_api_t httpd_api;

static str trace_destination_name = {NULL, 0};
trace_dest t_dst;

int mi_trace_mod_id;
char* mi_trace_bwlist_s;

static const str MI_HTTP_U_ERROR = str_init("Internal server error");
static const str MI_HTTP_U_METHOD = str_init("Unexpected method");
static const str MI_HTTP_U_NOT_FOUND = str_init("Command not found");


static char err_buf[MI_JSON_ERROR_BUF_MAX_LEN];
static const char* MI_JSON_COMMAND_ERROR_S = "{\"error\": {\"code\": %u, \"message\": \"%.*s\"}}";

static str backend = str_init("json");
static union sockaddr_union* sv_socket = NULL;



/* module parameters */
static param_export_t mi_params[] = {
	{"mi_json_root",      STR_PARAM, &http_root.s},
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
	"mi_json",					/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	&deps,						/* OpenSIPS module dependencies */
	NULL,						/* exported functions */
	NULL,						/* exported async functions */
	mi_params,					/* exported parameters */
	NULL,						/* exported statistics */
	NULL,						/* exported MI functions */
	NULL,						/* exported PV */
	NULL,						/* exported transformations */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,		/* response handling function */
	(destroy_function) destroy,	/* destroy function */
	NULL						/* per-child init function */
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
	struct mi_handler *hdl = (struct mi_handler*)cls;
	gen_lock_t *lock;
	mi_json_async_resp_data_t *async_resp_data;
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
		(mi_json_async_resp_data_t*)((char*)hdl+sizeof(struct mi_handler));
	lock = async_resp_data->lock;
	lock_get(lock);
	if (hdl->param) {
		if (*(struct mi_root**)hdl->param) {
			page.s = buf;
			LM_DBG("tree=[%p]\n", *(struct mi_root**)hdl->param);
			if (mi_json_build_page(&page, max,
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

#define MI_JSON_MAX_WAIT       2*60*4
static inline struct mi_root* mi_json_wait_async_reply(struct mi_handler *hdl)
{
	mi_json_async_resp_data_t *async_resp_data =
		(mi_json_async_resp_data_t*)(hdl+1);
	struct mi_root *mi_rpl;
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

	mi_rpl = (struct mi_root *)hdl->param;
	if (mi_rpl==MI_JSON_ASYNC_FAILED)
		mi_rpl = NULL;

	/* free the async handler*/
	shm_free(hdl);

	return mi_rpl;
}

#define MI_JSON_OK				200
#define MI_JSON_NOT_ACCEPTABLE	406
#define MI_JSON_INTERNAL_ERROR	500

static inline void trace_json( struct mi_cmd* f, union sockaddr_union* cl_socket, char* url,
		struct mi_root* mi_req, str* error, int code, str* message)
{

	char* command;

	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

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

void trace_json_request( struct mi_cmd* f, union sockaddr_union* cl_socket, char* url,
		struct mi_root* mi_req )
{
	char* command;
	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	if ( url )
		command = url;
	else
		command = "";

	mi_trace_request( cl_socket, sv_socket, command,
								strlen(command), mi_req, &backend, t_dst);
}

static inline void trace_json_reply( struct mi_cmd* f, union sockaddr_union* cl_socket,
		str* error, int code, str* message)
{
	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	mi_trace_reply( sv_socket, cl_socket, code, error, message, t_dst);
}

int mi_json_answer_to_connection (void *cls, void *connection,
	const char *url, const char *method,
	const char *version, const char *upload_data,
	size_t *upload_data_size, void **con_cls,
	str *buffer, str *page, union sockaddr_union* cl_socket)
{
	str command = {NULL, 0};
	str params = {NULL, 0};
	struct mi_cmd *f = NULL;
	struct mi_root *tree = NULL;
	struct mi_handler *async_hdl;
	int ret_code = MI_JSON_OK;
	int is_shm = 0;


	page->s = err_buf;
	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
			"versio=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)*upload_data_size, upload_data, *con_cls);
	if (strncmp(method, "GET", 3)==0) {
		if(url && url[0] == '/' && url[1] != '\0') {
			command.s = (char*)url+1;
			command.len = strlen(command.s);
		}

		httpd_api.lookup_arg(connection, "params", *con_cls, &params);
		if (command.s) {
			f = lookup_mi_cmd(command.s, command.len);
			if (f == NULL) {
				LM_ERR("unable to find mi command [%.*s]\n",
					command.len, command.s);
				page->len = snprintf(page->s, MI_JSON_ERROR_BUF_MAX_LEN,
						MI_JSON_COMMAND_ERROR_S,
						MI_JSON_INTERNAL_ERROR,
						MI_HTTP_U_NOT_FOUND.len, MI_HTTP_U_NOT_FOUND.s);

				trace_json( f, cl_socket, command.s, 0, (str *)&MI_HTTP_U_NOT_FOUND,
						MI_JSON_INTERNAL_ERROR, 0);
			} else {

				tree = mi_json_run_mi_cmd(f, &command,&params,
						page, buffer, &async_hdl, cl_socket);
				if (tree == MI_ROOT_ASYNC_RPL) {
					LM_DBG("got an async reply\n");
					tree = mi_json_wait_async_reply(async_hdl);
					async_hdl = NULL;
					is_shm = 1;
				}

				if (tree == NULL) {
					LM_ERR("no reply\n");
					page->len = snprintf(page->s, MI_JSON_ERROR_BUF_MAX_LEN,
							MI_JSON_COMMAND_ERROR_S,
							MI_JSON_INTERNAL_ERROR,
							MI_HTTP_U_ERROR.len, MI_HTTP_U_ERROR.s);

					trace_json_reply( f, cl_socket, (str *)&MI_HTTP_U_ERROR,
							MI_JSON_INTERNAL_ERROR, 0);
				} else {
					LM_DBG("building on page [%p:%d]\n",
							page->s, page->len);
					if(0!=mi_json_build_page(page, buffer->len, tree)){
						LM_ERR("unable to build response\n");
						page->len = snprintf(page->s, MI_JSON_ERROR_BUF_MAX_LEN,
								MI_JSON_COMMAND_ERROR_S,
								MI_JSON_INTERNAL_ERROR,
								MI_HTTP_U_ERROR.len, MI_HTTP_U_ERROR.s);

						trace_json_reply( f, cl_socket, (str *)&MI_HTTP_U_ERROR,
								MI_JSON_INTERNAL_ERROR, 0);
					} else {
						if (tree->code >= 400) {
							page->s = err_buf;
							page->len = snprintf(page->s, MI_JSON_ERROR_BUF_MAX_LEN,
									MI_JSON_COMMAND_ERROR_S,
									tree->code, tree->reason.len, tree->reason.s);
						}

						/* everything ok here */
						trace_json_reply( f, cl_socket, &tree->reason,
								tree->code, page);
					}
				}
			}
		} else {
			LM_ERR("unable to build response for empty request\n");
			page->len = snprintf(page->s, MI_JSON_ERROR_BUF_MAX_LEN,
					MI_JSON_COMMAND_ERROR_S,
					MI_JSON_INTERNAL_ERROR,
					MI_HTTP_U_ERROR.len, MI_HTTP_U_ERROR.s);


			trace_json( 0, cl_socket, command.s, 0, (str *)&MI_HTTP_U_ERROR,
					MI_JSON_INTERNAL_ERROR, 0);
		}
		if (tree) {
			is_shm?free_shm_mi_tree(tree):free_mi_tree(tree);
			tree = NULL;
		}
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		page->len = snprintf(page->s, MI_JSON_ERROR_BUF_MAX_LEN,
					MI_JSON_COMMAND_ERROR_S,
					MI_JSON_NOT_ACCEPTABLE,
					MI_HTTP_U_METHOD.len, MI_HTTP_U_METHOD.s);

		trace_json( 0, cl_socket, *(char**)&url, 0, (str *)&MI_HTTP_U_METHOD,
					MI_JSON_NOT_ACCEPTABLE, 0);
	}

	return ret_code;
}
