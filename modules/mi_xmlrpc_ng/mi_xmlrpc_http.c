/*
 * Copyright (C) 2013 VoIP Embedded Inc.
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

static struct xml_errors {
	str reason;
	int code;
	str err_page;
}
xml_strerr[] = {
	/* request errors */
	{ str_init("Empty request"), 401,
		str_init(INIT_XMLRPC_FAULT("401","Empty request")) },
	{ str_init("Invalid request"), 404,
		str_init(INIT_XMLRPC_FAULT("404", "Invalid request")) },
	{ str_init("Command not available"), 405,
		str_init(INIT_XMLRPC_FAULT("405", "Command not available")) },
	{ str_init("Unexpected method (only POST is accepted)"), 406,
		str_init(INIT_XMLRPC_FAULT("405", "Unexpected method (only POST is accepted)")) },
	{ str_init("Missing node 'MethodCall'"), 407,
		str_init(INIT_XMLRPC_FAULT("407", "Missing node 'Method Call'")) },
	{ str_init("Missing node 'MethodName'"), 407,
		str_init(INIT_XMLRPC_FAULT("407", "Missing node 'MethodName'")) },
	{ str_init("Missing node 'value'"), 407,
		str_init(INIT_XMLRPC_FAULT("407", "Missing node 'value'")) },
	{ str_init("Missing node 'string'"), 407,
		str_init(INIT_XMLRPC_FAULT("407", "Missing node 'string'")) },
	{ str_init("Empty 'string' node"), 408,
		str_init(INIT_XMLRPC_FAULT("408", "Empty 'string' node")) },

	/* internal errors */
	{ str_init("Internal server error"), 500,
		str_init(INIT_XMLRPC_FAULT("500", "Internal server error")) },
	{ str_init("Failed to run command"), 501,
		str_init(INIT_XMLRPC_FAULT("501", "Failed to run command")) },

	{{0, 0}, 0, {0, 0} }
};

/* module functions */
static int mod_init();
static int destroy(void);
int mi_xmlrpc_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t mi_xmlrpc_http_flush_data(void *cls, uint64_t pos, char *buf, size_t max);

str http_root = str_init("RPC2");
int version = 2;
httpd_api_t httpd_api;

static str trace_destination_name = {NULL, 0};
trace_dest t_dst;
static str backend = str_init("xmlrpc");

static union sockaddr_union* sv_socket = NULL;

int mi_trace_mod_id;
char* mi_trace_bwlist_s;

#define MI_XML_ERROR_BUF_MAX_LEN 1024
static char err_buf[MI_XML_ERROR_BUF_MAX_LEN];

#define MI_XMLRPC_PRINT_FAULT(page, code, message) \
	do { \
	page->len = snprintf(page->s, MI_XML_ERROR_BUF_MAX_LEN, \
			XMLRPC_FAULT_FORMAT, \
			code, message.len, message.s); \
	} while(0);


/* module parameters */
static param_export_t mi_params[] = {
	{"http_root",        STR_PARAM, &http_root.s},
	{"format_version",   INT_PARAM, &version},
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
	"mi_xmlrpc_ng",                     /* module name */
	MOD_TYPE_DEFAULT,                   /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,                    /* dlopen flags */
	&deps,                              /* OpenSIPS module dependencies */
	NULL,                               /* exported functions */
	NULL,                               /* exported async functions */
	mi_params,                          /* exported parameters */
	NULL,                               /* exported statistics */
	NULL,                               /* exported MI functions */
	NULL,                               /* exported PV */
	NULL,								/* exported transformations */
	0,                                  /* extra processes */
	mod_init,                           /* module initialization function */
	(response_function) 0,              /* response handling function */
	(destroy_function) destroy,         /* destroy function */
	NULL                                /* per-child init function */
};


void proc_init(void)
{
	/* Build async lock */
	if (mi_xmlrpc_http_init_async_lock() != 0)
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
				&mi_xmlrpc_http_answer_to_connection,
				&mi_xmlrpc_http_flush_data,
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
	mi_xmlrpc_http_destroy_async_lock();
	return 0;
}



static ssize_t mi_xmlrpc_http_flush_data(void *cls, uint64_t pos, char *buf, size_t max)
{
	struct mi_handler *hdl = (struct mi_handler*)cls;
	gen_lock_t *lock;
	mi_xmlrpc_http_async_resp_data_t *async_resp_data;
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
		(mi_xmlrpc_http_async_resp_data_t*)((char*)hdl+sizeof(struct mi_handler));
	lock = async_resp_data->lock;
	lock_get(lock);
	if (hdl->param) {
		if (*(struct mi_root**)hdl->param) {
			page.s = buf;
			LM_DBG("tree=[%p]\n", *(struct mi_root**)hdl->param);
			if (mi_xmlrpc_http_build_page(&page, max,
						*(struct mi_root**)hdl->param)!=0){
				LM_ERR("Unable to build response\n");
				shm_free(*(void**)hdl->param);
				*(void**)hdl->param = NULL;
				lock_release(lock);
				memcpy(buf, xml_strerr[ERR_INTERNAL].err_page.s,
						xml_strerr[ERR_INTERNAL].err_page.len);
				return xml_strerr[ERR_INTERNAL].err_page.len;
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
		memcpy(buf, xml_strerr[ERR_INTERNAL].err_page.s,
				xml_strerr[ERR_INTERNAL].err_page.len);
		return xml_strerr[ERR_INTERNAL].err_page.len;
	}
	lock_release(lock);
	LM_CRIT("done?\n");
	shm_free(hdl);
	return -1;
}


#define MI_XMLRPC_MAX_WAIT       2*60*4
static inline struct mi_root*
mi_xmlrpc_wait_async_reply(struct mi_handler *hdl)
{
	mi_xmlrpc_http_async_resp_data_t *async_resp_data =
		(mi_xmlrpc_http_async_resp_data_t*)(hdl+1);
	struct mi_root *mi_rpl;
	int i;
	int x;

	for( i=0 ; i<MI_XMLRPC_MAX_WAIT ; i++ ) {
		if (hdl->param)
			break;
		sleep_us(1000*500);
	}

	if (i==MI_XMLRPC_MAX_WAIT) {
		/* no more waiting ....*/
		lock_get(async_resp_data->lock);
		if (hdl->param==NULL) {
			hdl->param = MI_XMLRPC_ASYNC_EXPIRED;
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
	if (mi_rpl==MI_XMLRPC_ASYNC_FAILED)
		mi_rpl = NULL;

	/* free the async handler*/
	shm_free(hdl);

	return mi_rpl;
}


#define MI_XMLRPC_OK				200
#define MI_XMLRPC_NOT_ACCEPTABLE	406
#define MI_XMLRPC_INTERNAL_ERROR	500

static inline void trace_xml( union sockaddr_union* cl_socket, char* url,
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

void trace_xml_request( union sockaddr_union* cl_socket, char* url,
		struct mi_root* mi_req )
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
}


static inline void trace_xml_reply( union sockaddr_union* cl_socket,
			str* error, int code, str* message)
{
	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	mi_trace_reply( sv_socket, cl_socket, code, error, message, t_dst);
}

int mi_xmlrpc_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket)
{
	str arg = {NULL, 0};
	struct mi_root *tree = NULL;
	struct mi_handler *async_hdl;
	int ret_code = MI_XMLRPC_OK;
	int is_shm = 0, is_cmd_traced=0;

	page->s = err_buf;
	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)*upload_data_size, upload_data, *con_cls);
	if (strncmp(method, "POST", 4)==0) {
		httpd_api.lookup_arg(connection, "1", *con_cls, &arg);
		if (arg.s) {
			tree = mi_xmlrpc_http_run_mi_cmd(&arg,
						page, buffer, &async_hdl, cl_socket, &is_cmd_traced);
			if (tree == MI_ROOT_ASYNC_RPL) {
				LM_DBG("got an async reply\n");
				tree = mi_xmlrpc_wait_async_reply(async_hdl);
				async_hdl = NULL;
				is_shm = 1;
			}

			if (tree == NULL) {
				LM_ERR("no reply\n");
				*page = xml_strerr[xml_errcode].err_page;

				if ( is_cmd_traced ) {
					trace_xml( cl_socket, (char *)url, 0,
						&xml_strerr[xml_errcode].reason,
						xml_strerr[xml_errcode].code, 0);
				}
			} else {
				LM_DBG("building on page [%p:%d]\n",
					page->s, page->len);
				if(0!=mi_xmlrpc_http_build_page(page, buffer->len, tree)){
					LM_ERR("unable to build response\n");
					*page = xml_strerr[ERR_INTERNAL].err_page;

					if ( is_cmd_traced )
						trace_xml_reply( cl_socket, &xml_strerr[ERR_INTERNAL].reason,
								xml_strerr[ERR_INTERNAL].code, 0);
				} else {
					if (tree->code >= 400) {
						MI_XMLRPC_PRINT_FAULT(page, tree->code, tree->reason);
					}

					if ( is_cmd_traced) {
						trace_xml_reply( cl_socket,
								&tree->reason, tree->code, page);
					}
				}
			}
		} else {
			page->s = buffer->s;
			LM_ERR("unable to build response for empty request\n");
			*page = xml_strerr[ERR_EMPTY].err_page;

			trace_xml_reply( cl_socket, &xml_strerr[ERR_EMPTY].reason,
						xml_strerr[ERR_EMPTY].code, page);
		}
		if (tree) {
			is_shm?free_shm_mi_tree(tree):free_mi_tree(tree);
			tree = NULL;
		}
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		*page = xml_strerr[ERR_UNEXPECTED].err_page;

		trace_xml( cl_socket, (char *)url, 0,
				&xml_strerr[ERR_UNEXPECTED].reason,
				xml_strerr[ERR_UNEXPECTED].code, 0);
	}

	return ret_code;
}

