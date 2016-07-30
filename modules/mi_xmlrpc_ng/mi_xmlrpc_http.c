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

/* module functions */
static int mod_init();
static int destroy(void);
int mi_xmlrpc_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page);
static ssize_t mi_xmlrpc_http_flush_data(void *cls, uint64_t pos, char *buf, size_t max);

str http_root = str_init("RPC2");
int version = 2;
httpd_api_t httpd_api;

#define MI_XMLRPC_NOT_ACCEPTABLE_STR	"406"
#define MI_XMLRPC_INTERNAL_ERROR_STR	"500"

static const str MI_XMLRPC_U_ERROR = str_init(
		INIT_XMLRPC_FAULT(MI_XMLRPC_INTERNAL_ERROR_STR,
			"Internal server error!" ));
static const str MI_XMLRPC_U_METHOD = str_init(
		INIT_XMLRPC_FAULT(MI_XMLRPC_NOT_ACCEPTABLE_STR,
			"Unexpected method (only POST is accepted)!"));

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
				memcpy(buf, MI_XMLRPC_U_ERROR.s, MI_XMLRPC_U_ERROR.len);
				return MI_XMLRPC_U_ERROR.len;
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
		memcpy(buf, MI_XMLRPC_U_ERROR.s, MI_XMLRPC_U_ERROR.len);
		return MI_XMLRPC_U_ERROR.len;
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


int mi_xmlrpc_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page)
{
	str arg = {NULL, 0};
	struct mi_root *tree = NULL;
	struct mi_handler *async_hdl;
	int ret_code = MI_XMLRPC_OK;
	int is_shm = 0;

	page->s = err_buf;
	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)*upload_data_size, upload_data, *con_cls);
	if (strncmp(method, "POST", 4)==0) {
		httpd_api.lookup_arg(connection, "1", *con_cls, &arg);
		if (arg.s) {
			tree = mi_xmlrpc_http_run_mi_cmd(&arg,
						page, buffer, &async_hdl);
			if (tree == MI_ROOT_ASYNC_RPL) {
				LM_DBG("got an async reply\n");
				tree = mi_xmlrpc_wait_async_reply(async_hdl);
				async_hdl = NULL;
				is_shm = 1;
			}

			if (tree == NULL) {
				LM_ERR("no reply\n");
				*page = MI_XMLRPC_U_ERROR;
			} else {
				LM_DBG("building on page [%p:%d]\n",
					page->s, page->len);
				if(0!=mi_xmlrpc_http_build_page(page, buffer->len, tree)){
					LM_ERR("unable to build response\n");
					*page = MI_XMLRPC_U_ERROR;
				} else {
					if (tree->code >= 400) {
						MI_XMLRPC_PRINT_FAULT(page, tree->code, tree->reason);
					}
				}
			}
		} else {
			page->s = buffer->s;
			LM_ERR("unable to build response for empty request\n");
			*page = MI_XMLRPC_U_ERROR;
		}
		if (tree) {
			is_shm?free_shm_mi_tree(tree):free_mi_tree(tree);
			tree = NULL;
		}
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		*page = MI_XMLRPC_U_METHOD;
	}

	return ret_code;
}

