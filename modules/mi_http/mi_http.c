/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

/* module functions */
static int mod_init();
static int destroy(void);
void mi_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page);
static ssize_t mi_http_flush_data(void *cls, uint64_t pos, char *buf, size_t max);

str http_root = str_init("mi");
int http_method = 0;

httpd_api_t httpd_api;


static const str MI_HTTP_U_ERROR = str_init("<html><body>"
"Internal server error!</body></html>");
static const str MI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str MI_HTTP_U_METHOD = str_init("<html><body>"
"Unexpected method (only GET is accepted)!</body></html>");


/* module parameters */
static param_export_t mi_params[] = {
	{"mi_http_root",   STR_PARAM, &http_root.s},
	{"mi_http_method", INT_PARAM, &http_method},
	{0,0,0}
};

/* module exports */
struct module_exports exports = {
	"mi_http",                          /* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,                    /* dlopen flags */
	0,                                  /* exported functions */
	mi_params,                          /* exported parameters */
	0,                                  /* exported statistics */
	0,                                  /* exported MI functions */
	0,                                  /* exported PV */
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

void mi_http_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls,
		str *buffer, str *page)
{
	int mod = -1;
	int cmd = -1;
	str arg = {NULL, 0};
	struct mi_root *tree = NULL;
	struct mi_handler *async_hdl;

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
							page, buffer, &async_hdl);
				if (tree == NULL) {
					LM_ERR("no reply\n");
					*page = MI_HTTP_U_ERROR;
				} else if (tree == MI_ROOT_ASYNC_RPL) {
					LM_DBG("got an async reply\n");
					tree = NULL;
				} else {
					LM_DBG("building on page [%p:%d]\n",
						page->s, page->len);
					if(0!=mi_http_build_page(page, buffer->len,
								mod, cmd, tree)){
						LM_ERR("unable to build response "
							"for cmd [%d] w/ args [%.*s]\n",
							cmd,
							arg.len, arg.s);
						*page = MI_HTTP_U_ERROR;
					}
				}
			} else {
				page->s = buffer->s;
				if(0 != mi_http_build_page(page, buffer->len,
							mod, cmd, tree)) {
					LM_ERR("unable to build response\n");
					*page = MI_HTTP_U_ERROR;
				}
			}
			if (tree) {
				free_mi_tree(tree);
				tree = NULL;
			}
		} else {
			LM_ERR("unable to parse URL [%s]\n", url);
			*page = MI_HTTP_U_URL;
		}
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		*page = MI_HTTP_U_METHOD;
	}

	return;
}

