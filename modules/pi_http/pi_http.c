/*
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 *  2012-03-17  first version (osas)
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
#include "http_db_handler.h"


extern ph_framework_t *ph_framework_data;

/* module functions */
static int mod_init();
static int child_init();
static int destroy(void);
int ph_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t ph_flush_data(void *cls, uint64_t pos, char *buf, size_t max);
mi_response_t *mi_framework_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);

str http_root = str_init("pi");
int http_method = 0;
str filename = {NULL, 0};

httpd_api_t httpd_api;
gen_lock_t* ph_lock;

static const str PI_HTTP_U_ERROR = str_init("<html><body>"
"Internal server error!</body></html>");
static const str PI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str PI_HTTP_U_METHOD = str_init("<html><body>"
"Unexpected method (only GET is accepted)!</body></html>");


/* module parameters */
static param_export_t params[] = {
	{"pi_http_root",   STR_PARAM, &http_root.s},
	{"pi_http_method", INT_PARAM, &http_method},
	{"framework",      STR_PARAM, &filename.s},
	{0,0,0}
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "pi_reload_tbls_and_cmds", 0, 0, 0, {
		{mi_framework_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
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
	"pi_http",                          /* module name */
	MOD_TYPE_DEFAULT,                   /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,                    /* dlopen flags */
	0,				                    /* load function */
	&deps,                              /* OpenSIPS module dependencies */
	0,                                  /* exported functions */
	0,                                  /* exported async functions */
	params,                             /* exported parameters */
	0,                                  /* exported statistics */
	mi_cmds,                            /* exported MI functions */
	0,                                  /* exported PV */
	0,									/* exported transformations */
	0,                                  /* extra processes */
	0,                                  /* module pre-initialization function */
	mod_init,                           /* module initialization function */
	(response_function) 0,              /* response handling function */
	(destroy_function) destroy,         /* destroy function */
	(child_init_function)child_init,    /* per-child init function */
	0                                   /* reload confirm function */
};


void proc_init(void)
{

	return;
}


int ph_init_async_lock(void)
{
	ph_lock = lock_alloc();
	if (ph_lock==NULL) {
		LM_ERR("failed to create lock\n");
		return -1;
	}
	if (lock_init(ph_lock)==NULL) {
		LM_ERR("failed to init lock\n");
		return -1;
	}
	return 0;
}


void ph_destroy_async_lock(void)
{
	if (ph_lock) {
		lock_destroy(ph_lock);
		lock_dealloc(ph_lock);
	}
}


static int mod_init(void)
{
	int i;

	if (filename.s==NULL) {
		LM_ERR("invalid framework\n");
		return -1;
	}
	filename.len = strlen(filename.s);

	http_root.len = strlen(http_root.s);

	if (http_method<0 || http_method>1) {
		LM_ERR("pi_http_method can be between [0,1]\n");
		return -1;
	}

	/* Load httpd api */
	if(load_httpd_api(&httpd_api)<0) {
		LM_ERR("Failed to load httpd api\n");
		return -1;
	}
	/* Load httpd hooks */
	httpd_api.register_httpdcb(exports.name, &http_root,
				&ph_answer_to_connection,
				&ph_flush_data,
				HTTPD_TEXT_HTML_TYPE,
				&proc_init);

	/* Build a cache of all provisionning commands */
	if (0!=ph_init_cmds(&ph_framework_data, filename.s))
		return -1;

	/* init db connections */
	for(i=0;i<ph_framework_data->ph_db_urls_size;i++){
		ph_framework_data->ph_db_urls[i].http_db_handle =
								pkg_malloc(sizeof(db_con_t *));
		*ph_framework_data->ph_db_urls[i].http_db_handle = 0;

		LM_DBG("initializing db[%d] [%s]\n",
			i, ph_framework_data->ph_db_urls[i].db_url.s);
		if (init_http_db(ph_framework_data, i)!=0) {
			LM_ERR("failed to initialize the DB support\n");
			return -1;
		}


	}

	/* Build async lock */
	if (ph_init_async_lock() != 0) exit(-1);

	return 0;
}

static int child_init(int rank)
{
	int i;

	LM_DBG("Child initialization\n");

	for(i=0;i<ph_framework_data->ph_db_urls_size;i++){
		LM_DBG("connecting to db[%d] [%s]\n",
			i, ph_framework_data->ph_db_urls[i].db_url.s);

		if (connect_http_db(ph_framework_data, i)) {
			LM_ERR("failed to connect to database\n");
			return -1;
		}
	}

	return 0;
}


int destroy(void)
{
	destroy_http_db(ph_framework_data);
	ph_destroy_async_lock();
	return 0;
}


static ssize_t ph_flush_data(void *cls, uint64_t pos, char *buf, size_t max)
{
	/* Not used for now */
	return -1;
}


int ph_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket)
{
	int mod = -1;
	int cmd = -1;

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)upload_data_size, upload_data, *con_cls);
	if ((strncmp(method, "GET", 3)==0)
		|| (strncmp(method, "POST", 4)==0)) {
		lock_get(ph_lock);
		if(0 == ph_parse_url(url, &mod, &cmd)) {
				page->s = buffer->s;
			if(0!=ph_run_pi_cmd(mod, cmd, connection, *con_cls, page, buffer)){
				LM_ERR("unable to build response for cmd [%d]\n",
							cmd);
				*page = PI_HTTP_U_ERROR;
			}
		} else {
			LM_ERR("unable to parse URL [%s]\n", url);
			*page = PI_HTTP_U_URL;
		}
		lock_release(ph_lock);
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		*page = PI_HTTP_U_METHOD;
	}

	return 200;
}

mi_response_t *mi_framework_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	lock_get(ph_lock);

	if (0!=ph_init_cmds(&ph_framework_data, filename.s)) {
		lock_release(ph_lock);
		return NULL;
	}

	lock_release(ph_lock);

	return init_mi_result_ok();
}
