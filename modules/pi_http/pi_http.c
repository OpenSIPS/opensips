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
#include "../../db/pi_framework.h"
#include "../../db/pi_framework_db.h"
#include "../../db/db_pi.h"


/* module functions */
static int mod_init();
static int child_init(int);
static void destroy(void);
int ph_answer_to_connection (void *cls, void *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t upload_data_size, void **con_cls,
		str *buffer, str *page, union sockaddr_union* cl_socket);
static ssize_t ph_flush_data(void *cls, uint64_t pos, char *buf, size_t max);
static int ph_pi_transport(const str *method, const str *url,
		void *request_context, str *response, void *param);
static mi_response_t *pi_framework_list(const mi_params_t *params,
		struct mi_handler *async_hdl, void *param);
static mi_response_t *pi_framework_reload(const mi_params_t *params,
		struct mi_handler *async_hdl, void *param);

extern str http_root;
extern int http_method;
extern httpd_api_t httpd_api;
gen_lock_t* ph_lock;
static str pi_http_transport = str_init("http");

static const str PI_HTTP_U_ERROR = str_init("<html><body>"
"Internal server error!</body></html>");
static const str PI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str PI_HTTP_U_METHOD = str_init("<html><body>"
"Unexpected method (only GET is accepted)!</body></html>");

struct ph_http_request {
	void *connection;
	void **con_cls;
	str *buffer;
};


/* module parameters */
static const param_export_t params[] = {
	{"pi_http_root",   STR_PARAM, &http_root.s},
	{"pi_http_method", INT_PARAM, &http_method},
	{0,0,0}
};

static const dep_export_t deps = {
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
	0,                                  /* exported MI functions */
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

	if (pi_framework.s==NULL) {
		LM_ERR("invalid pi_framework\n");
		return -1;
	}

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

	if (!ph_framework_data) {
		LM_ERR("PI framework was not initialized by the core\n");
		return -1;
	}

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
	if (db_pi_register_transport(&pi_http_transport, ph_pi_transport,
			pi_framework_list, pi_framework_reload, NULL) < 0) {
		LM_ERR("failed to register the HTTP PI transport\n");
		return -1;
	}

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


static void destroy(void)
{
	destroy_http_db(ph_framework_data);
	ph_destroy_async_lock();
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
	struct ph_http_request request = {connection, con_cls, buffer};
	str method_str = {(char *)method, strlen(method)};
	str url_str = {(char *)url, strlen(url)};

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, *con_cls=%p\n",
			cls, connection, url, method, version,
			(int)upload_data_size, upload_data, *con_cls);
	page->s = buffer->s;
	if (db_pi_dispatch(&pi_http_transport, &method_str, &url_str,
			&request, page) < 0)
		*page = PI_HTTP_U_ERROR;

	return 200;
}

static int ph_pi_transport(const str *method, const str *url,
		void *request_context, str *response, void *param)
{
	struct ph_http_request *request = request_context;
	int mod = -1;
	int cmd = -1;

	/* Keep the historical prefix matching used by pi_http. */
	if ((method->len >= 3 && !memcmp(method->s, "GET", 3)) ||
			(method->len >= 4 && !memcmp(method->s, "POST", 4))) {
		lock_get(ph_lock);
		if (ph_parse_url(url->s, &mod, &cmd) == 0) {
			if (ph_run_pi_cmd(mod, cmd, request->connection,
					*request->con_cls, response, request->buffer) != 0) {
				LM_ERR("unable to build response for cmd [%d]\n", cmd);
				*response = PI_HTTP_U_ERROR;
			}
		} else {
			LM_ERR("unable to parse URL [%.*s]\n", url->len, url->s);
			*response = PI_HTTP_U_URL;
		}
		lock_release(ph_lock);
	} else {
		LM_ERR("unexpected method [%.*s]\n", method->len, method->s);
		*response = PI_HTTP_U_METHOD;
	}
	return 0;
}

static mi_response_t *pi_framework_list(const mi_params_t *params,
		struct mi_handler *async_hdl, void *param)
{
	mi_item_t *response_obj, *commands;
	mi_response_t *response = init_mi_result_object(&response_obj);
	int i, j;

	if (!response)
		return NULL;
	for (i = 0; i < ph_framework_data->ph_modules_size; i++) {
		commands = add_mi_array(response_obj,
				ph_framework_data->ph_modules[i].module.s,
				ph_framework_data->ph_modules[i].module.len);
		for (j = 0; j < ph_framework_data->ph_modules[i].cmds_size; j++)
			add_mi_string(commands, 0, 0,
					ph_framework_data->ph_modules[i].cmds[j].name.s,
					ph_framework_data->ph_modules[i].cmds[j].name.len);
	}
	return response;
}

static mi_response_t *pi_framework_reload(const mi_params_t *params,
		struct mi_handler *async_hdl, void *param)
{
	lock_get(ph_lock);

	if (0!=ph_init_cmds(&ph_framework_data, pi_framework.s)) {
		lock_release(ph_lock);
		return NULL;
	}

	lock_release(ph_lock);

	return init_mi_result_ok();
}
