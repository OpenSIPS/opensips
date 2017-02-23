/*
 * Copyright (C) 2011-2012 VoIP Embedded Inc.
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
 *  2012-01-19  first version (osas)
 */


#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <grp.h>
#include <stdlib.h>

#include "../../globals.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../mem/mem.h"
#include "../../trace_api.h"
#include "httpd_load.h"
#include "httpd_proc.h"


#define MIN_POST_BUF_SIZE 256
#define DEFAULT_POST_BUF_SIZE 1024

/* module functions */
static int mod_init();
static int destroy(void);
static struct mi_root* mi_list_root_path(struct mi_root* cmd, void* param);

int port = 8888;
str ip = {NULL, 0};
str buffer = {NULL, 0};
int post_buf_size = DEFAULT_POST_BUF_SIZE;
struct httpd_cb *httpd_cb_list = NULL;


static proc_export_t mi_procs[] = {
	{"HTTPD",  0,  0, httpd_proc, 1, PROC_FLAG_INITCHILD },
	{NULL, 0, 0, NULL, 0, 0}
};


/** Module parameters */
static param_export_t params[] = {
	{"port",          INT_PARAM, &port},
	{"ip",            STR_PARAM, &ip.s},
	{"buf_size",      INT_PARAM, &buffer.len},
	{"post_buf_size", INT_PARAM, &post_buf_size},
	{NULL, 0, NULL}
};

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"httpd_bind",	(cmd_function)httpd_bind,	1, 0, 0, 0},
	{NULL, NULL, 0, 0, 0, 0}
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "httpd_list_root_path", 0, mi_list_root_path, 0,  0,  0},
	{ NULL, 0, NULL, 0, 0, 0}
};

/** Module exports */
struct module_exports exports = {
	"httpd",                    /* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	NULL,                       /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	NULL,                       /* exported PV */
	mi_procs,                   /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) NULL,   /* response handling function */
	(destroy_function) destroy, /* destroy function */
	NULL                        /* per-child init function */
};


static int mod_init(void)
{
	struct ip_addr *_ip;


	if (ip.s) {
		ip.len = strlen(ip.s);
		if ( (_ip=str2ip(&ip)) == NULL ) {
			LM_ERR("invalid IP [%.*s]\n", ip.len, ip.s);
			return -1;
		}
	}

	if (post_buf_size < MIN_POST_BUF_SIZE) {
		LM_ERR("post_buf_size should be bigger then %d\n",
			MIN_POST_BUF_SIZE);
		return -1;
	}
	if (buffer.len == 0)
		buffer.len = (pkg_mem_size/4)*3;
	LM_DBG("buf_size=[%d]\n", buffer.len);

	return 0;
}


int destroy(void)
{
	struct httpd_cb *cb = httpd_cb_list;

	httpd_proc_destroy();

	while(cb) {
		httpd_cb_list = cb->next;
		shm_free(cb);
		cb = httpd_cb_list;
	}
	return 0;
}


int httpd_register_httpdcb(const char *module, str *http_root,
			httpd_acces_handler_cb f1,
			httpd_flush_data_cb f2,
			httpd_init_proc_cb f3)
{
	int i;
	struct httpd_cb *cb;

	if (!module) {
		LM_ERR("NULL module name\n"); return -1;
	}
	if (!http_root) {
		LM_ERR("NULL http root path\n"); return -1;
	}
	if (!f1) {
		LM_ERR("NULL acces handler cb\n"); return -1;
	}
	if (!f2) {
		LM_ERR("NULL flush data cb\n"); return -1;
	}

	trim_spaces_lr(*http_root);
	if (!http_root->len) {
		LM_ERR("invalid http root path from module [%s]\n", module);
		return -1;
	}
	for(i=0;i<http_root->len;i++) {
		if ( !isalnum(http_root->s[i]) && http_root->s[i]!='_') {
			LM_ERR("bad mi_http_root param [%.*s], char [%c] "
				"- use only alphanumerical characters\n",
				http_root->len, http_root->s, http_root->s[i]);
			return -1;
		}
	}
	cb = (struct httpd_cb*)shm_malloc(sizeof(struct httpd_cb));
	if (cb==NULL) {
		LM_ERR("no more shm mem\n");
		return -1;
	}

	cb->module = module;
	cb->http_root = http_root;
	cb->callback = f1;
	cb->flush_data_callback = f2;
	cb->init_proc_callback = f3;
	cb->next = httpd_cb_list;
	httpd_cb_list = cb;

	LM_DBG("got root_path [%s][%.*s]\n",
		cb->module, cb->http_root->len, cb->http_root->s);
	return 0;
}

int httpd_bind(httpd_api_t *api)
{
	if (!api) {
		LM_ERR("Invalid parameter value\n");
		return -1;
	}

	api->lookup_arg = httpd_lookup_arg;
	api->register_httpdcb = httpd_register_httpdcb;
	api->get_server_info = httpd_get_server_info;
	return 0;
}


static struct mi_root* mi_list_root_path(struct mi_root* cmd, void* param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node, *rpl;
	struct mi_attr* attr;
	struct httpd_cb *cb = httpd_cb_list;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;
	while(cb) {
		node = add_mi_node_child(rpl, 0, "http_root", 9,
				cb->http_root->s, cb->http_root->len);
		if(node == NULL) goto error;
		attr = add_mi_attr(node, 0, "module", 6,
				(char*)cb->module, strlen(cb->module));
		if(attr == NULL) goto error;

		cb = cb->next;
	}

	return rpl_tree;
error:
	LM_ERR("Unable to create reply\n");
	free_mi_tree(rpl_tree);
	return NULL;
}


