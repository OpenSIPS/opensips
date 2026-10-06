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
#define DEFAULT_TLS_CIPHERS "SECURE256:+SECURE192:-VERS-ALL:+VERS-TLS1.2"
#define DEFAULT_CONN_TIMEOUT 30

/* module functions */
static int mod_init();
static void destroy(void);

static mi_response_t *mi_list_root_path(const mi_params_t *params,
						struct mi_handler *async_hdl);

int port = 8888;
str ip = {"127.0.0.1", 9};
str buffer = {NULL, 0};
unsigned int hd_conn_timeout_s = DEFAULT_CONN_TIMEOUT;
str tls_cert_file = {NULL, 0};
str tls_key_file = {NULL, 0};
str tls_ciphers = {DEFAULT_TLS_CIPHERS, sizeof(DEFAULT_TLS_CIPHERS) - 1};
int post_buf_size = DEFAULT_POST_BUF_SIZE;
int receive_buf_size = DEFAULT_POST_BUF_SIZE;
str auth_realm = {"OpenSIPS MI", 11};
str auth_username = {NULL, 0};
str auth_password = {NULL, 0};
struct httpd_cb *httpd_cb_list = NULL;

char *httpd_receive_buff = NULL;
int httpd_receive_buff_pos=0;

#define HTTPD_DEFAULT_SRV "default"

struct httpd_server *httpd_servers = NULL;
int httpd_n_servers = 0;

static proc_export_t mi_procs[] = {
	{"HTTPD",  httpd_pre_fork,  httpd_post_fork, httpd_proc, 1,
		PROC_FLAG_INITCHILD|PROC_FLAG_HAS_IPC|PROC_FLAG_NEEDS_SCRIPT },
	{NULL, 0, 0, NULL, 0, 0}
};


static void httpd_split(char *val, str *name, str *rest)
{
	char *p;
	str v;

	v.s = val;
	v.len = val ? strlen(val) : 0;
	while (v.len && v.s[0] == ' ') {
		v.s++;
		v.len--;
	}

	if (v.len && v.s[0] == '[' && (p = memchr(v.s, ']', v.len))) {
		name->s = v.s + 1;
		name->len = (int)(p - v.s - 1);
		while (name->len && name->s[0] == ' ') {
			name->s++;
			name->len--;
		}
		while (name->len && name->s[name->len - 1] == ' ')
			name->len--;

		rest->s = p + 1;
		rest->len = v.len - (int)(p - v.s) - 1;
	} else {
		name->s = HTTPD_DEFAULT_SRV;
		name->len = sizeof(HTTPD_DEFAULT_SRV) - 1;
		rest->s = v.s;
		rest->len = v.len;
	}

	while (rest->len && rest->s[0] == ' ') {
		rest->s++;
		rest->len--;
	}
	while (rest->len && rest->s[rest->len - 1] == ' ')
		rest->len--;
}

static struct httpd_server *httpd_get_server(str *name)
{
	struct httpd_server *arr;
	int i;

	for (i = 0; i < httpd_n_servers; i++)
		if (httpd_servers[i].name.len == name->len &&
				memcmp(httpd_servers[i].name.s, name->s, name->len) == 0)
			return &httpd_servers[i];

	arr = realloc(httpd_servers, (httpd_n_servers + 1) * sizeof *arr);
	if (!arr) {
		LM_ERR("no more memory for HTTP servers\n");
		return NULL;
	}
	httpd_servers = arr;
	arr = &httpd_servers[httpd_n_servers];
	memset(arr, 0, sizeof *arr);
	arr->name.s = malloc(name->len + 1);
	if (!arr->name.s) {
		LM_ERR("no more memory for HTTP server name\n");
		return NULL;
	}
	memcpy(arr->name.s, name->s, name->len);
	arr->name.s[name->len] = '\0';
	arr->name.len = name->len;
	arr->listen_fd = -1;
	httpd_n_servers++;
	return arr;
}

static struct httpd_server *httpd_srv_str(void *val, str *rest)
{
	str name;

	httpd_split((char *)val, &name, rest);
	return httpd_get_server(&name);
}

static int httpd_srv_int(modparam_t type, void *val, struct httpd_server **s,
		int *out)
{
	str name, rest;

	if (type & STR_PARAM) {
		httpd_split((char *)val, &name, &rest);
		if (str2sint(&rest, out) < 0) {
			LM_ERR("invalid integer modparam value '%.*s'\n",
				rest.len, rest.s);
			return -1;
		}
	} else {
		name.s = HTTPD_DEFAULT_SRV;
		name.len = sizeof(HTTPD_DEFAULT_SRV) - 1;
		*out = (int)(long)val;
	}
	*s = httpd_get_server(&name);
	return *s ? 0 : -1;
}

static int set_ip(modparam_t t, void *v)
{ struct httpd_server *s; str r; s = httpd_srv_str(v, &r); if (!s) return -1; s->ip = r; return 0; }
static int set_tls_cert(modparam_t t, void *v)
{ struct httpd_server *s; str r; s = httpd_srv_str(v, &r); if (!s) return -1; s->tls_cert_file = r; return 0; }
static int set_tls_key(modparam_t t, void *v)
{ struct httpd_server *s; str r; s = httpd_srv_str(v, &r); if (!s) return -1; s->tls_key_file = r; return 0; }
static int set_tls_ciphers(modparam_t t, void *v)
{ struct httpd_server *s; str r; s = httpd_srv_str(v, &r); if (!s) return -1; s->tls_ciphers = r; return 0; }
static int set_port(modparam_t t, void *v)
{ struct httpd_server *s; int n; if (httpd_srv_int(t, v, &s, &n) < 0) return -1; s->port = n; return 0; }
static int set_buf_size(modparam_t t, void *v)
{ struct httpd_server *s; int n; if (httpd_srv_int(t, v, &s, &n) < 0) return -1; s->buf_size = n; return 0; }
static int set_conn_timeout(modparam_t t, void *v)
{ struct httpd_server *s; int n; if (httpd_srv_int(t, v, &s, &n) < 0) return -1; s->conn_timeout = n; return 0; }
static int set_post_buf_size(modparam_t t, void *v)
{ struct httpd_server *s; int n; if (httpd_srv_int(t, v, &s, &n) < 0) return -1; s->post_buf_size = n; return 0; }
static int set_receive_buf_size(modparam_t t, void *v)
{ struct httpd_server *s; int n; if (httpd_srv_int(t, v, &s, &n) < 0) return -1; s->receive_buf_size = n; return 0; }
static int set_workers(modparam_t t, void *v)
{ struct httpd_server *s; int n; if (httpd_srv_int(t, v, &s, &n) < 0) return -1; s->workers = n; return 0; }

/** Module parameters */
static const param_export_t params[] = {
	{"ip",               STR_PARAM|USE_FUNC_PARAM,           (void*)set_ip},
	{"port",             STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)set_port},
	{"buf_size",         STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)set_buf_size},
	{"conn_timeout",     STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)set_conn_timeout},
	{"post_buf_size",    STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)set_post_buf_size},
	{"receive_buf_size", STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)set_receive_buf_size},
	{"tls_cert_file",    STR_PARAM|USE_FUNC_PARAM,           (void*)set_tls_cert},
	{"tls_key_file",     STR_PARAM|USE_FUNC_PARAM,           (void*)set_tls_key},
	{"tls_ciphers",      STR_PARAM|USE_FUNC_PARAM,           (void*)set_tls_ciphers},
	{"workers",          STR_PARAM|INT_PARAM|USE_FUNC_PARAM, (void*)set_workers},
	{"auth_realm", STR_PARAM, &auth_realm.s},
	{"auth_username", STR_PARAM, &auth_username.s},
	{"auth_password", STR_PARAM, &auth_password.s},
	{NULL, 0, NULL}
};

/** Exported functions */
static const cmd_export_t cmds[] = {
	{"httpd_bind",	(cmd_function)httpd_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/** MI commands */
static const mi_export_t mi_cmds[] = {
	{ "list_root_path", 0, 0, 0, {
		{mi_list_root_path, {0}},
		{EMPTY_MI_RECIPE}}, {"httpd_list_root_path", 0}
	},
	{EMPTY_MI_EXPORT}
};

/** Module exports */
struct module_exports exports = {
	"httpd",                    /* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,				            /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	NULL,                       /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	NULL,                       /* exported PV */
	NULL,						/* exported transformations */
	mi_procs,                   /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) NULL,   /* response handling function */
	(destroy_function) destroy, /* destroy function */
	NULL,                       /* per-child init function */
	NULL                        /* reload confirm function */
};


#if defined MHD_VERSION && MHD_VERSION < 0x00093500
static long httpd_get_runtime_version(void)
{
	char *end;
	const char *ver = MHD_get_version(), *rend, *vi;
	unsigned long tmp, version = 0;
	int i;

	vi = ver;
	rend = ver + strlen(ver);
	for (i = 1; i < 4; i++) {
		tmp = strtoul(vi, &end, 16);
		if (end == vi || end > rend) {
			LM_ERR("invalid libmicrohttpd version %s at token %d\n", ver, i);
			return 0;
		}
		vi = end + 1;
		version += tmp;
		version <<= 8;
	}

	return version;
}
#endif

static int mod_init(void)
{
	struct ip_addr *_ip;
	struct httpd_server *s;
	int i, total_workers = 0;

#if defined MHD_VERSION && MHD_VERSION >= 0x00093500
	/* Get whether epoll() is supported. If supported then
	 * Flags MHD_USE_EPOLL and MHD_USE_EPOLL_INTERNAL_THREAD can be used. */
	if (MHD_is_feature_supported(MHD_FEATURE_EPOLL)!=MHD_YES) {
#else
	if (httpd_get_runtime_version() < 0x00095000) {
#endif
		LM_CRIT("the version of libmicrohttpd you have does not support "
			"EPOLL feature, you need a version newer than 0.9.50, but "
			"running %s\n",MHD_get_version());
		return -1;
	}

	if (httpd_n_servers == 0) {
		str def = {HTTPD_DEFAULT_SRV, sizeof(HTTPD_DEFAULT_SRV) - 1};
		if (!httpd_get_server(&def))
			return -1;
	}

	for (i = 0; i < httpd_n_servers; i++) {
		s = &httpd_servers[i];

		if (s->port == 0) {
			if (s->name.len == sizeof(HTTPD_DEFAULT_SRV) - 1 &&
					memcmp(s->name.s, HTTPD_DEFAULT_SRV, s->name.len) == 0)
				s->port = 8888;
			else {
				LM_ERR("missing 'port' for HTTP server '%.*s'\n",
					s->name.len, s->name.s);
				return -1;
			}
		}

		if (s->ip.s) {
			s->ip.len = strlen(s->ip.s);
			if (strcmp(s->ip.s, "*") && !(_ip=str2ip(&s->ip))
					&& !(_ip=str2ip6(&s->ip))) {
				LM_ERR("invalid IP [%.*s] for HTTP server '%.*s'\n",
					s->ip.len, s->ip.s, s->name.len, s->name.s);
				return -1;
			}
		}

		if (s->workers < 1)
			s->workers = 1;
		if (s->post_buf_size == 0)
			s->post_buf_size = DEFAULT_POST_BUF_SIZE;
		if (s->post_buf_size < MIN_POST_BUF_SIZE) {
			LM_ERR("post_buf_size should be bigger than %d (HTTP server '%.*s')\n",
				MIN_POST_BUF_SIZE, s->name.len, s->name.s);
			return -1;
		}
		if (s->receive_buf_size == 0)
			s->receive_buf_size = DEFAULT_POST_BUF_SIZE;
		if (s->conn_timeout == 0)
			s->conn_timeout = DEFAULT_CONN_TIMEOUT;
		if (!s->tls_ciphers.s)
			s->tls_ciphers.s = DEFAULT_TLS_CIPHERS;
		if ((s->tls_cert_file.s && !s->tls_key_file.s) ||
				(!s->tls_cert_file.s && s->tls_key_file.s)) {
			LM_ERR("both tls_cert_file and tls_key_file are required for a "
				"TLS HTTP server ('%.*s')\n", s->name.len, s->name.s);
			return -1;
		}

		total_workers += s->workers;
		LM_INFO("HTTP server '%.*s' on %s:%d with %d worker(s)%s\n",
			s->name.len, s->name.s, s->ip.s ? s->ip.s : "*", s->port,
			s->workers, s->tls_cert_file.s ? " (TLS)" : "");
	}

	if (auth_realm.s)
		auth_realm.len = strlen(auth_realm.s);
	if (auth_username.s)
		auth_username.len = strlen(auth_username.s);
	if (auth_password.s)
		auth_password.len = strlen(auth_password.s);

	if ((auth_username.s && !auth_password.s) ||
			(!auth_username.s && auth_password.s)) {
		LM_ERR("both auth_username and auth_password must be set\n");
		return -1;
	}
	if (auth_username.s && auth_username.len == 0) {
		LM_ERR("auth_username cannot be empty\n");
		return -1;
	}

	mi_procs[0].no = total_workers;

	return 0;
}


static void destroy(void)
{
	struct httpd_cb *cb = httpd_cb_list;

	httpd_proc_destroy();

	while(cb) {
		httpd_cb_list = cb->next;
		shm_free(cb);
		cb = httpd_cb_list;
	}
}


int httpd_register_httpdcb(const char *module, str *http_root,
			httpd_access_handler_cb f1,
			httpd_flush_data_cb f2,
			enum HTTPD_CONTENT_TYPE type,
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
		LM_ERR("NULL access handler cb\n"); return -1;
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
	cb->type = type;
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

static mi_response_t *mi_list_root_path(const mi_params_t *params,
						struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_arr;
	mi_item_t *root_item;
	struct httpd_cb *cb = httpd_cb_list;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	while(cb) {
		root_item = add_mi_object(resp_arr, 0, 0);
		if (!root_item)
			goto error;

		if (add_mi_string(root_item, MI_SSTR("http_root"),
				cb->http_root->s, cb->http_root->len) < 0)
			goto error;

		if (add_mi_string(root_item, MI_SSTR("module"),
				(char*)cb->module, strlen(cb->module)) < 0)
			goto error;

		cb = cb->next;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}
