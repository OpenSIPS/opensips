/*
 * Copyright (C) 2024 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 * Foundation, Inc., 51 Franklin Street, 5th Floor, Boston, MA 02110-1301, USA
 */

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "../../globals.h"
#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"

#include "server.h"
#include "h2_evi.h"

/* module functions */
static int mod_init();
static void mod_destroy(void);

unsigned int h2_port = 443;
char *h2_ip;
str h2_tls_cert = STR_NULL;
str h2_tls_key = STR_NULL;

int h2_response_timeout = 2000; /* ms */
unsigned int max_headers_size = 8192; /* B */

struct h2_response **h2_response, *ng_h2_response;

static int h2_send_response(struct sip_msg *msg, int *code,
		str *headers_json, str *body);

static const cmd_export_t cmds[]= {
	{"http2_send_response", (cmd_function)h2_send_response, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		EVENT_ROUTE},

	{0,0,{{0,0,0}},0}
};

static const proc_export_t procs[] = {
	{"HTTP2D",  0,  0, http2_server, 1, PROC_FLAG_INITCHILD|PROC_FLAG_NEEDS_SCRIPT },
	{NULL, 0, 0, NULL, 0, 0}
};

/* Module parameters */
static const param_export_t params[] = {
	{"ip",            STR_PARAM, &h2_ip},
	{"port",          INT_PARAM, &h2_port},
	{"tls_cert_path", STR_PARAM, &h2_tls_cert.s},
	{"tls_key_path", STR_PARAM,  &h2_tls_key.s},
	{"max_headers_size", INT_PARAM,  &max_headers_size},
	{"response_timeout", INT_PARAM,  &h2_response_timeout},
	{NULL, 0, NULL}
};

/* MI commands */
static const mi_export_t mi_cmds[] = {
	{EMPTY_MI_EXPORT},
};

/* Module exports */
struct module_exports exports = {
	"http2d",                   /* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load function */
	NULL,                       /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	NULL,                       /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	NULL,                       /* exported PV */
	NULL,                       /* exported transformations */
	procs,                      /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) NULL,   /* response handling function */
	(destroy_function) mod_destroy, /* destroy function */
	NULL,                       /* per-child init function */
	NULL                        /* reload confirm function */
};


static int mod_init(void)
{
	if (!h2_tls_cert.s) {
		LM_ERR("no TLS cert filepath provided (mandatory)\n");
		return -1;
	}

	if (!h2_tls_key.s) {
		LM_ERR("no TLS key filepath provided (mandatory)\n");
		return -1;
	}

	if (!h2_ip)
		h2_ip = "127.0.0.1";

	h2_tls_cert.len = strlen(h2_tls_cert.s);
	h2_tls_key.len = strlen(h2_tls_key.s);

	if (h2_init_evi() != 0) {
		LM_ERR("failed to init EVI structures\n");
		return -1;
	}

	return 0;
}


static int h2_send_response(struct sip_msg *msg, int *code,
		str *headers_json, str *body)
{
#define H_STATUS ":status"
	cJSON *hdrs, *it;
	struct h2_response *r;
	int nh = 1;

	if (!h2_response)
		return -1;
	r = *h2_response;
	r->code = -1;

	if (*code < 100 || *code > 599) {
		LM_ERR("invalid HTTP/2 response code: %d, must be 100-599\n", *code);
		goto error;
	}

	if (headers_json) {
		char *hp;
		str h;

		/* safe to dereference outside buff (still within PKG block) */
		if (headers_json->s[headers_json->len] != '\0') {
			if (pkg_nt_str_dup(&h, headers_json) != 0) {
				LM_ERR("oom\n");
				goto error;
			}
			hp = h.s;
		} else {
			hp = headers_json->s;
		}

		hdrs = cJSON_Parse(hp);
		if (hp != headers_json->s)
			pkg_free(hp);

		if (!hdrs) {
			LM_ERR("failed to parse 'headers_json' (bad JSON syntax)\n");
			LM_ERR("first %d characters: %.*s ...\n",
				headers_json->len > 20 ? 20 : headers_json->len,
				headers_json->len > 20 ? 20 : headers_json->len, headers_json->s);
			cJSON_Delete(hdrs);
			goto error;
		}

		if (hdrs->type != cJSON_Array) {
			LM_ERR("bad 'headers_json' value (must be a List of name/value pairs)\n");
			LM_ERR("first %d characters: %.*s ...\n",
				headers_json->len > 20 ? 20 : headers_json->len,
				headers_json->len > 20 ? 20 : headers_json->len, headers_json->s);
			cJSON_Delete(hdrs);
			goto error;
		}

		int pseudo_headers_done = 0;

		for (it = hdrs->child; it; it = it->next, nh++) {
			if (it->type != cJSON_Object) {
				LM_ERR("bad 'headers_json' value (must be a List of Objects, but "
						"detected cJSON type %d as element)\n", it->type);
				LM_ERR("first %d characters: %.*s ...\n",
					headers_json->len > 20 ? 20 : headers_json->len,
					headers_json->len > 20 ? 20 : headers_json->len, headers_json->s);
				cJSON_Delete(hdrs);
				goto error;
			}

			if (it->child->type != cJSON_String) {
				LM_ERR("bad 'headers_json' value (header values must be Strings, but "
						"detected cJSON type %d as value)\n", it->child->type);
				LM_ERR("first %d characters: %.*s ...\n",
					headers_json->len > 20 ? 20 : headers_json->len,
					headers_json->len > 20 ? 20 : headers_json->len, headers_json->s);
				cJSON_Delete(hdrs);
				goto error;
			}

			if (!strlen(it->child->string)) {
				LM_ERR("bad 'headers_json' value (empty-string header found)\n");
				LM_ERR("first %d characters: %.*s ...\n",
					headers_json->len > 20 ? 20 : headers_json->len,
					headers_json->len > 20 ? 20 : headers_json->len, headers_json->s);
				cJSON_Delete(hdrs);
				goto error;
			}

			if (!strcmp(it->child->string, H_STATUS)) {
				LM_ERR("bad 'headers_json' value (':status' header/code "
							"already given as 1st argument)\n");
				LM_ERR("first %d characters: %.*s ...\n",
					headers_json->len > 20 ? 20 : headers_json->len,
					headers_json->len > 20 ? 20 : headers_json->len, headers_json->s);
				cJSON_Delete(hdrs);
				goto error;
			}

			if (it->child->string[0] != ':') {
				pseudo_headers_done = 1;
			} else if (pseudo_headers_done) {
				LM_ERR("bad response headers ordering: pseudo-header '%s' follows a literal header\n",
					it->child->string);
				cJSON_Delete(hdrs);
				goto error;
			}
		}
	}

	r->hdrs = shm_malloc(nh * sizeof *r->hdrs);
	if (!r->hdrs) {
		LM_ERR("oom\n");
		cJSON_Delete(hdrs);
		goto error;
	}
	r->hdrs_len = 1;
	nh = 0;

	r->hdrs[nh].name = (uint8_t *)shm_strdup(H_STATUS);
	r->hdrs[nh].value = (uint8_t *)shm_malloc(4);
	if (!r->hdrs[nh].name || !r->hdrs[nh].value) {
		LM_ERR("oom (SHM)\n");
		cJSON_Delete(hdrs);
		h2_response_clean();
		goto error;
	}

	r->hdrs[nh].namelen = strlen((const char *)r->hdrs[nh].name);
	sprintf((char *)r->hdrs[nh].value, "%d", *code);
	r->hdrs[nh].valuelen = 3;
	r->hdrs[nh].flags = NGHTTP2_NV_FLAG_NONE;
	nh++;

	if (headers_json) {
		for (it = hdrs->child; it; it = it->next, nh++, r->hdrs_len++) {
			r->hdrs[nh].name = (uint8_t *)shm_strdup(it->child->string);
			r->hdrs[nh].value = (uint8_t *)shm_strdup(it->child->valuestring);

			if (!r->hdrs[nh].name || !r->hdrs[nh].value) {
				LM_ERR("oom (SHM)\n");
				cJSON_Delete(hdrs);
				h2_response_clean();
				goto error;
			}

			r->hdrs[nh].namelen = strlen((const char *)r->hdrs[nh].name);
			r->hdrs[nh].valuelen = strlen((const char *)r->hdrs[nh].value);
			r->hdrs[nh].flags = NGHTTP2_NV_FLAG_NONE;
		}

		cJSON_Delete(hdrs);
	}

	if (body) {
		if (shm_str_dup(&r->body, body) != 0) {
			LM_ERR("oom (SHM)\n");
			h2_response_clean();
			goto error;
		}
	}

	r->code = *code;
	pthread_mutex_lock(&r->mutex);
	pthread_cond_signal(&r->cond);
	pthread_mutex_unlock(&r->mutex);
	return 1;

error:
	pthread_mutex_lock(&r->mutex);
	pthread_cond_signal(&r->cond);
	pthread_mutex_unlock(&r->mutex);
	return -1;
}


static void mod_destroy(void)
{
	return;
}
