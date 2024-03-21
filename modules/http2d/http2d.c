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

/* module functions */
static int mod_init();
static void mod_destroy(void);

unsigned int h2_port = 9111;
char *h2_ip;
str h2_tls_cert = STR_NULL;
str h2_tls_key = STR_NULL;


static const proc_export_t procs[] = {
	{"HTTP2D",  0,  0, http2_server, 1, PROC_FLAG_INITCHILD },
	{NULL, 0, 0, NULL, 0, 0}
};

/* Module parameters */
static const param_export_t params[] = {
	{"port",          INT_PARAM, &h2_port},
	{"ip",            STR_PARAM, &h2_ip},
	{"tls_cert_file", STR_PARAM, &h2_tls_cert.s},
	{"tls_key_file", STR_PARAM,  &h2_tls_key.s},
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
	NULL,                       /* exported functions */
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

	return 0;
}


static void mod_destroy(void)
{
	return;
}
