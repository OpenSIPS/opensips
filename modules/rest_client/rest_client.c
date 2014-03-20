/*
 * $Id$
 *
 * Copyright (C) 2013 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2013-02-28: Created (Liviu)
 */


#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"

#include "rest_methods.h"

/*
 * Module parameters
 */
long connection_timeout = 20;
long curl_timeout = 20;

char *ssl_capath;

/* libcurl enables these by default */
int ssl_verifypeer = 1;
int ssl_verifyhost = 1;

/*
 * Module initialization and cleanup
 */
static int mod_init(void);
static void mod_destroy(void);

/*
 * Fixup functions
 */
static int fixup_rest_get(void **param, int param_no);
static int fixup_rest_post(void **param, int param_no);

/*
 * Function headers
 */
static int w_rest_get(struct sip_msg *msg, char *gp_url, char *body_pv,
				char *type_pv, char *code_pv);
static int w_rest_post(struct sip_msg *msg, char *gp_url, char *gp_body,
				char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv);


/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{ "rest_get",(cmd_function)w_rest_get, 2, fixup_rest_get, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_get",(cmd_function)w_rest_get, 3, fixup_rest_get, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_get",(cmd_function)w_rest_get, 4, fixup_rest_get, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_post",(cmd_function)w_rest_post, 4, fixup_rest_post, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_post",(cmd_function)w_rest_post, 5, fixup_rest_post, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ "rest_post",(cmd_function)w_rest_post, 6, fixup_rest_post, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|
		ONREPLY_ROUTE|STARTUP_ROUTE|TIMER_ROUTE },
	{ 0, 0, 0, 0, 0, 0 }
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{ "connection_timeout",	INT_PARAM, &connection_timeout	},
	{ "curl_timeout",		INT_PARAM, &curl_timeout		},
	{ "ssl_capath",			STR_PARAM, &ssl_capath			},
	{ "ssl_verifypeer",		INT_PARAM, &ssl_verifypeer		},
	{ "ssl_verifyhost",		INT_PARAM, &ssl_verifyhost		},
	{ 0, 0, 0 }
};


/*
 * Module parameter variables
 */
struct module_exports exports = {
	"rest_client",
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,     /* Exported functions */
	params,   /* Exported parameters */
	0,        /* exported statistics */
	0,        /* exported MI functions */
	0,        /* exported pseudo-variables */
	0,        /* extra processes */
	mod_init, /* module initialization function */
	0,        /* response function*/
	mod_destroy,
	0         /* per-child init function */
};


static int mod_init(void)
{
	LM_DBG("Initializing...\n");

	curl_global_init(CURL_GLOBAL_ALL);

	LM_INFO("Module initialized!\n");

	return 0;
}

static void mod_destroy(void)
{
	curl_global_cleanup();
}

/**************************** Fixup functions *******************************/


static int fixup_rest_get(void **param, int param_no)
{
	switch (param_no) {
	case 1:
		return fixup_spve(param);
	case 2:
	case 3:
	case 4:
		return fixup_pvar(param);

	default:
		LM_ERR("Too many parameters!\n");
		return -1;
	}
}

static int fixup_rest_post(void **param, int param_no)
{
	switch (param_no) {
	case 1:
	case 2:
	case 3:
		return fixup_spve(param);
	case 4:
	case 5:
	case 6:
		return fixup_pvar(param);

	default:
		LM_ERR("Too many parameters!\n");
		return -1;
	}
}

/**************************** Module functions *******************************/

static int w_rest_get(struct sip_msg *msg, char *gp_url, char *body_pv,
                      char *type_pv, char *code_pv)
{
	str url;

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	return rest_get_method(msg, url.s, (pv_spec_p)body_pv, (pv_spec_p)type_pv,
	                       (pv_spec_p)code_pv);
}

static int w_rest_post(struct sip_msg *msg, char *gp_url, char *gp_body,
                   char *gp_ctype, char *body_pv, char *ctype_pv, char *code_pv)
{
	str url, ctype, body;

	if (fixup_get_svalue(msg, (gparam_p)gp_url, &url) != 0) {
		LM_ERR("Invalid HTTP URL pseudo variable!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)gp_ctype, &ctype) != 0) {
		LM_ERR("Invalid HTTP POST content type pseudo variable!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)gp_body, &body) != 0) {
		LM_ERR("Invalid HTTP POST body pseudo variable!\n");
		return -1;
	}

	return rest_post_method(msg, url.s, ctype.s, body.s, (pv_spec_p)body_pv,
	                        (pv_spec_p)ctype_pv, (pv_spec_p)code_pv);
}

