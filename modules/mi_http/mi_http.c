/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * History:
 * ---------
 *  2011-09-20  first version (osas)
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
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "httpd_proc.h"

/* module functions */
static int mod_init();
static int destroy(void);

int port = 8888;
int buf_size = 0;
str http_root = str_init("mi");

static proc_export_t mi_procs[] = {
	{"MI HTTP",  0,  0, httpd_proc, 1, PROC_FLAG_INITCHILD },
	{0,0,0,0,0,0}
};


/* module parameters */
static param_export_t mi_params[] = {
	{"port",			INT_PARAM, &port},
	{"mi_http_root",		STR_PARAM, &http_root.s},
	{"buf_size",			INT_PARAM, &buf_size},
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
	mi_procs,                           /* extra processes */
	mod_init,                           /* module initialization function */
	(response_function) 0,              /* response handling function */
	(destroy_function) destroy,         /* destroy function */
	NULL                                /* per-child init function */
};


static int mod_init(void)
{
	int i;

	if ( port <= 1024 ) {
		LM_ERR("port<1024, using 8888...\n");
		return -1;
	}

	if (buf_size == 0)
		buf_size = (pkg_mem_size/4)*3;
	LM_DBG("buf_size=[%d]\n", buf_size);

	http_root.len = strlen(http_root.s);
	trim_spaces_lr(http_root);
	for(i=0;i<http_root.len;i++) {
		if ( !isalnum(http_root.s[i]) && http_root.s[i]!='_') {
			LM_ERR("bad mi_http_root param [%.*s], char [%c] "
				"- use only alphanumerical characters\n",
				http_root.len, http_root.s, http_root.s[i]);
			return -1;
		}
	}
	return 0;
}


int destroy(void)
{
	httpd_proc_destroy();
	return 0;
}
