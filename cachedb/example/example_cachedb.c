/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 *
 * history:
 * ---------
 *  2011-10-xx  created (vlad-paiu)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"

/* needed for cachedb functionality */
#include "../../cachedb/cachedb.h"

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

static int process_msg(struct sip_msg *msg);

/* URL provided as modparam
 * Examples of URLs :
 ** local://
 ** memcached://192.168.2.134:9999,192.168.2.135:10234/
 ** redis://root:foobared@localhost:6381/
*/
str cachedb_url;

/* Functions that will allow operations with a Cache/DB back-end */
cachedb_funcs cdbf;
/* Actual connection to the Cache/DB back-end */
cachedb_con *con;

static cmd_export_t cmds[]=
{
	{"process_msg",  (cmd_function)process_msg,  0, 0, 0, REQUEST_ROUTE},
	{0,0,0,0,0,0}
};

static param_export_t params[]={
	{ "cachedb_url",                 STR_PARAM, &cachedb_url.s},
	{0,0,0}
};


/** module exports */
struct module_exports exports= {
	"example_cachedb",			/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	0,						/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function)destroy,	/* destroy function */
	child_init                  /* per-child init function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module example_cachedb ...\n");
	str key=str_init("opensips_online");
	str value=str_init("1");

	cachedb_url.len = cachedb_url.s ? strlen(cachedb_url.s) : 0;
	LM_DBG("cachedb_url=%s\n", ZSW(cachedb_url.s));

	if(cachedb_url.s== NULL)
	{
		LM_ERR("URL not set!\n");
		return -1;
	}

	LM_DBG("binding to specific module, based on URL\n");

	if (cachedb_bind_mod(&cachedb_url,&cdbf) < 0) {
		LM_ERR("failed to bind to mod\n");
		return -1;
	}

	LM_DBG("initializing connection to back-end \n");
	con = cdbf.init(&cachedb_url);
	if (con == NULL) {
		LM_ERR("failed to connect to back-end\n");
		return -1;
	}

	LM_DBG("Setting key opensips_online in back-end\n");
	if (cdbf.set(con,&key,&value,0) < 0) {
		LM_ERR("failed to set key\n");
		return -1;
	}

	LM_DBG("Destroying connection to back-end\n");
	cdbf.destroy(con);

	LM_INFO("successfully loaded cachedb_example module\n");
	return 0;
}

static int child_init(int rank)
{
	/* create a connection for each child */
	LM_DBG("initializing connection to back-end for child %d \n",rank);

	con = cdbf.init(&cachedb_url);
	if (con == NULL) {
		LM_ERR("failed to connect to back-end\n");
		return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	str key_op=str_init("opensips_online");
	str value_op=str_init("0");
	str key_inv=str_init("inv_bye");
	str val_inv;

	LM_NOTICE("Destroy module cachedb_example...\n");

	if (cdbf.get(con,&key_inv,&val_inv) < 0)
		LM_ERR("failed to get key\n");

	LM_DBG("At OpenSIPS shutdown, counter = %.*s\n",val_inv.len,val_inv.s);
	LM_DBG("Setting key opensips_online in back-end\n");

	if (cdbf.set(con,&key_op,&value_op,0) < 0)
		LM_ERR("failed to set key\n");

	LM_DBG("Closing connection to back-end\n");
	cdbf.destroy(con);
}

static int process_msg(struct sip_msg *msg)
{
	str key=str_init("inv_bye");
	int ret,result;

	LM_DBG("Inside process_msg\n");

	/* based on different message contents, decide to do some Cache/DB ops
	 ** Each time we receive an Invite we will increment a counter
	 ** Each time we receive a BYE we will decrement a counter
	 */
	if (msg->first_line.u.request.method_value==METHOD_INVITE) {
		ret = cdbf.add(con,&key,1,0,&result);
		if (ret<0) {
			LM_ERR("failed to add to key\n");
			return -1;
		}
	} else if (msg->first_line.u.request.method_value==METHOD_BYE) {
		ret = cdbf.sub(con,&key,1,0,&result);
		if (ret<0) {
			LM_ERR("failed to add to key\n");
			return -1;
		}
	}

	LM_DBG("Exiting process_msg. Counter =  %d\n",result);
	return 1;
}
