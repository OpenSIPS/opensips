/*
 * xcap_client module - XCAP client for OpenSIPS
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2007-08-20  initial version (anca)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <curl/curl.h>

#include "../../sr_module.h"
#include "../../pt.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../xcap/api.h"
#include "../xcap/util.h"
#include "../presence/utils_func.h"
#include "xcap_functions.h"
#include "xcap_client.h"



static int mod_init(void);
static int child_init(int);
void destroy(void);
struct mi_root* refreshXcapDoc(struct mi_root* cmd, void* param);
int get_auid_flag(str auid);
xcap_callback_t* xcapcb_list= NULL;
int periodical_query= 1;
unsigned int query_period= 100;

str str_source_col = str_init("source");
str str_path_col = str_init("path");
str str_doc_col = str_init("doc");
str str_etag_col = str_init("etag");
str str_username_col = str_init("username");
str str_domain_col = str_init("domain");
str str_doc_type_col = str_init("doc_type");
str str_doc_uri_col = str_init("doc_uri");
str str_port_col = str_init("port");


/* database connection */
db_con_t *xcap_db = NULL;
db_func_t xcap_dbf;

/* xcap API */
str xcap_db_url = {NULL, 0};
str xcap_db_table = {NULL, 0};


void query_xcap_update(unsigned int ticks, void* param);

static param_export_t params[]={
	{ "periodical_query",       INT_PARAM,         &periodical_query },
	{ "query_period",           INT_PARAM,         &query_period     },
	{    0,                     0,                      0            }
};


static cmd_export_t  cmds[]=
{
	{"bind_xcap_client",  (cmd_function)bind_xcap_client,  1,    0, 0,        0},
	{    0,                     0,           0,    0, 0,        0}
};

static mi_export_t mi_cmds[] = {
	{ "refreshXcapDoc", 0, refreshXcapDoc,      0,  0,  0},
	{ 0,                0, 0,                  0,  0,  0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "xcap", DEP_ABORT },
		{ MOD_TYPE_SQLDB,   NULL,   DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"xcap_client",				/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,  						/* exported functions */
	0,  						/* exported async functions */
	params,						/* exported parameters */
	0,      					/* exported statistics */
	mi_cmds,   					/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init                  /* per-child init function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	bind_xcap_t bind_xcap;
	xcap_api_t xcap_api;

        /* load XCAP API */
        bind_xcap = (bind_xcap_t)find_export("bind_xcap", 1, 0);
        if (!bind_xcap)
        {
                LM_ERR("Can't bind xcap\n");
                return -1;
        }

        if (bind_xcap(&xcap_api) < 0)
        {
                LM_ERR("Can't bind xcap\n");
                return -1;
        }
        xcap_db_url = xcap_api.db_url;
        xcap_db_table = xcap_api.xcap_table;

	/* binding to mysql module  */
	if (db_bind_mod(&xcap_db_url, &xcap_dbf))
	{
		LM_ERR("Database module not found\n");
		return -1;
	}

	if (!DB_CAPABILITY(xcap_dbf, DB_CAP_ALL)) {
		LM_ERR("Database module does not implement all functions"
				" needed by the module\n");
		return -1;
	}

	xcap_db = xcap_dbf.init(&xcap_db_url);
	if (!xcap_db)
	{
		LM_ERR("while connecting to database\n");
		return -1;
	}

	curl_global_init(CURL_GLOBAL_ALL);

	if(periodical_query)
	{
		register_timer("xcapc-update", query_xcap_update, 0,
			query_period, TIMER_FLAG_DELAY_ON_DELAY);
	}

	if(xcap_db)
		xcap_dbf.close(xcap_db);
	xcap_db = NULL;

	return 0;
}


static int child_init(int rank)
{
	if (xcap_dbf.init==0)
	{
		LM_CRIT("child_init: database not bound\n");
		return -1;
	}
	xcap_db = xcap_dbf.init(&xcap_db_url);
	if (!xcap_db)
	{
		LM_ERR("child %d: unsuccessful connecting to database\n", rank);
		return -1;
	}

	LM_DBG("child %d: Database connection opened successfully\n", rank);

	return 0;
}

void destroy(void)
{
	curl_global_cleanup();
}

void query_xcap_update(unsigned int ticks, void* param)
{
	db_key_t query_cols[3], update_cols[3];
	db_val_t query_vals[3], update_vals[3];
	db_key_t result_cols[7];
	int n_result_cols = 0, n_query_cols= 0, n_update_cols= 0;
	db_res_t* result= NULL;
	int user_col, domain_col, doc_type_col, etag_col, doc_uri_col, port_col;
	db_row_t *row ;
	db_val_t *row_vals ;
	unsigned int port;
	char* etag, *path, *new_etag= NULL;
	str doc= {0, 0};
	int u_doc_col, u_etag_col;
	str user, domain, uri;
	int i;

	/* query the ones I have to handle */
	query_cols[n_query_cols] = &str_source_col;
	query_vals[n_query_cols].type = DB_INT;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.int_val= XCAP_CL_MOD;
	n_query_cols++;

	query_cols[n_query_cols] = &str_path_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;

	update_cols[u_doc_col=n_update_cols] = &str_doc_col;
	update_vals[n_update_cols].type = DB_BLOB;
	update_vals[n_update_cols].nul = 0;
	n_update_cols++;

	update_cols[u_etag_col=n_update_cols] = &str_etag_col;
	update_vals[n_update_cols].type = DB_STRING;
	update_vals[n_update_cols].nul = 0;
	n_update_cols++;

	result_cols[user_col= n_result_cols++]     = &str_username_col;
	result_cols[domain_col=n_result_cols++]    = &str_domain_col;
	result_cols[doc_type_col=n_result_cols++]  = &str_doc_type_col;
	result_cols[etag_col=n_result_cols++]      = &str_etag_col;
	result_cols[doc_uri_col= n_result_cols++]  = &str_doc_uri_col;
	result_cols[port_col= n_result_cols++]     = &str_port_col;

	if (xcap_dbf.use_table(xcap_db, &xcap_db_table) < 0)
	{
		LM_ERR("in use_table-[table]= %.*s\n", xcap_db_table.len, xcap_db_table.s);
		goto error;
	}

	if(xcap_dbf.query(xcap_db, query_cols, 0, query_vals, result_cols, 1,
				n_result_cols, 0, &result)< 0)
	{
		LM_ERR("in sql query\n");
		goto error;
	}
	if(result== NULL)
	{
		LM_ERR("in sql query- null result\n");
		return;
	}
	if(result->n<= 0)
	{
		xcap_dbf.free_result(xcap_db, result);
		return;
	}
	n_query_cols++;

	/* ask if updated */
	for(i= 0; i< result->n; i++)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);

		path= (char*)row_vals[doc_uri_col].val.string_val;
		port= row_vals[port_col].val.int_val;
		etag= (char*)row_vals[etag_col].val.string_val;

		user.s= (char*)row_vals[user_col].val.string_val;
		user.len= strlen(user.s);

		domain.s= (char*)row_vals[domain_col].val.string_val;
		domain.len= strlen(domain.s);

		/* send HTTP request */
		doc.s= send_http_get(path, port, etag, IF_NONE_MATCH, &new_etag, &doc.len);
		if(doc.s == NULL)
		{
			LM_DBG("document not update\n");
			continue;
		}
		if(new_etag== NULL)
		{
			LM_ERR("etag not found\n");
			pkg_free(doc.s);
			goto error;
		}
		/* update in xcap db table */
		update_vals[u_doc_col].val.blob_val= doc;
		update_vals[u_etag_col].val.string_val= etag;

		if(xcap_dbf.update(xcap_db, query_cols, 0, query_vals, update_cols,
					update_vals, n_query_cols, n_update_cols)< 0)
		{
			LM_ERR("in sql update\n");
			pkg_free(doc.s);
			goto error;
		}
		/* call registered callbacks */
		if(uandd_to_uri(user, domain, &uri)< 0)
		{
			LM_ERR("converting user and domain to uri\n");
			pkg_free(doc.s);
			goto error;
		}
		run_xcap_update_cb(row_vals[doc_type_col].val.int_val, uri, doc.s);
		pkg_free(doc.s);

	}

	xcap_dbf.free_result(xcap_db, result);
	return;

error:
	if(result)
		xcap_dbf.free_result(xcap_db, result);
}

int parse_doc_url(str doc_url, char** serv_addr, xcap_doc_sel_t* doc_sel)
{
	char* sl, *str_type;

	sl= strchr(doc_url.s, '/');
	*sl= '\0';
	*serv_addr= doc_url.s;

	sl++;
	doc_sel->auid.s= sl;
	sl= strchr(sl, '/');
	doc_sel->auid.len= sl- doc_sel->auid.s;

	sl++;
	str_type= sl;
	sl= strchr(sl, '/');
	*sl= '\0';

	if(strcasecmp(str_type, "users")== 0)
		doc_sel->type= USERS_TYPE;
	else
	if(strcasecmp(str_type, "group")== 0)
		doc_sel->type= GLOBAL_TYPE;

	sl++;

	return 0;

}
/*
 * mi cmd: refreshXcapDoc
 *			<document uri>
 *			<xcap_port>
 * */

struct mi_root* refreshXcapDoc(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str doc_url;
	xcap_doc_sel_t doc_sel;
	char* serv_addr;
	str stream= {0, 0};
	int type;
	unsigned int xcap_port;
	char* etag= NULL;

	node = cmd->node.kids;
	if(node == NULL)
		return 0;

	doc_url = node->value;
	if(doc_url.s == NULL || doc_url.len== 0)
	{
		LM_ERR("empty uri\n");
		return init_mi_tree(404, "Empty document URL", 20);
	}
	node= node->next;
	if(node== NULL)
		return 0;
	if(node->value.s== NULL || node->value.len== 0)
	{
		LM_ERR("port number\n");
		return init_mi_tree(404, "Empty document URL", 20);
	}
	if(str2int(&node->value, &xcap_port)< 0)
	{
		LM_ERR("while converting string to int\n");
		goto error;
	}

	if(node->next!= NULL)
		return 0;

	/* send GET HTTP request to the server */
	stream.s = send_http_get(doc_url.s, xcap_port, NULL, 0, &etag, &stream.len);
	if(stream.s== NULL)
	{
		LM_ERR("in http get\n");
		return 0;
	}

	/* call registered functions with document argument */
	if(parse_doc_url(doc_url, &serv_addr, &doc_sel)< 0)
	{
		LM_ERR("parsing document url\n");
		return 0;
	}

	type = xcap_doc_type(&doc_sel.auid);
	if (type < 0)
	{
		LM_ERR("incorect auid: %.*s\n",
				doc_sel.auid.len, doc_sel.auid.s);
		goto error;
	}

	run_xcap_update_cb(type, doc_sel.xid, stream.s);
	pkg_free(stream.s);

	return init_mi_tree(200, "OK", 2);

error:
	if(stream.s)
		pkg_free(stream.s);
	return 0;
}

