/*
 * b2b_sca module
 *
 * Copyright (C) 2010 VoIP Embedded, Inc.
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
 *  2010-11-02  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mod_fix.h"
#include "../../trim.h"
#include "../../db/db.h"
#include "../../parser/parse_from.h"
#include "../tm/tm_load.h"
#include "../pua/pua_bind.h"
#include "../b2b_logic/b2b_load.h"
#include "sca_records.h"
#include "sca_logic.h"
#include "sca_db_handler.h"

extern str app_state[];


/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
int sca_init_request(struct sip_msg* msg, int *shared_entity);
int sca_bridge_request(struct sip_msg* msg, str* arg1);
mi_response_t *mi_sca_list(const mi_params_t *params,
								struct mi_handler *async_hdl);

/** Global variables */
struct tm_binds tmb;
pua_api_t pua_api;
b2bl_api_t b2bl_api;

b2b_sca_table_t b2b_sca_htable;
unsigned int b2b_sca_hsize = 10;

static str db_url = {NULL, 0};

int watchers_avp_name = -1;
unsigned short watchers_avp_type = 0;
static str watchers_avp_spec = {NULL, 0};
static pv_spec_t watchers_spec;

static str shared_line_spec_param = {NULL, 0};
static pv_spec_t shared_line_spec;
static pv_value_t shared_line_tok;

static str appearance_name_addr_spec_param = {NULL, 0};
static pv_spec_t appearance_name_addr_spec;
static pv_value_t appearance_name_addr_tok;
static struct to_body appearance_name_addr;

#define APPEARANCE_NAME_ADDR_BUF_LEN	255
static char appearance_name_addr_buf[APPEARANCE_NAME_ADDR_BUF_LEN + 1];

str presence_server = {NULL, 0};


/** Exported functions */
static cmd_export_t cmds[]=
{
	{"sca_init_request"  ,(cmd_function)sca_init_request, {
		{CMD_PARAM_INT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"sca_bridge_request",(cmd_function)sca_bridge_request, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

/** Exported parameters */
static param_export_t params[]=
{
	{"hash_size",				INT_PARAM,&b2b_sca_hsize			},
	{"presence_server",			STR_PARAM,&presence_server.s			},
	{"watchers_avp_spec",			STR_PARAM,&watchers_avp_spec.s			},
	{"shared_line_spec_param",		STR_PARAM,&shared_line_spec_param.s		},
	{"appearance_name_addr_spec_param",	STR_PARAM,&appearance_name_addr_spec_param.s	},
	{"db_url",				STR_PARAM,&db_url.s				},
	{"db_mode",				INT_PARAM,&sca_db_mode				},
	{"table_name",				STR_PARAM,&sca_table_name			},
	{"shared_line_column",			STR_PARAM,&shared_line_column.s			},
	{"watchers_column",			STR_PARAM,&watchers_column.s			},
	{"app1_shared_entity_column",		STR_PARAM,&app_shared_entity_column[0].s	},
	{"app1_call_state_column",		STR_PARAM,&app_call_state_column[0].s		},
	{"app1_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[0].s	},
	{"app1_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[0].s},
	{"app1_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[0].s		},
	{"app2_shared_entity_column",		STR_PARAM,&app_shared_entity_column[1].s	},
	{"app2_call_state_column",		STR_PARAM,&app_call_state_column[1].s		},
	{"app2_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[1].s	},
	{"app2_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[1].s},
	{"app2_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[1].s		},
	{"app3_shared_entity_column",		STR_PARAM,&app_shared_entity_column[2].s	},
	{"app3_call_state_column",		STR_PARAM,&app_call_state_column[2].s		},
	{"app3_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[2].s	},
	{"app3_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[2].s},
	{"app3_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[2].s		},
	{"app4_shared_entity_column",		STR_PARAM,&app_shared_entity_column[3].s	},
	{"app4_call_state_column",		STR_PARAM,&app_call_state_column[3].s		},
	{"app4_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[3].s	},
	{"app4_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[3].s},
	{"app4_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[3].s		},
	{"app5_shared_entity_column",		STR_PARAM,&app_shared_entity_column[4].s	},
	{"app5_call_state_column",		STR_PARAM,&app_call_state_column[4].s		},
	{"app5_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[4].s	},
	{"app5_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[4].s},
	{"app5_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[4].s		},
	{"app6_shared_entity_column",		STR_PARAM,&app_shared_entity_column[5].s	},
	{"app6_call_state_column",		STR_PARAM,&app_call_state_column[5].s		},
	{"app6_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[5].s	},
	{"app6_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[5].s},
	{"app6_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[5].s		},
	{"app7_shared_entity_column",		STR_PARAM,&app_shared_entity_column[6].s	},
	{"app7_call_state_column",		STR_PARAM,&app_call_state_column[6].s		},
	{"app7_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[6].s	},
	{"app7_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[6].s},
	{"app7_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[6].s		},
	{"app8_shared_entity_column",		STR_PARAM,&app_shared_entity_column[7].s	},
	{"app8_call_state_column",		STR_PARAM,&app_call_state_column[7].s		},
	{"app8_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[7].s	},
	{"app8_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[7].s},
	{"app8_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[7].s		},
	{"app9_shared_entity_column",		STR_PARAM,&app_shared_entity_column[8].s	},
	{"app9_call_state_column",		STR_PARAM,&app_call_state_column[8].s		},
	{"app9_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[8].s	},
	{"app9_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[8].s},
	{"app9_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[8].s		},
	{"app10_shared_entity_column",		STR_PARAM,&app_shared_entity_column[9].s	},
	{"app10_call_state_column",		STR_PARAM,&app_call_state_column[9].s		},
	{"app10_call_info_uri_column",		STR_PARAM,&app_call_info_uri_column[9].s	},
	{"app10_call_info_appearance_uri_column",STR_PARAM,&app_call_info_appearance_uri_column[9].s},
	{"app10_b2bl_key_column",		STR_PARAM,&app_b2bl_key_column[9].s		},
	{0,				0,		0				}
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "sca_list", 0,0,0,{
		{mi_sca_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "pua",       DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "b2b_logic", DEP_ABORT },
		{ MOD_TYPE_SQLDB,   NULL,        DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** Module interface */
struct module_exports exports= {
        "b2b_sca",                      /* module name */
        MOD_TYPE_DEFAULT,               /* class of this module */
        MODULE_VERSION,                 /* module version */
        DEFAULT_DLFLAGS,                /* dlopen flags */
        0,				                /* load function */
        &deps,                          /* OpenSIPS module dependencies */
        cmds,                           /* exported functions */
        0,                              /* exported async functions */
        params,                         /* exported parameters */
        0,                              /* exported statistics */
        mi_cmds,                        /* exported MI functions */
        0,                              /* exported pseudo-variables */
		0,								/* exported transformations */
        0,                              /* extra processes */
        0,                              /* module pre-initialization function */
        mod_init,                       /* module initialization function */
        (response_function) 0,          /* response handling function */
        (destroy_function) mod_destroy, /* destroy function */
        child_init,                     /* per-child init function */
		0                               /* reload confirm function */
};

/** Module init function */
static int mod_init(void)
{
	unsigned int i;

	LM_DBG("start\n");

	init_db_url( db_url , 0 /*cannot be null*/);

	/* load tm api */
	if(load_tm_api(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	/* load pua api */
	if(load_pua_api(&pua_api) < 0)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	/* add event in pua module */
	if(pua_api.add_event(CALLINFO_EVENT, "call-info", NULL, 0) < 0) {
		LM_ERR("failed to add 'call-info' event to pua module\n");
		return -1;
	}

	/* load b2b_logic api */
	if(load_b2b_logic_api(&b2bl_api)< 0)
	{
		LM_ERR("Failed to load b2b_logic api\n");
		return -1;
	}

	if(b2b_sca_hsize<1 || b2b_sca_hsize>20)
	{
		LM_ERR("Wrong hash size. Needs to be greater than 1"
			" and smaller than 20. Be aware that you should set the log 2"
			" value of the real size\n");
		return -1;
	}
	b2b_sca_hsize = 1<<b2b_sca_hsize;

	if(presence_server.s)
		presence_server.len = strlen(presence_server.s);
	LM_DBG("fix db columns\n");
	sca_table_name.len = strlen(sca_table_name.s);
	shared_line_column.len = strlen(shared_line_column.s);
	watchers_column.len = strlen(watchers_column.s);
	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		app_shared_entity_column[i].len = strlen(app_shared_entity_column[i].s);
		app_call_state_column[i].len = strlen(app_call_state_column[i].s);
		app_call_info_uri_column[i].len = strlen(app_call_info_uri_column[i].s);
		app_call_info_appearance_uri_column[i].len =
				strlen(app_call_info_appearance_uri_column[i].s);
		app_b2bl_key_column[i].len = strlen(app_b2bl_key_column[i].s);
	}

	LM_DBG("fix AVP spec\n");
	/* fix AVP spec */
	if(watchers_avp_spec.s)
	{
		watchers_avp_spec.len = strlen(watchers_avp_spec.s);
		if(pv_parse_spec(&watchers_avp_spec, &watchers_spec)==NULL ||
			watchers_spec.type != PVT_AVP)
		{
			LM_ERR("failed to parse watchers spec [%.*s]\n",
				watchers_avp_spec.len, watchers_avp_spec.s);
			return E_CFG;
		}
		if(pv_get_avp_name(NULL, &(watchers_spec.pvp), &(watchers_avp_name),
			&(watchers_avp_type) )!=0)
		{
			LM_ERR("[%.*s]- invalid AVP definition for watchers_avp_spec\n",
				watchers_avp_spec.len, watchers_avp_spec.s);
		}
	} else {
		watchers_avp_name = -1;
		watchers_avp_type = 0;
	}

	if(shared_line_spec_param.s)
	{
		shared_line_spec_param.len = strlen(shared_line_spec_param.s);
		if(pv_parse_spec(&shared_line_spec_param, &shared_line_spec)==NULL)
		{
			LM_ERR("failed to parse shared_line spec\n");
			return E_CFG;
		}
		switch(shared_line_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid shared_line spec\n");
				return -3;
			default: ;
		}
	}

	if(appearance_name_addr_spec_param.s)
	{
		appearance_name_addr_spec_param.len = strlen(appearance_name_addr_spec_param.s);
		if(pv_parse_spec(&appearance_name_addr_spec_param, &appearance_name_addr_spec)==NULL)
		{
			LM_ERR("failed to parse appearance_name_addr spec\n");
			return E_CFG;
		}
		switch(appearance_name_addr_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid appearance_name_addr spec\n");
				return -3;
			default: ;
		}
	}

	if(init_b2b_sca_htable() < 0) {
		LM_ERR("Failed to initialize b2b_sca hash table\n");
		return -1;
	}

	if (sca_db_mode==DB_MODE_NONE) {
		db_url.s = NULL; db_url.len = 0;
	} else {
		if (sca_db_mode!=DB_MODE_REALTIME) {
			LM_ERR("unsupported db_mode %d\n", sca_db_mode);
			return -1;
		}
		if ( !db_url.s || db_url.len==0 ) {
			LM_ERR("db_url not configured for db_mode %d\n", sca_db_mode);
			return -1;
		}
		if (init_sca_db(&db_url, b2b_sca_hsize)!=0) {
			LM_ERR("failed to initialize the DB support\n");
			return -1;
		}
	}
	return 0;
}


static int child_init(int rank)
{
	if (sca_db_mode==DB_MODE_REALTIME &&  (rank>=1 || rank==PROC_MODULE)) {
		if (connect_sca_db(&db_url)) {
			LM_ERR("failed to connect to database (rank=%d)\n",rank);
			return -1;
		}
	}

	return 0;
}


static void mod_destroy(void)
{
	destroy_b2b_sca_handlers();
	destroy_b2b_sca_htable();

	LM_DBG("done\n");
	return;
}


int get_hash_index_and_shared_line(struct sip_msg* msg, unsigned int *hash_index, str **shared_line)
{
	if(shared_line_spec_param.s)
	{
		memset(&shared_line_tok, 0, sizeof(pv_value_t));
		if(pv_get_spec_value(msg, &shared_line_spec, &shared_line_tok) < 0)
		{
			LM_ERR("Failed to get shared_line value\n");
			return -1;
		}
		//LM_DBG("got shared_line_spec_param flags [%d]\n", shared_line_tok.flags);
		if(!(shared_line_tok.flags&PV_VAL_INT) && (shared_line_tok.flags&PV_VAL_STR))
		{
			*shared_line = &shared_line_tok.rs;
			*hash_index = core_hash(&shared_line_tok.rs, NULL, b2b_sca_hsize);
			//LM_DBG("got hash_index=[%d] for PV_SPEC user [%.*s]\n", *hash_index,
			//	shared_line_tok.rs.len, shared_line_tok.rs.s);
			return 0;
		}
		else
		{
			LM_ERR("No shared line PV [%.*s] defined\n",
				shared_line_spec_param.len, shared_line_spec_param.s);
			return -1;
		}
	}
	else
	{
		LM_ERR("No shared line PV defined\n");
		return -1;
	}

	/* If the shared_line_spec_param is not set, use the username from original RURI */
	/*
	parse_orig_ruri(msg);
	if (msg->parsed_orig_ruri_ok &&
		msg->parsed_orig_ruri.user.s && msg->parsed_orig_ruri.user.len) {
		*shared_line = &msg->parsed_orig_ruri.user;
		*hash_index = core_hash(&msg->parsed_orig_ruri.user, NULL, b2b_sca_hsize);
		//LM_DBG("got hash_index=[%d] for RURI user [%.*s]\n", *hash_index,
		//		msg->parsed_orig_ruri.user.len, msg->parsed_orig_ruri.user.s);
		return 0;
	} else {
		LM_ERR("msg->parsed_orig_ruri_ok is NULL\n");
	}
	*/

	return -1;
}


struct to_body* get_appearance_name_addr(struct sip_msg* msg)
{
	int len = 0;

	if(appearance_name_addr_spec_param.s)
	{
		memset(&appearance_name_addr_tok, 0, sizeof(pv_value_t));
		if(pv_get_spec_value(msg, &appearance_name_addr_spec, &appearance_name_addr_tok) < 0)
		{
			LM_ERR("Failed to get appearance_name_addr value\n");
			return NULL;
		}
		//LM_DBG("got appearance_name_addr_spec_param flags [%d]\n", appearance_name_addr_tok.flags);
		if(!(appearance_name_addr_tok.flags&PV_VAL_INT) &&
			(appearance_name_addr_tok.flags&PV_VAL_STR))
		{
			//LM_DBG("got PV_SPEC appearance_name_addr [%.*s]\n",
			//	appearance_name_addr_tok.rs.len, appearance_name_addr_tok.rs.s);
			if(appearance_name_addr_tok.rs.len+CRLF_LEN > APPEARANCE_NAME_ADDR_BUF_LEN) {
				LM_ERR("Buffer overflow\n");
				return NULL;
			}
			trim(&appearance_name_addr_tok.rs);
			memcpy(appearance_name_addr_buf, appearance_name_addr_tok.rs.s,
				appearance_name_addr_tok.rs.len);
			len = appearance_name_addr_tok.rs.len;
			if(strncmp(appearance_name_addr_tok.rs.s + len - CRLF_LEN, CRLF, CRLF_LEN)) {
				memcpy(appearance_name_addr_buf + len, CRLF, CRLF_LEN);
				len+= CRLF_LEN;
			}

			parse_to(appearance_name_addr_buf, appearance_name_addr_buf+len,
				&appearance_name_addr);
			if (appearance_name_addr.error != PARSE_OK) {
				LM_ERR("Failed to parse PV_SPEC appearance_name_addr [%.*s]\n",
					len, appearance_name_addr_buf);
				return NULL;
			}
			if (parse_uri(appearance_name_addr.uri.s, appearance_name_addr.uri.len,
					&appearance_name_addr.parsed_uri)<0) {
				LM_ERR("failed to parse PV_SPEC appearance_name_addr uri [%.*s]\n",
					appearance_name_addr.uri.len, appearance_name_addr.uri.s);
				return NULL;
			}
			return &appearance_name_addr;
		}
	}

	/* If the appearance_name_addr_spec_param is not set, use the From uri */
	/*
	if (msg->from->parsed == NULL) {
		if (parse_from_header(msg)<0) {
			LM_ERR("cannot parse From header\n");
			return NULL;
		}
	}
	*/

	return msg->from->parsed;
}

mi_response_t *mi_sca_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int i, index;
	b2b_sca_record_t *rec;
	b2b_sca_call_t *call;
	str_lst_t *watcher;
	mi_response_t *resp;
	mi_item_t *resp_arr;
	mi_item_t *resp_item, *watchers_arr, *apps_arr, *app_item;

	resp = init_mi_result_array(&resp_arr);
	if (!resp)
		return 0;

	for(index = 0; index<b2b_sca_hsize; index++) {
		lock_get(&b2b_sca_htable[index].lock);
		rec = b2b_sca_htable[index].first;
		while(rec) {
			resp_item = add_mi_object(resp_arr, NULL, 0);
			if (!resp_item)
				goto error;

			if (add_mi_string(resp_item, MI_SSTR("shared_line"),
				rec->shared_line.s, rec->shared_line.len) < 0)
				goto error;

			watchers_arr = add_mi_array(resp_item, MI_SSTR("watchers"));
			if (!watchers_arr)
				goto error;
			watcher = rec->watchers;
			while (watcher) {
				if (add_mi_string(watchers_arr, 0, 0,
					watcher->watcher.s, watcher->watcher.len) < 0)
					goto error;
				watcher = watcher->next;
			}

			apps_arr = add_mi_array(resp_item, MI_SSTR("appearances"));
			if (!apps_arr)
				goto error;
			for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
				if (rec->call[i]) {
					call = rec->call[i];
					app_item = add_mi_object(apps_arr, NULL, 0);
					if (!app_item)
						goto error;

					if (add_mi_string(app_item, MI_SSTR("index"),
						call->appearance_index_str.s,
						call->appearance_index_str.len) < 0)
						goto error;

					if (add_mi_string(app_item, MI_SSTR("state"),
						app_state[call->call_state].s,
						app_state[call->call_state].len) < 0)
						goto error;

					if (add_mi_string(app_item, MI_SSTR("b2b_key"),
						call->b2bl_key.s, call->b2bl_key.len) < 0)
						goto error;

					if (add_mi_string(app_item, MI_SSTR("app_uri"),
						call->call_info_apperance_uri.s,
						call->call_info_apperance_uri.len) < 0)
						goto error;
				}
			}

			rec = rec->next;
		}
		lock_release(&b2b_sca_htable[index].lock);
	}

	return resp;

error:
	lock_release(&b2b_sca_htable[index].lock);
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return NULL;
}

