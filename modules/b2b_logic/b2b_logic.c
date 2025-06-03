/*
 * back-to-back logic module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 *  2010-11-02  new mi function: mi_b2b_list (Ovidiu Sas)
 *  2010-11-12  new cmd: b2b_bridge_request (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_uri.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../mem/mem.h"
#include "../../timer.h"
#include "../../pt.h"
#include "../../lib/csv.h"
#include "../../mod_fix.h"

#include "records.h"
#include "b2b_logic.h"
#include "b2b_load.h"
#include "b2bl_db.h"
#include "entity_storage.h"
#include "bridging.h"

#define TABLE_VERSION 5

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
static int fixup_init_flags(void** param);
static int fixup_reply_flags(void** param);
static int fixup_free_init_flags(void** param);
static int fixup_bridge_flags(void** param);
static int fixup_bridge_request_flags(void** param);
static int fixup_init_id(void** param);
static int fixup_check_avp(void** param);
static int fixup_route(void** param);
static int free_fixup_route(void** param);
static mi_response_t *mi_trigger_scenario(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_b2b_bridge_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_b2b_bridge_f(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_b2b_bridge_pmu(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_b2b_bridge_4(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_b2b_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_b2b_terminate_call(const mi_params_t *params,
								struct mi_handler *async_hdl);
static void b2bl_clean(unsigned int ticks, void* param);
void b2bl_term_entities_timer(unsigned int ticks, void* param);
static void b2bl_db_timer_update(unsigned int ticks, void* param);
static int init_entities_term_timer(void);

int b2bl_script_init_request(struct sip_msg *msg, str *id, struct b2b_params *init_params,
	void *req_routeid, void *reply_routeid);
int b2bl_server_new(struct sip_msg *msg, str *id, str *adv_contact,
	pv_spec_t *hnames, pv_spec_t *hvals);
int b2bl_client_new(struct sip_msg *msg, str *id, str *dest_uri, str *proxy,
	 str *from_dname, str *adv_contact, pv_spec_t *hnames, pv_spec_t *hvals);
int b2b_handle_reply(struct sip_msg* msg, unsigned int flags);
int b2b_pass_request(struct sip_msg *msg);
int b2b_delete_entity(struct sip_msg *msg);
int b2b_end_dlg_leg(struct sip_msg *msg);
int b2b_send_reply(struct sip_msg *msg, int *code, str *reason, str *headers, str *body);
int  b2bl_script_bridge_msg(struct sip_msg* msg, str *key, int *entity_no,
	str *adv_contact, void *flags);
int script_trigger_scenario(struct sip_msg* msg, str *id, str * params,
	str *ent1, pv_spec_t *ent1_hnames, pv_spec_t *ent1_hvals,
	str *ent2, pv_spec_t *ent2_hnames, pv_spec_t *ent2_hvals);	

str* b2bl_init_extern(struct b2b_params *init_params,
	b2bl_init_params_t *scen_params, str *e1_id, str *e2_id,
	b2bl_cback_f cbf, void* cb_param, unsigned int cb_mask);

int pv_get_b2bl_key(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_get_scenario(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_parse_entity_name(pv_spec_p sp, const str *in);
int pv_parse_entity_index(pv_spec_p sp, const str* in);
int pv_get_entity(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_parse_ctx_name(pv_spec_p sp, const str *in);
int pv_get_ctx(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
int pv_set_ctx(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val);

void b2b_mark_todel( b2bl_tuple_t* tuple);

/** Global variables */
b2b_api_t b2b_api;
b2bl_table_t b2bl_htable;
unsigned int b2bl_hsize = 10;
static char* script_req_route;
static char* script_reply_route;
struct script_route_ref *global_req_rt_ref  = NULL;
struct script_route_ref *global_reply_rt_ref = NULL;
unsigned int b2b_clean_period = 100;
unsigned int b2b_update_period = 100;
str custom_headers = {0, 0};
str custom_headers_lst[HDR_LST_LEN];
int custom_headers_lst_len =0;
str custom_headers_regexp = {0, 0};
regex_t* custom_headers_re;
/* The list of the headers that are passed on the other side by default */
static str default_headers[HDR_DEFAULT_LEN]=
{
   {"Max-Forwards",12},
   {"Content-Type",12},
   {"Supported", 9},
   {"Allow", 5},
   {"Proxy-Require", 13},
   {"Session-Expires", 15},
   {"Min-SE", 6},
   {"Require", 7},
   {"RSeq", 4},
};
int contact_user = 0;
unsigned int max_duration = 12*3600;

static str requestTimeout = str_init("Request Timeout");

int b2bl_key_avp_name;
unsigned short b2bl_key_avp_type;
static str b2bl_key_avp_param = {NULL, 0};

static str b2bl_from_spec_param = {NULL, 0};
static pv_spec_t b2bl_from_spec;
static pv_value_t b2bl_from_tok;
static struct to_body b2bl_from;

#define B2BL_FROM_BUF_LEN    255
static char b2bl_from_buf[B2BL_FROM_BUF_LEN + 1];

str db_url= {0, 0};
str cdb_url;
str cdb_key_prefix = str_init("b2bl$");
db_con_t *b2bl_db = NULL;
db_func_t b2bl_dbf;
str b2bl_dbtable= str_init("b2b_logic");
str init_callid_hdr={0, 0};

cachedb_funcs b2bl_cdbf;
cachedb_con *b2bl_cdb;

str server_address = {0, 0};
pv_elem_t *server_address_pve;
int b2b_early_update = 0;

int b2bl_db_mode = WRITE_BACK;
int unsigned b2bl_th_init_timeout = 60;

str b2bl_mod_name = str_init("b2b_logic");

str top_hiding_scen_s;
str internal_scen_s;

int new_ent_1_ctx_idx, new_ent_2_ctx_idx;

/* used to identify the current tuple in local_route, in the context of a request
 * that is not triggerd by a received message from an ongoing b2b dialog */
b2bl_tuple_t *local_ctx_tuple;

/* used to save context values set in the request route / b2b_trigger_scenario
 * MI cmd, when the tuple is not created yet */
struct b2b_ctx_val *local_ctx_vals;

unsigned int ent_term_interval;
struct b2b_term_timer *ent_term_timer;

static const cmd_export_t cmds[]=
{
	{"b2b_init_request", (cmd_function)b2bl_script_init_request, {
		{CMD_PARAM_STR, fixup_init_id, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL,
			fixup_init_flags, fixup_free_init_flags},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_route, free_fixup_route},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_route ,free_fixup_route}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_server_new", (cmd_function)b2bl_server_new, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_client_new", (cmd_function)b2bl_client_new, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_handle_reply",(cmd_function)b2b_handle_reply, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_reply_flags, NULL}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_pass_request",(cmd_function)b2b_pass_request, {{0,0,0}},
		REQUEST_ROUTE},
	{"b2b_delete_entity",(cmd_function)b2b_delete_entity, {{0,0,0}},
		REQUEST_ROUTE},
	{"b2b_end_dlg_leg",(cmd_function)b2b_end_dlg_leg, {{0,0,0}},
		REQUEST_ROUTE},
	{"b2b_send_reply",(cmd_function)b2b_send_reply, {
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{0,0,0}		
		},
		REQUEST_ROUTE},
	{"b2b_bridge", (cmd_function)b2b_script_bridge, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_FIX_NULL,
			fixup_bridge_flags, fixup_free_init_flags}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_bridge_retry", (cmd_function)b2b_script_bridge_retry, {
		{CMD_PARAM_STR,0,0},
		{0,0,0}},
		REQUEST_ROUTE},
	{"b2b_trigger_scenario", (cmd_function)script_trigger_scenario, {
		{CMD_PARAM_STR,fixup_init_id,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,
			0, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0},
		{0,0,0}},
		REQUEST_ROUTE},
	{"b2b_bridge_request", (cmd_function)b2bl_script_bridge_msg, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_bridge_request_flags, 0},
		{0,0,0}},
		REQUEST_ROUTE},
	{"b2b_logic_bind", (cmd_function)b2b_logic_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/** Exported parameters */
static const param_export_t params[]=
{
	{"hash_size",       INT_PARAM,                &b2bl_hsize                },
	{"cleanup_period",  INT_PARAM,                &b2b_clean_period          },
	{"update_period",   INT_PARAM,                &b2b_update_period         },
	{"script_req_route",      STR_PARAM,          &script_req_route          },
	{"script_reply_route",    STR_PARAM,          &script_reply_route        },
	{"custom_headers",  STR_PARAM,                &custom_headers.s          },
	{"custom_headers_regexp", STR_PARAM,          &custom_headers_regexp.s   },
	{"contact_user",    INT_PARAM,                &contact_user              },
	{"db_url",          STR_PARAM,                &db_url.s                  },
	{"cachedb_url",     STR_PARAM, 				  &cdb_url.s         		 },
	{"cachedb_key_prefix",    STR_PARAM, 	 	  &cdb_key_prefix.s  		 },
	{"db_table",        STR_PARAM,                &b2bl_dbtable.s            },
	{"max_duration",    INT_PARAM,                &max_duration              },
	/*
	{"b2bl_key_avp",    STR_PARAM,                &b2bl_key_avp_param.s      },
	*/
	{"b2bl_from_spec_param",STR_PARAM,            &b2bl_from_spec_param.s    },
	{"server_address",  STR_PARAM,                &server_address.s          },
	{"init_callid_hdr", STR_PARAM,                &init_callid_hdr.s         },
	{"db_mode",         INT_PARAM,                &b2bl_db_mode              },
	{"b2bl_th_init_timeout",INT_PARAM,            &b2bl_th_init_timeout      },
	{"b2bl_early_update",INT_PARAM,				  &b2b_early_update          },
	{"old_entity_term_delay",INT_PARAM,           &ent_term_interval         },
	{0,                    0,                          0                     }
};

static const pv_export_t mod_items[] = {
	{str_const_init("b2b_logic.key"), 1000, pv_get_b2bl_key,
		0, 0, 0, 0, 0},
	{str_const_init("b2b_logic.scenario"), 1000,
		pv_get_scenario, 0, 0, 0, 0, 0},
	{str_const_init("b2b_logic.entity"), 1000, pv_get_entity,
		0, pv_parse_entity_name, pv_parse_entity_index, 0, 0},
	{str_const_init("b2b_logic.ctx"), 1000, pv_get_ctx,
		pv_set_ctx, pv_parse_ctx_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static const mi_export_t mi_cmds[] = {
	{"b2b_trigger_scenario", 0, 0, 0, {
		{mi_trigger_scenario, {"scenario_id", "entity1", "entity2", 0}},
		{mi_trigger_scenario, {"scenario_id", "entity1", "entity2", "context", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"b2b_bridge", 0, 0, 0, {
		{mi_b2b_bridge_2,   {"dialog_id", "new_uri", 0}},
		{mi_b2b_bridge_f,   {"dialog_id", "new_uri", "flag", 0}},
		{mi_b2b_bridge_pmu, {"dialog_id", "new_uri", "prov_media_uri", 0}},
		{mi_b2b_bridge_4,   {"dialog_id", "new_uri", "flag", "prov_media_uri", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"b2b_list", 0, 0, 0, {
		{mi_b2b_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{"b2b_terminate_call", 0, 0, 0, {
		{mi_b2b_terminate_call,   {"key", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "b2b_entities", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url",           get_deps_sqldb_url  },
		{ NULL, NULL },
	},
};

/** Module interface */
struct module_exports exports= {
	"b2b_logic",                    /* module name */
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
	mod_items,                      /* exported pseudo-variables */
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
	char* p = NULL;
	char* flags = NULL;
	int regexp_flags = 0;
	int i = 0, j;
	pv_spec_t avp_spec;

	LM_DBG("start\n");

	/* load b2b_entities api */
	if(load_b2b_api(&b2b_api)< 0)
	{
		LM_ERR("Failed to load b2b api\n");
		return -1;
	}

	if(b2bl_hsize< 1 || b2bl_hsize> 20)
	{
		LM_ERR("Wrong hash size. Needs to be greater than 1"
				" and smaller than 20. Be aware that you should set the log 2"
				" value of the real size\n");
		return -1;
	}
	b2bl_hsize = 1<<b2bl_hsize;

	if (server_address.s)
	{
		server_address.len = strlen(server_address.s);
		if(pv_parse_format(&server_address, &server_address_pve) < 0)
		{
			LM_ERR("failed to parse server_address [%.*s]\n", server_address.len, server_address.s);
			return E_CFG;
		}
	}

	if (script_req_route) {
		global_req_rt_ref = ref_script_route_by_name(script_req_route,
			sroutes->request, RT_NO, REQUEST_ROUTE, 0);
		if (!ref_script_route_is_valid(global_req_rt_ref)) {
			LM_ERR("route <%s> does not exist\n", script_req_route);
			return -1;
		}
	}

	if (script_reply_route) {
		global_reply_rt_ref = ref_script_route_by_name(script_reply_route,
			sroutes->request, RT_NO, REQUEST_ROUTE, 0);
		if (!ref_script_route_is_valid(global_reply_rt_ref)) {
			LM_ERR("route <%s> does not exist\n",script_reply_route);
			return -1;
		}
	}

	if(init_b2bl_htable() < 0)
	{
		LM_ERR("Failed to initialize b2b logic hash table\n");
		return -1;
	}

	if(b2bl_db_mode) {
		if (!cdb_url.s) {
			init_db_url(db_url, 1);
			if (!db_url.s)
				b2bl_db_mode = NO_DB;
		} else if (db_url.s) {
			LM_ERR("Both 'db_url' and 'cachedb_url' defined\n");
			return -1;
		} else {
			cdb_url.len = strlen(cdb_url.s);
		}
	}

	if(b2bl_db_mode && db_url.s)
	{
		b2bl_dbtable.len = strlen(b2bl_dbtable.s);
		/* binding to database module  */
		if (db_bind_mod(&db_url, &b2bl_dbf))
		{
			LM_ERR("Database module not found\n");
			return -1;
		}

		if (!DB_CAPABILITY(b2bl_dbf, DB_CAP_ALL))
		{
			LM_ERR("Database module does not implement all functions"
					" needed by b2b_entities module\n");
			return -1;
		}
		b2bl_db = b2bl_dbf.init(&db_url);
		if(!b2bl_db)
		{
			LM_ERR("connecting to database failed\n");
			return -1;
		}

		/*verify table versions */
		if(db_check_table_version(&b2bl_dbf, b2bl_db, &b2bl_dbtable, TABLE_VERSION) < 0)
		{
			LM_ERR("error during table version check\n");
			return -1;
		}

		b2bl_db_init();

		/* reload data */
		if(b2b_logic_restore() < 0)
		{
			LM_ERR("Failed to restore data from database\n");
			return -1;
		}

		if(b2bl_db)
			b2bl_dbf.close(b2bl_db);
		b2bl_db = NULL;
	} else if (b2bl_db_mode && cdb_url.s) {
		if (cachedb_bind_mod(&cdb_url, &b2bl_cdbf) < 0) {
			LM_ERR("cannot bind functions for cachedb_url %.*s\n",
			       cdb_url.len, cdb_url.s);
			return -1;
		}

		if (!CACHEDB_CAPABILITY(&b2bl_cdbf, CACHEDB_CAP_MAP)) {
			LM_ERR("not enough capabilities for cachedb_url %.*s\n",
			       cdb_url.len, cdb_url.s);
			return -1;
		}

		b2bl_cdb = b2bl_cdbf.init(&cdb_url);
		if (!b2bl_cdb) {
			LM_ERR("connecting to database failed\n");
			return -1;
		}

		cdb_key_prefix.len = strlen(cdb_key_prefix.s);

		b2bl_db_init();

		/* reload data */
		if(b2b_logic_restore() < 0)
		{
			LM_ERR("Failed to restore data from database\n");
			return -1;
		}

		if(b2bl_cdb)
			b2bl_cdbf.destroy(b2bl_cdb);
		b2bl_cdb = NULL;
	}

	if (b2bl_key_avp_param.s)
		b2bl_key_avp_param.len = strlen(b2bl_key_avp_param.s);

	if (b2bl_key_avp_param.s && b2bl_key_avp_param.len > 0)
	{
		if (pv_parse_spec(&b2bl_key_avp_param, &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %.*s AVP definition\n",
				b2bl_key_avp_param.len, b2bl_key_avp_param.s);
			return -1;
		}
		if (pv_get_avp_name(0, &(avp_spec.pvp), &b2bl_key_avp_name, &b2bl_key_avp_type)!=0){
			LM_ERR("[%.*s]- invalid AVP definition\n", b2bl_key_avp_param.len,
					b2bl_key_avp_param.s);
			return -1;
		}
	} else {
		b2bl_key_avp_name = -1;
		b2bl_key_avp_type = 0;
	}

	if(b2bl_from_spec_param.s)
	{
		b2bl_from_spec_param.len = strlen(b2bl_from_spec_param.s);
		if(pv_parse_spec(&b2bl_from_spec_param, &b2bl_from_spec)==NULL)
		{
			LM_ERR("failed to parse b2bl_from spec\n");
			return E_CFG;
		}
		switch(b2bl_from_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid b2bl_from spec\n");
				return -1;
			default: ;
		}
	}

	/* parse extra headers */
	if(custom_headers.s)
		custom_headers.len = strlen(custom_headers.s);

	memset(custom_headers_lst, 0, HDR_LST_LEN*sizeof(str));
	custom_headers_lst[i].s = custom_headers.s;
	if(custom_headers.s)
	{
		p = strchr(custom_headers.s, ';');
		while(p)
		{
			custom_headers_lst[i].len = p - custom_headers_lst[i].s;
			/* check if this is among the default headers */
			for(j = 0; j< HDR_DEFAULT_LEN; j++)
			{
				if(custom_headers_lst[i].len == default_headers[j].len &&
						strncmp(custom_headers_lst[i].s, default_headers[j].s,
							default_headers[j].len)== 0)
					goto next_hdr;
			}
			/* check if defined twice */
			for(j = 0; j< i; j++)
			{
				if(custom_headers_lst[i].len == custom_headers_lst[j].len &&
						strncmp(custom_headers_lst[i].s, custom_headers_lst[j].s,
							custom_headers_lst[j].len)== 0)
					goto next_hdr;
			}
			i++;
			if(i == HDR_LST_LEN)
			{
				LM_ERR("Too many extra headers defined."
						" The maximum value is %d\n.", HDR_LST_LEN);
				return -1;
			}
next_hdr:
			p++;
			if(p-custom_headers.s >= custom_headers.len)
				break;
			custom_headers_lst[i].s = p;
			p = strchr(p, ';');
		}
	}

	if(p == NULL)
	{
		custom_headers_lst[i].len = custom_headers.s + custom_headers.len
			- custom_headers_lst[i].s;
		if(custom_headers_lst[i].len == 0)
			i--;
	}
	custom_headers_lst_len = i +1;

	if(custom_headers_regexp.s)
	{
		custom_headers_regexp.len = strlen(custom_headers_regexp.s);
		if ((custom_headers_re=pkg_malloc(sizeof(regex_t)))==0) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		if (*custom_headers_regexp.s == '/')
		{
			flags = (char *)memchr(custom_headers_regexp.s+1, '/',
				custom_headers_regexp.len-1);
			if (flags)
			{
				custom_headers_regexp.s++;
				custom_headers_regexp.len = flags - custom_headers_regexp.s;
				custom_headers_regexp.s[custom_headers_regexp.len] = '\0';
				flags++;
				while(*flags != '\0')
				{
					switch (*flags) {
						case 'i':
							regexp_flags |= REG_ICASE;
							break;
						case 'e':
							regexp_flags |= REG_EXTENDED;
							break;
						default:
							LM_ERR("Unknown option '%c'\n", *flags);
					}
					flags++;
				}
			} else {
				LM_ERR("Second '/' missing from regexp\n");
				return -1;
			}
		}
		if (regcomp(custom_headers_re, custom_headers_regexp.s,
		regexp_flags) != 0) {
			pkg_free(custom_headers_re);
			LM_ERR("bad regexp '%.*s'\n",
				custom_headers_regexp.len, custom_headers_regexp.s);
			return -1;
		}
	}

	if(init_callid_hdr.s)
		init_callid_hdr.len = strlen(init_callid_hdr.s);

	if (b2bl_init_bridge_retry() < 0) {
		LM_ERR("cannot initiate bridge retry!\n");
		return -1;
	}

	register_timer("b2bl-clean", b2bl_clean, 0, b2b_clean_period,
		TIMER_FLAG_DELAY_ON_DELAY);
	if(b2bl_db_mode == WRITE_BACK)
		register_timer("b2bl-dbupdate", b2bl_db_timer_update, 0,
			b2b_update_period, TIMER_FLAG_SKIP_ON_DELAY);
	register_timer("b2bl-bridge-retry", b2bl_timer_bridge_retry, 0, 1,
		TIMER_FLAG_SKIP_ON_DELAY);

	if (ent_term_interval) {
		register_timer("b2bl-term-entities", b2bl_term_entities_timer, 0, 1,
			TIMER_FLAG_DELAY_ON_DELAY);

		if (init_entities_term_timer() < 0) {
			LM_ERR("Failed to init entities termination timer\n");
			return -1;
		}
	}

	if (b2b_api.register_cb(entity_event_trigger,
		B2BCB_TRIGGER_EVENT, &b2bl_mod_name) < 0) {
		LM_ERR("could not register entity event trigger callback!\n");
		return -1;
	}
	if (b2b_api.register_cb(entity_event_received,
		B2BCB_RECV_EVENT, &b2bl_mod_name) < 0) {
		LM_ERR("could not register entity event received callback!\n");
		return -1;
	}

	new_ent_1_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, new_ent_ctx_destroy);
	new_ent_2_ctx_idx = context_register_ptr(CONTEXT_GLOBAL, new_ent_ctx_destroy);

	return 0;
}

static int init_entities_term_timer(void)
{
	ent_term_timer = shm_malloc(sizeof *ent_term_timer);
	if (!ent_term_timer) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(ent_term_timer, 0, sizeof *ent_term_timer);

	ent_term_timer->lock = lock_alloc();
	if (ent_term_timer->lock==0) {
		LM_ERR("failed to alloc lock\n");
		return -1;
	}

	if (lock_init(ent_term_timer->lock)==0) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	return 0;
}

void b2bl_db_timer_update(unsigned int ticks, void* param)
{
	b2b_logic_dump(0);
}

static void term_entity(b2bl_entity_id_t *entity, int hash_index, str *key)
{
	str bye = {BYE, BYE_LEN};
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	struct b2b_context *ctx;

	if (entity->type == B2B_SERVER &&
		entity->state != B2BL_ENT_CONFIRMED) {
		memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
		PREP_RPL_DATA(entity);
		rpl_data.method = METHOD_INVITE;
		rpl_data.body = NULL;

		if (entity->state == B2BL_ENT_CANCELING) {
			rpl_data.code = 487;
			rpl_data.text = &requestTerminated;
		} else {
			rpl_data.code = 408;
			rpl_data.text = &requestTimeout;
		}

		if(b2b_api.send_reply(&rpl_data) < 0)
			LM_ERR("Sending reply failed - %d, [%.*s]\n",
				rpl_data.code, entity->key.len,
				entity->key.s);
	} else {
		if ( key && ( !push_new_global_context() ||
		(ctx=b2b_api.get_context())==NULL ||
		pkg_str_dup(&ctx->b2bl_key, key)!=0 )
		) {
			LM_ERR("preparing ctx for request failed, entity [%.*s]\n",
				entity->key.len, entity->key.s);
		} else {
			memset(&req_data, 0, sizeof(b2b_req_data_t));
			PREP_REQ_DATA(entity);
			req_data.method =&bye;
			b2b_api.send_request(&req_data);
			if (key)
				pop_pushed_global_context();
		}
	}
}

void b2bl_clean(unsigned int ticks, void* param)
{
	int i;
	b2bl_tuple_t* tuple, *tuple_next;
	unsigned int now;

	now = get_ticks();

	for(i = 0; i< b2bl_hsize; i++)
	{
		B2BL_LOCK_GET(i);
		tuple = b2bl_htable[i].first;
		while(tuple)
		{
			tuple_next = tuple->next;
			if(tuple->lifetime > 0 && tuple->lifetime < now)
			{
				LM_INFO("Found expired tuple [%.*s]: delete and send BYEs\n",
					tuple->key->len, tuple->key->s);
				if(tuple->bridge_entities[0] && tuple->bridge_entities[1] && !tuple->to_del)
				{
					if(!tuple->bridge_entities[0]->disconnected)
						term_entity(tuple->bridge_entities[0], i, tuple->key);

					if(!tuple->bridge_entities[1]->disconnected)
						term_entity(tuple->bridge_entities[1], i, tuple->key);
				}
				b2bl_delete(tuple, i, 1, tuple->repl_flag != TUPLE_REPL_RECV);
			}
			tuple = tuple_next;
		}
		B2BL_LOCK_RELEASE(i);
	}
}

void destroy_entities_term_timer(void)
{
	if (ent_term_timer==0)
		return;

	lock_destroy(ent_term_timer->lock);
	lock_dealloc(ent_term_timer->lock);

	shm_free(ent_term_timer);
	ent_term_timer = 0;
}

static void mod_destroy(void)
{
	if (b2bl_db_mode==WRITE_BACK) {
		if (b2bl_dbf.init) {

			b2bl_db = b2bl_dbf.init(&db_url);
			if(!b2bl_db)
			{
				LM_ERR("connecting to database failed\n");
			} else {
				b2b_logic_dump(1);
				b2bl_dbf.close(b2bl_db);
			}
		} else if (b2bl_cdbf.init) {
			b2bl_cdb = b2bl_cdbf.init(&cdb_url);
			if (!b2bl_cdb) {
				LM_ERR("connecting to database failed\n");
			} else {
				b2b_logic_dump(1);
				b2bl_cdbf.destroy(b2bl_cdb);
			}
		}
	}

	if (server_address_pve)
		pv_elem_free_all(server_address_pve);

	if (ent_term_interval)
		destroy_entities_term_timer();

	destroy_b2bl_htable();
	b2bl_free_bridge_retry();
}

static int child_init(int rank)
{
	if (b2bl_db_mode==0)
		return 0;

	if (db_url.s) {
		if (b2bl_dbf.init==0)
		{
			LM_CRIT("child_init: database not bound\n");
			return -1;
		}

		b2bl_db = b2bl_dbf.init(&db_url);
		if(!b2bl_db)
		{
			LM_ERR("connecting to database failed\n");
			return -1;
		}
		LM_DBG("child %d: Database connection opened successfully\n", rank);
	} else {
		if (!b2bl_cdbf.init) {
			LM_ERR("cachedb functions not initialized\n");
			return -1;
		}

		b2bl_cdb = b2bl_cdbf.init(&cdb_url);
		if (!b2bl_cdb) {
			LM_ERR("connecting to database failed\n");
			return -1;
		}

		LM_DBG("child %d: cachedb connection opened successfully\n", rank);
	}

	return 0;
}

static str init_request_flags[] =
{
	str_init("transparent-auth"), /* B2BL_FLAG_TRANSPARENT_AUTH */
	str_init("preserve-to"),      /* B2BL_FLAG_TRANSPARENT_TO */
	STR_NULL
};
static str init_request_kv_flags[] =
{
	str_init("setup-timeout"),
	STR_NULL
};

static int fixup_init_flags(void** param)
{
	str *s = (str*)*param;
	struct b2b_params *init_params;
	str flag_vals[1];

	init_params = pkg_malloc(sizeof	*init_params);
	if (!init_params) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memset(init_params, 0, sizeof *init_params);

	init_params->init_timeout = b2bl_th_init_timeout;

	if (!s) {
		*param = (void*)init_params;
		return 0;
	}

	if (fixup_named_flags(param, init_request_flags, init_request_kv_flags,
		flag_vals) < 0) {
		LM_ERR("Failed to parse flags\n");
		return -1;
	}

	init_params->flags = (unsigned int)(unsigned long)(void*)*param;
	*param = (void*)init_params;

	if (flag_vals[0].s) {
		if (str2int(&flag_vals[0], &init_params->init_timeout) < 0) {
			LM_ERR("timeout is not an integer\n");
			return -1;
		}
	}

	return 0;
}

static str reply_flags[] =
{
	str_init("pass-3xx-contact"),	/* B2BL_RPL_FLAG_PASS_CONTACT */
	STR_NULL
};

static int fixup_reply_flags(void** param)
{
	return fixup_named_flags(param, reply_flags, NULL, NULL);
}

static int fixup_free_init_flags(void** param)
{
	if (*param)
		pkg_free(*param);

	return 0;
}

static str bridge_flags[] =
{
	str_init("notify"),          /* B2BL_BR_FLAG_NOTIFY */
	str_init("rollback-failed"), /* B2BL_BR_FLAG_RETURN_AFTER_FAILURE */
	str_init("hold"),            /* B2BL_BR_FLAG_HOLD */
	str_init("no-late-sdp"),     /* B2BL_BR_FLAG_RENEW_SDP */
	STR_NULL
};
static str bridge_kv_flags[] =
{
	str_init("max_duration"),
	STR_NULL
};

static int fixup_bridge_flags(void** param)
{
	str *s = (str*)*param;
	struct b2b_bridge_params *bridge_params;
	str flag_vals[1];

	bridge_params = pkg_malloc(sizeof *bridge_params);
	if (!bridge_params) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memset(bridge_params, 0, sizeof *bridge_params);

	if (!s) {
		*param = (void*)bridge_params;
		return 0;
	}

	if (fixup_named_flags(param, bridge_flags, bridge_kv_flags, flag_vals) < 0) {
		LM_ERR("Failed to parse flags\n");
		return -1;
	}

	bridge_params->flags = (unsigned int)(unsigned long)(void*)*param;
	*param = (void*)bridge_params;

	if (flag_vals[0].s) {
		if (str2int(&flag_vals[0], &bridge_params->lifetime) < 0) {
			LM_ERR("duration is not an integer\n");
			return -1;
		}
	}

	return 0;
}


static str bridge_req_kv_flags[] =
{
	str_init("late_bye"),
	STR_NULL
};

static int fixup_bridge_request_flags(void** param)
{
	if (fixup_named_flags(param, bridge_req_kv_flags, NULL, NULL)<0) {
		LM_ERR("Failed to parse flags\n");
		return -1;
	}

	/* ugly hack to move the flag on its right position (as the 
	   fixup_named_flags() will set it with index 0 (as in the def array))
	   WARNING: this works only because we have a single flag!!!! */
	if (param)
		*param = (void*)(unsigned long)B2BL_BR_FLAG_BR_MSG_LATE_BYE;

	return 0;
}

static int fixup_init_id(void** param)
{
	str *s = (str*)*param;

	if (s->len == B2B_TOP_HIDING_SCENARY_LEN &&
		!memcmp(B2B_TOP_HIDING_SCENARY, s->s, s->len))
		*param = B2B_TOP_HIDING_ID_PTR;

	return 0;
}

static int fixup_route(void** param)
{
	struct script_route_ref *rt;

	rt = ref_script_route_by_name_str( (str*)*param,
			sroutes->request, RT_NO, REQUEST_ROUTE, 0);
	if ( !ref_script_route_is_valid(rt) ) {
		LM_ERR("route <%.*s> does not exist\n",
			((str*)*param)->len, ((str*)*param)->s);
		return -1;
	}

	*param = (void*)rt;

	return 0;
}


static int free_fixup_route(void** param)
{
	if (*param)
		unref_script_route( (struct script_route_ref *)*param );
	return 0;
}


static int fixup_check_avp(void** param)
{
	if (((pv_spec_t *)*param)->type!=PVT_AVP) {
		LM_ERR("return parameter must be an AVP\n");
		return E_SCRIPT;
	}

	return 0;
}

struct to_body* get_b2bl_from(struct sip_msg* msg)
{
	int len = 0;

	if(b2bl_from_spec_param.s)
	{
		memset(&b2bl_from_tok, 0, sizeof(pv_value_t));
		if(pv_get_spec_value(msg, &b2bl_from_spec, &b2bl_from_tok) < 0)
		{
			LM_ERR("Failed to get b2bl_from value\n");
			return NULL;
		}
		//LM_DBG("got b2bl_from_spec_param flags [%d]\n", b2bl_from_tok.flags);
		if(b2bl_from_tok.flags&PV_VAL_INT)
		{
			/* the PV might be empty */
			return NULL;
		}
		if(b2bl_from_tok.flags&PV_VAL_STR)
		{
			//LM_DBG("got PV_SPEC b2bl_from [%.*s]\n",
			//	b2bl_from_tok.rs.len, b2bl_from_tok.rs.s);
			if(b2bl_from_tok.rs.len+CRLF_LEN > B2BL_FROM_BUF_LEN) {
				LM_ERR("Buffer overflow\n");
				return NULL;
			}
			trim(&b2bl_from_tok.rs);
			memcpy(b2bl_from_buf, b2bl_from_tok.rs.s,
				b2bl_from_tok.rs.len);
			len = b2bl_from_tok.rs.len;
			if(strncmp(b2bl_from_tok.rs.s + len - CRLF_LEN, CRLF, CRLF_LEN)) {
				memcpy(b2bl_from_buf + len, CRLF, CRLF_LEN);
				len+= CRLF_LEN;
			}

			parse_to(b2bl_from_buf, b2bl_from_buf+len,
				&b2bl_from);
			if (b2bl_from.error != PARSE_OK) {
				LM_ERR("Failed to parse PV_SPEC b2bl_from [%.*s]\n",
					len, b2bl_from_buf);
				return NULL;
			}
			if (parse_uri(b2bl_from.uri.s, b2bl_from.uri.len,
					&b2bl_from.parsed_uri)<0) {
				LM_ERR("failed to parse PV_SPEC b2bl_from uri [%.*s]\n",
					b2bl_from.uri.len, b2bl_from.uri.s);
				return NULL;
			}

			/* side effect of parsing - nobody should need them later on,
			 * so free them right now */
			free_to_params(&b2bl_from);
			return &b2bl_from;
		}
	}

	return NULL;
}

mi_response_t *mi_trigger_scenario(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str scenario_id;
	str entity1_str, entity2_str;
	csv_record *list1 = NULL, *list2 = NULL;
	str *s;
	str *e1_id, *e2_id;
	struct b2b_params init_params;
	b2bl_init_params_t scen_params;
	mi_item_t *ctx_arr;
	int n;
	str ctx_kv_s;
	str ctx_k, ctx_v;
	mi_response_t *resp;
	int i;

	if (get_mi_string_param(params, "scenario_id",
		&scenario_id.s, &scenario_id.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "entity1",
		&entity1_str.s, &entity1_str.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "entity2",
		&entity2_str.s, &entity2_str.len) < 0)
		return init_mi_param_error();

	memset(&init_params, 0, sizeof init_params);
	init_params.id = &scenario_id;
	init_params.req_route = global_req_rt_ref;
	init_params.reply_route = global_reply_rt_ref;

	memset(&scen_params, 0, sizeof scen_params);
	scen_params.e1_type = B2B_CLIENT;
	scen_params.e2_type = B2B_CLIENT;

	list1 = parse_csv_record(&entity1_str);
	if (!list1) {
		LM_ERR("Failed to parse CSV record\n");
		resp = init_mi_error(400, MI_SSTR("Bad format for entity1"));
		goto end;
	}

	s = &list1->s;
	if (!s->s || !s->len) {
		resp = init_mi_error(400, MI_SSTR("Missing ID for entity1"));
		goto end;
	}
	e1_id = s;

	s = list1->next ? &list1->next->s : NULL;
	if (!s || !s->s || !s->len) {
		resp = init_mi_error(400, MI_SSTR("Missing destination URI for entity1"));
		goto end;
	}
	scen_params.e1_to = *s;

	s = list1->next->next ? &list1->next->next->s : NULL;
	if (s && s->s && s->len)
		scen_params.e1_from_dname = *s;

	list2 = parse_csv_record(&entity2_str);
	if (!list2) {
		LM_ERR("Failed to parse CSV record\n");
		resp = init_mi_error(400, MI_SSTR("Bad format for entity2"));
		goto end;
	}

	s = &list2->s;
	if (!s->s || !s->len) {
		resp = init_mi_error(400, MI_SSTR("Missing ID for entity2"));
		goto end;
	}
	e2_id = s;

	s = list2->next ? &list2->next->s : NULL;
	if (!s || !s->s || !s->len) {
		resp = init_mi_error(400, MI_SSTR("Missing destination URI for entity2"));
		goto end;
	}
	scen_params.e2_to = *s;

	s = list2->next->next ? &list2->next->next->s : NULL;
	if (s && s->s && s->len)
		scen_params.e2_from_dname = *s;

	if (try_get_mi_array_param(params, "context", &ctx_arr, &n) == 0)
		for (i = 0; i < n; i++) {
			if (get_mi_arr_param_string(ctx_arr, i,
				&ctx_kv_s.s, &ctx_kv_s.len) < 0) {
				resp = init_mi_param_error();
				goto end;
			}

			ctx_k.s = ctx_kv_s.s;
			ctx_v.s = q_memchr(ctx_kv_s.s, '=', ctx_kv_s.len);
			if (!ctx_v.s) {
				resp = init_mi_error(400, MI_SSTR("Bad format for context value"));
				goto end;
			}
			ctx_k.len = ctx_v.s - ctx_k.s;
			ctx_v.s++;
			ctx_v.len = ctx_kv_s.len - ctx_k.len - 1;

			if (store_ctx_value(&local_ctx_vals, &ctx_k, &ctx_v) < 0) {
				LM_ERR("Failed to store context value [%.*s]\n",
					ctx_k.len, ctx_k.s);
				resp = init_mi_error(500, MI_SSTR("Failed to store context value"));
				goto end;
			}
		}

	if (b2bl_init_extern(&init_params, &scen_params, e1_id, e2_id,
		0, 0, 0) == NULL) {
		resp = init_mi_error(500, MI_SSTR("Failed to initialize scenario"));
		goto end;
	}

	resp = init_mi_result_ok();
end:
	if (list1)
		free_csv_record(list1);
	if (list2)
		free_csv_record(list2);

	return resp;
}

int  b2bl_script_bridge_msg(struct sip_msg* msg, str *key, int *entity_no,
	str *adv_contact, void *flags_p)
{
	unsigned int flags = 0;

	if (cur_route_ctx.flags & (B2BL_RT_REQ_CTX|B2BL_RT_RPL_CTX)) {
		LM_ERR("The 'b2b_bridge_request' function cannot be used from the "
			"b2b_logic dedicated routes\n");
		return -1;
	}

	if (flags_p)
		flags = (unsigned int)(unsigned long)flags_p;

	return b2bl_bridge_msg(msg, key, *entity_no, flags, adv_contact);
}

static int b2bl_api_bridge_msg(struct sip_msg* msg, str* key, int entity_no)
{
	return b2bl_bridge_msg(msg, key, entity_no, 0, NULL);
}

static mi_response_t *mi_b2b_terminate_call(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str key;
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();

	if (b2bl_get_tuple_key(&key, &hash_index, &local_index) < 0)
		return init_mi_error(404, MI_SSTR("B2B session not found"));

	B2BL_LOCK_GET(hash_index);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		B2BL_LOCK_RELEASE(hash_index);
		return init_mi_error(404, MI_SSTR("B2B session not found"));
	}

	if(tuple->bridge_entities[0] && tuple->bridge_entities[1] && !tuple->to_del)
	{
		if(!tuple->bridge_entities[0]->disconnected) {
			term_entity(tuple->bridge_entities[0], hash_index, &key);
			tuple->bridge_entities[0]->disconnected = 1;
		}

		if(!tuple->bridge_entities[1]->disconnected) {
			term_entity(tuple->bridge_entities[1], hash_index, &key);
			tuple->bridge_entities[1]->disconnected = 1;
		}
	}
	b2b_mark_todel(tuple);

	B2BL_LOCK_RELEASE(hash_index);

	return init_mi_result_ok();
}

static mi_response_t *mi_b2b_bridge_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_b2b_bridge(params, 0, NULL);
}

static mi_response_t *mi_b2b_bridge_f(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int flag;

	if (get_mi_int_param(params, "flag", &flag) < 0)
		return init_mi_param_error();

	return mi_b2b_bridge(params, flag, NULL);
}

static mi_response_t *mi_b2b_bridge_pmu(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str prov_media;

	if (get_mi_string_param(params, "prov_media_uri",
		&prov_media.s, &prov_media.len) < 0)
		return init_mi_param_error();

	return mi_b2b_bridge(params, 0, &prov_media);
}

static mi_response_t *mi_b2b_bridge_4(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int flag;
	str prov_media;

	if (get_mi_int_param(params, "flag", &flag) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "prov_media_uri",
		&prov_media.s, &prov_media.len) < 0)
		return init_mi_param_error();

	return mi_b2b_bridge(params, flag, &prov_media);
}

static inline int internal_mi_print_b2bl_entity_id(mi_item_t *item, b2bl_entity_id_t *c)
{
	if (c->scenario_id.s && c->scenario_id.len != 0)
		if (add_mi_string(item, MI_SSTR("scenario_id"),
			c->scenario_id.s, c->scenario_id.len) < 0)
			goto error;

	if (c->key.s && c->key.len != 0)
		if (add_mi_string(item, MI_SSTR("key"),
			c->key.s, c->key.len) < 0)
			goto error;

	if (add_mi_number(item, MI_SSTR("disconnected"),
		c->disconnected) < 0)
		goto error;
	if (add_mi_number(item, MI_SSTR("state"),
		c->state) < 0)
		goto error;
	if (add_mi_number(item, MI_SSTR("no"),
		c->no) < 0)
		goto error;
	if (add_mi_number(item, MI_SSTR("type"),
		c->type) < 0)
		goto error;

	if (c->peer)
	{
		if (c->peer->key.s && c->peer->key.len != 0)
			if (add_mi_string(item, MI_SSTR("peer"),
				c->peer->key.s, c->peer->key.len) < 0)
				goto error;
	}

	if (c->to_uri.s && c->to_uri.len != 0)
		if (add_mi_string(item, MI_SSTR("to_uri"),
			c->to_uri.s, c->to_uri.len) < 0)
			goto error;

	if (c->from_uri.s && c->from_uri.len != 0)
		if (add_mi_string(item, MI_SSTR("from_uri"),
			c->from_uri.s, c->from_uri.len) < 0)
			goto error;

	if (c->from_dname.s && c->from_dname.len != 0)
		if (add_mi_string(item, MI_SSTR("from_dname"),
			c->from_dname.s, c->from_dname.len) < 0)
			goto error;

	return 0;

error:
	LM_ERR("failed to add mi item\n");
	return -1;
}

static mi_response_t *mi_b2b_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int i, index;
	b2bl_tuple_t* tuple;

	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *tuples_arr, *tuple_item;
	mi_item_t *servers_arr, *server_item;
	mi_item_t *clients_arr, *clients_item;
	mi_item_t *b_entities_arr, *b_entities_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	tuples_arr = add_mi_array(resp_obj, MI_SSTR("Tuples"));
	if (!tuples_arr) {
		free_mi_response(resp);
		return 0;
	}

	for(i = 0; i< b2bl_hsize; i++)
	{
		B2BL_LOCK_GET(i);
		tuple = b2bl_htable[i].first;
		while(tuple)
		{
			tuple_item = add_mi_object(tuples_arr, NULL, 0);
			if (!tuple_item)
				goto error;

			if (add_mi_number(tuple_item, MI_SSTR("id"), tuple->id) < 0)
				goto error;
			if (add_mi_string(tuple_item, MI_SSTR("key"),
				tuple->key->s, tuple->key->len) < 0)
				goto error;
			if (add_mi_number(tuple_item, MI_SSTR("state"),
				tuple->state) < 0)
				goto error;
			if (add_mi_number(tuple_item, MI_SSTR("lifetime"),
				tuple->lifetime) < 0)
				goto error;
			if (add_mi_number(tuple_item, MI_SSTR("db_flag"),
				tuple->db_flag) < 0)
				goto error;

			if (tuple->scenario_id == B2B_TOP_HIDING_ID_PTR) {
				if (add_mi_string(tuple_item, MI_SSTR("scenario"),
					B2B_TOP_HIDING_SCENARY, B2B_TOP_HIDING_SCENARY_LEN) < 0)
					goto error;
			} else if (tuple->scenario_id != B2B_INTERNAL_ID_PTR) {
				if (add_mi_string(tuple_item, MI_SSTR("scenario"),
					tuple->scenario_id->s, tuple->scenario_id->len) < 0)
					goto error;
			}

			servers_arr = add_mi_array(tuple_item, MI_SSTR("SERVERS"));
			if (!servers_arr)
				goto error;
			for (index=0; index < MAX_B2BL_ENT; index++)
			{
				if (tuple->servers[index] != NULL)
				{
					server_item = add_mi_object(servers_arr, NULL, 0);
					if (!server_item)
						goto error;

					if (add_mi_number(server_item, MI_SSTR("index"), index) < 0)
						goto error;
					if (internal_mi_print_b2bl_entity_id(server_item,
							tuple->servers[index])!=0)
						goto error;
				}
			}

			clients_arr = add_mi_array(tuple_item, MI_SSTR("CLIENTS"));
			if (!clients_arr)
				goto error;
			for (index=0; index < MAX_B2BL_ENT; index++)
			{
				if (tuple->clients[index] != NULL)
				{
					clients_item = add_mi_object(clients_arr, NULL, 0);
					if (!clients_item)
						goto error;

					if (add_mi_number(clients_item, MI_SSTR("index"), index) < 0)
						goto error;
					if (internal_mi_print_b2bl_entity_id(clients_item,
							tuple->clients[index])!=0)
						goto error;
				}
			}

			b_entities_arr = add_mi_array(tuple_item, MI_SSTR("BRIDGE_ENTITIES"));
			if (!b_entities_arr)
				goto error;
			for (index=0; index < MAX_BRIDGE_ENT; index++)
			{
				if (tuple->bridge_entities[index] != NULL)
				{
					b_entities_item = add_mi_object(b_entities_arr, NULL, 0);
					if (!b_entities_item)
						goto error;

					if (add_mi_number(b_entities_item, MI_SSTR("index"), index) < 0)
						goto error;
					if (internal_mi_print_b2bl_entity_id(b_entities_item,
							tuple->bridge_entities[index])!=0)
						goto error;
				}
			}
			tuple = tuple->next;
		}
		B2BL_LOCK_RELEASE(i);
	}

	return resp;
error:
	B2BL_LOCK_RELEASE(i);
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return NULL;
}

static b2bl_tuple_t *ctx_search_tuple(struct b2b_context *ctx, int *locked)
{
	b2bl_tuple_t *tuple;

	*locked = 1;
	B2BL_LOCK_GET_AUX(ctx->hash_index);

	tuple = b2bl_search_tuple_safe(ctx->hash_index, ctx->local_index);
	if (!tuple) {
		LM_ERR("Tuple [%u, %u] not found\n", ctx->hash_index, ctx->local_index);
		B2BL_LOCK_RELEASE_AUX(ctx->hash_index);
		*locked = 0;
		return NULL;
	}

	return tuple;
}

/* get current tuple from the b2b_etities context */
b2bl_tuple_t *get_entities_ctx_tuple(struct b2b_context *ctx, int *locked)
{
	b2bl_tuple_t *tuple;

	if (!ctx->init) {
		/* find tuple based on the tuple key from the b2b_etities context */
		if (b2bl_parse_key(&ctx->b2bl_key,
			&ctx->hash_index, &ctx->local_index) < 0) {
			LM_ERR("Failed to parse key [%.*s]\n", ctx->b2bl_key.len,
				ctx->b2bl_key.s);
			return NULL;
		}

		tuple = ctx_search_tuple(ctx, locked);
		if (tuple)
			ctx->init = 1;
	} else {
		tuple = ctx_search_tuple(ctx, locked);
	}

	return tuple;
}

b2bl_tuple_t *get_ctx_tuple(int *locked)
{
	b2bl_tuple_t *tuple;
	struct b2b_context *ctx;

	if (!local_ctx_tuple) {
		ctx = b2b_api.get_context();
		if (!ctx) {
			LM_ERR("Failed to get b2b_entities context\n");
			return NULL;
		}

		if (!ctx->b2bl_key.s) {
			LM_DBG("b2b_logic key not set in b2b_entities context\n");
			/* we are in the context of a received message that doesn't
			 * belonging to an ongoing b2b dialog (yet) */
			if (!ctx->init)
				return NULL;
			else
				return ctx_search_tuple(ctx, locked);
		}

		tuple = get_entities_ctx_tuple(ctx, locked);
		if (!tuple) {
			LM_ERR("Failed to get tuple [%.*s] from b2b context\n",
				ctx->b2bl_key.len, ctx->b2bl_key.s);
			return NULL;
		}
	} else {
		/* we are in local route, in the context of a request that is not
		 * triggerd by a received message from an ongoing b2b dialog */
		tuple = local_ctx_tuple;
	}

	return tuple;
}

int pv_get_b2bl_key(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	b2bl_tuple_t *tuple;
	int locked = 0;

	tuple = get_ctx_tuple(&locked);
	if (!tuple) {
		LM_DBG("Unable to get the tuple from the current context\n");
		return pv_get_null(msg, param, res);
	}

	res->flags = PV_VAL_STR;
	res->rs = *tuple->key;

	if (locked)
		B2BL_LOCK_RELEASE_AUX(tuple->hash_index);

	return 0;
}

int pv_get_scenario(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	b2bl_tuple_t *tuple;
	int locked = 0;

	tuple = get_ctx_tuple(&locked);
	if (!tuple) {
		LM_DBG("Unable to get the tuple from the current context\n");
		return pv_get_null(msg, param, res);
	}

	res->flags = PV_VAL_STR;
	res->rs = *tuple->scenario_id;

	if (locked)
		B2BL_LOCK_RELEASE_AUX(tuple->hash_index);

	return 0;
}

int pv_parse_entity_name(pv_spec_p sp, const str *in)
{
	if (!in || !in->s || !in->len) {
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_KEY;
		return 0;
	}

	if (!str_strcmp(in, const_str("key")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_KEY;
	else if (!str_strcmp(in, const_str("callid")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_CALLID;
	else if (!str_strcmp(in, const_str("id")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_ID;
	else if (!str_strcmp(in, const_str("fromtag")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITIY_FROMTAG;
	else if (!str_strcmp(in, const_str("totag")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITIY_TOTAG;		
	else {
		LM_ERR("Bad subname for $b2b_logic.entity\n");
		return -1;
	}

	return 0;
}

int pv_parse_entity_index(pv_spec_p sp, const str* in)
{
	int idx;

	if (!in || !in->s || !in->len) {
		LM_ERR("No index provided for $b2b_logic.entity\n");
		return -1;
	}
	if (!sp) {
		LM_ERR("Bad pv spec for $b2b_logic.entity\n");
		return -1;
	}

	if (str2sint(in, &idx) < 0) {
		LM_ERR("Bad index! not a number! <%.*s>!\n", in->len, in->s);
		return -1;
	}
	if (idx < 0 || idx > 1) {
		LM_ERR("Bad index! should be 0 or 1!\n");
		return -1;
	}

	sp->pvp.pvi.type = PV_IDX_INT;
	sp->pvp.pvi.u.ival = idx;

	return 0;
}

int pv_get_entity(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *entity;
	b2bl_entity_id_t *curr_entities[MAX_BRIDGE_ENT];
	b2bl_entity_id_t dummy_entity;
	b2b_dlginfo_t dummy_dlginfo;
	str callid = {NULL, 0};
	int i;
	int locked = 0;

	tuple = get_ctx_tuple(&locked);
	if (!tuple) {
		LM_ERR("Failed to get the tuple from the current context\n");
		return pv_get_null(msg, param, res);
	}

	if (!locked)
		B2BL_LOCK_GET_AUX(tuple->hash_index);

	curr_entities[0] = tuple->bridge_entities[0];
	curr_entities[1] = tuple->bridge_entities[1];

	if (local_ctx_tuple) {
		/* the bridge_entities array might not be populated yet but the entities
		 * might be created */
		for (i = 0; i < MAX_B2BL_ENT; i++)
			if (tuple->servers[i] &&
				!tuple->bridge_entities[tuple->servers[i]->no])
				curr_entities[tuple->servers[i]->no] = tuple->servers[i];

		for (i = 0; i < MAX_B2BL_ENT; i++)
			if (tuple->clients[i] &&
				!tuple->bridge_entities[tuple->clients[i]->no])
				curr_entities[tuple->clients[i]->no] = tuple->clients[i];
	}

	if (param->pvi.type != PV_IDX_INT) {
		if (cur_route_ctx.flags & (B2BL_RT_REQ_CTX|B2BL_RT_RPL_CTX)) {
			/* identify the current entity by entity key */
			entity = curr_entities[0];
			if (entity && str_strcmp(&entity->key, &cur_route_ctx.entity_key))
				entity = NULL;

			if (!entity) {
				entity = curr_entities[1];
				if (entity && str_strcmp(&entity->key, &cur_route_ctx.entity_key))
					entity = NULL;
			}
		} else {
			/* identify the current entity by callid */
			if (get_callid(msg, &callid) < 0) {
				LM_ERR("Failed to get callid from SIP message\n");
				goto ret_null;
			}

			entity = curr_entities[0];
			if (entity &&
				(!entity->dlginfo || str_strcmp(&entity->dlginfo->callid, &callid)))
				entity = NULL;

			if (!entity) {
				entity = curr_entities[1];
				if (entity && (!entity->dlginfo ||
					str_strcmp(&entity->dlginfo->callid, &callid)))
					entity = NULL;
			}
		}

		if (!entity) {
			if (local_ctx_tuple &&
				msg->first_line.u.request.method_value == METHOD_INVITE) {
				/* we must be in the client_new() function from the entities
				 * API so we can take the callid/entity key from the SIP msg */
				dummy_entity.key = callid;
				dummy_dlginfo.callid = callid;
				dummy_entity.dlginfo = &dummy_dlginfo;
				entity = &dummy_entity;
			} else {
				LM_DBG("Unable to identify current entity in tuple: [%.*s]\n",
					tuple->key->len, tuple->key->s);
				goto ret_null;
			}
		}
	} else {
		entity = curr_entities[param->pvi.u.ival];
		if (!entity) {
			if (local_ctx_tuple &&
				msg->first_line.u.request.method_value == METHOD_INVITE) {
				/* we must be in the client_new() function from the entities
				 * API so we can take the callid/entity key from the SIP msg
				 * XXX is this  */
				if (get_callid(msg, &callid) < 0) {
					LM_ERR("Failed to get callid from SIP message\n");
					goto ret_null;
				}

				dummy_entity.key = callid;
				dummy_dlginfo.callid = callid;
				dummy_entity.dlginfo = &dummy_dlginfo;
				entity = &dummy_entity;
			} else {
				LM_DBG("No bridge entity at index: [%d] for tuple: [%.*s]\n",
					param->pvi.u.ival, tuple->key->len, tuple->key->s);
				goto ret_null;
			}
		}
	}

	switch (param->pvn.u.isname.name.n) {
	case PV_ENTITY_KEY:
		res->rs = entity->key;
		break;
	case PV_ENTITY_CALLID:
		if (entity->dlginfo) {
			res->rs = entity->dlginfo->callid;
		} else {
			LM_DBG("No dialog info for entity: [%d] from tuple: [%.*s]\n",
				param->pvi.u.ival, tuple->key->len, tuple->key->s);
			goto ret_null;
		}
		break;
	case PV_ENTITY_ID:
		res->rs = entity->scenario_id;
		break;
	case PV_ENTITIY_FROMTAG:
		if (entity->dlginfo) {
			res->rs = entity->dlginfo->fromtag;
		} else {
			LM_DBG("No dialog info for entity: [%d] from tuple: [%.*s]\n",
				param->pvi.u.ival, tuple->key->len, tuple->key->s);
			goto ret_null;
		}
		break;
	case PV_ENTITIY_TOTAG:
		if (entity->dlginfo) {
			res->rs = entity->dlginfo->totag;
		} else {
			LM_DBG("No dialog info for entity: [%d] from tuple: [%.*s]\n",
				param->pvi.u.ival, tuple->key->len, tuple->key->s);
			goto ret_null;
		}
		break;
	default:
		LM_ERR("Bad subname\n");
		goto ret_null;
	}

	res->flags = PV_VAL_STR;

	B2BL_LOCK_RELEASE_AUX(tuple->hash_index);

	return 0;

ret_null:
	B2BL_LOCK_RELEASE_AUX(tuple->hash_index);
	return pv_get_null(msg, param, res);
}

static inline unsigned int _get_val_name_id(const str *name)
{
	char *p;
	unsigned short id;

	id = 0;
	for (p = name->s + name->len - 1; p >= name->s; p--)
		id ^= *p;
	return id;
}

int fetch_ctx_value(struct b2b_ctx_val *vals, const str *name, str *out_val)
{
	struct b2b_ctx_val *v;
	unsigned int id;

	LM_DBG("looking for context value [%.*s]\n",name->len,name->s);

	id = _get_val_name_id(name);

	for (v = vals; v; v = v->next)
		if (id == v->id && name->len == v->name.len &&
			memcmp(name->s, v->name.s, name->len) == 0) {
			if (v->val.len > out_val->len) {
				out_val->s = pkg_realloc(out_val->s, v->val.len);
				if (!out_val->s) {
					LM_ERR("oom\n");
					return -1;
				}
			}

			memcpy(out_val->s, v->val.s, v->val.len);
			out_val->len = v->val.len;

			return 0;
		}

	LM_DBG("context value not found!\n");

	return -2;
}

int store_ctx_value(struct b2b_ctx_val **vals, str *name, str *new_val)
{
	struct b2b_ctx_val *v = NULL;
	struct b2b_ctx_val *it;
	struct b2b_ctx_val *it_prev;
	unsigned int id;

	if (new_val) {
		LM_DBG("inserting [%.*s]=[%.*s]\n", name->len, name->s,
			new_val->len, new_val->s);
		v = shm_malloc(sizeof *v + name->len + new_val->len);
		if (!v) {
			LM_ERR("oom!\n");
			return -1;
		}
		memset(v, 0, sizeof *v);

		v->id = _get_val_name_id(name);

		v->name.len = name->len;
		v->name.s = (char*)(v + 1);
		memcpy(v->name.s, name->s, name->len);

		v->val.len = new_val->len;
		v->val.s = ((char*)(v + 1)) + name->len;
		memcpy(v->val.s, new_val->s, new_val->len);
	}

	id = new_val ? v->id : _get_val_name_id(name);

	for (it_prev = NULL, it = *vals; it; it_prev = it, it = it->next)
		if (id == it->id && name->len == it->name.len &&
			memcmp(name->s, it->name.s, name->len) == 0) {
			LM_DBG("context value found-> [%.*s]!\n", it->val.len, it->val.s);
			/* value already exists -> replace or delete it */
			if (new_val == NULL) {
				if (it_prev)
					it_prev->next = it->next;
				else
					*vals = it->next;
			} else {
				v->next = it->next;
				if (it_prev)
					it_prev->next = v;
				else
					*vals = v;
			}

			shm_free(it);
			return 0;
		}

	if (new_val==NULL)
		return 0;

	v->next = *vals;
	*vals = v;

	return 0;
}

int pv_parse_ctx_name(pv_spec_p sp, const str *in)
{
	if (!in || !in->s || !sp)
		return -1;

	sp->pvp.pvn.u.isname.name.s = *in;

	return 0;
}

int get_ctx_vals(struct b2b_ctx_val ***vals, b2bl_tuple_t **tuple, int *locked)
{
	struct b2b_context *ctx;

	if (!local_ctx_tuple) {
		ctx = b2b_api.get_context();
		if (!ctx) {
			LM_ERR("Failed to get b2b context\n");
			return -1;
		}

		if (!ctx->b2bl_key.s) {
			if (!ctx->init) {
				LM_DBG("tuple not created yet\n");
				/* context values are saved in a temporary global variable */
				*vals = &local_ctx_vals;
				return 0;
			} else {
				*tuple = ctx_search_tuple(ctx, locked);
				if (*tuple == NULL)
					return -1;
			}
		} else {
			*tuple = get_entities_ctx_tuple(ctx, locked);
			if (*tuple == NULL) {
				LM_ERR("Failed to get tuple [%.*s] from b2b context\n",
					ctx->b2bl_key.len, ctx->b2bl_key.s);
				return -1;
			}
		}
	} else {
		*tuple = local_ctx_tuple;
	}

	*vals = &(*tuple)->vals;

	return 0;
}

int pv_get_ctx(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	struct b2b_ctx_val **vals;
	b2bl_tuple_t *tuple = NULL;
	int locked = 0;

	if (!param || !param->pvn.u.isname.name.s.s) {
		LM_ERR("Bad parameters!\n");
		return -1;
	}

	if (get_ctx_vals(&vals, &tuple, &locked) < 0) {
		LM_ERR("Failed to get context values list\n");
		return pv_get_null(msg, param, res);
	}

	if (tuple && !locked)
		B2BL_LOCK_GET_AUX(tuple->hash_index);

	if (fetch_ctx_value(*vals, &param->pvn.u.isname.name.s, &param->pvv) != 0) {
		if (tuple)
			B2BL_LOCK_RELEASE_AUX(tuple->hash_index);
		return pv_get_null(msg, param, res);
	}

	if (tuple)
			B2BL_LOCK_RELEASE_AUX(tuple->hash_index);

	res->flags = PV_VAL_STR;
	res->rs = param->pvv;
	return 0;
}

int pv_set_ctx(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val)
{
	struct b2b_ctx_val **ctx_vals = NULL;
	b2bl_tuple_t *tuple = NULL;
	int locked = 0;

	if (!param || !param->pvn.u.isname.name.s.s) {
		LM_ERR("Bad parameters!\n");
		return -1;
	}

	if (get_ctx_vals(&ctx_vals, &tuple, &locked) < 0) {
		LM_ERR("Failed to get context values list\n");
		return -1;
	}

	if (tuple && !locked)
		B2BL_LOCK_GET_AUX(tuple->hash_index);

	if (val==NULL || val->flags&(PV_VAL_NONE|PV_VAL_NULL|PV_VAL_EMPTY)) {
		/* delete value */
		if (store_ctx_value(ctx_vals, &param->pvn.u.isname.name.s, NULL) < 0) {
			LM_ERR("Failed to delete context value [%.*s]\n",
				param->pvn.u.isname.name.s.len,param->pvn.u.isname.name.s.s);
			goto error;
		}
	} else {
		if (!(val->flags & PV_VAL_STR)) {
			LM_ERR("non-string values are not supported\n");
			goto error;
		}

		if (store_ctx_value(ctx_vals, &param->pvn.u.isname.name.s, &val->rs) < 0) {
			LM_ERR("Failed to store context value [%.*s]\n",
				param->pvn.u.isname.name.s.len,param->pvn.u.isname.name.s.s);
			goto error;
		}
	}


	if (tuple)
		B2BL_LOCK_RELEASE_AUX(tuple->hash_index);

	return 0;

error:
	if (tuple)
		B2BL_LOCK_RELEASE_AUX(tuple->hash_index);
	return -1;
}

int b2bl_register_cb(str* key, b2bl_cback_f cbf, void* cb_param,
														unsigned int cb_mask)
{
	int ret = -1;
	b2bl_tuple_t* tuple;
	unsigned int hash_index, local_index;

	if(!key)
	{
		if (cb_mask != B2B_NEW_TUPLE_CB) {
			LM_ERR("only B2B_NEW_TUPLE_CB can be used without key!\n");
			return -1;
		}
		if (b2bl_register_new_tuple_cb(cbf, cb_param) < 0) {
			LM_ERR("cannot register new tuple callback\n");
			return -1;
		}
		return 0;
	}
	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key->len, key->s);
		return -1;
	}

	B2BL_LOCK_GET_AUX(hash_index);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No tuple found\n");
		goto error;
	}
	if(tuple->cb.f || tuple->cb.param || tuple->cb.mask)
	{
		LM_ERR("callback already registered\n");
		goto error;
	}

	ret = 0;
error:
	B2BL_LOCK_RELEASE_AUX(hash_index);
	return ret;
}

static str *b2bl_get_key(void)
{
	static str ret;
	static char buf[MAX_B2BL_KEY];
	int locked = 0;
	b2bl_tuple_t *tuple = get_ctx_tuple(&locked);

	if (!tuple)
		return NULL;

	ret.s = buf;
	ret.len = 0;

	ret.len = tuple->key->len;
	memcpy(ret.s, tuple->key->s, ret.len);

	if (locked)
		B2BL_LOCK_RELEASE_AUX(tuple->hash_index);

	return &ret;
}

static int b2bl_get_entity_info(str *key, struct sip_msg *msg, int entity, struct b2b_entity_info_t *info)
{
	str callid;
	b2bl_tuple_t *tuple;
	b2bl_entity_id_t *bentity = NULL;
	int locked = 0;
	int rc = -1;

	if (!info)
		return -4;
	memset(info, 0, sizeof *info);
	if (entity < -2 || entity > 1)
		return -4;

	if (key) {
		tuple = b2bl_get_tuple(key);
		if (tuple)
			locked = 1;
	} else {
		tuple = get_ctx_tuple(&locked);

		if (tuple && !locked)
			B2BL_LOCK_GET_AUX(tuple->hash_index);
	}
	if (!tuple)
		return -2;

	if (entity < 0) {
		if (cur_route_ctx.flags & (B2BL_RT_REQ_CTX|B2BL_RT_RPL_CTX)) {
			if (tuple->bridge_entities[0]) {
				if (!str_strcmp(&cur_route_ctx.entity_key,
						&tuple->bridge_entities[0]->key))
					bentity = tuple->bridge_entities[(entity == -2?1:0)];
			}
			if (!bentity && tuple->bridge_entities[1]) {
				if (!str_strcmp(&cur_route_ctx.entity_key,
						&tuple->bridge_entities[1]->key))
					bentity = tuple->bridge_entities[(entity == -2?0:1)];
			}
		} else {
			if (!msg) {
				rc = -2;
				goto end;
			}
			if (get_callid(msg, &callid) < 0) {
				LM_ERR("Failed to get callid from SIP message\n");
				goto end;
			}
			if (tuple->bridge_entities[0] && tuple->bridge_entities[0]->dlginfo) {
				if (!str_strcmp(&callid,
						&tuple->bridge_entities[0]->dlginfo->callid))
					bentity = tuple->bridge_entities[(entity == -2?1:0)];
			}
			if (!bentity && tuple->bridge_entities[1] && tuple->bridge_entities[1]->dlginfo) {
				if (!str_strcmp(&callid,
						&tuple->bridge_entities[1]->dlginfo->callid))
					bentity = tuple->bridge_entities[(entity == -2?0:1)];
			}
		}
		/* if we still don't have an entity, most likely we are in a
		 * client_new callback, with a single server entity */
		if (entity == -2)
			bentity = tuple->servers[0];

	} else {
		bentity = tuple->bridge_entities[entity];
	}
	if (!bentity) {
		rc = -3;
		goto end;
	}
	if (bentity->key.len && pkg_str_dup(&info->key, &bentity->key) < 0)
		goto end;
	if (bentity->dlginfo) {
		if (bentity->dlginfo->callid.len
				&& pkg_str_dup(&info->callid, &bentity->dlginfo->callid) < 0)
			goto end;
		if (bentity->dlginfo->fromtag.len
				&& pkg_str_dup(&info->fromtag, &bentity->dlginfo->fromtag) < 0)
			goto end;
		if (bentity->dlginfo->totag.len
				&& pkg_str_dup(&info->totag, &bentity->dlginfo->totag) < 0)
			goto end;
	}

	rc = 0;
end:
	if (locked)
		B2BL_LOCK_RELEASE_AUX(tuple->hash_index);
	return rc;
}

static void b2bl_release_entity_info(struct b2b_entity_info_t *info)
{
	if (!info)
		return;
	if (info->key.s)
		pkg_free(info->key.s);
	if (info->callid.s)
		pkg_free(info->callid.s);
	if (info->fromtag.s)
		pkg_free(info->fromtag.s);
	if (info->totag.s)
		pkg_free(info->totag.s);
}


int b2b_logic_bind(b2bl_api_t* api)
{
	if (!api)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}
	api->init          = b2bl_api_init;
	api->bridge        = b2bl_api_bridge;
	api->bridge_2calls = b2bl_bridge_2calls;
	api->bridge_msg    = b2bl_api_bridge_msg;
	api->terminate_call= b2bl_terminate_call;
	api->get_stats     = b2bl_get_stats;
	api->register_cb   = b2bl_register_cb;
	api->get_key       = b2bl_get_key;
	api->register_set_tracer_cb = b2bl_register_set_tracer_cb;
	api->restore_upper_info = b2bl_restore_upper_info;

	api->get_entity_info     = b2bl_get_entity_info;
	api->release_entity_info = b2bl_release_entity_info;

	api->ctx_register_int = b2bl_ctx_register_int;
	api->ctx_register_str = b2bl_ctx_register_str;
	api->ctx_register_ptr = b2bl_ctx_register_ptr;

	api->ctx_put_int = b2bl_ctx_put_int;
	api->ctx_put_str = b2bl_ctx_put_str;
	api->ctx_put_ptr = b2bl_ctx_put_ptr;

	api->ctx_get_int = b2bl_ctx_get_int;
	api->ctx_get_str = b2bl_ctx_get_str;
	api->ctx_get_ptr = b2bl_ctx_get_ptr;

	return 0;
}


int b2bl_restore_upper_info(str* b2bl_key, b2bl_cback_f cbf, void* param,
														unsigned int cb_mask)
{
	b2bl_tuple_t* tuple;
	unsigned int local_index, hash_index;

	if(b2bl_key == NULL)
	{
		LM_ERR("'param' argument NULL\n");
		return -1;
	}
	if(b2bl_parse_key(b2bl_key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n",
			b2bl_key->len, b2bl_key->s);
		return -1;
	}
	LM_DBG("hi= %d, li=%d\n", hash_index, local_index);

	B2BL_LOCK_GET(hash_index);
	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		B2BL_LOCK_RELEASE(hash_index);
		return -1;
	}
	tuple->cb.f = cbf;
	tuple->cb.mask = cb_mask;
	tuple->cb.param = param;
	B2BL_LOCK_RELEASE(hash_index);

	return 0;
}
