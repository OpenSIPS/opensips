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
#include <libxml/parser.h>

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

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"
#include "b2b_load.h"
#include "b2bl_db.h"
#include "entity_storage.h"

#define TABLE_VERSION 3

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
static int load_script_scenario(modparam_t type, void* val);
static int load_extern_scenario(modparam_t type, void* val);
static int fixup_b2b_logic(void** param);
static int fixup_free_b2b_logic(void** param);
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
static void b2bl_db_timer_update(unsigned int ticks, void* param);
int  b2b_init_request(struct sip_msg* msg, str* arg1, str* arg2, str* arg3,
		str* arg4, str* arg5, str* arg6);
int  b2b_bridge_request(struct sip_msg* msg, str *key, int *entity_no);

int pv_get_b2bl_key(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_parse_entity_name(pv_spec_p sp, str *in);
int pv_parse_entity_index(pv_spec_p sp, str* in);
int pv_get_entity(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_parse_ctx_name(pv_spec_p sp, str *in);
int pv_get_ctx(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
int pv_set_ctx(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val);

void b2b_mark_todel( b2bl_tuple_t* tuple);

/** Global variables */
b2b_api_t b2b_api;
b2bl_table_t b2bl_htable;
unsigned int b2bl_hsize = 10;
b2b_scenario_t* script_scenarios = NULL;
b2b_scenario_t* extern_scenarios = NULL;
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
   {"Content-Type",12},
   {"Supported", 9},
   {"Allow", 5},
   {"Proxy-Require", 13},
   {"Session-Expires", 15},
   {"Min-SE", 6},
   {"Require", 7},
   {"RSeq", 4},
};
int use_init_sdp = 0;
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
db_con_t *b2bl_db = NULL;
db_func_t b2bl_dbf;
str b2bl_dbtable= str_init("b2b_logic");
str init_callid_hdr={0, 0};

str server_address = {0, 0};
int b2bl_db_mode = WRITE_BACK;
int unsigned b2bl_th_init_timeout = 60;

str b2bl_mod_name = str_init("b2b_logic");

/* used to identify the current tuple in local_route, in the context of a request
 * that is not triggerd by a received message from an ongoing b2b dialog */
b2bl_tuple_t *local_ctx_tuple;

/* used to save context values set in the request route when the tuple is not
 * created yet */
struct b2b_ctx_val *local_ctx_vals;

static cmd_export_t cmds[]=
{
	{"b2b_init_request", (cmd_function)b2b_init_request, {
		{CMD_PARAM_STR, fixup_b2b_logic, fixup_free_b2b_logic},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_bridge_request", (cmd_function)b2b_bridge_request,
		{{CMD_PARAM_STR,0,0}, {CMD_PARAM_INT,0,0}, {0,0,0}},
		REQUEST_ROUTE},
	{"b2b_logic_bind", (cmd_function)b2b_logic_bind, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

/** Exported parameters */
static param_export_t params[]=
{
	{"hash_size",       INT_PARAM,                &b2bl_hsize                },
	{"cleanup_period",  INT_PARAM,                &b2b_clean_period          },
	{"update_period",   INT_PARAM,                &b2b_update_period         },
	{"script_scenario", STR_PARAM|USE_FUNC_PARAM, (void*)load_script_scenario},
	{"extern_scenario", STR_PARAM|USE_FUNC_PARAM, (void*)load_extern_scenario},
	{"custom_headers",  STR_PARAM,                &custom_headers.s          },
	{"custom_headers_regexp", STR_PARAM,          &custom_headers_regexp.s   },
	{"use_init_sdp",    INT_PARAM,                &use_init_sdp              },
	{"db_url",          STR_PARAM,                &db_url.s                  },
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
	{0,                    0,                          0                     }
};

static pv_export_t mod_items[] = {
	{{"b2b_logic.key", sizeof("b2b_logic.key") - 1}, 1000, pv_get_b2bl_key,
		0, 0, 0, 0, 0},
	{{"b2b_logic.entity", sizeof("b2b_logic.entity") - 1}, 1000, pv_get_entity,
		0, pv_parse_entity_name, pv_parse_entity_index, 0, 0},
	{{"b2b_logic.ctx", sizeof("b2b_logic.ctx") - 1}, 1000, pv_get_ctx,
		pv_set_ctx, pv_parse_ctx_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static mi_export_t mi_cmds[] = {
	{"b2b_trigger_scenario", 0, 0, 0, {
		{mi_trigger_scenario, {"scenario_id", "scenario_params", 0}},
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
		{mi_b2b_terminate_call, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
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

	if(server_address.s == NULL)
	{
		if(extern_scenarios)
		{
			LM_ERR("'server_address' parameter not set. This parameter is"
				" compulsory if you want to use extern scenarios. It must"
				" be set to the IP address of the machine\n");
			return -1;
		}
	}
	else
		server_address.len = strlen(server_address.s);

	if(init_b2bl_htable() < 0)
	{
		LM_ERR("Failed to initialize b2b logic hash table\n");
		return -1;
	}

	if(b2bl_db_mode)
		init_db_url(db_url, 1);

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
	}
	else
		b2bl_db_mode = 0;

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

	register_timer("b2bl-clean", b2bl_clean, 0, b2b_clean_period,
		TIMER_FLAG_DELAY_ON_DELAY);
	if(b2bl_db_mode == WRITE_BACK)
		register_timer("b2bl-dbupdate", b2bl_db_timer_update, 0,
			b2b_update_period, TIMER_FLAG_SKIP_ON_DELAY);

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

	return 0;
}

void b2bl_db_timer_update(unsigned int ticks, void* param)
{
	b2b_logic_dump(0);
}

static void term_expired_entity(b2bl_entity_id_t *entity, int hash_index)
{
	str bye = {BYE, BYE_LEN};
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;

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

		b2bl_htable[hash_index].locked_by = process_no;
		if(b2b_api.send_reply(&rpl_data) < 0)
			LM_ERR("Sending reply failed - %d, [%.*s]\n",
				rpl_data.code, entity->key.len,
				entity->key.s);
		b2bl_htable[hash_index].locked_by = -1;
	} else {
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(entity);
		req_data.method =&bye;
		b2bl_htable[hash_index].locked_by = process_no;
		b2b_api.send_request(&req_data);
		b2bl_htable[hash_index].locked_by = -1;
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
		lock_get(&b2bl_htable[i].lock);
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
						term_expired_entity(tuple->bridge_entities[0], i);

					if(!tuple->bridge_entities[1]->disconnected)
						term_expired_entity(tuple->bridge_entities[1], i);
				}
				b2bl_delete(tuple, i, 1, tuple->repl_flag != TUPLE_REPL_RECV);
			}
			tuple = tuple_next;
		}
		lock_release(&b2bl_htable[i].lock);
	}
}

static int load_scenario(b2b_scenario_t** scenario_list,char* filename)
{
	xmlDocPtr doc;
	xmlNodePtr node;
	b2b_scenario_t* scenario = NULL;
	str attr;
	xmlNodePtr rules_node, rule_node, request_node;
	int request_id = 0;
	b2b_rule_t* rule_struct = NULL;
	xmlNodePtr body_node;
	char* body_content= 0;
	char* body_type= 0;

	doc = xmlParseFile(filename);
	if(doc == NULL)
	{
		LM_ERR("Failed to parse xml file\n");
		return -1;
	}

	scenario = (b2b_scenario_t*)pkg_malloc(sizeof(b2b_scenario_t));
	if(scenario == NULL)
	{
		LM_ERR("No more private memory\n");
		xmlFreeDoc(doc);
		return -1;
	}
	memset(scenario, 0, sizeof(b2b_scenario_t));

	/* analyze the scenario document and descompose so that
	 * applying it will be more efficient */

	/* extract scenario_id and param no */

	scenario->id.s = (char*)xmlNodeGetAttrContentByName(doc->children, "id");
	if(scenario->id.s == NULL)
	{
		LM_ERR("XML scenario document not well formed. No id attribute found"
				" for root node\n");
		pkg_free(scenario);
		xmlFreeDoc(doc);
		return -1;
	}
	scenario->id.len = strlen(scenario->id.s);
	LM_DBG("Loaded scenario with id = [%.*s]\n", scenario->id.len, scenario->id.s);

	attr.s = (char*)xmlNodeGetAttrContentByName(doc->children, "param");
	if(attr.s == NULL)
	{
		LM_ERR("XML scenario document not well formed. No id attribute found"
				" for root node\n");
		pkg_free(scenario);
		xmlFreeDoc(doc);
		return -1;
	}
	attr.len = strlen(attr.s);

	if( str2int(&attr, &scenario->param_no) < 0)
	{
		LM_ERR("Failed to parse id attribute for scenario node. It must be an integer.\n");
		xmlFreeDoc(doc);
		xmlFree(attr.s);
		pkg_free(scenario);
		return -1;
	}
	xmlFree(attr.s);

	/* extract init node */
	scenario->init_node =  xmlDocGetNodeByName(doc, "init", NULL);
	if(scenario->init_node == NULL)
	{
		LM_ERR("Wrong formatted xml doc. Didn't find an init node\n");
		goto error;
	}

	node = xmlNodeGetChildByName(scenario->init_node, "use_init_sdp");
	if(node)
	{
		scenario->use_init_sdp = 1;
		body_node = xmlNodeGetChildByName(node, "body");
		if(body_node)
		{
			body_type = (char *)xmlNodeGetAttrContentByName(body_node, "type");
			if (body_type == NULL)
			{
				LM_ERR("Bad formatted scenario document. Empty body content type\n");
				goto error;
			}
			body_content = (char*)xmlNodeGetContent(body_node);
			if(body_content == NULL)
			{
				LM_ERR("Bad formatted scenario document. Empty body\n");
				xmlFree(body_type);
				goto error;
			}
			/* we move everything in pkg to be able to strip them */
			scenario->body_type.len = strlen(body_type);
			scenario->body_type.s = body_type;
			scenario->body.len = strlen(body_content);
			scenario->body.s = body_content;
		}
	}

	/* go through the rules */
	node = xmlDocGetNodeByName(doc, "rules", NULL);
	if(node == NULL)
	{
		LM_DBG("No rules defined\n");
		goto done;
	}

	rules_node = xmlNodeGetChildByName(node, "request");
	if(rules_node == NULL)
	{
		LM_DBG("No request rules defined\n");
		goto after_req_rules;
	}
	for(request_node= rules_node->children; request_node; request_node = request_node->next)
	{
		if(xmlStrcasecmp(request_node->name, (unsigned char*)"text") == 0)
			continue;
		attr.s =  (char*)request_node->name;
		attr.len = strlen(attr.s);

		request_id = b2b_get_request_id(&attr);
		if(request_id < 0)
		{
			LM_ERR("Bad scenario document. A rule defined for a not supported"
					" request type [%s]\n", request_node->name);
			goto error;
		}

		for(rule_node= request_node->children; rule_node; rule_node = rule_node->next)
		{
			if(xmlStrcasecmp(rule_node->name, (unsigned char*)"rule")!= 0)
				continue;

			rule_struct = (b2b_rule_t*)pkg_malloc(sizeof(b2b_rule_t));
			if(rule_struct == NULL)
			{
				LM_ERR("No more memory\n");
				goto error;
			}
			memset(rule_struct, 0, sizeof(b2b_rule_t));
			rule_struct->next =  scenario->request_rules[request_id];
			scenario->request_rules[request_id] = rule_struct;

			attr.s = (char*)xmlNodeGetAttrContentByName(rule_node, "id");
			if(attr.s == NULL)
			{
				LM_ERR("Bad scenario document. No id attribute for 'rule' node\n");
				goto error;
			}

			attr.len = strlen(attr.s);
			if(str2int(&attr, &rule_struct->id)< 0)
			{
				LM_ERR("Bad scenario document. rules_no subschild for request rule not an integer\n");
				xmlFree(attr.s);
				goto error;
			}
			xmlFree(attr.s);

			rule_struct->cond_state = -1;

			/* extract conditional state if present */
			rule_struct->cond_node = xmlNodeGetChildByName(rule_node, "condition");
			if(rule_struct->cond_node)
			{
				/* extract the condition state if any */
				attr.s = (char*)xmlNodeGetNodeContentByName(rule_struct->cond_node, "state", NULL);
				if(attr.s)
				{
					attr.len = strlen(attr.s);
					if(str2int(&attr, (unsigned int*)&rule_struct->cond_state)< 0)
					{
						LM_ERR("Bad scenario. Cond state must be an integer [%s]\n",attr.s);
						xmlFree(attr.s);
						goto error;
					}
					xmlFree(attr.s);
				}
			}
			node = xmlNodeGetChildByName(rule_node, "action");
			if(node == NULL)
			{
				LM_ERR("Bad scenario document. A rule needs an action node\n");
				goto error;
			}

			rule_struct->action_node = node;
		}
	}
after_req_rules:
	/* TODO - Analyze if there are actions for replies */
	LM_DBG("scenario_id = %.*s\n", scenario->id.len, scenario->id.s);
done:
	scenario->doc  = doc;
	scenario->next = *scenario_list;
	*scenario_list  = scenario;

	return 0;

error:
	if(doc)
		xmlFree(doc);
	if(scenario)
	{
		int i;
		b2b_rule_t* prev;
		for(i = 0; i< B2B_METHODS_NO; i++)
		{
			rule_struct = scenario->request_rules[i];
			while(rule_struct)
			{
				prev = rule_struct;
				rule_struct = rule_struct->next;
				pkg_free(prev);
			}
		}

		rule_struct = scenario->reply_rules;
		while(rule_struct)
		{
			prev = rule_struct;
			rule_struct = rule_struct->next;
			pkg_free(prev);
		}
		if(scenario->id.s)
			xmlFree(scenario->id.s);
		if(scenario->body.s)
			xmlFree(scenario->body.s);
		if(scenario->body_type.s)
			xmlFree(scenario->body_type.s);
		pkg_free(scenario);
	}

	return -1;
}

static int load_script_scenario(modparam_t type, void* val)
{
	return load_scenario(&script_scenarios, (char*)val);
}

static int load_extern_scenario(modparam_t type, void* val)
{
	return load_scenario(&extern_scenarios, (char*)val);
}


static void mod_destroy(void)
{
	int i;
	b2b_rule_t* rule_struct = NULL;

	b2b_scenario_t* scenario, *next;

	if (b2bl_db_mode==WRITE_BACK && b2bl_dbf.init) {

		b2bl_db = b2bl_dbf.init(&db_url);
		if(!b2bl_db)
		{
			LM_ERR("connecting to database failed\n");
		} else {
			b2b_logic_dump(1);
			b2bl_dbf.close(b2bl_db);
		}
	}

	scenario = extern_scenarios;
	while(scenario)
	{
		next = scenario->next;

		xmlFree(scenario->id.s);
		xmlFreeDoc(scenario->doc);
		pkg_free(scenario);
		scenario = next;
	}

	scenario = script_scenarios;
	while(scenario)
	{
		next = scenario->next;

		xmlFreeDoc(scenario->doc);
		b2b_rule_t* prev;
		for(i = 0; i< B2B_METHODS_NO; i++)
		{
			rule_struct = scenario->request_rules[i];
			while(rule_struct)
			{
				prev = rule_struct;
				rule_struct = rule_struct->next;
				pkg_free(prev);
			}
		}

		rule_struct = scenario->reply_rules;
		while(rule_struct)
		{
			prev = rule_struct;
			rule_struct = rule_struct->next;
			pkg_free(prev);
		}
		if(scenario->id.s)
			xmlFree(scenario->id.s);
		if (scenario->body.s)
			xmlFree(scenario->body.s);
		if (scenario->body_type.s)
			xmlFree(scenario->body_type.s);

		pkg_free(scenario);
		scenario = next;
	}

	destroy_b2bl_htable();
}

static int child_init(int rank)
{
	if (b2bl_db_mode==0)
		return 0;

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

	return 0;
}

b2b_scenario_t* get_scenario_id_list(str* sid, b2b_scenario_t* list)
{
	b2b_scenario_t* scenario;

	/*search first in script_scenarios */
	scenario = list;
	while(scenario)
	{
		LM_DBG("scenario id = %.*s\n", scenario->id.len, scenario->id.s);
		if(scenario->id.len == sid->len &&
				strncmp(scenario->id.s, sid->s, sid->len) == 0)
		{
			return scenario;
		}
		scenario = scenario->next;
	}
	return 0;
}


b2b_scenario_t* get_scenario_id(str* sid)
{
	b2b_scenario_t* scenario;

	if(sid->s== 0 || sid->len== 0)
		return 0;

	if(sid->len == B2B_TOP_HIDING_SCENARY_LEN &&
		strncmp(sid->s,B2B_TOP_HIDING_SCENARY,B2B_TOP_HIDING_SCENARY_LEN)==0)
	{
		return 0;
	}
	scenario = get_scenario_id_list(sid, script_scenarios);
	if(scenario)
		return scenario;

	return get_scenario_id_list(sid, extern_scenarios);
}

static int fixup_b2b_logic(void** param)
{
	str s;
	str flags_s;
	int st;
	struct b2b_scen_fl *scf;

	s = *(str*)*param;

	scf = prepare_b2b_scen_fl_struct();
	if (scf == NULL)
	{
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	scf->params.init_timeout = b2bl_th_init_timeout;

	if ( (flags_s.s = q_memchr(s.s,'/',s.len)) != NULL)
	{
		flags_s.s++;
		flags_s.len = s.len - (flags_s.s - s.s);
		s.len = s.len - flags_s.len - 1;

		/* parse flags */
		for( st=0 ; st< flags_s.len ; st++ ) {
			switch (flags_s.s[st])
			{
				case 't':
					scf->params.init_timeout = 0;
					while (st<flags_s.len-1 && isdigit(flags_s.s[st+1])) {
						scf->params.init_timeout =
							scf->params.init_timeout*10 + flags_s.s[st+1] - '0';
						st++;
					}
					break;
				case 'a':
					scf->params.flags |= B2BL_FLAG_TRANSPARENT_AUTH;
					break;
				case 'p':
					scf->params.flags |= B2BL_FLAG_TRANSPARENT_TO;
					break;
				default:
					LM_WARN("unknown option `%c'\n", *flags_s.s);
			}
		}
	}

	if(s.len == B2B_TOP_HIDING_SCENARY_LEN &&
		strncmp(s.s,B2B_TOP_HIDING_SCENARY,B2B_TOP_HIDING_SCENARY_LEN)==0)
	{
		scf->scenario = NULL;
	}
	else
	{
		scf->scenario = get_scenario_id_list(&s, script_scenarios);
		if (!scf->scenario)
		{
			LM_ERR("Wrong Scenary ID. No scenario with this ID [%.*s]\n", s.len, s.s);
			return E_UNSPEC;
		}
	}

	*param=(void*)scf;
	return 0;
}

static int fixup_free_b2b_logic(void** param)
{
	if (*param)
		pkg_free(*param);

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


str* b2bl_bridge_extern(str* scenario_name, str* args[],
		b2bl_cback_f cbf, void* cb_param, unsigned int cb_mask)
{
	b2b_scenario_t* scenario_struct;
	unsigned int hash_index;
	b2bl_tuple_t* tuple= NULL;
	str* b2bl_key;
	unsigned int state = 0;
	xmlNodePtr xml_node;
	str attr;

	if(scenario_name== NULL || args[0] == NULL || args[1]== NULL)
	{
		LM_ERR("Wrong arguments\n");
		return 0;
	}
	hash_index = core_hash(args[0], args[1], b2bl_hsize);

	LM_DBG("start: bridge [%.*s] with [%.*s]\n", args[0]->len, args[0]->s,
			 args[1]->len, args[1]->s);
	/* find the scenario with the corresponding id */
	scenario_struct = extern_scenarios;
	while(scenario_struct)
	{
		if(scenario_struct->id.len == scenario_name->len &&
				strncmp(scenario_struct->id.s, scenario_name->s, scenario_name->len) == 0)
		{
			break;
		}
		scenario_struct = scenario_struct->next;
	}
	if(scenario_struct == NULL)
	{
		LM_ERR("No scenario found with the specified id\n");
		return 0;
	}

	/* apply the init part of the scenario */
	tuple = b2bl_insert_new(NULL, hash_index, scenario_struct, args,
				NULL, NULL, -1, &b2bl_key, INSERTDB_FLAG, TUPLE_NO_REPL);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return 0;
	}
	tuple->cbf = cbf;
	tuple->cb_mask = cb_mask;
	tuple->cb_param = cb_param;
	tuple->lifetime = 60 + get_ticks();

	local_ctx_tuple = tuple;

	b2bl_htable[hash_index].locked_by = process_no;

	/* need to get the next action */
	xml_node = xmlNodeGetChildByName(scenario_struct->init_node, "state");
	if(xml_node)
	{
		attr.s = (char*)xmlNodeGetContent(xml_node);
		if(attr.s == NULL)
		{
			LM_ERR("No state node content found\n");
			goto error;
		}
		attr.len = strlen(attr.s);

		if(str2int(&attr, &state)< 0)
		{
			LM_ERR("Bad scenario. Scenary state not an integer\n");
			xmlFree(attr.s);
			goto error;
		}
		LM_DBG("Next scenario state is [%d]\n", state);
		xmlFree(attr.s);
	}
	tuple->next_scenario_state = state;

	xml_node =  xmlNodeGetChildByName(scenario_struct->init_node, "bridge");
	if(xml_node == NULL)
	{
		LM_ERR("No bridge node found\n");
		goto error;
	}

	if(process_bridge_action(0, 0, tuple, hash_index, xml_node) < 0)
	{
		LM_ERR("Failed to process bridge node\n");
		goto error;
	}

	local_ctx_tuple = NULL;

	b2bl_htable[hash_index].locked_by = -1;

	lock_release(&b2bl_htable[hash_index].lock);
	return b2bl_key;

error:
	if(tuple) {
		b2bl_htable[hash_index].locked_by = -1;
		lock_release(&b2bl_htable[hash_index].lock);
	}
	local_ctx_tuple = NULL;
	return 0;
}

mi_response_t *mi_trigger_scenario(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str args[MAX_SCENARIO_PARAMS];
	str* argsp[MAX_SCENARIO_PARAMS];
	str scenario_name;
	int i = 0, no_args;
	mi_item_t *params_arr;

	if (get_mi_string_param(params, "scenario_id",
		&scenario_name.s, &scenario_name.len) < 0)
		return init_mi_param_error();

	if (get_mi_array_param(params, "scenario_params", &params_arr, &no_args) < 0)
		return init_mi_param_error();

	memset(args, 0, MAX_SCENARIO_PARAMS * sizeof(str));
	memset(argsp, 0, MAX_SCENARIO_PARAMS * sizeof(str*));

	for (i = 0; i < no_args; i++) {
		if (get_mi_arr_param_string(params_arr, i,
			&args[i].s, &args[i].len) < 0)
			return init_mi_param_error();
		argsp[i] = &args[i];
	}

	if(b2bl_bridge_extern(&scenario_name, argsp, 0, 0, 0) == 0)
	{
		LM_ERR("Failed to initialize scenario\n");
		return 0;
	}

	return init_mi_result_ok();
}

int  b2b_bridge_request(struct sip_msg* msg, str *key, int *entity_no)
{
	return b2bl_bridge_msg(msg, key, *entity_no);
}

static mi_response_t *mi_b2b_terminate_call(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str key;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();

	b2bl_terminate_call(&key);

	return init_mi_result_ok();
}

static mi_response_t *mi_b2b_bridge(const mi_params_t *params,
							int entity_no, str *prov_media)
{
	str key;
	b2bl_tuple_t* tuple;
	str new_dest;
	b2bl_entity_id_t* entity, *old_entity, *bridging_entity, *prov_entity = 0;
	struct sip_uri uri;
	str meth_inv = {INVITE, INVITE_LEN};
	str meth_bye = {BYE, BYE_LEN};
	unsigned int hash_index, local_index;
	str ok= str_init("ok");
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;
	int ret;

	if (get_mi_string_param(params, "dialog_id", &key.s, &key.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "new_uri", &new_dest.s, &new_dest.len) < 0)
		return init_mi_param_error();

	if(parse_uri(new_dest.s, new_dest.len, &uri)< 0)
	{
		LM_ERR("Bad argument. Not a valid uri [%.*s]\n", new_dest.len, new_dest.s);
		return init_mi_error(404, MI_SSTR("Invalid uri for the new destination"));
	}

	/* if 'flag' parameter is 1 - >
	 * means that destination from the current call must be
	 * bridged to the new destination */
	if (entity_no != 0 && entity_no != 1)
		return init_mi_error(404, MI_SSTR("Invalid 'flag' parameter"));

	if (prov_media) {
		/* parse new uri */
		if(parse_uri(prov_media->s, prov_media->len, &uri)< 0)
		{
			LM_ERR("Bad argument. Not a valid provisional media uri [%.*s]\n",
				   new_dest.len, new_dest.s);
			return init_mi_error(404, MI_SSTR("Bad 'prov_media_uri' parameter"));
		}
		prov_entity = b2bl_create_new_entity(B2B_CLIENT,
						0, prov_media, 0, 0, 0, 0, 0);
		if (!prov_entity) {
			LM_ERR("Failed to create new b2b entity\n");
			goto free;
		}
	}

	ret = b2bl_get_tuple_key(&key, &hash_index, &local_index);
	if(ret < 0)
	{
		if (ret == -1)
			LM_ERR("Failed to parse key or find an entity [%.*s]\n",
					key.len, key.s);
		else
			LM_ERR("Could not find entity [%.*s]\n",
					key.len, key.s);
		goto free;
	}

	entity = b2bl_create_new_entity(B2B_CLIENT, 0, &new_dest, 0, 0, 0, 0, 0);
	if(entity == NULL)
	{
		LM_ERR("Failed to create new b2b entity\n");
		goto free;
	}

	lock_get(&b2bl_htable[hash_index].lock);
	b2bl_htable[hash_index].locked_by = process_no;

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	local_ctx_tuple = tuple;

	if (!tuple->bridge_entities[entity_no] ||
	tuple->bridge_entities[entity_no]->disconnected)
	{
		LM_ERR("Can not bridge requested entity [%p]\n",
			tuple->bridge_entities[entity_no]);
		goto error;
	}

	bridging_entity = tuple->bridge_entities[entity_no];
	old_entity = tuple->bridge_entities[(entity_no?0:1)];

	if(old_entity == NULL || bridging_entity == NULL)
	{
		LM_ERR("Wrong dialog id\n");
		goto error;
	}

	if(old_entity->next || old_entity->prev)
	{
		LM_ERR("Can not disconnect entity [%p]\n", old_entity);
		b2bl_print_tuple(tuple, L_ERR);
		goto error;
	}

	if(bridging_entity->state != B2BL_ENT_CONFIRMED)
	{
		LM_ERR("Wrong state for entity ek= [%.*s], tk=[%.*s]\n",
			bridging_entity->key.len,bridging_entity->key.s,
			tuple->key->len, tuple->key->s);
		goto error;
	}

	b2bl_print_tuple(tuple, L_DBG);

	/* send BYE to old client */
	if(old_entity->disconnected)
	{
		memset(&rpl_data, 0, sizeof(b2b_rpl_data_t));
		PREP_RPL_DATA(old_entity);
		rpl_data.method =METHOD_BYE;
		rpl_data.code =200;
		rpl_data.text =&ok;
		b2b_api.send_reply(&rpl_data);
	}
	else
	{
		old_entity->disconnected = 1;
		memset(&req_data, 0, sizeof(b2b_req_data_t));
		PREP_REQ_DATA(old_entity);
		req_data.method =&meth_bye;
		b2b_api.send_request(&req_data);
	}

	if (0 == b2bl_drop_entity(old_entity, tuple))
	{
		LM_ERR("Inconsistent tuple [%p]\n", tuple);
		b2bl_print_tuple(tuple, L_ERR);
		goto error;
	}

	if (old_entity->peer->peer == old_entity)
		old_entity->peer->peer = NULL;
	else
	{
		LM_ERR("Unexpected chain: old_entity=[%p] and old_entity->peer->peer=[%p]\n",
			old_entity, old_entity->peer->peer);
		goto error;
	}
	old_entity->peer = NULL;

	tuple->bridge_entities[0]= bridging_entity;
	if (prov_entity) {
		tuple->bridge_entities[1]= prov_entity;
		tuple->bridge_entities[2]= entity;
		/* we don't have to free it anymore */
		prov_entity = 0;
	} else {
		tuple->bridge_entities[1]= entity;
		bridging_entity->peer = entity;
		entity->peer = bridging_entity;
	}

	tuple->scenario_state = B2B_BRIDGING_STATE;
	bridging_entity->state = 0;
	bridging_entity->sdp_type = B2BL_SDP_LATE;

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(bridging_entity);
	req_data.method =&meth_inv;
	b2bl_htable[hash_index].locked_by = process_no;
	b2b_api.send_request(&req_data);
	b2bl_htable[hash_index].locked_by = -1;

	local_ctx_tuple = NULL;

	b2bl_htable[hash_index].locked_by = -1;;
	lock_release(&b2bl_htable[hash_index].lock);

	return init_mi_result_ok();

error:
	if(tuple)
		b2b_mark_todel(tuple);
	local_ctx_tuple = NULL;
	b2bl_htable[hash_index].locked_by = -1;
	lock_release(&b2bl_htable[hash_index].lock);
free:
	if (prov_entity)
		shm_free(prov_entity);
	return 0;
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
		lock_get(&b2bl_htable[i].lock);
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
			if (add_mi_number(tuple_item, MI_SSTR("scenario_state"),
				tuple->scenario_state) < 0)
				goto error;
			if (add_mi_number(tuple_item, MI_SSTR("lifetime"),
				tuple->lifetime) < 0)
				goto error;
			if (add_mi_number(tuple_item, MI_SSTR("db_flag"),
				tuple->db_flag) < 0)
				goto error;

			if (tuple->scenario) {
				if (add_mi_string(tuple_item, MI_SSTR("scenario"),
					tuple->scenario->id.s, tuple->scenario->id.len) < 0)
					goto error;
				if (add_mi_number(tuple_item, MI_SSTR("next_scenario_state"),
					tuple->next_scenario_state) < 0)
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
		lock_release(&b2bl_htable[i].lock);
	}

	return resp;
error:
	lock_release(&b2bl_htable[i].lock);
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return NULL;
}

/* get current tuple from the b2b_etities context */
b2bl_tuple_t *get_entities_ctx_tuple(struct b2b_context *ctx)
{
	b2bl_tuple_t *tuple;
	unsigned int hash_index, local_index;

	tuple = ctx->data;
	if (!tuple) {
		/* find tuple based on the tuple key from the b2b_etities context */
		if (b2bl_parse_key(&ctx->b2bl_key, &hash_index, &local_index) < 0) {
			LM_ERR("Failed to parse key [%.*s]\n", ctx->b2bl_key.len,
				ctx->b2bl_key.s);
			return NULL;
		}

		if (b2bl_htable[hash_index].locked_by != process_no)
			lock_get(&b2bl_htable[hash_index].lock);

		tuple = b2bl_search_tuple_safe(hash_index, local_index);
		if (!tuple) {
			LM_ERR("Tuple [%.*s] not found\n", ctx->b2bl_key.len,
				ctx->b2bl_key.s);
			if (b2bl_htable[hash_index].locked_by != process_no)
				lock_release(&b2bl_htable[hash_index].lock);
			return NULL;
		}

		/* save it in context */
		ctx->data = tuple;

		if (b2bl_htable[hash_index].locked_by != process_no)
			lock_release(&b2bl_htable[hash_index].lock);
	}

	return tuple;
}

b2bl_tuple_t *get_ctx_tuple(void)
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
			return ctx->data;
		}

		tuple = get_entities_ctx_tuple(ctx);
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

	tuple = get_ctx_tuple();
	if (!tuple) {
		LM_DBG("Unable to get the tuple from the current context\n");
		return pv_get_null(msg, param, res);
	}

	res->flags = PV_VAL_STR;
	res->rs = *tuple->key;

	return 0;
}

int pv_parse_entity_name(pv_spec_p sp, str *in)
{
	if (!in || !in->s || !in->len) {
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_KEY;
		return 0;
	}

	if (!str_strcmp(in, _str("key")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_KEY;
	else if (!str_strcmp(in, _str("callid")))
		sp->pvp.pvn.u.isname.name.n = PV_ENTITY_CALLID;
	else {
		LM_ERR("Bad subname for $b2b_logic.entity\n");
		return -1;
	}

	return 0;
}

int pv_parse_entity_index(pv_spec_p sp, str* in)
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
	if (idx < 0 && idx > 1) {
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
	str callid;
	int i;

	tuple = get_ctx_tuple();
	if (!tuple) {
		LM_ERR("Failed to get the tuple from the current context\n");
		return pv_get_null(msg, param, res);
	}

	if (b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_get(&b2bl_htable[tuple->hash_index].lock);

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
		/* no index provided, identify the current entity by callid */
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
	default:
		LM_ERR("Bad subname\n");
		goto ret_null;
	}

	res->flags = PV_VAL_STR;

	if (b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_release(&b2bl_htable[tuple->hash_index].lock);

	return 0;

ret_null:
	if (b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_release(&b2bl_htable[tuple->hash_index].lock);
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

int pv_parse_ctx_name(pv_spec_p sp, str *in)
{
	if (!in || !in->s || !sp)
		return -1;

	sp->pvp.pvn.u.isname.name.s = *in;

	return 0;
}

int get_ctx_vals(struct b2b_ctx_val ***vals, b2bl_tuple_t **tuple)
{
	struct b2b_context *ctx;

	if (!local_ctx_tuple) {
		ctx = b2b_api.get_context();
		if (!ctx) {
			LM_ERR("Failed to get b2b context\n");
			return -1;
		}

		if (!ctx->b2bl_key.s) {
			if (!ctx->data) {
				LM_DBG("tuple not created yet\n");
				/* context values are saved in a temporary global variable */
				*vals = &local_ctx_vals;
				return 0;
			} else {
				*tuple = ctx->data;
			}
		} else {
			*tuple = get_entities_ctx_tuple(ctx);
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

	if (!param || !param->pvn.u.isname.name.s.s) {
		LM_ERR("Bad parameters!\n");
		return -1;
	}

	if (get_ctx_vals(&vals, &tuple) < 0) {
		LM_ERR("Failed to get context values list\n");
		return pv_get_null(msg, param, res);
	}

	if (tuple && b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_get(&b2bl_htable[tuple->hash_index].lock);

	if (fetch_ctx_value(*vals, &param->pvn.u.isname.name.s, &param->pvv) != 0) {
		if (tuple && b2bl_htable[tuple->hash_index].locked_by != process_no)
			lock_release(&b2bl_htable[tuple->hash_index].lock);
		return pv_get_null(msg, param, res);
	}

	if (tuple && b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_release(&b2bl_htable[tuple->hash_index].lock);

	res->flags = PV_VAL_STR;
	res->rs = param->pvv;
	return 0;
}

int pv_set_ctx(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val)
{
	struct b2b_ctx_val **ctx_vals = NULL;
	b2bl_tuple_t *tuple = NULL;

	if (!param || !param->pvn.u.isname.name.s.s) {
		LM_ERR("Bad parameters!\n");
		return -1;
	}

	if (get_ctx_vals(&ctx_vals, &tuple) < 0) {
		LM_ERR("Failed to get context values list\n");
		return -1;
	}

	if (tuple && b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_get(&b2bl_htable[tuple->hash_index].lock);

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

	if (tuple && b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_release(&b2bl_htable[tuple->hash_index].lock);

	return 0;

error:
	if (tuple && b2bl_htable[tuple->hash_index].locked_by != process_no)
		lock_release(&b2bl_htable[tuple->hash_index].lock);
	return -1;
}

int b2bl_register_cb(str* key, b2bl_cback_f cbf, void* cb_param,
														unsigned int cb_mask)
{
	b2bl_tuple_t* tuple;
	unsigned int hash_index, local_index;

	if(!key)
	{
		LM_ERR("null key\n");
		return -1;
	}
	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key->len, key->s);
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No tuple found\n");
		goto error;
	}
	if(tuple->cbf || tuple->cb_param || tuple->cb_mask)
	{
		LM_ERR("callback already registered\n");
		goto error;
	}

	tuple->cbf = cbf;
	tuple->cb_mask = cb_mask;
	tuple->cb_param = cb_param;

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
error:
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
}


int b2b_logic_bind(b2bl_api_t* api)
{
	if (!api)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}
	api->init          = internal_init_scenario;
	api->bridge        = b2bl_bridge;
	api->bridge_extern = b2bl_bridge_extern;
	api->set_state     = b2bl_set_state;
	api->bridge_2calls = b2bl_bridge_2calls;
	api->bridge_msg    = b2bl_bridge_msg;
	api->terminate_call= b2bl_terminate_call;
	api->get_stats     = b2bl_get_stats;
	api->register_cb   = b2bl_register_cb;
	api->restore_upper_info = b2bl_restore_upper_info;

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

	lock_get(&b2bl_htable[hash_index].lock);
	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}
	tuple->cbf = cbf;
	tuple->cb_mask = cb_mask;
	tuple->cb_param = param;
	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
}
