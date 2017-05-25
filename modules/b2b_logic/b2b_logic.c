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

#include "../../db/db.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_content.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"
#include "b2b_load.h"
#include "b2bl_db.h"

#define TABLE_VERSION 3

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
static int load_script_scenario(modparam_t type, void* val);
static int load_extern_scenario(modparam_t type, void* val);
static int fixup_b2b_logic(void** param, int param_no);
static struct mi_root* mi_trigger_scenario(struct mi_root* cmd, void* param);
static struct mi_root* mi_b2b_bridge(struct mi_root* cmd, void* param);
static struct mi_root* mi_b2b_list(struct mi_root* cmd, void* param);
static struct mi_root* mi_b2b_terminate_call(struct mi_root* cmd, void* param);
static void b2bl_clean(unsigned int ticks, void* param);
static void b2bl_db_timer_update(unsigned int ticks, void* param);
int  b2b_init_request(struct sip_msg* msg, str* arg1, str* arg2, str* arg3,
		str* arg4, str* arg5, str* arg6);
int  b2b_bridge_request(struct sip_msg* msg, str* arg1, str* arg2);

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
enum b2bl_caller_type b2bl_caller;
unsigned int max_duration = 12*3600;

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

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"b2b_init_request", (cmd_function)b2b_init_request, 5 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 4 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 3 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 2 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 1 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 0 , 0               , 0 , REQUEST_ROUTE},
	{"b2b_bridge_request",(cmd_function)b2b_bridge_request,2,fixup_pvar_pvar , 0 , REQUEST_ROUTE},
	{"b2b_logic_bind",   (cmd_function)b2b_logic_bind,   1 , 0,  0,  0},
	{ 0,                 0,                              0 , 0 , 0,  0}
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

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "b2b_trigger_scenario", 0, mi_trigger_scenario,   0,  0,  0},
	{ "b2b_bridge",           0, mi_b2b_bridge,         0,  0,  0},
	{ "b2b_list",             0, mi_b2b_list,           0,  0,  0},
	{ "b2b_terminate_call",   0, mi_b2b_terminate_call, 0,  0,  0},
	{  0,                  0, 0,                        0,  0,  0}
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
	&deps,                          /* OpenSIPS module dependencies */
	cmds,                           /* exported functions */
	0,                              /* exported async functions */
	params,                         /* exported parameters */
	0,                              /* exported statistics */
	mi_cmds,                        /* exported MI functions */
	0,                              /* exported pseudo-variables */
	0,								/* exported transformations */
	0,                              /* extra processes */
	mod_init,                       /* module initialization function */
	(response_function) 0,          /* response handling function */
	(destroy_function) mod_destroy, /* destroy function */
	child_init                      /* per-child init function */
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

	if(b2bl_db_mode && db_url.s)
	{
		db_url.len = strlen(db_url.s);
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

	return 0;
}

void b2bl_db_timer_update(unsigned int ticks, void* param)
{
	b2b_logic_dump(0);
}

void b2bl_clean(unsigned int ticks, void* param)
{
	int i;
	b2bl_tuple_t* tuple, *tuple_next;
	unsigned int now;
	str bye = {BYE, BYE_LEN};
	b2b_req_data_t req_data;

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
					{
						memset(&req_data, 0, sizeof(b2b_req_data_t));
						PREP_REQ_DATA(tuple->bridge_entities[0]);
						req_data.method =&bye;
						b2b_api.send_request(&req_data);
					}
					if(!tuple->bridge_entities[1]->disconnected)
					{
						memset(&req_data, 0, sizeof(b2b_req_data_t));
						PREP_REQ_DATA(tuple->bridge_entities[1]);
						req_data.method =&bye;
						b2b_api.send_request(&req_data);
					}
				}
				b2bl_delete(tuple, i, 0);
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
		return -1;
	}
	scenario->id.len = strlen(scenario->id.s);
	LM_DBG("Loaded scenario with id = [%.*s]\n", scenario->id.len, scenario->id.s);

	attr.s = (char*)xmlNodeGetAttrContentByName(doc->children, "param");
	if(attr.s == NULL)
	{
		LM_ERR("XML scenario document not well formed. No id attribute found"
				" for root node\n");
		return -1;
	}
	attr.len = strlen(attr.s);

	if( str2int(&attr, &scenario->param_no) < 0)
	{
		LM_ERR("Failed to parse id attribute for scenario node. It must be an integer.\n");
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

	if(b2bl_db)
	{
		if(b2bl_db_mode==WRITE_BACK)
			b2b_logic_dump(1);
		b2bl_dbf.close(b2bl_db);
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


static int fixup_b2b_logic(void** param, int param_no)
{
	pv_elem_t *model;
	str s;
	str flags_s;
	int st;
	struct b2b_scen_fl *scf;

	if(param_no== 0)
		return 0;

	if(*param)
	{
		s.s = (char*)(*param);
		s.len = strlen(s.s);

		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR( "wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}

		/* the first parameter must be the scenario id and possible flags, must be a string */
		if(param_no == 1)
		{
			if(model->spec.type != PVT_NONE )
			{
				LM_ERR("The first parameter is not a string\n");
				return -1;
			}

			scf = prepare_b2b_scen_fl_struct();
			if (scf == NULL)
			{
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			scf->params.init_timeout = b2bl_th_init_timeout;

			if ( (flags_s.s = strchr(s.s,'/')) != NULL)
			{
				s.len = flags_s.s - s.s;
				flags_s.s++;
				flags_s.len = strlen(flags_s.s);

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

		*param = (void*)model;
		return 0;
	}
	LM_ERR( "null format\n");
	return E_UNSPEC;
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
		b2bl_cback_f cbf, void* cb_param)
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
				NULL, NULL, -1, &b2bl_key, INSERTDB_FLAG);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return 0;
	}
	tuple->cbf = cbf;
	tuple->cb_param = cb_param;
	tuple->lifetime = 60 + get_ticks();

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

	if(process_bridge_action(0, 0, tuple, xml_node) < 0)
	{
		LM_ERR("Failed to process bridge node");
		goto error;
	}
	lock_release(&b2bl_htable[hash_index].lock);
	return b2bl_key;

error:
	if(tuple)
		lock_release(&b2bl_htable[hash_index].lock);
	return 0;
}

static struct mi_root* mi_trigger_scenario(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str* args[MAX_SCENARIO_PARAMS];
	int i = 0;
	str scenario_name;

	node = cmd->node.kids;
	if(node == NULL)
		return 0;

	b2bl_caller = CALLER_MI;
	/* Get scenario ID */
	scenario_name = node->value;
	if(scenario_name.s == NULL || scenario_name.len== 0)
	{
		LM_ERR("Empty scenario name parameter\n");
		return init_mi_tree(404, "Empty scenario ID", 16);
	}
	node = node->next;

	memset(args, 0, MAX_SCENARIO_PARAMS* sizeof(str*));
	/* get the other parameters */
	while(i < MAX_SCENARIO_PARAMS && node)
	{
		if(node->value.s == NULL || node->value.len== 0)
			break;

		args[i++] = &node->value;

		node = node->next;
	}

	if(b2bl_bridge_extern(&scenario_name, args, 0, 0) == 0)
	{
		LM_ERR("Failed to initialize scenario\n");
		return 0;
	}
	return init_mi_tree(200, "OK", 2);
}


int  b2b_bridge_request(struct sip_msg* msg, str* p1, str* p2)
{
	pv_value_t pv_val;
	str key = {NULL, 0};
	int entity_no;

	if (p1 && (pv_get_spec_value(msg, (pv_spec_t *)p1, &pv_val) == 0))
	{
		if (pv_val.flags & PV_VAL_STR)
		{
			LM_DBG("got key:'%.*s'\n", pv_val.rs.len, pv_val.rs.s);
			key = pv_val.rs;
		} else {
			LM_ERR("Unable to get key from PV that is not a string\n");
			return -1;
		}
	} else {
		LM_ERR("Unable to get key from pv:%p\n", p1);
		return -1;
	}

	if (p2 && (pv_get_spec_value(msg, (pv_spec_t *)p2, &pv_val) == 0))
	{
		if (pv_val.flags & PV_VAL_INT)
		{
			entity_no = pv_val.ri;
			LM_DBG("got entity_no %d\n", entity_no);
		}
		else
		if (pv_val.flags & PV_VAL_STR) {
			if(str2int(&(pv_val.rs), (unsigned int*)&entity_no) != 0) {
				LM_ERR("Unable to get entity_no from pv '%.*s'i\n",
				pv_val.rs.len, pv_val.rs.s);
				return -1;
			}
		} else {
			LM_ERR("second pv not a str or int type\n");
			return -1;
		}
	} else {
		LM_ERR("Unable to get entity from pv:%p\n", p1);
		return -1;
	}
	return b2bl_bridge_msg(msg, &key, entity_no);
}

static struct mi_root* mi_b2b_terminate_call(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str key;

	node = cmd->node.kids;
	if(node == NULL)
		return 0;

	/* b2bl_key */
	key = node->value;
	if(key.s == NULL || key.len== 0)
	{
		LM_ERR("Wrong b2b_logic key parameter\n");
		return init_mi_tree(404, "Empty b2bl key", 14);
	}

	b2bl_terminate_call(&key);

	return init_mi_tree(200, "OK", 2);
}

/*
 * arguments: b2bl_key, new_dest, entity (1 - client)
 * */
static struct mi_root* mi_b2b_bridge(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str key;
	b2bl_tuple_t* tuple;
	str new_dest;
	str prov_media;
	unsigned int entity_no = 0;
	b2bl_entity_id_t* entity, *old_entity, *bridging_entity, *prov_entity = 0;
	struct sip_uri uri;
	str meth_inv = {INVITE, INVITE_LEN};
	str meth_bye = {BYE, BYE_LEN};
	unsigned int hash_index, local_index;
	str ok= str_init("ok");
	b2b_req_data_t req_data;
	b2b_rpl_data_t rpl_data;

	node = cmd->node.kids;
	if(node == NULL)
		return 0;

	/* b2bl_key */
	key = node->value;
	if(key.s == NULL || key.len== 0)
	{
		LM_ERR("Wrong b2b_logic key parameter\n");
		return init_mi_tree(404, "Empty b2bl key", 14);
	}

	/* new destination- must be a valid SIP URI */
	node = node->next;
	if(node == NULL)
		return 0;

	new_dest = node->value;
	if(new_dest.s == NULL || new_dest.len == 0)
	{
		LM_ERR("Empty new dest parameter\n");
		return init_mi_tree(404, "Empty parameter", 15);
	}

	if(parse_uri(new_dest.s, new_dest.len, &uri)< 0)
	{
		LM_ERR("Bad argument. Not a valid uri [%.*s]\n", new_dest.len, new_dest.s);
		return init_mi_tree(404, "Bad parameter", 13);
	}

	/* the last parameter is optional, if present and 1 - >
	 * means that destination from the current call must be
	 * bridged to the new destination */
	node = node->next;
	if(node)
	{
		if (node->value.len==1)
		{
			if(strncmp(node->value.s, "0", 1)==0)
				entity_no = 0;
			else if(strncmp(node->value.s, "1", 1)==0)
				entity_no = 1;
			else
				return init_mi_tree(404, "Invalid entity no parameter", 27);
		}
		else
		{
			return init_mi_tree(404, "Invalid entity no parameter", 27);
		}
		node = node->next;
		if (node)
		{
			/* parse new uri */
			prov_media = node->value;
			if(parse_uri(node->value.s, node->value.len, &uri)< 0)
			{
				LM_ERR("Bad argument. Not a valid provisional media uri [%.*s]\n",
					   new_dest.len, new_dest.s);
				return init_mi_tree(404, "Bad parameter", 13);
			}
			prov_entity = b2bl_create_new_entity(B2B_CLIENT,
							0, &prov_media, 0, 0, 0, 0, 0);
			if (!prov_entity) {
				LM_ERR("Failed to create new b2b entity\n");
				goto free;
			}
			if (node->next)
				return init_mi_tree(404, MI_SSTR(MI_MISSING_PARM));
		}
	}

	if(b2bl_parse_key(&key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key '%.*s'\n", key.len, key.s);
		goto free;
	}

	entity = b2bl_create_new_entity(B2B_CLIENT, 0, &new_dest, 0, 0, 0, 0, 0);
	if(entity == NULL)
	{
		LM_ERR("Failed to create new b2b entity\n");
		goto free;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
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

	memset(&req_data, 0, sizeof(b2b_req_data_t));
	PREP_REQ_DATA(bridging_entity);
	req_data.method =&meth_inv;
	b2b_api.send_request(&req_data);

	lock_release(&b2bl_htable[hash_index].lock);

	return init_mi_tree(200, "OK", 2);

error:
	if(tuple)
		b2b_mark_todel(tuple);
	lock_release(&b2bl_htable[hash_index].lock);
free:
	if (prov_entity)
		shm_free(prov_entity);
	return 0;
}

static inline int internal_mi_print_b2bl_entity_id(struct mi_node *node1, b2bl_entity_id_t *c)
{
	int len;
	char* p;
	struct mi_node *node2=NULL;
	struct mi_attr* attr;

	if (c->scenario_id.s && c->scenario_id.len != 0)
	{
		attr = add_mi_attr(node1, MI_DUP_VALUE, "scenario_id", 11,
				c->scenario_id.s, c->scenario_id.len);
		if(attr == NULL) goto error;
	}
	if (c->key.s && c->key.len != 0)
	{
		attr = add_mi_attr(node1, MI_DUP_VALUE, "key", 3,
					c->key.s, c->key.len);
		if(attr == NULL) goto error;
	}
	p = int2str((unsigned long)(c->disconnected), &len);
	attr = add_mi_attr(node1, MI_DUP_VALUE, "disconnected", 12, p, len);
	if(attr == NULL) goto error;
	p = int2str((unsigned long)(c->state), &len);
	attr = add_mi_attr(node1, MI_DUP_VALUE, "state", 5, p, len);
	if(attr == NULL) goto error;
	p = int2str((unsigned long)(c->no), &len);
	attr = add_mi_attr(node1, MI_DUP_VALUE, "no", 2, p, len);
	if(attr == NULL) goto error;
	p = int2str((unsigned long)(c->type), &len);
	attr = add_mi_attr(node1, MI_DUP_VALUE, "type", 4, p, len);
	if(attr == NULL) goto error;

	if (c->peer)
	{
		if (c->peer->key.s && c->peer->key.len != 0)
		{
			attr = add_mi_attr(node1, MI_DUP_VALUE, "peer", 4,
				c->peer->key.s, c->peer->key.len);
			if(attr == NULL) goto error;
		}
	}

	if (c->to_uri.s && c->to_uri.len != 0)
	{
		node2 = add_mi_node_child(node1, MI_DUP_VALUE, "to_uri", 6,
						c->to_uri.s, c->to_uri.len);
		if(node2 == NULL) goto error;
	}
	if (c->from_uri.s && c->from_uri.len != 0)
	{
		node2 = add_mi_node_child(node1, MI_DUP_VALUE, "from_uri", 8,
						c->from_uri.s, c->from_uri.len);
		if(node2 == NULL) goto error;
	}
	if (c->from_dname.s && c->from_dname.len != 0)
	{
		node2 = add_mi_node_child(node1, MI_DUP_VALUE, "from_dname", 10,
						c->from_dname.s, c->from_dname.len);
		if(node2 == NULL) goto error;
	}

	return 0;
error:
	LM_ERR("failed to add node\n");
	return -1;
}

static struct mi_root* mi_b2b_list(struct mi_root* cmd, void* param)
{
	int i, len, index;
	char* p;
	b2bl_tuple_t* tuple;
	struct mi_root *rpl_tree;
	struct mi_node *node=NULL, *node1=NULL, *rpl=NULL, *node_a=NULL;
	struct mi_attr* attr;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	for(i = 0; i< b2bl_hsize; i++)
	{
		lock_get(&b2bl_htable[i].lock);
		tuple = b2bl_htable[i].first;
		while(tuple)
		{
			p = int2str((unsigned long)(tuple->id), &len);
			node = add_mi_node_child(rpl, MI_DUP_VALUE, "tuple", 5, p, len);
			if(node == NULL) goto error;
			attr = add_mi_attr(node, MI_DUP_VALUE, "key", 3,
					tuple->key->s, tuple->key->len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(tuple->scenario_state), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "scenario_state", 14, p, len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(tuple->lifetime), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "lifetime", 8, p, len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(tuple->db_flag), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "db_flag", 7, p, len);
			if(attr == NULL) goto error;

			if (tuple->scenario)
			{
				attr = add_mi_attr(node, MI_DUP_VALUE, "scenario", 8,
						tuple->scenario->id.s, tuple->scenario->id.len);
				if(attr == NULL) goto error;
				p = int2str((unsigned long)(tuple->next_scenario_state), &len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "next_scenario_state", 19,
						p, len);
				if(attr == NULL) goto error;
			}

			for (node_a=NULL,index=0; index < MAX_B2BL_ENT; index++)
			{
				if (tuple->servers[index] != NULL)
				{
					if (node_a==NULL) {
						node_a = add_mi_node_child(node, MI_IS_ARRAY,
							"SERVERS", 7, NULL, 0);
						if (node_a==NULL) goto error;
					}
					p = int2str((unsigned long)(index), &len);
					node1 = add_mi_node_child(node_a, MI_DUP_VALUE,
						"server", 6, p, len);
					if(node1 == NULL) goto error;
					if (internal_mi_print_b2bl_entity_id(node1,
							tuple->servers[index])!=0)
						goto error;
				}
			}
			for (node_a=NULL,index=0; index < MAX_B2BL_ENT; index++)
			{
				if (tuple->clients[index] != NULL)
				{
					if (node_a==NULL) {
						node_a = add_mi_node_child(node, MI_IS_ARRAY,
							"CLIENTS", 7, NULL, 0);
						if (node_a==NULL) goto error;
					}
					p = int2str((unsigned long)(index), &len);
					node1 = add_mi_node_child(node_a, MI_DUP_VALUE,
						"client", 6, p, len);
					if(node1 == NULL) goto error;
					if (internal_mi_print_b2bl_entity_id(node1,
							tuple->clients[index])!=0)
						goto error;
				}
			}
			for (node_a=NULL,index=0; index < MAX_BRIDGE_ENT; index++)
			{
				if (tuple->bridge_entities[index] != NULL)
				{
					if (node_a==NULL) {
						node_a = add_mi_node_child(node, MI_IS_ARRAY,
							"BRIDGE_ENTITIES", 15, NULL, 0);
						if (node_a==NULL) goto error;
					}
					p = int2str((unsigned long)(index), &len);
					node1 = add_mi_node_child(node_a, MI_DUP_VALUE,
							"bridge_entitie", 14, p, len);
					if(node1 == NULL) goto error;
					if (internal_mi_print_b2bl_entity_id(node1,
							tuple->bridge_entities[index])!=0)
						goto error;
				}
			}
			tuple = tuple->next;
		}
		lock_release(&b2bl_htable[i].lock);
	}
	return rpl_tree;
error:
	lock_release(&b2bl_htable[i].lock);
	LM_ERR("Unable to create reply\n");
	free_mi_tree(rpl_tree);
	return NULL;
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

