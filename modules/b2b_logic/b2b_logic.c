/*
 * $Id: b2b_logic.c $
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 *  2010-11-02  new mi function: mi_b2b_list (Ovidiu Sas)
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
#include "../../mem/mem.h"

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"
#include "b2b_load.h"

#define TABLE_VERSION 1
#define B2BL_FETCH_SIZE  128

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
static int  b2b_logic_restore(void);
static void b2b_logic_dump(int no_lock);
static int load_script_scenario(modparam_t type, void* val);
static int load_extern_scenario(modparam_t type, void* val);
static int fixup_b2b_logic(void** param, int param_no);
static struct mi_root* mi_trigger_scenario(struct mi_root* cmd, void* param);
static struct mi_root* mi_b2b_bridge(struct mi_root* cmd, void* param);
static struct mi_root* mi_b2b_list(struct mi_root* cmd, void* param);
void b2bl_clean(unsigned int ticks, void* param);
void b2bl_db_update(unsigned int ticks, void* param);
int  b2b_init_request(struct sip_msg* msg, str* arg1, str* arg2, str* arg3,
		str* arg4, str* arg5, str* arg6);

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
/* The list of the headers that are passed on the other side by default */
static str default_headers[HDR_DEFAULT_LEN]=
   {{"Content-Type",12},
   {"Supported", 9},
   {"Allow", 5},
   {"Proxy-Require", 13},
   {"Session-Expires", 15},
   {"Min-SE", 6},
   {"Require", 7},
   {"RSeq", 4},
   {"Max-Forwards", 12}
};
int use_init_sdp = 0;
enum b2bl_caller_type b2bl_caller;
static unsigned int max_duration = 12*3600;

static str db_url= {0, 0};
static db_con_t *b2bl_db = NULL;
static db_func_t b2bl_dbf;
static str dbtable= str_init("b2b_logic");

static str str_key_col         = str_init("si_key");
static str str_scenario_col    = str_init("scenario");
static str str_sstate_col      = str_init("sstate");
static str str_next_sstate_col = str_init("next_sstate");
static str str_sparam0_col     = str_init("sparam0");
static str str_sparam1_col     = str_init("sparam1");
static str str_sparam2_col     = str_init("sparam2");
static str str_sparam3_col     = str_init("sparam3");
static str str_sparam4_col     = str_init("sparam4");
static str str_sdp_col         = str_init("sdp");
static str str_e1_type_col     = str_init("e1_type");
static str str_e1_sid_col      = str_init("e1_sid");
static str str_e1_to_col       = str_init("e1_to");
static str str_e1_from_col     = str_init("e1_from");
static str str_e1_key_col      = str_init("e1_key");
static str str_e2_type_col     = str_init("e2_type");
static str str_e2_sid_col      = str_init("e2_sid");
static str str_e2_to_col       = str_init("e2_to");
static str str_e2_from_col     = str_init("e2_from");
static str str_e2_key_col      = str_init("e2_key");
static str str_e3_type_col     = str_init("e3_type");
static str str_e3_sid_col      = str_init("e3_sid");
static str str_e3_to_col       = str_init("e3_to");
static str str_e3_from_col     = str_init("e3_from");
static str str_e3_key_col      = str_init("e3_key");

#define DB_COLS_NO  25

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"b2b_init_request", (cmd_function)b2b_init_request, 5 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 4 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 3 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 2 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 1 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 0 , 0               , 0 , REQUEST_ROUTE},
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
	{"use_init_sdp",    INT_PARAM,                &use_init_sdp              },
	{"db_url",          STR_PARAM,                &db_url.s                  },
	{"dbtable",         STR_PARAM,                &dbtable.s                 },
	{"max_duration",    INT_PARAM,                &max_duration              },
	{0,                    0,                          0                     }
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "b2b_trigger_scenario", mi_trigger_scenario, 0,  0,  0},
	{ "b2b_bridge",           mi_b2b_bridge,       0,  0,  0},
	{ "b2b_list",             mi_b2b_list,         0,  0,  0},
	{  0,                  0,                      0,  0,  0}
};

/** Module interface */
struct module_exports exports= {
	"b2b_logic",                    /* module name */
	MODULE_VERSION,                 /* module version */
	DEFAULT_DLFLAGS,                /* dlopen flags */
	cmds,                           /* exported functions */
	params,                         /* exported parameters */
	0,                              /* exported statistics */
	mi_cmds,                        /* exported MI functions */
	0,                              /* exported pseudo-variables */
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
	int i = 0, j;

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

	if(init_b2bl_htable() < 0)
	{
		LM_ERR("Failed to initialize b2b logic hash table\n");
		return -1;
	}

	if(b2b_clean_period < 0)
	{
		LM_ERR("Wrong parameter - b2b_clean_period [%d]\n", b2b_clean_period);
		return -1;
	}
	if(b2b_update_period < 0)
	{
		LM_ERR("Wrong parameter - b2b_update_period [%d]\n", b2b_update_period);
		return -1;
	}

	if(db_url.s)
		db_url.len = strlen(db_url.s);
	else
	{
		LM_ERR("DB_URL parameter not set\n");
		return -1;
	}
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
	if(db_check_table_version(&b2bl_dbf, b2bl_db, &dbtable, TABLE_VERSION) < 0)
	{
		LM_ERR("error during table version check\n");
		return -1;
	}

	/* reload data */
	if(b2b_logic_restore() < 0)
	{
		LM_ERR("Failed to restore data from database\n");
		return -1;
	}

	if(b2bl_db)
		b2bl_dbf.close(b2bl_db);
	b2bl_db = NULL;

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

	register_timer(b2bl_clean, 0, b2b_clean_period);
	register_timer(b2bl_db_update, 0, b2b_update_period);

	return 0;
}

void b2bl_db_update(unsigned int ticks, void* param)
{
	b2b_logic_dump(0);
}
void b2bl_clean(unsigned int ticks, void* param)
{
	int i;
	b2bl_tuple_t* tuple, *tuple_next;
	unsigned int now;
	str bye = {BYE, BYE_LEN};

	now = get_ticks();

	for(i = 0; i< b2bl_hsize; i++)
	{
		lock_get(&b2bl_htable[i].lock);
		tuple = b2bl_htable[i].first;
		while(tuple)
		{
			tuple_next = tuple->next;
			if((tuple->lifetime > 0 && tuple->lifetime < now)
					|| ((now - tuple->insert_time) > max_duration))  /* if an expired dialog */
			{
				LM_INFO("Found an expired dialog. Send BYE in both sides and delete\n");
				if(tuple->bridge_entities[0] && tuple->bridge_entities[1] && !tuple->to_del)
				{
					if(tuple->bridge_entities[0]->dlginfo &&
							tuple->bridge_entities[0]->dlginfo->totag.s &&
							!tuple->bridge_entities[0]->disconnected)
						b2b_api.send_request(tuple->bridge_entities[0]->type,
							&tuple->bridge_entities[0]->key, &bye, 0, 0,
							 tuple->bridge_entities[0]->dlginfo);
					if(tuple->bridge_entities[1]->dlginfo &&
							tuple->bridge_entities[1]->dlginfo->totag.s &&
							!tuple->bridge_entities[1]->disconnected)
						b2b_api.send_request(tuple->bridge_entities[1]->type,
						&tuple->bridge_entities[1]->key, &bye, 0, 0,
						tuple->bridge_entities[1]->dlginfo);
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
		b2b_logic_dump(1);

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
		pkg_free(scenario);
		scenario = next;
	}

	destroy_b2bl_htable();
}

static int child_init(int rank)
{
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

static int fixup_b2b_logic(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

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

		/* the first parameter must be the scenario id and must be a string */
		if(param_no == 1)
		{
			if(model->spec.type != PVT_NONE )
			{
				LM_ERR("The first parameter is not a string\n");
				return -1;
			}
			if(s.len == B2B_TOP_HIDING_SCENARY_LEN &&
				strncmp(s.s,B2B_TOP_HIDING_SCENARY,B2B_TOP_HIDING_SCENARY_LEN)==0)
			{
				*param = NULL;
				return 0;
			}
			*param = get_scenario_id_list(&s, script_scenarios);
			if(*param)
				return 0;
			LM_ERR("Wrong Scenary ID. No scenario with this ID [%.*s]\n", s.len, s.s);
			return E_UNSPEC;
		}

		*param = (void*)model;
		return 0;
	}
	LM_ERR( "null format\n");
	return E_UNSPEC;
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
	tuple = b2bl_insert_new(0, hash_index, scenario_struct, args, 0, &b2bl_key);
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
	str* args[B2B_INIT_MAX_PARAMNO];
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

	memset(args, 0, B2B_INIT_MAX_PARAMNO* sizeof(str*));
	/* get the other parameters */
	while(i < B2B_INIT_MAX_PARAMNO && node)
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


/*
 * arguments: b2bl_key, new_dest, entity (1 - client)
 * */
static struct mi_root* mi_b2b_bridge(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str key;
	b2bl_tuple_t* tuple;
	str new_dest;
	b2bl_entity_id_t* entity, *old_entity;
	struct sip_uri uri;
	str meth_inv = {INVITE, INVITE_LEN};
	str meth_bye = {BYE, BYE_LEN};
	unsigned int hash_index, local_index;
	str ok= str_init("ok");

	node = cmd->node.kids;
	if(node == NULL)
		return 0;

	/* scenario ID */
	key = node->value;
	if(key.s == NULL || key.len== 0)
	{
		LM_ERR("Wrong dialog id parameter\n");
		return init_mi_tree(404, "Empty dialog ID", 15);
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
		
	}
	if(b2bl_parse_key(&key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return 0;
	}

	entity = b2bl_create_new_entity(B2B_CLIENT, 0, &new_dest, 0, 0, 0, 0);
	if(entity == NULL)
	{
		LM_ERR("Failed to create new b2b entity\n");
		return 0;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	/* send BYE to old client */
	old_entity = tuple->clients;
	if(old_entity == NULL)
	{
		LM_ERR("Wrong dialog id\n");
		goto error;
	}
	if(old_entity->disconnected)
	{
		b2b_api.send_reply(old_entity->type, &old_entity->key,
				200, &ok, 0, 0, old_entity->dlginfo);
	}
	else
	{
		old_entity->disconnected = 1;
		b2b_api.send_request(old_entity->type, &old_entity->key,
				&meth_bye, 0, 0, old_entity->dlginfo);
	}
	old_entity->peer = NULL;

	tuple->bridge_entities[0]= tuple->server;
	tuple->bridge_entities[1]= entity;

	tuple->server->peer = entity;
	entity->peer = tuple->server;

	tuple->scenario_state = B2B_BRIDGING_STATE;


	b2b_api.send_request(B2B_SERVER, &tuple->server->key, &meth_inv,
				 0, 0, tuple->server->dlginfo);

	lock_release(&b2bl_htable[hash_index].lock);

	return init_mi_tree(200, "OK", 2);

error:
	lock_release(&b2bl_htable[hash_index].lock);
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
	b2bl_entity_id_t* c;
	struct mi_root *rpl_tree;
	struct mi_node *node=NULL, *node1=NULL, *rpl=NULL;
	struct mi_attr* attr;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;

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
			if (tuple->scenario)
			{
				attr = add_mi_attr(node, MI_DUP_VALUE, "scenario", 8,
						tuple->scenario->id.s, tuple->scenario->id.len);
				if(attr == NULL) goto error;
				p = int2str((unsigned long)(tuple->scenario_state), &len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "scenario_state", 14,
						p, len);
				if(attr == NULL) goto error;
				p = int2str((unsigned long)(tuple->next_scenario_state), &len);
				attr = add_mi_attr(node, MI_DUP_VALUE, "next_scenario_state", 19,
						p, len);
				if(attr == NULL) goto error;
			}

			c = tuple->server;
			index = 0;
			while(c)
			{
				p = int2str((unsigned long)(index), &len);
				node1 = add_mi_node_child(node, MI_DUP_VALUE, "server", 6, p, len);
				if(node1 == NULL) goto error;
				if (internal_mi_print_b2bl_entity_id(node1, c)!=0)
					goto error;
				index++;
				c = c->next;
			}

			c = tuple->clients;
			index = 0;
			while(c)
			{
				p = int2str((unsigned long)(index), &len);
				node1 = add_mi_node_child(node, MI_DUP_VALUE, "client", 6, p, len);
				if(node1 == NULL) goto error;
				if (internal_mi_print_b2bl_entity_id(node1, c)!=0)
					goto error;
				index++;
				c = c->next;
			}
			for (index = 0; index < 3; index++)
			{
				if (tuple->bridge_entities[index] != NULL)
				{
					p = int2str((unsigned long)(index), &len);
					node1 = add_mi_node_child(node, MI_DUP_VALUE,
							"bridge_entities", 15, p, len);
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


void b2bl_db_delete(b2bl_tuple_t* tuple)
{
	static db_key_t qcols[1];
	db_val_t qvals[1];

	if(!tuple || !tuple->key|| tuple->db_flag==INSERTDB_FLAG)
		return;

	LM_DBG("Delete key = %.*s\n", tuple->key->len, tuple->key->s);

	if(b2bl_dbf.use_table(b2bl_db, &dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}
	memset(qvals, 0, sizeof(db_val_t));

	qcols[0]             = &str_key_col;
	qvals[0].type        = DB_STR;
	qvals[0].val.str_val = *tuple->key;

	if(b2bl_dbf.delete(b2bl_db, qcols, 0, qvals, 1) < 0)
	{
		LM_ERR("Failed to delete from database table\n");
	}
}

void b2b_logic_dump(int no_lock)
{
	b2bl_tuple_t* tuple;
	static db_key_t qcols[DB_COLS_NO];
	db_val_t qvals[DB_COLS_NO];
	int key_col, scenario_col, sstate_col, next_sstate_col, sparam0_col;
	int sparam1_col, sparam2_col, sparam3_col, sparam4_col, sdp_col;
	int e1_type_col, e1_sid_col, e1_to_col, e1_from_col, e1_key_col;
	int e2_type_col, e2_sid_col, e2_to_col, e2_from_col, e2_key_col;
	int e3_type_col, e3_sid_col, e3_to_col, e3_from_col, e3_key_col;
	int n_query_cols= 0;
	int n_insert_cols, n_query_update;
	int i;

	if(b2bl_dbf.use_table(b2bl_db, &dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}
	memset(qvals, 0, DB_COLS_NO* sizeof(db_val_t));

	qcols[key_col= n_query_cols++]         = &str_key_col;
	qvals[key_col].type                    = DB_STR;
	qcols[scenario_col= n_query_cols++]    = &str_scenario_col;
	qvals[scenario_col].type               = DB_STR;
	qcols[sparam0_col= n_query_cols++]     = &str_sparam0_col;
	qvals[sparam0_col].type                = DB_STR;
	qcols[sparam1_col= n_query_cols++]     = &str_sparam1_col;
	qvals[sparam1_col].type                = DB_STR;
	qcols[sparam2_col= n_query_cols++]     = &str_sparam2_col;
	qvals[sparam2_col].type                = DB_STR;
	qcols[sparam3_col= n_query_cols++]     = &str_sparam3_col;
	qvals[sparam3_col].type                = DB_STR;
	qcols[sparam4_col= n_query_cols++]     = &str_sparam4_col;
	qvals[sparam4_col].type                = DB_STR;
	qcols[sdp_col= n_query_cols++]         = &str_sdp_col;
	qvals[sdp_col].type                    = DB_STR;
	n_query_update                         = n_query_cols;
	qcols[sstate_col= n_query_cols++]      = &str_sstate_col;
	qvals[sstate_col].type                 = DB_INT;
	qcols[next_sstate_col= n_query_cols++] = &str_next_sstate_col;
	qvals[next_sstate_col].type            = DB_INT;
	qcols[e1_type_col= n_query_cols++]     = &str_e1_type_col;
	qvals[e1_type_col].type                = DB_INT;
	qcols[e1_sid_col= n_query_cols++]      = &str_e1_sid_col;
	qvals[e1_sid_col].type                 = DB_STR;
	qcols[e1_to_col= n_query_cols++]       = &str_e1_to_col;
	qvals[e1_to_col].type                  = DB_STR;
	qcols[e1_from_col= n_query_cols++]     = &str_e1_from_col;
	qvals[e1_from_col].type                = DB_STR;
	qcols[e1_key_col= n_query_cols++]      = &str_e1_key_col;
	qvals[e1_key_col].type                 = DB_STR;
	qcols[e2_type_col= n_query_cols++]     = &str_e2_type_col;
	qvals[e2_type_col].type                = DB_INT;
	qcols[e2_sid_col= n_query_cols++]      = &str_e2_sid_col;
	qvals[e2_sid_col].type                 = DB_STR;
	qcols[e2_to_col= n_query_cols++]       = &str_e2_to_col;
	qvals[e2_to_col].type                  = DB_STR;
	qcols[e2_from_col= n_query_cols++]     = &str_e2_from_col;
	qvals[e2_from_col].type                = DB_STR;
	qcols[e2_key_col= n_query_cols++]      = &str_e2_key_col;
	qvals[e2_key_col].type                 = DB_STR;
	qcols[e3_type_col= n_query_cols++]     = &str_e3_type_col;
	qvals[e3_type_col].type                = DB_INT;
	qcols[e3_sid_col= n_query_cols++]      = &str_e3_sid_col;
	qvals[e3_sid_col].type                 = DB_STR;
	qcols[e3_to_col= n_query_cols++]       = &str_e3_to_col;
	qvals[e3_to_col].type                  = DB_STR;
	qcols[e3_from_col= n_query_cols++]     = &str_e3_from_col;
	qvals[e3_from_col].type                = DB_STR;
	qcols[e3_key_col= n_query_cols++]      = &str_e3_key_col;
	qvals[e3_key_col].type                 = DB_STR;

	for(i = 0; i< b2bl_hsize; i++)
	{
		if(!no_lock)
			lock_get(&b2bl_htable[i].lock);
		tuple = b2bl_htable[i].first;
		while(tuple)
		{
			/* check the state of the scenario instantiation */
			if(tuple->db_flag == NO_UPDATEDB_FLAG)
				goto next;

			if(tuple->key == NULL)
			{
				LM_ERR("No key stored\n");
				goto next;
			}
			if(tuple->bridge_entities[0]==NULL || tuple->bridge_entities[1]== NULL)
			{
				LM_ERR("Bridge entities is NULL\n");
				if(tuple->bridge_entities[0]==NULL)
					LM_DBG("0 NULL\n");
				else
					LM_DBG("1 NULL\n");
				goto next;
			}

			qvals[key_col].val.str_val           = *tuple->key;
			if(tuple->db_flag == INSERTDB_FLAG)
			{
				if(tuple->scenario)
					qvals[scenario_col].val.str_val  = tuple->scenario->id;
				qvals[sparam0_col].val.str_val       = tuple->scenario_params[0];
				qvals[sparam1_col].val.str_val       = tuple->scenario_params[1];
				qvals[sparam2_col].val.str_val       = tuple->scenario_params[2];
				qvals[sparam3_col].val.str_val       = tuple->scenario_params[3];
				qvals[sparam4_col].val.str_val       = tuple->scenario_params[4];
				qvals[sdp_col].val.str_val           = tuple->sdp;
			}

			qvals[sstate_col].val.int_val        = tuple->scenario_state;
			qvals[next_sstate_col].val.int_val   = tuple->next_scenario_state;
			qvals[e1_type_col].val.int_val       = tuple->bridge_entities[0]->type;
			qvals[e1_sid_col].val.str_val        = tuple->bridge_entities[0]->scenario_id;
			qvals[e1_to_col].val.str_val         = tuple->bridge_entities[0]->to_uri;
			qvals[e1_from_col].val.str_val       = tuple->bridge_entities[0]->from_uri;
			qvals[e1_key_col].val.str_val        = tuple->bridge_entities[0]->key;
			qvals[e2_type_col].val.int_val       = tuple->bridge_entities[1]->type;
			qvals[e2_sid_col].val.str_val        = tuple->bridge_entities[1]->scenario_id;
			qvals[e2_to_col].val.str_val         = tuple->bridge_entities[1]->to_uri;
			qvals[e2_from_col].val.str_val       = tuple->bridge_entities[1]->from_uri;
			qvals[e2_key_col].val.str_val        = tuple->bridge_entities[1]->key;

			n_insert_cols = e2_key_col+1;

			if(tuple->bridge_entities[2])
			{
				qvals[e3_type_col].val.int_val       = tuple->bridge_entities[2]->type;
				qvals[e3_sid_col].val.str_val        = tuple->bridge_entities[2]->scenario_id;
				qvals[e3_to_col].val.str_val         = tuple->bridge_entities[2]->to_uri;
				qvals[e3_from_col].val.str_val       = tuple->bridge_entities[2]->from_uri;
				qvals[e3_key_col].val.str_val        = tuple->bridge_entities[2]->key;
				n_insert_cols = n_query_cols;
			}

			/* insert into database */
			if(tuple->db_flag == INSERTDB_FLAG)
			{
				if(b2bl_dbf.insert(b2bl_db, qcols, qvals, n_insert_cols)< 0)
				{
					LM_ERR("Sql insert failed\n");
					if(!no_lock)
						lock_release(&b2bl_htable[i].lock);
					return;
				}
			}
			else
			{
				/*do update */
				if(b2bl_dbf.update(b2bl_db, qcols, 0, qvals, qcols+n_query_update,
					qvals+n_query_update, 1, n_insert_cols - n_query_update)< 0)
				{
					LM_ERR("Sql update failed\n");
					if(!no_lock)
						lock_release(&b2bl_htable[i].lock);
					return;
				}
			}
			tuple->db_flag = NO_UPDATEDB_FLAG;
next:
			tuple = tuple->next;
		}
		if(!no_lock)
			lock_release(&b2bl_htable[i].lock);
	}
}

int b2bl_add_tuple(b2bl_tuple_t* tuple, str* params[])
{
	b2bl_tuple_t* shm_tuple= NULL;
	unsigned int hash_index, local_index;
	str* b2bl_key;
	b2bl_entity_id_t* entity;
	int i;
	b2b_notify_t cback;
	str* client_id = NULL;

	LM_DBG("Add tuple key [%.*s]\n", tuple->key->len, tuple->key->s);
	if(b2bl_parse_key(tuple->key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Wrong formatted b2b logic key\n");
		return -1;
	}
	shm_tuple = b2bl_insert_new(0, hash_index, tuple->scenario, params,
			(tuple->sdp.s?&tuple->sdp:0), &b2bl_key);
	if(shm_tuple == NULL)
	{
		LM_ERR("Failed to insert new tuple\n");
		return -1;
	}
	lock_release(&b2bl_htable[hash_index].lock);
	shm_tuple->scenario_state= tuple->scenario_state;
	shm_tuple->next_scenario_state= tuple->next_scenario_state;

	/* add entities */
	for(i=0; i< 3; i++)
	{
		if(!tuple->bridge_entities[i]->to_uri.len)
			continue;
		LM_DBG("Restore logic info i=%d\n", i);

		if(tuple->bridge_entities[i]->type == B2B_SERVER)
			cback = b2b_server_notify;
		else
			cback = b2b_client_notify;

		/* restore to the entities from b2b_entities module the parameter and callback function */
		if(b2b_api.restore_logic_info(tuple->bridge_entities[i]->type,
			&tuple->bridge_entities[i]->key, cback)< 0)
		{
			LM_DBG("Failed to restore logic info for entity %d\n", i);
		}
		entity= b2bl_create_new_entity(tuple->bridge_entities[i]->type,
			&tuple->bridge_entities[i]->key,&tuple->bridge_entities[i]->to_uri,
			&tuple->bridge_entities[i]->from_uri, 0, &tuple->bridge_entities[i]->scenario_id, 0);
		if(client_id)
			pkg_free(client_id);
		if(entity == NULL)
		{
			LM_ERR("Failed to create entity %d\n", i);
			goto error;
		}
		shm_tuple->bridge_entities[i]= entity;
		/* put the pointer in clients or servers array */
		if(tuple->bridge_entities[i]->type == B2B_SERVER)
		{
			shm_tuple->server = entity;
		}
		else
		{
			entity->next = shm_tuple->clients;
			shm_tuple->clients = entity;
		}
	}
	if(shm_tuple->bridge_entities[1])
		shm_tuple->bridge_entities[1]->peer = shm_tuple->bridge_entities[0];
	if(shm_tuple->bridge_entities[0])
		shm_tuple->bridge_entities[0]->peer = shm_tuple->bridge_entities[1];

	return 0;
error:
	shm_free(shm_tuple);
	return -1;
}

int b2b_logic_restore(void)
{
	static db_key_t result_cols[DB_COLS_NO];
	int key_col, scenario_col, sstate_col, next_sstate_col, sdp_col;
	int sparam0_col, sparam1_col, sparam2_col, sparam3_col, sparam4_col;
	int e1_type_col, e1_sid_col, e1_to_col, e1_from_col, e1_key_col;
	int e2_type_col, e2_sid_col, e2_to_col, e2_from_col, e2_key_col;
	int e3_type_col, e3_sid_col, e3_to_col, e3_from_col, e3_key_col;
	int n_result_cols= 0;
	int i;
	int nr_rows;
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	b2bl_tuple_t tuple;
	str b2bl_key;
	str scenario_id;
	b2bl_entity_id_t bridge_entities[3];
	str* params[5];

	if(b2bl_db == NULL)
	{
		LM_DBG("NULL database connection\n");
		return 0;
	}
	if(b2bl_dbf.use_table(b2bl_db, &dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}

	result_cols[key_col        = n_result_cols++] =&str_key_col;
	result_cols[scenario_col   = n_result_cols++] =&str_scenario_col;
	result_cols[sstate_col     = n_result_cols++] =&str_sstate_col;
	result_cols[next_sstate_col= n_result_cols++] =&str_next_sstate_col;
	result_cols[sparam0_col    = n_result_cols++] =&str_sparam0_col;
	result_cols[sparam1_col    = n_result_cols++] =&str_sparam1_col;
	result_cols[sparam2_col    = n_result_cols++] =&str_sparam2_col;
	result_cols[sparam3_col    = n_result_cols++] =&str_sparam3_col;
	result_cols[sparam4_col    = n_result_cols++] =&str_sparam4_col;
	result_cols[sdp_col        = n_result_cols++] =&str_sdp_col;
	result_cols[e1_type_col    = n_result_cols++] =&str_e1_type_col;
	result_cols[e1_sid_col     = n_result_cols++] =&str_e1_sid_col;
	result_cols[e1_to_col      = n_result_cols++] =&str_e1_to_col;
	result_cols[e1_from_col    = n_result_cols++] =&str_e1_from_col;
	result_cols[e1_key_col     = n_result_cols++] =&str_e1_key_col;
	result_cols[e2_type_col    = n_result_cols++] =&str_e2_type_col;
	result_cols[e2_sid_col     = n_result_cols++] =&str_e2_sid_col;
	result_cols[e2_to_col      = n_result_cols++] =&str_e2_to_col;
	result_cols[e2_from_col    = n_result_cols++] =&str_e2_from_col;
	result_cols[e2_key_col     = n_result_cols++] =&str_e2_key_col;
	result_cols[e3_type_col    = n_result_cols++] =&str_e3_type_col;
	result_cols[e3_sid_col     = n_result_cols++] =&str_e3_sid_col;
	result_cols[e3_to_col      = n_result_cols++] =&str_e3_to_col;
	result_cols[e3_from_col    = n_result_cols++] =&str_e3_from_col;
	result_cols[e3_key_col     = n_result_cols++] =&str_e3_key_col;

	if (DB_CAPABILITY(b2bl_dbf, DB_CAP_FETCH))
	{
		if(b2bl_dbf.query(b2bl_db,0,0,0,result_cols, 0,
			n_result_cols, 0, 0) < 0) 
		{
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		if(b2bl_dbf.fetch_result(b2bl_db,&result,B2BL_FETCH_SIZE)<0)
		{
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	}
	else
	{
		if (b2bl_dbf.query (b2bl_db, 0, 0, 0,result_cols,0, n_result_cols,
					0, &result) < 0)
		{
			LM_ERR("querying presentity\n");
			return -1;
		}
	}

	nr_rows = RES_ROW_N(result);

	do {
		LM_DBG("loading information from database %i records\n", nr_rows);

		rows = RES_ROWS(result);

		/* for every row */
		for(i=0; i<nr_rows; i++)
		{
			row_vals = ROW_VALUES(rows +i);
			memset(&tuple, 0, sizeof(b2bl_tuple_t));

			b2bl_key.s = (char*)row_vals[key_col].val.string_val;
			b2bl_key.len = b2bl_key.s?strlen(b2bl_key.s):0;

			tuple.key = &b2bl_key;
			if(row_vals[scenario_col].val.string_val)
			{
				scenario_id.s = (char*)row_vals[scenario_col].val.string_val;
				scenario_id.len = strlen(scenario_id.s);
				tuple.scenario = get_scenario_id(&scenario_id);
			}
			memset(bridge_entities, 0, 3*sizeof(b2bl_entity_id_t));
			tuple.scenario_state     =row_vals[sstate_col].val.int_val;
			tuple.next_scenario_state=row_vals[next_sstate_col].val.int_val;
			memset(params, 0, 5* sizeof(str*));
			if(row_vals[sparam0_col].val.string_val)
			{
				tuple.scenario_params[0].s =(char*)row_vals[sparam0_col].val.string_val;
				tuple.scenario_params[0].len = strlen(tuple.scenario_params[0].s);
				params[0] = &tuple.scenario_params[0];
			}
			if(row_vals[sparam1_col].val.string_val)
			{
				tuple.scenario_params[1].s =(char*)row_vals[sparam1_col].val.string_val;
				tuple.scenario_params[1].len = strlen(tuple.scenario_params[1].s);
				params[1] = &tuple.scenario_params[1];
			}
			if(row_vals[sparam2_col].val.string_val)
			{
				tuple.scenario_params[2].s =(char*)row_vals[sparam2_col].val.string_val;
				tuple.scenario_params[2].len = strlen(tuple.scenario_params[2].s);
				params[2] = &tuple.scenario_params[2];
			}
			if(row_vals[sparam3_col].val.string_val)
			{
				tuple.scenario_params[3].s =(char*)row_vals[sparam3_col].val.string_val;
				tuple.scenario_params[3].len = strlen(tuple.scenario_params[3].s);
				params[3] = &tuple.scenario_params[3];
			}
			if(row_vals[sparam4_col].val.string_val)
			{
				tuple.scenario_params[4].s =(char*)row_vals[sparam4_col].val.string_val;
				tuple.scenario_params[4].len = strlen(tuple.scenario_params[4].s);
				params[4] = &tuple.scenario_params[4];
			}

			bridge_entities[0].type  = row_vals[e1_type_col].val.int_val;
			bridge_entities[0].scenario_id.s =(char*)row_vals[e1_sid_col].val.string_val;
			bridge_entities[0].scenario_id.len=
				bridge_entities[0].scenario_id.s?strlen(bridge_entities[0].scenario_id.s):0;
			bridge_entities[0].to_uri.s  =(char*)row_vals[e1_to_col].val.string_val;
			bridge_entities[0].to_uri.len=
				bridge_entities[0].to_uri.s?strlen(bridge_entities[0].to_uri.s):0;
			bridge_entities[0].from_uri.s=(char*)row_vals[e1_from_col].val.string_val;
			bridge_entities[0].from_uri.len=
				bridge_entities[0].from_uri.s?strlen(bridge_entities[0].from_uri.s):0;
			bridge_entities[0].key.s  =(char*)row_vals[e1_key_col].val.string_val;
			bridge_entities[0].key.len=
				bridge_entities[0].key.s?strlen(bridge_entities[0].key.s):0;

			bridge_entities[1].type = row_vals[e2_type_col].val.int_val;
			bridge_entities[1].scenario_id.s  = (char*)row_vals[e2_sid_col].val.string_val;
			bridge_entities[1].scenario_id.len=
				bridge_entities[1].scenario_id.s?strlen(bridge_entities[1].scenario_id.s):0;
			bridge_entities[1].to_uri.s  = (char*)row_vals[e2_to_col].val.string_val;
			bridge_entities[1].to_uri.len=
				bridge_entities[1].to_uri.s?strlen(bridge_entities[1].to_uri.s):0;
			bridge_entities[1].from_uri.s  = (char*)row_vals[e2_from_col].val.string_val;
			bridge_entities[1].from_uri.len=
				bridge_entities[1].from_uri.s?strlen(bridge_entities[1].from_uri.s):0;
			bridge_entities[1].key.s  = (char*)row_vals[e2_key_col].val.string_val;
			bridge_entities[1].key.len=
				bridge_entities[1].key.s?strlen(bridge_entities[1].key.s):0;

			if(row_vals[e3_to_col].val.string_val)
			{
				bridge_entities[2].type = row_vals[e3_type_col].val.int_val;
				bridge_entities[2].scenario_id.s  = (char*)row_vals[e3_sid_col].val.string_val;
				bridge_entities[2].scenario_id.len=
					bridge_entities[2].scenario_id.s?strlen(bridge_entities[2].scenario_id.s):0;
				bridge_entities[2].to_uri.s  = (char*)row_vals[e3_to_col].val.string_val;
				bridge_entities[2].to_uri.len=
					bridge_entities[2].to_uri.s?strlen(bridge_entities[2].to_uri.s):0;
				bridge_entities[2].from_uri.s  = (char*)row_vals[e3_from_col].val.string_val;
				bridge_entities[2].from_uri.len=
					bridge_entities[2].from_uri.s?strlen(bridge_entities[2].from_uri.s):0;
				bridge_entities[2].key.s  = (char*)row_vals[e3_key_col].val.string_val;
				bridge_entities[2].key.len=
					bridge_entities[2].key.s?strlen(bridge_entities[2].key.s):0;
			}

			tuple.sdp.s   = (char*)row_vals[sdp_col].val.string_val;
			tuple.sdp.len = (tuple.sdp.s?strlen(tuple.sdp.s):0);

			tuple.bridge_entities[0] = &bridge_entities[0];
			tuple.bridge_entities[1] = &bridge_entities[1];
			tuple.bridge_entities[2] = &bridge_entities[2];

			if(b2bl_add_tuple(&tuple, params) < 0)
			{
				LM_ERR("Failed to add new tuple\n");
				goto error;
			}
		}
		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(b2bl_dbf, DB_CAP_FETCH)) {
			if (b2bl_dbf.fetch_result( b2bl_db, &result,
				B2BL_FETCH_SIZE ) < 0) 
			{
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(result);
		} else {
			nr_rows = 0;
		}
	}while (nr_rows>0);

	b2bl_dbf.free_result(b2bl_db, result);
	LM_DBG("Finished\n");

	/* delete all from database */
	if(b2bl_dbf.delete(b2bl_db, 0, 0, 0, 0) < 0)
	{
		LM_ERR("Failed to delete from database table\n");
		return -1;
	}

	return 0;


error:
	if(result)
		b2bl_dbf.free_result(b2bl_db, result);
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
	api->terminate_call= b2bl_terminate_call;

	return 0;
}
