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
#include "../../ut.h"
#include "../../mem/mem.h"

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"


/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);

static int load_script_scenario(modparam_t type, void* val);
static int load_extern_scenario(modparam_t type, void* val);

static int fixup_b2b_logic(void** param, int param_no);

static struct mi_root* mi_trigger_scenario(struct mi_root* cmd, void* param);

void b2bl_clean(unsigned int ticks, void* param);

int b2b_init_request(struct sip_msg* msg, str* arg1, str* arg2, str* arg3,
		str* arg4, str* arg5, str* arg6);

/** Global variables */
b2b_api_t b2b_api;
b2bl_table_t b2bl_htable;
unsigned int b2bl_hsize = 10;
b2b_scenario_t* script_scenaries = NULL;
b2b_scenario_t* extern_scenaries = NULL;
unsigned int b2b_clean_period = 100;

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"b2b_init_request", (cmd_function)b2b_init_request, 5 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 4 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 3 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 2 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 1 , fixup_b2b_logic , 0 , REQUEST_ROUTE},
	{"b2b_init_request", (cmd_function)b2b_init_request, 0 , 0               , 0 , REQUEST_ROUTE},
	{ 0,                 0,                              0 , 0 , 0,  0}
};

/** Exported parameters */
static param_export_t params[]=
{
	{"hash_size",       INT_PARAM,                &b2bl_hsize                },
	{"clean_period",    INT_PARAM,                &b2b_clean_period          },
	{"script_scenario", STR_PARAM|USE_FUNC_PARAM, (void*)load_script_scenario},
	{"extern_scenario", STR_PARAM|USE_FUNC_PARAM, (void*)load_extern_scenario},
	{0,                    0,                          0                     }
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "b2b_trigger_scenario", mi_trigger_scenario, 0,  0,  0},
	{  0,                  0,                      0,  0,  0}
};

/** Module interface */
struct module_exports exports= {
	"b2b_logic",                    /* module name */
	MODULE_VERSION,					/* module version */
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

//	register_timer(b2bl_clean, 0, b2b_clean_period);

	return 0;
}

void b2bl_clean(unsigned int ticks, void* param)
{
	int i;
	b2bl_tuple_t* tuple;
	unsigned int now;
	str bye = {BYE, BYE_LEN};

	now = get_ticks();

	for(i = 0; i< b2bl_hsize; i++)
	{
		lock_get(&b2bl_htable[i].lock);
		tuple = b2bl_htable[i].first;
		while(tuple)
		{
			if(tuple->lifetime > 0 && tuple->lifetime < now)  /* if an expired dialog */
			{
				LM_DBG("Found an expired dialog. Send BYE in both sides and delete\n");
				b2b_api.send_request(tuple->bridge_entities[0]->type,
						&tuple->bridge_entities[0]->key, &bye, 0, 0);
				b2b_api.send_request(tuple->bridge_entities[1]->type,
						&tuple->bridge_entities[1]->key, &bye, 0, 0);
				b2bl_delete(tuple, i);
			}
			tuple = tuple->next;
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
	return load_scenario(&script_scenaries, (char*)val);
}

static int load_extern_scenario(modparam_t type, void* val)
{
	return load_scenario(&extern_scenaries, (char*)val);
}

static void mod_destroy(void)
{
	int i;
	b2b_rule_t* rule_struct = NULL;

	b2b_scenario_t* scenario, *next;

	scenario = extern_scenaries;
	while(scenario)
	{
		next = scenario->next;

		xmlFree(scenario->id.s);
		xmlFreeDoc(scenario->doc);
		pkg_free(scenario);
		scenario = next;
	}

	scenario = script_scenaries;
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
			b2b_scenario_t* scenario = script_scenaries;
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
			while(scenario)
			{
				LM_DBG("scenario id = %.*s\n", scenario->id.len, scenario->id.s);
				if(scenario->id.len == s.len &&
						strncmp(scenario->id.s, s.s, s.len) == 0)
				{
					*param = (void*)scenario;
					LM_DBG("Fixup parameter for scenario id = %.*s\n", s.len, s.s);
					return 0;
				}
				scenario = scenario->next;
			}
			LM_ERR("Wrong Scenary ID. No scenario with this ID [%.*s]\n", s.len, s.s);
			return E_UNSPEC;
		}

		*param = (void*)model;
		return 0;
	}
	LM_ERR( "null format\n");
	return E_UNSPEC;
}


static struct mi_root* mi_trigger_scenario(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str attr;
	b2b_scenario_t* scenario_struct;
	str* args[B2B_INIT_MAX_PARAMNO];
	int i = 0;
	unsigned int hash_index = 0;
	xmlNodePtr xml_node;
	unsigned int state = 0;
	b2bl_tuple_t* tuple;
	str* b2bl_key;

	node = cmd->node.kids;
	if(node == NULL)
		return 0;

	/* Get scenario ID */
	attr = node->value;
	if(attr.s == NULL || attr.len== 0)
	{
		LM_ERR("Empty scenario name parameter\n");
		return init_mi_tree(404, "Empty scenario ID", 16);
	}
	node = node->next;

	/* find the scenario with the corresponding id */
	scenario_struct = extern_scenaries;
	while(scenario_struct)
	{
		if(scenario_struct->id.len == attr.len && 
				strncmp(scenario_struct->id.s, attr.s, attr.len) == 0)
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

	memset(args, 0, B2B_INIT_MAX_PARAMNO* sizeof(str*));
	/* get the other parameters */
	while(i < B2B_INIT_MAX_PARAMNO && node)
	{
		if(node->value.s == NULL || node->value.len== 0)
			break;

		args[i++] = &node->value;

		node = node->next;
	}

	if(i < scenario_struct->param_no)
	{
		return init_mi_tree(400, "Too few parameters", 18);
	}
	else
	if(i > scenario_struct->param_no)
	{
		return init_mi_tree(400, "Too many parameters", 19);
	}

	/* compute the hash index */
	/* if there are at least 2 parameters use them to compute the hash_index */
	if(i >= 2)
	{
		hash_index = core_hash(args[0], args[1], b2bl_hsize);
	}
	else
	{
		/* the scenario must have at least 2 client - take hash index from their destinations*/
	}

	/* apply the init part of the scenario */

	tuple = b2bl_insert_new(hash_index, scenario_struct, args, &b2bl_key);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return 0;
	}

	/* need to get the next action */
	xml_node = xmlNodeGetChildByName(scenario_struct->init_node, "state");
	if(xml_node)
	{
		attr.s = (char*)xmlNodeGetContent(xml_node);
		if(attr.s == NULL)
		{
			LM_ERR("No state node content found\n");
			return 0;
		}
		attr.len = strlen(attr.s);

		if(str2int(&attr, &state)< 0)
		{
			LM_ERR("Bad scenario. Scenary state not an integer\n");
			xmlFree(attr.s);
			return 0;
		}
		LM_DBG("Next scenario state is [%d]\n", state);
		xmlFree(attr.s);
	}
	tuple->next_scenario_state = state;

	xml_node =  xmlNodeGetChildByName(scenario_struct->init_node, "bridge");
	if(xml_node == NULL)
	{
		LM_ERR("No bridge node found\n");
		return 0;
	}

	if(process_bridge_action(tuple, xml_node) < 0)
	{
		LM_ERR("Failed to process bridge node");
		return 0;
	}

	return init_mi_tree(200, "OK", 2);
}
