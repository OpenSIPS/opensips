/*
 * back-to-back entities module
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
 *  2011-01-04  new mi function: mi_b2be_list (Ovidiu Sas)
 *  2011-06-27  added authentication support (Ovidiu Sas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../db/db.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../script_cb.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../uac_auth/uac_auth.h"
#include "b2be_db.h"

#include "b2b_entities.h"
#include "server.h"
#include "dlg.h"

#define TABLE_VERSION 1

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
int b2b_entities_bind(b2b_api_t* api);
static struct mi_root* mi_b2be_list(struct mi_root* cmd, void* param);

/** Global variables */
unsigned int server_hsize = 9;
unsigned int client_hsize = 9;
static char* script_req_route = NULL;
static char* script_reply_route = NULL;
int req_routeid  = -1;
int reply_routeid = -1;
int replication_mode= 0;
static str db_url= {0, 0};
db_con_t *b2be_db = NULL;
db_func_t b2be_dbf;
str b2be_dbtable= str_init("b2b_entities");
static int b2b_update_period = 100;
int uac_auth_loaded;
str b2b_key_prefix = str_init("B2B");
int b2be_db_mode = WRITE_BACK;

#define DB_COLS_NO  26

/* TM bind */
struct tm_binds tmb;

/* UAC_AUTH bind */
uac_auth_api_t uac_auth_api;

/** Exported functions */
static cmd_export_t cmds[]=
{
	{"load_b2b",  (cmd_function)b2b_entities_bind, 1,  0,  0,  0},
	{ 0,               0,                          0,  0,  0,  0}
};

/** Exported parameters */
static param_export_t params[]={
	{ "server_hsize",          INT_PARAM,    &server_hsize       },
	{ "client_hsize",          INT_PARAM,    &client_hsize       },
	{ "script_req_route",      STR_PARAM,    &script_req_route   },
	{ "script_reply_route",    STR_PARAM,    &script_reply_route },
	{ "replication_mode",      INT_PARAM,    &replication_mode   },
	{ "db_url",                STR_PARAM,    &db_url.s           },
	{ "db_table",              STR_PARAM,    &b2be_dbtable.s     },
	{ "db_mode",               INT_PARAM,    &b2be_db_mode       },
	{ "update_period",         INT_PARAM,    &b2b_update_period  },
	{ "b2b_key_prefix",        STR_PARAM,    &b2b_key_prefix.s   },
	{ 0,                       0,            0                   }
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "b2be_list", 0, mi_b2be_list, 0,  0,  0},
	{  0,          0, 0,            0,  0,  0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",       DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "uac_auth", DEP_WARN  },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

/** Module interface */
struct module_exports exports= {
	"b2b_entities",                 /* module name */
	MOD_TYPE_DEFAULT,               /* class of this module */
	MODULE_VERSION,                 /* module version */
	DEFAULT_DLFLAGS,                /* dlopen flags */
	&deps,                          /* OpenSIPS module dependencies */
	cmds,                           /* exported functions */
	NULL,                           /* exported async functions */
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

void b2be_db_timer_update(unsigned int ticks, void* param)
{
	b2b_entities_dump(0);
}

/** Module initialize function */
static int mod_init(void)
{
	/* inspect the parameters */
	if(server_hsize< 1 || server_hsize> 20 ||
			client_hsize< 1 || client_hsize> 20)
	{
		LM_ERR("Wrong hash size. Needs to be greater than 1"
				" and smaller than 20. Be aware that you should set the log 2"
				" value of the real size\n");
		return -1;
	}
	server_hsize = 1<<server_hsize;
	client_hsize = 1<<client_hsize;

	if(b2b_key_prefix.s)
	{
		b2b_key_prefix.len = strlen(b2b_key_prefix.s);
		if(b2b_key_prefix.len > B2B_MAX_PREFIX_LEN)
		{
			LM_ERR("b2b_key_prefix [%s] too long. Maximum size %d\n",
					b2b_key_prefix.s, B2B_MAX_PREFIX_LEN);
			return -1;
		}
	}

	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	/* load the UAC_AUTH API - FIXME it should be loaded only
	 * if authentication is required */
	if(load_uac_auth_api(&uac_auth_api)<0)
	{
		LM_INFO("authentication functionality disabled:"
				" load uac_auth first to enable it\n");
		uac_auth_loaded = 0;
	}
	else
	{
		uac_auth_loaded = 1;
	}

	/* initialize the hash tables; they will be allocated in shared memory
	 * to be accesible by all processes */
	if(init_b2b_htables()< 0)
	{
		LM_ERR("Failed to initialize b2b table\n");
		return -1;
	}
	memset(&b2be_dbf, 0, sizeof(db_func_t));
	if(b2be_db_mode && db_url.s)
	{
		db_url.len = strlen(db_url.s);
		b2be_dbtable.len = strlen(b2be_dbtable.s);

		/* binding to database module  */
		if (db_bind_mod(&db_url, &b2be_dbf))
		{
			LM_ERR("Database module not found\n");
			return -1;
		}

		if (!DB_CAPABILITY(b2be_dbf, DB_CAP_ALL))
		{
			LM_ERR("Database module does not implement all functions"
					" needed by b2b_entities module\n");
			return -1;
		}

		b2be_db = b2be_dbf.init(&db_url);
		if(!b2be_db)
		{
			LM_ERR("connecting to database failed\n");
			return -1;
		}

		/*verify table versions */
		if(db_check_table_version(&b2be_dbf, b2be_db, &b2be_dbtable, TABLE_VERSION) < 0)
		{
			LM_ERR("error during table version check\n");
			return -1;
		}

		b2be_initialize();

		/* reload data */
		if(b2b_entities_restore() < 0)
		{
			LM_ERR("Failed to restore data from database\n");
			return -1;
		}

		if(b2be_db)
			b2be_dbf.close(b2be_db);
		b2be_db = NULL;
	}
	else
		b2be_db_mode = 0;

	if(register_script_cb( b2b_prescript_f, PRE_SCRIPT_CB|REQ_TYPE_CB, 0 ) < 0)
	{
		LM_ERR("Failed to register prescript function\n");
		return -1;
	}

	if (script_req_route)
	{
		req_routeid = get_script_route_ID_by_name( script_req_route, rlist, RT_NO);
		if (req_routeid < 1)
		{
			LM_ERR("route <%s> does not exist\n",script_req_route);
			return -1;
		}
	}

	if (script_reply_route)
	{
		reply_routeid = get_script_route_ID_by_name( script_reply_route, rlist, RT_NO);
		if (reply_routeid < 1)
		{
			LM_ERR("route <%s> does not exist\n",script_reply_route);
			return -1;
		}
	}
	if(b2b_update_period < 0)
	{
		LM_ERR("Wrong parameter - b2b_update_period [%d]\n", b2b_update_period);
		return -1;
	}
	if(b2be_db_mode == WRITE_BACK)
		register_timer("b2be-dbupdate", b2be_db_timer_update, 0,
			b2b_update_period, TIMER_FLAG_SKIP_ON_DELAY);
	//register_timer("b2b2-clean", b2be_clean,  0, b2b_update_period);

	return 0;
}

void check_htable(b2b_table table, int hsize)
{
	int i;
	b2b_dlg_t* dlg, *dlg_next;

	for(i= 0; i< hsize; i++)
	{
		lock_get(&table[i].lock);
		dlg = table[i].first;
		while(dlg)
		{
			dlg_next = dlg->next;
			if(dlg->b2b_cback == 0)
			{
				LM_ERR("Found entity not linked to any logic\n");
				b2b_delete_record(dlg, table, i);
			}
			dlg = dlg_next;
		}
		lock_release(&table[i].lock);
	}
	table->checked = 1;
}

void check_htables(void)
{
	if(server_htable->checked && client_htable->checked)
		return;
	if(!server_htable->checked)
		check_htable(server_htable, server_hsize);
	if(!client_htable->checked)
		check_htable(client_htable, client_hsize);
}

/** Module child initialize function */
static int child_init(int rank)
{
	/* if database is needed */
	if (b2be_db_mode && db_url.s)
	{
		if (b2be_dbf.init==0)
		{
			LM_CRIT("child_init: database not bound\n");
			return -1;
		}

		b2be_db = b2be_dbf.init(&db_url);
		if(!b2be_db)
		{
			LM_ERR("connecting to database failed\n");
			return -1;
		}
		LM_DBG("child %d: Database connection opened successfully\n", rank);
	}
	check_htables();
	return 0;
}

/** Module destroy function */
static void mod_destroy(void)
{
	if(b2be_db ) {
		if(b2be_db_mode==WRITE_BACK)
			b2b_entities_dump(1);
		b2be_dbf.close(b2be_db);
	}
	destroy_b2b_htables();
}

int b2b_restore_logic_info(enum b2b_entity_type type, str* key,
		b2b_notify_t cback)
{
	b2b_dlg_t* dlg;
	b2b_table table;
	unsigned int hash_index, local_index;

	if(server_htable== NULL)
	{
		LM_ERR("You have to load b2b_entities module before b2b_logic module\n");
		return -1;
	}

	if(type == B2B_SERVER)
	{
		table = server_htable;
	}
	else
	{
		table = client_htable;
	}
	if(b2b_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", key->len, key->s);
		return -1;
	}
	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg == NULL)
	{
		LM_ERR("No dialog found for key [%.*s]\n", key->len, key->s);
		return -1;
	}
	dlg->b2b_cback = cback;
	return 0;
}

int b2b_update_b2bl_param(enum b2b_entity_type type, str* key,
		str* param)
{
	b2b_dlg_t* dlg;
	b2b_table table;
	unsigned int hash_index, local_index;

	if(!param)
	{
		LM_ERR("NULL param\n");
		return -1;
	}
	if(param->len > B2BL_MAX_KEY_LEN)
	{
		LM_ERR("parameter too long, received [%d], maximum [%d]\n",
				param->len, B2BL_MAX_KEY_LEN);
		return -1;
	}

	if(type == B2B_SERVER)
	{
		table = server_htable;
	}
	else
	{
		table = client_htable;
	}
	if(b2b_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", key->len, key->s);
		return -1;
	}
	lock_get(&table[hash_index].lock);
	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg == NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}
	memcpy(dlg->param.s, param->s, param->len);
	dlg->param.len = param->len;
	lock_release(&table[hash_index].lock);

	return 0;
}

int b2b_get_b2bl_key(str* callid, str* from_tag, str* to_tag, str* entity_key, str* tuple_key)
{
	b2b_dlg_t* dlg;
	unsigned int hash_index, local_index;
	b2b_table table;
	int ret;

	if(!callid || !callid->s || !callid->len){
		LM_ERR("Wrong callid param\n");
		return -1;
	}
	if(!from_tag || !from_tag->s || !from_tag->len){
		LM_ERR("Wrong from_tag param\n");
		return -1;
	}
	if(!to_tag || !to_tag->s || !to_tag->len){
		LM_ERR("Wrong to_tag param\n");
		return -1;
	}
	if(!tuple_key || !tuple_key->s || tuple_key->len<B2BL_MAX_KEY_LEN) {
		LM_ERR("Wrong tuple param\n");
		return -1;
	}
	/* check if the to tag has the b2b key format
	 * -> meaning that it is a server request */
	if(b2b_parse_key(to_tag, &hash_index, &local_index)>=0) {
		table = server_htable;
		lock_get(&table[hash_index].lock);
		dlg=b2b_search_htable_dlg(table, hash_index, local_index,
						to_tag, from_tag, callid);
		if(dlg){
			memcpy(tuple_key->s, dlg->param.s, dlg->param.len);
			tuple_key->len = dlg->param.len;
			entity_key->s = to_tag->s;
			entity_key->len = to_tag->len;
			LM_DBG("got tuple [%.*s] for entity [%.*s]\n",
				tuple_key->len, tuple_key->s, entity_key->len, entity_key->s);
			ret = 0;
		} else {
			ret = -1;
		}
		lock_release(&table[hash_index].lock);
		return ret;
	}
	return -1;
}


int b2b_entities_bind(b2b_api_t* api)
{
	if (!api)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}
	api->server_new         = server_new;
	api->client_new         = client_new;
	api->send_request       = b2b_send_request;
	api->send_reply         = b2b_send_reply;
	api->entity_delete      = b2b_entity_delete;
	api->restore_logic_info = b2b_restore_logic_info;
	api->update_b2bl_param  = b2b_update_b2bl_param;
	api->entities_db_delete = b2b_db_delete;
	api->get_b2bl_key       = b2b_get_b2bl_key;
	api->apply_lumps        = b2b_apply_lumps;

	return 0;
}


static inline int mi_print_b2be_dlg(struct mi_node *rpl, b2b_table htable, unsigned int hsize)
{
	int i, len;
	char* p;
	b2b_dlg_t* dlg;
	dlg_leg_t* leg;
	struct mi_node *node=NULL, *node1=NULL, *node_l=NULL;
	struct mi_attr* attr;

	for(i = 0; i< hsize; i++)
	{
		lock_get(&htable[i].lock);
		dlg = htable[i].first;
		while(dlg)
		{
			p = int2str((unsigned long)(dlg->id), &len);
			node = add_mi_node_child(rpl, MI_DUP_VALUE, "dlg", 3, p, len);
			if(node == NULL) goto error;
			attr = add_mi_attr(node, MI_DUP_VALUE, "param", 5,
					dlg->param.s, dlg->param.len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(dlg->state), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "state", 5, p, len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(dlg->last_invite_cseq), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "last_invite_cseq", 16, p, len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(dlg->last_method), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "last_method", 11, p, len);
			if(attr == NULL) goto error;
			if (dlg->last_reply_code)
			{
				p = int2str((unsigned long)(dlg->last_reply_code), &len);
				attr = add_mi_attr(node,MI_DUP_VALUE,"last_reply_code",15,p,len);
				if(attr == NULL) goto error;
			}
			p = int2str((unsigned long)(dlg->db_flag), &len);
			attr = add_mi_attr(node, MI_DUP_VALUE, "db_flag", 7, p, len);
			if(attr == NULL) goto error;

			if (dlg->ruri.len)
			{
				node1 = add_mi_node_child(node, MI_DUP_VALUE, "ruri", 4,
						dlg->ruri.s, dlg->ruri.len);
				if(node1 == NULL) goto error;
			}

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "callid", 6,
					dlg->callid.s, dlg->callid.len);
			if(node1 == NULL) goto error;

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "from", 4,
					dlg->from_dname.s, dlg->from_dname.len);
			if(node1 == NULL) goto error;
			attr = add_mi_attr(node1, MI_DUP_VALUE, "uri", 3,
					dlg->from_uri.s, dlg->from_uri.len);
			if(attr == NULL) goto error;
			attr = add_mi_attr(node1, MI_DUP_VALUE, "tag", 3,
					dlg->tag[0].s, dlg->tag[0].len);
			if(attr == NULL) goto error;

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "to", 2,
					dlg->to_dname.s, dlg->to_dname.len);
			if(node1 == NULL) goto error;
			attr = add_mi_attr(node1, MI_DUP_VALUE, "uri", 3,
					dlg->to_uri.s, dlg->to_uri.len);
			if(attr == NULL) goto error;
			attr = add_mi_attr(node1, MI_DUP_VALUE, "tag", 3,
					dlg->tag[1].s, dlg->tag[1].len);
			if(attr == NULL) goto error;

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "cseq", 4, NULL, 0);
			if(node1 == NULL) goto error;
			p = int2str((unsigned long)(dlg->cseq[0]), &len);
			attr = add_mi_attr(node1, MI_DUP_VALUE, "caller", 6, p, len);
			if(attr == NULL) goto error;
			p = int2str((unsigned long)(dlg->cseq[1]), &len);
			attr = add_mi_attr(node1, MI_DUP_VALUE, "callee", 6, p, len);
			if(attr == NULL) goto error;

			if (dlg->route_set[0].len||dlg->route_set[1].len)
			{
				node1 = add_mi_node_child(node,MI_DUP_VALUE,"route_set",9,NULL,0);
				if(node1 == NULL) goto error;
				if (dlg->route_set[0].len)
				{
					attr = add_mi_attr(node1, MI_DUP_VALUE, "caller", 6,
							dlg->route_set[0].s, dlg->route_set[0].len);
					if(attr == NULL) goto error;
				}
				if (dlg->route_set[1].len)
				{
					attr = add_mi_attr(node1, MI_DUP_VALUE, "callee", 6,
							dlg->route_set[1].s, dlg->route_set[1].len);
					if(attr == NULL) goto error;
				}
			}

			node1 = add_mi_node_child(node, MI_DUP_VALUE, "contact", 7, NULL, 0);
			if(node1 == NULL) goto error;
			attr = add_mi_attr(node1, MI_DUP_VALUE, "caller", 6,
					dlg->contact[0].s, dlg->contact[0].len);
			if(attr == NULL) goto error;
			attr = add_mi_attr(node1, MI_DUP_VALUE, "callee", 6,
					dlg->contact[1].s, dlg->contact[1].len);
			if(attr == NULL) goto error;

			if (dlg->send_sock)
			{
				node1 = add_mi_node_child(node, MI_DUP_VALUE, "send_sock", 9,
					dlg->send_sock->name.s, dlg->send_sock->name.len);
				if(node1 == NULL) goto error;
			}

			if(dlg->uac_tran||dlg->uas_tran||dlg->update_tran||dlg->cancel_tm_tran)
			{
				node1 = add_mi_node_child(node, MI_DUP_VALUE, "tm_tran", 7, NULL, 0);
				if(node1 == NULL) goto error;
				if(dlg->uac_tran) {
					attr = add_mi_attr(node1,MI_DUP_VALUE,"uac",3,NULL,0);
					if(attr == NULL) goto error;
				}
				if(dlg->uas_tran) {
					attr = add_mi_attr(node1,MI_DUP_VALUE,"uas",3,NULL,0);
					if(attr == NULL) goto error;
				}
				if(dlg->update_tran) {
					attr = add_mi_attr(node1,MI_DUP_VALUE,"update",6,NULL,0);
					if(attr == NULL) goto error;
				}
				if(dlg->cancel_tm_tran) {
					attr = add_mi_attr(node1,MI_DUP_VALUE,"cancel_tm",9,NULL,0);
					if(attr == NULL) goto error;
				}
			}

			if ( (leg=dlg->legs)!=NULL ) {
				node_l = add_mi_node_child(node, MI_IS_ARRAY, "LEGS", 4, NULL, 0);
				if(node_l == NULL) goto error;
				while(leg)
				{
					p = int2str((unsigned long)(leg->id), &len);
					node1 = add_mi_node_child(node_l, MI_DUP_VALUE, "leg", 3, p, len);
					if(node1 == NULL) goto error;
					attr = add_mi_attr(node1, MI_DUP_VALUE, "tag", 3,
							leg->tag.s, leg->tag.len);
					if(attr == NULL) goto error;
					p = int2str((unsigned long)(leg->cseq), &len);
					attr = add_mi_attr(node1, MI_DUP_VALUE, "cseq", 4, p, len);
					if(attr == NULL) goto error;
					attr = add_mi_attr(node1, MI_DUP_VALUE, "contact", 7,
							leg->contact.s, leg->contact.len);
					if(attr == NULL) goto error;
					if(leg->route_set.len)
					{
						attr = add_mi_attr(node1, MI_DUP_VALUE, "route_set", 9,
							leg->route_set.s, leg->route_set.len);
						if(attr == NULL) goto error;
					}

					leg=leg->next;
				}
			}

			dlg = dlg->next;
		}
		lock_release(&htable[i].lock);
	}
	return 0;
error:
	lock_release(&htable[i].lock);
	LM_ERR("failed to add node\n");
	return -1;
}

static struct mi_root* mi_b2be_list(struct mi_root* cmd, void* param)
{
	struct mi_root *rpl_tree;
	struct mi_node *rpl=NULL;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	if (server_htable)
		if (mi_print_b2be_dlg(rpl, server_htable, server_hsize)!=0)
			goto error;
	if (client_htable)
		if (mi_print_b2be_dlg(rpl, client_htable, client_hsize)!=0)
			goto error;

	return rpl_tree;
error:
	LM_ERR("Unable to create reply\n");
	free_mi_tree(rpl_tree);
	return NULL;
}

