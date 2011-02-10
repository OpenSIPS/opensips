/*
 * $Id: b2b_entities.c $
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 *  2011-01-04  new mi function: mi_b2be_list (Ovidiu Sas)
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
#include "../presence/hash.h"
#include "../dialog/dlg_load.h"

#include "b2b_entities.h"
#include "server.h"
#include "dlg.h"

#define TABLE_VERSION 1
#define B2BE_FETCH_SIZE  128

/** Functions declarations */
static int mod_init(void);
static void mod_destroy(void);
static int child_init(int rank);
int b2b_entities_bind(b2b_api_t* api);
void b2b_entities_dump(int no_lock);
int b2b_entities_restore(void);
void b2be_db_update(unsigned int ticks, void* param);
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
static db_con_t *b2be_db = NULL;
static db_func_t b2be_dbf;
static str dbtable= str_init("b2b_entities");
static int b2b_update_period = 100;
str b2b_key_prefix = str_init("B2B");

static str str_type_col         = str_init("type");
static str str_state_col        = str_init("state");
static str str_ruri_col         = str_init("ruri");
static str str_from_col         = str_init("from_uri");
static str str_from_dname_col   = str_init("from_dname");
static str str_to_col           = str_init("to_uri");
static str str_to_dname_col     = str_init("to_dname");
static str str_tag0_col         = str_init("tag0");
static str str_tag1_col         = str_init("tag1");
static str str_callid_col       = str_init("callid");
static str str_cseq0_col        = str_init("cseq0");
static str str_cseq1_col        = str_init("cseq1");
static str str_route0_col       = str_init("route0");
static str str_route1_col       = str_init("route1");
static str str_contact0_col     = str_init("contact0");
static str str_contact1_col     = str_init("contact1");
static str str_lm_col           = str_init("lm");
static str str_lrc_col          = str_init("lrc");
static str str_lic_col          = str_init("lic");
static str str_leg_tag_col      = str_init("leg_tag");
static str str_leg_cseq_col     = str_init("leg_cseq");
static str str_leg_route_col    = str_init("leg_route");
static str str_leg_contact_col  = str_init("leg_contact");
static str str_sockinfo_srv_col = str_init("sockinfo_srv");
static str str_param_col        = str_init("param");

#define DB_COLS_NO  26

/* TM bind */
struct tm_binds tmb;

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
	{ "dbtable",               STR_PARAM,    &dbtable.s          },
	{ "update_period",         INT_PARAM,    &b2b_update_period  },
	{ "b2b_key_prefix",        STR_PARAM,    &b2b_key_prefix.s   },
	{ 0,                       0,            0                   }
};

/** MI commands */
static mi_export_t mi_cmds[] = {
	{ "b2be_list", mi_b2be_list, 0,  0,  0},
	{  0,          0,            0,  0,  0}
};
/** Module interface */
struct module_exports exports= {
	"b2b_entities",                 /* module name */
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

	/* initialize the hash tables; they will be allocated in shared memory 
	 * to be accesible by all processes */
	if(init_b2b_htables()< 0)
	{
		LM_ERR("Failed to initialize b2b table\n");
		return -1;
	}
	memset(&b2be_dbf, 0, sizeof(db_func_t));
	if(db_url.s)
	{
		db_url.len = strlen(db_url.s);

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
		if(db_check_table_version(&b2be_dbf, b2be_db, &dbtable, TABLE_VERSION) < 0)
		{
			LM_ERR("error during table version check\n");
			return -1;
		}

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
	if(db_url.s)
		register_timer(b2be_db_update, 0, b2b_update_period);
	//register_timer(b2be_clean,  0, b2b_update_period);

	return 0;
}

void b2be_db_update(unsigned int ticks, void* param)
{
	b2b_entities_dump(0);
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
	if (db_url.s)
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
	if(b2be_db) {
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
		LM_ERR("No dialog found\n");
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

	return 0;
}

void store_b2b_dlg(b2b_table htable, unsigned int hsize, int type, int no_lock)
{
	static db_key_t qcols[DB_COLS_NO];
	db_val_t qvals[DB_COLS_NO];
	int type_col, state_col, from_col, to_col, callid_col;
	int tag0_col, tag1_col, cseq0_col, cseq1_col, route0_col;
	int route1_col, contact0_col, contact1_col, lm_col, lrc_col;
	int ruri_col, lic_col, from_dname_col, to_dname_col, leg_tag_col;
	int leg_cseq_col, leg_route_col, leg_contact_col;
	int sockinfo_col, param_col;
	int i;
	int n_query_cols= 0, n_query_update;
	int n_start_update;
	dlg_leg_t* leg;
	b2b_dlg_t* dlg;

	if (!b2be_dbf.init)
		return;

	LM_DBG("storing b2b_entities type '%d' in db\n", type);
	if(b2be_dbf.use_table(b2be_db, &dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}
	memset(qvals, 0, DB_COLS_NO* sizeof(db_val_t));

	qcols[type_col=n_query_cols++]        = &str_type_col;
	qvals[type_col].type                  = DB_INT;
	qvals[type_col].val.int_val           = type;
	qcols[tag0_col=n_query_cols++]        = &str_tag0_col;
	qvals[tag0_col].type                  = DB_STR;
	qcols[tag1_col=n_query_cols++]        = &str_tag1_col;
	qvals[tag1_col].type                  = DB_STR;
	qcols[callid_col=n_query_cols++]      = &str_callid_col;
	qvals[callid_col].type                = DB_STR;
	n_query_update                        = n_query_cols;

	qcols[ruri_col=n_query_cols++]        = &str_ruri_col;
	qvals[ruri_col].type                  = DB_STR;
	qcols[from_col=n_query_cols++]        = &str_from_col;
	qvals[from_col].type                  = DB_STR;
	qcols[from_dname_col=n_query_cols++]  = &str_from_dname_col;
	qvals[from_dname_col].type            = DB_STR;
	qcols[to_col=n_query_cols++]          = &str_to_col;
	qvals[to_col].type                    = DB_STR;
	qcols[to_dname_col=n_query_cols++]    = &str_to_dname_col;
	qvals[to_dname_col].type              = DB_STR;
	qcols[route0_col=n_query_cols++]      = &str_route0_col;
	qvals[route0_col].type                = DB_STR;
	qcols[route1_col=n_query_cols++]      = &str_route1_col;
	qvals[route1_col].type                = DB_STR;
	qcols[sockinfo_col=n_query_cols++]    = &str_sockinfo_srv_col;
	qvals[sockinfo_col].type              = DB_STR;
	qcols[param_col=n_query_cols++]       = &str_param_col;
	qvals[param_col].type                 = DB_STR;
	n_start_update = n_query_cols;

	qcols[state_col=n_query_cols++]       = &str_state_col;
	qvals[state_col].type                 = DB_INT;
	qcols[cseq0_col=n_query_cols++]       = &str_cseq0_col;
	qvals[cseq0_col].type                 = DB_INT;
	qcols[cseq1_col=n_query_cols++]       = &str_cseq1_col;
	qvals[cseq1_col].type                 = DB_INT;
	qcols[lm_col=n_query_cols++]          = &str_lm_col;
	qvals[lm_col].type                    = DB_INT;
	qcols[lrc_col=n_query_cols++]         = &str_lrc_col;
	qvals[lrc_col].type                   = DB_INT;
	qcols[lic_col=n_query_cols++]         = &str_lic_col;
	qvals[lic_col].type                   = DB_INT;
	qcols[leg_tag_col=n_query_cols++]     = &str_leg_tag_col;
	qvals[leg_tag_col].type               = DB_STR;
	qcols[leg_cseq_col=n_query_cols++]    = &str_leg_cseq_col;
	qvals[leg_cseq_col].type              = DB_INT;
	qcols[leg_route_col=n_query_cols++]   = &str_leg_route_col;
	qvals[leg_route_col].type             = DB_STR;
	qcols[leg_contact_col=n_query_cols++] = &str_leg_contact_col;
	qvals[leg_contact_col].type           = DB_STR;
	qcols[contact0_col=n_query_cols++]    = &str_contact0_col;
	qvals[contact0_col].type              = DB_STR;
	qcols[contact1_col=n_query_cols++]    = &str_contact1_col;
	qvals[contact1_col].type              = DB_STR;

	for(i = 0; i< hsize; i++)
	{
		if(!no_lock)
			lock_get(&htable[i].lock);
		dlg = htable[i].first;
		while(dlg)
		{
			if(dlg->state < B2B_CONFIRMED || dlg->db_flag == NO_UPDATEDB_FLAG)
			{
				dlg = dlg->next;
				continue;
			}
			qvals[tag0_col].val.str_val     = dlg->tag[0];
			qvals[tag1_col].val.str_val     = dlg->tag[1];
			qvals[callid_col].val.str_val   = dlg->callid;
			if(dlg->db_flag == INSERTDB_FLAG )
			{
				qvals[ruri_col].val.str_val       = dlg->ruri;
				qvals[from_col].val.str_val       = dlg->from_uri;
				qvals[to_col].val.str_val         = dlg->to_uri;
				qvals[route0_col].val.str_val     = dlg->route_set[0];
				qvals[route1_col].val.str_val     = dlg->route_set[1];
				qvals[param_col].val.str_val      = dlg->param;
				qvals[from_dname_col].val.str_val = dlg->from_dname;
				qvals[to_dname_col].val.str_val   = dlg->to_dname;
				if(dlg->send_sock)
					qvals[sockinfo_col].val.str_val= dlg->send_sock->sock_str;
				else
				{
					qvals[sockinfo_col].val.str_val.s = 0;
					qvals[sockinfo_col].val.str_val.len = 0;
				}
			}

			qvals[contact0_col].val.str_val = dlg->contact[0];
			qvals[contact1_col].val.str_val = dlg->contact[1];
			qvals[cseq0_col].val.int_val    = dlg->cseq[0];
			qvals[cseq1_col].val.int_val    = dlg->cseq[1];
			qvals[state_col].val.int_val    = dlg->state;
			qvals[lm_col].val.int_val       = dlg->last_method;
			qvals[lrc_col].val.int_val      = dlg->last_reply_code;
			qvals[lic_col].val.int_val      = dlg->last_invite_cseq;

			leg = dlg->legs;
			if(leg) /* there can only be one leg as we do not deal with dialogs in early state */
			{
				qvals[leg_tag_col].val.str_val= leg->tag;
				qvals[leg_cseq_col].val.int_val= leg->cseq;
				qvals[leg_contact_col].val.str_val= leg->contact;
				qvals[leg_route_col].val.str_val= leg->route_set;
			}

			if(dlg->db_flag == INSERTDB_FLAG)
			{
				/* insert into database */
				if(b2be_dbf.insert(b2be_db, qcols, qvals, n_query_cols)< 0)
				{
					LM_ERR("Sql insert failed\n");
					if(!no_lock)
						lock_release(&htable[i].lock);
					return;
				}
			}
			else
			{
				if(b2be_dbf.update(b2be_db, qcols, 0, qvals,
							qcols+n_start_update, qvals+n_start_update,
							n_query_update, n_query_cols-n_start_update)< 0)
				{
					LM_ERR("Sql update failed\n");
					if(!no_lock)
						lock_release(&htable[i].lock);
					return;
				}
			}

			dlg->db_flag = NO_UPDATEDB_FLAG;
			dlg = dlg->next;
		}
		if(!no_lock)
			lock_release(&htable[i].lock);
	}
}

dlg_leg_t* b2b_dup_leg(dlg_leg_t* leg, int mem_type)
{
	int size;
	dlg_leg_t* new_leg;

	size = sizeof(dlg_leg_t) + leg->route_set.len + leg->tag.len + leg->contact.len;

	if(mem_type == SHM_MEM_TYPE)
		new_leg = (dlg_leg_t*)shm_malloc(size);
	else
		new_leg = (dlg_leg_t*)pkg_malloc(size);

	if(new_leg == NULL)
	{
		LM_ERR("No more shared memory");
		goto error;
	}
	memset(new_leg, 0, size);
	size = sizeof(dlg_leg_t);

	if(leg->contact.s && leg->contact.len)
	{
		new_leg->contact.s = (char*)new_leg + size;
		memcpy(new_leg->contact.s, leg->contact.s, leg->contact.len);
		new_leg->contact.len = leg->contact.len;
		size+= leg->contact.len;
	}

	if(leg->route_set.s)
	{
		new_leg->route_set.s = (char*)new_leg + size;
		memcpy(new_leg->route_set.s, leg->route_set.s, leg->route_set.len);
		new_leg->route_set.len = leg->route_set.len;
		size+= leg->route_set.len;
	}

	new_leg->tag.s = (char*)new_leg + size;
	memcpy(new_leg->tag.s, leg->tag.s, leg->tag.len);
	new_leg->tag.len = leg->tag.len;
	size += leg->tag.len;

	new_leg->cseq = leg->cseq;
	new_leg->id = leg->id;

	return new_leg;

error:
	return 0;
}

int b2b_entities_restore(void)
{
	static db_key_t result_cols[DB_COLS_NO];
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	int i;
	int n_result_cols= 0;
	dlg_leg_t leg, *new_leg;
	b2b_dlg_t dlg, *shm_dlg= NULL;
	int type_col, state_col, from_col, to_col, callid_col;
	int tag0_col, tag1_col, cseq0_col, cseq1_col, route0_col;
	int route1_col, contact0_col, contact1_col, lm_col, lrc_col;
	int ruri_col, lic_col, from_dname_col, to_dname_col, leg_tag_col;
	int leg_cseq_col, leg_route_col, leg_contact_col;
	int sockinfo_col, param_col;
	unsigned int hash_index, local_index;
	int nr_rows;
	str* b2b_key;
	str sockinfo_str;
	str host;
	int port, proto;
	b2b_table htable;
	unsigned int hsize;
	int type;

	if(b2be_db == NULL)
	{
		LM_DBG("NULL database connection\n");
		return 0;
	}
	if(b2be_dbf.use_table(b2be_db, &dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}
	result_cols[type_col        = n_result_cols++] =&str_type_col;
	result_cols[state_col       = n_result_cols++] =&str_state_col;
	result_cols[ruri_col        = n_result_cols++] =&str_ruri_col;
	result_cols[from_col        = n_result_cols++] =&str_from_col;
	result_cols[from_dname_col  = n_result_cols++] =&str_from_dname_col;
	result_cols[to_col          = n_result_cols++] =&str_to_col;
	result_cols[to_dname_col    = n_result_cols++] =&str_to_dname_col;
	result_cols[tag0_col        = n_result_cols++] =&str_tag0_col;
	result_cols[tag1_col        = n_result_cols++] =&str_tag1_col;
	result_cols[callid_col      = n_result_cols++] =&str_callid_col;
	result_cols[cseq0_col       = n_result_cols++] =&str_cseq0_col;
	result_cols[cseq1_col       = n_result_cols++] =&str_cseq1_col;
	result_cols[route0_col      = n_result_cols++] =&str_route0_col;
	result_cols[route1_col      = n_result_cols++] =&str_route1_col;
	result_cols[contact0_col    = n_result_cols++] =&str_contact0_col;
	result_cols[contact1_col    = n_result_cols++] =&str_contact1_col;
	result_cols[lm_col          = n_result_cols++] =&str_lm_col;
	result_cols[lrc_col         = n_result_cols++] =&str_lrc_col;
	result_cols[lic_col         = n_result_cols++] =&str_lic_col;
	result_cols[leg_tag_col     = n_result_cols++] =&str_leg_tag_col;
	result_cols[leg_cseq_col    = n_result_cols++] =&str_leg_cseq_col;
	result_cols[leg_route_col   = n_result_cols++] =&str_leg_route_col;
	result_cols[leg_contact_col = n_result_cols++] =&str_leg_contact_col;
	result_cols[sockinfo_col    = n_result_cols++] =&str_sockinfo_srv_col;
	result_cols[param_col       = n_result_cols++] =&str_param_col;

	if (DB_CAPABILITY(b2be_dbf, DB_CAP_FETCH))
	{
		if(b2be_dbf.query(b2be_db,0,0,0,result_cols, 0,
			n_result_cols, 0, 0) < 0) 
		{
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		if(b2be_dbf.fetch_result(b2be_db,&result,B2BE_FETCH_SIZE)<0)
		{
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	}
	else
	{
		if (b2be_dbf.query (b2be_db, 0, 0, 0,result_cols,0, n_result_cols,
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
			memset(&dlg, 0, sizeof(b2b_dlg_t));

			type           = row_vals[type_col].val.int_val;
			dlg.tag[1].s   = (char*)row_vals[tag1_col].val.string_val;
			dlg.tag[1].len = dlg.tag[1].s?strlen(dlg.tag[1].s):0;
			dlg.callid.s   = (char*)row_vals[callid_col].val.string_val;
			dlg.callid.len = dlg.callid.s?strlen(dlg.callid.s):0;

			if(type == B2B_SERVER)/* extract hash and local index */
			{
				htable = server_htable;
				hsize  = server_hsize;
				if(b2b_parse_key(&dlg.tag[1], &hash_index, &local_index) < 0)
				{
					LM_ERR("Wrong format for b2b key [%.*s]\n", dlg.tag[1].len,  dlg.tag[1].s);
					goto error;
				}
			}
			else
			{
				htable = client_htable;
				hsize  = client_hsize;

				if(b2b_parse_key(&dlg.callid, &hash_index, &local_index) < 0)
				{
					LM_ERR("Wrong format for b2b key [%.*s]\n", dlg.callid.len,  dlg.callid.s);
					goto error;
				}
			}
			dlg.id               = local_index;
			dlg.state            = row_vals[state_col].val.int_val;
			dlg.ruri.s           = (char*)row_vals[ruri_col].val.string_val;
			dlg.ruri.len         = strlen(dlg.ruri.s);
			dlg.from_uri.s       = (char*)row_vals[from_col].val.string_val;
			dlg.from_uri.len     = strlen(dlg.from_uri.s);
			dlg.to_uri.s         = (char*)row_vals[to_col].val.string_val;
			dlg.to_uri.len       = strlen(dlg.to_uri.s);
			dlg.tag[0].s         = (char*)row_vals[tag0_col].val.string_val;
			dlg.tag[0].len       = dlg.tag[0].s?strlen(dlg.tag[0].s):0;
			dlg.cseq[0]          = row_vals[cseq0_col].val.int_val;
			dlg.cseq[1]          = row_vals[cseq1_col].val.int_val;
			dlg.route_set[0].s   = (char*)row_vals[route0_col].val.string_val;
			dlg.route_set[0].len = dlg.route_set[0].s?strlen(dlg.route_set[0].s):0;
			dlg.route_set[1].s   = (char*)row_vals[route1_col].val.string_val;
			dlg.route_set[1].len = dlg.route_set[1].s?strlen(dlg.route_set[1].s):0;
			dlg.contact[0].s     = (char*)row_vals[contact0_col].val.string_val;
			dlg.contact[0].len   = dlg.contact[0].s?strlen(dlg.contact[0].s):0;
			dlg.contact[1].s     = (char*)row_vals[contact1_col].val.string_val;
			dlg.contact[1].len   = dlg.contact[1].s?strlen(dlg.contact[1].s):0;
			dlg.last_method      = row_vals[lm_col].val.int_val;
			dlg.last_reply_code  = row_vals[lrc_col].val.int_val;
			dlg.last_invite_cseq = row_vals[lic_col].val.int_val;
			dlg.param.s          = (char*)row_vals[param_col].val.string_val;
			dlg.param.len        = strlen(dlg.param.s);
			sockinfo_str.s       = (char*)row_vals[sockinfo_col].val.string_val;
			if(sockinfo_str.s)
			{
				sockinfo_str.len = strlen(sockinfo_str.s);
				if(sockinfo_str.len)
				{
					if (parse_phostport (sockinfo_str.s, sockinfo_str.len, &host.s,
							&host.len, &port, &proto )< 0)
					{
						LM_ERR("bad format for stored sockinfo string [%.*s]\n",
								sockinfo_str.len, sockinfo_str.s);
						goto error;
					}
					dlg.send_sock = grep_sock_info(&host, (unsigned short) port,
							(unsigned short) proto);
				}
			}
			dlg.db_flag = INSERTDB_FLAG;
			shm_dlg = b2b_dlg_copy(&dlg);
			if(shm_dlg == NULL)
			{
				LM_ERR("Failed to create new dialog structure\n");
				goto error;
			}
			b2b_key= b2b_htable_insert(htable,shm_dlg,hash_index,type);
			if(b2b_key == NULL)
			{
				LM_ERR("Failed to insert new record\n");
				goto error;
			}
			pkg_free(b2b_key);

			memset(&leg, 0, sizeof(dlg_leg_t));
			leg.tag.s= (char*)row_vals[leg_tag_col].val.string_val;
			if(!leg.tag.s)
			{
				continue;
			}
			leg.tag.len       = strlen(leg.tag.s);
			leg.contact.s     = (char*)row_vals[leg_contact_col].val.string_val;
			leg.contact.len   = leg.contact.s?strlen(leg.contact.s):0;
			leg.route_set.s   = (char*)row_vals[leg_route_col].val.string_val;
			leg.route_set.len = leg.route_set.s?strlen(leg.route_set.s):0;
			leg.cseq          = row_vals[leg_cseq_col].val.int_val;

			new_leg = b2b_dup_leg(&leg, SHM_MEM_TYPE);
			if(new_leg== NULL)
			{
				LM_ERR("Failed to construct b2b leg structure\n");
				goto error;
			}
			shm_dlg->legs = new_leg;
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(b2be_dbf, DB_CAP_FETCH)) {
			if (b2be_dbf.fetch_result( b2be_db, &result,
				B2BE_FETCH_SIZE ) < 0) 
			{
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(result);
		} else {
			nr_rows = 0;
		}
	}while (nr_rows>0);

	b2be_dbf.free_result(b2be_db, result);

	/* delete all from database */
	if(b2be_dbf.delete(b2be_db, 0, 0, 0, 0) < 0)
	{
		LM_ERR("Failed to delete from database table\n");
		return -1;
	}

	return 0;

error:
	if(result)
		b2be_dbf.free_result(b2be_db, result);
	return -1;
}


void b2b_entities_dump(int no_lock)
{
	if(!server_htable || !client_htable)
	{
		LM_DBG("NULL pointers for hash tables\n");
		return;
	}
	store_b2b_dlg(server_htable, server_hsize, B2B_SERVER, no_lock);
	store_b2b_dlg(client_htable, client_hsize, B2B_CLIENT, no_lock);
}

void b2b_db_delete(b2b_dlg_t* dlg, int type)
{
	static db_key_t qcols[4];
	db_val_t qvals[4];
	int n_query_cols= 0;
	int type_col, tag0_col, tag1_col, callid_col;

	if(!b2be_db || dlg->db_flag== INSERTDB_FLAG)
		return;


	memset(qvals, 0, 4* sizeof(db_val_t));

	qcols[type_col=n_query_cols++]        = &str_type_col;
	qvals[type_col].type                  = DB_INT;
	qvals[type_col].val.int_val           = type;
	qcols[tag0_col=n_query_cols++]        = &str_tag0_col;
	qvals[tag0_col].type                  = DB_STR;
	qvals[tag0_col].val.str_val           = dlg->tag[0];
	qcols[tag1_col=n_query_cols++]        = &str_tag1_col;
	qvals[tag1_col].type                  = DB_STR;
	qvals[tag1_col].val.str_val           = dlg->tag[1];
	qcols[callid_col=n_query_cols++]      = &str_callid_col;
	qvals[callid_col].type                = DB_STR;
	qvals[callid_col].val.str_val         = dlg->callid;

	LM_DBG("Deleted cid=[%.*s], local_index=[%d]\n",
			dlg->callid.len, dlg->callid.s, dlg->id);

	if(b2be_dbf.use_table(b2be_db, &dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	if(b2be_dbf.delete(b2be_db, qcols, 0, qvals, n_query_cols)< 0)
	{
		LM_ERR("Sql insert failed\n");
		return;
	}
}



static inline int mi_print_b2be_dlg(struct mi_node *rpl, b2b_table htable, unsigned int hsize)
{
	int i, len;
	char* p;
	b2b_dlg_t* dlg;
	dlg_leg_t* leg;
	struct mi_node *node=NULL, *node1=NULL;
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
				if(dlg->uac_tran)
					attr = add_mi_attr(node1,MI_DUP_VALUE,"uac",3,NULL,0);
					if(attr == NULL) goto error;
				if(dlg->uas_tran)
					attr = add_mi_attr(node1,MI_DUP_VALUE,"uas",3,NULL,0);
					if(attr == NULL) goto error;
				if(dlg->update_tran)
					attr = add_mi_attr(node1,MI_DUP_VALUE,"update",6,NULL,0);
					if(attr == NULL) goto error;
				if(dlg->cancel_tm_tran)
					attr = add_mi_attr(node1,MI_DUP_VALUE,"cancel_tm",9,NULL,0);
					if(attr == NULL) goto error;
			}

			leg=dlg->legs;
			while(leg)
			{
				p = int2str((unsigned long)(leg->id), &len);
				node1 = add_mi_node_child(node, MI_DUP_VALUE, "leg", 3, p, len);
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
					attr = add_mi_attr(node1, MI_DUP_VALUE, "route_set", 8,
						leg->route_set.s, leg->route_set.len);
					if(attr == NULL) goto error;
				}

				leg=leg->next;
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

