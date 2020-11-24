/*
 * back-to-back logic module
 *
 * Copyright (C) 2011 Free Software Fundation
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
 *  2011-04-04  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>

#include "../../db/db.h"
#include "b2b_logic.h"
#include "b2bl_db.h"
#include "entity_storage.h"

#define B2BL_FETCH_SIZE  128
static str str_key_col         = str_init("si_key");
static str str_scenario_col    = str_init("scenario");
static str str_sparam0_col     = str_init("sparam0");
static str str_sparam1_col     = str_init("sparam1");
static str str_sparam2_col     = str_init("sparam2");
static str str_sparam3_col     = str_init("sparam3");
static str str_sparam4_col     = str_init("sparam4");
static str str_sdp_col         = str_init("sdp");
static str str_sstate_col      = str_init("sstate");
static str str_next_sstate_col = str_init("next_sstate");
static str str_lifetime_col    = str_init("lifetime");
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

#define DB_COLS_NO  26
static db_key_t qcols[DB_COLS_NO];
static db_val_t qvals[DB_COLS_NO];
static int n_query_update;

/* initialize the column names and vals type -> take care always to keep this order */
void b2bl_db_init(void)
{
	memset(qvals, 0, DB_COLS_NO* sizeof(db_val_t));

	qcols[0]      = &str_key_col;
	qvals[0].type = DB_STR;
	qcols[1]      = &str_scenario_col;
	qvals[1].type = DB_STR;
	qcols[2]      = &str_sparam0_col;
	qvals[2].type = DB_STR;
	qcols[3]      = &str_sparam1_col;
	qvals[3].type = DB_STR;
	qcols[4]      = &str_sparam2_col;
	qvals[4].type = DB_STR;
	qcols[5]      = &str_sparam3_col;
	qvals[5].type = DB_STR;
	qcols[6]      = &str_sparam4_col;
	qvals[6].type = DB_STR;
	qcols[7]      = &str_sdp_col;
	qvals[7].type = DB_STR;
	n_query_update= 8;
	qcols[8]      = &str_sstate_col;
	qvals[8].type = DB_INT;
	qcols[9]      = &str_next_sstate_col;
	qvals[9].type = DB_INT;
	qcols[10]     = &str_lifetime_col;
	qvals[10].type= DB_INT;
	qcols[11]     = &str_e1_type_col;
	qvals[11].type= DB_INT;
	qcols[12]     = &str_e1_sid_col;
	qvals[12].type= DB_STR;
	qcols[13]     = &str_e1_to_col;
	qvals[13].type= DB_STR;
	qcols[14]     = &str_e1_from_col;
	qvals[14].type= DB_STR;
	qcols[15]     = &str_e1_key_col;
	qvals[15].type= DB_STR;
	qcols[16]     = &str_e2_type_col;
	qvals[16].type= DB_INT;
	qcols[17]     = &str_e2_sid_col;
	qvals[17].type= DB_STR;
	qcols[18]     = &str_e2_to_col;
	qvals[18].type= DB_STR;
	qcols[19]     = &str_e2_from_col;
	qvals[19].type= DB_STR;
	qcols[20]     = &str_e2_key_col;
	qvals[20].type= DB_STR;
	qcols[21]     = &str_e3_type_col;
	qvals[21].type= DB_INT;
	qcols[22]     = &str_e3_sid_col;
	qvals[22].type= DB_STR;
	qcols[23]     = &str_e3_to_col;
	qvals[23].type= DB_STR;
	qcols[24]     = &str_e3_from_col;
	qvals[24].type= DB_STR;
	qcols[25]     = &str_e3_key_col;
	qvals[25].type= DB_STR;
}

void b2bl_db_delete(b2bl_tuple_t* tuple)
{
	if(!tuple || !tuple->key || b2bl_db_mode==NO_DB ||
		(b2bl_db_mode==WRITE_BACK && tuple->db_flag==INSERTDB_FLAG))
		return;

	LM_DBG("Delete key = %.*s\n", tuple->key->len, tuple->key->s);

	if(b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	qvals[0].val.str_val = *tuple->key;

	if(b2bl_dbf.delete(b2bl_db, qcols, 0, qvals, 1) < 0)
	{
		LM_ERR("Failed to delete from database table [%.*s]\n",
				tuple->key->len, tuple->key->s);
	}
}

void b2b_logic_dump(int no_lock)
{
	b2bl_tuple_t* tuple;
	int i;
	int n_insert_cols;

	if(b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

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

			qvals[0].val.str_val = *tuple->key;
			if(tuple->db_flag == INSERTDB_FLAG)
			{
				if(tuple->scenario)
					qvals[1].val.str_val = tuple->scenario->id;
				else{
					qvals[1].val.str_val.len = 0;
					qvals[1].val.str_val.s = "";
				}

				qvals[2].val.str_val = tuple->scenario_params[0];
				qvals[3].val.str_val = tuple->scenario_params[1];
				qvals[4].val.str_val = tuple->scenario_params[2];
				qvals[5].val.str_val = tuple->scenario_params[3];
				qvals[6].val.str_val = tuple->scenario_params[4];
				qvals[7].val.str_val = tuple->sdp;
			}


			qvals[8].val.int_val  = tuple->scenario_state;
			qvals[9].val.int_val  = tuple->next_scenario_state;
			qvals[10].val.int_val = tuple->lifetime - get_ticks() + (int)time(NULL);
			qvals[11].val.int_val = tuple->bridge_entities[0]->type;
			qvals[12].val.str_val = tuple->bridge_entities[0]->scenario_id;
			qvals[13].val.str_val = tuple->bridge_entities[0]->to_uri;
			qvals[14].val.str_val = tuple->bridge_entities[0]->from_uri;
			qvals[15].val.str_val = tuple->bridge_entities[0]->key;
			qvals[16].val.int_val = tuple->bridge_entities[1]->type;
			qvals[17].val.str_val = tuple->bridge_entities[1]->scenario_id;
			qvals[18].val.str_val = tuple->bridge_entities[1]->to_uri;
			qvals[19].val.str_val = tuple->bridge_entities[1]->from_uri;
			qvals[20].val.str_val = tuple->bridge_entities[1]->key;

			n_insert_cols = 21;

			if(tuple->bridge_entities[2])
			{
				qvals[21].val.int_val = tuple->bridge_entities[2]->type;
				qvals[22].val.str_val = tuple->bridge_entities[2]->scenario_id;
				qvals[23].val.str_val = tuple->bridge_entities[2]->to_uri;
				qvals[24].val.str_val = tuple->bridge_entities[2]->from_uri;
				qvals[25].val.str_val = tuple->bridge_entities[2]->key;
			}
			n_insert_cols = DB_COLS_NO;

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
					qvals+n_query_update, 1, DB_COLS_NO - n_query_update)< 0)
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

static int b2bl_add_tuple(b2bl_tuple_t* tuple, str* params[])
{
	b2bl_tuple_t* shm_tuple= NULL;
	unsigned int hash_index, local_index;
	str* b2bl_key;
	b2bl_entity_id_t* entity;
	int i;
	b2b_notify_t cback;
	str* client_id = NULL;
	unsigned int logic_restored = 0;

	LM_DBG("Add tuple key [%.*s]\n", tuple->key->len, tuple->key->s);
	if(b2bl_parse_key(tuple->key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Wrong formatted b2b logic key\n");
		return -1;
	}
	shm_tuple = b2bl_insert_new(NULL, hash_index, tuple->scenario, params,
			(tuple->sdp.s?&tuple->sdp:NULL), NULL, local_index,
			&b2bl_key, UPDATEDB_FLAG, TUPLE_NO_REPL);
	if(shm_tuple == NULL)
	{
		LM_ERR("Failed to insert new tuple\n");
		return -1;
	}
	shm_tuple->lifetime = tuple->lifetime;
	lock_release(&b2bl_htable[hash_index].lock);
	shm_tuple->scenario_state= tuple->scenario_state;
	shm_tuple->next_scenario_state= tuple->next_scenario_state;

	/* add entities */
	for(i=0; i< MAX_BRIDGE_ENT; i++)
	{
		if(!tuple->bridge_entities[i]->to_uri.len)
			continue;
		LM_DBG("Restore logic info for tuple:entity [%.*s][%d]\n",
				b2bl_key->len, b2bl_key->s, i);

		if(tuple->bridge_entities[i]->type == B2B_SERVER)
			cback = b2b_server_notify;
		else
			cback = b2b_client_notify;

		/* restore to the entities from b2b_entities module
		 * the parameter and callback function */
		if(b2b_api.restore_logic_info(tuple->bridge_entities[i]->type,
			&tuple->bridge_entities[i]->key, cback)< 0)
			LM_WARN("Failed to restore logic info for tuple:entity [%.*s][%d]\n",
				b2bl_key->len, b2bl_key->s, i);
		else
			logic_restored = 1;

		/* TODO: store headers in database */
		entity= b2bl_create_new_entity(tuple->bridge_entities[i]->type,
			&tuple->bridge_entities[i]->key,&tuple->bridge_entities[i]->to_uri,
			&tuple->bridge_entities[i]->from_uri, 0, &tuple->bridge_entities[i]->scenario_id,0, 0);
		if(client_id)
			pkg_free(client_id);
		if(entity == NULL)
		{
			LM_ERR("Failed to create entity %d\n", i);
			goto error;
		}
		shm_tuple->bridge_entities[i]= entity;
		/* put the pointer in clients or servers array */
		// FIXME: check if the restore logic is ok
		if(tuple->bridge_entities[i]->type == B2B_SERVER)
		{
			if (shm_tuple->servers[0])
				shm_tuple->servers[1] = entity;
			else
				shm_tuple->servers[0] = entity;
		}
		else
		{
			if (shm_tuple->clients[0])
				shm_tuple->clients[1] = entity;
			else
				shm_tuple->clients[0] = entity;
		}
	}
	if(shm_tuple->bridge_entities[1])
		shm_tuple->bridge_entities[1]->peer = shm_tuple->bridge_entities[0];
	if(shm_tuple->bridge_entities[0])
		shm_tuple->bridge_entities[0]->peer = shm_tuple->bridge_entities[1];

	/* Mark tuple without entities as expired */
	if(logic_restored==0)
		shm_tuple->lifetime = 1;

	return 0;
error:
	shm_free(shm_tuple);
	return -1;
}

int b2b_logic_restore(void)
{
	int i;
	int nr_rows;
	int _time;
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	b2bl_tuple_t tuple;
	str b2bl_key;
	str scenario_id;
	b2bl_entity_id_t bridge_entities[3];
	str* params[MAX_SCENARIO_PARAMS];

	if(b2bl_db == NULL)
	{
		LM_DBG("NULL database connection\n");
		return 0;
	}
	if(b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}

	if (DB_CAPABILITY(b2bl_dbf, DB_CAP_FETCH))
	{
		if(b2bl_dbf.query(b2bl_db, 0, 0, 0, qcols, 0,
			DB_COLS_NO, 0, 0) < 0)
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
		if (b2bl_dbf.query(b2bl_db, 0, 0, 0, qcols, 0,
				DB_COLS_NO, 0, &result) < 0)
		{
			LM_ERR("querying presentity\n");
			return -1;
		}
	}

	nr_rows = RES_ROW_N(result);

	do {
		LM_DBG("loading [%i] records from db\n", nr_rows);

		rows = RES_ROWS(result);

		/* for every row */
		for(i=0; i<nr_rows; i++)
		{
			row_vals = ROW_VALUES(rows +i);
			memset(&tuple, 0, sizeof(b2bl_tuple_t));

			b2bl_key.s = (char*)row_vals[0].val.string_val;
			b2bl_key.len = b2bl_key.s?strlen(b2bl_key.s):0;

			tuple.key = &b2bl_key;
			if(row_vals[1].val.string_val)
			{
				scenario_id.s = (char*)row_vals[1].val.string_val;
				scenario_id.len = strlen(scenario_id.s);
				tuple.scenario = get_scenario_id(&scenario_id);
			}
			memset(bridge_entities, 0, 3*sizeof(b2bl_entity_id_t));
			memset(params, 0, MAX_SCENARIO_PARAMS* sizeof(str*));
			if(row_vals[2].val.string_val)
			{
				tuple.scenario_params[0].s =(char*)row_vals[2].val.string_val;
				tuple.scenario_params[0].len = strlen(tuple.scenario_params[0].s);
				params[0] = &tuple.scenario_params[0];
			}
			if(row_vals[3].val.string_val)
			{
				tuple.scenario_params[1].s =(char*)row_vals[3].val.string_val;
				tuple.scenario_params[1].len = strlen(tuple.scenario_params[1].s);
				params[1] = &tuple.scenario_params[1];
			}
			if(row_vals[4].val.string_val)
			{
				tuple.scenario_params[2].s =(char*)row_vals[4].val.string_val;
				tuple.scenario_params[2].len = strlen(tuple.scenario_params[2].s);
				params[2] = &tuple.scenario_params[2];
			}
			if(row_vals[5].val.string_val)
			{
				tuple.scenario_params[3].s =(char*)row_vals[5].val.string_val;
				tuple.scenario_params[3].len = strlen(tuple.scenario_params[3].s);
				params[3] = &tuple.scenario_params[3];
			}
			if(row_vals[6].val.string_val)
			{
				tuple.scenario_params[4].s =(char*)row_vals[6].val.string_val;
				tuple.scenario_params[4].len = strlen(tuple.scenario_params[4].s);
				params[4] = &tuple.scenario_params[4];
			}
			if(row_vals[7].val.string_val)
			{
				tuple.sdp.s =(char*)row_vals[7].val.string_val;
				tuple.sdp.len = strlen(tuple.sdp.s);
			}
			tuple.scenario_state     =row_vals[8].val.int_val;
			tuple.next_scenario_state=row_vals[9].val.int_val;
			_time = (int)time(NULL);
			if (row_vals[10].val.int_val <= _time)
				tuple.lifetime = 1;
			else
				tuple.lifetime=row_vals[10].val.int_val - _time + get_ticks();

			bridge_entities[0].type  = row_vals[11].val.int_val;
			bridge_entities[0].scenario_id.s =(char*)row_vals[12].val.string_val;
			bridge_entities[0].scenario_id.len=
				bridge_entities[0].scenario_id.s?strlen(bridge_entities[0].scenario_id.s):0;
			bridge_entities[0].to_uri.s  =(char*)row_vals[13].val.string_val;
			bridge_entities[0].to_uri.len=
				bridge_entities[0].to_uri.s?strlen(bridge_entities[0].to_uri.s):0;
			bridge_entities[0].from_uri.s=(char*)row_vals[14].val.string_val;
			bridge_entities[0].from_uri.len=
				bridge_entities[0].from_uri.s?strlen(bridge_entities[0].from_uri.s):0;
			bridge_entities[0].key.s  =(char*)row_vals[15].val.string_val;
			bridge_entities[0].key.len=
				bridge_entities[0].key.s?strlen(bridge_entities[0].key.s):0;

			bridge_entities[1].type = row_vals[16].val.int_val;
			bridge_entities[1].scenario_id.s  = (char*)row_vals[17].val.string_val;
			bridge_entities[1].scenario_id.len=
				bridge_entities[1].scenario_id.s?strlen(bridge_entities[1].scenario_id.s):0;
			bridge_entities[1].to_uri.s  = (char*)row_vals[18].val.string_val;
			bridge_entities[1].to_uri.len=
				bridge_entities[1].to_uri.s?strlen(bridge_entities[1].to_uri.s):0;
			bridge_entities[1].from_uri.s  = (char*)row_vals[19].val.string_val;
			bridge_entities[1].from_uri.len=
				bridge_entities[1].from_uri.s?strlen(bridge_entities[1].from_uri.s):0;
			bridge_entities[1].key.s  = (char*)row_vals[20].val.string_val;
			bridge_entities[1].key.len=
				bridge_entities[1].key.s?strlen(bridge_entities[1].key.s):0;

			if(row_vals[21].val.string_val)
			{
				bridge_entities[2].type = row_vals[21].val.int_val;
				bridge_entities[2].scenario_id.s  = (char*)row_vals[22].val.string_val;
				bridge_entities[2].scenario_id.len=
					bridge_entities[2].scenario_id.s?strlen(bridge_entities[2].scenario_id.s):0;
				bridge_entities[2].to_uri.s  = (char*)row_vals[23].val.string_val;
				bridge_entities[2].to_uri.len=
					bridge_entities[2].to_uri.s?strlen(bridge_entities[2].to_uri.s):0;
				bridge_entities[2].from_uri.s  = (char*)row_vals[24].val.string_val;
				bridge_entities[2].from_uri.len=
					bridge_entities[2].from_uri.s?strlen(bridge_entities[2].from_uri.s):0;
				bridge_entities[2].key.s  = (char*)row_vals[25].val.string_val;
				bridge_entities[2].key.len=
					bridge_entities[2].key.s?strlen(bridge_entities[2].key.s):0;
			}

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

	return 0;
error:
	if(result)
		b2bl_dbf.free_result(b2bl_db, result);
	return -1;
}

void b2bl_db_insert(b2bl_tuple_t* tuple)
{
	int ci;
	int i;

	qvals[0].val.str_val = *tuple->key;
	if(tuple->scenario)
		qvals[1].val.str_val = tuple->scenario->id;
	else{
		qvals[1].val.str_val.len = 0;
		qvals[1].val.str_val.s = "";
	}

	qvals[2].val.str_val = tuple->scenario_params[0];
	qvals[3].val.str_val = tuple->scenario_params[1];
	qvals[4].val.str_val = tuple->scenario_params[2];
	qvals[5].val.str_val = tuple->scenario_params[3];
	qvals[6].val.str_val = tuple->scenario_params[4];
	qvals[7].val.str_val = tuple->sdp;
	qvals[8].val.int_val = tuple->scenario_state;
	qvals[9].val.int_val = tuple->next_scenario_state;
	qvals[10].val.int_val= tuple->lifetime - get_ticks() + (int)time(NULL);
	ci = 11;

	for(i = 0; i< 3; i++)
	{
		if(!tuple->bridge_entities[i])
			break;
		qvals[ci++].val.int_val = tuple->bridge_entities[i]->type;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->scenario_id;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->to_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->from_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->key;
	}

	if(b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	if(b2bl_dbf.insert(b2bl_db, qcols, qvals, ci)< 0)
	{
		LM_ERR("Sql insert failed\n");
	}
}

void b2bl_db_update(b2bl_tuple_t* tuple)
{
	int ci;
	int i;

	if(!tuple->key) {
		LM_ERR("No key found\n");
		return;
	}
	LM_DBG("key= %.*s\n", tuple->key->len, tuple->key->s);

	qvals[0].val.str_val = *tuple->key;

	qvals[8].val.int_val  = tuple->scenario_state;
	qvals[9].val.int_val  = tuple->next_scenario_state;
	qvals[10].val.int_val = tuple->lifetime -get_ticks() + (int)time(NULL);
	ci = 11;

	for(i = 0; i< 3; i++)
	{
		if(!tuple->bridge_entities[i])
			break;
		qvals[ci++].val.int_val = tuple->bridge_entities[i]->type;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->scenario_id;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->to_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->from_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->key;
		LM_DBG("UPDATE %.*s\n", qvals[ci-1].val.str_val.len, qvals[ci-1].val.str_val.s);
	}

	if(b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	if(b2bl_dbf.update(b2bl_db, qcols, 0, qvals, qcols+n_query_update,
		qvals+n_query_update, 1, ci - n_query_update)< 0)
	{
		LM_ERR("Sql update failed\n");
	}
}

