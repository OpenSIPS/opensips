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
#include "../../lib/osips_malloc.h"
#include "b2b_logic.h"
#include "b2bl_db.h"
#include "entity_storage.h"

#define B2BL_FETCH_SIZE  128
static str str_key_col         = str_init("si_key");
static str str_scenario_col    = str_init("scenario");
static str str_sstate_col      = str_init("sstate");
static str str_lifetime_col    = str_init("lifetime");
static str str_e1_type_col     = str_init("e1_type");
static str str_e1_sid_col      = str_init("e1_sid");
static str str_e1_to_col       = str_init("e1_to");
static str str_e1_from_col     = str_init("e1_from");
static str str_e1_key_col      = str_init("e1_key");
static str str_e1_sdp_col      = str_init("e1_sdp");
static str str_e2_type_col     = str_init("e2_type");
static str str_e2_sid_col      = str_init("e2_sid");
static str str_e2_to_col       = str_init("e2_to");
static str str_e2_from_col     = str_init("e2_from");
static str str_e2_key_col      = str_init("e2_key");
static str str_e2_sdp_col      = str_init("e2_sdp");
static str str_e3_type_col     = str_init("e3_type");
static str str_e3_sid_col      = str_init("e3_sid");
static str str_e3_to_col       = str_init("e3_to");
static str str_e3_from_col     = str_init("e3_from");
static str str_e3_key_col      = str_init("e3_key");

#define DB_COLS_NO  21
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
	n_query_update= 2;
	qcols[2]      = &str_sstate_col;
	qvals[2].type = DB_INT;
	qcols[3]     = &str_lifetime_col;
	qvals[3].type= DB_INT;
	qcols[4]     = &str_e1_type_col;
	qvals[4].type= DB_INT;
	qcols[5]     = &str_e1_sid_col;
	qvals[5].type= DB_STR;
	qcols[6]     = &str_e1_to_col;
	qvals[6].type= DB_STR;
	qcols[7]     = &str_e1_from_col;
	qvals[7].type= DB_STR;
	qcols[8]     = &str_e1_key_col;
	qvals[8].type= DB_STR;
	qcols[9]      = &str_e1_sdp_col;
	qvals[9].type = DB_STR;
	qcols[10]     = &str_e2_type_col;
	qvals[10].type= DB_INT;
	qcols[11]     = &str_e2_sid_col;
	qvals[11].type= DB_STR;
	qcols[12]     = &str_e2_to_col;
	qvals[12].type= DB_STR;
	qcols[13]     = &str_e2_from_col;
	qvals[13].type= DB_STR;
	qcols[14]     = &str_e2_key_col;
	qvals[14].type= DB_STR;
	qcols[15]      = &str_e2_sdp_col;
	qvals[15].type = DB_STR;
	qcols[16]     = &str_e3_type_col;
	qvals[16].type= DB_INT;
	qcols[17]     = &str_e3_sid_col;
	qvals[17].type= DB_STR;
	qcols[18]     = &str_e3_to_col;
	qvals[18].type= DB_STR;
	qcols[19]     = &str_e3_from_col;
	qvals[19].type= DB_STR;
	qcols[20]     = &str_e3_key_col;
	qvals[20].type= DB_STR;
}

static inline str *get_b2bl_map_key(str *tuple_key)
{
	static str key = {0,0};

	/* map key format: [prefix][tuple_key] */
	key.len = cdb_key_prefix.len + tuple_key->len;
	key.s = pkg_malloc(key.len);
	if (!key.s) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}

	memcpy(key.s, cdb_key_prefix.s, cdb_key_prefix.len);
	memcpy(key.s + cdb_key_prefix.len, tuple_key->s, tuple_key->len);

	return &key;
}

void b2bl_db_delete(b2bl_tuple_t* tuple)
{
	str *cdb_key;

	if(!tuple || !tuple->key || b2bl_db_mode==NO_DB ||
		(b2bl_db_mode==WRITE_BACK && tuple->db_flag==INSERTDB_FLAG))
		return;

	LM_DBG("Delete key = %.*s\n", tuple->key->len, tuple->key->s);

	qvals[0].val.str_val = *tuple->key;

	if (db_url.s) {
		if(b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
		{
			LM_ERR("sql use table failed\n");
			return;
		}

		if(b2bl_dbf.delete(b2bl_db, qcols, 0, qvals, 1) < 0)
		{
			LM_ERR("Failed to delete from database table [%.*s]\n",
					tuple->key->len, tuple->key->s);
		}
	} else {
		cdb_key = get_b2bl_map_key(&qvals[0].val.str_val);
		if (!cdb_key) {
			LM_ERR("Failed to build map key\n");
			return;
		}

		if (b2bl_cdbf.map_remove(b2bl_cdb, cdb_key, NULL) != 0)
			LM_ERR("Failed to delete from cachedb\n");

		pkg_free(cdb_key->s);
	}
}

void cdb_add_n_pairs(cdb_dict_t *pairs, int idx_start, int idx_end)
{
	int i;

	for (i = idx_start; i <= idx_end; i++)
		if (qvals[i].nul || (qvals[i].type == DB_STR && !qvals[i].val.str_val.s))
			cdb_dict_add_null(pairs, qcols[i]->s, qcols[i]->len);
		else if (qvals[i].type == DB_STR)
			cdb_dict_add_str(pairs, qcols[i]->s, qcols[i]->len,
				&qvals[i].val.str_val);
		else if (qvals[i].type == DB_INT)
			cdb_dict_add_int32(pairs, qcols[i]->s, qcols[i]->len,
				qvals[i].val.int_val);
}

void b2b_logic_dump(int no_lock)
{
	b2bl_tuple_t* tuple;
	int i, j;
	int n_insert_cols;
	cdb_dict_t cdb_pairs;
	str *cdb_key;

	if(db_url.s && b2bl_dbf.use_table(b2bl_db, &b2bl_dbtable)< 0)
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
				if (tuple->scenario_id == B2B_TOP_HIDING_ID_PTR) {
					qvals[1].val.str_val.len = B2B_TOP_HIDING_SCENARY_LEN;
					qvals[1].val.str_val.s = B2B_TOP_HIDING_SCENARY;
				} else if (tuple->scenario_id == B2B_INTERNAL_ID_PTR) {
					qvals[1].val.str_val.len = 0;
					qvals[1].val.str_val.s = "";
				} else {
					qvals[1].val.str_val = *tuple->scenario_id;
				}
			}

			qvals[2].val.int_val  = tuple->state;
			qvals[3].val.int_val = tuple->lifetime - get_ticks() + (int)time(NULL);
			qvals[4].val.int_val = tuple->bridge_entities[0]->type;
			qvals[5].val.str_val = tuple->bridge_entities[0]->scenario_id;
			qvals[6].val.str_val = tuple->bridge_entities[0]->to_uri;
			qvals[7].val.str_val = tuple->bridge_entities[0]->from_uri;
			qvals[8].val.str_val = tuple->bridge_entities[0]->key;
			qvals[9].val.str_val = tuple->bridge_entities[0]->out_sdp;
			qvals[10].val.int_val = tuple->bridge_entities[1]->type;
			qvals[11].val.str_val = tuple->bridge_entities[1]->scenario_id;
			qvals[12].val.str_val = tuple->bridge_entities[1]->to_uri;
			qvals[13].val.str_val = tuple->bridge_entities[1]->from_uri;
			qvals[14].val.str_val = tuple->bridge_entities[1]->key;
			qvals[15].val.str_val = tuple->bridge_entities[1]->out_sdp;

			n_insert_cols = 16;

			if(tuple->bridge_entities[2])
			{
				qvals[15].val.int_val = tuple->bridge_entities[2]->type;
				qvals[16].val.str_val = tuple->bridge_entities[2]->scenario_id;
				qvals[17].val.str_val = tuple->bridge_entities[2]->to_uri;
				qvals[18].val.str_val = tuple->bridge_entities[2]->from_uri;
				qvals[19].val.str_val = tuple->bridge_entities[2]->key;
			}

			/* insert into database */
			if(tuple->db_flag == INSERTDB_FLAG)
			{
				if (cdb_url.s) {
					cdb_dict_init(&cdb_pairs);

					cdb_key = get_b2bl_map_key(&qvals[0].val.str_val);
					if (!cdb_key) {
						LM_ERR("Failed to build map key\n");
						if(!no_lock)
							lock_release(&b2bl_htable[i].lock);
						return;
					}

					cdb_add_n_pairs(&cdb_pairs, 0, n_insert_cols - 1);

					if(!tuple->bridge_entities[2]) {
						for(j = n_insert_cols; j < n_insert_cols + 5; j++)
							qvals[j].nul = 1;

						cdb_add_n_pairs(&cdb_pairs,n_insert_cols,n_insert_cols+4);

						for(j = n_insert_cols; j < n_insert_cols + 5; j++)
							qvals[j].nul = 0;
					}

					if (b2bl_cdbf.map_set(b2bl_cdb, cdb_key, NULL, &cdb_pairs))
						LM_ERR("cachedb set failed\n");

					pkg_free(cdb_key->s);
					cdb_free_entries(&cdb_pairs, NULL);
				} else {
					n_insert_cols = DB_COLS_NO;

					if(b2bl_dbf.insert(b2bl_db, qcols, qvals, n_insert_cols)< 0)
					{
						LM_ERR("Sql insert failed\n");
						if(!no_lock)
							lock_release(&b2bl_htable[i].lock);
						return;
					}
				}
			}
			else
			{
				if (cdb_url.s) {
					cdb_dict_init(&cdb_pairs);

					cdb_key = get_b2bl_map_key(&qvals[0].val.str_val);
					if (!cdb_key) {
						LM_ERR("Failed to build map key\n");
						if(!no_lock)
							lock_release(&b2bl_htable[i].lock);
						return;
					}

					cdb_add_n_pairs(&cdb_pairs, n_query_update, n_insert_cols-1);

					if (b2bl_cdbf.map_set(b2bl_cdb, cdb_key, NULL, &cdb_pairs))
						LM_ERR("cachedb set failed\n");

					pkg_free(cdb_key->s);
					cdb_free_entries(&cdb_pairs, NULL);
				} else {
					/*do update */
					if(b2bl_dbf.update(b2bl_db,qcols,0,qvals,qcols+n_query_update,
						qvals+n_query_update, 1, DB_COLS_NO - n_query_update)< 0)
					{
						LM_ERR("Sql update failed\n");
						if(!no_lock)
							lock_release(&b2bl_htable[i].lock);
						return;
					}
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

static int b2bl_add_tuple(b2bl_tuple_t* tuple)
{
	b2bl_tuple_t* shm_tuple= NULL;
	unsigned int hash_index, local_index;
	str* b2bl_key;
	b2bl_entity_id_t* entity;
	int i;
	b2b_notify_t cback;
	str* client_id = NULL;
	unsigned int logic_restored = 0;
	struct b2b_params init_params;

	LM_DBG("Add tuple key [%.*s]\n", tuple->key->len, tuple->key->s);
	if(b2bl_parse_key(tuple->key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Wrong formatted b2b logic key\n");
		return -1;
	}

	memset(&init_params, 0, sizeof init_params);
	init_params.id = tuple->scenario_id;
	init_params.req_routeid = global_req_rtid;
	init_params.reply_routeid = global_reply_rtid;


	shm_tuple = b2bl_insert_new(NULL, hash_index, &init_params,
			NULL, local_index,
			&b2bl_key, UPDATEDB_FLAG, TUPLE_NO_REPL);
	if(shm_tuple == NULL)
	{
		LM_ERR("Failed to insert new tuple\n");
		return -1;
	}
	shm_tuple->lifetime = tuple->lifetime;
	lock_release(&b2bl_htable[hash_index].lock);
	shm_tuple->state= tuple->state;

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
			&tuple->bridge_entities[i]->key, cback, NULL, NULL)< 0)
			LM_WARN("Failed to restore logic info for tuple:entity [%.*s][%d]\n",
				b2bl_key->len, b2bl_key->s, i);
		else
			logic_restored = 1;

		/* TODO: store headers in database */
		entity= b2bl_create_new_entity(tuple->bridge_entities[i]->type,
			&tuple->bridge_entities[i]->key,&tuple->bridge_entities[i]->to_uri, 0,
			&tuple->bridge_entities[i]->from_uri, 0,
			&tuple->bridge_entities[i]->scenario_id,0, 0, 0);
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

	if (shm_str_dup(&shm_tuple->bridge_entities[0]->out_sdp,
		&tuple->bridge_entities[0]->out_sdp) < 0)
		goto error;
	if (shm_str_dup(&shm_tuple->bridge_entities[0]->in_sdp,
		&tuple->bridge_entities[1]->out_sdp) < 0)
		goto error;
	if (shm_str_dup(&shm_tuple->bridge_entities[1]->out_sdp,
		&tuple->bridge_entities[1]->out_sdp) < 0)
		goto error;
	if (shm_str_dup(&shm_tuple->bridge_entities[1]->in_sdp,
		&tuple->bridge_entities[0]->out_sdp) < 0)
		goto error;

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

static int load_tuple(int_str_t *vals)
{
	int _time;
	b2bl_tuple_t tuple;
	str b2bl_key;
	str scenario_id;
	b2bl_entity_id_t bridge_entities[3];

	memset(&tuple, 0, sizeof(b2bl_tuple_t));

	b2bl_key = vals[0].s;

	tuple.key = &b2bl_key;
	if(vals[1].s.s)
	{
		scenario_id = vals[1].s;

		if (!str_strcmp(&scenario_id, const_str(B2B_TOP_HIDING_SCENARY)))
			tuple.scenario_id = B2B_TOP_HIDING_ID_PTR;
		else
			tuple.scenario_id = &scenario_id;
	} else {
		tuple.scenario_id = B2B_INTERNAL_ID_PTR;
	}
	memset(bridge_entities, 0, 3*sizeof(b2bl_entity_id_t));

	tuple.state = vals[2].i;
	_time = (int)time(NULL);
	if (vals[3].i <= _time)
		tuple.lifetime = 1;
	else
		tuple.lifetime=vals[3].i - _time + get_ticks();

	bridge_entities[0].type  = vals[4].i;
	bridge_entities[0].scenario_id = vals[5].s;
	bridge_entities[0].to_uri = vals[6].s;
	bridge_entities[0].from_uri = vals[7].s;
	bridge_entities[0].key = vals[8].s;
	bridge_entities[0].out_sdp = vals[9].s;

	bridge_entities[1].type = vals[10].i;
	bridge_entities[1].scenario_id = vals[11].s;
	bridge_entities[1].to_uri = vals[12].s;
	bridge_entities[1].from_uri = vals[13].s;
	bridge_entities[1].key = vals[14].s;
	bridge_entities[1].out_sdp = vals[15].s;

	if(vals[20].s.s)
	{
		bridge_entities[2].type = vals[16].i;
		bridge_entities[2].scenario_id = vals[17].s;
		bridge_entities[2].to_uri = vals[18].s;
		bridge_entities[2].from_uri = vals[19].s;
		bridge_entities[2].key = vals[20].s;
	}

	tuple.bridge_entities[0] = &bridge_entities[0];
	tuple.bridge_entities[1] = &bridge_entities[1];
	tuple.bridge_entities[2] = &bridge_entities[2];

	if(b2bl_add_tuple(&tuple) < 0)
	{
		LM_ERR("Failed to add new tuple\n");
		return -1;
	}

	return 0;
}

int b2b_logic_restore_db(void)
{
	int i;
	int nr_rows;
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	int_str_t vals[DB_COLS_NO];

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

			memset(vals, 0, sizeof vals);

			vals[0].s.s = (char*)row_vals[0].val.string_val;
			vals[0].s.len = vals[0].s.s?strlen(vals[0].s.s):0;

			vals[1].s.s = (char*)row_vals[1].val.string_val;
			vals[1].s.len = vals[1].s.s?strlen(vals[1].s.s):0;

			vals[2].i = row_vals[2].val.int_val;
			vals[3].i = row_vals[3].val.int_val;

			vals[4].i = row_vals[4].val.int_val;
			vals[5].s.s = (char*)row_vals[5].val.string_val;
			vals[5].s.len = vals[5].s.s?strlen(vals[5].s.s):0;
			vals[6].s.s = (char*)row_vals[6].val.string_val;
			vals[6].s.len = vals[6].s.s?strlen(vals[6].s.s):0;
			vals[7].s.s = (char*)row_vals[7].val.string_val;
			vals[7].s.len = vals[7].s.s?strlen(vals[7].s.s):0;
			vals[8].s.s = (char*)row_vals[8].val.string_val;
			vals[8].s.len = vals[8].s.s?strlen(vals[8].s.s):0;
			vals[9].s.s = (char*)row_vals[9].val.string_val;
			vals[9].s.len = vals[9].s.s?strlen(vals[9].s.s):0;

			vals[10].i = row_vals[10].val.int_val;
			vals[11].s.s = (char*)row_vals[11].val.string_val;
			vals[11].s.len = vals[11].s.s?strlen(vals[11].s.s):0;
			vals[12].s.s = (char*)row_vals[12].val.string_val;
			vals[12].s.len = vals[12].s.s?strlen(vals[12].s.s):0;
			vals[13].s.s = (char*)row_vals[13].val.string_val;
			vals[13].s.len = vals[13].s.s?strlen(vals[13].s.s):0;
			vals[14].s.s  = (char*)row_vals[14].val.string_val;
			vals[14].s.len = vals[14].s.s?strlen(vals[14].s.s):0;
			vals[15].s.s  = (char*)row_vals[15].val.string_val;
			vals[15].s.len = vals[15].s.s?strlen(vals[15].s.s):0;

			if(row_vals[16].val.string_val) {
				vals[16].i = row_vals[16].val.int_val;
				vals[17].s.s = (char*)row_vals[17].val.string_val;
				vals[17].s.len = vals[17].s.s?strlen(vals[17].s.s):0;
				vals[18].s.s = (char*)row_vals[18].val.string_val;
				vals[18].s.len = vals[18].s.s?strlen(vals[18].s.s):0;
				vals[19].s.s = (char*)row_vals[19].val.string_val;
				vals[19].s.len = vals[19].s.s?strlen(vals[19].s.s):0;
				vals[20].s.s = (char*)row_vals[20].val.string_val;
				vals[20].s.len = vals[20].s.s?strlen(vals[20].s.s):0;
			} else {
				/* just mark 'e3_key' field as null for load_tuple() */
				vals[21].s.s = NULL;
			}

			if (load_tuple(vals) < 0)
				goto error;
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

static int get_val_from_dict(int idx, int is_str, cdb_dict_t *dict,
	int_str_t *vals)
{
	cdb_key_t key;
	cdb_pair_t *pair;

	key.is_pk = 0;
	key.name = *qcols[idx];

	pair = cdb_dict_fetch(&key, dict);
	if (!pair) {
		LM_ERR("Field '%.*s' not found\n", key.name.len, key.name.s);
		return -1;
	}

	if (is_str) {
		if (pair->val.type == CDB_STR) {
			vals[idx].s = pair->val.val.st;
		} else if (pair->val.type != CDB_NULL) {
			LM_ERR("Unexpected type [%d] for field '%.*s'\n",
				pair->val.type, key.name.len, key.name.s);
			return -1;
		}
	} else {
		if (pair->val.type == CDB_INT32) {
			vals[idx].i = pair->val.val.i32;
		} else if (pair->val.type != CDB_NULL) {
			LM_ERR("Unexpected type [%d] for field '%.*s'\n",
				pair->val.type, key.name.len, key.name.s);
			return -1;
		}
	}

	return 0;
}

int b2b_logic_restore_cdb(void)
{
	cdb_res_t res;
	cdb_row_t *row;
	struct list_head *_;
	cdb_pair_t *pair;
	int_str_t vals[DB_COLS_NO];

	if (b2bl_cdbf.map_get(b2bl_cdb, NULL, &res) != 0)
		LM_ERR("Failed to retrieve map keys\n");

	list_for_each (_, &res.rows) {
		row = list_entry(_, cdb_row_t, list);
		/* we have a single pair per row, that contains a dict
		 * with all the fields */
		pair = list_last_entry(&row->dict, cdb_pair_t, list);

		if (pair->key.name.len <= cdb_key_prefix.len ||
			memcmp(pair->key.name.s, cdb_key_prefix.s, cdb_key_prefix.len))
			continue;

		memset(vals, 0, sizeof vals);

		get_val_from_dict(0, 1, &pair->val.val.dict, vals);
		get_val_from_dict(1, 1, &pair->val.val.dict, vals);
		get_val_from_dict(2, 0, &pair->val.val.dict, vals);
		get_val_from_dict(3, 0, &pair->val.val.dict, vals);

		get_val_from_dict(4, 0, &pair->val.val.dict, vals);
		get_val_from_dict(5, 1, &pair->val.val.dict, vals);
		get_val_from_dict(6, 1, &pair->val.val.dict, vals);
		get_val_from_dict(7, 1, &pair->val.val.dict, vals);
		get_val_from_dict(8, 1, &pair->val.val.dict, vals);
		get_val_from_dict(9, 1, &pair->val.val.dict, vals);

		get_val_from_dict(10, 0, &pair->val.val.dict, vals);
		get_val_from_dict(11, 1, &pair->val.val.dict, vals);
		get_val_from_dict(12, 1, &pair->val.val.dict, vals);
		get_val_from_dict(13, 1, &pair->val.val.dict, vals);
		get_val_from_dict(14, 1, &pair->val.val.dict, vals);
		get_val_from_dict(15, 1, &pair->val.val.dict, vals);

		get_val_from_dict(16, 0, &pair->val.val.dict, vals);
		get_val_from_dict(17, 1, &pair->val.val.dict, vals);
		get_val_from_dict(18, 1, &pair->val.val.dict, vals);
		get_val_from_dict(19, 1, &pair->val.val.dict, vals);
		get_val_from_dict(20, 1, &pair->val.val.dict, vals);

		if (load_tuple(vals) < 0) {
			cdb_free_rows(&res);
			return -1;
		}
	}

	cdb_free_rows(&res);

	return 0;
}

int b2b_logic_restore(void)
{
	if (db_url.s)
		return b2b_logic_restore_db();
	else
		return b2b_logic_restore_cdb();
}

void b2bl_db_insert(b2bl_tuple_t* tuple)
{
	int ci;
	int i, j;
	cdb_dict_t cdb_pairs;
	str *cdb_key;

	qvals[0].val.str_val = *tuple->key;
	if (tuple->scenario_id == B2B_TOP_HIDING_ID_PTR) {
		qvals[1].val.str_val.len = B2B_TOP_HIDING_SCENARY_LEN;
		qvals[1].val.str_val.s = B2B_TOP_HIDING_SCENARY;
	} else if (tuple->scenario_id == B2B_INTERNAL_ID_PTR) {
		qvals[1].val.str_val.len = 0;
		qvals[1].val.str_val.s = "";
	} else {
		qvals[1].val.str_val = *tuple->scenario_id;
	}

	qvals[2].val.int_val = tuple->state;
	qvals[3].val.int_val= tuple->lifetime - get_ticks() + (int)time(NULL);
	ci = 4;

	for(i = 0; i< 3; i++)
	{
		if(!tuple->bridge_entities[i])
			break;
		qvals[ci++].val.int_val = tuple->bridge_entities[i]->type;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->scenario_id;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->to_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->from_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->key;
		if (i<2)
			qvals[ci++].val.str_val = tuple->bridge_entities[i]->out_sdp;
	}

	if (cdb_url.s) {
		cdb_dict_init(&cdb_pairs);

		cdb_key = get_b2bl_map_key(&qvals[0].val.str_val);
		if (!cdb_key) {
			LM_ERR("Failed to build map key\n");
			return;
		}

		cdb_add_n_pairs(&cdb_pairs, 0, ci - 1);

		if(!tuple->bridge_entities[2]) {
			for(j = ci; j < ci + 5; j++)
				qvals[j].nul = 1;

			cdb_add_n_pairs(&cdb_pairs, ci, ci + 4);

			for(j = ci; j < ci + 5; j++)
				qvals[j].nul = 0;
		}

		if (b2bl_cdbf.map_set(b2bl_cdb, cdb_key, NULL, &cdb_pairs) != 0)
			LM_ERR("cachedb set failed\n");

		pkg_free(cdb_key->s);
		cdb_free_entries(&cdb_pairs, NULL);
	} else {
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
}

void b2bl_db_update(b2bl_tuple_t* tuple)
{
	int ci;
	int i;
	cdb_dict_t cdb_pairs;
	str *cdb_key;

	if(!tuple->key) {
		LM_ERR("No key found\n");
		return;
	}
	LM_DBG("key= %.*s\n", tuple->key->len, tuple->key->s);

	qvals[0].val.str_val = *tuple->key;

	qvals[3].val.int_val  = tuple->state;
	qvals[4].val.int_val = tuple->lifetime -get_ticks() + (int)time(NULL);
	ci = 4;

	for(i = 0; i< 3; i++)
	{
		if(!tuple->bridge_entities[i])
			break;
		qvals[ci++].val.int_val = tuple->bridge_entities[i]->type;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->scenario_id;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->to_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->from_uri;
		qvals[ci++].val.str_val = tuple->bridge_entities[i]->key;
		if (i<2)
			qvals[ci++].val.str_val = tuple->bridge_entities[i]->out_sdp;
		LM_DBG("UPDATE %.*s\n", qvals[ci-1].val.str_val.len, qvals[ci-1].val.str_val.s);
	}

	if (cdb_url.s) {
		cdb_dict_init(&cdb_pairs);

		cdb_key = get_b2bl_map_key(&qvals[0].val.str_val);
		if (!cdb_key) {
			LM_ERR("Failed to build map key\n");
			return;
		}

		cdb_add_n_pairs(&cdb_pairs, n_query_update, ci - 1);

		if (b2bl_cdbf.map_set(b2bl_cdb, cdb_key, NULL, &cdb_pairs) != 0)
			LM_ERR("cachedb set failed\n");

		pkg_free(cdb_key->s);
		cdb_free_entries(&cdb_pairs, NULL);
	} else {
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
}
