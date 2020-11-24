/*
 * sca_db_handler module
 *
 * Copyright (C) 2011 VoIP Embedded, Inc.
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
 *  2010-11-21  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <stdlib.h>

#include "../../dprint.h"
#include "../../db/db.h"
#include "../../str.h"
#include "sca_db_handler.h"
#include "sca_logic.h"


str shared_line_column = str_init(SHARED_LINE_COL);
str watchers_column = str_init(WATCHERS_COL);

str app_shared_entity_column[MAX_APPEARANCE_INDEX] = {
	str_init(SHARED_ENTITY_1_COL),
	str_init(SHARED_ENTITY_2_COL),
	str_init(SHARED_ENTITY_3_COL),
	str_init(SHARED_ENTITY_4_COL),
	str_init(SHARED_ENTITY_5_COL),
	str_init(SHARED_ENTITY_6_COL),
	str_init(SHARED_ENTITY_7_COL),
	str_init(SHARED_ENTITY_8_COL),
	str_init(SHARED_ENTITY_9_COL),
	str_init(SHARED_ENTITY_10_COL),
};
str app_call_state_column[MAX_APPEARANCE_INDEX] = {
	str_init(CALL_STATE_1_COL),
	str_init(CALL_STATE_2_COL),
	str_init(CALL_STATE_3_COL),
	str_init(CALL_STATE_4_COL),
	str_init(CALL_STATE_5_COL),
	str_init(CALL_STATE_6_COL),
	str_init(CALL_STATE_7_COL),
	str_init(CALL_STATE_8_COL),
	str_init(CALL_STATE_9_COL),
	str_init(CALL_STATE_10_COL),
};
str app_call_info_uri_column[MAX_APPEARANCE_INDEX] = {
	str_init(CALL_INFO_URI_1_COL),
	str_init(CALL_INFO_URI_2_COL),
	str_init(CALL_INFO_URI_3_COL),
	str_init(CALL_INFO_URI_4_COL),
	str_init(CALL_INFO_URI_5_COL),
	str_init(CALL_INFO_URI_6_COL),
	str_init(CALL_INFO_URI_7_COL),
	str_init(CALL_INFO_URI_8_COL),
	str_init(CALL_INFO_URI_9_COL),
	str_init(CALL_INFO_URI_10_COL),
};
str app_call_info_appearance_uri_column[MAX_APPEARANCE_INDEX] = {
	str_init(CALL_INFO_APPEARANCE_URI_1_COL),
	str_init(CALL_INFO_APPEARANCE_URI_2_COL),
	str_init(CALL_INFO_APPEARANCE_URI_3_COL),
	str_init(CALL_INFO_APPEARANCE_URI_4_COL),
	str_init(CALL_INFO_APPEARANCE_URI_5_COL),
	str_init(CALL_INFO_APPEARANCE_URI_6_COL),
	str_init(CALL_INFO_APPEARANCE_URI_7_COL),
	str_init(CALL_INFO_APPEARANCE_URI_8_COL),
	str_init(CALL_INFO_APPEARANCE_URI_9_COL),
	str_init(CALL_INFO_APPEARANCE_URI_10_COL),
};
str app_b2bl_key_column[MAX_APPEARANCE_INDEX] = {
	str_init(B2BL_KEY_1_COL),
	str_init(B2BL_KEY_2_COL),
	str_init(B2BL_KEY_3_COL),
	str_init(B2BL_KEY_4_COL),
	str_init(B2BL_KEY_5_COL),
	str_init(B2BL_KEY_6_COL),
	str_init(B2BL_KEY_7_COL),
	str_init(B2BL_KEY_8_COL),
	str_init(B2BL_KEY_9_COL),
	str_init(B2BL_KEY_10_COL),
};

str sca_table_name = str_init(SCA_TABLE_NAME);
int sca_db_mode = DB_MODE_NONE;

static db_con_t *sca_db_handle = NULL;
static db_func_t sca_dbf;

extern b2bl_api_t b2bl_api;

int connect_sca_db(const str *db_url)
{
	if (sca_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((sca_db_handle = sca_dbf.init(db_url)) == NULL)
		return -1;
	return 0;
}


static int use_sca_table(void)
{
	if(!sca_db_handle){
		LM_ERR("invalid database handle\n");
		return -1;
	}
	sca_dbf.use_table(sca_db_handle, &sca_table_name);
	return 0;
}


int delete_sca_info_from_db(b2b_sca_record_t *record)
{
	db_key_t q_cols[1] = {&shared_line_column};
	db_val_t q_vals[1];

	if(use_sca_table()) return -1;

	memset(q_vals, 0, sizeof(db_val_t));

	q_vals[0].type = DB_STR;
	q_vals[0].val.str_val = record->shared_line;

	/* Delete based on "q_cols" keys with matching "q_vals" values. */
	if(sca_dbf.delete(sca_db_handle, q_cols, 0, q_vals, 1) < 0) {
		LM_ERR("failed to delete record\n");
		return -1;
	}
	return 0;
}


int update_sca_info_to_db(b2b_sca_record_t *record, unsigned int appearance_index)
{
	b2b_sca_call_t *call;
	unsigned int i;
	unsigned int n_q_cols = 0, n_q_vals = 0;
	unsigned int shared_line_col, watchers_col;
	unsigned int app_shared_entity_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_state_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_info_uri_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_info_appearance_uri_col[MAX_APPEARANCE_INDEX];
	unsigned int app_b2bl_key_col[MAX_APPEARANCE_INDEX];
	db_key_t q_cols[SCA_TABLE_TOTAL_COL_NO];
	db_val_t q_vals[SCA_TABLE_TOTAL_COL_NO];


	LM_DBG("\n");
	if(use_sca_table()) return -1;

	memset(q_vals, 0, SCA_TABLE_TOTAL_COL_NO * sizeof(db_val_t));

	q_cols[shared_line_col		= n_q_cols++] = &shared_line_column;
	q_vals[shared_line_col].type	= DB_STR;
	q_cols[watchers_col		= n_q_cols++] = &watchers_column;
	q_vals[watchers_col].type	= DB_STR;

	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		q_cols[app_shared_entity_col[i]	= n_q_cols++] = &app_shared_entity_column[i];
		q_vals[app_shared_entity_col[i]].type = DB_INT;
		q_cols[app_call_state_col[i] = n_q_cols++] = &app_call_state_column[i];
		q_vals[app_call_state_col[i]].type = DB_INT;
		q_cols[app_call_info_uri_col[i] = n_q_cols++] = &app_call_info_uri_column[i];
		q_vals[app_call_info_uri_col[i]].type = DB_STR;
		q_cols[app_call_info_appearance_uri_col[i] = n_q_cols++] =
						&app_call_info_appearance_uri_column[i];
		q_vals[app_call_info_appearance_uri_col[i]].type = DB_STR;
		q_cols[app_b2bl_key_col[i] = n_q_cols++] = &app_b2bl_key_column[i];
		q_vals[app_b2bl_key_col[i]].type = DB_STR;
	}

	q_vals[shared_line_col].val.str_val = record->shared_line;

	i = appearance_index - 1;
	if (i >= MAX_APPEARANCE_INDEX) {
		LM_ERR("Non matching call\n");
		return -1;
	}

	call = record->call[i];
	if (call) {
		LM_DBG("update shared_entity [%d] and call_state [%d] for call[%d][%.*s]\n",
			call->shared_entity, call->call_state, i,
			call->b2bl_key.len, call->b2bl_key.s);
		switch(call->call_state) {
		case ALERTING_STATE:
			q_vals[app_call_info_uri_col[i]].val.str_val = call->call_info_uri;
			q_vals[app_call_info_appearance_uri_col[i]].val.str_val =
							call->call_info_apperance_uri;
			q_vals[app_b2bl_key_col[i]].val.str_val = call->b2bl_key;
			LM_DBG("update [%.*s][%.*s][%.*s]\n",
				call->call_info_uri.len, call->call_info_uri.s,
				call->call_info_apperance_uri.len, call->call_info_apperance_uri.s,
				call->b2bl_key.len, call->b2bl_key.s);
			n_q_vals += 3;
			/* fall through */
		default:
			q_vals[app_shared_entity_col[i]].val.int_val = call->shared_entity;
			q_vals[app_call_state_col[i]].val.int_val = call->call_state;
			n_q_vals += 2;
		}
	} else {
		n_q_vals = 5;
	}
	if(sca_dbf.update(sca_db_handle, q_cols, 0, q_vals,
			q_cols + app_shared_entity_col[i],
			q_vals + app_shared_entity_col[i], 1, n_q_vals) != 0) {
		LM_ERR("failed to update record\n");
		return -1;
	}

	return 0;
}


int insert_sca_info_into_db(b2b_sca_record_t *record)
{
	b2b_sca_call_t *call = NULL;
	unsigned int n_q_cols = 0;
	unsigned int i;
	unsigned int appearance_index = MAX_APPEARANCE_INDEX;
	unsigned int shared_line_col, watchers_col;
	unsigned int app_shared_entity_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_state_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_info_uri_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_info_appearance_uri_col[MAX_APPEARANCE_INDEX];
	unsigned int app_b2bl_key_col[MAX_APPEARANCE_INDEX];
	db_key_t q_cols[SCA_TABLE_TOTAL_COL_NO];
	db_val_t q_vals[SCA_TABLE_TOTAL_COL_NO];

	LM_DBG("\n");
	if(use_sca_table()) return -1;

	memset(q_vals, 0, SCA_TABLE_TOTAL_COL_NO * sizeof(db_val_t));

	q_cols[shared_line_col		= n_q_cols++] = &shared_line_column;
	q_vals[shared_line_col].type	= DB_STR;
	q_cols[watchers_col		= n_q_cols++] = &watchers_column;
	q_vals[watchers_col].type	= DB_STR;

	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		q_cols[app_shared_entity_col[i]	= n_q_cols++] = &app_shared_entity_column[i];
		q_vals[app_shared_entity_col[i]].type = DB_INT;
		q_cols[app_call_state_col[i] = n_q_cols++] = &app_call_state_column[i];
		q_vals[app_call_state_col[i]].type = DB_INT;
		q_cols[app_call_info_uri_col[i] = n_q_cols++] = &app_call_info_uri_column[i];
		q_vals[app_call_info_uri_col[i]].type = DB_STR;
		q_cols[app_call_info_appearance_uri_col[i] = n_q_cols++] =
						&app_call_info_appearance_uri_column[i];
		q_vals[app_call_info_appearance_uri_col[i]].type = DB_STR;
		q_cols[app_b2bl_key_col[i] = n_q_cols++] = &app_b2bl_key_column[i];
		q_vals[app_b2bl_key_col[i]].type = DB_STR;
	}

	q_vals[shared_line_col].val.str_val = record->shared_line;
	/* FIXME: get all the watchers */
	if (record->watchers) {
		q_vals[watchers_col].val.str_val = record->watchers->watcher;
	}

	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		if (record->call[i]) {
			if (call) {
				LM_ERR("This should be an UPDATE not an INSERT\n");
				return -1;
			}
			call = record->call[i];
			appearance_index = i;
		}
	}

	if (call) {
		q_vals[app_shared_entity_col[appearance_index]].val.int_val = call->shared_entity;
		q_vals[app_call_state_col[appearance_index]].val.int_val = call->call_state;
		q_vals[app_call_info_uri_col[appearance_index]].val.str_val = call->call_info_uri;
		q_vals[app_call_info_appearance_uri_col[appearance_index]].val.str_val =
							call->call_info_apperance_uri;
		q_vals[app_b2bl_key_col[appearance_index]].val.str_val = call->b2bl_key;

		if((sca_dbf.insert(sca_db_handle, q_cols, q_vals, SCA_TABLE_TOTAL_COL_NO)) != 0) {
			LM_ERR("could not add record\n");
			return -1;
		}
	} else {
		LM_ERR("Empty record?\n");
		return -1;
	}

	return 0;
}


int push_sca_info_to_db(b2b_sca_record_t *record, unsigned int appearance_index,
						unsigned int forced_update)
{
	unsigned int i;
	unsigned int no_calls = 0;
	b2b_sca_call_t *_call = NULL;

	LM_DBG("\n");
	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		if (record->call[i]) {
			no_calls++;
			_call = record->call[i];
		}
	}
	switch (no_calls) {
	case 0:
		return delete_sca_info_from_db(record);
		break;
	case 1:
		if (_call->call_state==ALERTING_STATE) {
			if (forced_update)
				return update_sca_info_to_db(record, appearance_index);
			else
				return insert_sca_info_into_db(record);
		} else {
			return update_sca_info_to_db(record, appearance_index);
		}
		break;
	default:
		return update_sca_info_to_db(record, appearance_index);
	}
	LM_ERR("logic error\n");
	return -1;

}


static int load_sca_info_from_db(void)
{
	db_res_t * res = NULL;
	db_val_t * values;
	db_row_t * rows;
	int i, j, nr_rows;
	unsigned int valid_record;
	unsigned int n_result_cols = 0;
	unsigned int shared_line_col, watchers_col;
	unsigned int app_shared_entity_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_state_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_info_uri_col[MAX_APPEARANCE_INDEX];
	unsigned int app_call_info_appearance_uri_col[MAX_APPEARANCE_INDEX];
	unsigned int app_b2bl_key_col[MAX_APPEARANCE_INDEX];
	db_key_t q_cols[SCA_TABLE_TOTAL_COL_NO];

	str shared_line, watchers_csv;
	//str_lst_t *watchers;
	//unsigned int size, watcher_size, watchers_no;
	//unsigned int size;
	unsigned int hash_index;
	//char *p;
	b2b_sca_record_t *record;
	b2b_sca_call_t *call;
	unsigned int shared_entity, appearance_index, call_state;
	str call_info_uri, call_info_apperance_uri, b2bl_key;
	b2bl_cb_ctx_t *cb_params;

	if(use_sca_table()) return -1;

	q_cols[shared_line_col = n_result_cols++] = &shared_line_column;
	q_cols[watchers_col = n_result_cols++] = &watchers_column;

	for (i=0; i<MAX_APPEARANCE_INDEX; i++) {
		q_cols[app_shared_entity_col[i]	= n_result_cols++] = &app_shared_entity_column[i];
		q_cols[app_call_state_col[i] = n_result_cols++] = &app_call_state_column[i];
		q_cols[app_call_info_uri_col[i] = n_result_cols++] = &app_call_info_uri_column[i];
		q_cols[app_call_info_appearance_uri_col[i] = n_result_cols++] =
						&app_call_info_appearance_uri_column[i];
		q_cols[app_b2bl_key_col[i] = n_result_cols++] = &app_b2bl_key_column[i];
	}

	/* select the whole tabel and all the columns */
	if (DB_CAPABILITY(sca_dbf, DB_CAP_FETCH)) {
		if(sca_dbf.query(sca_db_handle, 0, 0, 0, q_cols, 0,
				SCA_TABLE_TOTAL_COL_NO, 0, 0) < 0) {
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		if(sca_dbf.fetch_result(sca_db_handle, &res, SCA_FETCH_SIZE)<0){
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	} else {
		if(sca_dbf.query(sca_db_handle, 0, 0, 0, q_cols, 0,
				SCA_TABLE_TOTAL_COL_NO, 0, &res) < 0) {
			LM_ERR("Error while querying database\n");
			return -1;
		}
	}

	nr_rows = RES_ROW_N(res);

	do {
		LM_DBG("loading [%i] records from db\n", nr_rows);
		rows = RES_ROWS(res);
		/* for every row/record */
		for(i=0; i<nr_rows; i++){
			values = ROW_VALUES(rows + i);
			if (VAL_NULL(values+shared_line_col) || VAL_NULL(values+watchers_col)) {
				LM_ERR("columns [%.*s] or/and [%.*s] cannot be null -> skipping\n",
					shared_line_column.len, shared_line_column.s,
					watchers_column.len, watchers_column.s);
				continue;
			}
			shared_line.s = (char*)values[shared_line_col].val.string_val;
			shared_line.len = strlen(shared_line.s);

			watchers_csv.s = (char*)values[watchers_col].val.string_val;
			watchers_csv.len = strlen(watchers_csv.s);

			record = restore_record(&shared_line, &watchers_csv);
			if (record == NULL)
				goto error;
			hash_index = core_hash(&shared_line, NULL, b2b_sca_hsize);

			j = 0;
			while (j < MAX_APPEARANCE_INDEX) {
				if(	VAL_NULL(values + app_shared_entity_col[j]) ||
					VAL_NULL(values + app_call_state_col[j]) ||
					VAL_NULL(values + app_call_info_uri_col[j]) ||
					VAL_NULL(values + app_call_info_appearance_uri_col[j]) ||
					VAL_NULL(values + app_b2bl_key_col[j]) ) {
					goto cont;
				}
				appearance_index = j + 1;
				/* 1 - get shared_entity */
				shared_entity = values[app_shared_entity_col[j]].val.int_val;
				if (shared_entity!=0 && shared_entity!=1) {
					LM_ERR("Unexpected shared_entity [%d] "
						"for shared_line [%.*s]\n",
						shared_entity, shared_line.len, shared_line.s);
					goto cont;
				}
				/* 2 - get call_state */
				call_state = values[app_call_state_col[j]].val.int_val;
				if (call_state == IDLE_STATE) {
					LM_DBG("empty call[%d]\n", appearance_index);
					goto cont;
				}
				if (call_state > MAX_INDEX_STATE) {
					LM_ERR("Unexpected call_state [%d] for shared_line [%.*s]\n",
						call_state, shared_line.len, shared_line.s);
					goto cont;
				}
				/* 3 - get call_info_uri */
				call_info_uri.s =
					(char*)values[app_call_info_uri_col[j]].val.string_val;
				if (call_info_uri.s)
					call_info_uri.len = strlen(call_info_uri.s);
				else {
					LM_ERR("Missing call_info_uri for shared_line [%.*s][%d]\n",
						shared_line.len, shared_line.s, appearance_index);
					goto cont;
				}
				LM_DBG("call_info_uri=[%.*s]\n",
					call_info_uri.len, call_info_uri.s);
				/* 4 - get call_info_apperance_uri */
				call_info_apperance_uri.s =
					(char*)
					values[app_call_info_appearance_uri_col[j]].val.string_val;
				if (call_info_apperance_uri.s)
					call_info_apperance_uri.len =
						strlen(call_info_apperance_uri.s);
				else {
					LM_ERR("Missing call_info_apperance_uri for "
						"shared_line [%.*s][%d]\n",
						shared_line.len, shared_line.s, appearance_index);
					goto cont;
				}
				LM_DBG("call_info_apperance_uri=[%.*s]\n",
					call_info_apperance_uri.len, call_info_apperance_uri.s);
				/* 5 - get b2bl_key */
				b2bl_key.s = (char*)values[app_b2bl_key_col[j]].val.string_val;
				if (b2bl_key.s) {
					b2bl_key.len = strlen(b2bl_key.s);
					if (b2bl_key.len > B2BL_MAX_KEY_LEN) {
						LM_ERR("buffer overflow on b2bl_key [%.*s]"
							" for shared_line [%.*s][%d]\n",
							b2bl_key.len, b2bl_key.s,
							shared_line.len, shared_line.s,
							appearance_index);
						goto cont;
					}
					LM_DBG("b2bl_key=[%.*s]\n", b2bl_key.len, b2bl_key.s);
				} else {
					LM_ERR("Missing b2bl_key for shared_line [%.*s][1]\n",
						shared_line.len, shared_line.s);
					goto cont;
				}
				/* restore the call */
				call = restore_call(record, appearance_index,
					shared_entity, call_state,
					&call_info_uri, &call_info_apperance_uri);
				if (call == NULL) {
					goto error;
				}
				/* update record */
				if (0!=b2b_sca_update_call_record_key(call, &b2bl_key)) {
					LM_ERR("Unable to update b2bl_key [%.*s]\n",
						b2bl_key.len, b2bl_key.s);
					shm_free(call);
					call = NULL;
					record->call[appearance_index-1] = NULL;
					goto cont;
				}
				/* Prepare b2b_logic callback params. */
				cb_params = build_cb_params(hash_index,
							&shared_line, appearance_index);
				if (cb_params == NULL) {
					LM_ERR("Unable to build cb_params\n");
					goto error;
				}
				/* re-register callbacks */
				if(b2bl_api.register_cb(&b2bl_key, &sca_logic_notify, cb_params,
					B2B_RE_INVITE_CB|B2B_CONFIRMED_CB|B2B_DESTROY_CB) != 0){
					LM_ERR("Unable register b2b cb\n");
					shm_free(call);
					call = NULL;
					record->call[appearance_index-1] = NULL;
					goto cont;
				}
cont:
				j++;
			}

			valid_record = j = 0;
			while (j < MAX_APPEARANCE_INDEX) {
				if (record->call[j]) {
					valid_record = 1;
					goto check_valid_record;
				}
				j++;
			}
check_valid_record:
			if (valid_record) {
				b2b_sca_print_record(record);
				insert_record(hash_index, record);
			} else {
				LM_DBG("removing the record from db!\n");
				delete_sca_info_from_db(record);
			}
			LM_DBG("Done\n");
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(sca_dbf, DB_CAP_FETCH)) {
			if (sca_dbf.fetch_result(sca_db_handle, &res, SCA_FETCH_SIZE)<0) {
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(res);
		} else {
			nr_rows = 0;
		}
	}while (nr_rows>0);

	sca_dbf.free_result(sca_db_handle, res);
	return 0;
error:
	sca_dbf.free_result(sca_db_handle, res);
	return -1;
}


int init_sca_db(const str *db_url, int dlg_hash_size)
{
	/* Find a database module */
	if (db_bind_mod(db_url, &sca_dbf) < 0) {
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}
	if (connect_sca_db(db_url)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}
	if(db_check_table_version(&sca_dbf, sca_db_handle, &sca_table_name, SCA_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		return -1;
	}
	if(load_sca_info_from_db() !=0){
		LM_ERR("unable to load the sca data\n");
		return -1;
	}

	sca_dbf.close(sca_db_handle);
	sca_db_handle = NULL;

	return 0;
}

void destroy_sca_db(void)
{
	/* close the DB connection */
	if (sca_db_handle) {
		sca_dbf.close(sca_db_handle);
		sca_db_handle = NULL;
	}
}

