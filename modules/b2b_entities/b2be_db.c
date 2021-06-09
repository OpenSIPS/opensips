/*
 * back-to-back entities module
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
#include <string.h>
#include <stdlib.h>

#include "../../db/db.h"
#include "../../dprint.h"
#include "../presence/hash.h"

#include "b2b_entities.h"
#include "b2be_db.h"

#define DB_COLS_NO  27

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
static str str_mod_name_col     = str_init("mod_name");
static str str_storage_col      = str_init("storage");

static db_key_t qcols[DB_COLS_NO];
static db_val_t qvals[DB_COLS_NO];
static int n_query_update, n_start_update;


void b2be_initialize(void)
{
	memset(qvals, 0, DB_COLS_NO*sizeof(db_val_t));
	qcols[0]      = &str_type_col;
	qvals[0].type = DB_INT;
	qcols[1]      = &str_tag0_col;
	qvals[1].type = DB_STR;
	qcols[2]      = &str_tag1_col;
	qvals[2].type = DB_STR;
	qcols[3]      = &str_callid_col;
	qvals[3].type = DB_STR;
	n_query_update= 4;

	qcols[4]     = &str_ruri_col;
	qvals[4].type= DB_STR;
	qcols[5]     = &str_from_col;
	qvals[5].type= DB_STR;
	qcols[6]     = &str_from_dname_col;
	qvals[6].type= DB_STR;
	qcols[7]     = &str_to_col;
	qvals[7].type= DB_STR;
	qcols[8]     = &str_to_dname_col;
	qvals[8].type= DB_STR;
	qcols[9]     = &str_route0_col;
	qvals[9].type= DB_STR;
	qcols[10]    = &str_route1_col;
	qvals[10].type= DB_STR;
	qcols[11]     = &str_sockinfo_srv_col;
	qvals[11].type= DB_STR;
	qcols[12]     = &str_param_col;
	qvals[12].type= DB_STR;
	qcols[13]     = &str_mod_name_col;
	qvals[13].type= DB_STR;
	n_start_update= 14;

	qcols[14]     = &str_storage_col;
	qvals[14].type= DB_BLOB;
	qcols[15]     = &str_state_col;
	qvals[15].type= DB_INT;
	qcols[16]     = &str_cseq0_col;
	qvals[16].type= DB_INT;
	qcols[17]     = &str_cseq1_col;
	qvals[17].type= DB_INT;
	qcols[18]     = &str_lm_col;
	qvals[18].type= DB_INT;
	qcols[19]     = &str_lrc_col;
	qvals[19].type= DB_INT;
	qcols[20]     = &str_lic_col;
	qvals[20].type= DB_INT;
	qcols[21]     = &str_contact0_col;
	qvals[21].type= DB_STR;
	qcols[22]     = &str_contact1_col;
	qvals[22].type= DB_STR;
	qcols[23]     = &str_leg_tag_col;
	qvals[23].type= DB_STR;
	qcols[24]     = &str_leg_cseq_col;
	qvals[24].type= DB_INT;
	qcols[25]     = &str_leg_contact_col;
	qvals[25].type= DB_STR;
	qcols[26]     = &str_leg_route_col;
	qvals[26].type= DB_STR;
}

int b2be_db_insert(b2b_dlg_t* dlg, int type)
{
	dlg_leg_t* leg;
	int cols_no;

	if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}

	qvals[0].val.int_val = type;
	qvals[1].val.str_val = dlg->tag[0];
	qvals[2].val.str_val = dlg->tag[1];
	qvals[3].val.str_val = dlg->callid;
	qvals[4].val.str_val = dlg->ruri;
	qvals[5].val.str_val = dlg->from_uri;
	qvals[6].val.str_val = dlg->from_dname;
	qvals[7].val.str_val = dlg->to_uri;
	qvals[8].val.str_val = dlg->to_dname;
	qvals[9].val.str_val = dlg->route_set[0];
	qvals[10].val.str_val= dlg->route_set[1];
	if(dlg->send_sock)
		qvals[11].val.str_val= dlg->send_sock->sock_str;
	else
	{
		qvals[11].val.str_val.s = 0;
		qvals[11].val.str_val.len = 0;
	}
	if (!str_check_token(&dlg->param)) {
		qvals[12].val.str_val.s = NULL;
		qvals[12].val.str_val.len = 0;
	} else {
		qvals[12].val.str_val = dlg->param;
	}
	qvals[13].val.str_val= dlg->mod_name;

	if (!dlg->storage.len) {
		VAL_NULL(qvals+14) = 1;
	} else {
		VAL_NULL(qvals+14) = 0;
		VAL_BLOB(qvals+14) = dlg->storage;
	}

	qvals[15].val.int_val = dlg->state;
	qvals[16].val.int_val = dlg->cseq[0];
	qvals[17].val.int_val = dlg->cseq[1];
	qvals[18].val.int_val = dlg->last_method;
	qvals[19].val.int_val = dlg->last_reply_code;
	qvals[20].val.int_val = dlg->last_invite_cseq;
	qvals[21].val.str_val = dlg->contact[0];
	qvals[22].val.str_val = dlg->contact[1];
	cols_no = 23;


	leg = dlg->legs;
	if(leg) /* there can only be one leg as we do not deal with dialogs in early state */
	{
		qvals[23].val.str_val= leg->tag;
		qvals[24].val.int_val= leg->cseq;
		qvals[25].val.str_val= leg->contact;
		qvals[26].val.str_val= leg->route_set;
		cols_no = 27;
	}

	/* insert into database */
	if(b2be_dbf.insert(b2be_db, qcols, qvals, cols_no)< 0)
	{
		LM_ERR("Sql insert failed\n");
		return -1;
	}
	LM_DBG("INSERTED [%.*s], [%.*s]\n", dlg->tag[0].len, dlg->tag[0].s, dlg->callid.len, dlg->callid.s);
	return 0;
}

int b2be_db_update(b2b_dlg_t* dlg, int type)
{
	dlg_leg_t* leg;
	int cols_no;

	qvals[0].val.int_val = type;

	if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}

	qvals[1].val.str_val     = dlg->tag[0];
	qvals[2].val.str_val     = dlg->tag[1];
	qvals[3].val.str_val     = dlg->callid;

	/* if the state is terminated delete the record */
	if(dlg->state == B2B_TERMINATED)
	{
		if(b2be_dbf.delete(b2be_db, qcols, 0, qvals, n_query_update)< 0)
		{
			LM_ERR("Sql delete failed\n");
			return -1;
		}
		return 0;
	}

	if (!dlg->storage.len) {
		VAL_NULL(qvals+14) = 1;
	} else {
		VAL_NULL(qvals+14) = 0;
		VAL_BLOB(qvals+14) = dlg->storage;
	}

	qvals[15].val.int_val = dlg->state;
	qvals[16].val.int_val = dlg->cseq[0];
	qvals[17].val.int_val = dlg->cseq[1];
	qvals[18].val.int_val = dlg->last_method;
	qvals[19].val.int_val = dlg->last_reply_code;
	qvals[20].val.int_val = dlg->last_invite_cseq;
	qvals[21].val.str_val = dlg->contact[0];
	qvals[22].val.str_val = dlg->contact[1];
	cols_no = 23;
	leg = dlg->legs;
	if(leg) /* there can only be one leg as we do not deal with dialogs in early state */
	{
		qvals[23].val.str_val= leg->tag;
		qvals[24].val.int_val= leg->cseq;
		qvals[25].val.str_val= leg->contact;
		qvals[26].val.str_val= leg->route_set;
		cols_no = 27;
	}

	if(b2be_dbf.update(b2be_db, qcols, 0, qvals,
			qcols+n_start_update, qvals+n_start_update,
			n_query_update, cols_no-n_start_update)< 0)
	{
		LM_ERR("Sql update failed\n");
		return -1;
	}
	LM_DBG("UPDATED [%.*s], [%.*s] State= %d\n", dlg->tag[0].len, dlg->tag[0].s,
		dlg->callid.len, dlg->callid.s, dlg->state);
	return 0;
}

void store_b2b_dlg(b2b_table htable, unsigned int hsize, int type, int no_lock)
{
	int i;
	dlg_leg_t* leg;
	b2b_dlg_t* dlg;

	if (!b2be_dbf.init)
		return;

	qvals[0].val.int_val = type;
	//LM_DBG("storing b2b_entities type '%d' in db\n", type);
	if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

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
			qvals[1].val.str_val     = dlg->tag[0];
			qvals[2].val.str_val     = dlg->tag[1];
			qvals[3].val.str_val     = dlg->callid;
			if(dlg->db_flag == INSERTDB_FLAG )
			{
				qvals[4].val.str_val = dlg->ruri;
				qvals[5].val.str_val = dlg->from_uri;
				qvals[6].val.str_val = dlg->from_dname;
				qvals[7].val.str_val = dlg->to_uri;
				qvals[8].val.str_val = dlg->to_dname;
				qvals[9].val.str_val = dlg->route_set[0];
				qvals[10].val.str_val= dlg->route_set[1];
				if(dlg->send_sock)
					qvals[11].val.str_val= dlg->send_sock->sock_str;
				else
				{
					qvals[11].val.str_val.s = 0;
					qvals[11].val.str_val.len = 0;
				}
				if (!str_check_token(&dlg->param)) {
					qvals[12].val.str_val.s = NULL;
					qvals[12].val.str_val.len = 0;
				} else {
					qvals[12].val.str_val = dlg->param;
				}
				qvals[13].val.str_val= dlg->mod_name;
			}

			if (!dlg->storage.len)
				VAL_NULL(qvals+14) = 1;
			else {
				VAL_NULL(qvals+14) = 0;
				VAL_BLOB(qvals+14) = dlg->storage;
			}

			qvals[15].val.int_val = dlg->state;
			qvals[16].val.int_val = dlg->cseq[0];
			qvals[17].val.int_val = dlg->cseq[1];
			qvals[18].val.int_val = dlg->last_method;
			qvals[19].val.int_val = dlg->last_reply_code;
			qvals[20].val.int_val = dlg->last_invite_cseq;
			qvals[21].val.str_val = dlg->contact[0];
			qvals[22].val.str_val = dlg->contact[1];

			leg = dlg->legs;
			if(leg) /* there can only be one leg as we do not deal with dialogs in early state */
			{
				qvals[23].val.str_val= leg->tag;
				qvals[24].val.int_val= leg->cseq;
				qvals[25].val.str_val= leg->contact;
				qvals[26].val.str_val= leg->route_set;
			}

			if(dlg->db_flag == INSERTDB_FLAG)
			{
				/* insert into database */
				if(b2be_dbf.insert(b2be_db, qcols, qvals, DB_COLS_NO)< 0)
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
							n_query_update, DB_COLS_NO-n_start_update)< 0)
				{
					LM_ERR("Sql update failed\n");
					if(!no_lock)
						lock_release(&htable[i].lock);
					return;
				}
			}

			if (b2be_db_mode == WRITE_BACK && dlg->storage.len) {
				shm_free(dlg->storage.s);
				dlg->storage.len = 0;
				dlg->storage.s = NULL;
			}

			dlg->db_flag = NO_UPDATEDB_FLAG;
			dlg = dlg->next;
		}
		if(!no_lock)
			lock_release(&htable[i].lock);
	}
}

int b2b_entities_restore(void)
{
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	int i;
	dlg_leg_t leg, *new_leg;
	b2b_dlg_t dlg, *shm_dlg= NULL;
	unsigned int hash_index, local_index;
	int nr_rows;
	str* b2b_key;
	str sockinfo_str;
	str host;
	int port, proto;
	b2b_table htable;
	int type;
	int no_rows = 10;
	uint64_t ts = 0;

	if(b2be_db == NULL)
	{
		LM_DBG("NULL database connection\n");
		return 0;
	}
	if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}
	if (DB_CAPABILITY(b2be_dbf, DB_CAP_FETCH))
	{
		if(b2be_dbf.query(b2be_db,0,0,0,qcols, 0,
			DB_COLS_NO, 0, 0) < 0)
		{
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		no_rows = estimate_available_rows( DB_COLS_NO*128, DB_COLS_NO);
		if (no_rows==0) no_rows = 10;
		if(b2be_dbf.fetch_result(b2be_db,&result,no_rows)<0)
		{
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	}
	else
	{
		if (b2be_dbf.query (b2be_db, 0, 0, 0,qcols,0, DB_COLS_NO,
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

			type           = row_vals[0].val.int_val;
			dlg.tag[1].s   = (char*)row_vals[2].val.string_val;
			dlg.tag[1].len = dlg.tag[1].s?strlen(dlg.tag[1].s):0;
			dlg.callid.s   = (char*)row_vals[3].val.string_val;
			dlg.callid.len = dlg.callid.s?strlen(dlg.callid.s):0;

			if(type == B2B_SERVER)/* extract hash and local index */
			{
				htable = server_htable;
				if(b2b_parse_key(&dlg.tag[1], &hash_index, &local_index, &ts) < 0)
				{
					LM_ERR("Wrong format for b2b key [%.*s]\n", dlg.tag[1].len, dlg.tag[1].s);
					goto error;
				}
				dlg.tag[1].s = NULL;
				dlg.tag[1].len = 0;

				if (hash_index >= server_hsize) {
					LM_ERR("Hash Index [%d] too large! Increase the 'server_hsize'"
						"parameter!\n", hash_index);
					goto error;
				}
			}
			else
			{
				htable = client_htable;

				if(b2b_parse_key(&dlg.callid, &hash_index, &local_index, NULL) < 0)
				{
					LM_ERR("Wrong format for b2b key [%.*s]\n", dlg.callid.len, dlg.callid.s);
					goto error;
				}

				if (hash_index >= client_hsize) {
					LM_DBG("Hash Index [%d] too large! Increase the 'client_hsize'"
						"parameter!\n", hash_index);
					goto error;
				}
			}
			dlg.id               = local_index;
			dlg.state            = row_vals[15].val.int_val;
			dlg.ruri.s           = (char*)row_vals[4].val.string_val;
			dlg.ruri.len         = dlg.ruri.s?strlen(dlg.ruri.s):0;
			dlg.from_uri.s       = (char*)row_vals[5].val.string_val;
			dlg.from_uri.len     = strlen(dlg.from_uri.s);
			dlg.from_dname.s     = (char*)row_vals[6].val.string_val;
			dlg.from_dname.len   = dlg.from_dname.s?strlen(dlg.from_dname.s):0;
			dlg.to_uri.s         = (char*)row_vals[7].val.string_val;
			dlg.to_uri.len       = strlen(dlg.to_uri.s);
			dlg.to_dname.s       = (char*)row_vals[8].val.string_val;
			dlg.to_dname.len     = dlg.to_dname.s?strlen(dlg.to_dname.s):0;
			dlg.tag[0].s         = (char*)row_vals[1].val.string_val;
			dlg.tag[0].len       = dlg.tag[0].s?strlen(dlg.tag[0].s):0;
			dlg.cseq[0]          = row_vals[16].val.int_val;
			dlg.cseq[1]          = row_vals[17].val.int_val;
			dlg.route_set[0].s   = (char*)row_vals[9].val.string_val;
			dlg.route_set[0].len = dlg.route_set[0].s?strlen(dlg.route_set[0].s):0;
			dlg.route_set[1].s   = (char*)row_vals[10].val.string_val;
			dlg.route_set[1].len = dlg.route_set[1].s?strlen(dlg.route_set[1].s):0;
			dlg.contact[0].s     = (char*)row_vals[21].val.string_val;
			dlg.contact[0].len   = dlg.contact[0].s?strlen(dlg.contact[0].s):0;
			dlg.contact[1].s     = (char*)row_vals[22].val.string_val;
			dlg.contact[1].len   = dlg.contact[1].s?strlen(dlg.contact[1].s):0;
			dlg.last_method      = row_vals[18].val.int_val;
			dlg.last_reply_code  = row_vals[19].val.int_val;
			dlg.last_invite_cseq = row_vals[20].val.int_val;
			dlg.param.s          = (char*)row_vals[12].val.string_val;
			dlg.param.len        = dlg.param.s?strlen(dlg.param.s):0;
			dlg.mod_name.s       = (char*)row_vals[13].val.string_val;
			dlg.mod_name.len     = dlg.mod_name.s?strlen(dlg.mod_name.s):0;
			sockinfo_str.s       = (char*)row_vals[11].val.string_val;
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
			dlg.db_flag = NO_UPDATEDB_FLAG;
			shm_dlg = b2b_dlg_copy(&dlg);
			if(shm_dlg == NULL)
			{
				LM_ERR("Failed to create new dialog structure\n");
				goto error;
			}
			b2b_key= b2b_htable_insert(htable,shm_dlg,hash_index, ts, type, 1, 0);
			if(b2b_key == NULL)
			{
				LM_ERR("Failed to insert new record\n");
				goto error;
			}
			pkg_free(b2b_key);

			if (!VAL_NULL(row_vals+14)) {
				if (shm_str_dup(&shm_dlg->storage, &(VAL_BLOB(row_vals+14))) < 0) {
					LM_ERR("oom!\n");
					goto error;
				}
			}

			memset(&leg, 0, sizeof(dlg_leg_t));
			leg.tag.s= (char*)row_vals[23].val.string_val;
			if(!leg.tag.s)
				continue;
			leg.tag.len       = strlen(leg.tag.s);
			leg.cseq          = row_vals[24].val.int_val;
			leg.contact.s     = (char*)row_vals[25].val.string_val;
			leg.contact.len   = leg.contact.s?strlen(leg.contact.s):0;
			leg.route_set.s   = (char*)row_vals[26].val.string_val;
			leg.route_set.len = leg.route_set.s?strlen(leg.route_set.s):0;

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
			if (b2be_dbf.fetch_result( b2be_db, &result, no_rows) < 0)
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

/* delete only one entity  */
void b2b_entity_db_delete(int type, b2b_dlg_t* dlg)
{
	if(!b2be_db)
		return;


	if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	qvals[0].val.int_val = type;
	qvals[1].val.str_val = dlg->tag[0];
	qvals[2].val.str_val = dlg->tag[1];
	qvals[3].val.str_val = dlg->callid;

	/* if the state is terminated delete the record */
	if(b2be_dbf.delete(b2be_db, qcols, 0, qvals, 4)< 0)
	{
		LM_ERR("Sql delete failed\n");
	}
}

/* delete all entities belonging to a tuple */
void b2b_db_delete(str param)
{

	if(!b2be_db)
		return;

	qvals[12].val.str_val = param;

	if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
	{
		LM_ERR("sql use table failed\n");
		return;
	}

	if(b2be_dbf.delete(b2be_db, qcols+12, 0, qvals+12, 1)< 0)
	{
		LM_ERR("Sql delete failed\n");
	}
}



