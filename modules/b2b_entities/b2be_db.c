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

void cdb_add_n_pairs(cdb_dict_t *pairs, int idx_start, int idx_end)
{
	int i;

	for (i = idx_start; i <= idx_end; i++)
		if (qvals[i].nul || (qvals[i].type == DB_STR && !qvals[i].val.str_val.s))
			cdb_dict_add_null(pairs, qcols[i]->s, qcols[i]->len);
		else if (qvals[i].type == DB_STR || qvals[i].type == DB_BLOB)
			cdb_dict_add_str(pairs, qcols[i]->s, qcols[i]->len,
				&qvals[i].val.str_val);
		else if (qvals[i].type == DB_INT)
			cdb_dict_add_int32(pairs, qcols[i]->s, qcols[i]->len,
				qvals[i].val.int_val);
}

static inline str *get_b2be_map_key(int type, str *tag0, str *tag1, str *callid)
{
	static str key = {0,0};
	int len = 3/*3 x '$'*/ + 1 /*type*/ + cdb_key_prefix.len +
	tag0->len + tag1->len + callid->len + 1;

	/* map key format: [prefix][type]$[tag0]$[tag1]$[callid] */
	key.s = pkg_malloc(len);
	if (!key.s) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}

	key.len = snprintf(key.s, len, "%.*s%d$%.*s$%.*s$%.*s",
		cdb_key_prefix.len, cdb_key_prefix.s, type, tag0->len, tag0->s,
		tag1->len, tag1->s, callid->len, callid->s);

	return &key;
}

static inline str *get_b2be_map_subkey(str *param)
{
	static str subkey = {0,0};

	/* subkey format: [prefix][param] */
	subkey.len = cdb_key_prefix.len + param->len;
	subkey.s = pkg_malloc(subkey.len);
	if (!subkey.s) {
		LM_ERR("no more pkg memory\n");
		return NULL;
	}

	memcpy(subkey.s, cdb_key_prefix.s, cdb_key_prefix.len);
	memcpy(subkey.s + cdb_key_prefix.len, param->s, param->len);

	return &subkey;
}

static int b2be_cdb_insert(int type, b2b_dlg_t* dlg, int cols_no)
{
	cdb_dict_t cdb_pairs;
	str *cdb_key, *cdb_subkey;
	int i;
	int rc;

	cdb_dict_init(&cdb_pairs);

	cdb_key = get_b2be_map_key(type, &dlg->tag[0], &dlg->tag[1], &dlg->callid);
	if (!cdb_key) {
		LM_ERR("Failed to build map key\n");
		return -1;
	}

	cdb_add_n_pairs(&cdb_pairs, 0, cols_no - 1);

	if(!dlg->legs) {
		for(i = cols_no; i < cols_no + 4; i++)
			qvals[i].nul = 1;

		cdb_add_n_pairs(&cdb_pairs, cols_no, cols_no + 3);

		for(i = cols_no; i < cols_no + 4; i++)
			qvals[i].nul = 0;
	}

	if (qvals[12].val.str_val.s) {
		cdb_subkey = get_b2be_map_subkey(&qvals[12].val.str_val);
		if (!cdb_subkey) {
			LM_ERR("Failed to build map subkey\n");
			pkg_free(cdb_key->s);
			cdb_free_entries(&cdb_pairs, NULL);
			return -1;
		}
	} else {
		cdb_subkey = NULL;
	}

	if ((rc = b2be_cdbf.map_set(b2be_cdb, cdb_key, cdb_subkey, &cdb_pairs)))
		LM_ERR("cachedb set failed\n");

	pkg_free(cdb_subkey->s);
	pkg_free(cdb_key->s);
	cdb_free_entries(&cdb_pairs, NULL);

	return rc;
}

int b2be_db_insert(b2b_dlg_t* dlg, int type)
{
	dlg_leg_t* leg;
	int cols_no;

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

	if (b2be_cdb_url.s) {
		if (b2be_cdb_insert(type, dlg, cols_no))
			return -1;
	} else {
		if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
		{
			LM_ERR("sql use table failed\n");
			return -1;
		}

		/* insert into database */
		if(b2be_dbf.insert(b2be_db, qcols, qvals, cols_no)< 0)
		{
			LM_ERR("Sql insert failed\n");
			return -1;
		}
	}

	LM_DBG("INSERTED [%.*s], [%.*s]\n", dlg->tag[0].len, dlg->tag[0].s,
		dlg->callid.len, dlg->callid.s);
	return 0;
}

static void b2b_entity_cdb_delete(int type, b2b_dlg_t* dlg)
{
	str *cdb_key, *cdb_subkey;

	cdb_key = get_b2be_map_key(type, &dlg->tag[0], &dlg->tag[1], &dlg->callid);
	if (!cdb_key) {
		LM_ERR("Failed to build map key\n");
		return;
	}

	if (!str_check_token(&dlg->param)) {
		cdb_subkey = NULL;
	} else {
		cdb_subkey = get_b2be_map_subkey(&dlg->param);
		if (!cdb_subkey) {
			LM_ERR("Failed to build map key\n");
			return;
		}
	}

	if (b2be_cdbf.map_remove(b2be_cdb, cdb_key, cdb_subkey) < 0)
		LM_ERR("Failed to delete from cachedb\n");

	if (cdb_subkey)
		pkg_free(cdb_subkey->s);
	pkg_free(cdb_key->s);
}

static int b2be_cdb_update(int type, b2b_dlg_t* dlg, int cols_no)
{
	cdb_dict_t cdb_pairs;
	str *cdb_key;
	int rc;

	cdb_dict_init(&cdb_pairs);

	cdb_key = get_b2be_map_key(type, &dlg->tag[0], &dlg->tag[1], &dlg->callid);
	if (!cdb_key) {
		LM_ERR("Failed to build map key\n");
		return -1;
	}

	cdb_add_n_pairs(&cdb_pairs, n_start_update, cols_no - 1);

	if ((rc = b2be_cdbf.map_set(b2be_cdb, cdb_key, NULL, &cdb_pairs)))
		LM_ERR("cachedb set failed\n");

	pkg_free(cdb_key->s);
	cdb_free_entries(&cdb_pairs, NULL);

	return rc;
}

int b2be_db_update(b2b_dlg_t* dlg, int type)
{
	dlg_leg_t* leg;
	int cols_no;

	qvals[0].val.int_val = type;
	qvals[1].val.str_val     = dlg->tag[0];
	qvals[2].val.str_val     = dlg->tag[1];
	qvals[3].val.str_val     = dlg->callid;

	/* if the state is terminated delete the record */
	if(dlg->state == B2B_TERMINATED)
	{
		if (b2be_cdb_url.s) {
			b2b_entity_cdb_delete(type, dlg);
		} else {
			if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
			{
				LM_ERR("sql use table failed\n");
				return -1;
			}

			if(b2be_dbf.delete(b2be_db, qcols, 0, qvals, n_query_update)< 0)
			{
				LM_ERR("Sql delete failed\n");
				return -1;
			}
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

	if (b2be_cdb_url.s) {
		if (b2be_cdb_update(type, dlg, cols_no))
			return -1;
	} else {
		if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
		{
			LM_ERR("sql use table failed\n");
			return -1;
		}

		if(b2be_dbf.update(b2be_db, qcols, 0, qvals,
				qcols+n_start_update, qvals+n_start_update,
				n_query_update, cols_no-n_start_update)< 0)
		{
			LM_ERR("Sql update failed\n");
			return -1;
		}
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
	int cols_no;

	if (db_url.s && !b2be_dbf.init)
		return;
	else if (b2be_cdb_url.s && !b2be_cdbf.init)
		return;

	qvals[0].val.int_val = type;
	//LM_DBG("storing b2b_entities type '%d' in db\n", type);
	if(db_url.s && b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
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

			if(dlg->db_flag == INSERTDB_FLAG)
			{
				if (b2be_cdb_url.s) {
					if (b2be_cdb_insert(type, dlg, cols_no)) {
						if(!no_lock)
							lock_release(&htable[i].lock);
						return;
					}
				} else {
					/* insert into database */
					if(b2be_dbf.insert(b2be_db, qcols, qvals, DB_COLS_NO)< 0)
					{
						LM_ERR("Sql insert failed\n");
						if(!no_lock)
							lock_release(&htable[i].lock);
						return;
					}
				}
			}
			else
			{
				if (b2be_cdb_url.s) {
					if (b2be_cdb_update(type, dlg, cols_no)) {
						if(!no_lock)
							lock_release(&htable[i].lock);
						return;
					}
				} else {
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

static int load_entity(int_str_t *vals)
{
	dlg_leg_t leg, *new_leg;
	b2b_dlg_t dlg, *shm_dlg= NULL;
	unsigned int hash_index, local_index;
	str* b2b_key;
	str sockinfo_str;
	str host;
	int port, proto;
	b2b_table htable;
	int type;
	uint64_t ts = 0;

	memset(&dlg, 0, sizeof(b2b_dlg_t));

	type = vals[0].i;
	dlg.tag[1] = vals[2].s;
	dlg.callid = vals[3].s;

	if(type == B2B_SERVER)/* extract hash and local index */
	{
		htable = server_htable;
		if(b2b_parse_key(&dlg.tag[1], &hash_index, &local_index, &ts) < 0)
		{
			LM_ERR("Wrong format for b2b key [%.*s]\n", dlg.tag[1].len, dlg.tag[1].s);
			return -1;
		}
		dlg.tag[1].s = NULL;
		dlg.tag[1].len = 0;

		if (hash_index >= server_hsize) {
			LM_ERR("Hash Index [%d] too large! Increase the 'server_hsize'"
				"parameter!\n", hash_index);
			return -1;
		}
	}
	else
	{
		htable = client_htable;

		if(b2b_parse_key(&dlg.callid, &hash_index, &local_index, NULL) < 0)
		{
			LM_ERR("Wrong format for b2b key [%.*s]\n", dlg.callid.len, dlg.callid.s);
			return -1;
		}

		if (hash_index >= client_hsize) {
			LM_DBG("Hash Index [%d] too large! Increase the 'client_hsize'"
				"parameter!\n", hash_index);
			return -1;
		}
	}
	dlg.id               = local_index;
	dlg.state            = vals[15].i;
	dlg.ruri             = vals[4].s;
	dlg.from_uri         = vals[5].s;
	dlg.from_dname       = vals[6].s;
	dlg.to_uri           = vals[7].s;
	dlg.to_dname         = vals[8].s;
	dlg.tag[0]           = vals[1].s;
	dlg.cseq[0]          = vals[16].i;
	dlg.cseq[1]          = vals[17].i;
	dlg.route_set[0]     = vals[9].s;
	dlg.route_set[1]     = vals[10].s;
	dlg.contact[0]       = vals[21].s;
	dlg.contact[1]       = vals[22].s;
	dlg.last_method      = vals[18].i;
	dlg.last_reply_code  = vals[19].i;
	dlg.last_invite_cseq = vals[20].i;
	dlg.param            = vals[12].s;
	dlg.mod_name         = vals[13].s;
	sockinfo_str         = vals[11].s;
	if(sockinfo_str.s)
	{
		if(sockinfo_str.len)
		{
			if (parse_phostport (sockinfo_str.s, sockinfo_str.len, &host.s,
					&host.len, &port, &proto )< 0)
			{
				LM_ERR("bad format for stored sockinfo string [%.*s]\n",
						sockinfo_str.len, sockinfo_str.s);
				return -1;
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
		return -1;
	}
	b2b_key= b2b_htable_insert(htable,shm_dlg,hash_index, ts, type, 1, 0);
	if(b2b_key == NULL)
	{
		LM_ERR("Failed to insert new record\n");
		return -1;
	}
	pkg_free(b2b_key);

	if (vals[14].s.len) {
		if (shm_str_dup(&shm_dlg->storage, &vals[14].s) < 0) {
			LM_ERR("oom!\n");
			return -1;
		}
	}

	memset(&leg, 0, sizeof(dlg_leg_t));
	leg.tag = vals[23].s;
	if(leg.tag.s) {
		leg.cseq          = vals[24].i;
		leg.contact       = vals[25].s;
		leg.route_set     = vals[26].s;

		new_leg = b2b_dup_leg(&leg, SHM_MEM_TYPE);
		if(new_leg== NULL)
		{
			LM_ERR("Failed to construct b2b leg structure\n");
			return -1;
		}
		shm_dlg->legs = new_leg;
	}

	return 0;
}

int b2b_entities_restore_db(void)
{
	db_res_t *result= NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals= NULL;
	int i;
	int nr_rows;
	int no_rows = 10;
	int_str_t vals[DB_COLS_NO];

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

			memset(vals, 0, sizeof vals);

			vals[0].i      = row_vals[0].val.int_val;
			vals[2].s.s    = (char*)row_vals[2].val.string_val;
			vals[2].s.len  = vals[2].s.s?strlen(vals[2].s.s):0;
			vals[3].s.s    = (char*)row_vals[3].val.string_val;
			vals[3].s.len  = vals[3].s.s?strlen(vals[3].s.s):0;

			vals[15].i           = row_vals[15].val.int_val;
			vals[4].s.s          = (char*)row_vals[4].val.string_val;
			vals[4].s.len        = vals[4].s.s?strlen(vals[4].s.s):0;
			vals[5].s.s          = (char*)row_vals[5].val.string_val;
			vals[5].s.len        = strlen(vals[5].s.s);
			vals[6].s.s          = (char*)row_vals[6].val.string_val;
			vals[6].s.len        = vals[6].s.s?strlen(vals[6].s.s):0;
			vals[7].s.s          = (char*)row_vals[7].val.string_val;
			vals[7].s.len        = strlen(vals[7].s.s);
			vals[8].s.s          = (char*)row_vals[8].val.string_val;
			vals[8].s.len        = vals[8].s.s?strlen(vals[8].s.s):0;
			vals[1].s.s          = (char*)row_vals[1].val.string_val;
			vals[1].s.len        = vals[1].s.s?strlen(vals[1].s.s):0;
			vals[16].i           = row_vals[16].val.int_val;
			vals[17].i           = row_vals[17].val.int_val;
			vals[9].s.s          = (char*)row_vals[9].val.string_val;
			vals[9].s.len        = vals[9].s.s?strlen(vals[9].s.s):0;
			vals[10].s.s         = (char*)row_vals[10].val.string_val;
			vals[10].s.len       = vals[10].s.s?strlen(vals[10].s.s):0;
			vals[21].s.s         = (char*)row_vals[21].val.string_val;
			vals[21].s.len       = vals[21].s.s?strlen(vals[21].s.s):0;
			vals[22].s.s         = (char*)row_vals[22].val.string_val;
			vals[22].s.len       = vals[22].s.s?strlen(vals[22].s.s):0;
			vals[18].i           = row_vals[18].val.int_val;
			vals[19].i           = row_vals[19].val.int_val;
			vals[20].i           = row_vals[20].val.int_val;
			vals[12].s.s         = (char*)row_vals[12].val.string_val;
			vals[12].s.len       = vals[12].s.s?strlen(vals[12].s.s):0;
			vals[13].s.s         = (char*)row_vals[13].val.string_val;
			vals[13].s.len       = vals[13].s.s?strlen(vals[13].s.s):0;
			vals[11].s.s         = (char*)row_vals[11].val.string_val;
			vals[11].s.len       = vals[11].s.s?strlen(vals[11].s.s):0;

			if (!VAL_NULL(&row_vals[14])) {
				vals[14].s = VAL_BLOB(&row_vals[14]);
			} else {
				vals[14].s.s = NULL;
				vals[14].s.len = 0;
			}

			vals[23].s.s         = (char*)row_vals[23].val.string_val;
			vals[23].s.len       = vals[23].s.s?strlen(vals[23].s.s):0;

			if (vals[23].s.s) {
				vals[24].i        = row_vals[24].val.int_val;
				vals[25].s.s      = (char*)row_vals[25].val.string_val;
				vals[25].s.len    = vals[25].s.s?strlen(vals[25].s.s):0;
				vals[26].s.s      = (char*)row_vals[26].val.string_val;
				vals[26].s.len    = vals[26].s.s?strlen(vals[26].s.s):0;
			}

			if (load_entity(vals) < 0)
				goto error;
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

int b2b_entities_restore_cdb(void)
{
	cdb_res_t res;
	cdb_row_t *row;
	struct list_head *_;
	cdb_pair_t *pair;
	int_str_t vals[DB_COLS_NO];

	if (b2be_cdbf.map_get(b2be_cdb, NULL, &res) != 0)
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

		get_val_from_dict(0, 0, &pair->val.val.dict, vals);
		get_val_from_dict(2, 1, &pair->val.val.dict, vals);
		get_val_from_dict(3, 1, &pair->val.val.dict, vals);

		get_val_from_dict(15, 0, &pair->val.val.dict, vals);
		get_val_from_dict(4, 1, &pair->val.val.dict, vals);
		get_val_from_dict(5, 1, &pair->val.val.dict, vals);
		get_val_from_dict(6, 1, &pair->val.val.dict, vals);
		get_val_from_dict(7, 1, &pair->val.val.dict, vals);
		get_val_from_dict(8, 1, &pair->val.val.dict, vals);
		get_val_from_dict(1, 1, &pair->val.val.dict, vals);
		get_val_from_dict(16, 0, &pair->val.val.dict, vals);
		get_val_from_dict(17, 0, &pair->val.val.dict, vals);
		get_val_from_dict(9, 1, &pair->val.val.dict, vals);
		get_val_from_dict(10, 1, &pair->val.val.dict, vals);
		get_val_from_dict(21, 1, &pair->val.val.dict, vals);
		get_val_from_dict(22, 1, &pair->val.val.dict, vals);
		get_val_from_dict(18, 0, &pair->val.val.dict, vals);
		get_val_from_dict(19, 0, &pair->val.val.dict, vals);
		get_val_from_dict(20, 0, &pair->val.val.dict, vals);
		get_val_from_dict(12, 1, &pair->val.val.dict, vals);
		get_val_from_dict(13, 1, &pair->val.val.dict, vals);
		get_val_from_dict(11, 1, &pair->val.val.dict, vals);

		get_val_from_dict(14, 1, &pair->val.val.dict, vals);
		get_val_from_dict(23, 1, &pair->val.val.dict, vals);

		get_val_from_dict(24, 0, &pair->val.val.dict, vals);

		get_val_from_dict(25, 1, &pair->val.val.dict, vals);
		get_val_from_dict(26, 1, &pair->val.val.dict, vals);

		if (load_entity(vals) < 0) {
			cdb_free_rows(&res);
			return -1;
		}
	}

	cdb_free_rows(&res);

	return 0;
}

int b2b_entities_restore(void)
{
	if (db_url.s)
		return b2b_entities_restore_db();
	else
		return b2b_entities_restore_cdb();
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
	qvals[0].val.int_val = type;
	qvals[1].val.str_val = dlg->tag[0];
	qvals[2].val.str_val = dlg->tag[1];
	qvals[3].val.str_val = dlg->callid;

	if (b2be_cdb_url.s) {
		if(!b2be_cdb)
			return;

		b2b_entity_cdb_delete(type, dlg);
	} else {
		if(!b2be_db)
			return;

		if(b2be_dbf.use_table(b2be_db, &b2be_dbtable)< 0)
		{
			LM_ERR("sql use table failed\n");
			return;
		}

		/* if the state is terminated delete the record */
		if(b2be_dbf.delete(b2be_db, qcols, 0, qvals, 4)< 0)
		{
			LM_ERR("Sql delete failed\n");
		}
	}
}

/* delete all entities belonging to a tuple */
void b2b_db_delete(str param)
{
	str *cdb_subkey;

	qvals[12].val.str_val = param;

	if (b2be_cdb_url.s) {
		if(!b2be_cdb)
			return;

		cdb_subkey = get_b2be_map_subkey(&param);
		if (!cdb_subkey) {
			LM_ERR("Failed to build map key\n");
			return;
		}

		if (b2be_cdbf.map_remove(b2be_cdb, NULL, cdb_subkey) < 0)
			LM_ERR("Failed to delete from cachedb\n");

		pkg_free(cdb_subkey->s);
	} else {
		if(!b2be_db)
			return;

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
}
