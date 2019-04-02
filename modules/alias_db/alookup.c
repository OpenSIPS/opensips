/*
 * ALIAS_DB Module
 *
 * Copyright (C) 2004-2009 Voice Sistem SRL
 *
 * This file is part of a module for opensips, a free SIP server.
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
 * 2004-09-01: first version (ramona)
 * 2009-04-30: alias_db_find() added; NO_DOMAIN and REVERT flags added;
 *             use_domain param removed (bogdan)
 */

#include <string.h>

#include "../../dprint.h"
#include "../../action.h"
#include "../../config.h"
#include "../../ut.h"
#include "../../parser/parse_uri.h"
#include "../../db/db.h"
#include "../../mod_fix.h"
#include "../../dset.h"

#include "alias_db.h"
#include "alookup.h"

#define MAX_USERURI_SIZE	256

extern db_func_t adbf;  /* DB functions */

char useruri_buf[MAX_USERURI_SIZE];

typedef int (*set_alias_f)(struct sip_msg* _msg, str *alias, int no, pv_spec_t *p);


/**
 *
 */
static int alias_db_query(struct sip_msg* _msg, str* table_s,
								struct sip_uri *puri, unsigned long flags,
								set_alias_f set_alias, pv_spec_t *param)
{
	static db_ps_t my_ps[4] = {NULL,NULL,NULL,NULL};
	str user_s;
	db_key_t db_keys[2];
	db_val_t db_vals[2];
	db_key_t db_cols[2];
	db_res_t* db_res = NULL;
	int i;
	int ps_idx=0;

	if (flags&ALIAS_REVERT_FLAG) {
		/* revert lookup: user->alias */
		db_keys[0] = &user_column;
		db_keys[1] = &domain_column;
		db_cols[0] = &alias_user_column;
		db_cols[1] = &alias_domain_column;
		ps_idx += 2;
	} else {
		/* rnormal lookup: alias->user */
		db_keys[0] = &alias_user_column;
		db_keys[1] = &alias_domain_column;
		db_cols[0] = &user_column;
		db_cols[1] = &domain_column;
	}

	db_vals[0].type = DB_STR;
	db_vals[0].nul = 0;
	db_vals[0].val.str_val.s = puri->user.s;
	db_vals[0].val.str_val.len = puri->user.len;

	if ( (flags&ALIAS_NO_DOMAIN_FLAG)==0 ) {
		db_vals[1].type = DB_STR;
		db_vals[1].nul = 0;
		db_vals[1].val.str_val.s = puri->host.s;
		db_vals[1].val.str_val.len = puri->host.len;

		if (domain_prefix.s && domain_prefix.len>0
			&& domain_prefix.len<puri->host.len
			&& strncasecmp(puri->host.s,domain_prefix.s,
				domain_prefix.len)==0)
		{
			db_vals[1].val.str_val.s   += domain_prefix.len;
			db_vals[1].val.str_val.len -= domain_prefix.len;
		}
		ps_idx ++;
	}

	adbf.use_table(db_handle, table_s);
	if (!ald_append_branches)
		CON_PS_REFERENCE(db_handle) = my_ps[ps_idx];

	if(adbf.query( db_handle, db_keys, NULL, db_vals, db_cols,
		(flags&ALIAS_NO_DOMAIN_FLAG)?1:2 /*no keys*/, 2 /*no cols*/,
		NULL, &db_res)!=0)
	{
		LM_ERR("failed to query database\n");
		goto err_server;
	}

	if (db_res == NULL || RES_ROW_N(db_res)<=0 || RES_ROWS(db_res)[0].values[0].nul != 0) {
		LM_DBG("no alias found for R-URI\n");
		if (db_res!=NULL && adbf.free_result(db_handle, db_res) < 0)
			LM_DBG("failed to freeing result of query\n");
		return -1;
	}

	memcpy(useruri_buf, "sip:", 4);
	for(i=0; i<RES_ROW_N(db_res); i++)
	{
		user_s.len = 4;
		user_s.s = useruri_buf+4;
		switch(RES_ROWS(db_res)[i].values[0].type)
		{
			case DB_STRING:
				strcpy(user_s.s,
					(char*)RES_ROWS(db_res)[i].values[0].val.string_val);
				user_s.len += strlen(user_s.s);
			break;
			case DB_STR:
				strncpy(user_s.s,
					(char*)RES_ROWS(db_res)[i].values[0].val.str_val.s,
					RES_ROWS(db_res)[i].values[0].val.str_val.len);
				user_s.len += RES_ROWS(db_res)[i].values[0].val.str_val.len;
			break;
			case DB_BLOB:
				strncpy(user_s.s,
					(char*)RES_ROWS(db_res)[i].values[0].val.blob_val.s,
					RES_ROWS(db_res)[i].values[0].val.blob_val.len);
				user_s.len += RES_ROWS(db_res)[i].values[0].val.blob_val.len;
			break;
			default:
				LM_ERR("unknown type of DB user column\n");
				if (db_res != NULL && adbf.free_result(db_handle, db_res)<0){
					LM_DBG("failed to freeing result of query\n");
				}
				goto err_server;
		}

		/* add the @*/
		useruri_buf[user_s.len] = '@';
		user_s.len++;

		/* add the domain */
		user_s.s = useruri_buf+user_s.len;
		switch(RES_ROWS(db_res)[i].values[1].type)
		{
			case DB_STRING:
				strcpy(user_s.s,
					(char*)RES_ROWS(db_res)[i].values[1].val.string_val);
				user_s.len += strlen(user_s.s);
			break;
			case DB_STR:
				strncpy(user_s.s,
					(char*)RES_ROWS(db_res)[i].values[1].val.str_val.s,
					RES_ROWS(db_res)[i].values[1].val.str_val.len);
				user_s.len += RES_ROWS(db_res)[i].values[1].val.str_val.len;
				useruri_buf[user_s.len] = '\0';
			break;
			case DB_BLOB:
				strncpy(user_s.s,
					(char*)RES_ROWS(db_res)[i].values[1].val.blob_val.s,
					RES_ROWS(db_res)[i].values[1].val.blob_val.len);
				user_s.len += RES_ROWS(db_res)[i].values[1].val.blob_val.len;
				useruri_buf[user_s.len] = '\0';
			break;
			default:
				LM_ERR("unknown type of DB user column\n");
				if (db_res != NULL && adbf.free_result(db_handle, db_res) < 0)
				{
					LM_DBG("failed to freeing result of query\n");
				}
				goto err_server;
		}
		user_s.s = useruri_buf;
		/* set the URI */
		LM_DBG("new URI [%d] is [%.*s]\n", i, user_s.len ,user_s.s );
		if (set_alias(_msg, &user_s, i, param)!=0) {
			LM_ERR("error while setting alias\n");
			goto err_server;
		}
	}

	/**
	 * Free the DB result
	 */
	if (db_res!=NULL && adbf.free_result(db_handle, db_res) < 0)
		LM_DBG("failed to freeing result of query\n");

	return 1;

err_server:
	if (db_res!=NULL && adbf.free_result(db_handle, db_res) < 0)
		LM_DBG("failed to freeing result of query\n");
	return -1;
}


static inline int set_alias_to_ruri(struct sip_msg* _msg, str *alias, int no, pv_spec_t *p)
{
	/* set the RURI */
	if(no==0) {
		if(set_ruri(_msg, alias)<0) {
			LM_ERR("cannot replace the R-URI\n");
			return -1;
		}
	} else if (ald_append_branches) {
		if (append_branch(_msg, alias, 0, 0, MIN_Q, 0, 0) == -1) {
			LM_ERR("error while appending branches\n");
			return -1;
		}
	}
	return 0;
}


/**
 *
 */
int alias_db_lookup(struct sip_msg* _msg, str* _table, void *flags)
{
	if (parse_sip_msg_uri(_msg) < 0)
		return -1;

	return alias_db_query(_msg, _table, &_msg->parsed_uri,(unsigned long)flags,
		set_alias_to_ruri, NULL);
}


static inline int set_alias_to_pvar(struct sip_msg* _msg, str *alias, int no, pv_spec_t *pvs)
{
	pv_value_t val;

	if(no && !ald_append_branches)
		return 0;

	/* set the PVAR */
	val.flags = PV_VAL_STR;
	val.ri = 0;
	val.rs = *alias;

	if(pv_set_value(_msg, pvs, (int)(no?EQ_T:COLONEQ_T), &val)<0) {
		LM_ERR("setting PV AVP failed\n");
		return -1;
	}
	return 0;
}


int alias_db_find(struct sip_msg* _msg, str* _table, str* _in_s, pv_spec_t* _out,
															void* flags)
{
	struct sip_uri puri;

	if (parse_uri(_in_s->s, _in_s->len, &puri)<0) {
		LM_ERR("failed to parse uri %.*s\n",_in_s->len,_in_s->s);
		return -1;
	}

	return alias_db_query(_msg, _table, &puri, (unsigned long)flags,
		set_alias_to_pvar, _out);
}

