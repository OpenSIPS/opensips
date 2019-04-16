/*
 * Domain table related functions
 *
 * Copyright (C) 2002-2003 Juha Heinanen
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
 *  2004-06-07  updated to the new DB api, moved reload_table here, created
 *               domain_db_{init.bind,ver,close} (andrei)
 *  2004-09-06  is_uri_host_local() can now be called also from
 *              failure route (juhe)
 */

#include "domain_mod.h"
#include "hash.h"
#include "../../db/db.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../ut.h"
#include "../../dset.h"
#include "../../route.h"
#include "../../pvar.h"
#include "../../str.h"

#define DOMAIN_TABLE_VERSION 3

static db_con_t* db_handle=0;
static db_func_t domain_dbf;

/* helper db functions*/

int domain_db_bind(const str* db_url)
{
	if (db_bind_mod(db_url, &domain_dbf )) {
	        LM_ERR("Cannot bind to database module!\n");
		return -1;
	}
	return 0;
}



int domain_db_init(const str* db_url)
{
	if (domain_dbf.init==0){
		LM_ERR("Unbound database module\n");
		goto error;
	}
	db_handle=domain_dbf.init(db_url);
	if (db_handle==0){
		LM_ERR("Cannot initialize database connection\n");
		goto error;
	}
	return 0;
error:
	return -1;
}


void domain_db_close(void)
{
	if (db_handle && domain_dbf.close){
		domain_dbf.close(db_handle);
		db_handle=0;
	}
}



int domain_db_ver(str* name, int version)
{
	if (db_handle==0){
		LM_ERR("null database handler\n");
		return -1;
	}
	return db_check_table_version(&domain_dbf, db_handle, name, version);
}


/*
 * Check if domain is local and store attributes in a pvar
 */
int is_domain_local_pvar(struct sip_msg *msg, str* _host, pv_spec_t *pv)
{
	pv_value_t val;
	db_val_t *values;

	if (db_mode == 0) {
		db_key_t keys[1];
		db_val_t vals[1];
		db_key_t cols[2];
		db_res_t* res = NULL;

		keys[0] = &domain_col;
		cols[0] = &domain_col;
		cols[1] = &domain_attrs_col;

		if (domain_dbf.use_table(db_handle, &domain_table) < 0) {
			LM_ERR("Error while trying to use domain table\n");
			return -3;
		}

		VAL_TYPE(vals) = DB_STR;
		VAL_NULL(vals) = 0;

		VAL_STR(vals).s = _host->s;
		VAL_STR(vals).len = _host->len;

		if (domain_dbf.query(db_handle, keys, 0, vals, cols, 1, 2, 0, &res) < 0
				) {
			LM_ERR("Error while querying database\n");
			return -3;
		}

		if (RES_ROW_N(res) == 0) {
			LM_DBG("Realm '%.*s' is not local\n",
			       _host->len, ZSW(_host->s));
			domain_dbf.free_result(db_handle, res);
			return -1;
		} else {
			LM_DBG("Realm '%.*s' is local\n",
			       _host->len, ZSW(_host->s));
			if (pv) {
				/* XXX: what shall we do if there are duplicate entries? */
				/* we only check the first row - razvanc */
				values = ROW_VALUES(RES_ROWS(res));
				if (!VAL_NULL(values +1)) {
					if (VAL_TYPE(values + 1) == DB_STR) {
						val.rs = VAL_STR(values + 1);
					} else {
						val.rs.s = (char *)VAL_STRING(values + 1);
						val.rs.len = strlen(val.rs.s);
					}
					val.flags = PV_VAL_STR;
					if (pv_set_value(msg, pv, 0, &val) != 0)
						LM_ERR("Cannot set attributes value\n");
				}
			}
			domain_dbf.free_result(db_handle, res);
			return 1;
		}
	} else {
		return hash_table_lookup (msg, _host, pv);
	}

}

/*
 * Check if domain is local
 */
int is_domain_local(str* _host)
{
	return is_domain_local_pvar(NULL, _host, NULL);
}


/*
 * Check if host in From uri is local
 */
int is_from_local(struct sip_msg* _msg, pv_spec_t* _s1)
{
	struct sip_uri *puri;

	if ((puri=parse_from_uri(_msg))==NULL) {
		LM_ERR("Error while parsing From header\n");
		return -2;
	}

	return is_domain_local_pvar(_msg, &(puri->host), _s1);

}

/*
 * Check if host in Request URI is local
 */
int is_uri_host_local(struct sip_msg* _msg, pv_spec_t* _s1)
{
	if (parse_sip_msg_uri(_msg) < 0) {
		LM_ERR("Error while parsing R-URI\n");
		return -1;
	}
	return is_domain_local_pvar(_msg, &(_msg->parsed_uri.host), _s1);
}


/*
 * Check if domain given as value of pseudo variable parameter is local
 */
int w_is_domain_local(struct sip_msg* _msg, str *domain, pv_spec_t* _s2)
{
	return is_domain_local_pvar(_msg, domain, _s2);
}


/*
 * Reload domain table to new hash table and when done, make new hash table
 * current one.
 */
int reload_domain_table ( void )
{
	db_key_t cols[2];
	db_res_t* res = NULL;
	db_row_t* row;
	db_val_t* val;

	struct domain_list **new_hash_table;
	int i;

	str domain, attrs;

	cols[0] = &domain_col;
	cols[1] = &domain_attrs_col;

	if (domain_dbf.use_table(db_handle, &domain_table) < 0) {
		LM_ERR("Error while trying to use domain table\n");
		return -3;
	}

	if (domain_dbf.query(db_handle, NULL, 0, NULL, cols, 0, 2, 0, &res) < 0) {
		LM_ERR("Error while querying database\n");
		return -3;
	}

	/* Choose new hash table and free its old contents */
	if (*hash_table == hash_table_1) {
		hash_table_free(hash_table_2);
		new_hash_table = hash_table_2;
	} else {
		hash_table_free(hash_table_1);
		new_hash_table = hash_table_1;
	}

	row = RES_ROWS(res);

	LM_DBG("Number of rows in domain table: %d\n", RES_ROW_N(res));

	for (i = 0; i < RES_ROW_N(res); i++) {
		val = ROW_VALUES(row + i);
		if (VAL_TYPE(val) == DB_STRING) {
			domain.s = (char *)VAL_STRING(val);
			domain.len = strlen(domain.s);
		} else if (VAL_TYPE(val) == DB_STR) {
			domain = VAL_STR(val);
		} else {
			LM_ERR("Database problem on domain column\n");
			domain_dbf.free_result(db_handle, res);
			return -3;
		}
		if (VAL_NULL(val + 1)) {
			/* add a marker to determine whether the attributes exist or not */
			attrs.len = 0;
			attrs.s = NULL;
		} else if (VAL_TYPE(val + 1) == DB_STRING) {
			attrs.s = (char *)VAL_STRING(val + 1);
			attrs.len = strlen(attrs.s);
		} else if (VAL_TYPE(val + 1) == DB_STR) {
			attrs = VAL_STR(val + 1);
		} else {
			LM_ERR("Database problem on attrs column\n");
			domain_dbf.free_result(db_handle, res);
			return -3;
		}
		LM_DBG("Value: %s inserted into domain hash table\n",VAL_STRING(val));

		if (hash_table_install(new_hash_table, &domain, &attrs)==-1){
			LM_ERR("Hash table problem\n");
			domain_dbf.free_result(db_handle, res);
			return -3;
		}
	}
	domain_dbf.free_result(db_handle, res);

	*hash_table = new_hash_table;

	return 1;
}

