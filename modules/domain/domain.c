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
#include "../../name_alias.h"

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

int db_table_lookup(struct sip_msg *msg, str *lookup_domain, str *host, pv_spec_t *pv)
{
	pv_value_t val;
	db_val_t *values;

	db_key_t keys[1];
	db_val_t vals[1];
	db_key_t cols[3];
	db_res_t* res = NULL;

	int accept_subdomain;

	keys[0] = &domain_col;
	cols[0] = &domain_col;
	cols[1] = &domain_attrs_col;
	cols[2] = &domain_accept_subdomain_col;

	if (domain_dbf.use_table(db_handle, &domain_table) < 0) {
		LM_ERR("Error while trying to use domain table\n");
		return -3;
	}

	VAL_TYPE(vals) = DB_STR;
	VAL_NULL(vals) = 0;

	VAL_STR(vals).s = lookup_domain->s;
	VAL_STR(vals).len = lookup_domain->len;

	if (domain_dbf.query(db_handle, keys, 0, vals, cols, 1, 3, 0, &res) < 0) {
		LM_ERR("Error while querying database\n");
		return -3;
	}

	if (RES_ROW_N(res) > 0) {
		values = ROW_VALUES(RES_ROWS(res));

		// If we have a row then we need to get the accept_subdomain column first
		// If the host does not strictly match this ensures the accept_subdomain can match the subdomain
		if (VAL_NULL(values + 2)) {
			accept_subdomain = 0;
		} else if (VAL_TYPE(values + 2) == DB_INT) {
			accept_subdomain = VAL_INT(values + 2);
		} else {
			LM_ERR("Error setting accept_subdomain, default to 0\n");
			accept_subdomain = 0;
		}

		LM_DBG("Checking realm '%.*s' against domain entry '%.*s' accept_subdomain is '%d' \n",
			host->len, ZSW(host->s), lookup_domain->len, ZSW(lookup_domain->s), accept_subdomain);

		if (match_domain(lookup_domain->s, lookup_domain->len, host->s, host->len, accept_subdomain)) {
			if (pv) {
				/* XXX: what shall we do if there are duplicate entries? */
				/* we only check the first row - razvanc */
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
	}

	domain_dbf.free_result(db_handle, res);
	return -1;
}

/*
 * Check if domain is local and store attributes in a pvar
 */
int is_domain_local_pvar(struct sip_msg *msg, str* _host, pv_spec_t *pv)
{
	char *next_domain;
	str lookup_domain = { _host->s, _host->len };

	do {
		if (db_mode == 0) {
			if (db_table_lookup(msg, &lookup_domain, _host, pv) == 1)
				return 1;
		} else {
			if (hash_table_lookup(msg, &lookup_domain, _host, pv) == 1)
				return 1;
		}

		LM_DBG("Realm '%.*s' is not local\n", lookup_domain.len, ZSW(lookup_domain.s));

		next_domain = strchr(lookup_domain.s, '.');

		// If the _host string originally supplied is not a domain eg. sip.com but rather sipcom then strchr will return NULL
		// This conditional is for the first strchr check, subsequent runs will not happen based on reverse check in the while condition
		if (next_domain == NULL)
			break;

		next_domain++; // Remove the '.'

		// strlen(next_domain) will not work here as the _host->s char* pointer contains the SIP request domain including port and params
		// The bounds checking is done based on the supplied len and this calculation will decrement host part and '.' removed
		lookup_domain.len = lookup_domain.len - (next_domain - lookup_domain.s);
		lookup_domain.s = next_domain;
	} while(strrchr(next_domain, '.') != NULL); // Exits if the next domain that has been parsed has no '.'

	return -1;
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
	db_key_t cols[3];
	db_res_t* res = NULL;
	db_row_t* row;
	db_val_t* val;

	struct domain_list **new_hash_table;
	int i;
	int accept_subdomain;

	str domain, attrs;

	cols[0] = &domain_col;
	cols[1] = &domain_attrs_col;
	cols[2] = &domain_accept_subdomain_col;

	if (domain_dbf.use_table(db_handle, &domain_table) < 0) {
		LM_ERR("Error while trying to use domain table\n");
		return -3;
	}

	if (domain_dbf.query(db_handle, NULL, 0, NULL, cols, 0, 3, 0, &res) < 0) {
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
		} else if (VAL_TYPE(val + 1) == DB_BLOB) {
			attrs = VAL_BLOB(val + 1);
		} else {
			LM_ERR("Database problem on attrs column\n");
			domain_dbf.free_result(db_handle, res);
			return -3;
		}

		if (VAL_NULL(val + 2)) {
			accept_subdomain = 0;
		} else if (VAL_TYPE(val + 2) == DB_INT) {
			accept_subdomain = VAL_INT(val + 2);
		} else if (VAL_TYPE(val + 2) == DB_BIGINT) {
			accept_subdomain = VAL_BIGINT(val + 2);
		} else {
			LM_ERR("Database problem on accept_subdomain column\n");
			domain_dbf.free_result(db_handle, res);
			return -3;
		}

		LM_DBG("Value: %s with accept_subdomain %d inserted into domain hash table\n", VAL_STRING(val), accept_subdomain);

		if (hash_table_install(new_hash_table, &domain, &attrs, accept_subdomain)==-1){
			LM_ERR("Hash table problem\n");
			domain_dbf.free_result(db_handle, res);
			return -3;
		}
	}
	domain_dbf.free_result(db_handle, res);

	*hash_table = new_hash_table;

	return 1;
}

