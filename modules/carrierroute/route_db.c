/*
 * Copyright (C) 2007-2008 1&1 Internet AG
 *
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
 */

/**
 * @file route_db.c
 * @brief Functions for loading routing data from a database.
 */

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "carrierroute.h"
#include "route_db.h"
#include <stdio.h>

#define QUERY_LEN 2048

struct carrier {
	int id;
	char * name;
	struct carrier * next;
};

static int store_carriers(struct carrier ** start);

static void destroy_carriers(struct carrier * start);

static char query[QUERY_LEN];

/**
 * Database API
 */
db_func_t dbf;
db_con_t * dbh = NULL;

/**
 * Initializes the db API
 *
 * @return 0 means ok, -1 means an error occurred.
 */
int db_init(void) {
	if (!db_url.s) {
		LM_ERR("You have to set the db_url module parameter.\n");
		return -1;
	}
	if (db_bind_mod(&db_url, &dbf) < 0) {
		LM_ERR("Can't bind database module.\n");
		return -1;
	}
	if((dbh = dbf.init(&db_url)) == NULL){
		LM_ERR("Can't connect to database.\n");
		return -1;
	}
	if ( (db_check_table_version(&dbf, dbh, &db_table, ROUTE_TABLE_VER) < 0) ||
		 (db_check_table_version(&dbf, dbh, &carrier_table, CARRIER_TABLE_VER) < 0) ||
		 (db_check_table_version(&dbf, dbh, &db_failure_table, FAILURE_TABLE_VER) < 0) ) {
			LM_ERR("Error during table version check.\n");
			return -1;
	}
	return 0;
}

void main_db_close(void){
	dbf.close(dbh);
	dbh = NULL;
}

int db_child_init(void) {
	if(dbh){
		dbf.close(dbh);
	}
	if((dbh = dbf.init(&db_url)) == NULL){
		LM_ERR("Can't connect to database.\n");
		return -1;
	}
	return 0;
}

void db_destroy(void){
	if(dbh){
		dbf.close(dbh);
	}
	return;
}

int load_user_carrier(str * user, str * domain) {
	db_res_t * res;
	db_key_t cols[1];
	db_key_t keys[2];
	db_val_t vals[2];
	db_op_t op[2];
	int id;
	if (!user || (use_domain && !domain)) {
		LM_ERR("NULL pointer in parameter\n");
		return -1;
	}

	cols[0] = subscriber_columns[SUBSCRIBER_CARRIER_COL];

	keys[0] = subscriber_columns[SUBSCRIBER_USERNAME_COL];
	op[0] = OP_EQ;
	vals[0].type = DB_STR;
	vals[0].nul = 0;
	vals[0].val.str_val = *user;

	keys[1] = subscriber_columns[SUBSCRIBER_DOMAIN_COL];
	op[1] = OP_EQ;
	vals[1].type = DB_STR;
	vals[1].nul = 0;
	vals[1].val.str_val = *domain;

	if (dbf.use_table(dbh, &subscriber_table) < 0) {
		LM_ERR("can't use table\n");
		return -1;
	}

	if (dbf.query(dbh, keys, op, vals, cols, use_domain ? 2 : 1, 1, NULL, &res) < 0) {
		LM_ERR("can't query database\n");
		return -1;
	}

	if (RES_ROW_N(res) == 0) {
		dbf.free_result(dbh, res);
		return 0;
	}

	if (VAL_NULL(ROW_VALUES(RES_ROWS(res)))) {
		dbf.free_result(dbh, res);
		return 0;
	}

	id = VAL_INT(ROW_VALUES(RES_ROWS(res)));
	dbf.free_result(dbh, res);
	return id;
}

/**
 * Loads the routing data from the database given in global
 * variable db_url and stores it in routing tree rd.
 *
 * @param rd Pointer to the route data tree where the routing data
 * shall be loaded into
 *
 * @return 0 means ok, -1 means an error occurred
 *
 */
int load_route_data(struct rewrite_data * rd) {
	db_res_t * res = NULL;
	db_row_t * row = NULL;
	int i, n = 0, ret;
	int carrier_count = 0;
	struct carrier * carriers = NULL, * tmp = NULL;
	static str query_str;
	str tmp_carrier;
	str tmp_domain;
	str tmp_scan_prefix;
	str tmp_rewrite_host;
	str tmp_rewrite_prefix;
	str tmp_rewrite_suffix;
	str tmp_host_name;
	str tmp_reply_code;
	str tmp_next_domain;
	str tmp_comment;
	int no_rows=10;
	UNUSED(n);

	if( (strlen("SELECT DISTINCT  FROM  WHERE = ")
			+ db_table.len + columns[COL_DOMAIN]->len
			+ columns[COL_CARRIER]->len + 20) >  QUERY_LEN) {
		LM_ERR("query too long\n");
		return -1;
	}

	if((carrier_count = store_carriers(&carriers)) <= 0){
		LM_ERR("error while retrieving carriers\n");
		goto errout;
	}

	if ((rd->carriers = shm_malloc(sizeof(struct carrier_tree *) * carrier_count)) == NULL) {
		LM_ERR("out of shared memory\n");
		goto errout;
	}
	memset(rd->carriers, 0, sizeof(struct carrier_tree *) * carrier_count);
	rd->tree_num = carrier_count;

	tmp = carriers;
	for (i=0; i<carrier_count; i++) {
		memset(query, 0, QUERY_LEN);
		ret = snprintf(query, QUERY_LEN, "SELECT DISTINCT %.*s FROM %.*s WHERE %.*s=%i",
		columns[COL_DOMAIN]->len, columns[COL_DOMAIN]->s, db_table.len, db_table.s,
		columns[COL_CARRIER]->len, columns[COL_CARRIER]->s, tmp->id);
		if (ret < 0) {
			LM_ERR("error in snprintf");
			goto errout;
		}
		query_str.s = query;
		query_str.len = ret;

		if (dbf.raw_query(dbh, &query_str, &res) < 0) {
			LM_ERR("Failed to query database.\n");
			goto errout;
		}
		LM_INFO("name %s, id %i, trees: %i\n", tmp->name, tmp->id, RES_ROW_N(res));
		tmp_carrier.s=tmp->name;
		tmp_carrier.len=strlen(tmp_carrier.s);
		if (add_carrier_tree(&tmp_carrier, tmp->id, rd, RES_ROW_N(res)) == NULL) {
			LM_ERR("can't add carrier %s\n", tmp->name);
			goto errout;
		}
		dbf.free_result(dbh, res);
		res = NULL;
		tmp = tmp->next;
	}

	if (dbf.use_table(dbh, &db_table) < 0) {
		LM_ERR("Cannot set database table '%.*s'.\n", db_table.len, db_table.s);
		return -1;
	}

	if (DB_CAPABILITY(dbf, DB_CAP_FETCH)) {
		if (dbf.query(dbh, NULL, NULL, NULL, (db_key_t *) columns, 0, COLUMN_NUM, NULL, NULL) < 0) {
			LM_ERR("Failed to query database to prepare fetchrow.\n");
			return -1;
		}
		no_rows = estimate_available_rows( 4+64+64+64+4+4+4+64+4+64+64+128,
			COLUMN_NUM);
		if (no_rows==0) no_rows = 10;
		if(dbf.fetch_result(dbh, &res, no_rows) < 0) {
			LM_ERR("Fetching rows failed\n");
			return -1;
		}
	} else {
		if (dbf.query(dbh, NULL, NULL, NULL, (db_key_t *)columns, 0, COLUMN_NUM, NULL, &res) < 0) {
			LM_ERR("Failed to query database.\n");
			return -1;
		}
	}

	do {
		LM_DBG("loading, cycle %d", n++);
			for (i = 0; i < RES_ROW_N(res); ++i) {
			row = &RES_ROWS(res)[i];
			tmp_domain.s=(char *)row->values[COL_DOMAIN].val.string_val;
			tmp_scan_prefix.s=(char *)row->values[COL_SCAN_PREFIX].val.string_val;
			tmp_rewrite_host.s=(char *)row->values[COL_REWRITE_HOST].val.string_val;
			tmp_rewrite_prefix.s=(char *)row->values[COL_REWRITE_PREFIX].val.string_val;
			tmp_rewrite_suffix.s=(char *)row->values[COL_REWRITE_SUFFIX].val.string_val;
			tmp_comment.s=(char *)row->values[COL_COMMENT].val.string_val;
			if (tmp_domain.s==NULL) tmp_domain.s="";
			if (tmp_scan_prefix.s==NULL) tmp_scan_prefix.s="";
			if (tmp_rewrite_host.s==NULL) tmp_rewrite_host.s="";
			if (tmp_rewrite_prefix.s==NULL) tmp_rewrite_prefix.s="";
			if (tmp_rewrite_suffix.s==NULL) tmp_rewrite_suffix.s="";
			if (tmp_comment.s==NULL) tmp_comment.s="";
			tmp_domain.len=strlen(tmp_domain.s);
			tmp_scan_prefix.len=strlen(tmp_scan_prefix.s);
			tmp_rewrite_host.len=strlen(tmp_rewrite_host.s);
			tmp_rewrite_prefix.len=strlen(tmp_rewrite_prefix.s);
			tmp_rewrite_suffix.len=strlen(tmp_rewrite_suffix.s);
			tmp_comment.len=strlen(tmp_comment.s);
			if (add_route(rd,
					row->values[COL_CARRIER].val.int_val,
					&tmp_domain,
					&tmp_scan_prefix,
					row->values[COL_FLAGS].val.int_val,
					row->values[COL_MASK].val.int_val,
					0,
					row->values[COL_PROB].val.double_val,
					&tmp_rewrite_host,
					row->values[COL_STRIP].val.int_val,
					&tmp_rewrite_prefix,
					&tmp_rewrite_suffix,
					1,
					0,
					-1,
					NULL,
					&tmp_comment) == -1) {
				goto errout;
			}
		}
		if (DB_CAPABILITY(dbf, DB_CAP_FETCH)) {
			if(dbf.fetch_result(dbh, &res, no_rows) < 0) {
				LM_ERR("fetching rows failed\n");
				dbf.free_result(dbh, res);
				return -1;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res) > 0);

	dbf.free_result(dbh, res);
	res = NULL;

	if (dbf.use_table(dbh, &db_failure_table) < 0) {
		LM_ERR("cannot set database table '%.*s'.\n",
				db_failure_table.len, db_failure_table.s);
		return -1;
	}
	if (dbf.query(dbh, NULL, NULL, NULL, (db_key_t *)failure_columns, 0,
								FAILURE_COLUMN_NUM, NULL, &res) < 0) {
		LM_ERR("failed to query database.\n");
		return -1;
	}
	for (i = 0; i < RES_ROW_N(res); ++i) {
		row = &RES_ROWS(res)[i];
		tmp_domain.s=(char *)row->values[FCOL_DOMAIN].val.string_val;
		tmp_scan_prefix.s=(char *)row->values[FCOL_SCAN_PREFIX].val.string_val;
		tmp_host_name.s=(char *)row->values[FCOL_HOST_NAME].val.string_val;
		tmp_reply_code.s=(char *)row->values[FCOL_REPLY_CODE].val.string_val;
		tmp_next_domain.s=(char *)row->values[FCOL_NEXT_DOMAIN].val.string_val;
		tmp_comment.s=(char *)row->values[FCOL_COMMENT].val.string_val;
		if (tmp_domain.s==NULL) tmp_domain.s="";
		if (tmp_scan_prefix.s==NULL) tmp_scan_prefix.s="";
		if (tmp_host_name.s==NULL) tmp_host_name.s="";
		if (tmp_reply_code.s==NULL) tmp_reply_code.s="";
		if (tmp_next_domain.s==NULL) tmp_next_domain.s="";
		if (tmp_comment.s==NULL) tmp_comment.s="";
		tmp_domain.len=strlen(tmp_domain.s);
		tmp_scan_prefix.len=strlen(tmp_scan_prefix.s);
		tmp_host_name.len=strlen(tmp_host_name.s);
		tmp_reply_code.len=strlen(tmp_reply_code.s);
		tmp_next_domain.len=strlen(tmp_next_domain.s);
		tmp_comment.len=strlen(tmp_comment.s);
		if (add_failure_route(rd,
				row->values[FCOL_CARRIER].val.int_val,
				&tmp_domain,
				&tmp_scan_prefix,
				&tmp_host_name,
				&tmp_reply_code,
				row->values[FCOL_FLAGS].val.int_val,
				row->values[FCOL_MASK].val.int_val,
				&tmp_next_domain,
				&tmp_comment) == -1) {
			goto errout;
		}
	}

	destroy_carriers(carriers);
	dbf.free_result(dbh, res);
	return 0;

errout:
	destroy_carriers(carriers);
	if (res) {
		dbf.free_result(dbh, res);
	}
	return -1;
}

static int store_carriers(struct carrier ** start){
	db_res_t * res = NULL;
	int i;
	int count;
	struct carrier * nc;
	if(!start){
		LM_ERR("invalid parameter\n");
		return -1;
	}
	if (dbf.use_table(dbh, &carrier_table) < 0) {
		LM_ERR("couldn't use table\n");
		return -1;
	}

	if (dbf.query(dbh, 0, 0, 0, (db_key_t *)carrier_columns, 0, CARRIER_COLUMN_NUM, 0, &res) < 0) {
		LM_ERR("couldn't query table\n");
		return -1;
	}
	count = RES_ROW_N(res);
	for(i=0; i<RES_ROW_N(res); i++){
		if((nc = pkg_malloc(sizeof(struct carrier))) == NULL){
			LM_ERR("out of private memory\n");
			return -1;
		}
		nc->id = res->rows[i].values[0].val.int_val;
		if((nc->name = pkg_malloc(strlen(res->rows[i].values[1].val.string_val) + 1)) == NULL){
			LM_ERR("out of private memory\n");
			pkg_free(nc);
			goto errout;
		}
		strcpy(nc->name, res->rows[i].values[1].val.string_val);
		nc->next = *start;
		*start = nc;
	}
	dbf.free_result(dbh, res);
	return count;
errout:
if(res){
	dbf.free_result(dbh, res);
}
	return -1;
}

static void destroy_carriers(struct carrier * start){
	struct carrier * tmp, * tmp2;
	tmp = start;

	while(tmp){
		tmp2 = tmp;
		tmp = tmp->next;
		pkg_free(tmp2->name);
		pkg_free(tmp2);
	}
	return;
}
