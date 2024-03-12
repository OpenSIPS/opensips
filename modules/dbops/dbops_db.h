/*
 * Copyright (C) 2008-2024 OpenSIPS Solutions
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */



#ifndef _DB_OPS_DB_H_
#define _DB_OPS_DB_H_

#include "../../lib/cJSON.h"
#include "../../db/db.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../sr_module.h"
#include "../../pvar.h"

extern struct db_url *default_db_url;

struct db_url
{
	str url;
	unsigned int idx;
	db_con_t  *hdl;     /* DB handler */
	db_func_t dbf;  /* DB functions */
};

/* definition of a DB scheme*/
struct db_scheme
{
	str name;
	str uuid_col;
	str username_col;
	str domain_col;
	str value_col;
	str table;
	int db_flags;
	struct db_scheme *next;
};


int add_db_url(modparam_t type, void *val);

struct db_url* get_db_url(unsigned int idx);

struct db_url* get_default_db_url(void);

int dbops_db_bind(void);

int dbops_db_init(const str* db_table, str **db_columns);

db_res_t *db_avp_load(struct db_url *url,str *uuid, str *username, str *domain,
		char *attr, const str *table, struct db_scheme *scheme);

void db_close_query( struct db_url *url, db_res_t *res );

int db_avp_store( struct db_url *url, db_key_t *keys, db_val_t *vals,
		int n, const str *table);

int db_avp_delete( struct db_url *url, str *uuid, str *username, str *domain,
		char *attr, const str *table);

int db_query(struct db_url *url, struct sip_msg* msg, str *query,
		pvname_list_t* dest, int one_row);

int add_avp_db_scheme( modparam_t type, void* val);

struct db_scheme *get_avp_db_scheme( str *name );

int db_query_print_one_result(struct sip_msg *msg, const db_res_t *db_res,
		pvname_list_t *dest);

int db_query_print_results(struct sip_msg *msg, const db_res_t *db_res,
		pvname_list_t *dest);

int db_api_select(struct db_url *url, struct sip_msg* msg, cJSON *Jcols,
		str *table, cJSON *Jfilter, str * order,
		pvname_list_t* dest, int one_row);

int db_api_update(struct db_url *url, struct sip_msg* msg, cJSON *Jcols,
		str *table, cJSON *Jfilter);

int db_api_insert(struct db_url *url, struct sip_msg* msg, str *table,
		cJSON *Jcols);

int db_api_delete(struct db_url *url, struct sip_msg* msg,
		str *table, cJSON *Jfilter);

int db_api_replace(struct db_url *url, struct sip_msg* msg, str *table,
		cJSON *Jcols);

#endif
