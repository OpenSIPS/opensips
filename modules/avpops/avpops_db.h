/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 *  2004-10-04  first version (ramona)
 *  2004-11-11  added support for db schemes for avp_db_load (ramona)
 */



#ifndef _AVP_OPS_DB_H_
#define _AVP_OPS_DB_H_

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

int avpops_db_bind(void);

int avpops_db_init(const str* db_table, str **db_columns);

db_res_t *db_load_avp(struct db_url *url,str *uuid, str *username, str *domain,
		char *attr, const str *table, struct db_scheme *scheme);

void db_close_query( struct db_url *url, db_res_t *res );

int db_store_avp( struct db_url *url, db_key_t *keys, db_val_t *vals,
		int n, const str *table);

int db_delete_avp( struct db_url *url, str *uuid, str *username, str *domain,
		char *attr, const str *table);

int db_query_avp(struct db_url *url, struct sip_msg* msg, str *query,
		pvname_list_t* dest);

int avp_add_db_scheme( modparam_t type, void* val);

struct db_scheme *avp_get_db_scheme( str *name );

int db_query_avp_print_results(struct sip_msg *msg, const db_res_t *db_res,
								pvname_list_t *dest);

#endif
