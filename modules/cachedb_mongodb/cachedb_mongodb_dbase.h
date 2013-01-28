/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-09-xx  created (vlad-paiu)
 */

#ifndef CACHEDBMONGO_DBASE_H
#define CACHEDBMONGO_DBASE_H

#include "../../cachedb/cachedb.h"

#define MONGO_HAVE_STDINT 1

#include <mongo.h>
#include <bson.h>

#include <json/json.h>
#include <stdint.h>

extern int mongo_op_timeout;

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	/* shortcuts for raw queries */
	char* database;
	char* collection;

	/* only if we connect to a repl set*/
	char *replset_name;

	/* actual connection to mongo */
	mongo connection;
} mongo_con;

#define MONGO_CON(mon_con)			((mon_con)->connection)
#define MONGO_CDB_CON(cdb_con)		(((mongo_con *)((cdb_con)->data))->connection)
#define MONGO_NAMESPACE(cdb_con)	(((mongo_con *)((cdb_con)->data))->id->database)
#define MONGO_DATABASE(cdb_con)		(((mongo_con *)((cdb_con)->data))->database)
#define MONGO_COLLECTION(cdb_con)	(((mongo_con *)((cdb_con)->data))->collection)

cachedb_con* mongo_con_init(str *url);
void mongo_con_destroy(cachedb_con *con);
int mongo_con_get(cachedb_con *con,str *attr,str *val);
int mongo_con_set(cachedb_con *con,str *attr,str *val,int expires);
int mongo_con_remove(cachedb_con *connection,str *attr);
int mongo_con_raw_query(cachedb_con *connection,str *attr,cdb_raw_entry ***val,int expected_kv_no,int *reply_no);
int mongo_con_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val);
int mongo_con_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val);
int mongo_con_get_counter(cachedb_con *connection,str *attr,int *val);

#endif /* CACHEDBMONGO_DBASE_H */

