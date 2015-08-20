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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2013-01-xx  created (vlad-paiu)
 */

#ifndef CACHEDBCOUCHBASE_DBASE_H
#define CACHEDBCOUCHBASE_DBASE_H

#include <unistd.h>
#include <libcouchbase/couchbase.h>
#include "../../cachedb/cachedb.h"

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	lcb_t couchcon;
} couchbase_con;

#define COUCHBASE_CON(cdb_con) (((couchbase_con*)((cdb_con)->data))->couchcon)

#define COUCH_KEY_SEPPARATOR		'|'
#define COUCH_KEY_SEPPARATOR_LEN	1
#define COUCH_VIEW_MARKER		'?'
#define COUCH_VIEW_MARKER_LEN		1

cachedb_con* couchbase_init(str *url);
void couchbase_destroy(cachedb_con *con);

int couchbase_set(cachedb_con *connection,str *attr,str *val,int expires);
int couchbase_get(cachedb_con *con,str *attr,str *val);
int couchbase_remove(cachedb_con *con,str *attr);
int couchbase_add(cachedb_con *connection,str *attr,int val,int expires,int *new_val);
int couchbase_sub(cachedb_con *connection,str *attr,int val,int expires,int *new_val);
int couchbase_get_counter(cachedb_con *connection,str *attr,int *val);

#endif /* CACHEDBCOUCHBASE_DBASE_H */

