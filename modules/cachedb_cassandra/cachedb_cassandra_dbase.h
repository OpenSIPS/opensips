/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 */

#ifndef CACHEDBCASSANDRA_DBASE_H
#define CACHEDBCASSANDRA_DBASE_H

#include <cassandra.h>
#include "../../cachedb/cachedb.h"

#define CASS_OSS_KEY_COL_S    "opensipskey"
#define CASS_OSS_KEY_COL_LEN  11
#define CASS_OSS_VAL_COL_S    "opensipsval"
#define CASS_OSS_VAL_COL_LEN  11

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	str keyspace;
	str table;
	str cnt_table;
	CassCluster *cluster;
	CassSession *session;
} cassandra_con;

extern CassConsistency rd_consistency;
extern CassConsistency wr_consistency;

cachedb_con* cassandra_init(str *url);
void cassandra_destroy(cachedb_con *con);
int cassandra_set(cachedb_con *con, str *attr, str *val, int expires);
int cassandra_get(cachedb_con *con, str *attr, str *val);
int cassandra_get_counter(cachedb_con *con, str *attr, int *val);
int cassandra_remove(cachedb_con *con, str *attr);
int _cassandra_remove(cachedb_con *con, str *attr, const str *key);
int cassandra_add(cachedb_con *con, str *attr, int val, int expires, int *new_val);
int cassandra_sub(cachedb_con *con, str *attr, int val, int expires, int *new_val);

#endif
