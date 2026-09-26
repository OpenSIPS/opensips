/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef DB_REDIS_SCHEMA_H
#define DB_REDIS_SCHEMA_H

#include "../../str.h"
#include "../../db/db_val.h"
#include "redis_con.h"

/* a table schema is provisioned as the hash "schema:<table>" with:
 *   __cols   -> ordered, space-separated column names
 *   __pk     -> name of the primary-key column
 *   <column> -> type[,null][,auto]
 * where type is one of: int, bigint, double, string, blob, datetime */

struct rdb_col {
	str name;
	db_type_t type;
	int nullable;
	int is_auto;      /* auto-increment (emulated via INCR seq:<table>) */
};

struct rdb_schema {
	str table;
	int nr_cols;
	struct rdb_col *cols;
	int pk;           /* index into cols[] */
	struct rdb_schema *next;
};

/* cached lookup; loads "schema:<table>" from redis on first use */
struct rdb_schema *rdb_get_schema(struct redis_con *con, const str *table);

/* index of a column by name, -1 if not part of the schema */
int rdb_schema_col(const struct rdb_schema *sch, const str *name);

void rdb_free_schemas(struct redis_con *con);

#endif /* DB_REDIS_SCHEMA_H */
