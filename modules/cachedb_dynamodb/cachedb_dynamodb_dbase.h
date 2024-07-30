/*
 * Copyright (C) 2024 OpenSIPS Solutions
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

#ifndef CACHEDB_DYNAMODB_DBASE
#define CACHEDB_DYNAMODB_DBASE

#include "dynamodb_lib.h"
#include "../../cachedb/cachedb.h"

int dynamodb_get(cachedb_con *connection, str *attr, str *val);
int dynamodb_get_counter(cachedb_con *connection, str *attr, int *val);
int dynamodb_set(cachedb_con *connection, str *attr, str *val, int expires);
int dynamodb_remove(cachedb_con *connection, str *attr);
int dynamodb_add(cachedb_con *connection, str *attr, int val, int expires, int *new_val);
int dynamodb_sub(cachedb_con *connection, str *attr, int val, int expires, int *new_val);
int dynamodb_map_set(cachedb_con *con, const str *key, const str *subkey, const cdb_dict_t *pairs);
int dynamodb_map_get(cachedb_con *con, const str *key, cdb_res_t *res);
int dynamodb_map_remove(cachedb_con *con, const str *key, const str *subkey);
void dynamodb_destroy(cachedb_con *con);

#endif
