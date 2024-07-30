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

#ifndef DYNAMODB_LIB
#define DYNAMODB_LIB
#include <stdbool.h>
#include "../../cachedb/cachedb_id.h"
#include "../../cachedb/cachedb_pool.h"
#include "../../lib/list.h"


#include <string.h>

#define DYNAMODB_KEY_COL_S    "opensipskey"
#define DYNAMODB_KEY_COL_LEN  11
#define DYNAMODB_VAL_COL_S    "opensipsval"
#define DYNAMODB_VAL_COL_LEN  11

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	void *options;
	void *clientConfig;
} dynamodb_config;


typedef struct key_set_entry {
	str *keyset_name;
	struct list_head keys;
	struct key_set_entry *next;
} key_set_entry_t;

typedef struct key_entry {
	str *key;
	struct list_head list;
} key_entry_t;

typedef struct dynamodb_con {
	cachedb_pool_con cache_con;

	str *host;				// Note: the .id may contain multi-hosts, so the
	unsigned short port;	// host/port of this connection are extracted here
	str endpoint;
	str region;
	str key;
	key_set_entry_t *key_sets; // List to store key sets
	str value;
	str tableName;
	dynamodb_config config;
} dynamodb_con;

typedef struct {
	char *key;
	char *value;
} key_value_pair_t;

typedef struct {
	int no_attributes;
	char *key;
	char *key_value;
	key_value_pair_t *attributes;
} rows_t;

typedef struct {
	int num_rows;
	rows_t *items;
} query_result_t;

typedef struct {
	str* str;
	int number;
	enum { STR_TYPE, INT_TYPE, NULL_TYPE } type;
} query_item_t;

int init_dynamodb(dynamodb_con *con);
void shutdown_dynamodb(dynamodb_config *config);
int insert_item_dynamodb(dynamodb_config *config,
						 const str tableName,
						 const str partitionKey,
						 const str partitionValue,
						 const str attributeName,
						 const str attributeValue,
						 int ttl);
int delete_item_dynamodb(dynamodb_config *config,
						 const str tableName,
						 const str partitionKey,
						 const str partitionValue);
query_item_t *query_item_dynamodb(dynamodb_config *config,
								  const str tableName,
								  const str partitionKey,
								  const str partitionValue,
								  const str attributeKey);
int *update_item_inc_dynamodb(dynamodb_config *config,
							  const str tableName,
							  const str partitionKey,
							  const str partitionValue,
							  const str valueKey,
							  int incrementValue,
							  int ttl);
query_result_t *query_items_dynamodb(dynamodb_config *config,
									 const str tableName,
									 const str partitionKey,
									 const str partitionValue);
int *update_item_sub_dynamodb(dynamodb_config *config,
							  const str tableName,
							  const str partitionKey,
							  const str partitionValue,
							  const str valueKey,
							  int incrementValue,
							  int ttl);
query_result_t *scan_table_dynamodb(dynamodb_config *config,
									const str tableName,
									const str key);
#ifdef __cplusplus
}
#endif

#endif // DYNAMODB_LIB
