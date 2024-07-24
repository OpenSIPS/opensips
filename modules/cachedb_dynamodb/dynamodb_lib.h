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



#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	void *options;
	void *clientConfig;
} dynamodb_config;


typedef struct key_set_entry {
	char *keyset_name;
	struct list_head keys;
	struct key_set_entry *next;
} key_set_entry_t;

typedef struct key_entry {
	char *key;
	struct list_head list;
} key_entry_t;

typedef struct dynamodb_con {
	cachedb_pool_con cache_con;

	char *host;				// Note: the .id may contain multi-hosts, so the
	unsigned short port;	// host/port of this connection are extracted here
	char *endpoint;
	char *region;
	char *key;
	key_set_entry_t *key_sets; // List to store key sets
	char *value;
	char *tableName;
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


dynamodb_config init_dynamodb(dynamodb_con *con);
void shutdown_dynamodb(dynamodb_config *config);
bool create_table_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey);
bool put_item_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey,
				const char *partitionValue, const char *founder, int employeeCount, int yearFounded,
				int qualityRanking);
int insert_item_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue,
				const char *attributeName, const char* attributeValue, int ttl);
bool delete_item_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue);
char *query_item_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey,
				const char *partitionValue, const char *attributeKey);
void dealloc_query_result_dynamodb(query_result_t *result);
int update_item_inc_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue, const char *valueKey, int incrementValue, int ttl);
query_result_t *query_items_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue);
int update_item_sub_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue, const char *valueKey, int incrementValue, int ttl);
query_result_t *scan_table_dynamodb(dynamodb_config *config, const char *tableName, const char *key);
#ifdef __cplusplus
}
#endif

#endif // DYNAMODB_LIB
