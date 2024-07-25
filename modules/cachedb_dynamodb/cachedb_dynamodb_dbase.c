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

#include "cachedb_dynamodb_dbase.h"


void dynamodb_destroy(cachedb_con *connection) {
	dynamodb_con *con = (dynamodb_con *)(connection->data);
	if (con->endpoint) {
		pkg_free(con->endpoint);
	}

	if (con->host) {
		pkg_free(con->host);
	}

	if (con->key && con->key != (char *)DYNAMODB_KEY_COL_S) {
		pkg_free(con->key);
	}

	if(con->region) {
		pkg_free(con->region);
	}

	if(con->tableName) {
		pkg_free(con->tableName);
	}

	if (con->value && con->value != (char *)DYNAMODB_VAL_COL_S) {
		pkg_free(con->value);
	}

	shutdown_dynamodb(&con->config);

	pkg_free(con);
}

char *from_str_to_string(const str *str) {
	char *string;
	if(str == NULL)
		return NULL;

	string = (char *)pkg_malloc((str->len + 1) * sizeof(char));
	if(!string) {
		LM_ERR("No more pkg mem\n");
		return NULL;
	}
	strncpy(string, str->s, str->len);
	string[str->len] = '\0';
	return string;

}

int dynamodb_get(cachedb_con *connection,str *attr,str *val) {
	dynamodb_con *con;
	char *attr_string, *result1, *result2;


	con = (dynamodb_con *)(connection->data);

	attr_string = from_str_to_string(attr);
	if (attr_string == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	result1 = query_item_dynamodb(&con->config, con->tableName, con->key, attr_string, con->value);

	pkg_free(attr_string);

	if (result1 == NULL) {
		val->s = NULL;
		val->len = 0;
		LM_ERR("Item not found\n");
		return -2;
	}

	result2 = pkg_malloc(strlen(result1) * sizeof(char));
	if (!result2) {
		LM_ERR("No more pkg mem\n");
		free(result1);
		return -1;
	}

	strcpy(result2, result1);
	init_str(val, result2);

	free(result1);
	pkg_free(result2);

	return 0;
}

int dynamodb_get_counter(cachedb_con *connection,str *attr, int *val) {
	dynamodb_con *con;
	char *attr_string, *result1;

	con = (dynamodb_con *)(connection->data);

	attr_string = from_str_to_string(attr);
	if (attr_string == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	result1 = query_item_dynamodb(&con->config, con->tableName, con->key, attr_string, con->value);
	pkg_free(attr_string);

	if (result1 == NULL) {
		val = NULL;
		LM_ERR("Item not found\n");
		return -2;
	}

	*val = atoi(result1);
	if((strcmp(result1, "0") != 0) && (*val) == 0) {
		LM_ERR("Not an integer value\n");
		val = NULL;
		free(result1);
		return -1;
	}

	free(result1);
	return 1;
}

int dynamodb_set(cachedb_con *connection, str *attr, str *val, int expires) {

	dynamodb_con *con;
	char *attr_string, *val_string;

	con = (dynamodb_con *)(connection->data);

	attr_string = from_str_to_string(attr);
	if (attr_string == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	val_string = from_str_to_string(val);

	insert_item_dynamodb(&con->config, con->tableName, con->key, attr_string, con->value, val_string, expires);

	pkg_free(attr_string);
	pkg_free(val_string);

	return 1;
}

int dynamodb_remove(cachedb_con *connection,str *attr) {
	dynamodb_con *con;
	char *attr_string;
	con = (dynamodb_con *)(connection->data);

	attr_string = from_str_to_string(attr);
	if (attr_string == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	delete_item_dynamodb(&con->config, con->tableName, con->key, attr_string);

	pkg_free(attr_string);

	return 0;
}

int dynamodb_add(cachedb_con *connection, str *attr, int val, int expires, int *new_val) {
	dynamodb_con *con;
	char *attr_string;
	int new_value;

	con = (dynamodb_con *)(connection->data);

	attr_string = from_str_to_string(attr);
	if (attr_string == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	new_value = update_item_inc_dynamodb(&con->config, con->tableName, con->key, attr_string, con->value, val, expires);

	pkg_free(attr_string);

	*new_val = new_value;

	return 1;
}

int dynamodb_sub(cachedb_con *connection, str *attr, int val, int expires, int *new_val) {
	dynamodb_con *con;
	char *attr_string;
	int new_value;
	con = (dynamodb_con *)(connection->data);

	attr_string = from_str_to_string(attr);
	if (attr_string == NULL) {
		LM_ERR("Invalid Key name\n");
		return -1;
	}

	new_value = update_item_sub_dynamodb(&con->config, con->tableName, con->key, attr_string, con->value, val, expires);

	pkg_free(attr_string);

	*new_val = new_value;

	return 1;
}

void add_key_to_set(dynamodb_con *con, const char *keyset_name, const char *key) {
	key_set_entry_t *current_set;
	key_entry_t *new_key;

	current_set = con->key_sets;

	while (current_set != NULL && strcmp(current_set->keyset_name, keyset_name) != 0) {
		current_set = current_set->next;
	}

	if (current_set == NULL) {
		current_set = (key_set_entry_t *)pkg_malloc(sizeof(key_set_entry_t));
		if (!current_set) {
			LM_ERR("No more pkg mem\n");
			return;
		}
		current_set->keyset_name = strdup(keyset_name);
		if(!current_set->keyset_name) {
			LM_ERR("Strdup failed\n");
			return;
		}

		INIT_LIST_HEAD(&current_set->keys);
		current_set->next = con->key_sets;
		con->key_sets = current_set;
	}

	new_key = (key_entry_t *)pkg_malloc(sizeof(key_entry_t));
	if (!new_key) {
		LM_ERR("No more pkg mem\n");
		return;
	}
	new_key->key = strdup(key);
	if(!new_key->key) {
		LM_ERR("Strdup failed\n");
		return;
	}

	list_add_tail(&new_key->list, &current_set->keys);
}

int dynamodb_map_set(cachedb_con *connection, const str *key, const str *keyset, const cdb_dict_t *pairs) {
	dynamodb_con *con;
	struct list_head *_;
	cdb_pair_t *pair;
	char *key_string, *attribute_value, *attribute_name, *keyset_string;

	con = (dynamodb_con *)(connection->data);

	key_string = from_str_to_string(key);
	if (key_string == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	list_for_each (_, pairs) {

		pair = list_entry(_, cdb_pair_t, list);

		switch (pair->val.type) {
		case CDB_NULL:
			attribute_value = from_str_to_string(&pair->val.val.st);
			break;

		case CDB_INT32:
			attribute_value = (char*)pkg_malloc(12 * sizeof(char));
			if (!attribute_value) {
				LM_ERR("No more pkg mem\n");
				return -1;
			}
			sprintf(attribute_value, "%d", pair->val.val.i32);
			break;

		case CDB_INT64:
			attribute_value = (char *)pkg_malloc(20 *sizeof(char));
			if (!attribute_value) {
				LM_ERR("No more pkg mem\n");
				return -1;
			}
			sprintf(attribute_value, "%ld", pair->val.val.i64);
			break;

		case CDB_STR:
			attribute_value = from_str_to_string(&pair->val.val.st);
			if (attribute_value == NULL && pair->val.val.st.s != NULL) {
				LM_ERR("Invalid attribute value due to leak of mem\n");
				return -1;
			}
			break;

		default:
			LM_DBG("Unexpected type [%d] for hash field\n", pair->val.type);
			return -1;
		}
		attribute_name = from_str_to_string(&pair->key.name);
		insert_item_dynamodb(&con->config, con->tableName, con->key, key_string, attribute_name, attribute_value, 0);
		pkg_free(attribute_name);
		pkg_free(attribute_value);
	}

	/* Handle key sets */
	if (keyset != NULL) {
		keyset_string = from_str_to_string(keyset);
		if (keyset_string == NULL) {
			LM_ERR("Invalid keyset name\n");
			return -1;
		}

		add_key_to_set(con, keyset_string, key_string);
		pkg_free(keyset_string);
	}
	pkg_free(key_string);
	return 0;
}


int is_valid_int32(const char *str, int32_t *value) {
	char *endptr;
	long val;

	if (str == NULL)
		return 0;
	errno = 0;

	val = strtol(str, &endptr, 10);

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
		 || (errno != 0 && val == 0)) {
		return 0;
	}

	if (endptr == str) {
		return 0;
	}

	if (val < INT_MIN || val > INT_MAX) {
		return 0;
	}

	if (*endptr != '\0') {
		return 0;
	}

	if (value != NULL) {
		*value = (int32_t)val;
	}

	return 1;
}

int is_valid_int64(const char *str, int64_t *value) {
	char *endptr;
	long long val;

	if (str == NULL)
		return 0;
	errno = 0;

	val = strtoll(str, &endptr, 10);

	if ((errno == ERANGE && (val == LLONG_MAX || val == LLONG_MIN))
		|| (errno != 0 && val == 0)) {
		return 0;
	}

	if (endptr == str) {
		return 0;
	}

	if (val < INT64_MIN || val > INT64_MAX) {
		return 0;
	}

	if (*endptr != '\0') {
		return 0;
	}

	if (value != NULL) {
		*value = (int64_t)val;
	}

	return 1;
}

void populate_cdb_res(cdb_res_t *res, query_result_t *queryResult) {
	cdb_row_t *row;
	rows_t current_row;
	cdb_key_t key, subkey;
	cdb_pair_t *pair, *hfield;
	key_value_pair_t kvp;
	int32_t int32_value;
	int64_t int64_value;
	str val;

	if (!res) {
		LM_ERR("null parameter\n");
		return;
	}

	cdb_res_init(res);

	for (int i = 0; i < queryResult->num_rows; ++i) {
		row = (cdb_row_t *)pkg_malloc(sizeof(cdb_row_t));
		if (!row) {
			LM_ERR("No more pkg mem\n");
			cdb_free_rows(res);
			return;
		}
		INIT_LIST_HEAD(&row->dict);

		current_row = queryResult->items[i];

		init_str(&key.name, current_row.key);
		key.is_pk = 1;

		pair = cdb_mk_pair(&key, NULL);
		if (!pair) {
			LM_ERR("No more pkg mem\n");
			pkg_free(row);
			cdb_free_rows(res);
			return;
		}

		pair->val.type = CDB_DICT;
		INIT_LIST_HEAD(&pair->val.val.dict);

		for (int j = 0; j < current_row.no_attributes; ++j) {
			kvp = current_row.attributes[j];

			init_str(&subkey.name, kvp.key);
			subkey.is_pk = 0;

			hfield = cdb_mk_pair(&subkey, NULL);
			if (!hfield) {
				LM_ERR("No more pkg mem\n");
				pkg_free(row);
				pkg_free(pair);
				cdb_free_rows(res);
				return;
			}

			if (is_valid_int32(kvp.value, &int32_value)) {

				hfield->val.type = CDB_INT32;
				hfield->val.val.i32 = int32_value;

			} else if (is_valid_int64(kvp.value, &int64_value)) {

				hfield->val.type = CDB_INT64;
				hfield->val.val.i64 = int64_value;

			} else if (kvp.value != NULL) {

				hfield->val.type = CDB_STR;

				init_str(&val, kvp.value);

				pkg_str_dup(&hfield->val.val.st, &val);

			} else {

				hfield->val.type = CDB_NULL;
				hfield->val.val.st.s = NULL;
				hfield->val.val.st.len = 0;

			}

			cdb_dict_add(hfield, &pair->val.val.dict);
		}

		cdb_dict_add(pair, &row->dict);
		res->count++;
		list_add_tail(&row->list, &res->rows);
	}

}

void free_query_result(query_result_t *result) {
	if (result == NULL) {
		return;
	}

	for (int i = 0; i < result->num_rows; i++) {

		free(result->items[i].key);
		free(result->items[i].key_value);

		if (result->items[i].attributes != NULL) {
			for (int j = 0; j < result->items[i].no_attributes; j++) {
				free(result->items[i].attributes[j].key);
				free(result->items[i].attributes[j].value);
			}
			free(result->items[i].attributes);
		}
	}

	free(result->items);

	free(result);
}

int dynamodb_map_get(cachedb_con *connection, const str *key, cdb_res_t *res) {
	dynamodb_con *con;
	query_result_t *result;
	char *key_string;

	con = (dynamodb_con *)(connection->data);
	result = NULL;

	if (key == NULL) {

		result = scan_table_dynamodb(&con->config, con->tableName, con->key);

	} else {

		key_string = from_str_to_string(key);
		if (key_string == NULL) {
			LM_ERR("Invalid key name\n");
			return -1;
		}
		result = query_items_dynamodb(&con->config, con->tableName, con->key, key_string);
		pkg_free(key_string);

	}

	if (!result) {
		LM_ERR("No items found\n");
		return -1;
	}


	populate_cdb_res(res, result);

	free_query_result(result);

	return 0;
}


int remove_key_from_dynamodb(cachedb_con *connection, const str *key) {
	char *attr;
	str *key_attr;

	attr = from_str_to_string(key);
	if(attr == NULL) {
		LM_ERR("Invalid key name\n");
		return -1;
	}

	key_attr = pkg_malloc(sizeof(str));
	if (!key_attr) {
		LM_ERR("No more pkg mem\n");
		pkg_free(attr);
		return -1;
	}

	init_str(key_attr, attr);

	dynamodb_remove(connection, key_attr);

	pkg_free(attr);

	return 0;
}


int dynamodb_map_remove(cachedb_con *connection, const str *key, const str *keyset) {
	dynamodb_con *con;
	key_set_entry_t *current_set, *prev_set;
	struct list_head *pos, *n;
	key_entry_t *entry;
	str *key_to_remove;

	con = (dynamodb_con *)(connection->data);

	if (!keyset) {

		return remove_key_from_dynamodb(connection, key);

	}

	if (key) {

		current_set = con->key_sets;
		while (current_set != NULL && memcmp(current_set->keyset_name, keyset->s, keyset->len) != 0) {
			current_set = current_set->next;
		}

		if (current_set) {

			list_for_each_safe(pos, n, &current_set->keys) {
				entry = list_entry(pos, key_entry_t, list);
				if (memcmp(entry->key, key->s, key->len) == 0) {
					list_del(&entry->list);
					break;
				}
			}

			int result = remove_key_from_dynamodb(connection, key);

			return result;
		} else {
			LM_ERR("Keyset not found\n");
			return -1;
		}
	} else {

		current_set = con->key_sets;
		while (current_set != NULL && memcmp(current_set->keyset_name, keyset->s, keyset->len) != 0) {
			 current_set = current_set->next;
		}

		if (current_set) {

			list_for_each_safe(pos, n, &current_set->keys) {
				entry = list_entry(pos, key_entry_t, list);
				key_to_remove = pkg_malloc(sizeof(str));
				init_str(key_to_remove, entry->key);

				dynamodb_remove(connection, key_to_remove);
				list_del(&entry->list);

			}

			prev_set = con->key_sets;
			if (prev_set == current_set) {
				 con->key_sets = current_set->next;
			} else {
				while (prev_set->next != current_set) {
					prev_set = prev_set->next;
				}
				prev_set->next = current_set->next;
			}

		} else {

			LM_ERR("Keyset not found\n");
			return -1;

		}

	}
	return 0;
}
