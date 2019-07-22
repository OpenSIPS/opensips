/*
 * Copyright (C) 2011-2017 OpenSIPS Project
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
 */

#include "../../dprint.h"
#include "../../ut.h"
#include "cachedb_mongodb_json.h"
#include "cachedb_mongodb_dbase.h"

int json_to_bson_append_element(bson_t *doc, const char *k, struct json_object *v);

int json_to_bson_append_array(bson_t *doc, struct json_object *a)
{
	int i, al_len;
	char *al;
	json_object *it;

	for (i = 0; i < json_object_array_length(a); i++) {
		al = int2str(i, &al_len);
		if (!al) {
			LM_ERR("Failed to convert %d to str\n", i);
			return -1;
		}

		al[al_len] = '\0';
		it = json_object_array_get_idx(a, i);
		if (!it) {
			LM_ERR("Failed to get JSON idx\n");
			return -1;
		}

		if (json_to_bson_append_element(doc, al, it) < 0) {
			LM_ERR("Failed to append element to BSON\n");
			return -1;
		}
	}

	return 0;
}

# define json_object_object_iterator(obj,key,val) \
	char *key; struct json_object *val; struct lh_entry *entry; \
	for(entry = json_object_get_object(obj)->head; \
		(entry ? (key = (char*)entry->k, \
		val = (struct json_object*)entry->v, entry) : 0); \
		entry = entry->next)

int json_to_bson_append(bson_t *doc, struct json_object *o)
{
	json_object_object_iterator(o, key, val) {
		if (json_to_bson_append_element(doc, key, val) < 0) {
			LM_ERR("Failed to append new element\n");
			return -1;
		}
	}

	return 0;
}

int json_to_bson_append_element(bson_t *doc, const char *k, struct json_object *v)
{
	bson_t child;

	if (!v) {
		bson_append_null(doc, k, -1);
		return 0;
	}

	switch (json_object_get_type(v)) {
		case json_type_int:
			if (!bson_append_int32(doc, k, -1, json_object_get_int(v))) {
				LM_ERR("Failed to append int\n");
				return -1;
			}
			break;
		case json_type_boolean:
			if (!bson_append_bool(doc, k, -1, json_object_get_boolean(v))) {
				LM_ERR("Failed to append boolean\n");
				return -1;
			}
			break;
		case json_type_double:
			if (!bson_append_double(doc, k, -1, json_object_get_double(v))) {
				LM_ERR("Failed to append double\n");
				return -1;
			}
			break;
		case json_type_string:
			if (!bson_append_utf8(doc, k, -1, json_object_get_string(v), -1)) {
				LM_ERR("Failed to append string\n");
				return -1;
			}
			break;
		case json_type_object:
			BSON_APPEND_DOCUMENT_BEGIN(doc, k, &child);
			if (json_to_bson_append(&child, v) < 0) {
				LM_ERR("Failed to append to bson_t\n");
				return -1;
			}
			bson_append_document_end(doc, &child);
			break;
		case json_type_array:
			BSON_APPEND_ARRAY_BEGIN(doc, k, &child);
			if (json_to_bson_append_array(&child, v) < 0) {
				LM_ERR("Failed to append array to bson_t\n");
				return -1;
			}
			bson_append_array_end(doc, &child);
			break;
		default:
			LM_ERR("Can't handle type for : %s\n", json_object_to_json_string(v));
			return -1;
	}

	return 0;
}

int json_to_bson(char *json, bson_t *doc)
{
	struct json_object *obj;

	LM_DBG("Trying to convert [%s]\n", json);

	obj = json_tokener_parse(json);
	if (!obj) {
		LM_ERR("Failed to parse JSON: %s\n", json);
		return -2;
	}

	if (!json_object_is_type(obj, json_type_object)) {
		LM_ERR("Inconsistent JSON type\n");
		goto error;
	}

	bson_init(doc);
	if (json_to_bson_append(doc, obj) < 0) {
		LM_ERR("Failed to convert json to bson_t\n");
		bson_destroy(doc);
		goto error;
	}

	json_object_put(obj);
	return 0;

error:
	if (obj)
		json_object_put(obj);
	return -1;
}

void bson_to_json_generic(struct json_object *obj, bson_iter_t *it,
                          bson_type_t type)
{
	const char *curr_key;
	char *s, oid[25];
	const unsigned char *bin;
	int len;
	struct json_object *obj2 = NULL;
	unsigned int ts, ulen, _;
	bson_iter_t it2;
	bson_subtype_t subtype;

	while (bson_iter_next(it)) {
		curr_key = bson_iter_key(it);
		switch (bson_iter_type(it) ) {
				case BSON_TYPE_INT32:
					LM_DBG("Found key %s with type int\n", curr_key);
					if (type == BSON_TYPE_DOCUMENT) {
						json_object_object_add(obj,curr_key,
						           json_object_new_int(bson_iter_int32(it)));
					} else if (type == BSON_TYPE_ARRAY) {
						json_object_array_add(obj,
						     json_object_new_int(bson_iter_int32(it)));
					}
					break;
				case BSON_TYPE_INT64:
					LM_DBG("Found key %s with type long\n", curr_key);
					/* no intrinsic support in OpenSIPS for 64bit integers -
					 * converting to string */
					s = int2str(bson_iter_int64(it), &len);
					s[len]=0;
					if (type == BSON_TYPE_DOCUMENT) {
						json_object_object_add(obj,curr_key,json_object_new_string(s));
					} else if (type == BSON_TYPE_ARRAY) {
						json_object_array_add(obj,json_object_new_string(s));
					}
					break;
				case BSON_TYPE_DOUBLE:
					/* no intrinsic support in OpenSIPS for floating point numbers
					 * converting to int */
					LM_DBG("Found key %s with type double\n",curr_key);
					if (type == BSON_TYPE_DOCUMENT)
						json_object_object_add(obj,curr_key,
								json_object_new_int((int)bson_iter_double(it)));
					else if (type == BSON_TYPE_ARRAY)
						json_object_array_add(obj,
						       json_object_new_int((int)bson_iter_double(it)));
					break;
				case BSON_TYPE_UTF8:
					LM_DBG("Found key %s with type string\n",curr_key);
					if (type == BSON_TYPE_DOCUMENT)
						json_object_object_add(obj,curr_key,
								json_object_new_string(bson_iter_utf8(it, NULL)));
					else if (type == BSON_TYPE_ARRAY)
						json_object_array_add(obj,json_object_new_string(bson_iter_utf8(it, NULL)));
					break;
				case BSON_TYPE_BOOL:
					LM_DBG("Found key %s with type bool\n",curr_key);
					if (type == BSON_TYPE_DOCUMENT)
						json_object_object_add(obj,curr_key,
								json_object_new_int((int)bson_iter_bool(it)));
					else if (type == BSON_TYPE_ARRAY)
						json_object_array_add(obj,json_object_new_int((int)bson_iter_bool(it)));
					break;
				case BSON_TYPE_DATE_TIME:
					LM_DBG("Found key %s with type date\n",curr_key);
					if (type == BSON_TYPE_DOCUMENT)
						json_object_object_add(obj,curr_key,
								json_object_new_int((int)(bson_iter_date_time(it)/1000)));
					else if (type == BSON_TYPE_ARRAY)
						json_object_array_add(obj,json_object_new_int((int)(bson_iter_date_time(it)/1000)));
					break;
				case BSON_TYPE_ARRAY:
					LM_DBG("Found key %s with type array\n",curr_key);
					obj2 = json_object_new_array();
					bson_iter_recurse(it, &it2);
					bson_to_json_generic(obj2,&it2,BSON_TYPE_ARRAY);
					if (type == BSON_TYPE_DOCUMENT)
						json_object_object_add(obj,curr_key,obj2);
					else if (type == BSON_TYPE_ARRAY)
						json_object_array_add(obj,obj2);
					break;
				case BSON_TYPE_DOCUMENT:
					LM_DBG("Found key %s with type object\n",curr_key);
					obj2 = json_object_new_object();
					bson_iter_recurse(it, &it2);
					bson_to_json_generic(obj2,&it2,BSON_TYPE_DOCUMENT);
					if (type == BSON_TYPE_DOCUMENT)
						json_object_object_add(obj,curr_key,obj2);
					else if (type == BSON_TYPE_ARRAY)
						json_object_array_add(obj,obj2);
					break;
				case BSON_TYPE_OID:
					memset(oid, 0, sizeof oid);
					bson_oid_to_string(bson_iter_oid(it), oid);
					json_object_object_add(obj,curr_key,
							json_object_new_string(oid));
					LM_DBG(" Found type %d for key %s \n",
							bson_iter_type(it),curr_key);
					break;
				case BSON_TYPE_NULL:
					json_object_object_add(obj,curr_key,NULL);
					break;
				case BSON_TYPE_TIMESTAMP:
					bson_iter_timestamp(it, &ts, &_);
					json_object_object_add(obj, curr_key,
					                       json_object_new_int(ts));
					break;
				case BSON_TYPE_BINARY:
					bson_iter_binary(it, &subtype, &ulen, &bin);
					json_object_object_add(obj, curr_key,
					                       json_object_new_string((const char *)bin));
					break;
				default:
					LM_WARN("Unsupported type %d for key %s - skipping\n",
							bson_iter_type(it),curr_key);
		}
	}
}
