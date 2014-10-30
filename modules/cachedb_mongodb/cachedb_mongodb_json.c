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

#include "../../dprint.h"
#include "../../ut.h"
#include "cachedb_mongodb_json.h"
#include "cachedb_mongodb_dbase.h"

int json_to_bson_append_element( bson *bb , const char *k , struct json_object *v );

int json_to_bson_append_array( bson *bb , struct json_object *a )
{
	int i,al_len;
	char *al;
	json_object *it;

	for ( i=0; i<json_object_array_length( a ); i++ ) {
		al = int2str(i,&al_len);
		if (al == NULL) {
			LM_ERR("Failed to convert %d to str\n",i);
			return -1;
		}

		al[al_len]=0;
		it = json_object_array_get_idx(a,i);
		if (it == NULL) {
			LM_ERR("Failed to get JSON idx\n");
			return -1;
		}

		if (json_to_bson_append_element(bb,al,it) < 0) {
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

int json_to_bson_append(bson *bb,struct json_object *o)
{
	json_object_object_iterator( o,key,val ) {
		if (json_to_bson_append_element(bb,key,val)<0) {
			LM_ERR("Failed to append new element\n");
			return -1;
		}
	}

	return 0;
}

int json_to_bson_append_element( bson *bb , const char *k , struct json_object *v )
{
	if (v==NULL) {
		bson_append_null(bb,k);
		return 0;
	}

	switch (json_object_get_type(v)) {
		case json_type_int:
			if (bson_append_int(bb,k,json_object_get_int(v))
					 != BSON_OK) {
				LM_ERR("Failed to append int\n");
				return -1;
			}
			break;
		case json_type_boolean:
			if (bson_append_bool(bb,k,json_object_get_boolean(v))
					!= BSON_OK) {
				LM_ERR("Failed to append boolean\n");
				return -1;
			}
			break;
		case json_type_double:
			if (bson_append_double(bb,k,json_object_get_double(v))
					!= BSON_OK) {
				LM_ERR("Failed to append double\n");
				return -1;
			}
			break;
		case json_type_string:
			if (bson_append_string(bb,k,json_object_get_string(v))
					!= BSON_OK) {
				LM_ERR("Failed to append string\n");
				return -1;
			}
			break;
		case json_type_object:
			if (bson_append_start_object( bb,k)
					!= BSON_OK) {
				LM_ERR("Failed to append start object\n");
				return -1;
			}
			if (json_to_bson_append(bb,v)<0) {
				LM_ERR("Failed to append to bson\n");
				return -1;
			}
			if (bson_append_finish_object(bb)
					!= BSON_OK) {
				LM_ERR("Failed to finish appending to BSON\n");
				return -1;
			}
			break;
		case json_type_array:
			if (bson_append_start_array(bb,k)
					!= BSON_OK) {
				LM_ERR("Failed to append start array\n");
				return -1;
			}

			if (json_to_bson_append_array(bb,v) < 0) {
				LM_ERR("Failed to append array to bson\n");
				return -1;
			}
			if (bson_append_finish_object(bb)
					!= BSON_OK) {
				LM_ERR("Failed to finish appending array to bson\n");
				return -1;
			}
			break;
		default:
			LM_ERR("Can't handle type for : %s\n",json_object_to_json_string(v));
			return -1;
	}

	return 0;
}

int json_to_bson(char *json,bson *bb)
{
	struct json_object *obj;

	LM_DBG("Trying to convert [%s]\n",json);

	obj=json_tokener_parse(json);
	if (is_error(obj)) {
		LM_ERR("Failed to parse JSON: %s\n",json);
		return -2;
	}

	if (!json_object_is_type(obj,json_type_object)) {
		LM_ERR("Inconsystent JSON type\n");
		goto error;
	}

	bson_init(bb);
	if (json_to_bson_append(bb,obj) < 0) {
		LM_ERR("Failed to convert json to bson\n");
		bson_finish(bb);
		bson_destroy(bb);
		goto error;
	}

	bson_finish(bb);
	json_object_put(obj);

	return 0;

error:
	if (obj)
		json_object_put(obj);
	return -1;
}

void bson_to_json_generic(struct json_object *obj,bson_iterator *it,int type)
{
	const char *curr_key;
	char *s;
	int len;
	struct json_object *obj2=NULL;
	bson_iterator it2;

		while (bson_iterator_next(it)) {
			curr_key=bson_iterator_key(it);

			switch( bson_iterator_type(it) ) {
					case BSON_INT:
						LM_DBG("Found key %s with type int\n",curr_key);
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,
									json_object_new_int(bson_iterator_int(it)));
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,json_object_new_int(bson_iterator_int(it)));
						break;
					case BSON_LONG:
						LM_DBG("Found key %s with type long\n",curr_key);
						/* no intrinsic support in OpenSIPS for 64bit integers -
 						 * converting to string */
						s = int2str(bson_iterator_long(it),&len);
						s[len]=0;
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,json_object_new_string(s));
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,json_object_new_string(s));
						break;
					case BSON_DOUBLE:
						/* no intrinsic support in OpenSIPS for floating point numbers
 						 * converting to int */
						LM_DBG("Found key %s with type double\n",curr_key);
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,
									json_object_new_int((int)bson_iterator_double(it)));
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,json_object_new_int((int)bson_iterator_double(it)));
						break;
					case BSON_STRING:
						LM_DBG("Found key %s with type string\n",curr_key);
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,
									json_object_new_string(bson_iterator_string(it)));
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,json_object_new_string(bson_iterator_string(it)));
						break;
					case BSON_BOOL:
						LM_DBG("Found key %s with type bool\n",curr_key);
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,
									json_object_new_int((int)bson_iterator_bool(it)));
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,json_object_new_int((int)bson_iterator_bool(it)));
						break;
					case BSON_ARRAY:
						LM_DBG("Found key %s with type array\n",curr_key);
						obj2 = json_object_new_array();
						bson_iterator_subiterator(it, &it2 );
						bson_to_json_generic(obj2,&it2,BSON_ARRAY);
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,obj2);
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,obj2);
						break;
					case BSON_OBJECT:
						LM_DBG("Found key %s with type object\n",curr_key);
						obj2 = json_object_new_object();
						bson_iterator_subiterator(it, &it2 );
						bson_to_json_generic(obj2,&it2,BSON_OBJECT);
						if (type == BSON_OBJECT)
							json_object_object_add(obj,curr_key,obj2);
						else if (type == BSON_ARRAY)
							json_object_array_add(obj,obj2);
						break;
					default:
						LM_DBG("Unsupported type %d for key %s - skipping\n",
								bson_iterator_type(it),curr_key);
			}
		}
}

int mongo_cursor_to_json(mongo_cursor *m_cursor,
		cdb_raw_entry ***reply,int expected_kv_no,int *reply_no)
{
	struct json_object *obj=NULL;
	bson_iterator it;
	const char *p;
	int current_size=0,len;

	/* start with a single returned document */
	*reply = pkg_malloc(1 * sizeof(cdb_raw_entry *));
	if (*reply == NULL) {
		LM_ERR("No more PKG mem\n");
		return -1;
	}

	/* expected_kv_no is always 1 for mongoDB */
	**reply = pkg_malloc(expected_kv_no * sizeof(cdb_raw_entry));
	if (**reply == NULL) {
		LM_ERR("No more pkg mem\n");
		pkg_free(*reply);
		return -1;
	}

	while( mongo_cursor_next(m_cursor) == MONGO_OK ) {
		if (current_size > 0) {
			*reply = pkg_realloc(*reply,(current_size + 1) * sizeof(cdb_raw_entry *));
			if (*reply == NULL) {
				LM_ERR("No more pkg\n");
				goto error_cleanup;
			}
			(*reply)[current_size] = pkg_malloc(expected_kv_no * sizeof(cdb_raw_entry));
			if ((*reply)[current_size] == NULL) {
				LM_ERR("No more pkg\n");
				goto error_cleanup;
			}
		}

		obj = json_object_new_object();
		bson_iterator_init(&it,mongo_cursor_bson(m_cursor));
		bson_to_json_generic(obj,&it,BSON_OBJECT);

		p = json_object_to_json_string(obj);
		if (!p) {
			LM_ERR("Json failed to be translated to string\n");
			goto error_cleanup;
		}

		len = strlen(p);

		(*reply)[current_size][0].val.s.s = pkg_malloc(len);
		if (! (*reply)[current_size][0].val.s.s ) {
			LM_ERR("No more pkg \n");
			goto error_cleanup;
		}

		memcpy((*reply)[current_size][0].val.s.s,p,len);
		(*reply)[current_size][0].val.s.len = len;
		(*reply)[current_size][0].type = CDB_STR;

		json_object_put(obj);

		current_size++;
	}

	*reply_no = current_size;
	LM_DBG("Fetched %d results\n",current_size);
	if (current_size == 0)
		return -2;

	return 1;

error_cleanup:
	if (obj)
		json_object_put(obj);

	for (len = 0;len<current_size;len++) {
		pkg_free((*reply)[len][0].val.s.s);
		pkg_free((*reply)[len]);
	}

	pkg_free(*reply);

	*reply = NULL;
	*reply_no=0;
	return -1;
}
