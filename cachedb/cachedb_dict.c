/*
 * Doubly-linked list implementation of a dictionary
 *
 * Copyright (C) 2018 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "cachedb_types.h"
#include "../lib/cJSON.h"

int cdb_dict_add_str(cdb_dict_t *dest, const char *key, int key_len,
                     const str *val)
{
	cdb_key_t _key;
	cdb_pair_t *pair;

	_key.name.s = (char *)key;
	_key.name.len = key_len;
	_key.is_pk = 0;

	pair = cdb_mk_pair(&_key, NULL);
	if (!pair) {
		LM_ERR("oom\n");
		return -1;
	}

	pair->val.type = CDB_STR;
	pair->val.val.st = *val;

	cdb_dict_add(pair, dest);
	return 0;
}

int cdb_dict_add_int32(cdb_dict_t *dest, const char *key, int key_len,
                       uint32_t v)
{
	cdb_key_t _key;
	cdb_pair_t *pair;

	_key.name.s = (char *)key;
	_key.name.len = key_len;
	_key.is_pk = 0;

	pair = cdb_mk_pair(&_key, NULL);
	if (!pair) {
		LM_ERR("oom\n");
		return -1;
	}

	pair->val.type = CDB_INT32;
	pair->val.val.i32 = v;

	cdb_dict_add(pair, dest);
	return 0;
}

int cdb_dict_add_int64(cdb_dict_t *dest, const char *key, int key_len,
                       uint64_t v)
{
	cdb_key_t _key;
	cdb_pair_t *pair;

	_key.name.s = (char *)key;
	_key.name.len = key_len;
	_key.is_pk = 0;

	pair = cdb_mk_pair(&_key, NULL);
	if (!pair) {
		LM_ERR("oom\n");
		return -1;
	}

	pair->val.type = CDB_INT64;
	pair->val.val.i64 = v;

	cdb_dict_add(pair, dest);
	return 0;
}

int cdb_dict_add_null(cdb_dict_t *dest, const char *key, int key_len)
{
	cdb_key_t _key;
	cdb_pair_t *pair;

	_key.name.s = (char *)key;
	_key.name.len = key_len;
	_key.is_pk = 0;

	pair = cdb_mk_pair(&_key, NULL);
	if (!pair) {
		LM_ERR("oom\n");
		return -1;
	}

	pair->val.type = CDB_NULL;

	cdb_dict_add(pair, dest);
	return 0;
}

void cdb_dict_add(struct cdb_pair *pair, cdb_dict_t *dict)
{
	list_add(&pair->list, dict);
}

static int __dbg_cdb_dict(const cdb_dict_t *dict, str *buf,
                          char **head, int *cur_len)
{
	struct list_head *_, *__;
	cdb_pair_t *pair;
	int needed;
	char *ip;
	int ilen;

	list_for_each_safe (_, __, dict) {
		pair = list_entry(_, cdb_pair_t, list);

		needed = 1 + pair->key.name.len + 1 + pair->subkey.len + 3 + 2;
		if (pkg_str_extend(buf, *cur_len + needed) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
		*head = buf->s + *cur_len;

		if (pair->key.is_pk) {
			**head = '*'; (*head)++;
			*cur_len += 1;
		}
		memcpy(*head, pair->key.name.s, pair->key.name.len);
		*head += pair->key.name.len;
		*cur_len += pair->key.name.len;

		if (pair->subkey.len > 0) {
			**head = '.'; (*head)++;
			*cur_len += 1;
			memcpy(*head, pair->subkey.s, pair->subkey.len);
			*head += pair->subkey.len;
			*cur_len += pair->subkey.len;
		}

		memcpy(*head, " : ", 3);
		*head += 3;
		*cur_len += 3;

		if (pkg_str_extend(buf, *cur_len + 20 + 4 +
		        (pair->val.type == CDB_STR ? pair->val.val.st.len : 0)) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
		*head = buf->s + *cur_len;

		if (pair->val.type == CDB_DICT) {
			memcpy(*head, "{ ", 2); (*head) += 2; *cur_len += 2;
			__dbg_cdb_dict(&pair->val.val.dict, buf, head, cur_len);
			memcpy(*head, " }", 2); (*head) += 2; *cur_len += 2;
			goto next_pair;
		}

		switch (pair->val.type) {
		case CDB_NULL:
			memcpy(*head, "null", 4);
			*head += 4;
			*cur_len += 4;
			break;
		case CDB_INT32:
			ip = int2str(pair->val.val.i32, &ilen);
			memcpy(*head, ip, ilen);
			*head += ilen;
			*cur_len += ilen;
			break;
		case CDB_INT64:
			ip = int2str(pair->val.val.i64, &ilen);
			memcpy(*head, ip, ilen);
			*head += ilen;
			*cur_len += ilen;
			break;
		case CDB_STR:
			**head = '"'; (*head)++; *cur_len += 1;
			memcpy(*head, pair->val.val.st.s, pair->val.val.st.len);
			*head += pair->val.val.st.len;
			*cur_len += pair->val.val.st.len;
			**head = '"'; (*head)++; *cur_len += 1;
			break;
		default:
			LM_ERR("unsupported type: %d\n", pair->val.type);
		}

	next_pair:
		if (__ != dict) {
			memcpy(*head, ", ", 2);
			*head += 2;
			*cur_len += 2;
		}
	}

	return 0;
}

void _dbg_cdb_dict(const char *pre_txt, const cdb_dict_t *dict)
{
	static str static_pkg_buf;
	char *head;
	int final_len = 0;

	if (!dict)
		goto out;

	if (pkg_str_extend(&static_pkg_buf, 32) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	head = static_pkg_buf.s;

	memcpy(head, "{ ", 2);
	head += 2;
	final_len += 2;

	if (__dbg_cdb_dict(dict, &static_pkg_buf, &head, &final_len) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	if (pkg_str_extend(&static_pkg_buf, final_len + 2) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	memcpy(head, " }", 2);
	final_len += 2;

out:
	LM_DBG("%s%.*s\n", pre_txt, final_len, static_pkg_buf.s);
}

cdb_pair_t *cdb_dict_fetch(const cdb_key_t *key, const cdb_dict_t *dict)
{
	struct list_head *_;
	cdb_pair_t *pair;

	if (!dict)
		return NULL;

	list_for_each (_, dict) {
		pair = list_entry(_, cdb_pair_t, list);

		if ((key->is_pk && pair->key.is_pk)
		    || str_match(&pair->key.name, &key->name))
			return pair;
	}

	return NULL;
}

int dict_cmp(const cdb_dict_t *a, const cdb_dict_t *b)
{
	const struct list_head *p1, *p2;
	cdb_pair_t *pair1;
	cdb_pair_t *pair2;

	if (a == b)
		return 0;

	if (!a || !b)
		return 1;

	/* different # of pairs? */
	for (p1 = a->next, p2 = b->next; p1 != a && p2 != b;
	     p1 = p1->next, p2 = p2->next)
		{}
	if (p1 != a || p2 != b)
		return 1;

	list_for_each (p1, a) {
		pair1 = list_entry(p1, cdb_pair_t, list);

		pair2 = cdb_dict_fetch(&pair1->key, b);
		if (!pair2)
			return 1;

		if ((!pair1->key.is_pk || !pair2->key.is_pk) &&
		     val_cmp(&pair1->val, &pair2->val))
			return 1;
	}

	return 0;
}

int val_cmp(const cdb_val_t *v1, const cdb_val_t *v2)
{
	if (v1->type != v2->type)
		return 1;

	switch (v1->type) {
	case CDB_INT32:
		return v1->val.i32 != v2->val.i32;
	case CDB_INT64:
		return v1->val.i64 != v2->val.i64;
	case CDB_DICT:
		return dict_cmp(&v1->val.dict, &v2->val.dict);
	case CDB_STR:
		return str_strcmp(&v1->val.st, &v2->val.st);
	case CDB_NULL:
		return 0;
		break;
	default:
		LM_BUG("unsupported type: %d\n", v1->type);
		return 1;
	}
}

int cdb_dict_has_pair(const cdb_dict_t *haystack, const cdb_pair_t *pair)
{
	cdb_pair_t *needle;

	if (!haystack)
		return 0;

	needle = cdb_dict_fetch(&pair->key, haystack);
	if (!needle || needle->val.type != pair->val.type)
		return 0;

	return !val_cmp(&needle->val, &pair->val);
}

int cdb_dict_has_subkeys(const cdb_dict_t *dict)
{
	struct list_head *it;
	cdb_pair_t *p;

	list_for_each (it, dict) {
		p = list_entry(it, cdb_pair_t, list);
		if (!ZSTR(p->subkey))
			return 1;
	}

	return 0;
}

cdb_pair_t *nth_pair(const cdb_dict_t *dict, int nth)
{
	struct list_head *_;
	cdb_pair_t *pair;

	if (!dict)
		return NULL;

	list_for_each (_, dict) {
		if (--nth == 0) {
			pair = list_entry(_, cdb_pair_t, list);
			return pair;
		}
	}

	return NULL;
}

char *cdb_dict_to_json(const cdb_dict_t *dict,
         unsigned int (*escape)(char *dst, const str *src),
         unsigned int (*calc_escaped_len)(str *in))
{
#define MAX_OBJ_PAIRS 32
	struct list_head *_;
	cdb_pair_t *pair;
	unsigned int len = 1; /* { */
	char *obj = NULL, *objs[MAX_OBJ_PAIRS];
	unsigned int i = 0, cnt = 0, o = 0;
	int obj_cnt = 0;

	list_for_each (_, dict) {
		pair = list_entry(_, cdb_pair_t, list);

		switch (pair->val.type) {
		case CDB_DICT:
			if (obj_cnt == MAX_OBJ_PAIRS) {
				LM_ERR("max DICT pairs limit exceeded (%d)\n", MAX_OBJ_PAIRS);
				goto error;
			}

			objs[obj_cnt] = cdb_dict_to_json(
					&pair->val.val.dict, escape, calc_escaped_len);
			if (!objs[obj_cnt]) {
				LM_ERR("oom\n");
				goto error;
			}

			len += strlen(objs[obj_cnt++]);
			goto next_item;

		case CDB_STR:
			len += 2; /* "" */
			if (!calc_escaped_len)
				len += pair->val.val.st.len;
			else
				len += calc_escaped_len(&pair->val.val.st);
			break;

		case CDB_INT32:
			len += 1 + 10;
			break;

		case CDB_INT64:
			len += 1 + 20;
			break;

		case CDB_NULL:
			len += 4;
			break;

		default:
			LM_ERR("unsupported CDB type: %d\n", pair->val.type);
			continue;
		}

next_item:
		if (cnt++ > 0)
			len++; /* , */

		len += 1 + pair->key.name.len + 1 + 1;  /* "" : ??? */
	}

	len += 2; /* }\0 */
	obj = pkg_malloc(len);
	if (!obj) {
		LM_ERR("oom\n");
		goto error;
	}

	obj[i++] = '{';

	cnt = 0;
	list_for_each (_, dict) {
		pair = list_entry(_, cdb_pair_t, list);
		if (cnt++ > 0)
			obj[i++] = ',';

		i += sprintf(obj+i, "\"%.*s\":", pair->key.name.len, pair->key.name.s);

		switch (pair->val.type) {
		case CDB_DICT:
			if (o == obj_cnt && o > 0) {
				LM_BUG("bufer overflow (%d) in JSON key %.*s\n",
				        o, pair->key.name.len, pair->key.name.s);
				goto error;
			}

			i += sprintf(obj+i, "%s", objs[o++]);
			break;

		case CDB_STR:
			if (!escape) {
				i += sprintf(obj+i, "\"%.*s\"",
				        pair->val.val.st.len, pair->val.val.st.s);
			} else {
				obj[i++] = '\"';
				i += escape(obj+i, &pair->val.val.st);
				obj[i++] = '\"';
			}
			break;

		case CDB_INT32:
			i += sprintf(obj+i, "%d", pair->val.val.i32);
			break;

		case CDB_INT64:
			i += sprintf(obj+i, "%lld", (long long)pair->val.val.i64);
			break;

		case CDB_NULL:
			i += sprintf(obj+i, "null");
			break;

		default:
			LM_ERR("unsupported value type (%d), key: %.*s\n", pair->val.type,
			        pair->key.name.len, pair->key.name.s);
			break;
		}
	}

	obj[i++] = '}';
	obj[i++] = '\0';
	if (i > len)
		LM_BUG("buffer overflow (%u > %u) in JSON: '%s'\n", i, len, obj);

	while (obj_cnt > 0)
		pkg_free(objs[--obj_cnt]);
	return obj;

error:
	while (obj_cnt > 0)
		pkg_free(objs[--obj_cnt]);
	pkg_free(obj);
	return NULL;
}



int cdb_cjson_to_dict(const cJSON *obj, cdb_dict_t *out_dict,
            void (*unescape)(char *))
{
	cJSON *it;
	cdb_key_t key;
	cdb_pair_t *pair;
	union cdb_val_u *val;

	INIT_LIST_HEAD(out_dict);

	for (it = obj->child; it; it = it->next) {
		LM_DBG("  iter object item, type %d\n", it->type);

		init_str(&key.name, it->string);
		key.is_pk = 0;

		pair = cdb_mk_pair(&key, NULL);
		if (!pair) {
			LM_ERR("oom\n");
			continue;
		}

		val = &pair->val.val;

		switch (it->type) {
		case cJSON_Object:
			pair->val.type = CDB_DICT;
			if (cdb_cjson_to_dict(it, &val->dict, unescape) != 0) {
				LM_ERR("failed to convert cJSON to cdb_dict_t (oom)\n");
				continue;
			}
			break;

		case cJSON_NULL:
			pair->val.type = CDB_NULL;
			break;

		case cJSON_True:
		case cJSON_False:
			pair->val.type = CDB_INT32;
			val->i32 = it->valueint;
			break;

		case cJSON_Number:
			pair->val.type = CDB_INT32;
			val->i32 = it->valueint;
			break;

		case cJSON_String:
			if (unescape)
				unescape(it->valuestring);

			str st = {.s = it->valuestring, .len = strlen(it->valuestring)};

			pair->val.type = CDB_STR;
			if (pkg_nt_str_dup(&val->st, &st) != 0) {
				LM_ERR("oom\n");
				pkg_free(pair);
				continue;
			}
			break;

		default:
			LM_ERR("unimplemented type (%d), skipping!\n", it->type);
			pkg_free(pair);
			continue;
		}

		cdb_dict_add(pair, out_dict);
	}


	return 0;
}

int cdb_json_to_dict(const char *json, cdb_dict_t *out, void (*unescape)(char *))
{
	cJSON *root;

	root = cJSON_Parse(json);
	if (!root) {
		LM_ERR("failed to parse JSON: '%s'\n", json);
		return -1;
	}

	LM_DBG("parsed JSON '%s'\n", json);

	if (root->type != cJSON_Object) {
		LM_ERR("unexpected root JSON type (%d), need Object in json: '%s'\n",
		        root->type, json);
		goto error;
	}

	if (cdb_cjson_to_dict(root, out, unescape) != 0) {
		LM_ERR("failed to convert cJSON to cdb_dict_t (oom)\n");
		goto error;
	}

	cJSON_Delete(root);
	return 0;

error:
	cJSON_Delete(root);
	return -1;
}

void cdb_free_entries(cdb_dict_t *dict, void (*free_val_str) (void *val))
{
	struct list_head *_, *__;
	cdb_pair_t *kv;

	list_for_each_safe(_, __, dict) {
		kv = list_entry(_, cdb_pair_t, list);

		switch (kv->val.type) {
		case CDB_DICT:
			cdb_free_entries(&kv->val.val.dict, free_val_str);
			break;
		case CDB_STR:
			if (free_val_str)
				free_val_str(kv->val.val.st.s);
			break;
		default:
			break;
		}

		list_del(&kv->list);
		pkg_free(kv);
	}
}
