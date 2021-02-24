/*
 * Copyright (C) 2018-2021 OpenSIPS Solutions
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

#include <tap.h>

#include "../../str.h"
#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"
#include "../../lib/osips_malloc.h"
#include "../../sr_module.h"
#include "../../modparam.h"

#define CACHEDB_SKIP_BACKEND_TESTS

extern cachedb_engine* lookup_cachedb(str *name);
extern cachedb_con *cachedb_get_connection(cachedb_engine *cde,str *group_name);
static void test_cachedb_backends(void);
static void load_cachedb_modules(void);
static void test_cachedb_url(void);


void init_cachedb_tests(void)
{
	load_cachedb_modules();
}


void test_cachedb(void)
{
	test_cachedb_url();
	test_cachedb_backends();
}


static void load_cachedb_modules(void)
{
#ifdef CACHEDB_SKIP_BACKEND_TESTS
	return;
#endif

	if (load_module("cachedb_mongodb.so") != 0) {
		printf("failed to load mongo\n");
		exit(-1);
	}

	if (load_module("cachedb_cassandra.so") != 0) {
		printf("failed to load cassandra\n");
		exit(-1);
	}

	if (set_mod_param_regex("cachedb_mongodb", "cachedb_url", STR_PARAM,
	    "mongodb://10.0.0.177:27017/OpensipsTests.OpensipsTests") != 0) {
		printf("failed to set mongo url\n");
		exit(-1);
	}

	if (set_mod_param_regex("cachedb_cassandra", "cachedb_url", STR_PARAM,
	    "cassandra:test1://10.0.0.178/testcass1.osstest1.osscnttest1") != 0) {
		printf("failed to set cassandra url\n");
		exit(-1);
	}

	/* for Cassandra we need a different table schema for the col-oriented ops tests */
	if (set_mod_param_regex("cachedb_cassandra", "cachedb_url", STR_PARAM,
	    "cassandra:test2://10.0.0.178/testcass1.osstest2.osscnttest1") != 0) {
		printf("failed to set cassandra url\n");
		exit(-1);
	}
}


int res_has_kv(const cdb_res_t *res, const cdb_pair_t *pair)
{
	struct list_head *_;
	cdb_row_t *row;

	list_for_each (_, &res->rows) {
		row = list_entry(_, cdb_row_t, list);
		if (cdb_dict_has_pair(&row->dict, pair))
			return 1;
	}

	return 0;
}

static inline cdb_dict_t *nth_dict(const cdb_res_t *res, int nth)
{
	struct list_head *_;
	cdb_row_t *row;

	list_for_each (_, &res->rows) {
		if (--nth == 0) {
			row = list_entry(_, cdb_row_t, list);
			return &row->dict;
		}
	}

	return NULL;
}

static int test_query_filters(cachedb_funcs *api, cachedb_con *con,
								const char *cachedb_name)
{
	cdb_key_t key;
	str sa = str_init("A"), sb = str_init("B"), sc = str_init("C"),
	    sd = str_init("D");
	int_str_t isv;
	cdb_filter_t *filter;
	cdb_res_t res;
	cdb_pair_t pair;

	init_str(&key.name, "tgr_1");
	ok(api->set(con, &key.name, &sa, 0) == 0, "test_query: set A");

	init_str(&key.name, "tgr_2");
	ok(api->set(con, &key.name, &sb, 0) == 0, "test_query: set B");

	init_str(&key.name, "tgr_3");
	ok(api->set(con, &key.name, &sc, 0) == 0, "test_query: set C");

	init_str(&key.name, "tgr_4");
	ok(api->set(con, &key.name, &sd, 0) == 0, "test_query: set D");

	memset(&key, 0, sizeof key);

	if (!strcmp(cachedb_name, "mongodb"))
		init_str(&key.name, "opensips");
	else if (!strcmp(cachedb_name, "cassandra"))
		init_str(&key.name, "opensipsval");
	else
		return 0;

	isv.is_str = 1;
	isv.s = sd;

	/* single filter tests */

	filter = cdb_append_filter(NULL, &key, CDB_OP_LTE, &isv);
	ok(api->query(con, filter, &res) == 0, "test_query: get 4 items");
	ok(res.count == 4, "test_query: have 4 items");

	memset(&pair, 0, sizeof pair);
	pair.val.type = CDB_STR;
	if (!strcmp(cachedb_name, "mongodb"))
		init_str(&pair.key.name, "opensips");
	else if (!strcmp(cachedb_name, "cassandra"))
		init_str(&pair.key.name, "opensipsval");
	else
		return 0;

	pair.val.val.st = sa; ok(res_has_kv(&res, &pair), "has A");
	pair.val.val.st = sb; ok(res_has_kv(&res, &pair), "has B");
	pair.val.val.st = sc; ok(res_has_kv(&res, &pair), "has C");
	pair.val.val.st = sd; ok(res_has_kv(&res, &pair), "has D");
	init_str(&pair.val.val.st, "Z");
	ok(!res_has_kv(&res, &pair), "!has Z");
	cdb_free_rows(&res);
	cdb_free_filters(filter);

	filter = cdb_append_filter(NULL, &key, CDB_OP_LT, &isv);
	ok(api->query(con, filter, &res) == 0, "test_query: get 3 items");
	ok(res.count == 3, "test_query: have 3 items");
	pair.val.val.st = sa; ok(res_has_kv(&res, &pair), "has A");
	pair.val.val.st = sb; ok(res_has_kv(&res, &pair), "has B");
	pair.val.val.st = sc; ok(res_has_kv(&res, &pair), "has C");
	pair.val.val.st = sd; ok(!res_has_kv(&res, &pair), "!has D");
	cdb_free_rows(&res);
	cdb_free_filters(filter);

	init_str(&isv.s, "A");
	filter = cdb_append_filter(NULL, &key, CDB_OP_LT, &isv);
	ok(api->query(con, filter, &res) == 0, "test_query: get 0 items");
	ok(res.count == 0, "test_query: have 0 items");
	pair.val.val.st = sa; ok(!res_has_kv(&res, &pair), "!has A");
	pair.val.val.st = sc; ok(!res_has_kv(&res, &pair), "!has C");
	cdb_free_rows(&res);
	cdb_free_filters(filter);

	filter = cdb_append_filter(NULL, &key, CDB_OP_LTE, &isv);
	ok(api->query(con, filter, &res) == 0, "test_query: get 1 item");
	ok(res.count == 1, "test_query: have 1 item");
	pair.val.val.st = sa; ok(res_has_kv(&res, &pair), "has A");
	pair.val.val.st = sb; ok(!res_has_kv(&res, &pair), "!has B");
	cdb_free_rows(&res);
	cdb_free_filters(filter);

	/* multi filter tests */

	init_str(&isv.s, "D");
	filter = cdb_append_filter(NULL, &key, CDB_OP_LT, &isv);
	ok(api->query(con, filter, &res) == 0, "test_query: get 3 items");
	ok(res.count == 3, "test_query: have 3 items");
	init_str(&isv.s, "A");
	filter = cdb_append_filter(filter, &key, CDB_OP_GTE, &isv);
	ok(api->query(con, filter, &res) == 0, "test_query: get 3 items");
	ok(res.count == 3, "test_query: have 3 items");
	cdb_free_rows(&res);
	cdb_free_filters(filter);

	return 1;
}

static int test_query(cachedb_funcs *api, cachedb_con *con,
                         const cdb_dict_t *pairs)
{
	cdb_res_t res;

	if (!ok(api->query(con, NULL, &res) == 0, "query: NULL filter"))
		return 0;

	ok(res.count == 2, "query: 2 results");
	dbg_cdb_dict("pairs: ", pairs);
	dbg_cdb_dict("res 1: ", nth_dict(&res, 1));
	dbg_cdb_dict("res 2: ", nth_dict(&res, 2));

	ok(!dict_cmp(nth_dict(&res, 1), nth_dict(&res, 2)), "identical results");

	cdb_free_rows(&res);

	return 1;
}

static int test_update(cachedb_funcs *api, cachedb_con *con,
                       cdb_dict_t *out_pairs)
{
	cdb_filter_t *filter;
	int_str_t isv;
	cdb_key_t key;
	str subkey;
	cdb_pair_t *pair, *dict_pair;

	cdb_pkey_init(&key, "aor");
	init_str(&isv.s, "foo@opensips.org"); isv.is_str = 1;
	filter = cdb_append_filter(NULL, &key, CDB_OP_EQ, &isv);

	cdb_dict_init(out_pairs);

	cdb_key_init(&key, "key_null");
	pair = cdb_mk_pair(&key, NULL);
	pair->val.type = CDB_NULL;
	cdb_dict_add(pair, out_pairs);

	cdb_key_init(&key, "key_32bit");
	pair = cdb_mk_pair(&key, NULL);
	pair->val.type = CDB_INT32;
	pair->val.val.i32 = 2147483647;
	cdb_dict_add(pair, out_pairs);

	cdb_key_init(&key, "key_64bit");
	pair = cdb_mk_pair(&key, NULL);
	pair->val.type = CDB_INT64;
	pair->val.val.i64 = 9223372036854775807;
	cdb_dict_add(pair, out_pairs);

	cdb_key_init(&key, "key_str");
	pair = cdb_mk_pair(&key, NULL);
	pair->val.type = CDB_STR;
	init_str(&pair->val.val.st, pkg_strdup("31337"));
	cdb_dict_add(pair, out_pairs);

	/* set a dict subkey which contains a dict */
	cdb_key_init(&key, "key_dict"); init_str(&subkey, "subkey-dict");
	dict_pair = cdb_mk_pair(&key, &subkey);
	dict_pair->val.type = CDB_DICT;
	cdb_dict_init(&dict_pair->val.val.dict);
	cdb_key_init(&key, "foo");
	pair = cdb_mk_pair(&key, NULL);
	pair->val.type = CDB_INT64;
	pair->val.val.i64 = 9223372036854775807;
	cdb_dict_add(pair, &dict_pair->val.val.dict);
	cdb_key_init(&key, "bar");
	pair = cdb_mk_pair(&key, NULL);
	pair->val.type = CDB_STR;
	init_str(&pair->val.val.st, pkg_strdup("hello, world!"));
	cdb_dict_add(pair, &dict_pair->val.val.dict);
	cdb_dict_add(dict_pair, out_pairs);

	ok(api->update(con, filter, out_pairs) == 0, "test_update #1");

	cdb_free_filters(filter);
	cdb_pkey_init(&key, "aor");
	init_str(&isv.s, "bar@opensips.org");
	filter = cdb_append_filter(NULL, &key, CDB_OP_EQ, &isv);

	ok(api->update(con, filter, out_pairs) == 0, "test_update #2");

	cdb_free_filters(filter);

	return 1;
}

static int test_update_unset(cachedb_funcs *api, cachedb_con *con,
                             cdb_dict_t *out_pairs)
{
	struct list_head *_;
	cdb_pair_t *pair;
	cdb_filter_t *filter;
	cdb_key_t key;
	int_str_t isv;

	list_for_each (_, out_pairs) {
		pair = list_entry(_, cdb_pair_t, list);
		pair->unset = 1;
	}

	cdb_pkey_init(&key, "aor");
	init_str(&isv.s, "foo@opensips.org"); isv.is_str = 1;
	filter = cdb_append_filter(NULL, &key, CDB_OP_EQ, &isv);

	ok(api->update(con, filter, out_pairs) == 0, "test_update_unset foo key");

	cdb_free_filters(filter);

	cdb_pkey_init(&key, "aor");
	init_str(&isv.s, "bar@opensips.org"); isv.is_str = 1;
	filter = cdb_append_filter(NULL, &key, CDB_OP_EQ, &isv);

	ok(api->update(con, filter, out_pairs) == 0, "test_update_unset bar key");

	cdb_free_filters(filter);

	return 1;
}

static int test_query_unset(cachedb_funcs *api, cachedb_con *con,
                            const cdb_dict_t *pairs, const char *cachedb_name)
{
	cdb_res_t res;
	cdb_dict_t *dict1, *dict2;
	cdb_pair_t *pair;
	cdb_key_t key = CDB_KEY_INITIALIZER;

	if (!strcmp(cachedb_name, "cassandra")) {
		if (!ok(api->query(con, NULL, &res) == 0, "query: NULL filter"))
			return 0;

		ok(res.count == 0, "query: 0 results");

		return 1;
	}

	if (!ok(api->query(con, NULL, &res) == 0, "query: NULL filter"))
		return 0;

	ok(res.count == 2, "query: 2 results");
	dbg_cdb_dict("pairs: ", pairs);
	dict1 = nth_dict(&res, 1);
	dict2 = nth_dict(&res, 2);

	dbg_cdb_dict("res 1: ", dict1);
	dbg_cdb_dict("res 2: ", dict2);

	init_str(&key.name, "key");

	pair = cdb_dict_fetch(&key, dict1);
	ok(!pair ||
	   (pair->val.type == CDB_DICT && cdb_dict_empty(&pair->val.val.dict)),
	   "subdict-1 is empty");

	pair = cdb_dict_fetch(&key, dict2);
	ok(!pair ||
	   (pair->val.type == CDB_DICT && cdb_dict_empty(&pair->val.val.dict)),
	   "subdict-2 is empty");

	ok(nth_pair(dict1, 3) == NULL, "dict1 has 2 entries");
	ok(nth_pair(dict2, 3) == NULL, "dict2 has 2 entries");

	ok(!dict_cmp(dict1, dict2), "identical results");

	cdb_free_rows(&res);

	return 1;
}

static int test_column_ops(cachedb_funcs *api, cachedb_con *con1,
						cachedb_con *con2, const char *cachedb_name)
{
	cdb_dict_t cols;
	cachedb_con *con;

	if (con2)
		con = con2;
	else
		con = con1;

	if (CACHEDB_CAPABILITY(api, CACHEDB_CAP_TRUNCATE))
		ok(api->truncate(con) == 0, "truncate");

	if (!ok(test_update(api, con, &cols), "test update-set")
	    || !ok(test_query(api, con, &cols), "test query-set")
	    || !ok(test_update_unset(api, con, &cols), "test update-unset")
	    || !ok(test_query_unset(api, con, &cols, cachedb_name), "test query-unset"))
		return 0;

	if (CACHEDB_CAPABILITY(api, CACHEDB_CAP_TRUNCATE))
		ok(api->truncate(con) == 0, "truncate");

	cdb_free_entries(&cols, osips_pkg_free);

	if (con2)
		con = con1;

	if (CACHEDB_CAPABILITY(api, CACHEDB_CAP_TRUNCATE))
		ok(api->truncate(con) == 0, "truncate");

	if (!ok(test_query_filters(api, con, cachedb_name), "test query filters"))
		return 0;

	if (CACHEDB_CAPABILITY(api, CACHEDB_CAP_TRUNCATE))
		ok(api->truncate(con) == 0, "truncate");

	return 1;
}

static void test_cachedb_api(const char *cachedb_name, const char *group1,
								const char *group2)
{
	str key = str_init("foo"),
	    val = str_init("bar");
	str cdb_str, cdb_gr1, str_gr1, str_gr2 = {0,0};
	cachedb_engine *cde;
	cachedb_con *con1 = NULL, *con2 = NULL;

	init_str(&cdb_str, cachedb_name);

	if (group1) {
		cdb_gr1.len = strlen(cachedb_name) + strlen(group1) + 1;
		cdb_gr1.s = pkg_malloc(cdb_gr1.len);
		snprintf(cdb_gr1.s, cdb_gr1.len+1, "%s:%s", cachedb_name, group1);

		init_str(&str_gr1, group1);
		init_str(&str_gr2, group2);
	} else
		init_str(&cdb_gr1, cachedb_name);

	/* high-level cachedb API (called by script, MI) */

	/* TODO: write tests for signed integers (may be broken in current Mongo) */

	ok(cachedb_store(&cdb_gr1, &key, &val, 0) == 1, "store key");

	memset(&val, 0, sizeof val);
	ok(cachedb_fetch(&cdb_gr1, &key, &val) == 1, "fetch key");
	cmp_mem(val.s, "bar", 3, "check fetched value");

	ok(cachedb_remove(&cdb_gr1, &key) == 1, "remove key");

	ok(cachedb_fetch(&cdb_gr1, &key, &val) == -2, "fetch non-existing key");

	/* low-level cachedb API (called by core and modules) */

	cde = lookup_cachedb(&cdb_str);
	if (!ok(cde != NULL, "have cachedb engine"))
		return;

	if (group1) {
		con1 = cachedb_get_connection(cde, &str_gr1);
		if (!ok(con1 != NULL, "engine has con"))
				return;

		con2 = cachedb_get_connection(cde, &str_gr2);
		if (!ok(con2 != NULL, "engine has con"))
				return;
	} else {
		con1 = cachedb_get_connection(cde, NULL);
		if (!ok(con1 != NULL, "engine has con"))
				return;
	}

	if (CACHEDB_CAPABILITY(&cde->cdb_func, CACHEDB_CAP_COL_ORIENTED))
		ok(test_column_ops(&cde->cdb_func, con1, con2, cachedb_name),
			"column-oriented tests");
}

/*
 * For Cassandra make sure to create the following tables:
 *  CREATE TABLE osstest1 (opensipskey text PRIMARY KEY, opensipsval text);
 *	CREATE TABLE osstest2 (
 *		aor text PRIMARY KEY,
 *		key_32bit int,
 *		key_64bit bigint,
 *		key_dict map<text, frozen<map<text, text>>>,
 *		key_null text,
 *		key_str text
 *	);
 */

static void test_cachedb_backends(void)
{
#ifdef CACHEDB_SKIP_BACKEND_TESTS
	return;
#endif

	test_cachedb_api("mongodb", NULL, NULL);
	test_cachedb_api("cassandra", "test1", "test2");

	// todo();
	// skip tests here
	// end_todo;
}


static void test_cachedb_url(void)
{
	struct cachedb_id *db;

	/* invalid URLs */
	ok(!new_cachedb_id(_str("d:g://@")));
	ok(!new_cachedb_id(_str("d:g://u:@")));
	ok(!new_cachedb_id(_str("d:g://u:p@")));
	ok(!new_cachedb_id(_str("d:g://u:p@h")));
	ok(!new_cachedb_id(_str("d:g://u:p@h:")));

	db = new_cachedb_id(_str("redis:group1://:devxxxxxx@172.31.180.127:6379"));
	if (!ok(db != NULL))
	        return;
	ok(!strcmp(db->scheme, "redis"));
	ok(!strcmp(db->group_name, "group1"));
	ok(!strcmp(db->username, ""));
	ok(!strcmp(db->password, "devxxxxxx"));
	ok(!strcmp(db->host, "172.31.180.127"));
	ok(db->port == 6379);
	ok(!db->database);
	ok(!db->extra_options);

	db = new_cachedb_id(_str("redis:group1://:devxxxxxx@172.31.180.127:6379/"));
	if (!ok(db != NULL))
	        return;
	ok(db->port == 6379);
	ok(!db->database);
	ok(!db->extra_options);

	db = new_cachedb_id(_str("redis:group1://:devxxxxxx@172.31.180.127:6379/d?x=1&q=2"));
	if (!ok(db != NULL))
	        return;
	ok(!strcmp(db->database, "d"));
	ok(!strcmp(db->extra_options, "x=1&q=2"));
}
