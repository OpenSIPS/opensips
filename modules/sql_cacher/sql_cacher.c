/**
 *
 * Copyright (C) 2015 OpenSIPS Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 *  2015-09-xx  initial version (Vlad Patrascu)
*/

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../pvar.h"
#include "../../locking.h"
#include "../../rw_locking.h"
#include "../../timer.h"
#include "../../ipc.h"
#include "sql_cacher.h"

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

int pv_parse_name(pv_spec_p sp, str *in);
int pv_init_param(pv_spec_p sp, int param);
int pv_get_sql_cached_value(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
static int parse_cache_entry(unsigned int type, void *val);
static void free_c_entry(cache_entry_t *c);

static mi_response_t *mi_reload_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reload_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

static str spec_delimiter = str_init(DEFAULT_SPEC_DELIM);
static str pvar_delimiter = str_init(DEFAULT_PVAR_DELIM);
static str columns_delimiter = str_init(DEFAULT_COLUMNS_DELIM);
static int fetch_nr_rows = DEFAULT_FETCH_NR_ROWS;
static int full_caching_expire = DEFAULT_FULL_CACHING_EXPIRE;
static int reload_interval = DEFAULT_RELOAD_INTERVAL;

static cache_entry_t **entry_list;
static struct queried_key **queries_in_progress;

/* per process db handlers corresponding to cache entries in entry_list */
static db_handlers_t *db_hdls_list;

gen_lock_t *queries_lock;

/* module parameters */
static param_export_t mod_params[] = {
	{"spec_delimiter", STR_PARAM, &spec_delimiter.s},
	{"pvar_delimiter", STR_PARAM, &pvar_delimiter.s},
	{"columns_delimiter", STR_PARAM, &columns_delimiter.s},
	{"sql_fetch_nr_rows", INT_PARAM, &fetch_nr_rows},
	{"full_caching_expire", INT_PARAM, &full_caching_expire},
	{"reload_interval", INT_PARAM, &reload_interval},
	{"cache_table", STR_PARAM|USE_FUNC_PARAM, (void *)&parse_cache_entry},
	{0,0,0}
};

static pv_export_t mod_items[] = {
	{{"sql_cached_value", sizeof("sql_cached_value") - 1}, 1000,
		pv_get_sql_cached_value, 0, pv_parse_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static mi_export_t mi_cmds[] = {
	{ "sql_cacher_reload", "reload the SQL database into the cache", 0, 0, {
		{mi_reload_1, {"id", 0}},
		{mi_reload_2, {"id", "key", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_CACHEDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/**
 * module exports
 */
struct module_exports exports = {
	"sql_cacher",				/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	&deps,						/* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	mod_params,					/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,					/* exported MI functions */
	mod_items,					/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload confirm function */
};

static int parse_cache_entry(unsigned int type, void *val)
{
	cache_entry_t *new_entry;
	char *p1, *p2, *tmp, *c_tmp1, *c_tmp2;
	int col_idx;
	int rc = -1;
	int i;
	int len;
	str parse_str_copy, parse_str;

	if(!entry_list){
		entry_list =  shm_malloc(sizeof(cache_entry_t*));
		if (!entry_list) {
			LM_ERR("No more memory for cache entries list\n");
			return -1;
		}
		*entry_list = NULL;
	}

	parse_str.len = strlen((char *)val);
	parse_str.s = pkg_malloc(parse_str.len);
	if(!parse_str.s){
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(parse_str.s, (char *)val, parse_str.len);
		new_entry = shm_malloc(sizeof(cache_entry_t));
		if (!new_entry) {
			LM_ERR("No more memory for cache entry struct\n");
			return -1;
		}
		new_entry->id.s = NULL;
		new_entry->columns = NULL;
		new_entry->key_type = DB_STR;
		new_entry->nr_columns = 0;
		new_entry->on_demand = 0;
		new_entry->expire = DEFAULT_ON_DEMAND_EXPIRE;
		new_entry->nr_ints = 0;
		new_entry->nr_strs = 0;
		new_entry->column_types = 0;
		new_entry->ref_lock = NULL;

#define PARSE_TOKEN(_ptr1, _ptr2, field, field_name_str, field_name_len) \
	do { \
		(_ptr2) = memchr((_ptr1), '=', parse_str.len - \
											((_ptr1) - parse_str.s)); \
		if (!(_ptr2)) { \
			LM_ERR("expected: '=' after %.*s\n", (field_name_len), (field_name_str)); \
			goto parse_err; \
		} \
		if (!memcmp((_ptr1), (field_name_str), (field_name_len))) { \
			if (*((_ptr1)+(field_name_len)) != '=') { \
				LM_ERR("expected: '=' after %.*s\n", (field_name_len), (field_name_str)); \
				goto parse_err; \
			} \
			tmp = memchr((_ptr2) + 1, spec_delimiter.s[0], parse_str.len - \
													((_ptr2) - parse_str.s)); \
			if (!tmp) { \
				LM_ERR("expected: %c after value of %.*s\n", spec_delimiter.s[0], \
					(field_name_len), (field_name_str)); \
				goto parse_err; \
			} \
			new_entry->field.len = tmp - (_ptr2) - 1; \
			if (new_entry->field.len <= 0) { \
				LM_ERR("expected value of: %.*s\n", (field_name_len), (field_name_str)); \
				goto parse_err; \
			} \
			new_entry->field.s = shm_malloc(new_entry->field.len); \
			memcpy(new_entry->field.s, p2 + 1, new_entry->field.len); \
		} else { \
			LM_ERR("expected: %.*s instead of: %.*s\n", (field_name_len), (field_name_str), \
				(field_name_len), (_ptr1)); \
			goto parse_err; \
		} \
	} while (0)

		parse_str_copy = parse_str;
		trim(&parse_str);
		/* parse the id */
		p1 = parse_str.s;
		PARSE_TOKEN(p1, p2, id, ID_STR, ID_STR_LEN);
		/* parse the db_url */
		p1 = tmp + 1;
		PARSE_TOKEN(p1, p2, db_url, DB_URL_STR, DB_URL_LEN);
		/* parse the cachedb_url */
		p1 = tmp + 1;
		PARSE_TOKEN(p1, p2, cachedb_url, CACHEDB_URL_STR, CACHEDB_URL_LEN);
		/* parse the table name */
		p1 = tmp + 1;
		PARSE_TOKEN(p1, p2, table, TABLE_STR, TABLE_STR_LEN);
#undef PARSE_TOKEN

		/* parse the key column name */
		p1 = tmp + 1;
		p2 = memchr(p1, '=', parse_str.len - (p1 - parse_str.s));
		if (!p2) {
			LM_ERR("expected: '=' after %.*s\n", KEY_STR_LEN, KEY_STR);
			goto parse_err;
		}
		if (!memcmp(p1, KEY_STR, KEY_STR_LEN)) {
			if (*(p1+KEY_STR_LEN) != '=') { \
				LM_ERR("expected: '=' after %.*s\n", KEY_STR_LEN, KEY_STR);
				goto parse_err;
			}

			tmp = memchr(p2 + 1, spec_delimiter.s[0],
						parse_str.len - (p2 - parse_str.s));
			if (!tmp) /* delimiter not found, reached the end of the string to parse */
				new_entry->key.len = parse_str.len - (p2 - parse_str.s + 1);
			else
				new_entry->key.len = tmp - p2 - 1;

			if (new_entry->key.len <= 0) {
				LM_ERR("expected value of: %.*s\n", KEY_STR_LEN, KEY_STR);
				goto parse_err;
			}

			new_entry->key.s = shm_malloc(new_entry->key.len);
			memcpy(new_entry->key.s, p2 + 1, new_entry->key.len);

			if (!tmp)
				goto end_parsing;
		} else {
			LM_ERR("expected: %.*s instead of: %.*s\n", (KEY_STR_LEN), (KEY_STR), \
				KEY_STR_LEN, p1);
			goto parse_err;
		}

		/* parse the key type if present */
		p1 = tmp + 1;
		p2 = memchr(p1, '=', parse_str.len - (p1 - parse_str.s));
		if (!p2) {
			LM_ERR("expected: '='\n");
			goto parse_err;
		}
		if (!memcmp(p1, KEY_TYPE_STR, KEY_TYPE_STR_LEN)) {
			if (*(p1+KEY_TYPE_STR_LEN) != '=') { \
				LM_ERR("expected: '=' after: %.*s\n", KEY_TYPE_STR_LEN, KEY_TYPE_STR);
				goto parse_err;
			}


			tmp = memchr(p2 + 1, spec_delimiter.s[0],
						parse_str.len - (p2 - parse_str.s));
			if (!tmp)
				len = parse_str.len - (p2 - parse_str.s + 1);
			else
				len = tmp - p2 - 1;

			if (len <= 0) {
				LM_ERR("expected value of: %.*s\n", KEY_TYPE_STR_LEN, KEY_TYPE_STR);
				goto parse_err;
			}

			if (len == TYPE_STR_LEN && !memcmp(p2+1, TYPE_STR_STR, len))
				new_entry->key_type = DB_STR;
			else if (len == TYPE_INT_LEN && !memcmp(p2+1, TYPE_INT_STR, len))
				new_entry->key_type = DB_INT;
			else {
				LM_ERR("Unsupported key type: %.*s\n", len, p2+1);
				goto parse_err;
			}

			if (!tmp) /* delimiter not found, reached the end of the string to parse */
				goto end_parsing;
			else {
				p1 = tmp + 1;
				p2 = memchr(p1, '=', parse_str.len - (p1 - parse_str.s));
				if (!p2) {
					LM_ERR("expected: '='\n");
					goto parse_err;
				}
			}
		}

		/* parse the required column names if present */
		if (!memcmp(p1, COLUMNS_STR, COLUMNS_STR_LEN)) {
			if (*(p1+COLUMNS_STR_LEN) != '=') { \
				LM_ERR("expected: '=' after: %.*s\n", COLUMNS_STR_LEN, COLUMNS_STR);
				goto parse_err;
			}
			col_idx = 0;
			tmp = memchr(p2 + 1, spec_delimiter.s[0],
						parse_str.len - (p2 - parse_str.s + 1));
			/* just count how many columns there are */
			new_entry->nr_columns = 1;
			c_tmp1 = memchr(p2 + 1, columns_delimiter.s[0],
							parse_str.len - (p2 - parse_str.s + 1));
			while (c_tmp1) {
				new_entry->nr_columns++;
				c_tmp1 = memchr(c_tmp1 + 1, columns_delimiter.s[0],
								parse_str.len - (c_tmp1 - parse_str.s + 1));
			}

			if (new_entry->nr_columns > sizeof(long long) * 8) {
				LM_WARN("Too many columns, maximum number is %zu\n", sizeof(long long) * 8);
				goto parse_err;
			}
			/* allocate array of columns and actually parse */
			new_entry->columns = shm_malloc(new_entry->nr_columns * sizeof(str*));

			c_tmp1 = p2 + 1;
			c_tmp2 = memchr(p2 + 1, columns_delimiter.s[0],
						parse_str.len - (p2 - parse_str.s + 1));
			while (c_tmp2) {
				new_entry->columns[col_idx] = shm_malloc(sizeof(str));
				(*new_entry->columns[col_idx]).len = c_tmp2 - c_tmp1;
				if ((*new_entry->columns[col_idx]).len <= 0) {
					LM_ERR("expected name of column\n");
					goto parse_err;
				}
				(*new_entry->columns[col_idx]).s = shm_malloc((*new_entry->columns[col_idx]).len);
				memcpy((*new_entry->columns[col_idx]).s, c_tmp1, (*new_entry->columns[col_idx]).len);

				c_tmp1 = c_tmp2 + 1;
				c_tmp2 = memchr(c_tmp1, columns_delimiter.s[0],
							parse_str.len - (c_tmp1 - parse_str.s + 1));
				col_idx++;
			}

			new_entry->columns[col_idx] = shm_malloc(sizeof(str));
			if (!tmp)
				(*new_entry->columns[col_idx]).len = parse_str.len - (c_tmp1 - parse_str.s);
			else
				(*new_entry->columns[col_idx]).len = tmp - c_tmp1;

			if ((*new_entry->columns[col_idx]).len <= 0) {
				LM_ERR("expected name of column\n");
				goto parse_err;
			}
			(*new_entry->columns[col_idx]).s = shm_malloc((*new_entry->columns[col_idx]).len);
			memcpy((*new_entry->columns[col_idx]).s, c_tmp1, (*new_entry->columns[col_idx]).len);

			if (!tmp) /* delimiter not found, reached the end of the string to parse */
				goto end_parsing;
			else {
				p1 = tmp + 1;
				p2 = memchr(p1, '=', parse_str.len - (p1 - parse_str.s));
				if (!p2) {
					LM_ERR("expected: '='\n");
					goto parse_err;
				}
			}
		}

		/* parse on demand parameter */
		if (!memcmp(p1, ONDEMAND_STR, ONDEMAND_STR_LEN)) {
			if (*(p1+ONDEMAND_STR_LEN) != '=') { \
				LM_ERR("expected: '=' after: %.*s\n", ONDEMAND_STR_LEN, ONDEMAND_STR);
				goto parse_err;
			}
			tmp = memchr(p2 + 1, spec_delimiter.s[0],
					parse_str.len - (p2 - parse_str.s));
			str str_val;
			if (!tmp) /* delimiter not found, reached the end of the string to parse */
				str_val.len = parse_str.len - (p2 - parse_str.s + 1);
			else
				str_val.len = tmp - p2 - 1;

			if (str_val.len <= 0) {
				LM_ERR("expected value of: %.*s\n", ONDEMAND_STR_LEN, ONDEMAND_STR);
				goto parse_err;
			}
			str_val.s = p2 + 1; 
			if(str2int(&str_val, &new_entry->on_demand)) {
				LM_ERR("expected integer value for: %.*s instead of: %.*s\n",
						ONDEMAND_STR_LEN, ONDEMAND_STR, str_val.len, str_val.s);
				goto parse_err;
			}

			if (!tmp) /* delimiter not found, reached the end of the string to parse */
				goto end_parsing;
			else {
				p1 = tmp + 1;
				p2 = memchr(p1, '=', parse_str.len - (p1 - parse_str.s));
				if (!p2) {
					LM_ERR("expected: '='\n");
					goto parse_err;
				}
			}
		}

		/* parse expire parameter */
		if (!memcmp(p1, EXPIRE_STR, EXPIRE_STR_LEN)) {
			str str_val;
			str_val.len = parse_str.len - (p2 - parse_str.s + 1);
			if (str_val.len <= 0) {
				LM_ERR("expected value of: %.*s\n", EXPIRE_STR_LEN, EXPIRE_STR);
				goto parse_err;
			}
			str_val.s = p2 + 1; 
			if(str2int(&str_val, &new_entry->expire)) {
				LM_ERR("expected integer value for: %.*s instead of: %.*s\n",
						EXPIRE_STR_LEN, EXPIRE_STR, str_val.len, str_val.s);
				goto parse_err;
			}
		} else {
			LM_ERR("unknown parameter: %.*s\n",
				(int)(parse_str.len - (p1 - parse_str.s)), p1);
			goto parse_err;
		}

end_parsing:
		new_entry->next = NULL;
		if (*entry_list)
			new_entry->next = *entry_list;
		*entry_list = new_entry;

		pkg_free(parse_str_copy.s);
		return 0;
parse_err:
		if (!new_entry->id.s)
			LM_WARN("invalid cache entry specification: %.*s\n",
				parse_str.len, parse_str.s);
		else
			LM_WARN("invalid cache entry specification for id: %.*s\n",
				new_entry->id.len, new_entry->id.s);

		if (new_entry->columns) {
			for (i=0; i < new_entry->nr_columns; i++)
				if (new_entry->columns[i]) {
					if ((*new_entry->columns[i]).s)
						shm_free((*new_entry->columns[i]).s);
					shm_free(new_entry->columns[i]);
				}
			shm_free(new_entry->columns);
		}
		shm_free(new_entry);
		pkg_free(parse_str_copy.s);

	return rc;
}

/* get the column types from the sql query result */
static int get_column_types(cache_entry_t *c_entry, db_val_t *values, int nr_columns)
{
	unsigned int i;
	db_type_t val_type;

	c_entry->nr_ints = 0;
	c_entry->nr_strs = 0;
	c_entry->column_types = 0;

	for (i = 0; i < nr_columns; i++) {
		val_type = VAL_TYPE(values + i);
		switch (val_type) {
			case DB_INT:
			case DB_BIGINT:
			case DB_DOUBLE:
				c_entry->nr_ints++;
				c_entry->column_types &= ~(1LL << i);
				break;
			case DB_STRING:
			case DB_STR:
			case DB_BLOB:
				c_entry->nr_strs++;
				c_entry->column_types |= (1LL << i);
				break;
			default:
				LM_ERR("Unsupported type: %d for column: %.*s\n", val_type,
					c_entry->columns[i]->len, c_entry->columns[i]->s);
				return -1;
		}
	}

	return 0;
}

/* returns the total size of the actual value which will be stored in the cachedb*/
static unsigned int get_cdb_val_size(cache_entry_t *c_entry, db_val_t *values, int nr_columns)
{
	unsigned int i, len = 0;
	db_type_t val_type;

	/* reload version + integer values + offsets of the string values */
	len = INT_B64_ENC_LEN + c_entry->nr_ints*INT_B64_ENC_LEN + c_entry->nr_strs*INT_B64_ENC_LEN;
	/* length of the actual string values*/
	for (i = 0; i < nr_columns; i++) {
		val_type = VAL_TYPE(values + i);
		switch (val_type) {
			case DB_STRING:
				len += strlen(VAL_STRING(values + i));
				break;
			case DB_STR:
				len += VAL_STR(values + i).len;
				break;
			case DB_BLOB:
				len += VAL_BLOB(values + i).len;
				break;
			default: continue;
		}
	}

	return len;
}

static int insert_in_cachedb(cache_entry_t *c_entry, db_handlers_t *db_hdls,
			db_val_t *key, db_val_t *values, int reload_version, int nr_columns)
{
	unsigned int i, offset = 0, strs_offset = 0;
	int int_val;
	int int_key_len = 0, rc = 0;
	char int_buf[4], int_enc_buf[INT_B64_ENC_LEN];
	char *int_key_buf = NULL;
	str str_val;
	db_type_t val_type;
	str str_key = STR_NULL;
	str cdb_val;
	str cdb_key = STR_NULL;

	cdb_val.len = get_cdb_val_size(c_entry, values, nr_columns);
	cdb_val.s = pkg_malloc(cdb_val.len);
	if (!cdb_val.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}

	/* store the reload version (base64 encoded) */
	memcpy(int_buf, &reload_version, 4);
	base64encode((unsigned char *)int_enc_buf, (unsigned char *)int_buf, 4);
	memcpy(cdb_val.s, int_enc_buf, INT_B64_ENC_LEN);

	offset += INT_B64_ENC_LEN;

	/* store the integer values (base64 encoded) */
	for (i = 0; i < nr_columns; i++) {
		int_val = 0;
		val_type = VAL_TYPE(values + i);

		switch (val_type) {
			case DB_INT:
				int_val = VAL_INT(values + i);
				break;
			case DB_BIGINT:
				int_val = (int)VAL_BIGINT(values + i);
				break;
			case DB_DOUBLE:
				int_val = (int)VAL_DOUBLE(values + i);
				break;
			default: continue;
		}
		if (VAL_NULL(values + i))
			memset(int_enc_buf, 0, INT_B64_ENC_LEN);
		else {
			memcpy(int_buf, &int_val, 4);
			base64encode((unsigned char *)int_enc_buf, (unsigned char *)int_buf, 4);
		}

		memcpy(cdb_val.s + offset, int_enc_buf, INT_B64_ENC_LEN);

		offset += INT_B64_ENC_LEN;
	}

	/* store the string values and their offsets as integers (base64 encoded) */
	strs_offset = offset + c_entry->nr_strs * INT_B64_ENC_LEN;

	for (i = 0; i < nr_columns; i++) {
		val_type = VAL_TYPE(values + i);
		switch (val_type) {
			case DB_STRING:
				str_val.s = (char *)VAL_STRING(values + i);
				str_val.len = strlen(str_val.s);
				break;
			case DB_STR:
				str_val = VAL_STR(values + i);
				break;
			case DB_BLOB:
				str_val = VAL_BLOB(values + i);
				break;
			default: continue;
		}
		if (VAL_NULL(values + i))
			int_val = 0;
		else
			int_val = strs_offset;

		memcpy(int_buf, &int_val, 4);
		base64encode((unsigned char *)int_enc_buf, (unsigned char *)int_buf, 4);
		memcpy(cdb_val.s + offset, int_enc_buf, INT_B64_ENC_LEN);

		offset += INT_B64_ENC_LEN;

		memcpy(cdb_val.s + strs_offset, str_val.s, str_val.len);
		strs_offset += str_val.len;
	}

	/* make sure the key is string */
	val_type = VAL_TYPE(key);
	switch (val_type) {
		case DB_STRING:
			str_key.s = (char *)VAL_STRING(key);
			str_key.len = strlen(str_key.s);
			break;
		case DB_STR:
			str_key = VAL_STR(key);
			break;
		case DB_BLOB:
			str_key = VAL_BLOB(key);
			break;
		case DB_INT:
			int_key_buf = sint2str(VAL_INT(key), &int_key_len);
			break;
		case DB_BIGINT:
			int_val = (int)VAL_BIGINT(key);
			int_key_buf = sint2str(int_val, &int_key_len);
			break;
		case DB_DOUBLE:
			int_val = (int)VAL_DOUBLE(key);
			int_key_buf = sint2str(int_val, &int_key_len);
			break;
		default:
			LM_ERR("Unsupported type for SQL DB key column\n");
			rc = -1;
			goto out;
	}
	if (int_key_len) {
		str_key.s = int_key_buf;
		str_key.len = int_key_len;
	}

	cdb_key.len = c_entry->id.len + str_key.len;
	cdb_key.s = pkg_malloc(cdb_key.len);
	if (!cdb_key.s) {
		LM_ERR("No more pkg memory\n");
		rc = -1;
		goto out;
	}
	memcpy(cdb_key.s, c_entry->id.s, c_entry->id.len);
	memcpy(cdb_key.s + c_entry->id.len, str_key.s, str_key.len);

	if (db_hdls->cdbf.set(db_hdls->cdbcon, &cdb_key, &cdb_val, c_entry->expire) < 0) {
		LM_ERR("Failed to insert the values for key: %.*s in cachedb\n",
			str_key.len, str_key.s);
		rc = -1;
	}

out:
	pkg_free(cdb_key.s);
	pkg_free(cdb_val.s);
	return rc;
}

static db_handlers_t *db_init_test_conn(cache_entry_t *c_entry)
{
	db_handlers_t *new_db_hdls;
	str test_query_key_str = str_init(TEST_QUERY_STR);
	str cdb_test_key = str_init(CDB_TEST_KEY_STR);
	str cdb_test_val = str_init(CDB_TEST_VAL_STR);
	db_key_t query_key_col;
	db_val_t query_key_val;
	db_res_t *sql_res;
	str cachedb_res;
	unsigned int i;
	int rc;

	new_db_hdls = pkg_malloc(sizeof(db_handlers_t));
	if (!new_db_hdls) {
		LM_ERR("No more pkg memory for db handlers\n");
		return NULL;
	}
	new_db_hdls->c_entry = c_entry;
	new_db_hdls->db_con = 0;
	new_db_hdls->query_ps = NULL;
	new_db_hdls->cdbcon = 0;

	/* cachedb init and test connection */
	if (cachedb_bind_mod(&c_entry->cachedb_url, &new_db_hdls->cdbf) < 0) {
		LM_ERR("Unable to bind to a cachedb database driver for URL: %.*s\n",
			c_entry->cachedb_url.len, c_entry->cachedb_url.s);
		return NULL;
	}
	/* open a test connection */
	new_db_hdls->cdbcon = new_db_hdls->cdbf.init(&c_entry->cachedb_url);
	if (!new_db_hdls->cdbcon) {
		LM_ERR("Cannot init connection to cachedb: %.*s\n",
			c_entry->cachedb_url.len, c_entry->cachedb_url.s);
		return NULL;
	}
	/* setting and getting a test key in cachedb */
	if (new_db_hdls->cdbf.set(new_db_hdls->cdbcon, &cdb_test_key, &cdb_test_val,
		0) < 0) {
		LM_ERR("Failed to set test key in cachedb: %.*s\n",
			c_entry->cachedb_url.len, c_entry->cachedb_url.s);
		new_db_hdls->cdbf.destroy(new_db_hdls->cdbcon);
		new_db_hdls->cdbcon = 0;
		return NULL;
	}
	if (new_db_hdls->cdbf.get(new_db_hdls->cdbcon, &cdb_test_key, &cachedb_res) < 0) {
		LM_ERR("Failed to get test key from cachedb: %.*s\n",
			c_entry->cachedb_url.len, c_entry->cachedb_url.s);
		new_db_hdls->cdbf.destroy(new_db_hdls->cdbcon);
		new_db_hdls->cdbcon = 0;
		return NULL;
	}
	rc = str_strcmp(&cachedb_res, &cdb_test_val);
	pkg_free(cachedb_res.s);
	if (rc != 0) {
		LM_ERR("Inconsistent test key for cachedb: %.*s\n",
			c_entry->cachedb_url.len, c_entry->cachedb_url.s);
		new_db_hdls->cdbf.destroy(new_db_hdls->cdbcon);
		new_db_hdls->cdbcon = 0;
		return NULL;
	}

	/* SQL DB init and test connection */
	if (db_bind_mod(&c_entry->db_url, &new_db_hdls->db_funcs) < 0) {
		LM_ERR("Unable to bind to a SQL database driver for URL: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
		return NULL;
	}
	/* open a test connection */
	if ((new_db_hdls->db_con = new_db_hdls->db_funcs.init(&c_entry->db_url)) == 0) {
		LM_ERR("Cannot init connection to SQL DB: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
		return NULL;
	}

	/* verify the column names by running a test query with a bogus key */
	if (new_db_hdls->db_funcs.use_table(new_db_hdls->db_con, &c_entry->table) < 0) {
		LM_ERR("Invalid table name: %.*s\n", c_entry->table.len, c_entry->table.s);
		new_db_hdls->db_funcs.close(new_db_hdls->db_con);
		new_db_hdls->db_con = 0;
		return NULL;
	}

	VAL_NULL(&query_key_val) = 0;
	VAL_TYPE(&query_key_val) = c_entry->key_type;
	if (c_entry->key_type == DB_STR)
		VAL_STR(&query_key_val) = test_query_key_str;
	else
		VAL_INT(&query_key_val) = TEST_QUERY_INT;

	query_key_col = &c_entry->key;

	if (new_db_hdls->db_funcs.query(new_db_hdls->db_con, &query_key_col, 0,
		&query_key_val, c_entry->columns, 1, c_entry->nr_columns, 0, &sql_res) != 0) {
		LM_ERR("Failure to issuse test query to SQL DB: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
		new_db_hdls->db_funcs.close(new_db_hdls->db_con);
		new_db_hdls->db_con = 0;
		return NULL;
	}

	/* no columns specified in cache entry -> cache entire table and get column
	 * names from the sql result */
	if (!c_entry->columns) {
		c_entry->nr_columns = RES_COL_N(sql_res);
		c_entry->columns = shm_malloc(c_entry->nr_columns * sizeof(str*));
		for (i = 0; i < c_entry->nr_columns; i++) {
			c_entry->columns[i] = shm_malloc(sizeof(str));
			(*c_entry->columns[i]).len = RES_NAMES(sql_res)[i]->len;
			(*c_entry->columns[i]).s = shm_malloc((*c_entry->columns[i]).len);
			memcpy((*c_entry->columns[i]).s, RES_NAMES(sql_res)[i]->s,
				(*c_entry->columns[i]).len);
		}
	}

	new_db_hdls->db_funcs.free_result(new_db_hdls->db_con, sql_res);
	return new_db_hdls;
}

static int inc_cache_rld_vers(db_handlers_t *db_hdls, int *rld_vers)
{
	str rld_vers_key;

	rld_vers_key.len = db_hdls->c_entry->id.len + 23;
	rld_vers_key.s = pkg_malloc(rld_vers_key.len);
	if (!rld_vers_key.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(rld_vers_key.s, db_hdls->c_entry->id.s, db_hdls->c_entry->id.len);
	memcpy(rld_vers_key.s + db_hdls->c_entry->id.len, "_sql_cacher_reload_vers", 23);

	if (db_hdls->cdbf.add(db_hdls->cdbcon, &rld_vers_key, 1, 0, rld_vers) < 0) {
		LM_DBG("Failed to increment reload version integer from cachedb\n");
		pkg_free(rld_vers_key.s);
		return -1;
	}

	pkg_free(rld_vers_key.s);

	return 0;
}

static int load_entire_table(cache_entry_t *c_entry, db_handlers_t *db_hdls,
								int inc_rld_vers)
{
	db_key_t *query_cols = NULL;
	db_res_t *sql_res = NULL;
	db_row_t *row;
	db_val_t *values;
	int i;
	int reload_vers = 0;

	query_cols = pkg_malloc((c_entry->nr_columns + 1) * sizeof(db_key_t));
	if (!query_cols) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	query_cols[0] = &(c_entry->key);
	for (i=0; i < c_entry->nr_columns; i++)
		query_cols[i+1] = &((*c_entry->columns[i]));

	/* query the entire table */
	if (db_hdls->db_funcs.use_table(db_hdls->db_con, &c_entry->table) < 0) {
		LM_ERR("Invalid table name: %.*s\n", c_entry->table.len, c_entry->table.s);
		db_hdls->db_funcs.close(db_hdls->db_con);
		db_hdls->db_con = 0;
		pkg_free(query_cols);
		return -1;
	}
	if (DB_CAPABILITY(db_hdls->db_funcs, DB_CAP_FETCH)) {
		if (db_hdls->db_funcs.query(db_hdls->db_con, NULL, 0, NULL,
						query_cols, 0, c_entry->nr_columns + 1, 0, 0) != 0) {
			LM_ERR("Failure to issue query to SQL DB: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
			pkg_free(query_cols);
			goto error;
		}

		if (db_hdls->db_funcs.fetch_result(db_hdls->db_con,&sql_res,fetch_nr_rows)<0) {
			LM_ERR("Error fetching rows from SQL DB: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
			pkg_free(query_cols);
			goto error;
		}
	} else {
		if (db_hdls->db_funcs.query(db_hdls->db_con, NULL, 0, NULL,
						query_cols, 0, c_entry->nr_columns + 1, 0, &sql_res) != 0) {
			LM_ERR("Failure to issue query to SQL DB: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
			pkg_free(query_cols);
			goto error;
		}
	}

	pkg_free(query_cols);

	lock_start_write(db_hdls->c_entry->ref_lock);

	if (inc_rld_vers && inc_cache_rld_vers(db_hdls, &reload_vers) < 0) {
		lock_stop_write(db_hdls->c_entry->ref_lock);
		goto error;
	}

	/* anything loaded ? if not, we can do a quick exit here */
	if (RES_ROW_N(sql_res) == 0) {
		lock_stop_write(db_hdls->c_entry->ref_lock);
		db_hdls->db_funcs.free_result(db_hdls->db_con, sql_res);
		return 0;
	}

	row = RES_ROWS(sql_res);
	values = ROW_VALUES(row);
	if (get_column_types(c_entry, values + 1, ROW_N(row) - 1) < 0) {
		lock_stop_write(db_hdls->c_entry->ref_lock);
		goto error;
	}

	/* load the rows into the cahchedb */
	do {
		for (i=0; i < RES_ROW_N(sql_res); i++) {
			row = RES_ROWS(sql_res) + i;
			values = ROW_VALUES(row);
			if (!VAL_NULL(values))
				if (insert_in_cachedb(c_entry, db_hdls, values ,values + 1,
					reload_vers, ROW_N(row) - 1) < 0) {
					lock_stop_write(db_hdls->c_entry->ref_lock);
					return -1;
				}
		}

		if (DB_CAPABILITY(db_hdls->db_funcs, DB_CAP_FETCH)) {
			if (db_hdls->db_funcs.fetch_result(db_hdls->db_con,&sql_res,fetch_nr_rows)<0) {
				LM_ERR("Error fetching rows (1) from SQL DB: %.*s\n",
					c_entry->db_url.len, c_entry->db_url.s);
				lock_stop_write(db_hdls->c_entry->ref_lock);
				goto error;
			}
		} else {
			break;
		}
	} while (RES_ROW_N(sql_res) > 0);

	lock_stop_write(db_hdls->c_entry->ref_lock);

	db_hdls->db_funcs.free_result(db_hdls->db_con, sql_res);
	return 0;

error:
	if (sql_res)
		db_hdls->db_funcs.free_result(db_hdls->db_con, sql_res);
	return -1;
}

/*  return:
 *  0 - succes
 * -1 - error
 * -2 - not found in sql db
 */
static int load_key(cache_entry_t *c_entry, db_handlers_t *db_hdls, str key,
				db_val_t **values, db_res_t **sql_res, int rld_vers)
{
	db_key_t key_col;
	db_row_t *row;
	db_val_t key_val;
	str src_key, null_val;

	src_key.len = c_entry->id.len + key.len;
	src_key.s = pkg_malloc(src_key.len);
	if (!src_key.s) {
		LM_ERR("No more shm memory\n");
		return -1;
	}
	memcpy(src_key.s, c_entry->id.s, c_entry->id.len);
	memcpy(src_key.s + c_entry->id.len, key.s, key.len);

	key_col = &(c_entry->key);

	VAL_NULL(&key_val) = 0;
	VAL_TYPE(&key_val) = c_entry->key_type;
	if (c_entry->key_type == DB_STR)
		VAL_STR(&key_val) = key;
	else if (str2sint(&key, &VAL_INT(&key_val)) < 0) {
		LM_ERR("Failed to convert key value to integer\n");
		goto out_error;
	}

	if (db_hdls->db_funcs.use_table(db_hdls->db_con, &c_entry->table) < 0) {
		LM_ERR("Invalid table name: %.*s\n", c_entry->table.len, c_entry->table.s);
		db_hdls->db_funcs.close(db_hdls->db_con);
		db_hdls->db_con = 0;
		goto out_error;
	}

	CON_PS_REFERENCE(db_hdls->db_con) = &db_hdls->query_ps;
	if (db_hdls->db_funcs.query(db_hdls->db_con,
		&key_col, 0, &key_val, c_entry->columns, 1,
		c_entry->nr_columns, 0, sql_res) != 0) {
		LM_ERR("Failure to issue query to SQL DB: %.*s\n",
			c_entry->db_url.len, c_entry->db_url.s);
		goto sql_error;
	}

	if (RES_ROW_N(*sql_res) == 0) {
		LM_DBG("key %.*s not found in SQL db\n", key.len, key.s);
		null_val.len = 0;
		null_val.s = NULL;
		if (db_hdls->cdbf.set(db_hdls->cdbcon, &src_key, &null_val, c_entry->expire) < 0) {
			LM_ERR("Failed to insert null in cachedb\n");
			goto sql_error;
		}

		pkg_free(src_key.s);
		db_hdls->db_funcs.free_result(db_hdls->db_con, *sql_res);
		return -2;

	} else if (RES_ROW_N(*sql_res) > 1) {
		LM_ERR("SQL query returned multiple rows\n");
		goto sql_error;
	}

	row = RES_ROWS(*sql_res);
	*values = ROW_VALUES(row);

	if (c_entry->nr_ints + c_entry->nr_strs == 0 &&
		get_column_types(c_entry, *values, ROW_N(row)) < 0)
		goto sql_error;

	if (insert_in_cachedb(c_entry, db_hdls, &key_val, *values, rld_vers, ROW_N(row)) < 0)
		goto sql_error;

	pkg_free(src_key.s);
	return 0;

sql_error:
	if (*sql_res)
		db_hdls->db_funcs.free_result(db_hdls->db_con, *sql_res);
out_error:
	pkg_free(src_key.s);
	return -1;
}

static int get_rld_vers_from_cache(cache_entry_t *c_entry, db_handlers_t *db_hdls)
{
	str rld_vers_key;
	int rld_vers = -1;

	rld_vers_key.len = c_entry->id.len + 23;
	rld_vers_key.s = pkg_malloc(rld_vers_key.len);
	if (!rld_vers_key.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(rld_vers_key.s, c_entry->id.s, c_entry->id.len);
	memcpy(rld_vers_key.s + c_entry->id.len, "_sql_cacher_reload_vers", 23);

	if (db_hdls->cdbf.get_counter(db_hdls->cdbcon, &rld_vers_key, &rld_vers) < 0) {
		LM_ERR("Failed to get reload version integer from cachedb\n");
		pkg_free(rld_vers_key.s);
		return -1;
	}

	pkg_free(rld_vers_key.s);

	return rld_vers;
}

void reload_timer(unsigned int ticks, void *param)
{
	db_handlers_t *db_hdls;

	for (db_hdls = db_hdls_list; db_hdls; db_hdls = db_hdls->next) {
		if (db_hdls->c_entry->on_demand)
			continue;

		if (load_entire_table(db_hdls->c_entry, db_hdls, 1) < 0)
			LM_ERR("Failed to reload table %.*s\n", db_hdls->c_entry->table.len,
				db_hdls->c_entry->table.s);
	}
}

static mi_item_t *mi_reload(const mi_params_t *params, str *key)
{
	db_handlers_t *db_hdls;
	db_val_t *values;
	db_res_t *sql_res = NULL;
	struct queried_key *it;
	str entry_id, src_key;
	int rld_vers, rc;

	if (get_mi_string_param(params, "id", &entry_id.s, &entry_id.len) < 0)
		return init_mi_param_error();

	for (db_hdls = db_hdls_list; db_hdls; db_hdls = db_hdls->next)
		if (!str_strcmp(&db_hdls->c_entry->id, &entry_id))
			break;
	if (!db_hdls) {
		LM_ERR("Entry %.*s not found\n", entry_id.len, entry_id.s);
		return init_mi_error(500, MI_SSTR("ERROR Cache entry not found"));
	}

	if (db_hdls->c_entry->on_demand) {
		if (key) {
			src_key.len = db_hdls->c_entry->id.len + key->len;
			src_key.s = pkg_malloc(src_key.len);
			if (!src_key.s) {
				LM_ERR("No more pkg memory\n");
				return NULL;
			}
			memcpy(src_key.s, db_hdls->c_entry->id.s, db_hdls->c_entry->id.len);
			memcpy(src_key.s + db_hdls->c_entry->id.len, key->s, key->len);

			lock_get(queries_lock);

			for (it = *queries_in_progress; it; it = it->next)
				if (!str_strcmp(&it->key, &src_key))
					break;
			pkg_free(src_key.s);
			if (it) {	/* key is in list */
				lock_release(queries_lock);
				lock_get(it->wait_sql_query);
			}

			if ((rld_vers = get_rld_vers_from_cache(db_hdls->c_entry, db_hdls)) < 0) {
				LM_ERR("Unable to fetch reload version counter\n");
				if (it)
					lock_release(it->wait_sql_query);
				else
					lock_release(queries_lock);

				return init_mi_error(500, MI_SSTR("ERROR Reloading key from SQL"
													" database\n"));
			}

			rc = load_key(db_hdls->c_entry, db_hdls, *key, &values, &sql_res, rld_vers);
			if (rc == 0)
				db_hdls->db_funcs.free_result(db_hdls->db_con, sql_res);

			if (it)
				lock_release(it->wait_sql_query);
			else
				lock_release(queries_lock);

			if (rc == -1)
				return init_mi_error(500, MI_SSTR("ERROR Reloading key from SQL"
													" database\n"));
			else if (rc == -2)
				return init_mi_error(500, MI_SSTR("ERROR Reloading key from SQL"
													"database, key not found\n"));
		} else {
			/* 'invalidate' all keys by increasing the reload version counter */
			if (inc_cache_rld_vers(db_hdls, &rld_vers) < 0)
				return init_mi_error(500, MI_SSTR("ERROR Invalidating cache"));
		}
	} else {
		if (load_entire_table(db_hdls->c_entry, db_hdls, 1) < 0) {
			LM_DBG("Failed to reload table\n");
			return init_mi_error(500, MI_SSTR("ERROR Reloading SQL database"));
		}
	}

	return init_mi_result_ok();
}

static mi_response_t *mi_reload_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_reload(params, NULL);
}

static mi_response_t *mi_reload_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str key;

	if (get_mi_string_param(params, "key", &key.s, &key.len) < 0)
		return init_mi_param_error();

	return mi_reload(params, &key);
}

static int init_rld_vers_key(cache_entry_t *c_entry, db_handlers_t *db_hdls)
{
	str rld_vers_key;
	int reload_version = -1;

	/* set up reload version counter for this entry in cachedb */
	rld_vers_key.len = c_entry->id.len + 23;
	rld_vers_key.s = pkg_malloc(rld_vers_key.len);
	if (!rld_vers_key.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(rld_vers_key.s, c_entry->id.s, c_entry->id.len);
	memcpy(rld_vers_key.s + c_entry->id.len, "_sql_cacher_reload_vers", 23);

	db_hdls->cdbf.add(db_hdls->cdbcon, &rld_vers_key, 1, 0, &reload_version);
	db_hdls->cdbf.sub(db_hdls->cdbcon, &rld_vers_key, 1, 0, &reload_version);

	pkg_free(rld_vers_key.s);

	if (reload_version != 0)
		return -1;

	return 0;
}

static void cache_init_load(int sender, void *param)
{
	db_handlers_t *db_hdls;

	for (db_hdls = db_hdls_list; db_hdls; db_hdls = db_hdls->next) {

		if (init_rld_vers_key(db_hdls->c_entry, db_hdls) < 0) {
			LM_ERR("Failed to set up reload version counter in cahchedb for "
				"entry: %.*s\n", db_hdls->c_entry->id.len, db_hdls->c_entry->id.s);
			return;
		}

		/* cache the entire table in full caching mode */
		if (!db_hdls->c_entry->on_demand &&
			load_entire_table(db_hdls->c_entry, db_hdls, 0) < 0) {
			LM_ERR("Failed to cache the entire table: %s\n", db_hdls->c_entry->table.s);
			continue;
		} else
			LM_DBG("Cached table: %.*s\n", db_hdls->c_entry->table.len,
				db_hdls->c_entry->table.s);

	}
}

static int mod_init(void)
{
	cache_entry_t *c_entry;
	db_handlers_t *db_hdls;
	char use_timer = 0;

	if (full_caching_expire <= 0) {
		full_caching_expire = DEFAULT_FULL_CACHING_EXPIRE;
		LM_WARN("Invalid full_caching_expire parameter, "
			"setting default value: %d sec\n", DEFAULT_FULL_CACHING_EXPIRE);
	}
	if (reload_interval <= 0 || reload_interval >= full_caching_expire) {
		reload_interval = DEFAULT_RELOAD_INTERVAL;
		LM_WARN("Invalid reload_interval parameter, "
			"setting default value: %d sec\n", DEFAULT_RELOAD_INTERVAL);
	}
	if(!entry_list){
		entry_list =  shm_malloc(sizeof(cache_entry_t*));
		if (!entry_list) {
			LM_ERR("No more memory for cache entries list\n");
			return -1;
		}
		*entry_list = NULL;
	}
	queries_in_progress =  shm_malloc(sizeof(struct queried_key *));
	if (!queries_in_progress) {
		LM_ERR("No more memory for queries_in_progress list\n");
		return -1;
	}
	*queries_in_progress = NULL;

	queries_lock = lock_alloc();
	if (!queries_lock) {
		LM_ERR("No more memory for queries_lock\n");
		return -1;
	}
	if (!lock_init(queries_lock)) {
		LM_ERR("Failed to init queries_lock\n");
		return -1;
	}

	c_entry = *entry_list;
	while (c_entry) {
		if ((db_hdls = db_init_test_conn(c_entry)) == NULL) {
			LM_ERR("Failed to validate db conns for cache entry\n");
			return -1;
		}

		if (!c_entry->on_demand) {
			use_timer = 1;
			c_entry->expire = full_caching_expire;
			c_entry->ref_lock = lock_init_rw();
			if (!c_entry->ref_lock) {
				LM_ERR("Failed to init readers-writers lock\n");
				continue;
			}
		}

		db_hdls->db_funcs.close(db_hdls->db_con);
		db_hdls->db_con = 0;
		db_hdls->cdbf.destroy(db_hdls->cdbcon);
		db_hdls->cdbcon = 0;
		db_hdls->next = db_hdls_list;
		db_hdls_list = db_hdls;

		c_entry = c_entry->next;
	}

	if (use_timer && register_timer("sql_cacher_reload-timer", reload_timer, NULL,
		full_caching_expire - reload_interval, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("failed to register timer\n");
		return -1;
	}

	return 0;
}

static int child_init(int rank)
{
	db_handlers_t *db_hdls;

	for (db_hdls = db_hdls_list; db_hdls; db_hdls = db_hdls->next) {
		db_hdls->cdbcon = db_hdls->cdbf.init(&db_hdls->c_entry->cachedb_url);
		if (!db_hdls->cdbcon) {
			LM_ERR("Cannot connect to cachedb from child\n");
			return -1;
		}

		if ((db_hdls->db_con = db_hdls->db_funcs.init(&db_hdls->c_entry->db_url)) == 0) {
			LM_ERR("Cannot connect to SQL DB from child\n");
			return -1;
		}
	}

	/* perform full caching load in the same process but after child_init is done */
	if ((rank == 1) && ipc_send_rpc(process_no, cache_init_load, NULL) < 0) {
		LM_ERR("Failed to RPC full caching load\n");
		return -1;
	}

	return 0;
}

/*	return:
 *	1 - if found
 * -2 - if not found
 * -1 - if error
 */
static int cdb_fetch(pv_name_fix_t *pv_name, str *cdb_res, int *entry_rld_vers)
{
	str cdb_key;
	int rc = -1;

	cdb_key.len = pv_name->id.len + pv_name->key.len;
	cdb_key.s = pkg_malloc(cdb_key.len);
	if (!cdb_key.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(cdb_key.s, pv_name->id.s, pv_name->id.len);
	memcpy(cdb_key.s + pv_name->id.len, pv_name->key.s, pv_name->key.len);

	*entry_rld_vers = get_rld_vers_from_cache(pv_name->c_entry, pv_name->db_hdls);
	if (*entry_rld_vers < 0)
		goto out_free;

	rc = pv_name->db_hdls->cdbf.get(pv_name->db_hdls->cdbcon, &cdb_key, cdb_res);

out_free:
	pkg_free(cdb_key.s);
	return rc;
}

/*  return:
 *  0 - succes
 *  1 - succes, null value in db
 *  2 - error
 *  3 - does not match reload version (old value)
 */
static int cdb_val_decode(pv_name_fix_t *pv_name, str *cdb_val, int reload_version,
							str *str_res, int *int_res)
{
	int int_val, next_str_off, i, rc;
	char int_buf[4];
	const char zeroes[INT_B64_ENC_LEN] = {0};

	if (pv_name->col_offset == -1) {
		LM_WARN("Unknown column %.*s\n", pv_name->col.len, pv_name->col.s);
		return 2;
	}

	/* decode the reload version */
	if (base64decode((unsigned char *)int_buf,
		(unsigned char *)(cdb_val->s), INT_B64_ENC_LEN) != 4)
		goto error;
	memcpy(&int_val, int_buf, 4);

	if (reload_version != int_val)
		return 3;

	/* null integer value in db */
	if (!memcmp(cdb_val->s + pv_name->col_offset, zeroes, INT_B64_ENC_LEN))
		return 1;

	/* decode the integer value or the offset of the string value */
	if (base64decode((unsigned char *)int_buf,
		(unsigned char *)(cdb_val->s + pv_name->col_offset), INT_B64_ENC_LEN) != 4)
		goto error;
	memcpy(&int_val, int_buf, 4);

	if (is_str_column(pv_name)) {
		/* null string value in db */
		if (int_val == 0)
			return 1;

		str_res->s = cdb_val->s + int_val;
		if (pv_name->last_str)
			str_res->len = cdb_val->len - int_val;
		else {
			/* calculate the length of the current string using the offset of the next not null string */
			i = 1;
			do {
				rc = base64decode((unsigned char *)int_buf, (unsigned char *)(cdb_val->s +
					pv_name->col_offset + i * INT_B64_ENC_LEN), INT_B64_ENC_LEN);
				if (rc != 4)
					goto error;
				memcpy(&next_str_off, int_buf, 4);
				i++;
			} while (next_str_off == 0 && pv_name->col_offset + i*INT_B64_ENC_LEN <
						(pv_name->c_entry->nr_columns + 1) * INT_B64_ENC_LEN);

			if (next_str_off == 0)
				str_res->len = cdb_val->len - int_val;
			else
				str_res->len = next_str_off - int_val;
		}
	} else {
		*int_res = int_val;
	}

	return 0;
error:
	LM_ERR("Failed to decode value: %.*s from cachedb\n", cdb_val->len, cdb_val->s);
	return 2;
}

static void optimize_cdb_decode(pv_name_fix_t *pv_name)
{
	int i, j, prev_cols;
	char col_type1, col_type2;

	for (i = 0; i < pv_name->c_entry->nr_columns; i++) {
		if (!str_strcmp(pv_name->c_entry->columns[i], &pv_name->col)) {
			pv_name->col_nr = i;

			prev_cols = 0;
			col_type1 = ((pv_name->c_entry->column_types & (1LL << i)) != 0);
			for (j = 0; j < i; j++) {
				col_type2 = ((pv_name->c_entry->column_types & (1LL << j)) != 0);
				if (col_type1 == col_type2)
					prev_cols++;
			}
			if (col_type1) {
				pv_name->col_offset = INT_B64_ENC_LEN +
					pv_name->c_entry->nr_ints*INT_B64_ENC_LEN + prev_cols*INT_B64_ENC_LEN;
				if (prev_cols == pv_name->c_entry->nr_strs - 1)
					pv_name->last_str = 1;
				else
					pv_name->last_str = 0;
			} else
				pv_name->col_offset = INT_B64_ENC_LEN + prev_cols*INT_B64_ENC_LEN;

			break;
		}
	}
	if (i == pv_name->c_entry->nr_columns)
		pv_name->col_offset = -1;
}

static void unlink_from_query_list(struct queried_key *pos)
{
	struct queried_key *prev;

	if (pos == *queries_in_progress) {
		*queries_in_progress = (*queries_in_progress)->next;
		return;
	}

	for (prev = *queries_in_progress; prev->next != pos; prev = prev->next) ;

	prev->next = pos->next;
}

/*  return:
 *  0 - succes => if str column, @str_res->s must be pkg_free()'d
 *  1 - succes, null value in db
 * -1 - error
 * -2 - not found in sql db
 *  2 - error in cdb_val_decode()
 *  3 - does not match reload version (old value)
 */
static int on_demand_load(pv_name_fix_t *pv_name, str *str_res, int *int_res,
							int rld_vers)
{
	struct queried_key *it, *tmp, *new_key;
	str src_key, st;
	str cdb_res;
	db_res_t *sql_res = NULL;
	db_val_t *values;
	db_type_t val_type;
	int i, rc;
	int rld_vers_retry;

	for (i = 0; i < pv_name->c_entry->nr_columns; i++)
		if (!str_strcmp(pv_name->c_entry->columns[i], &pv_name->col)) {
			pv_name->col_nr = i;
			break;
		}
	if (i == pv_name->c_entry->nr_columns) {
		LM_WARN("Unknown column %.*s\n", pv_name->col.len, pv_name->col.s);
		return -1;
	}

	src_key.len = pv_name->id.len + pv_name->key.len;
	src_key.s = shm_malloc(src_key.len);
	if (!src_key.s) {
		LM_ERR("No more shm memory\n");
		return -1;
	}
	memcpy(src_key.s, pv_name->id.s, pv_name->id.len);
	memcpy(src_key.s + pv_name->id.len, pv_name->key.s, pv_name->key.len);

	lock_get(queries_lock);

	for (it = *queries_in_progress; it; it = it->next) {
		if (str_strcmp(&it->key, &src_key))
			continue;

		it->nr_waiting_procs++;  /* key is in list! */
		lock_release(queries_lock);
		/* wait for the query to complete */
		lock_get(it->wait_sql_query);
		lock_get(queries_lock);
		shm_free(src_key.s);
		if (it->nr_waiting_procs == 1) {
			lock_release(it->wait_sql_query);
			lock_destroy(it->wait_sql_query);
			lock_dealloc(it->wait_sql_query);
			/* if this is the last process waiting, delete key from list */
			unlink_from_query_list(it);
			tmp = it;
			it = it->next;
			shm_free(tmp->key.s);
			shm_free(tmp);
		} else if (it->nr_waiting_procs > 1) {
			it->nr_waiting_procs--;
			lock_release(it->wait_sql_query);
		}
		lock_release(queries_lock);

		/* reload key from cachedb */
		if (cdb_fetch(pv_name, &cdb_res, &rld_vers_retry) < 0) {
			LM_ERR("Error on retrying fetch from cachedb\n");
			return -1;
		}
		if (cdb_res.len == 0 || !cdb_res.s) {
			LM_ERR("Cache fetch result should not be empty\n");
			pkg_free(cdb_res.s);
			return -1;
		}

		if (pv_name->last_str == -1)
			optimize_cdb_decode(pv_name);
		rc = cdb_val_decode(pv_name, &cdb_res, rld_vers_retry, str_res, int_res);
		if (is_str_column(pv_name) && rc == 0) {
			if (pkg_str_dup(&st, str_res) != 0) {
				LM_ERR("oom\n");
				rc = -1;
				memset(str_res, 0, sizeof *str_res);
			} else {
				*str_res = st;
			}
		}

		pkg_free(cdb_res.s);

		return rc;
	}

	/* key not found in list -> insert it */
	new_key = shm_malloc(sizeof(struct queried_key));
	if (!new_key) {
		LM_ERR("No more shm memory\n");
		lock_release(queries_lock);
		return -1;
	}
	new_key->key = src_key;
	new_key->nr_waiting_procs = 0;
	new_key->wait_sql_query = lock_alloc();
	if (!new_key->wait_sql_query) {
		LM_ERR("No more memory for wait_sql_query lock\n");
		shm_free(new_key);
		lock_release(queries_lock);
		return -1;
	}
	if (!lock_init(new_key->wait_sql_query)) {
		LM_ERR("Failed to init wait_sql_query lock\n");
		lock_dealloc(new_key->wait_sql_query);
		shm_free(new_key);
		lock_release(queries_lock);
		return -1;
	}

	new_key->next = *queries_in_progress;
	*queries_in_progress = new_key;

	lock_get(new_key->wait_sql_query);

	lock_release(queries_lock);

	rc = load_key(pv_name->c_entry, pv_name->db_hdls, pv_name->key, &values,
			&sql_res, rld_vers);

	lock_get(queries_lock);

	lock_release(new_key->wait_sql_query);

	/* delete key from list */
	if (new_key->nr_waiting_procs == 0) {
		lock_destroy(new_key->wait_sql_query);
		lock_dealloc(new_key->wait_sql_query);
		unlink_from_query_list(new_key);
		shm_free(new_key->key.s);
		shm_free(new_key);
	}

	lock_release(queries_lock);

	if (rc < 0)
		return rc;

	if (VAL_NULL(values + pv_name->col_nr)) {
		rc = 1;
		goto out_free_res;
	}

	rc = 0;
	val_type = VAL_TYPE(values + pv_name->col_nr);
	switch (val_type) {
		case DB_STRING:
			st.s = (char *)VAL_STRING(values + pv_name->col_nr);
			st.len = strlen(st.s);
			if (pkg_str_dup(str_res, &st) != 0) {
				LM_ERR("oom\n");
				rc = -1;
				goto out_free_res;
			}
			break;
		case DB_STR:
			if (pkg_str_dup(str_res, &(VAL_STR(values + pv_name->col_nr))) != 0) {
				LM_ERR("oom\n");
				rc = -1;
				goto out_free_res;
			}
			break;
		case DB_BLOB:
			if (pkg_str_dup(str_res, &(VAL_BLOB(values + pv_name->col_nr))) != 0) {
				LM_ERR("oom\n");
				rc = -1;
				goto out_free_res;
			}
			break;
		case DB_INT:
			*int_res = VAL_INT(values + pv_name->col_nr);
			break;
		case DB_BIGINT:
			*int_res = (int)VAL_BIGINT(values + pv_name->col_nr);
			break;
		case DB_DOUBLE:
			*int_res = (int)VAL_DOUBLE(values + pv_name->col_nr);
			break;
		default:
			LM_ERR("Unsupported type for SQL column\n");
			rc = -1;
			goto out_free_res;
	}

out_free_res:
	pv_name->db_hdls->db_funcs.free_result(pv_name->db_hdls->db_con, sql_res);
	return rc;
}

static int parse_pv_name_s(pv_name_fix_t *pv_name, str *name_s)
{
	char *p1 = NULL, *p2 = NULL;
	char last;

#define PARSE_TOKEN(_ptr1, _ptr2, type, delim) \
	do { \
		(_ptr2) = memchr((_ptr1), (delim), \
					name_s->len - ((_ptr1) - name_s->s) + 1); \
		if (!(_ptr2)) { \
			LM_ERR("Invalid syntax for pvar name\n"); \
			return -1; \
		} \
		int _prev_len = pv_name->type.len; \
		pv_name->type.len = (_ptr2) - (_ptr1); \
		if (!pv_name->type.s) { \
			pv_name->type.s = pkg_malloc(pv_name->type.len); \
			if (!pv_name->type.s) { \
				LM_ERR("No more pkg memory\n"); \
				return -1; \
			} \
			memcpy(pv_name->type.s, (_ptr1), pv_name->type.len); \
		} else if (memcmp(pv_name->type.s, (_ptr1), pv_name->type.len)) { \
			if (_prev_len != pv_name->type.len) { \
				pv_name->type.s = pkg_realloc(pv_name->type.s, pv_name->type.len); \
				if (!pv_name->type.s) { \
					LM_ERR("No more pkg memory\n"); \
					return -1; \
				} \
			} \
			memcpy(pv_name->type.s, (_ptr1), pv_name->type.len); \
		} \
	} while (0)

		last = name_s->s[name_s->len];
		p1 = name_s->s;
		PARSE_TOKEN(p1, p2, id, pvar_delimiter.s[0]);
		p1 = p2 + 1;
		PARSE_TOKEN(p1, p2, col, pvar_delimiter.s[0]);
		p1 = p2 + 1;
		PARSE_TOKEN(p1, p2, key, last);

#undef PARSE_TOKEN

	return 0;
}

int pv_parse_name(pv_spec_p sp, str *in)
{
	pv_elem_t *model = NULL, *it;
	pv_name_fix_t *pv_name;

	if (!in || !in->s || !sp)
		return -1;

	pv_name = pkg_malloc(sizeof(pv_name_fix_t));
	if (!pv_name) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memset(pv_name, 0, sizeof *pv_name);

	pv_name->col_offset = -1;
	pv_name->last_str = -1;

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void *)pv_name;

	if (pv_parse_format(in, &model) < 0) {
		LM_ERR("Wrong format for pvar name\n");
		return -1;
	}

	for (it = model; it; it = it->next) {
		if (it->spec.type != PVT_NONE)
			break;
	}
	if (it) { /* if there are variables in the name, parse later */
		pv_name->pv_elem_list = model;
	} else {
		if (parse_pv_name_s(pv_name, &(model->text)) < 0)
			return -1;
	}

	return 0;
}

static str valbuff[PV_VAL_BUF_NO];
int pv_get_sql_cached_value(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	pv_name_fix_t *pv_name;
	str name_s;
	db_handlers_t *it_db;
	int rc, rc2, int_res = 0, l = 0;
	char *ch = NULL;
	str str_res = {NULL, 0}, cdb_res = {NULL, 0};
	static int buf_itr = 0;
	int entry_rld_vers, free_str_res = 0;

	if (!param || param->pvn.type != PV_NAME_PVAR ||
		!param->pvn.u.dname) {
		LM_CRIT("Bad pvar get function parameters\n");
		return -1;
	}

	pv_name = (pv_name_fix_t *)param->pvn.u.dname;
	if (!pv_name) {
		LM_ERR("Unable to get name struct from dname\n");
		return -1;
	}

	if (pv_name->pv_elem_list) {
		/* there are variables in the name which need to be evaluated, then parse */
		if (pv_printf_s(msg, pv_name->pv_elem_list, &name_s) != 0 ||
			name_s.len == 0 || !name_s.s) {
			LM_ERR("Unable to evaluate variables in pv name\n");
			return pv_get_null(msg, param, res);
		}
		if (parse_pv_name_s(pv_name, &name_s) < 0)
			return pv_get_null(msg, param, res);
	}

	if (!pv_name->c_entry) {
		for (it_db = db_hdls_list; it_db; it_db = it_db->next)
			if (!str_strcmp(&it_db->c_entry->id, &pv_name->id)) {
				pv_name->c_entry = it_db->c_entry;
				pv_name->db_hdls = it_db;
				break;
			}
		if (!it_db) {
			LM_WARN("Unknown caching id %.*s\n", pv_name->id.len, pv_name->id.s);
			return pv_get_null(msg, param, res);
		}
	}

	if (!pv_name->c_entry->on_demand)
		lock_start_read(pv_name->c_entry->ref_lock);

	rc = cdb_fetch(pv_name, &cdb_res, &entry_rld_vers);
	if (rc == -1) {
		LM_ERR("Error fetching from cachedb\n");
		if (!pv_name->c_entry->on_demand)
			lock_stop_read(pv_name->c_entry->ref_lock);
		return pv_get_null(msg, param, res);
	}

	if (!pv_name->c_entry->on_demand) {
		if (rc == -2) {
			LM_DBG("key: %.*s not found\n", pv_name->key.len, pv_name->key.s);
			lock_stop_read(pv_name->c_entry->ref_lock);
			return pv_get_null(msg, param, res);
		} else {
			if (cdb_res.len == 0 || !cdb_res.s) {
				LM_ERR("Cache fetch result should not be empty\n");
				lock_stop_read(pv_name->c_entry->ref_lock);
				pkg_free(cdb_res.s);
				return pv_get_null(msg, param, res);
			}

			if (pv_name->last_str == -1)
				optimize_cdb_decode(pv_name);
			rc2 = cdb_val_decode(pv_name, &cdb_res, entry_rld_vers, &str_res,
									&int_res);

			lock_stop_read(pv_name->c_entry->ref_lock);

			if (rc2 == 2)
				goto out_free_null;
			if (rc2 == 3) {
				LM_DBG("key: %.*s not found\n", pv_name->key.len, pv_name->key.s);
				goto out_free_null;
			}
			if (rc2 == 1) {
				LM_DBG("NULL value in SQL db\n");
				goto out_free_null;
			}
		}
	} else {
		if (rc == -2) {  /* key not found in cache */
			rc2 = on_demand_load(pv_name, &str_res, &int_res, entry_rld_vers);
			if (rc2 == 1) {
				LM_DBG("NULL value in SQL db\n");
				goto out_free_null;
			} else if (rc2 != 0)
				goto out_free_null;

			free_str_res = 1;
		} else {
			if (cdb_res.len == 0 || !cdb_res.s) {
				LM_DBG("key: %.*s not found in SQL db\n", pv_name->key.len, pv_name->key.s);
				pkg_free(cdb_res.s);
				return pv_get_null(msg, param, res);
			}

			if (pv_name->last_str == -1)
				optimize_cdb_decode(pv_name);
			rc2 = cdb_val_decode(pv_name, &cdb_res, entry_rld_vers, &str_res,
									&int_res);
			if (rc2 == 2)
				goto out_free_null;
			if (rc2 == 1) {
				LM_DBG("NULL value in SQL db\n");
				goto out_free_null;
			}
			if (rc2 == 3) {
				/* old version(due to reload) so the key should be loaded again */
				rc2 = on_demand_load(pv_name, &str_res, &int_res, entry_rld_vers);
				if (rc2 == 1) {
					LM_DBG("NULL value in SQL db\n");
					goto out_free_null;
				} else if (rc2 != 0)
					goto out_free_null;

				free_str_res = 1;
			}
		}
	}

	if (is_str_column(pv_name)) {
		if (pkg_str_extend(&valbuff[buf_itr], str_res.len) != 0) {
			LM_ERR("failed to alloc buffer\n");
			if (free_str_res)
				pkg_free(str_res.s);
			goto out_free_null;
		}

		memcpy(valbuff[buf_itr].s, str_res.s, str_res.len);

		if (free_str_res)
			pkg_free(str_res.s);

		res->flags = PV_VAL_STR;
		res->rs.s = valbuff[buf_itr].s;
		res->rs.len = str_res.len;

		buf_itr = (buf_itr + 1) % PV_VAL_BUF_NO;
	} else {
		res->ri = int_res;
		ch = int2str(int_res, &l);
		res->rs.s = ch;
		res->rs.len = l;
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}

	if (cdb_res.s)
		pkg_free(cdb_res.s);
	return 0;

out_free_null:
	if (cdb_res.s)
		pkg_free(cdb_res.s);
	return pv_get_null(msg, param, res);
}

static void free_c_entry(cache_entry_t *c)
{
	int i;

	shm_free(c->id.s);
	shm_free(c->db_url.s);
	shm_free(c->cachedb_url.s);
	shm_free(c->table.s);
	shm_free(c->key.s);
	for (i = 0; i < c->nr_columns; i++) {
		shm_free((*c->columns[i]).s);
		shm_free(c->columns[i]);
	}
	shm_free(c->columns);
	lock_destroy_rw(c->ref_lock);
	shm_free(c);
}

static void destroy(void)
{
	struct queried_key *q_it, *q_tmp;
	cache_entry_t *c_it, *c_tmp;

	q_it = *queries_in_progress;
	while (q_it) {
		q_tmp = q_it;
		q_it = q_it->next;
		lock_destroy(q_tmp->wait_sql_query);
		lock_dealloc(q_tmp->wait_sql_query);
		shm_free(q_tmp->key.s);
		shm_free(q_tmp);
	}
	shm_free(queries_in_progress);

	c_it = *entry_list;
	while (c_it) {
		c_tmp = c_it;
		c_it = c_it->next;
		free_c_entry(c_tmp);
	}
	shm_free(entry_list);

	lock_destroy(queries_lock);
	lock_dealloc(queries_lock);
}
