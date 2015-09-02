#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../pvar.h"

#include "sql_cacher.h"

static int mod_init(void);
static void destroy(void);
static int child_init(int rank);

static int cache_new_table(unsigned int type, void *val);

int pv_parse_name(pv_spec_p sp, str *in);
int pv_init_param(pv_spec_p sp, int param);
int pv_get_sql_cached_value(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);

static str spec_delimiter;
static str pvar_delimiter;
static int fetch_nr_rows = DEFAULT_FETCH_NR_ROWS;

static cache_entry_t **entry_list;
static struct parse_entry *to_parse_list = NULL;

/* module parameters */
static param_export_t mod_params[] = {
	{"spec_delimiter", STR_PARAM, &spec_delimiter.s},
	{"pvar_delimiter", STR_PARAM, &pvar_delimiter.s},
	{"sql_fetch_nr_rows", INT_PARAM, &fetch_nr_rows},
	{"cache_table", STR_PARAM|USE_FUNC_PARAM, (void *)&cache_new_table},
	{0,0,0}
};

static pv_export_t mod_items[] = {
	{{"sql_cached_value", sizeof("sql_cached_value") - 1}, 1000,
		pv_get_sql_cached_value, 0, pv_parse_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/**
 * module exports
 */
struct module_exports exports = {
	"sql_cacher",				/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	NULL,						/* OpenSIPS module dependencies */
	0,							/* exported functions */
	0,							/* exported async functions */
	mod_params,					/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	mod_items,					/* exported pseudo-variables */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	0,							/* response handling function */
	destroy,					/* destroy function */
	child_init					/* per-child init function */
};

static int cache_new_table(unsigned int type, void *val) {
	struct parse_entry *new_entry;

	new_entry = pkg_malloc(sizeof(struct parse_entry));
	if (!new_entry) {
		LM_ERR("No more memory for to_parse list entry\n");
		return -1;
	}

	new_entry->next = NULL;
	new_entry->to_parse_str.len = strlen((char *)val);
	new_entry->to_parse_str.s = pkg_malloc(new_entry->to_parse_str.len);
	if (!new_entry->to_parse_str.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(new_entry->to_parse_str.s, (char *)val, new_entry->to_parse_str.len);

	if (!to_parse_list) {
		to_parse_list = new_entry;
	} else {
		new_entry->next = to_parse_list;
		to_parse_list = new_entry;
	}

	return 0;
}

static void insert_cache_entry(cache_entry_t *new_entry) {
	new_entry->next = NULL;

	if (*entry_list != NULL) {
		new_entry->next = *entry_list;
	}

	*entry_list = new_entry;
}

static int parse_cache_entries(void) {
	cache_entry_t *new_entry;
	struct parse_entry *it;
	char *p1, *p2, *tmp, *c_tmp1, *c_tmp2;
	int col_idx;
	int rc = -1;

	for (it = to_parse_list; it != NULL; it = it->next) {

		new_entry = shm_malloc(sizeof(cache_entry_t));
		if (!new_entry) {
			LM_ERR("No more memory for cache entry struct\n");
			return -1;
		}
		new_entry->columns = NULL;
		new_entry->nr_columns = 0;
		new_entry->on_demand = 0;
		new_entry->expire = DEFAULT_CACHEDB_EXPIRE;
		new_entry->nr_ints = 0;
		new_entry->nr_strs = 0;
		new_entry->column_types = 0;
		new_entry->db_con = 0;
		new_entry->cdbcon = 0;

#define PARSE_TOKEN(_ptr1, _ptr2, field, field_name_str, field_name_len) \
	do { \
		(_ptr2) = memchr((_ptr1), '=', it->to_parse_str.len - \
											((_ptr1) - it->to_parse_str.s)); \
		if (!(_ptr2)) \
			goto parse_err; \
		if (!memcmp((_ptr1), (field_name_str), (field_name_len))) { \
			tmp = memchr((_ptr2) + 1, spec_delimiter.s[0], it->to_parse_str.len - \
													((_ptr2) - it->to_parse_str.s)); \
			if (!tmp) \
				goto parse_err; \
			new_entry->field.len = tmp - (_ptr2) - 1; \
			if (new_entry->field.len <= 0) \
				goto parse_err; \
			new_entry->field.s = shm_malloc(new_entry->field.len); \
			memcpy(new_entry->field.s, p2 + 1, new_entry->field.len); \
		} else \
			goto parse_err; \
	} while (0)

		/* parse the id */
		p1 = it->to_parse_str.s;
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
		p2 = memchr(p1, '=', it->to_parse_str.len - (p1 - it->to_parse_str.s));
		if (!p2)
			goto parse_err;
		if (!memcmp(p1, KEY_STR, KEY_STR_LEN)) {
			tmp = memchr(p2 + 1, spec_delimiter.s[0], it->to_parse_str.len - (p2 - it->to_parse_str.s));
			if (!tmp) /* delimiter not found, reached the end of the string to parse */
				new_entry->key.len = it->to_parse_str.len - (p2 - it->to_parse_str.s + 1);
			else
				new_entry->key.len = tmp - p2 - 1;

			if (new_entry->key.len <= 0)
				goto parse_err;

			new_entry->key.s = shm_malloc(new_entry->key.len);
			memcpy(new_entry->key.s, p2 + 1, new_entry->key.len);

			if (!tmp)
				goto end_parsing;
		} else
			goto parse_err;

		/* parse the required column names if present */
		p1 = tmp + 1;
		p2 = memchr(p1, '=', it->to_parse_str.len - (p1 - it->to_parse_str.s));
		if (!p2)
			goto parse_err;
		if (!memcmp(p1, COLUMNS_STR, COLUMNS_STR_LEN)) {
			col_idx = 0;
			tmp = memchr(p2 + 1, spec_delimiter.s[0], it->to_parse_str.len - (p2 - it->to_parse_str.s));

			/* just count how many columns there are */
			new_entry->nr_columns = 1;
			c_tmp1 = memchr(p2 + 1, COLUMN_NAMES_DELIM, it->to_parse_str.len - (p2 - it->to_parse_str.s + 1));
			while (c_tmp1) {
				new_entry->nr_columns++;
				c_tmp1 = memchr(c_tmp1 + 1, COLUMN_NAMES_DELIM, it->to_parse_str.len - (c_tmp1 - it->to_parse_str.s + 1));
			}

			if (new_entry->nr_columns > sizeof(long long)) {
				LM_ERR("Too many columns, maximum number is %ld\n", sizeof(long long));
				goto parse_err;
			}

			/* allocate array of columns and actually parse */
			new_entry->columns = shm_malloc(new_entry->nr_columns * sizeof(str));

			c_tmp1 = p2 + 1;
			c_tmp2 = memchr(p2 + 1, COLUMN_NAMES_DELIM, it->to_parse_str.len - (p2 - it->to_parse_str.s + 1));
			while (c_tmp2) {
				new_entry->columns[col_idx].len = c_tmp2 - c_tmp1;
				if (new_entry->columns[col_idx].len <= 0)
					goto parse_err;
				new_entry->columns[col_idx].s = shm_malloc(new_entry->columns[col_idx].len);
				memcpy(new_entry->columns[col_idx].s, c_tmp1, new_entry->columns[col_idx].len);

				c_tmp1 = c_tmp2 + 1;
				c_tmp2 = memchr(c_tmp1, COLUMN_NAMES_DELIM, it->to_parse_str.len - (c_tmp1 - it->to_parse_str.s + 1));
				col_idx++;
			}

			if (!tmp)
				new_entry->columns[col_idx].len = it->to_parse_str.len - (p2 - c_tmp1 + 1);		
			else
				new_entry->columns[col_idx].len = tmp - c_tmp1;

			if (new_entry->columns[col_idx].len <= 0)
					goto parse_err;
				new_entry->columns[col_idx].s = shm_malloc(new_entry->columns[col_idx].len);
				memcpy(new_entry->columns[col_idx].s, c_tmp1, new_entry->columns[col_idx].len);

			if (!tmp) { /* delimiter not found, reached the end of the string to parse */	
				goto end_parsing;
			} else {
				p1 = tmp + 1;
				p2 = memchr(p1, '=', it->to_parse_str.len - (p1 - it->to_parse_str.s));
				if (!p2)
					goto parse_err;
			}
		}

		/* parse on demand parameter */
		if (!memcmp(p1, ONDEMAND_STR, ONDEMAND_STR_LEN)) {
			tmp = memchr(p2 + 1, spec_delimiter.s[0], it->to_parse_str.len - (p2 - it->to_parse_str.s));
			str str_val;
			if (!tmp) { /* delimiter not found, reached the end of the string to parse */
				str_val.len = it->to_parse_str.len - (p2 - it->to_parse_str.s + 1);
			} else {
				str_val.len = tmp - p2 - 1;
			}

			if (str_val.len <= 0)
				goto parse_err;
			str_val.s = p2 + 1; 
			if(str2int(&str_val, &new_entry->on_demand))
				goto parse_err;

			if (!tmp) { /* delimiter not found, reached the end of the string to parse */
				goto end_parsing;
			} else {
				p1 = tmp + 1;
				p2 = memchr(p1, '=', it->to_parse_str.len - (p1 - it->to_parse_str.s));
				if (!p2)
					goto parse_err;
			}
		}

		/* parse expire parameter */
		if (!memcmp(p1, EXPIRE_STR, EXPIRE_STR_LEN)) {
			str str_val;
			str_val.len = it->to_parse_str.len - (p2 - it->to_parse_str.s + 1);
			if (str_val.len <= 0)
				goto parse_err;
			str_val.s = p2 + 1; 
			if(str2int(&str_val, &new_entry->expire))
				goto parse_err;

			goto end_parsing;
		}

		goto end_parsing;

parse_err:
		LM_ERR("Invalid cache entry specification\n");
		if (new_entry->columns)
			free(new_entry->columns);
		free(new_entry);
		continue;
end_parsing:
		insert_cache_entry(new_entry);
		rc = 0;
	}

	return rc;
}

/* count the number of integers and strings from the SQL db query */
static int get_column_types(cache_entry_t *c_entry, db_val_t *values, int nr_columns) {
	unsigned int i;
	long long one = 1;
	db_type_t val_type;

	for (i = 0; i < nr_columns; i++) {
		val_type = VAL_TYPE(values + i);
		switch (val_type) {
			case DB_INT:
			case DB_BIGINT:
			case DB_DOUBLE:
				c_entry->nr_ints++;
				c_entry->column_types &= ~(one << i);
				break;
			case DB_STRING:
			case DB_STR:
				c_entry->nr_strs++;
				c_entry->column_types |= (one << i);
				break;
			default:
				return -1;
		}
	}

	return 0;
}

/* returns the total length of the actual value which will be stored in the cachedb*/
static unsigned int cdb_val_total_len(cache_entry_t *c_entry, db_val_t *values, int nr_columns) {
	unsigned int i, len = 0;
	db_type_t val_type;

	/* length of the integer values and the offsets of the string values(also stored as integers) */
	len = c_entry->nr_ints * INT_B64_ENC_LEN + c_entry->nr_strs * INT_B64_ENC_LEN;
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
			default: continue;
		}
	}

	return len;
}

static int insert_in_cachedb(cache_entry_t *c_entry, db_val_t *key, db_val_t *values, int nr_columns) {
	unsigned int i, offset = 0, strs_offset = 0;
	int int_val;
	int int_key_len = 0;
	char int_buf[4], int_enc_buf[INT_B64_ENC_LEN];
	char *int_key_buf = NULL;
	str str_val;
	db_type_t val_type;
	str str_key;
	str cdb_val;
	str cdb_key;

	cdb_val.len = cdb_val_total_len(c_entry, values, nr_columns);
	cdb_val.s = pkg_malloc(cdb_val.len);
	if (!cdb_val.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}

	/* store the integer values first (base64 encoded) */
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

		if (VAL_NULL(values + i)) {
			memset(int_enc_buf, 0, INT_B64_ENC_LEN);
		} else {
			memcpy(int_buf, &int_val, 4);
			base64encode((unsigned char *)int_enc_buf, (unsigned char *)int_buf, 4);
		}

		memcpy(cdb_val.s + offset, int_enc_buf, INT_B64_ENC_LEN);

		memset(int_enc_buf, 0, INT_B64_ENC_LEN);
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
			default: continue;
		}

		if (VAL_NULL(values + i) || !str_val.len)
			int_val = 0;
		else
			int_val = strs_offset;

		memcpy(int_buf, &int_val, 4);
		base64encode((unsigned char *)int_enc_buf, (unsigned char *)int_buf, 4);
		memcpy(cdb_val.s + offset, int_enc_buf, INT_B64_ENC_LEN);

		memset(int_enc_buf, 0, INT_B64_ENC_LEN);
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
			return -1;
	}
	if (int_key_len) {
		str_key.s = int_key_buf;
		str_key.len = int_key_len;
	}

	cdb_key.len = c_entry->id.len + str_key.len;
	cdb_key.s = pkg_malloc(cdb_key.len);
	if (!cdb_key.s) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memcpy(cdb_key.s, c_entry->id.s, c_entry->id.len);
	memcpy(cdb_key.s + c_entry->id.len, str_key.s, str_key.len);

	if (c_entry->cdbf.set(c_entry->cdbcon, &cdb_key, &cdb_val, c_entry->expire) < 0) {
		LM_ERR("Failed to insert in cachedb\n");
		return -1;
	}

	return 0;
}

static int db_init_test_conn(cache_entry_t *c_entry) {
	str test_query_key_str = str_init(TEST_QUERY_STR);
	str cdb_test_key = str_init(CDB_TEST_KEY_STR);
	str cdb_test_val = str_init(CDB_TEST_VAL_STR);
	db_key_t query_key_col;
	db_key_t *query_cols = NULL;
	db_val_t query_key_val;
	db_res_t *sql_res;
	str cachedb_res;
	unsigned int i;

	/* cachedb init and test connection */
	if (cachedb_bind_mod(&c_entry->cachedb_url, &c_entry->cdbf) < 0) {
		LM_ERR("Unable to bind to a cachedb database driver\n");
		return -1;
	}
	/* open a test connection */
	c_entry->cdbcon = c_entry->cdbf.init(&c_entry->cachedb_url);
	if (c_entry->cdbcon == NULL) {
		LM_ERR("Cannot init connection to cachedb\n");
		return -1;
	}
	/* setting and geting a test key in cachedb */
	if (c_entry->cdbf.set(c_entry->cdbcon, &cdb_test_key, &cdb_test_val, 0) < 0) {
		LM_ERR("Failed to set test key in cachedb\n");
		c_entry->cdbf.destroy(c_entry->cdbcon);
		c_entry->cdbcon = 0;
		return -1;
	}
	if (c_entry->cdbf.get(c_entry->cdbcon, &cdb_test_key, &cachedb_res) < 0) {
		LM_ERR("Failed to get test key from cachedb\n");
		c_entry->cdbf.destroy(c_entry->cdbcon);
		c_entry->cdbcon = 0;
		return -1;
	}
	if (str_strcmp(&cachedb_res, &cdb_test_val) != 0) {
		LM_ERR("Cachedb inconsistent test key\n");
		c_entry->cdbf.destroy(c_entry->cdbcon);
		c_entry->cdbcon = 0;
		return -1;
	}

	/* SQL DB init and test connection */
	if (db_bind_mod(&c_entry->db_url, &c_entry->db_funcs) < 0){
		LM_ERR("Unable to bind to a SQL database driver\n");
		return -1;
	}
	/* open a test connection */
	if ((c_entry->db_con = c_entry->db_funcs.init(&c_entry->db_url)) == 0) {
		LM_ERR("Cannot init connection to SQL DB\n");
		return -1;
	}

	/* verify the column names by running a test query with a bogus key */
	if (c_entry->db_funcs.use_table(c_entry->db_con, &c_entry->table) < 0) {
		LM_ERR("Invalid table name\n");
		c_entry->db_funcs.close(c_entry->db_con);
		c_entry->db_con = 0;
		return -1;
	}

	VAL_NULL(&query_key_val) = 0;
	VAL_TYPE(&query_key_val) = DB_STR;
	VAL_STR(&query_key_val) = test_query_key_str;

	query_key_col = &c_entry->key;

	query_cols = pkg_malloc(c_entry->nr_columns * sizeof(db_key_t));
	if (!query_cols) {
		LM_ERR("No more pkg memory\n");
		c_entry->db_funcs.close(c_entry->db_con);
		c_entry->db_con = 0;
		return -1;
	}

	for (i = 0; i < c_entry->nr_columns; i++)
		query_cols[i] = &(c_entry->columns[i]);

	if (c_entry->db_funcs.query(c_entry->db_con, &query_key_col, 0, &query_key_val,
					query_cols, 1, c_entry->nr_columns, 0, &sql_res) != 0) {
		LM_ERR("Failure to issuse test query to SQL DB\n");
		c_entry->db_funcs.close(c_entry->db_con);
		c_entry->db_con = 0;
		return -1;
	}

	c_entry->db_funcs.free_result(c_entry->db_con, sql_res);
	return 0;
}

static int load_entire_table(cache_entry_t *c_entry) {
	db_key_t *query_cols = NULL;
	db_res_t *sql_res = NULL;
	db_row_t *row;
	db_val_t *values;
	int i;

	query_cols = pkg_malloc((c_entry->nr_columns + 1) * sizeof(db_key_t));
	if (!query_cols) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	query_cols[0] = &(c_entry->key);
	for (i=0; i < c_entry->nr_columns; i++) {
		query_cols[i+1] = &(c_entry->columns[i]);
	}

	/* query the entire table */
	if (DB_CAPABILITY(c_entry->db_funcs, DB_CAP_FETCH)) {
		if (c_entry->db_funcs.query(c_entry->db_con, NULL, 0, NULL,
						query_cols, 0, c_entry->nr_columns + 1, 0, 0) != 0) {
			LM_ERR("Failure to issue query to SQL DB\n");
			goto error;
		}

		if (c_entry->db_funcs.fetch_result(c_entry->db_con,&sql_res,fetch_nr_rows)<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (c_entry->db_funcs.query(c_entry->db_con, NULL, 0, NULL,
						query_cols, 0, c_entry->nr_columns + 1, 0, &sql_res) != 0) {
			LM_ERR("Failure to issue query to SQL DB\n");
			goto error;
		}
	}

	if (RES_ROW_N(sql_res) == 0) {
		LM_DBG("Table is empty!\n");
		goto error;
	}
	row = RES_ROWS(sql_res);
	values = ROW_VALUES(row);
	if (get_column_types(c_entry, values + 1, ROW_N(row) - 1) < 0) {
		LM_ERR("SQL column has unsupported type\n");
		goto error;
	}

	/* load the rows into the cahchedb */
	do {
		for (i=0; i < RES_ROW_N(sql_res); i++) {
			row = RES_ROWS(sql_res) + i;
			values = ROW_VALUES(row);
			if (!VAL_NULL(values)) {
				insert_in_cachedb(c_entry, values ,values + 1, ROW_N(row) - 1);
			}
		}

		if (DB_CAPABILITY(c_entry->db_funcs, DB_CAP_FETCH)) {
			if (c_entry->db_funcs.fetch_result(c_entry->db_con,&sql_res,fetch_nr_rows)<0) {
				LM_ERR("Error fetching rows (1)\n");
				goto error;
			}
		} else {
			break;
		}
	} while (RES_ROW_N(sql_res) > 0);

	c_entry->db_funcs.free_result(c_entry->db_con, sql_res);
	return 0;
error:
	if (sql_res)
		c_entry->db_funcs.free_result(c_entry->db_con, sql_res);
	return -1;
}

static int mod_init(void) {
	cache_entry_t *c_entry;

	LM_NOTICE("initializing module......\n");

	if (!spec_delimiter.s) {
		spec_delimiter.s = pkg_malloc(sizeof(char));	
		if (!spec_delimiter.s) {
			LM_ERR("No more memory for spec_delimiter\n");
			return -1;
		}
		spec_delimiter.s[0] = DEFAULT_SPEC_DELIM;
	}

	if (!pvar_delimiter.s) {
		pvar_delimiter.s = pkg_malloc(sizeof(char));	
		if (!pvar_delimiter.s) {
			LM_ERR("No more memory for pvar_delimiter\n");
			return -1;
		}
		pvar_delimiter.s[0] = DEFAULT_PVAR_DELIM;
	} else
		pvar_delimiter.len = strlen(pvar_delimiter.s);

	entry_list =  shm_malloc(sizeof(cache_entry_t*));
	if (!entry_list) {
		LM_ERR("No more memory for cache entries list\n");
		return -1;
	}
	*entry_list = NULL;

	if (parse_cache_entries() < 0) {
		LM_ERR("Unable to parse any cache entry\n");
		return -1;
	}

	for (c_entry = *entry_list; c_entry != NULL; c_entry = c_entry->next) {
		if (db_init_test_conn(c_entry) < 0)
			continue;

		/* cache the entire table if on demand is not set*/
		if (!c_entry->on_demand) {
			c_entry->expire = 0;
			if (load_entire_table(c_entry) < 0)
				LM_ERR("Failed to cache the entire table %s\n", c_entry->table.s);
			else
				LM_DBG("Cached the entire table %s\n", c_entry->table.s);
		}

		c_entry->db_funcs.close(c_entry->db_con);
		c_entry->db_con = 0;
		c_entry->cdbf.destroy(c_entry->cdbcon);
		c_entry->cdbcon = 0;
	}

	return 0;
}

static int child_init(int rank) {
	cache_entry_t *c_entry;

	for (c_entry = *entry_list; c_entry != NULL; c_entry = c_entry->next) {
		c_entry->cdbcon = c_entry->cdbf.init(&c_entry->cachedb_url);
		if (c_entry->cdbcon == NULL) {
			LM_ERR("Cannot connect to cachedb from child\n");
			return -1;
		}

		if (c_entry->on_demand &&
				(c_entry->db_con = c_entry->db_funcs.init(&c_entry->db_url)) == 0) {
			LM_ERR("Cannot connect to SQL DB from child\n");
			return -1;
		}
	}

	return 0;
}

static int parse_pv_name_s(pv_name_fix_t *pv_name, str *name_s) {
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
		int prev_len = pv_name->type.len; \
		pv_name->type.len = (_ptr2) - (_ptr1); \
		if (!pv_name->type.s) { \
			pv_name->type.s = pkg_malloc(pv_name->type.len); \
			if (!pv_name->type.s) { \
				LM_ERR("No more pkg memory\n"); \
				return -1; \
			} \
			memcpy(pv_name->type.s, (_ptr1), pv_name->type.len); \
		} else if (memcmp(pv_name->type.s, (_ptr1), pv_name->type.len)) { \
			if (prev_len != pv_name->type.len) { \
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
		PARSE_TOKEN(p1, p2, id, DEFAULT_PVAR_DELIM);
		p1 = p2 + 1;
		PARSE_TOKEN(p1, p2, col, DEFAULT_PVAR_DELIM);
		p1 = p2 + 1;
		PARSE_TOKEN(p1, p2, key, last);

#undef PARSE_TOKEN

	return 0;
}

int pv_parse_name(pv_spec_p sp, str *in) {
	pv_elem_t *model = NULL, *it;
	pv_name_fix_t *pv_name;

	if (in == NULL || in->s == NULL || sp == NULL)
		return -1;

	pv_name = pkg_malloc(sizeof(pv_name_fix_t));
	if (!pv_name) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	pv_name->id.s = NULL;
	pv_name->id.len = 0;
	pv_name->col.s = NULL;
	pv_name->col.len = 0;
	pv_name->key.s = NULL;
	pv_name->key.len = 0;
	pv_name->c_entry = NULL;
	pv_name->pv_elem_list = NULL;
	pv_name->col_offset = -1;

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void *)pv_name;

	if (pv_parse_format(in, &model) < 0) {
		LM_ERR("Wrong format for pvar name\n");
		return -1;
	}

	for (it = model; it != NULL; it = it->next) {
		if (it->spec.type != PVT_NONE)
			break;
	}
	if (it != NULL) { /* if there are variables in the name, parse later */
		pv_name->pv_elem_list = model;
	} else {
		if (parse_pv_name_s(pv_name, &(model->text)) < 0)
			return -1;
	}

	return 0;
}

int pv_get_sql_cached_value(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res) {
	pv_name_fix_t *pv_name;
	str name_s;
	cache_entry_t *it;
	int i, j, prev_cols;
	char col_type1, col_type2;
	long long one = 1;

	if (param == NULL || param->pvn.type != PV_NAME_PVAR ||
		param->pvn.u.dname == NULL) {
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
			name_s.len == 0 || name_s.s == NULL) {
			LM_ERR("Unable to evaluate variables in pv name");
			return pv_get_null(msg, param, res);
		}
		if (parse_pv_name_s(pv_name, &name_s) < 0)
			return pv_get_null(msg, param, res);
	} else {
		/* already parsed */
		name_s = pv_name->id;
	}

	/* save pointer to cache entries list and collumn offset in the pv spec */
	if (!pv_name->c_entry) {
		for (it = *entry_list; it != NULL; it = it->next) {
			if (!memcmp(it->id.s, pv_name->id.s, pv_name->id.len)) {
				pv_name->c_entry = it;

				for (i = 0; i < it->nr_columns; i++) {
					if (!memcmp(it->columns[i].s, pv_name->col.s, pv_name->col.len)) {
						prev_cols = 0;
						col_type1 = ((it->column_types & (one << i)) != 0);
						for (j = 0; j < i; j++) {
							col_type2 = ((it->column_types & (one << j)) != 0);
							if (col_type1 == col_type2)
								prev_cols++;
						}
						if (col_type1)
							pv_name->col_offset = it->nr_ints * INT_B64_ENC_LEN +
													prev_cols * INT_B64_ENC_LEN;
						else
							pv_name->col_offset = prev_cols * INT_B64_ENC_LEN;
						break;
					}
				}
				if (i == it->nr_columns)
					pv_name->col_offset = -1;
				break;
			}
		}

		if (!it) {
			LM_ERR("Unknown caching id\n");
			return pv_get_null(msg, param, res);
		}
	}

	return pv_get_null(msg, param, res);
}

static void destroy(void) {
	LM_NOTICE("destroy module ...\n");
}