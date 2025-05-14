/*
 * Copyright (C) 2025 OpenSIPS Solutions
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../db/db.h"
#include "../../pt.h"
#include "../../ipc.h"
#include "../../locking.h"
#include "../../lib/hash.h"
#include "../../mem/rpm_mem.h"
#include "../../status_report.h"
#include "config.h"

static str config_db_url = {NULL, 0};
static str config_table = str_init("config");
static str config_name_col = str_init("name");
static str config_value_col = str_init("value");
static str config_desc_col = str_init("description");
static int config_rpm_enable = 0;
static db_con_t *config_db_con = NULL;
static db_func_t config_db_func;
static void rpc_config_reload(int sender_id, void *unused);
static int pv_parse_config_var(pv_spec_p sp, const str *in);
static int pv_get_config_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_set_config_var(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val);
static int pv_get_config_desc_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static mi_response_t *mi_config_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_config_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_config_push(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_config_push_bulk(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_config_flush(const mi_params_t *params,
								struct mi_handler *async_hdl);
static int config_push_val(gen_hash_t *hash, str *name, str *val, str *desc, int update);
static void free_config_hash(gen_hash_t *hash);
static void *config_srg = NULL;
static gen_lock_t *config_lock;
static int config_hash_size = CONFIG_DEFAULT_HASH_SIZE;

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

#define CONFIG_VAL_NULL  (1<<0)
#define CONFIG_VAL_DESC  (1<<1)
#define CONFIG_VAL_DIRTY (1<<2)

typedef struct config_val_t {
	unsigned int flags;
	str value;
	str desc;
} *config_val_p;

static gen_hash_t **config_hash;

static const cmd_export_t cmds[] =
{
	{0,0,{{0,0,0}},0}
};

static const pv_export_t mod_pvars[] = {
	{ str_const_init("config"), 2004, pv_get_config_var, pv_set_config_var,
		pv_parse_config_var, 0, 0, 0},
	{ str_const_init("config.description"), 2005, pv_get_config_desc_var, NULL,
		pv_parse_config_var, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};


static const param_export_t params[]={
	{ "db_url",                    STR_PARAM, &config_db_url.s},
	{ "table_name",                STR_PARAM, &config_table.s},
	{ "name_column",               STR_PARAM, &config_name_col.s},
	{ "value_column",              STR_PARAM, &config_value_col.s},
	{ "description_column",        STR_PARAM, &config_desc_col.s},
	{ "enable_restart_persistency",INT_PARAM, &config_rpm_enable},
	{ "hash_size",                 INT_PARAM, &config_hash_size},
	{0,0,0}
};

static const mi_export_t mi_cmds[] = {
	{ "config_reload", 0, 0, 0, {
		{mi_config_reload, {NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "config_list", 0, 0, 0, {
		{mi_config_list, {NULL}},
		{mi_config_list, {"description", NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "config_push", 0, 0, 0, {
		{mi_config_push, {"name", NULL}},
		{mi_config_push, {"name", "value", NULL}},
		{mi_config_push, {"name", "value", "description", NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "config_push_bulk", 0, 0, 0, {
		{mi_config_push_bulk, {"configs", NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{ "config_flush", 0, 0, 0, {
		{mi_config_flush, {NULL}},
		{mi_config_flush, {"name", NULL}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};


/** module exports */
struct module_exports exports= {
	"config",					/* module name */
	MOD_TYPE_DEFAULT,			/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	0,							/* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported asynchronous functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,					/* exported MI functions */
	mod_pvars,					/* exported pseudo-variables */
	0,							/* exported transformations */
	0,							/* extra processes */
	0,							/* module pre-initialization function */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	mod_destroy,				/* destroy function */
	child_init,					/* per-child init function */
	0							/* reload-ack function */
};


/**
 * init module function
 */
static int mod_init(void)
{
	int n;
	str srg_data = str_init("no data loaded");
	int srg_status = SR_STATUS_NO_DATA;

	LM_NOTICE("initializing config module ...\n");
	init_db_url(config_db_url , 1 /*can be null*/);
	config_table.len = strlen(config_table.s);
	config_name_col.len = strlen(config_name_col.s);
	config_value_col.len = strlen(config_value_col.s);
	config_desc_col.len = strlen(config_desc_col.s);

	if(db_bind_mod(&config_db_url, &config_db_func) == -1) {
		LM_ERR("Failed bind to database\n");
		return -1;
	}

	if (!DB_CAPABILITY(config_db_func, DB_CAP_QUERY|DB_CAP_FETCH|DB_CAP_INSERT_UPDATE)) {
		LM_ERR("Database module does not implement all functions"
				" needed by config module\n");
		return -1;
	}

	config_db_con = config_db_func.init(&config_db_url);
	if (!config_db_con) {
		LM_ERR("Failed to connect to database\n");
		return -1;
	}

	/*verify table versions */
	if(db_check_table_version(&config_db_func, config_db_con,
			&config_table, CONFIG_TABLE_VERSION) < 0) {
		LM_ERR("error during table version check\n");
		return -1;
	}

	config_lock = lock_alloc();
	if (!config_lock || !lock_init(config_lock)) {
		LM_ERR("could not allocate config lock\n");
		return -1;
	}

	config_srg = sr_register_group( CHAR_INT("config"), 0 /*not public*/);
	if (!config_srg) {
		LM_ERR("failed to create config group for 'status-report'\n");
		return -1;
	}

	config_hash = shm_malloc(sizeof *config_hash);
	if (!config_hash) {
		LM_ERR("oom for config_hash\n");
		return -1;
	}
	*config_hash = 0;

	if (config_rpm_enable) {
		/* if we are using cache, we need to fetch our dr zone */
		if (rpm_init_mem() < 0) {
			LM_ERR("could not initilize restart persistency memory!\n");
			return -1;
		}
		*config_hash = (gen_hash_t *)rpm_key_get("config");
		if (*config_hash) {
			if (hash_init_locks(*config_hash) < 0) {
				LM_ERR("could not initialize hash's locks\n");
				return -1;
			}
			LM_DBG("starting config with cache=%p\n", *config_hash);
			srg_status = SR_STATUS_READY;
			srg_data = str_init("data ready");
		} else {
			LM_INFO("starting config with empty cache - reloading\n");
		}
	}

	if (sr_register_identifier(config_srg, NULL, 0,
			srg_status, srg_data.s, srg_data.len, 20) ) {
		LM_ERR("failed to register status report identifier\n");
		return -1;
	}

	/* initialized the hash table */
	for( n=0 ; n<(8*sizeof(n)) ; n++) {
		if (config_hash_size==(1<<n))
			break;
		if (config_hash_size<(1<<n)) {
			/* make sure n does not go underflow - this is only possible if
			 * hash_size is declared to 0, and we "fix" it to 1 */
			if (n == 0)
				n = 1;
			LM_WARN("hash_size is not a power "
				"of 2 as it should be -> rounding from %d to %d\n",
				config_hash_size, 1<<(n-1));
			config_hash_size = 1<<(n-1);
			break;
		}
	}

	return 0;
}

static int child_init(int rank)
{
	if (!config_db_func.init) {
		LM_CRIT("database not bound\n");
		return -1;
	}

	config_db_con = config_db_func.init(&config_db_url);
	if (!config_db_con) {
		LM_ERR("Failed to connect to database\n");
		return -1;
	}

	if (rank == 1 && !*config_hash && ipc_dispatch_rpc(rpc_config_reload, NULL) < 0) {
		LM_ERR("could not reload sockets!\n");
		return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void mod_destroy(void)
{
	LM_NOTICE("destroying config module ...\n");
	if (config_lock)
		lock_destroy(config_lock);
	if (config_hash) {
		if (!config_rpm_enable)
			free_config_hash(*config_hash);
		else
			hash_destroy_locks(*config_hash);
		shm_free(config_hash);
	}
}

static int pv_parse_config_var(pv_spec_p sp, const str *in)
{
	pv_spec_t *pv;
	if (!in || !in->s || in->len < 1) {
		LM_ERR("invalid RTP relay var name!\n");
		return -1;
	}
	if (in->s[0] == PV_MARKER) {
		pv = pkg_malloc(sizeof(pv_spec_t));
		if (!pv) {
			LM_ERR("Out of mem!\n");
			return -1;
		}
		if (!pv_parse_spec(in, pv)) {
			LM_ERR("cannot parse PVAR [%.*s]\n",
					in->len, in->s);
			return -1;
		}
		sp->pvp.pvn.type |= PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = pv;
	} else {
		sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
		sp->pvp.pvn.u.isname.name.s = *in;
	}
	return 0;
}

static str *pv_get_config_name(struct sip_msg *msg,  pv_param_t *param)
{
	static pv_value_t tv;
	if (msg==NULL || param==NULL)
		return NULL;

	if(param->pvn.type == PV_NAME_PVAR)
	{
		if(pv_get_spec_name(msg, param, &tv)!=0)
		{
			LM_ERR("invalid name\n");
			return NULL;
		}
		if (tv.flags & PV_VAL_NULL)
			return NULL;

		if ((tv.flags & PV_VAL_STR) == 0)
			tv.rs.s = int2str(tv.ri, &tv.rs.len);
		return &tv.rs;
	} else {
		return &param->pvn.u.isname.name.s;
	}
}

static int pv_get_config_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	int len;
	unsigned int e;
	static char _buf[CONFIG_STATIC_BUF_LEN];
	config_val_p *_cv, cv;
	str *name = pv_get_config_name(msg, param);
	if (!name) {
		LM_DBG("no valid name provided!\n");
		return pv_get_null(msg, param, val);
	}
	if (!*config_hash) {
		LM_DBG("config not available yet!\n");
		return pv_get_null(msg, param, val);
	}

	lock_get(config_lock);
	e = hash_entry(*config_hash, *name);
	hash_lock(*config_hash, e);
	_cv = (config_val_p *)hash_find(*config_hash, e, *name);
	if (_cv && *_cv && (((*_cv)->flags & CONFIG_VAL_NULL) == 0)) {
		cv = *_cv;
		if (cv->value.len > CONFIG_STATIC_BUF_LEN) {
			len = CONFIG_STATIC_BUF_LEN;
			LM_WARN("value too long %d ... triming to %d\n",
					cv->value.len, CONFIG_STATIC_BUF_LEN);
		} else {
			len = cv->value.len;
		}
		memcpy(_buf, cv->value.s, len);
		val->rs.s = _buf;
		val->rs.len = len;
		val->flags = PV_VAL_STR;
	} else {
		pv_get_null(msg, 0, val);
	}
	hash_unlock(*config_hash, e);
	lock_release(config_lock);
	return 0;
}

static int pv_set_config_var(struct sip_msg *msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	str *v, tmp;
	str *name = pv_get_config_name(msg, param);
	if (!name) {
		LM_DBG("no valid name provided!\n");
		return -1;
	}
	lock_get(config_lock);
	if (!val || val->flags & PV_VAL_NULL) {
		v = NULL;
	} else if ((val->flags & PV_VAL_STR) == 0) {
		tmp.s = int2str(val->ri, &tmp.len);
		v = &tmp;
	} else {
		v = &val->rs;
	}
	config_push_val(*config_hash, name, v, NULL, 1);
	lock_release(config_lock);
	return 0;
}

static int pv_get_config_desc_var(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val)
{
	int len;
	unsigned int e;
	static char _buf[CONFIG_STATIC_BUF_LEN];
	config_val_p *_cv, cv;
	str *name = pv_get_config_name(msg, param);
	if (!name) {
		LM_DBG("no valid name provided!\n");
		return pv_get_null(msg, param, val);
	}
	if (!*config_hash) {
		LM_DBG("config not available yet!\n");
		return pv_get_null(msg, param, val);
	}

	lock_get(config_lock);
	e = hash_entry(*config_hash, *name);
	hash_lock(*config_hash, e);
	_cv = (config_val_p *)hash_find(*config_hash, e, *name);
	if (_cv && *_cv && ((*_cv)->flags & CONFIG_VAL_DESC)) {
		cv = *_cv;
		if (cv->desc.len > CONFIG_STATIC_BUF_LEN) {
			len = CONFIG_STATIC_BUF_LEN;
			LM_WARN("desc too long %d ... triming to %d\n",
					cv->desc.len, CONFIG_STATIC_BUF_LEN);
		} else {
			len = cv->desc.len;
		}
		memcpy(_buf, cv->desc.s, len);
		val->rs.s = _buf;
		val->rs.len = len;
		val->flags = PV_VAL_STR;
	} else {
		pv_get_null(msg, 0, val);
	}
	hash_unlock(*config_hash, e);
	lock_release(config_lock);
	return 0;
}


static void config_free_val(void *p)
{
	if (!p)
		return;
	if (config_rpm_enable)
		rpm_free(p);
	else
		shm_free(p);
}

static void free_config_hash(gen_hash_t *hash)
{
	hash_destroy(hash, config_free_val);
}

static gen_hash_t *config_new_cache(void)
{
	gen_hash_t *new = hash_init_flags(config_hash_size,
			(config_rpm_enable?HASH_MAP_PERSIST:HASH_MAP_SHARED));
	if (!new) {
		LM_ERR("could not add new cache\n");
		return NULL;
	}
	return new;
}

static int config_push_val(gen_hash_t *hash, str *name, str *val, str *desc, int update)
{
	unsigned int e;
	config_val_p cv, *old;
	int size;

	e = hash_entry(hash, *name);
	hash_lock(hash, e);
	if (!desc && update) {
		old = (config_val_p *)hash_find(hash, e, *name);
		if (old && *old && (*old)->flags & CONFIG_VAL_DESC)
			desc = &(*old)->desc;
	}

	size = (sizeof *cv) + (val?val->len:0) + (desc?desc->len:0);

	if (config_rpm_enable)
		cv = rpm_malloc(size);
	else
		cv = shm_malloc(size);
	if (!cv) {
		LM_ERR("could not allocate value\n");
		return -1;
	}
	memset(cv, 0, sizeof *cv);
	if (val) {
		cv->value.s = (char *)(cv + 1);
		cv->value.len = val->len;
		memcpy(cv->value.s, val->s, val->len);
	} else {
		cv->flags |= CONFIG_VAL_NULL;
	}
	if (desc) {
		if (val)
			cv->desc.s = cv->value.s + cv->value.len;
		else
			cv->desc.s = (char *)(cv + 1);
		cv->desc.len = desc->len;
		memcpy(cv->desc.s, desc->s, desc->len);
		cv->flags |= CONFIG_VAL_DESC;
	}
	if (update)
		cv->flags |= CONFIG_VAL_DIRTY;

	old = hash_insert(hash, e, *name, cv);
	hash_unlock(hash, e);
	if (old)
		config_free_val(old);

	return 0;
}

static gen_hash_t *load_config_hash(void)
{
	db_key_t colsToReturn[3];
	db_res_t *result = NULL;
	str name, value, description, *val, *desc;
	int rowCount = 0;
	db_row_t *row;
	gen_hash_t *ret = NULL;

	colsToReturn[0] = &config_name_col;
	colsToReturn[1] = &config_value_col;
	colsToReturn[2] = &config_desc_col;

	if (config_db_func.use_table(config_db_con, &config_table) < 0) {
		LM_ERR("Error trying to use %.*s table\n", config_table.len, config_table.s);
		return NULL;
	}

	if (config_db_func.query(config_db_con, 0, 0, 0,colsToReturn, 0, 3, 0,
				&result) < 0) {
		LM_ERR("Error querying database\n");
		goto error;
	}

	if (!result) {
		LM_ERR("mysql query failed - NULL result\n");
		return NULL;
	}

	ret = config_new_cache();
	if (!ret) {
		LM_ERR("could not create new config cache\n");
		goto error;
	}

	if (RES_ROW_N(result)<=0 || RES_ROWS(result)[0].values[0].nul != 0) {
		LM_DBG("no config found\n");
		goto end;
	}

	for (rowCount=0; rowCount < RES_ROW_N(result); rowCount++) {

		row = &result->rows[rowCount];

		switch (VAL_TYPE(ROW_VALUES(row))) {
			case DB_STR:
				name = VAL_STR(ROW_VALUES(row));
				break;
			case DB_STRING:
				name.s = (char *)VAL_STRING(ROW_VALUES(row));
				name.len = strlen(name.s);
				break;
			default:
				LM_ERR("unknown name column type %d\n", VAL_TYPE(ROW_VALUES(row)));
				continue;
		}

		if (!VAL_NULL(ROW_VALUES(row) + 1)) {
			switch (VAL_TYPE(ROW_VALUES(row) + 1)) {
				case DB_STR:
					value = VAL_STR(ROW_VALUES(row) + 1);
					break;
				case DB_STRING:
					value.s = (char *)VAL_STRING(ROW_VALUES(row) + 1);
					value.len = strlen(value.s);
					break;
				default:
					LM_ERR("unknown value column type %d\n",
							VAL_TYPE(ROW_VALUES(row) + 1));
					continue;
			}
			val = &value;
		} else {
			val = NULL;
		}

		if (!VAL_NULL(ROW_VALUES(row) + 2)) {
			switch (VAL_TYPE(ROW_VALUES(row) + 2)) {
				case DB_STR:
					description = VAL_STR(ROW_VALUES(row) + 2);
					break;
				case DB_STRING:
					description.s = (char *)VAL_STRING(ROW_VALUES(row) + 2);
					description.len = strlen(description.s);
					break;
				default:
					LM_ERR("unknown description column type %d\n",
							VAL_TYPE(ROW_VALUES(row) + 2));
					continue;
			}
			desc = &description;
		} else {
			desc = NULL;
		}

		if (config_push_val(ret, &name, val, desc, 0) < 0) {
			LM_ERR("could not create new config value %.*s\n",
					name.len, name.s);
			continue;
		}
	}

end:
	config_db_func.free_result(config_db_con, result);

	return ret;
error:
	if(result)
		config_db_func.free_result(config_db_con, result);
	if (ret)
		free_config_hash(ret);
	return NULL;
}

static int reload_config_hash(int initial)
{
	gen_hash_t *old_hash, *new_hash;
	if (initial)
		sr_set_status(config_srg, NULL, 0, SR_STATUS_LOADING_DATA,
			CHAR_INT("startup data loading"), 0);
	else
		sr_set_status(config_srg, NULL, 0, SR_STATUS_RELOADING_DATA,
			CHAR_INT("data re-loading"), 0);

	new_hash = load_config_hash();
	if (!new_hash)
		goto error;
	lock_get(config_lock);
	old_hash = *config_hash;
	*config_hash = new_hash;
	rpm_key_set("config", *config_hash);
	lock_release(config_lock);
	LM_DBG("reloaded data cache=%p\n", *config_hash);

	sr_set_status(config_srg, NULL, 0, SR_STATUS_READY,
		CHAR_INT("data available"), 0);
	free_config_hash(old_hash);
	return 0;
error:
	if (initial)
		sr_set_status(config_srg, NULL, 0, SR_STATUS_NO_DATA,
			CHAR_INT("no data loaded"), 0);
	else
		sr_set_status(config_srg, NULL, 0, SR_STATUS_READY,
			CHAR_INT("data available"), 0);
	return -1;
}

static void rpc_config_reload(int sender_id, void *unused)
{
	LM_DBG("config initial reloading\n");
	if (reload_config_hash(1) < 0)
		LM_ERR("could not reload sockets\n");
}

static mi_response_t *mi_config_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (reload_config_hash(0) < 0)
		return init_mi_error(500, MI_SSTR("Could not reload config"));

	return init_mi_result_ok();
}

static int config_val_hash_it(void *param, str key, void *value)
{
	mi_item_t *item = param;
	config_val_p cv = value;
	if (cv->flags & CONFIG_VAL_NULL) {
		if (add_mi_null(item, key.s, key.len) < 0)
			return -1;
	} else {
		if (add_mi_string(item, key.s, key.len, cv->value.s, cv->value.len) < 0)
			return -1;
	}
	return 0;
}

static int config_val_desc_hash_it(void *param, str key, void *value)
{
	mi_item_t *item, *arr = param;
	config_val_p cv = value;
	item = add_mi_object(arr, NULL, 0);
	if (!item)
		return -1;
	if (add_mi_string(item, MI_SSTR("name"), key.s, key.len) < 0)
		return -1;
	if (cv->flags & CONFIG_VAL_NULL) {
		if (add_mi_null(item, MI_SSTR("value")) < 0)
			return -1;
	} else {
		if (add_mi_string(item, MI_SSTR("value"), cv->value.s, cv->value.len) < 0)
			return -1;
	}
	if (cv->flags & CONFIG_VAL_DESC) {
		if (add_mi_string(item, MI_SSTR("description"), cv->desc.s, cv->desc.len) < 0)
			return -1;
	} else {
		if (add_mi_null(item, MI_SSTR("description")) < 0)
			return -1;
	}
	return 0;
}

static mi_response_t *mi_config_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *item;
	int desc = 0;

	if (try_get_mi_int_param(params, "description", &desc) == -2)
		return init_mi_param_error();

	if (desc)
		resp = init_mi_result_array(&item);
	else
		resp = init_mi_result_object(&item);
	if (!resp)
		return 0;

	lock_get(config_lock);
	hash_for_each_locked(*config_hash,
			(desc?config_val_desc_hash_it:config_val_hash_it), item);
	lock_release(config_lock);

	return resp;
}

static mi_response_t *mi_config_push(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str name, value, desc;
	str *v, *d;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return init_mi_param_error();
	switch (try_get_mi_string_param(params, "value", &value.s, &value.len)) {
		case -2:
			return init_mi_param_error();
		case -1:
			v = NULL;
			break;
		default:
			v = &value;
			break;
	}
	switch (try_get_mi_string_param(params, "description", &desc.s, &desc.len)) {
		case -2:
			return init_mi_param_error();
		case -1:
			d = NULL;
			break;
		default:
			d = &desc;
			break;
	}
	lock_get(config_lock);
	config_push_val(*config_hash, &name, v, d, 1);
	lock_release(config_lock);
	return init_mi_result_ok();
}

static mi_response_t *mi_config_push_bulk(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int items, count = 0, n = 0;
	mi_item_t *arr = NULL;
	str name, value, desc;
	str *v, *d;
	cJSON *o, *t;

	if (get_mi_array_param(params, "configs", &arr, &items) < 0)
		return init_mi_param_error();
	lock_get(config_lock);
	for (n = 0; n < items; n++) {
		if (get_mi_arr_param_object(arr, n, &o) < 0)
			continue;
		t = cJSON_GetObjectItem(o, "name");
		if (!t) {
			LM_ERR("no name in json\n");
			continue;
		}
		if (t->type != cJSON_String) {
			LM_ERR("bad name type %d in json\n", t->type);
			continue;
		}
		name.s = t->valuestring;
		name.len = strlen(name.s);
		t = cJSON_GetObjectItem(o, "value");
		if (!t) {
			LM_ERR("no value in json\n");
			continue;
		}
		if (t->type == cJSON_NULL) {
			v = NULL;
		} else if (t->type == cJSON_String) {
			value.s = t->valuestring;
			value.len = strlen(value.s);
			v = &value;
		} else if (t->type == cJSON_Number) {
			value.s = int2str(t->valueint, &value.len);
			v = &value;
		} else {
			LM_ERR("bad value type %d in json\n", t->type);
			continue;
		}
		t = cJSON_GetObjectItem(o, "description");
		if (t && t->type == cJSON_String) {
			desc.s = t->valuestring;
			desc.len = strlen(desc.s);
			d = &desc;
		} else {
			d = NULL;
		}
		if (config_push_val(*config_hash, &name, v, d, 1) == 0)
			count++;
	}
	lock_release(config_lock);
	return init_mi_result_number(count);
}

static int config_val_flush_hash_it(void *param, str key, void *value)
{
	int *count = (int *)param;
	config_val_p cv = value;
	db_key_t cols[3];
	db_val_t vals[3];

	memset(vals, 0, sizeof vals);

	cols[0] = &config_name_col;
	cols[1] = &config_value_col;
	cols[2] = &config_desc_col;

	VAL_TYPE(vals + 0)=DB_STR;
	VAL_TYPE(vals + 1)=DB_STR;
	VAL_TYPE(vals + 2)=DB_STR;

	VAL_STR(vals) = key;
	if (cv->flags & CONFIG_VAL_NULL)
		VAL_NULL(vals+1) = 1;
	else
		VAL_STR(vals+1) = cv->value;
	if (cv->flags & CONFIG_VAL_DESC)
		VAL_STR(vals+2) = cv->desc;
	else
		VAL_NULL(vals+2) = 1;

	if (config_db_func.replace(config_db_con, cols, vals, 3) < 0) {
		LM_ERR("Error replacing row %.*s\n", key.len, key.s);
		return -1;
	}
	(*count)++;

	return 0;
}


static mi_response_t *mi_config_flush(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str name;
	unsigned int e;
	int count;

	switch (try_get_mi_string_param(params, "name", &name.s, &name.len)) {
		case -2:
			return init_mi_param_error();
		case -1:
			name.len = 0;
			break;
		case 0:
			/* flush only specific key */
			break;
	}

	if (config_db_func.use_table(config_db_con, &config_table) < 0) {
		LM_ERR("Error trying to use %.*s table\n", config_table.len, config_table.s);
		return NULL;
	}

	count = 0;
	lock_get(config_lock);
	if (name.len) {
		e = hash_entry(*config_hash, name);
		hash_lock(*config_hash, e);
		config_val_p *_cv = (config_val_p *)hash_find(*config_hash, e, name);
		if (*_cv && _cv)
			config_val_flush_hash_it(&count, name, *_cv);
		hash_unlock(*config_hash, e);
	} else {
		hash_for_each_locked(*config_hash, config_val_flush_hash_it, &count);
	}
	lock_release(config_lock);
	return init_mi_result_number(count);
}
