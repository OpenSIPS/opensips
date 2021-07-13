/*
 * Rate Cacher Module
 *
 * Copyright (C) 2020 OpenSIPS Project
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
 * History:
 * --------
 * 2020-03-24 initial release (vlad)
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../db/db.h"
#include "../../mod_fix.h"

#include "rate_cacher.h"

/* module functions */
static int mod_init(void);
static int mod_child(int);
static void mod_destroy(void);
static int rate_cacher_load_all_info(void); 

static mi_response_t *mi_get_carrier_price(const mi_params_t *params,struct mi_handler  *async_hdl);
static mi_response_t *mi_reload_carrier_rate(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_add_carrier(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_delete_carrier(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_delete_carrier_rate(const mi_params_t *params,struct mi_handler *async_hdl);

static mi_response_t *mi_get_client_price(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_reload_client(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_add_client(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_delete_client(const mi_params_t *params,struct mi_handler *async_hdl);
static mi_response_t *mi_delete_client_rate(const mi_params_t *params,struct mi_handler *async_hdl);

static int script_get_client_price(struct sip_msg *msg, str *clientid, int *isws,
		str *dnis,pv_spec_t *prefix,pv_spec_t *destination, pv_spec_t *price,
		pv_spec_t *min,pv_spec_t *inc);
static int script_get_vendor_price(struct sip_msg *msg, str *vendorid,
		str *dnis,pv_spec_t *prefix,pv_spec_t *destination, pv_spec_t *price,
		pv_spec_t *min,pv_spec_t *inc);
static int script_cost_based_filtering(struct sip_msg *msg, str *clientid, int *isws,
		str *carrierlist,str *dnis,int *profit_margin,pv_spec_t *out_result);
static int script_cost_based_ordering(struct sip_msg *msg, str *clientid, int *isws,
		str *carrierlist,str *dnis,int *profit_margin,pv_spec_t *out_result);

static void free_carrier_cell(struct carrier_cell *carr);
static void free_trie(ptree_t* t);

/* table names */
static str carr_db_table = str_init("rc_vendors");
static str carr_id_col = str_init("vendor_id");
static str carr_rateid_col = str_init("vendor_rate");

static str acc_db_table = str_init("rc_clients");
static str acc_id_col = str_init("client_id");
static str acc_ws_rateid_col = str_init("wholesale_rate");
static str acc_rt_rateid_col = str_init("retail_rate");

static str ratesheets_db_table = str_init("rc_ratesheets");
static str rs_currency_col = str_init("currency");
static str rs_table_col = str_init("ratesheet_table");

static str rs_rateid_col = str_init("id");
static str rs_destination_col = str_init("destination");
static str rs_cc_col = str_init("prefix");
static str rs_price_col = str_init("price");
static str rs_minimum_col = str_init("minimum");
static str rs_increment_col = str_init("increment");

/* db connectors */
static str carriers_db_url = {NULL,0};
static str accounts_db_url = {NULL,0}; 
static str rates_db_url = {NULL,0}; 

static db_con_t *carriers_db_hdl=0;
static db_func_t carriers_dbf;   
static db_con_t *accounts_db_hdl=0;
static db_func_t accounts_dbf;   
static db_con_t *rates_db_hdl=0;
static db_func_t rates_dbf;   


static struct carrier_table *carr_table = NULL;
static struct accounts_table *acc_table = NULL;

static int carr_hash_size = 256;
static int acc_hash_size = 256;
static int add_carrier(str *carrier,int safe);
static int add_client(str *accountid,int safe);

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "rates_db_url", get_deps_sqldb_url },
		{ "clients_db_url", get_deps_sqldb_url },
		{ "vendors_db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

static param_export_t params[] = {
	{ "vendors_db_url",		STR_PARAM,	&carriers_db_url.s},
	{ "vendors_db_table",		STR_PARAM,	&carr_db_table.s},
	{ "vendors_hash_size",		INT_PARAM,	&carr_hash_size},
	{ "clients_db_url",		STR_PARAM,	&accounts_db_url.s},
	{ "clients_db_table",		STR_PARAM,	&acc_db_table.s},
	{ "cients_hash_size",		INT_PARAM,	&acc_hash_size},
	{ "rates_db_url",		STR_PARAM,	&rates_db_url.s},
	{ "rates_db_table",		STR_PARAM,	&ratesheets_db_table.s},
	{ 0,				0,		0}
};

static mi_export_t mi_cmds [] = {
	{ "rc_addVendor",             0, 0, 0, {
		{mi_add_carrier, {"name",  0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_deleteVendor",             0, 0, 0, {
		{mi_delete_carrier, {"name",  0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_getVendorPrice",             0, 0, 0, {
		{mi_get_carrier_price, {"name", "number", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_reloadVendorRate",             0, 0, 0, {
		{mi_reload_carrier_rate, {"name", "rateid", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_deleteVendorRate",             0, 0, 0, {
		{mi_delete_carrier_rate, {"name",  0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_addClient",             0, 0, 0, {
		{mi_add_client, {"name",  0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_deleteClient",             0, 0, 0, {
		{mi_delete_client, {"name",  0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_getClientPrice",             0, 0, 0, {
		{mi_get_client_price, {"name", "wholesale", "number", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_reloadClientRate",             0, 0, 0, {
		{mi_reload_client, {"name", "wholesale", "rateid", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "rc_deleteClientRate",             0, 0, 0, {
		{mi_delete_client_rate, {"name", "wholesale", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static cmd_export_t cmds[]={
	{"get_client_price", (cmd_function)script_get_client_price, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{"get_vendor_price", (cmd_function)script_get_vendor_price, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},  {0,0,0}},
		ALL_ROUTES},
	{"cost_based_filtering",(cmd_function)script_cost_based_filtering, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_VAR, 0, 0},  {0,0,0}},
		ALL_ROUTES},
	{"cost_based_ordering",(cmd_function)script_cost_based_ordering, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_VAR, 0, 0},  {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports= {
	"rate_cacher",
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,
	&deps,			/* OpenSIPS module dependencies */
	cmds,			/* script functions */
	0,			/* exported async functions */
	params,			/* exported parameters */
	0,			/* exported statistics */
	mi_cmds,		/* exported MI functions */
	0,			/* exported pseudo-variables */
	0,			/* exported transformations */
	0,			/* extra processes */
	0,
	mod_init,		/* module initialization function */
	0,
	mod_destroy,		/* module exit function */
	mod_child,		/* per-child init function */
	0
};

static int mod_init(void)
{
	int i;

	LM_INFO("Rate_Cacher module - initializing ...\n");

	carr_db_table.len=strlen(carr_db_table.s);
	acc_db_table.len=strlen(acc_db_table.s);
	ratesheets_db_table.len=strlen(ratesheets_db_table.s);

	/* init carriers hash */
	carr_table = (struct carrier_table*)shm_malloc(
		(sizeof(struct carrier_table) + carr_hash_size*sizeof(struct carrier_entry)));
	if (carr_table == NULL) {
		LM_ERR("No SHM for carrier hash \n");
		return -1;
	}
	carr_table->size = carr_hash_size;
	carr_table->entries = (struct carrier_entry*)(carr_table+1);
	for( i=0 ; i<carr_hash_size; i++ ) {
		memset( &(carr_table->entries[i]), 0, sizeof(struct carrier_entry));
		carr_table->entries[i].lock = lock_init_rw();
		if (carr_table->entries[i].lock == NULL) {
			LM_ERR("Failed to init carrier hash lock \n");
			return -1;
		}
	}

	/* init accounts hash */
	acc_table = (struct accounts_table*)shm_malloc(
		(sizeof(struct accounts_table) + acc_hash_size*sizeof(struct account_entry)));
	if (acc_table == NULL) {
		LM_ERR("No SHM for accounts hash \n");
		return -1;
	}
	acc_table->size = acc_hash_size;
	acc_table->entries = (struct account_entry*)(acc_table+1);
	for( i=0 ; i<acc_hash_size; i++ ) {
		memset( &(acc_table->entries[i]), 0, sizeof(struct account_entry));
		acc_table->entries[i].lock = lock_init_rw();
		if (acc_table->entries[i].lock == NULL) {
			LM_ERR("Failed to init account hash lock \n");
			return -1;
		}
	}

	/* init DB connection */
	init_db_url( carriers_db_url , 0 /*cannot be null*/);
	init_db_url( accounts_db_url , 0 /*cannot be null*/);
	init_db_url( rates_db_url , 0 /*cannot be null*/);

	if (db_bind_mod( &carriers_db_url, &carriers_dbf  )) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		return -1;
	}

	if (db_bind_mod(&accounts_db_url, &accounts_dbf)) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		return -1;
	}

	if (db_bind_mod(&rates_db_url, &rates_dbf)) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		return -1;
	}

	/* load all the data at startup, anyway we don't do any other stuff except rate caching */

	if ( (carriers_db_hdl=carriers_dbf.init(&carriers_db_url))==0 ) {
		LM_CRIT("cannot initialize carriers database connection\n");
		return -1;
	}

	if ( (accounts_db_hdl=accounts_dbf.init(&accounts_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	if ( (rates_db_hdl=rates_dbf.init(&rates_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	if (rate_cacher_load_all_info() < 0) {
		LM_ERR("Failed to load all data from the DB\n");
		return -1;
	}

	carriers_dbf.close(carriers_db_hdl);
	carriers_db_hdl = NULL;
	accounts_dbf.close(accounts_db_hdl);
	accounts_db_hdl = NULL;
	rates_dbf.close(rates_db_hdl);
	rates_db_hdl = NULL;

	return 0;
}

static int mod_child(int rank)
{
	if ( (carriers_db_hdl=carriers_dbf.init(&carriers_db_url))==0 ) {
		LM_CRIT("cannot initialize carriers database connection\n");
		return -1;
	}

	if ( (accounts_db_hdl=accounts_dbf.init(&accounts_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	if ( (rates_db_hdl=rates_dbf.init(&rates_db_url))==0 ) {
		LM_CRIT("cannot initialize accounts database connection\n");
		return -1;
	}

	return 0;
}

void mod_destroy(void)
{
	struct carrier_entry *carr_entry;
	struct carrier_cell *carr_it,*next_carr;
	struct account_entry* cl_entry;
	struct account_cell* cl_it,*next_cl;
	int bucket;

	for (bucket=0;bucket<carr_table->size;bucket++) {
		carr_entry = &(carr_table->entries[bucket]);
		for (carr_it=carr_entry->first;carr_it;carr_it=next_carr) {
			next_carr = carr_it->next;
			free_carrier_cell(carr_it);
		}
	}


	for (bucket=0;bucket<acc_table->size;bucket++) {
		cl_entry = &(acc_table->entries[bucket]);
		for (cl_it=cl_entry->first;cl_it;cl_it=next_cl) {
			next_cl=cl_it->next;
			if (cl_it->ws_rate_table.s)
				shm_free(cl_it->ws_rate_table.s);
			if (cl_it->rt_rate_table.s && cl_it->rt_rate_table.s != cl_it->ws_rate_table.s)
				shm_free(cl_it->rt_rate_table.s);
			if (cl_it->ws_rate_currency.s)
				shm_free(cl_it->ws_rate_currency.s);
			if (cl_it->rt_rate_currency.s && cl_it->rt_rate_currency.s != cl_it->ws_rate_currency.s)
				shm_free(cl_it->rt_rate_currency.s);
			if (cl_it->ws_trie)
				free_trie(cl_it->ws_trie);
			if (cl_it->rt_trie && cl_it->rt_trie != cl_it->ws_trie)
				free_trie(cl_it->rt_trie);
			shm_free(cl_it);
		}
	}
}

struct ratesheet_cell_entry* build_rate_prefix_entry(str *destination,double price,
	int minimum,int increment)
{

	struct ratesheet_cell_entry* new_cell = shm_malloc(sizeof(struct ratesheet_cell_entry)+
		destination->len);
	if (new_cell == NULL) {
		LM_ERR("No more SHM for prefix entry\n");
		return NULL;
	}

	memset(new_cell,0,sizeof(struct ratesheet_cell_entry));
	new_cell->price = price;
	new_cell->minimum = minimum;
	new_cell->increment = increment;
	new_cell->destination.s = (char *)(new_cell+1);
	new_cell->destination.len = destination->len;
	memcpy(new_cell->destination.s,destination->s,destination->len);

	return new_cell; 
} 

struct ratesheet_cell_entry* get_rate_price_prefix(ptree_t *ptree,str* in_prefix,unsigned int *matched_len)
{
	struct ratesheet_cell_entry *rt = NULL;
	char *tmp=NULL;
	char local=0;
	int idx=0;
	str prefix;

	if(NULL == ptree)
		goto err_exit;
	if(NULL == in_prefix)
		goto err_exit;

	if (in_prefix->len == 1 && (in_prefix->s[0] == 'x' || in_prefix->s[0] == 'X'))
		goto err_exit;

	prefix = *in_prefix;
	if (prefix.s[prefix.len-1] == 'x' || prefix.s[prefix.len-1] == 'X')
		prefix.len--;

	tmp = prefix.s;
	/* dst matching, make sure it's all digits */
	while(tmp < (prefix.s+prefix.len)) {
		if( !IS_DECIMAL_DIGIT(*tmp) ) {
			LM_ERR("DST [%.*s] is not digit only \n",prefix.len,prefix.s);
			return NULL;
		}
		tmp++;
	}

	tmp = prefix.s;
	if(NULL == tmp)
		goto err_exit;
	/* go the tree down to the last digit in the
	 * prefix string or down to a leaf */
	while(tmp< (prefix.s+prefix.len)) {
		local=*tmp;
		if( tmp == (prefix.s+prefix.len-1) || *tmp == 'x' ) {
			/* last digit in the prefix string */
			break;
		}
		idx = local -'0';
		if( NULL == ptree->ptnode[idx].next) {
			/* this is a leaf */
			break;
		}
		ptree = ptree->ptnode[idx].next;
		tmp++;
	}
	/* go in the tree up to the root trying to match the
	 * prefix */
	if (*tmp == 'x')
		tmp--;

	while(ptree !=NULL ) {
		/* is it a real node or an intermediate one */
		idx = *tmp-'0';
		if(NULL != ptree->ptnode[idx].re) {
			/* real node */
			rt = ptree->ptnode[idx].re;
			break;
		}
		tmp--;
		ptree = ptree->bp;
	}

	if (matched_len) *matched_len = tmp + 1 - prefix.s ;
	return rt;

err_exit:
	return NULL;
}

int add_price_prefix(ptree_t *ptree,str* prefix,struct ratesheet_cell_entry *value)
{
	char* tmp=NULL;

	if(ptree == NULL)
		goto err_exit;

	tmp = prefix->s;
	while(tmp < (prefix->s+prefix->len)) {
		if(NULL == tmp)
			goto err_exit;
		if( !IS_DECIMAL_DIGIT(*tmp) ) {
			/* unknown character in the prefix string */
			goto err_exit;
		}
		if( tmp == (prefix->s+prefix->len-1) ) {
			/* last digit in the prefix string */
			ptree->ptnode[*tmp-'0'].re = value;
			goto ok_exit;
		}
		/* process the current digit in the prefix */
		if(NULL == ptree->ptnode[*tmp - '0'].next) {
			/* allocate new node */
			INIT_PTREE_NODE(ptree, ptree->ptnode[*tmp - '0'].next);
		}
		ptree = ptree->ptnode[*tmp-'0'].next;
		tmp++;
	}

ok_exit:
	return 0;

err_exit:
	return -1;
}

static void free_trie(ptree_t* t)
{
	int i;
	if(NULL == t)
		return;

	/* delete all the children */
	for(i=0; i< PTREE_CHILDREN; i++) {
		if(t->ptnode[i].re != NULL) {
			shm_free(t->ptnode[i].re);
		}
		/* if non leaf delete all the children */
		if(t->ptnode[i].next != NULL)
			free_trie(t->ptnode[i].next);
	} 

	shm_free(t);    
}               

static void free_carrier_cell(struct carrier_cell *carr)
{
	if (carr->rate_table.s)
		shm_free(carr->rate_table.s);
	if (carr->rate_currency.s)
		shm_free(carr->rate_currency.s);
	free_trie(carr->trie);

	shm_free(carr);
}

static void lock_bucket_read(rw_lock_t *lock)
{
	lock_start_read(lock);
}

static void unlock_bucket_read(rw_lock_t *lock)
{
	lock_stop_read(lock);
}

static void lock_bucket_write(rw_lock_t *lock)
{
	lock_start_write(lock);
}

static void unlock_bucket_write(rw_lock_t *lock)
{
	lock_stop_write(lock);
}

static int reload_carrier_rate(str *carrierid, int rate_id)
{
	struct carrier_entry *entry;
	struct ratesheet_cell_entry* rs_entry;
	struct carrier_cell *it=NULL;
	str currency,rate_table,destination,prefix;
	int bucket,i,no_rows=10;
	db_key_t columns[5];
	db_res_t* res=NULL;
	db_row_t* row;
	db_key_t key_cmp;
	db_val_t val_cmp;
	ptree_t* new_trie;

	if (rate_id == 0)
		return -1;

	currency.s = NULL;
	rate_table.s = NULL;

	bucket = core_hash(carrierid,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	/* quickly lookup the carrier to see if it exists */
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrierid->len &&
		memcmp(it->carrierid.s,carrierid->s,carrierid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		LM_ERR("Could not find carrier %.*s - cannot reload \n",carrierid->len,carrierid->s);
		return -1;
	}

	if (it->reload_pending == 1) {
		LM_WARN("Reload already triggered for carrier %.*s - aborting this attempt\n",carrierid->len,carrierid->s);
		unlock_bucket_write( entry->lock );
		return 1;
	}
		
	it->reload_pending = 1;
	unlock_bucket_write( entry->lock );

	INIT_PTREE_NODE(NULL, new_trie);

	/* load the ratesheet */
	if (rates_dbf.use_table( rates_db_hdl, &ratesheets_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_unlock_pending;
	}

	columns[0] = &rs_currency_col;
	columns[1] = &rs_table_col;

	key_cmp = &rs_rateid_col;
	val_cmp.type = DB_INT;
	val_cmp.nul  = 0;
	val_cmp.val.int_val = rate_id;

	if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 2, 0, &res) < 0) {
		LM_ERR("Ratesheets DB query failed\n");
		goto err_unlock_pending;
	}

	if (RES_ROW_N(res) != 1) {
		LM_ERR("%d Rows returned for the rate of carrier %.*s\n",RES_ROW_N(res),carrierid->len,carrierid->s);
		goto err_carr_free;
	}

	row = RES_ROWS(res);

	/* duplicate to SHM now, we'll do another query to the rates DB */
	currency.s = (char *)(VAL_STRING(ROW_VALUES(row))); 

	currency.len = strlen(VAL_STRING(ROW_VALUES(row)));
	currency.s = shm_malloc(currency.len);
	if (currency.s == NULL) {
		LM_ERR("No more shm memory for currency\n");
		goto err_carr_free;
	}
	memcpy(currency.s,VAL_STRING(ROW_VALUES(row)),currency.len);

	rate_table.len = strlen(VAL_STRING(ROW_VALUES(row)+1));
	rate_table.s = shm_malloc(rate_table.len);
	if (rate_table.s == NULL) {
		LM_ERR("No more shm memory for rate table \n");
		goto err_carr_free;
	}
	memcpy(rate_table.s,VAL_STRING(ROW_VALUES(row)+1),rate_table.len);

	rates_dbf.free_result(rates_db_hdl, res);
	res = NULL;
	
	LM_INFO("Got rate in table %.*s with currency %.*s\n",rate_table.len,rate_table.s,currency.len,currency.s);

	if (rates_dbf.use_table( rates_db_hdl, &rate_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_carr_free;
	}

	columns[0] = &rs_destination_col;
	columns[1] = &rs_cc_col;
	columns[2] = &rs_price_col;
	columns[3] = &rs_minimum_col;
	columns[4] = &rs_increment_col;

	if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 5, 0, 0) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_carr_free;
		}
		no_rows=10000;
		/*
		if (no_rows==0)
			no_rows=10;
		*/
		if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
			LM_ERR("Failed to fetch %d rows\n",no_rows);	
			goto err_carr_free;
		}	
	} else {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 5, 0, &res) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_carr_free;
		}
	}

	LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			destination.s = (char *)VAL_STRING(ROW_VALUES(row));
			destination.len = strlen(destination.s);
			rs_entry = build_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4));
			if (rs_entry == NULL) {
				LM_ERR("Failed to build prefix rule \n");
				goto err_carr_free;
			}

			prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
			prefix.len = strlen(prefix.s);

			if (add_price_prefix(new_trie,&prefix,rs_entry)<0) {
				LM_ERR("Failed to add prefix to carrier trie\n");
				goto err_carr_free;
			}
		}
		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_carr_free;
			}	
			LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	rates_dbf.free_result(rates_db_hdl, res);

	lock_bucket_write( entry->lock );

	if (it->rate_table.s)
		shm_free(it->rate_table.s);
	if (it->rate_currency.s)
		shm_free(it->rate_currency.s);
	free_trie(it->trie);

	it->rateid = rate_id;
	it->rate_table = rate_table;
	it->rate_currency = currency;
	it->trie = new_trie;
	it->reload_pending = 0;
	
	unlock_bucket_write( entry->lock );

	return 0;

err_carr_free:
	if (res)
		rates_dbf.free_result(rates_db_hdl, res);
	if (new_trie)
		free_trie(new_trie);
	if (rate_table.s)
		shm_free(rate_table.s);
	if (currency.s)
		shm_free(currency.s);
err_unlock_pending:
	lock_bucket_write( entry->lock );
	it->reload_pending = 0;
	unlock_bucket_write( entry->lock );

	return -1;
}

static int reload_client_rate(str *accountid, int wholesale,int rate_id,int startup)
{
	db_key_t columns[5];
	db_res_t* res=NULL;
	db_row_t* row;
	db_key_t key_cmp;
	db_val_t val_cmp;
	str currency,rate_table,destination,prefix;
	int bucket,i,no_rows=10;
	struct account_entry *entry;
	struct account_cell *it;
	struct ratesheet_cell_entry* rs_entry;
	ptree_t* new_trie=NULL;

	if (rate_id == 0)
		return -1;

	rate_table.s = NULL;
	currency.s = NULL;

	bucket = core_hash(accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid->len &&
		memcmp(it->accountid.s,accountid->s,accountid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("No such account %.*s\n",accountid->len,accountid->s);
		unlock_bucket_write( entry->lock );
		return -2;
	}

	if (wholesale) {
		if (it->ws_reload_pending) {
			LM_WARN("Reload already triggered for account %.*s on wholesale - aborting this attempt\n",accountid->len,accountid->s);
			unlock_bucket_write( entry->lock );
			return 1;
		}
		it->ws_reload_pending = 1;
	} else {
		if (it->rt_reload_pending) {
			LM_WARN("Reload already triggered for account %.*s on retail - aborting this attempt\n",accountid->len,accountid->s);
			unlock_bucket_write( entry->lock );
			return 1;
		}
		it->rt_reload_pending = 1;
	}

	unlock_bucket_write( entry->lock );

	if (startup) {
		/* at startup we always load wholesale first, and then retail */
		/* just set the pointers for retail to the wholesale trie, if the rates are the same */
		if (wholesale==0 && it->ws_rateid == rate_id) { 
			it->rt_rate_table = it->ws_rate_table;
			it->rt_rate_currency = it->ws_rate_currency;
			it->rt_trie = it->ws_trie;	
			it->rt_rateid = rate_id;
			it->rt_reload_pending = 0;
			return 1;
		}
	}

	INIT_PTREE_NODE(NULL, new_trie);

	/* load the ratesheet */
	if (rates_dbf.use_table( rates_db_hdl, &ratesheets_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_unlock_pending;
	}

	columns[0] = &rs_currency_col;
	columns[1] = &rs_table_col;

	key_cmp = &rs_rateid_col;
	val_cmp.type = DB_INT;
	val_cmp.nul  = 0;
	val_cmp.val.int_val = rate_id;

	if ( rates_dbf.query( rates_db_hdl, &key_cmp, 0, &val_cmp, columns, 1, 2, 0, &res) < 0) {
		LM_ERR("Ratesheets DB query failed\n");
		goto err_unlock_pending;
	}

	if (RES_ROW_N(res) != 1) {
		LM_ERR("%d Rows returned for the rate ( type %d ) of client %.*s\n",RES_ROW_N(res),wholesale,accountid->len,accountid->s);
		goto err_account_free;
	}

	row = RES_ROWS(res);

	/* duplicate to SHM now, we'll do another query to the rates DB */
	currency.s = (char *)(VAL_STRING(ROW_VALUES(row))); 

	currency.len = strlen(VAL_STRING(ROW_VALUES(row)));
	currency.s = shm_malloc(currency.len);
	if (currency.s == NULL) {
		LM_ERR("No more shm memory for currency \n");
		goto err_account_free;
	}
	memcpy(currency.s,VAL_STRING(ROW_VALUES(row)),currency.len);

	rate_table.len = strlen(VAL_STRING(ROW_VALUES(row)+1));
	rate_table.s = shm_malloc(rate_table.len);
	if (rate_table.s == NULL) {
		shm_free(currency.s);
		LM_ERR("No more shm memory for rate table \n");
		goto err_account_free;
	}
	memcpy(rate_table.s,VAL_STRING(ROW_VALUES(row)+1),rate_table.len);

	rates_dbf.free_result(rates_db_hdl, res);
	res = NULL;

	LM_INFO("Got rate in table %.*s with currency %.*s\n",rate_table.len,rate_table.s,currency.len,currency.s);

	if (rates_dbf.use_table( rates_db_hdl, &rate_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		goto err_account_free;
	}

	columns[0] = &rs_destination_col;
	columns[1] = &rs_cc_col;
	columns[2] = &rs_price_col;
	columns[3] = &rs_minimum_col;
	columns[4] = &rs_increment_col;

	if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 5, 0, 0) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_account_free;
		}
		no_rows=10000;
		/*
		if (no_rows==0)
			no_rows=10;
		*/
		if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
			LM_ERR("Failed to fetch %d rows\n",no_rows);	
			goto err_account_free;
		}	
	} else {
		if ( rates_dbf.query( rates_db_hdl, 0, 0, 0, columns, 0, 5, 0, &res) < 0) {
			LM_ERR("Ratesheets DB query failed\n");
			goto err_account_free;
		}
	}

	LM_INFO("%d records found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			destination.s = (char *)VAL_STRING(ROW_VALUES(row));
			destination.len = strlen(destination.s);
			rs_entry = build_rate_prefix_entry(&destination,VAL_DOUBLE(ROW_VALUES(row)+2),VAL_INT(ROW_VALUES(row)+3),VAL_INT(ROW_VALUES(row)+4));
			if (rs_entry == NULL) {
				LM_ERR("Failed to build prefix rule \n");
				goto err_account_free;
			}

			prefix.s = (char *)VAL_STRING(ROW_VALUES(row)+1);
			prefix.len = strlen(prefix.s);

			if (add_price_prefix(new_trie,&prefix,rs_entry)<0) {
				LM_ERR("Failed to add prefix to carrier trie\n");
				goto err_account_free;
			}
		}
		if (DB_CAPABILITY(rates_dbf, DB_CAP_FETCH)) {
			if (rates_dbf.fetch_result(rates_db_hdl,&res,no_rows) < 0) {
				LM_ERR("Failed to fetch %d rows\n",no_rows);	
				goto err_account_free;
			}	
			LM_INFO("%d records more found in %.*s table \n",RES_ROW_N(res),rate_table.len,rate_table.s);
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);
	rates_dbf.free_result(rates_db_hdl, res);

	/* loaded everything, perform the changes */

	lock_bucket_write( entry->lock );

	if (wholesale ) {
		if (it->ws_rateid != it->rt_rateid) {
			/* free old info only if it wasn't shared */
			if (it->ws_rate_table.s)
				shm_free(it->ws_rate_table.s);
			if (it->ws_rate_currency.s)
				shm_free(it->ws_rate_currency.s);
			if (it->ws_trie)
				free_trie(it->ws_trie);
		}
		it->ws_rate_table = rate_table;
		it->ws_rate_currency = currency;
		it->ws_trie = new_trie;
		it->ws_rateid = rate_id;

		if (it->rt_rateid == rate_id) {
			/* retail used the same rate that we've assigned now for retail - free retail info and link it here */
			if (it->rt_rate_table.s)
				shm_free(it->rt_rate_table.s);
			if (it->rt_rate_currency.s)
				shm_free(it->rt_rate_currency.s);
			if (it->rt_trie)
				free_trie(it->rt_trie);

			it->rt_rate_table = it->ws_rate_table;
			it->rt_rate_currency = it->ws_rate_currency;
			it->rt_trie = it->ws_trie;	
		}
		it->ws_reload_pending = 0;
	} else {
		if (it->ws_rateid != it->rt_rateid) {
			/* free old info only if it wasn't shared */
			if (it->rt_rate_table.s)
				shm_free(it->rt_rate_table.s);
			if (it->rt_rate_currency.s)
				shm_free(it->rt_rate_currency.s);
			if (it->rt_trie)
				free_trie(it->rt_trie);
		}
		it->rt_rate_table = rate_table;
		it->rt_rate_currency = currency;
		it->rt_trie = new_trie;
		it->rt_rateid = rate_id;

		if (it->ws_rateid == rate_id) {
			/* wholesale used the same rate that we've assigned now for retail - free wholesale info and link it here */
			if (it->ws_rate_table.s)
				shm_free(it->ws_rate_table.s);
			if (it->ws_rate_currency.s)
				shm_free(it->ws_rate_currency.s);
			if (it->ws_trie)
				free_trie(it->ws_trie);
			
			it->ws_rate_table = it->rt_rate_table;
			it->ws_rate_currency = it->rt_rate_currency;
			it->ws_trie = it->rt_trie; 
		}
		it->rt_reload_pending = 0;
	}
	unlock_bucket_write( entry->lock );

	return 0;

err_account_free:
	if (res)
		rates_dbf.free_result(rates_db_hdl, res);
	if (rate_table.s)
		shm_free(rate_table.s);
	if (currency.s)
		shm_free(currency.s);
	if (new_trie)
		free_trie(it->rt_trie);
err_unlock_pending:
	lock_bucket_write( entry->lock );
	if (wholesale) {
		it->ws_reload_pending = 0;
	} else {
		it->rt_reload_pending = 0;
	}
	unlock_bucket_write( entry->lock );

	return -1;
}

static int rate_cacher_load_all_info(void) 
{
	db_key_t columns[6];
	db_res_t* res;
	db_row_t* row;
	str carrierid,accountid;
	int i;

	/* load all the carriers */
	if (carriers_dbf.use_table( carriers_db_hdl, &carr_db_table) < 0) {
		LM_ERR("cannot use carriers table \n");
		return -1;
	}

	columns[0] = &carr_id_col;
	columns[1] = &carr_rateid_col;

	if ( carriers_dbf.query( carriers_db_hdl, 0, 0, 0, columns, 0, 2, 0, &res) < 0) {
		LM_ERR("Carriers DB query failed\n");
		return -1;
	}

	LM_DBG("%d records found in dr_carriers table \n",RES_ROW_N(res));

	for(i=0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;
		carrierid.s = (char *)(VAL_STRING(ROW_VALUES(row)));
		carrierid.len = strlen(carrierid.s);

		if (add_carrier(&carrierid,0) != 0)
			continue;

		if (reload_carrier_rate(&carrierid,VAL_NULL(ROW_VALUES(row)+1)?0:VAL_INT(ROW_VALUES(row)+1)) < 0) {
			if (!VAL_NULL(ROW_VALUES(row)+1) && VAL_INT(ROW_VALUES(row)+1) != 0)
				LM_ERR("Failed to load carrier %s with rateid %d\n",
				VAL_STRING(ROW_VALUES(row)),VAL_NULL(ROW_VALUES(row)+1)?0:VAL_INT(ROW_VALUES(row)+1));
		} else
			LM_INFO("Loaded carrier %s with rateid %d\n",
			VAL_STRING(ROW_VALUES(row)),VAL_INT(ROW_VALUES(row)+1));
	}

	carriers_dbf.free_result(carriers_db_hdl, res);

	/* load all the accounts */
	if (accounts_dbf.use_table( accounts_db_hdl, &acc_db_table) < 0) {
		LM_ERR("cannot use accounts table \n");
		return -1;
	}
	columns[0] = &acc_id_col;
	columns[1] = &acc_ws_rateid_col;
	columns[2] = &acc_rt_rateid_col;

	if ( accounts_dbf.query( accounts_db_hdl, 0, 0, 0, columns, 0, 3, 0, &res) < 0) {
		LM_ERR("Accounts DB query failed\n");
		return -1;
	}

	LM_DBG("%d records found in accounts table \n",RES_ROW_N(res));

	for(i=0; i < RES_ROW_N(res); i++) {
		row = RES_ROWS(res) + i;
		accountid.s = (char *)VAL_STRING(ROW_VALUES(row));
		accountid.len = strlen(VAL_STRING(ROW_VALUES(row)));

		if (add_client(&accountid,0) != 0) {
			LM_ERR("Failed to add account %.*s\n",accountid.len,accountid.s);
			continue;
		}

		if (reload_client_rate(&accountid,1,VAL_INT(ROW_VALUES(row)+1),1) < 0) {
			if (VAL_INT(ROW_VALUES(row)+1) != 0)
				LM_ERR("Failed to load ws rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+1),accountid.len,accountid.s);
		} else
			LM_INFO("Loaded ws rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+1),accountid.len,accountid.s);

		if (reload_client_rate(&accountid,0,VAL_INT(ROW_VALUES(row)+2),1) < 0) {
			if (VAL_INT(ROW_VALUES(row)+2) != 0)
				LM_ERR("Failed to load rt rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+2),accountid.len,accountid.s);
		} else
			LM_INFO("Loaded rt rate %d for account %.*s\n",VAL_INT(ROW_VALUES(row)+2),accountid.len,accountid.s);
	}

	accounts_dbf.free_result(accounts_db_hdl, res);

	return 0;
}

static mi_response_t * mi_get_carrier_price(const mi_params_t *params,struct mi_handler *async_hdl)
{
	struct carrier_cell *it;
	struct carrier_entry *entry;
	int bucket;
	unsigned int matched_len;
	str carrier;
	str prefix;
	struct ratesheet_cell_entry *ret;
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;

	if (get_mi_string_param(params, "name",
		&carrier.s, &carrier.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "number",
		&prefix.s, &prefix.len) < 0)
		return init_mi_param_error();

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_error( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	ret = get_rate_price_prefix(it->trie,&prefix,&matched_len);
	if (ret == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_error( 401, "No prefix match", sizeof("No prefix match")-1);
	}

	resp = init_mi_result_object(&resp_obj);
	if (resp==NULL) {
		goto error_internal_unlock;
	}

	if (add_mi_string(resp_obj, "prefix", 6, prefix.s, matched_len) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	if (add_mi_string(resp_obj, "destination", 11, 
		ret->destination.s,ret->destination.len) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	if (add_mi_number(resp_obj, "price", 5,ret->price) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	if (add_mi_number(resp_obj, "minimum", 7,(double)ret->minimum) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	if (add_mi_number(resp_obj, "increment", 9,(double)ret->increment) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	if (add_mi_string(resp_obj, "currency", 8, 
		it->rate_currency.s,it->rate_currency.len) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	
	unlock_bucket_read( entry->lock );
	return resp;

error_internal_unlock:
	unlock_bucket_read( entry->lock );
	free_mi_response(resp);
	return init_mi_error( 400, MI_SSTR("Internal Error"));
}

static mi_response_t * mi_reload_carrier_rate(const mi_params_t *params,struct mi_handler *async_hdl)
{
	int rate_id;
	str carrier;

	if (get_mi_string_param(params, "name",
		&carrier.s, &carrier.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "rateid", &rate_id) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - reloadCarrierRate %.*s %d\n",carrier.len,carrier.s,rate_id); 

	if (reload_carrier_rate(&carrier,rate_id) < 0)
		return init_mi_error( 500, "Failed to reload", sizeof("Failed to reload")-1);
	else
    		return init_mi_result_ok();
}

static int add_client(str *accountid, int safe)
{
	int bucket;
	struct account_entry *entry;
	struct account_cell *it;

	bucket = core_hash(accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	if (safe)
		lock_bucket_write( entry->lock );

	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid->len &&
		memcmp(it->accountid.s,accountid->s,accountid->len) == 0) {
			break;
		}
	}

	if (it != NULL) {
		LM_ERR("Account %.*s already exists \n",accountid->len,accountid->s);
		if (safe)
			unlock_bucket_write( entry->lock );
		return 1;
	}

	it = (struct account_cell*)shm_malloc(sizeof(struct account_cell) + accountid->len);
	if (it == NULL) {
		LM_ERR("Failed to allocate shm for account cell \n");
		if (safe)
			unlock_bucket_write( entry->lock );
		return -1;
	}
		
	memset(it,0,sizeof(struct account_cell));

	it->accountid.s = (char *)(it+1);
	it->accountid.len = accountid->len;
	memcpy(it->accountid.s,accountid->s,accountid->len);

	if (entry->first==NULL) {
		entry->first = entry->last = it;
	} else {
		entry->last->next = it;
		it->prev = entry->last;
		entry->last = it;
	}

	if (safe)
		unlock_bucket_write( entry->lock );

	return 0;
}

static int add_carrier(str *carrier,int safe)
{
	int bucket;
	struct carrier_entry *entry;
	struct carrier_cell *carr_cell,*it=NULL;

	bucket = core_hash(carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	if (safe)
		lock_bucket_write( entry->lock );

	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier->len &&
		memcmp(it->carrierid.s,carrier->s,carrier->len) == 0) {
			break;
		}
	}

	if (it != NULL) {
		LM_ERR("Carrier %.*s already exists \n",carrier->len,carrier->s);
		if (safe)
			unlock_bucket_write( entry->lock );
		return 1;
	}

	carr_cell = (struct carrier_cell *)shm_malloc(sizeof(struct carrier_cell) + carrier->len);
	if (carr_cell == NULL) {
		LM_ERR("Failed to allocate shm for carrier cell \n");
		if (safe)
			unlock_bucket_write( entry->lock );
		return -1;
	}

	/* init carrier */
	memset(carr_cell,0,sizeof(struct carrier_cell));

	carr_cell->carrierid.s = (char *)(carr_cell+1);
	carr_cell->carrierid.len = carrier->len;
	memcpy(carr_cell->carrierid.s,carrier->s,carrier->len);

	/* link the new carrier */
	if (entry->first==NULL) {
		entry->first = entry->last = carr_cell;
	} else {
		entry->last->next = carr_cell;
		carr_cell->prev = entry->last;
		entry->last = carr_cell;
	}

	if (safe)
		unlock_bucket_write( entry->lock );

	return 0;
}

static mi_response_t * mi_add_carrier(const mi_params_t *params,struct mi_handler *async_hdl)
{
	str carrier;
	int rc;

	if (get_mi_string_param(params, "name",
		&carrier.s, &carrier.len) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - addCarrier %.*s\n",carrier.len,carrier.s);
	rc = add_carrier(&carrier,1);
	if (rc < 0)
		return init_mi_error( 500, "Failed to add", sizeof("Failed to add")-1);
	else if (rc > 0)
		return init_mi_error( 402, "Carrier exists", sizeof("Carrier exists")-1);
	else
    		return init_mi_result_ok();
}

static mi_response_t * mi_delete_carrier_rate(const mi_params_t *params,struct mi_handler *async_hdl)
{
	struct carrier_entry *entry;
	struct carrier_cell *it;
	int bucket;
	str carrier;

	if (get_mi_string_param(params, "name",
		&carrier.s, &carrier.len) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - deleteCarrierRate %.*s\n",carrier.len,carrier.s);

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);
	
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		return init_mi_error( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	if (it->reload_pending) {
		unlock_bucket_write( entry->lock );
		return init_mi_error( 401, "Pending Reload", sizeof("Pending Reload")-1);
	}

	if (it->rate_table.s)
		shm_free(it->rate_table.s);
	if (it->rate_currency.s)
		shm_free(it->rate_currency.s);
	free_trie(it->trie);
	it->trie = NULL;
	it->rateid = 0;

	unlock_bucket_write( entry->lock );
	return init_mi_result_ok();
}

static mi_response_t * mi_delete_carrier(const mi_params_t *params,struct mi_handler *async_hdl)
{
	struct carrier_entry *entry;
	struct carrier_cell *it;
	int bucket;
	str carrier;

	if (get_mi_string_param(params, "name",
		&carrier.s, &carrier.len) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - deleteCarrier %.*s\n",carrier.len,carrier.s);

	bucket = core_hash(&carrier,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);
	
	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == carrier.len &&
		memcmp(it->carrierid.s,carrier.s,carrier.len) == 0) {
			break;
		}
	}
	if (it == NULL) {
		unlock_bucket_write( entry->lock );
		return init_mi_error( 401, "No such carrier", sizeof("No such carrier")-1);
	}

	if (it->next)
		it->next->prev = it->prev;
	else
		entry->last = it->prev;
	if (it->prev)
		it->prev->next = it->next;
	else
		entry->first = it->next;
	it->next = it->prev = 0;
	
	unlock_bucket_write( entry->lock );

	free_carrier_cell(it);
	return init_mi_result_ok();
}

static mi_response_t * mi_get_client_price(const mi_params_t *params,struct mi_handler  *async_hdl)
{
	struct account_cell *it;
	struct account_entry *entry;
	int bucket,is_wholesale;
	unsigned int matched_len;
	str accountid;
	str prefix;
	struct ratesheet_cell_entry *ret;
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;

	if (get_mi_string_param(params, "name",
		&accountid.s, &accountid.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "wholesale",&is_wholesale) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "number",
		&prefix.s, &prefix.len) < 0)
		return init_mi_param_error();

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_error( 401, "No such client", sizeof("No such client")-1);
	}

	if (is_wholesale)
		ret = get_rate_price_prefix(it->ws_trie,&prefix,&matched_len);
	else
		ret = get_rate_price_prefix(it->rt_trie,&prefix,&matched_len);

	if (ret == NULL) {
		unlock_bucket_read( entry->lock );
		return init_mi_error( 401, "No prefix match", sizeof("No prefix match")-1);
	}

	resp = init_mi_result_object(&resp_obj);
	if (resp==NULL) {
		goto error_internal_unlock;
	}

	if (add_mi_string(resp_obj, "prefix", 6, prefix.s, matched_len) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}
	if (add_mi_string(resp_obj, "destination", 11, 
		ret->destination.s,ret->destination.len) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}

	if (add_mi_number(resp_obj, "price", 5, ret->price) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}

	if (add_mi_number(resp_obj, "minimum", 7, (double)ret->minimum) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}

	if (add_mi_number(resp_obj, "increment", 9, (double)ret->increment) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}

	if (add_mi_string(resp_obj, "currency", 8, 
	is_wholesale?it->ws_rate_currency.s:it->rt_rate_currency.s,
	is_wholesale?it->ws_rate_currency.len:it->rt_rate_currency.len) < 0) {
		LM_ERR("failed to mi item\n");
		goto error_internal_unlock;
	}

	unlock_bucket_read( entry->lock );
	return resp;

error_internal_unlock:
	unlock_bucket_read( entry->lock );
	free_mi_response(resp);
	return init_mi_error( 400, MI_SSTR("Internal Error"));
}

static mi_response_t * mi_reload_client(const mi_params_t *params,struct mi_handler *async_hdl)
{
	int rate_id,is_wholesale,ret;
	str accountid;

	if (get_mi_string_param(params, "name",
		&accountid.s, &accountid.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "wholesale",&is_wholesale) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "rateid",&rate_id) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - reloadClientRate %.*s %d %d\n",accountid.len,accountid.s,is_wholesale,rate_id);

	ret = reload_client_rate(&accountid,is_wholesale,rate_id,0);
	if (ret == -2)
		return init_mi_error( 401, "No such client", sizeof("No such client")-1);
	else if (ret < 0)
		return init_mi_error( 500, "Failed to reload", sizeof("Failed to reload")-1);
	else
		return init_mi_result_ok();
}

static mi_response_t * mi_add_client(const mi_params_t *params,struct mi_handler *async_hdl)
{
	str accountid;
	int rc;

	if (get_mi_string_param(params, "name",
		&accountid.s, &accountid.len) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - addClient %.*s\n",accountid.len,accountid.s);

	rc = add_client(&accountid,1);
	if (rc < 0)
		return init_mi_error( 500, "Failed to add", sizeof("Failed to add")-1);
	else if (rc > 0)
		return init_mi_error( 402, "Account exists", sizeof("Carrier exists")-1);
	else
		return init_mi_result_ok();
}

static mi_response_t * mi_delete_client(const mi_params_t *params,struct mi_handler *async_hdl)
{
	str accountid;
	int bucket;
	struct account_entry* entry;
	struct account_cell* it;

	if (get_mi_string_param(params, "name",
		&accountid.s, &accountid.len) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - deleteClient %.*s\n",accountid.len,accountid.s);

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("Client %.*s does not exist \n",accountid.len,accountid.s);
		unlock_bucket_write( entry->lock );
		return init_mi_error( 401, "No such client", sizeof("No such client")-1);
	}

	/* unlink the client from the hash */
	if (it->next)
		it->next->prev = it->prev;
	else
		entry->last = it->prev;
	if (it->prev)
		it->prev->next = it->next;
	else
		entry->first = it->next;
	it->next = it->prev = 0;

	unlock_bucket_write( entry->lock );

	if (it->ws_rate_table.s)
		shm_free(it->ws_rate_table.s);
	if (it->rt_rate_table.s && it->rt_rate_table.s != it->ws_rate_table.s)
		shm_free(it->rt_rate_table.s);
	if (it->ws_rate_currency.s)
		shm_free(it->ws_rate_currency.s);
	if (it->rt_rate_currency.s && it->rt_rate_currency.s != it->ws_rate_currency.s)
		shm_free(it->rt_rate_currency.s);
	if (it->ws_trie)
		free_trie(it->ws_trie);
	if (it->rt_trie && it->rt_trie != it->ws_trie)
		free_trie(it->rt_trie);
	shm_free(it);

	return init_mi_result_ok();
}

static mi_response_t * mi_delete_client_rate(const mi_params_t *params,struct mi_handler *async_hdl)
{
	str accountid;
	int bucket,wholesale;
	struct account_entry* entry;
	struct account_cell* it;

	if (get_mi_string_param(params, "name",
		&accountid.s, &accountid.len) < 0)
		return init_mi_param_error();

	if (get_mi_int_param(params, "wholesale",&wholesale) < 0)
		return init_mi_param_error();

	LM_INFO("XXX - deleteClientRate %.*s %d\n",accountid.len,accountid.s,wholesale);

	bucket = core_hash(&accountid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_write( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == accountid.len &&
		memcmp(it->accountid.s,accountid.s,accountid.len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		LM_ERR("Client %.*s does not exist \n",accountid.len,accountid.s);
		unlock_bucket_write( entry->lock );
		return init_mi_error( 401, "No such client", sizeof("No such client")-1);
	}

	if (wholesale) {
		it->ws_rateid = 0;
		if (it->ws_rate_table.s) {
			if (it->ws_rate_table.s != it->rt_rate_table.s) {
				shm_free(it->ws_rate_table.s);
			}
			it->ws_rate_table.s = NULL;
			it->ws_rate_table.len = 0;
		}

		if (it->ws_rate_currency.s) {
			if (it->ws_rate_currency.s != it->rt_rate_currency.s) {
				shm_free(it->ws_rate_currency.s);
			}
			it->ws_rate_currency.s = NULL;
			it->ws_rate_currency.len = 0;
		}
		if (it->ws_trie) {
			if (it->ws_trie != it->rt_trie)
				free_trie(it->ws_trie);
			it->ws_trie = NULL;
		}
	} else {
		it->rt_rateid = 0;
		if (it->rt_rate_table.s) {
			if (it->rt_rate_table.s != it->ws_rate_table.s) {
				shm_free(it->rt_rate_table.s);
			}
			it->rt_rate_table.s = NULL;
			it->rt_rate_table.len = 0;
		}

		if (it->rt_rate_currency.s) {
			if (it->rt_rate_currency.s != it->ws_rate_currency.s) {
				shm_free(it->rt_rate_currency.s);
			}
			it->rt_rate_currency.s = NULL;
			it->rt_rate_currency.len = 0;
		}
		if (it->rt_trie) {
			if (it->rt_trie != it->ws_trie)
				free_trie(it->rt_trie);
			it->rt_trie = NULL;
		}
	}

	unlock_bucket_write( entry->lock );
	return init_mi_result_ok();
}

static int script_get_client_price(struct sip_msg *msg, str *clientid, int *isws,
		str *dnis,pv_spec_t *prefix,pv_spec_t *destination, pv_spec_t *price,
		pv_spec_t *min,pv_spec_t *inc)
{
	struct account_cell *it;
	struct account_entry *entry;
	struct ratesheet_cell_entry *ret;
	int bucket;
	unsigned int matched_len;
	pv_value_t pv_val;

	bucket = core_hash(clientid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == clientid->len &&
		memcmp(it->accountid.s,clientid->s,clientid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		LM_ERR("Failed to find client %.*s\n",clientid->len,clientid->s);
		return -1;
	}

	if (*isws)
		ret = get_rate_price_prefix(it->ws_trie,dnis,&matched_len);
	else
		ret = get_rate_price_prefix(it->rt_trie,dnis,&matched_len);

	if (ret == NULL) {
		unlock_bucket_read( entry->lock );
		LM_ERR("Failed to match %.*s in client %.*s ratesheet\n",
		dnis->len,dnis->s,clientid->len,clientid->s);
		return -1;
	}

	pv_val.flags = PV_VAL_STR;
	pv_val.rs.s=dnis->s;
	pv_val.rs.len=matched_len;
	if (pv_set_value(msg, prefix, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.rs.s = ret->destination.s;
	pv_val.rs.len = ret->destination.len;
	if (pv_set_value(msg, destination, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.rs.s = double2str(ret->price,&pv_val.rs.len);
	if (pv_set_value(msg, price, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.rs.s = NULL;
	pv_val.rs.len = 0;
	pv_val.flags = PV_VAL_INT | PV_TYPE_INT;
	pv_val.ri = ret->minimum;
	if (pv_set_value(msg, min, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.ri = ret->increment;
	if (pv_set_value(msg, inc, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	unlock_bucket_read( entry->lock );
	return 1;

}

static int script_get_vendor_price(struct sip_msg *msg, str *vendorid,
		str *dnis,pv_spec_t *prefix,pv_spec_t *destination, pv_spec_t *price,
		pv_spec_t *min,pv_spec_t *inc)
{
	struct carrier_cell *it;
	struct carrier_entry *entry;
	int bucket;
	unsigned int matched_len;
	struct ratesheet_cell_entry *ret;
	pv_value_t pv_val;

	bucket = core_hash(vendorid,0,carr_table->size);
	entry = &(carr_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->carrierid.len == vendorid->len &&
		memcmp(it->carrierid.s,vendorid->s,vendorid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		LM_ERR("No such vendor %.*s \n",vendorid->len,vendorid->s);
		return -1;
	}

	ret = get_rate_price_prefix(it->trie,dnis,&matched_len);
	if (ret == NULL) {
		unlock_bucket_read( entry->lock );
		LM_ERR("No prefix match for %.*s on vendor %.*s \n",
		dnis->len,dnis->s,vendorid->len,vendorid->s);
		return -1;
	}

	pv_val.flags = PV_VAL_STR;
	pv_val.rs.s=dnis->s;
	pv_val.rs.len=matched_len;
	if (pv_set_value(msg, prefix, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.rs.s = ret->destination.s;
	pv_val.rs.len = ret->destination.len;
	if (pv_set_value(msg, destination, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.rs.s = double2str(ret->price,&pv_val.rs.len);
	if (pv_set_value(msg, price, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.rs.s = NULL;
	pv_val.rs.len = 0;
	pv_val.flags = PV_VAL_INT | PV_TYPE_INT;
	pv_val.ri = ret->minimum;
	if (pv_set_value(msg, min, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	pv_val.ri = ret->increment;
	if (pv_set_value(msg, inc, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		unlock_bucket_read( entry->lock );
		return -1;
	}

	unlock_bucket_read( entry->lock );
	return 1;
}

static double* bulk_cost_based_fetching(str *clientid,int isws, str *carrierlist,int carr_no,str *dnis,double *client_price) 
{
	int bucket,i;
	double *result;
	struct account_entry *entry;
	struct account_cell *it;
	struct ratesheet_cell_entry *ret;
	unsigned int dst_matched_len;
	double vendor_price;
	str carrier;
	struct carrier_cell *carr_it;
	struct carrier_entry *carr_entry;
	
	if (client_price == NULL)
		return NULL;

	bucket = core_hash(clientid,0,acc_table->size);
	entry = &(acc_table->entries[bucket]);

	lock_bucket_read( entry->lock );
	for (it=entry->first;it;it=it->next) {
		if (it->accountid.len == clientid->len &&
		memcmp(it->accountid.s,clientid->s,clientid->len) == 0) {
			break;
		}
	}

	if (it == NULL) {
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	if (isws) {
		ret = get_rate_price_prefix(it->ws_trie,dnis,&dst_matched_len);
	} else {
		ret = get_rate_price_prefix(it->rt_trie,dnis,&dst_matched_len);
	}

	if (ret == NULL) {
		LM_ERR("Failed to get client price \n");
		unlock_bucket_read( entry->lock );
		return NULL;
	}

	*client_price = ret->price;
	unlock_bucket_read( entry->lock );

	LM_INFO("Client price is %f\n",*client_price);

	result = (double *)pkg_malloc(carr_no * sizeof(double));
	if (result == NULL) {
		LM_ERR("No more mem \n");
		return NULL;
	}
	memset(result,0,carr_no);

	for (i=0;i<carr_no;i++) {
		carrier = carrierlist[i];

		bucket = core_hash(&carrier,0,carr_table->size);
		carr_entry = &(carr_table->entries[bucket]);

		lock_bucket_read( carr_entry->lock );
		for (carr_it=carr_entry->first;carr_it;carr_it=carr_it->next) {
			if (carr_it->carrierid.len == carrier.len &&
			memcmp(carr_it->carrierid.s,carrier.s,carrier.len) == 0) {
				break;
			}
		}

		if (carr_it == NULL) {
			unlock_bucket_read( carr_entry->lock );
			/* we did not find the carrier - do not use it */
			result[i] = 0;
			continue;
		}

		ret = get_rate_price_prefix(carr_it->trie,dnis,&dst_matched_len);
		if (ret == NULL) {
			/* no price found for carrier, do not use it */
			unlock_bucket_read( carr_entry->lock );
			result[i] = INT_MAX;
			continue;
		}

		vendor_price = ret->price;
		unlock_bucket_read( carr_entry->lock );

		LM_INFO("Vendor %.*s price is %f\n",carrier.len,carrier.s,vendor_price);
		result[i] = vendor_price;
	}

	return result;
}

typedef struct str_price_s {
	str vendor_name;
	double price;
} name_price_t;
	
static int script_cost_based_ordering(struct sip_msg *msg, str *clientid, int *isws,
		str *carrierlist,str *dnis,int *profit_margin,pv_spec_t *out_result)
{
	int i,j,len,matched_margin=0;
	double *results=NULL,client_price=-1;
	char *tmp=NULL,*token=NULL,*nts_carrierlist=NULL,*avp_result=NULL;
	str carrier_array[MAX_CARR_IN_SIZE];
	int carrier_array_len=0;
	pv_value_t pv_val;
	name_price_t *sort_arr=NULL,aux;

	nts_carrierlist = (char *)pkg_malloc(carrierlist->len+1);
	if (nts_carrierlist == NULL) {
		LM_ERR("Failed to alloc mem\n");
		return -1;
	}
	memcpy(nts_carrierlist,carrierlist->s,carrierlist->len);
	nts_carrierlist[carrierlist->len]=0;

	for (token = strtok_r(nts_carrierlist, ",", &tmp);
	token;
	token = strtok_r(NULL, ",", &tmp))
	{
		carrier_array[carrier_array_len].len = strlen(token);
		carrier_array[carrier_array_len].s = pkg_malloc(carrier_array[carrier_array_len].len);
		if (carrier_array[carrier_array_len].s == NULL) {
			LM_ERR("Failed to alloc mem\n");
			return -1;
		}
		
		memcpy(carrier_array[carrier_array_len].s,token,carrier_array[carrier_array_len].len);
		carrier_array_len++;

		if (carrier_array_len == MAX_CARR_IN_SIZE) {
			LM_ERR("TOo many IN Vendors \n");
			return -1;
		}
	}

	results = bulk_cost_based_fetching(clientid,*isws,carrier_array,carrier_array_len,dnis,&client_price);
	if (results == NULL) {
		LM_ERR("Failed to do CBR\n");
		goto err_free;
	}

	matched_margin = 0;
	for (i=0;i<carrier_array_len;i++) {
		if (client_price > 0) {
                        if (((client_price - results[i])*100/client_price) >= *profit_margin) {
				matched_margin++;
			}
		}
	}

	if (matched_margin == 0) {
		pv_val.rs.s = "";
		pv_val.rs.len = 0;
		goto set_and_return;
	}

	
	sort_arr = (name_price_t *) pkg_malloc(matched_margin * sizeof(name_price_t));
	if (sort_arr == NULL) {
		LM_ERR("No more pkg\n");
		goto err_free;
	}

	matched_margin=0;
	len=0;
	for (i=0;i<carrier_array_len;i++) {
		if (client_price > 0) {
                        if (((client_price - results[i])*100/client_price) >= *profit_margin) {
				sort_arr[matched_margin].vendor_name = carrier_array[i];
				sort_arr[matched_margin].price = results[i];
				matched_margin++;
				
				if (len == 0) {
					len+=carrier_array[i].len; /* carr_name */
				} else {
					len+=1 /* , */ + carrier_array[i].len;
				}
			}
		}
	}

	/* bubbly sort :( */
	for (i=0;i<matched_margin-1;++i) {
		for (j=0;j<matched_margin-1-i;++j) {
			if (sort_arr[j].price > sort_arr[j+1].price) {
				aux=sort_arr[j];
				sort_arr[j]=sort_arr[j+1];
				sort_arr[j+1]=aux;
			}
		}
	}

	avp_result = (char *)pkg_malloc(len+1);
	if (!avp_result) 
		goto err_free;

	memset(avp_result,0,len+1);
	for (i=0,tmp=avp_result;i<matched_margin;i++) {
		if (tmp == avp_result) {
			memcpy(tmp,sort_arr[i].vendor_name.s,sort_arr[i].vendor_name.len);
			tmp+=sort_arr[i].vendor_name.len;
		} else {
			*tmp++ = ',';
			memcpy(tmp,sort_arr[i].vendor_name.s,sort_arr[i].vendor_name.len);
			tmp+=sort_arr[i].vendor_name.len;
		}
	}
	pv_val.rs.s=avp_result;
	pv_val.rs.len=len;
	
set_and_return:
	pv_val.flags = PV_VAL_STR;
	if (pv_set_value(msg, out_result, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		goto err_free;
	}

	if (sort_arr)
		pkg_free(sort_arr);
	if (results)
		pkg_free(results);
	if (avp_result)
		pkg_free(avp_result);
	for (i=0;i<carrier_array_len;i++)
		pkg_free(carrier_array[i].s);

	pkg_free(nts_carrierlist);
	return 1;

err_free:
	if (sort_arr)
		pkg_free(sort_arr);
	if (results)
		pkg_free(results);
	if (avp_result)
		pkg_free(avp_result);
	for (i=0;i<carrier_array_len;i++)
		pkg_free(carrier_array[i].s);

	pkg_free(nts_carrierlist);
	return -1;
}

static int script_cost_based_filtering(struct sip_msg *msg, str *clientid, int *isws,
		str *carrierlist,str *dnis,int *profit_margin,pv_spec_t *out_result)
{
	int i,len;
	double *results=NULL,client_price=-1;
	char *tmp=NULL,*token=NULL,*nts_carrierlist=NULL,*avp_result=NULL;
	str carrier_array[MAX_CARR_IN_SIZE];
	int carrier_array_len=0;
	pv_value_t pv_val;

	nts_carrierlist = (char *)pkg_malloc(carrierlist->len+1);
	if (nts_carrierlist == NULL) {
		LM_ERR("Failed to alloc mem\n");
		return -1;
	}
	memcpy(nts_carrierlist,carrierlist->s,carrierlist->len);
	nts_carrierlist[carrierlist->len]=0;

	for (token = strtok_r(nts_carrierlist, ",", &tmp);
	token;
	token = strtok_r(NULL, ",", &tmp))
	{
		carrier_array[carrier_array_len].len = strlen(token);
		carrier_array[carrier_array_len].s = pkg_malloc(carrier_array[carrier_array_len].len);
		if (carrier_array[carrier_array_len].s == NULL) {
			LM_ERR("Failed to alloc mem\n");
			return -1;
		}
		
		memcpy(carrier_array[carrier_array_len].s,token,carrier_array[carrier_array_len].len);
		carrier_array_len++;
	}

	results = bulk_cost_based_fetching(clientid,*isws,carrier_array,carrier_array_len,dnis,&client_price);
	if (results == NULL) {
		LM_ERR("Failed to do CBR\n");
		goto err_free;
	}

	len=0;
	for (i=0;i<carrier_array_len;i++) {
		if (client_price > 0) {
                        if (((client_price - results[i])*100/client_price) >= *profit_margin) {
				if (len == 0) {
					len+=carrier_array[i].len; /* carr_name */
				} else {
					len+=1 /* , */ + carrier_array[i].len;
				}
			}
		}
	}
	
	if (len == 0) {
		pv_val.rs.s = "";
		pv_val.rs.len = 0;
	} else {
		avp_result = (char *)pkg_malloc(len+1);
		if (!avp_result) 
			goto err_free;
	
		memset(avp_result,0,len+1);
		for (i=0,tmp=avp_result;i<carrier_array_len;i++) {
			if (client_price > 0) {
                        	if (((client_price - results[i])*100/client_price) >= *profit_margin) {
					if (tmp == avp_result) {
						memcpy(tmp,carrier_array[i].s,carrier_array[i].len);
						tmp+=carrier_array[i].len;
					} else {
						*tmp++ = ',';
						memcpy(tmp,carrier_array[i].s,carrier_array[i].len);
						tmp+=carrier_array[i].len;
					}
				}
			}
		}
		pv_val.rs.s=avp_result;
		pv_val.rs.len=len;
	}
	
	pv_val.flags = PV_VAL_STR;
	if (pv_set_value(msg, out_result, (int)EQ_T ,&pv_val) != 0) {
		LM_ERR("failed to set value for out pvar\n");
		goto err_free;
	}

	if (results)
		pkg_free(results);
	if (avp_result)
		pkg_free(avp_result);
	for (i=0;i<carrier_array_len;i++)
		pkg_free(carrier_array[i].s);
	
	return 1;

err_free:
	if (results)
		pkg_free(results);
	if (avp_result)
		pkg_free(avp_result);
	for (i=0;i<carrier_array_len;i++)
		pkg_free(carrier_array[i].s);

	return -1;
}
