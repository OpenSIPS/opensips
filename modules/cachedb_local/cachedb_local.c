/*
 * memory cache system module
 *
 * Copyright (C) 2009 Anca Vamanu
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
 * History:
 * --------
 *  2009-01-29  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../timer.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"
#include "../../mi/item.h"
#include "../../lib/csv.h"
#include "../clusterer/api.h"

#include "cachedb_local.h"
#include "cachedb_local_replication.h"
#include "hash.h"

#include "../../mem/rpm_mem.h"

#include <fnmatch.h>


str cache_mod_name = str_init("local");
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

int cache_clean_period = 600;
int local_exec_threshold = 0;

lcache_col_t* lcache_collection = NULL;
url_lst_t* url_list=NULL;

str cache_repl_cap = str_init("cachedb-local-repl");
int cluster_id = 0;
enum cachedb_rr_persist rr_persist = RRP_SYNC_FROM_CLUSTER;
char *cluster_persist;

/* restart persistency with rpm */
int lcache_rpm_enable = 0;
lcache_rpm_cache_t *lcache_rpm_cache;

static int remove_chunk_f(struct sip_msg* msg, str* collection, str* glob);
mi_response_t *mi_cache_remove_chunk_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_cache_remove_chunk_2(const mi_params_t *params,

								struct mi_handler *async_hdl);

mi_response_t *mi_cache_fetch_chunk_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_cache_fetch_chunk_2(const mi_params_t *params,
								struct mi_handler *async_hdl);
void localcache_clean(unsigned int ticks,void *param);
static int parse_collections(unsigned int type, void *val);
static int store_urls(unsigned int type, void *val);

static const param_export_t params[]={
	{ "cache_clean_period", INT_PARAM, &cache_clean_period },
	{ "exec_threshold",     INT_PARAM, &local_exec_threshold },
	{ "cache_collections",  STR_PARAM|USE_FUNC_PARAM, (void *)parse_collections },
	{ "cachedb_url",        STR_PARAM|USE_FUNC_PARAM, (void *)store_urls },
	{ "cluster_id",INT_PARAM, &cluster_id },
	{ "cluster_persistency",STR_PARAM, &cluster_persist },
	{ "enable_restart_persistency",INT_PARAM, &lcache_rpm_enable },
	{0,0,0}
};

static const cmd_export_t cmds[]= {
	{"cache_remove_chunk",        (cmd_function)remove_chunk_f, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE},
	{0,0,{{0,0,0}},0}
};

static const mi_export_t mi_cmds[] = {
	{ "cache_remove_chunk", 0, 0, 0, {
		{mi_cache_remove_chunk_1, {"glob", 0}},
		{mi_cache_remove_chunk_2, {"glob", "collection", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "cache_fetch_chunk", 0, 0, 0, {
		{mi_cache_fetch_chunk_1, {"glob", 0}},
		{mi_cache_fetch_chunk_2, {"glob", "collection", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0},
	},
	{ /* modparam dependencies */
		{"cluster_id", get_deps_clusterer},
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"cachedb_local",               /* module name */
	MOD_TYPE_CACHEDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* load functionpen flags */
	&deps,            /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,							/* exported transformations */
	0,                          /* extra processes */
	0,                          /* module pre-initialization function */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init,                 /* per-child init function */
	0                           /* reload confirm function */
};

static char *key_buff = NULL;
static int key_buff_size = 0;
static char *pat_buff = NULL;
static int pat_buff_size = 0;


static int remove_chunk_f(struct sip_msg* msg, str* col_s, str* pat)
{
	int i;
	lcache_entry_t* me1, *me2;
	struct timeval start;

	lcache_col_t* col;
	lcache_t* cache_htable;

	if ( !col_s ) {
		/* use default collection; default collection is always first in list */
		col = lcache_collection;
	} else {
		for ( col=lcache_collection; col; col=col->next ) {
			if ( !str_strcmp( &col->col_name, col_s) )
				break;
		}

		if ( !col ) {
			LM_ERR("collection <%.*s> not defined!\n", col_s->len, col_s->s);
			return -1;
		}
	}

	cache_htable = col->col_htable->htable;

	if (pat->len+1 > pat_buff_size) {
		pat_buff = pkg_realloc(pat_buff,pat->len+1);
		if (pat_buff == NULL) {
			LM_ERR("No more pkg mem\n");
			pat_buff_size = 0;
			return -1;
		}

		pat_buff_size = pat->len +1;
	}

	memcpy(pat_buff,pat->s,pat->len);
	pat_buff[pat->len] = 0;

	LM_DBG("trying to remove chunk with pattern [%s]\n",pat_buff);
	start_expire_timer(start,local_exec_threshold);

	for(i = 0; i< col->col_htable->size; i++) {
		lock_get(&cache_htable[i].lock);
		me1 = cache_htable[i].entries;
		me2 = NULL;

		while(me1) {
			if (me1->attr.len + 1 > key_buff_size) {
				key_buff = pkg_realloc(key_buff,me1->attr.len+1);
				if (key_buff == NULL) {
					LM_ERR("No more pkg mem\n");
					key_buff_size = 0;
					lock_release(&cache_htable[i].lock);
					_stop_expire_timer(start,local_exec_threshold,
						"cachedb_local remove_chunk",pat->s,pat->len,0,
						cdb_slow_queries, cdb_total_queries);
					return -1;
				}

				key_buff_size = me1->attr.len + 1;
			}

			memcpy(key_buff,me1->attr.s,me1->attr.len);
			key_buff[me1->attr.len] = 0;

			if(fnmatch(pat_buff,key_buff,0) == 0) {
				LM_DBG("[%.*s] matches glob [%.*s] - removing from bucket %d\n",
						me1->attr.len, me1->attr.s,pat_buff_size,pat_buff,i);

				if(me2) {
					me2->next = me1->next;
					func_free(col->free, me1);
					me1 = me2->next;
				} else{
					cache_htable[i].entries = me1->next;
					func_free(col->free, me1);
					me1 = cache_htable[i].entries;
				}
			} else {
				me2 = me1;
				me1 = me1->next;
			}
		}
		lock_release(&cache_htable[i].lock);
	}

	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local remove_chunk",pat->s,pat->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 1;
}

mi_response_t *mi_cache_remove_chunk(const mi_params_t *params, str *collection)
{
	str glob;

	if (get_mi_string_param(params, "glob", &glob.s, &glob.len) < 0)
		return init_mi_param_error();

	if (remove_chunk_f(NULL,collection, &glob) < 1)
		return init_mi_error(500, MI_SSTR("Internal error"));
	else
		return init_mi_result_ok();
}

mi_response_t *mi_cache_remove_chunk_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_cache_remove_chunk(params, NULL);
}

mi_response_t *mi_cache_remove_chunk_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str col;

	if (get_mi_string_param(params, "collection", &col.s, &col.len) < 0)
		return init_mi_param_error();

	return mi_cache_remove_chunk(params, &col);
}

mi_response_t *mi_cache_fetch_chunk(const mi_params_t *params, str *collection)
{
	str glob;
	mi_response_t *resp;
	mi_item_t *resp_obj, *keys_arr, *key_obj;
	lcache_col_t* col;
	lcache_t* cache_htable;
	lcache_entry_t* me1;
	struct timeval start;
	int i;

	if (get_mi_string_param(params, "glob", &glob.s, &glob.len) < 0)
		return init_mi_param_error();

	if ( !collection ) {
		/* use default collection; default collection is always first in list */
		col = lcache_collection;
	} else {
		for ( col=lcache_collection; col; col=col->next ) {
			if ( !str_strcmp( &col->col_name, collection) )
				break;
		}

		if ( !col ) {
			LM_ERR("collection <%.*s> not defined!\n", collection->len, collection->s);
			return init_mi_param_error();
		}
	}

	cache_htable = col->col_htable->htable;

	if (glob.len+1 > pat_buff_size) {
		pat_buff = pkg_realloc(pat_buff,glob.len+1);
		if (pat_buff == NULL) {
			LM_ERR("No more pkg mem\n");
			pat_buff_size = 0;
			return init_mi_error( 400, MI_SSTR("Internal Error"));
		}

		pat_buff_size = glob.len +1;
	}

	memcpy(pat_buff,glob.s,glob.len);
	pat_buff[glob.len] = 0;

	resp = init_mi_result_object(&resp_obj);
	if (resp==NULL) {
		LM_ERR("Failed to init reply object \n");
		return init_mi_error( 400, MI_SSTR("Internal Error"));
	}

	if((keys_arr = add_mi_array(resp_obj, MI_SSTR("keys"))) < 0) {
		LM_ERR("Failed to init client rates reply object \n");
		return init_mi_error( 400, MI_SSTR("Internal Error"));
	}

	LM_DBG("trying to fetch entire chunk with pattern [%s]\n",pat_buff);
	start_expire_timer(start,local_exec_threshold);

	for(i = 0; i< col->size; i++) {
		lock_get(&cache_htable[i].lock);
		me1 = cache_htable[i].entries;

		while(me1) {
			if (me1->attr.len + 1 > key_buff_size) {
				key_buff = pkg_realloc(key_buff,me1->attr.len+1);
				if (key_buff == NULL) {
					LM_ERR("No more pkg mem\n");
					key_buff_size = 0;
					goto err_release;
				}
				key_buff_size = me1->attr.len + 1;
			}

			memcpy(key_buff,me1->attr.s,me1->attr.len);
			key_buff[me1->attr.len] = 0;

			if(fnmatch(pat_buff,key_buff,0) == 0) {
				LM_DBG("[%.*s] matches glob [%.*s] - returning %d\n",
						me1->attr.len, me1->attr.s,pat_buff_size,pat_buff,i);
				if ((key_obj = add_mi_object(keys_arr, MI_SSTR("key"))) < 0) {
					LM_ERR("Failed to add object \n");
					goto err_release;
				}
				if (add_mi_string(key_obj,MI_SSTR("name"),me1->attr.s,me1->attr.len) < 0) {
					LM_ERR("Failed to add key name \n");
					goto err_release;
				}
				if (add_mi_string(key_obj,MI_SSTR("value"),me1->value.s,me1->value.len) < 0) {
					LM_ERR("Failed to add key value \n");
					goto err_release;
				}
			}

			me1 = me1->next;
		}

		lock_release(&cache_htable[i].lock);
	}

	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local fetch_chunk",glob.s,glob.len,0,
		cdb_slow_queries, cdb_total_queries);


	return resp;
err_release:
	lock_release(&cache_htable[i].lock);
	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local fetch_chunk",glob.s,glob.len,0,
		cdb_slow_queries, cdb_total_queries);
	return init_mi_error( 400, MI_SSTR("Internal Error"));
}

mi_response_t *mi_cache_fetch_chunk_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_cache_fetch_chunk(params, NULL);
}

mi_response_t *mi_cache_fetch_chunk_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str col;

	if (get_mi_string_param(params, "collection", &col.s, &col.len) < 0)
		return init_mi_param_error();

	return mi_cache_fetch_chunk(params, &col);
}

lcache_con* lcache_new_connection(struct cachedb_id* id)
{
	lcache_con *con;
	lcache_col_t* it;

	if (id == NULL) {
		LM_ERR("null db_id\n");
		return 0;
	}

	con = pkg_malloc(sizeof(lcache_con));
	if (con == NULL) {
		LM_ERR("no more pkg\n");
		return 0;
	}

	memset(con,0,sizeof(lcache_con));
	con->id = id;
	con->ref = 1;

	if ( !id->database ) {
		/* if no collection used will used the default one */
		/* default collection is always first in list */
		it = lcache_collection;
	} else {
		for ( it=lcache_collection; it; it=it->next) {
			if ( !memcmp(it->col_name.s, id->database, strlen(id->database)) ) {
				break;
			}
		}
	}

	if ( !it ) {
		LM_ERR("collection <%s> not defined!\n", id->database);
		return 0;
	}

	con->col = it;

	return con;
}

cachedb_con *lcache_init(str *url)
{
	return cachedb_do_init(url,(void *)lcache_new_connection);
}

void lcache_free_connection(cachedb_pool_con *con)
{
	pkg_free(con);
}

void lcache_destroy(cachedb_con *con)
{
	cachedb_do_close(con,lcache_free_connection);
}

int lcache_is_replicated (cachedb_con *con)
{
	return ((lcache_con*)con->data)->col->replicated;
}

lcache_rpm_cache_t *get_rpm_cache(str *col_name)
{
	lcache_rpm_cache_t *cache;

	for (cache = lcache_rpm_cache; cache; cache = cache->next)
		if (cache->col_name.len == col_name->len &&
				memcmp(cache->col_name.s, col_name->s, col_name->len) == 0)
			return cache;
	return NULL;
}

lcache_rpm_cache_t *add_head_rpm_cache(str *col_name)
{
	lcache_rpm_cache_t *c = rpm_malloc(sizeof(*c) + col_name->len);
	if (!c) {
		LM_ERR("cannot allocate persistent mem for cache head!\n");
		return NULL;
	}
	c->col_name.s = (char *)(c + 1);
	c->col_name.len = col_name->len;
	memcpy(c->col_name.s, col_name->s, col_name->len);
	c->col_htable = NULL;
	c->next = lcache_rpm_cache;
	lcache_rpm_cache = c;
	rpm_key_set("cachedb_local", lcache_rpm_cache);

	return c;
}

void fix_rpm_cache_entries(lcache_htable_t *col_htable)
{
	lcache_entry_t *me;
	int i;

	for(i = 0; i < col_htable->size; i++) {
		me = col_htable->htable[i].entries;
		while (me) {
			if (me->expires > 0)
				me->expires = get_ticks() + me->ttl;

			me->synced = 0;

			me = me->next;
		}
	}
}

void clean_rpm_cache_old(void)
{
	lcache_col_t *it = NULL;
	lcache_rpm_cache_t *c, *prev_c = NULL, *free_c;

	if (!lcache_rpm_cache)
		return;

	/* cleanup old collections */
	c = lcache_rpm_cache;
	while (c) {
		for (it=lcache_collection; it; it=it->next) {
			if (c->col_name.len == it->col_name.len &&
				memcmp(c->col_name.s, it->col_name.s,
						it->col_name.len) == 0)
				break;
		}
		if (it != NULL) {
			prev_c = c;
			c = c->next;
			continue;
		}
		LM_NOTICE("<%.*s> collection no longer used - cleaning old data!\n",
			c->col_name.len, c->col_name.s);

		if (!prev_c) {
			lcache_rpm_cache = c->next;
			rpm_key_set("cachedb_local", lcache_rpm_cache);
		} else {
			prev_c->next = c->next;
		}
		free_c = c;
		c = c->next;
		lcache_htable_destroy(free_c->col_htable, rpm_free_func);
	}
}

/**
 * init module function
 */
static int mod_init(void)
{
	cachedb_engine cde;
	cachedb_con *con;
	str url=str_init("local://");
	str name=str_init("local");

	url_lst_t *it=url_list, *foo=NULL;
	lcache_col_t *default_col, *col_it;

	lcache_rpm_cache_t *rpm_cache;

	memset(&cde, 0, sizeof cde);

	/* register the cache system */
	cde.name = cache_mod_name;

	cde.cdb_func.init = lcache_init;
	cde.cdb_func.destroy = lcache_destroy;
	cde.cdb_func.get = lcache_htable_fetch;
	cde.cdb_func.get_counter = lcache_htable_fetch_counter;
	cde.cdb_func.set = lcache_htable_insert;
	cde.cdb_func.remove = lcache_htable_remove;
	cde.cdb_func.add = lcache_htable_add;
	cde.cdb_func.sub = lcache_htable_sub;
	cde.cdb_func.is_replicated = lcache_is_replicated;
	cde.cdb_func.iter_keys = lcache_htable_iter_keys;

	cde.cdb_func.capability = CACHEDB_CAP_BINARY_VALUE;

	if(cache_clean_period <= 0 )
	{
		LM_ERR("Wrong parameter cache_clean_period - need a positive value\n");
		return -1;
	}

	if( register_cachedb(&cde)< 0)
	{
		LM_ERR("failed to register to core memory store interface\n");
		return -1;
	}

	if (lcache_rpm_enable) {
		if (rpm_init_mem() < 0) {
			LM_ERR("could not initilize restart persistent memory!\n");
			return -1;
		}
		lcache_rpm_cache = (lcache_rpm_cache_t *)rpm_key_get("cachedb_local");
		if (!lcache_rpm_cache)
			LM_INFO("starting cachedb_local with empty rpm cache\n");

		LM_INFO("using %ld MB of restart-persistent memory, allocator: %s\n",
		          rpm_mem_size/1024/1024, mm_str(mem_allocator_rpm));
	}

	for ( col_it=lcache_collection; col_it; col_it=col_it->next ) {
		if ( !memcmp(col_it->col_name.s, DEFAULT_COLLECTION_NAME,
					sizeof(DEFAULT_COLLECTION_NAME) - 1) ) {
			break;
		}
	}

	/* no default collection defined; create it */
	if ( !col_it ) {
		default_col = shm_malloc(sizeof(lcache_col_t));
		if ( !default_col ) {
			LM_ERR("no more shared memory!\n");
			return -1;
		}
		memset(default_col, 0, sizeof(lcache_col_t));

		default_col->col_name.s = DEFAULT_COLLECTION_NAME;
		default_col->col_name.len = sizeof(DEFAULT_COLLECTION_NAME) - 1;
		default_col->size = (1 << HASH_SIZE_DEFAULT);

		/* link the default collection */
		default_col->next = lcache_collection;
		lcache_collection = default_col;
	}

	if ( it ) {
		while (it) {
			con = lcache_init(&it->url);
			if (con == NULL) {
				LM_ERR("failed to init connection for collection <%.*s>!\n",0,"");
				return -1;
			}

			if (cachedb_put_connection(&name,con) < 0) {
				LM_ERR("failed to insert connection for script\n");
				return -1;
			}

			foo = it;
			it = it->next;
			pkg_free(foo);
		}
	} else {
		/* no url defined; keep old functionality */
		/* insert connection for script */
		con = lcache_init(&url);
		if (con == NULL) {
			LM_ERR("failed to init connection for script\n");
			return -1;
		}

		if (cachedb_put_connection(&name,con) < 0) {
			LM_ERR("failed to insert connection for script\n");
			return -1;
		}
	}

	clean_rpm_cache_old();

	for ( col_it=lcache_collection; col_it; col_it=col_it->next ) {
		if (!cluster_id && col_it->replicated) {
			LM_WARN("collection <%.*s> is replicated but no "
				"'cluster_id' defined!\n",
					col_it->col_name.len, col_it->col_name.s);
		}

		if (lcache_rpm_enable) {
			rpm_cache = get_rpm_cache(&col_it->col_name);
			if (!rpm_cache)
				rpm_cache = add_head_rpm_cache(&col_it->col_name);
			if (!rpm_cache) {
				LM_ERR("could not create rpm cache head!\n");
				continue;
			} else {
				col_it->malloc = rpm_malloc_func;
				col_it->realloc = rpm_realloc_func;
				col_it->free = rpm_free_func;
				col_it->rpm_cache = rpm_cache;
			}

			if (rpm_cache->col_htable) {
				LM_INFO("starting cachedb_local with cache data %p->%p!\n",
					rpm_cache, rpm_cache->col_htable);

				col_it->col_htable = rpm_cache->col_htable;

				if (rpm_cache->col_htable->size != col_it->size) {
					LM_WARN("Defined size [%d] for collection <%.*s> is different "
						"than the old rpm cached size - cleaning old data\n",
						col_it->size, col_it->col_name.len, col_it->col_name.s);

					lcache_htable_destroy(col_it->col_htable, col_it->free);

					if (lcache_htable_init(col_it) < 0) {
						LM_ERR("failed to initialize htable for collection <%.*s>!\n",
							col_it->col_name.len, col_it->col_name.s);
						return -1;
					}

					rpm_cache->col_htable = col_it->col_htable;

					continue;
				}

				fix_rpm_cache_entries(col_it->col_htable);
			} else {
				if (lcache_htable_init(col_it) < 0) {
					LM_ERR("failed to initialize htable for collection <%.*s>!\n",
						col_it->col_name.len, col_it->col_name.s);
					return -1;
				}

				rpm_cache->col_htable = col_it->col_htable;
			}
		} else {
			col_it->malloc = shm_malloc_func;
			col_it->realloc = shm_realloc_func;
			col_it->free = shm_free_func;

			if (lcache_htable_init(col_it) < 0) {
				LM_ERR("failed to initialize htable for collection <%.*s>!\n",
					col_it->col_name.len, col_it->col_name.s);
				return -1;
			}
		}
	}

	/* register timer to delete the expired entries */
	register_timer("localcache-expire",localcache_clean, 0,
		cache_clean_period, TIMER_FLAG_DELAY_ON_DELAY);

	/* register clusterer module */
	if (cluster_id) {
		if (cluster_persist) {
			if (!strcasecmp(cluster_persist, "none"))
				rr_persist = RRP_NONE;
			else if (!strcasecmp(cluster_persist, "sync-from-cluster"))
				rr_persist = RRP_SYNC_FROM_CLUSTER;
			else
				LM_ERR("unknown 'cluster_persistency' value: %s, "
				       "using 'sync-from-cluster'\n", cluster_persist);
		}

		if (load_clusterer_api(&clusterer_api) < 0) {
			LM_DBG("failed to load clusterer API - is clusterer module loaded?\n");
			return -1;
		}

		if (clusterer_api.register_capability(&cache_repl_cap, receive_binary_packet,
		    receive_cluster_event, cluster_id,
		    rr_persist == RRP_SYNC_FROM_CLUSTER? 1 : 0,
		    NODE_CMP_ANY) < 0 ) {
			LM_ERR("Cannot register clusterer callback for cache replication!\n");
			return -1;
		}

		if (rr_persist == RRP_SYNC_FROM_CLUSTER &&
		    clusterer_api.request_sync(&cache_repl_cap, cluster_id, 0) < 0)
			LM_ERR("cachedb sync request failed\n");

	}

	return 0;
}

/**
 * Initialize children
 */
static int child_init(int rank)
{
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	lcache_col_t* it;
	lcache_entry_t *me;
	int i;

	for ( it=lcache_collection; it; it=it->next) {
		if (!it->rpm_cache) {
			lcache_htable_destroy(it->col_htable, it->free);
		} else {
			for(i = 0; i< it->col_htable->size; i++) {
				me = it->col_htable->htable[i].entries;
				while (me) {
					if (me->expires > 0)
						me->ttl = me->expires - get_ticks();

					me = me->next;
				}
			}
		}
	}
}

void localcache_clean(unsigned int ticks,void *param)
{
	int i;
	lcache_entry_t* me1, *me2;
	lcache_col_t* it;
	lcache_t* cache_htable;

	for ( it=lcache_collection; it; it=it->next ) {
		LM_DBG("start\n");
		cache_htable = it->col_htable->htable;

		for(i = 0; i< it->col_htable->size; i++)
		{
			lock_get(&cache_htable[i].lock);
			me1 = cache_htable[i].entries;
			me2 = NULL;

			while(me1)
			{
				if((me1->expires > 0) && (me1->expires < get_ticks()))
				{
					LM_DBG("deleted entry attr= [%.*s]\n",
							me1->attr.len, me1->attr.s);

					if(me2)
					{
						me2->next = me1->next;
						func_free(it->free, me1);
						me1 = me2->next;
					}
					else
					{
						cache_htable[i].entries = me1->next;
						func_free(it->free, me1);
						me1 = cache_htable[i].entries;
					}
				}
				else
				{
					if (me1->expires > 0 && it->rpm_cache)
						me1->ttl = me1->expires - get_ticks();

					me2 = me1;
					me1 = me1->next;
				}
			}

			lock_release(&cache_htable[i].lock);
		}
	}
}

static int parse_collections(unsigned int type, void* val)
{
	unsigned coll_size;
	str collection_list, coll;
	lcache_col_t *new_col, *it;
	csv_record *cols, *col, *kv;
	int replicated;

	if (!val) {
		LM_ERR("null collection list!\n");
		return -1;
	}

	init_str(&collection_list, (char *)val);
	cols = __parse_csv_record(&collection_list, 0, ';');
	if (!cols)
		goto bad_input;

	for (col = cols; col; col = col->next) {
		kv = __parse_csv_record(&col->s, 0, '=');
		if (!kv)
			goto bad_input;
		coll = kv->s;

		if (kv->next) {
			if (str2int(&kv->next->s, &coll_size) < 0) {
				LM_ERR("invalid hash size <%.*s>!\n", kv->next->s.len, kv->next->s.s);
				goto bad_input;
			}
		} else {
			coll_size = HASH_SIZE_DEFAULT;
		}

		if (ZSTR(coll)) {
			LM_DBG("skipping empty-string collection: ''!\n");
			continue;
		}

		if (coll.s[coll.len-2] == '/' && coll.s[coll.len-1] == 'r') {
			coll.len -= 2;
			replicated = 1;
		} else {
			replicated = 0;
		}

		LM_DBG("creating collection '%.*s' with hash_size %d\n",
		       coll.len, coll.s, coll_size);

		/* check if the collection was already defined */
		for ( it=lcache_collection; it; it = it->next ) {
			if ( !str_strcmp( &coll, &it->col_name)) {
				LM_ERR("collection <%.*s> defined more than once!\n",
						coll.len, coll.s);
				return -1;
			}
		}

		/* create the new collection */
		new_col = shm_malloc(sizeof(lcache_col_t));
		if (new_col == NULL) {
			LM_ERR("no more shm!\n");
			return -1;
		}
		memset(new_col, 0, sizeof(lcache_col_t));

		if (pkg_str_dup(&new_col->col_name, &coll) < 0) {
			LM_ERR("oom\n");
			return -1;
		}

		new_col->size = (1 << coll_size);

		new_col->replicated = replicated;

		add_last(new_col, lcache_collection);
		free_csv_record(kv);
	}

	free_csv_record(cols);
	return 0;

bad_input:
	LM_ERR("failed to parse 'cache_collections'!\n");
	return -1;
}


/**
 * store all the url's until mod init
 * because we don't know whether or not collections parameter was defined
 *
 */
static int store_urls(unsigned int type, void *val)
{
	url_lst_t* new_url;

	new_url = pkg_malloc(sizeof(url_lst_t));
	if ( !new_url ) {
		LM_ERR("no more pkg mem!\n");
		return -1;
	}

	new_url->url.s = (char *)val;
	new_url->url.len = strlen(new_url->url.s);
	new_url->next = 0;

	if ( !url_list ) {
		url_list = new_url;
	} else {
		/* we put the new url first; not intereseted in the order */
		new_url->next = url_list;
		url_list = new_url;
	}

	return 0;
}
