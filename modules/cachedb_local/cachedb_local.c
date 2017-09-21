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
#include "../../mi/tree.h"

#include "cachedb_local.h"
#include "hash.h"

#include <fnmatch.h>


str cache_mod_name = str_init("local");
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

int cache_clean_period = 600;
int local_exec_threshold = 0;

lcache_col_t* lcache_collection = NULL;
url_lst_t* url_list=NULL;


static int w_remove_chunk_1(struct sip_msg* msg, char* glob);
static int w_remove_chunk_2(struct sip_msg* msg, char* collection, char* glob);
static int remove_chunk_f(struct sip_msg* msg, char* collection, char* glob);
struct mi_root * mi_cache_remove_chunk(struct mi_root *cmd_tree,void *param);
void localcache_clean(unsigned int ticks,void *param);
static int parse_collections(unsigned int type, void *val);
static int store_urls(unsigned int type, void *val);

static param_export_t params[]={
	{ "cache_clean_period", INT_PARAM, &cache_clean_period },
	{ "exec_threshold",     INT_PARAM, &local_exec_threshold },
	{ "cache_collections",  STR_PARAM|USE_FUNC_PARAM, (void *)parse_collections },
	{ "cachedb_url",        STR_PARAM|USE_FUNC_PARAM, (void *)store_urls },
	{0,0,0}
};

static cmd_export_t cmds[]= {
	{"cache_remove_chunk",        (cmd_function)w_remove_chunk_1,  1,
	fixup_str_str, 0,
	REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE},
	{"cache_remove_chunk",        (cmd_function)w_remove_chunk_2,  1,
	fixup_str_str, 0,
	REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE},
	{0,0,0,0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ "cache_remove_chunk",           0, mi_cache_remove_chunk,         0,  0,  0},
	{ 0, 0, 0, 0, 0, 0}
};

/** module exports */
struct module_exports exports= {
	"cachedb_local",               /* module name */
	MOD_TYPE_CACHEDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,                       /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	mi_cmds,                    /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,							/* exported transformations */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init                  /* per-child init function */
};

static char *key_buff = NULL;
static int key_buff_size = 0;
static char *pat_buff = NULL;
static int pat_buff_size = 0;

static int w_remove_chunk_1(struct sip_msg* msg, char* glob)
{
	return remove_chunk_f(msg, NULL, glob);
}

static int w_remove_chunk_2(struct sip_msg* msg, char* collection, char* glob)
{
	return remove_chunk_f(msg, collection, glob);
}


static int remove_chunk_f(struct sip_msg* msg, char* collection, char* glob)
{
	int i;
	str *pat = (str *)glob;
	str *col_s = (str *)collection;
	lcache_entry_t* me1, *me2;
	struct timeval start;

	lcache_col_t* col;
	lcache_t* cache_htable;

	if ( !collection ) {
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

	cache_htable = col->col_htable;

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

	for(i = 0; i< col->size; i++) {
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
					stop_expire_timer(start,local_exec_threshold,
					"cachedb_local remove_chunk",pat->s,pat->len,0);
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
					shm_free(me1);
					me1 = me2->next;
				} else{
					cache_htable[i].entries = me1->next;
					shm_free(me1);
					me1 = cache_htable[i].entries;
				}
			} else {
				me2 = me1;
				me1 = me1->next;
			}
		}
		lock_release(&cache_htable[i].lock);
	}

	stop_expire_timer(start,local_exec_threshold,
	"cachedb_local remove_chunk",pat->s,pat->len,0);
	return 1;
}

struct mi_root * mi_cache_remove_chunk(struct mi_root *cmd_tree,void *param)
{
	struct mi_node* node;
	int status, msg_len;
	char *msg;

	char* collection;
	char* glob;

	node = cmd_tree->node.kids;
	if (node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if (!node->value.s || !node->value.len)
		return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

	if ( !node->next ) {
		collection = NULL;
		glob = (char *)(&node->value);
	} else {
		collection = (char *)(&node->value);
		glob = (char *)(&node->next->value);
	}

	if (remove_chunk_f(NULL,collection,glob) < 1) {
		status = 500;
		msg = MI_INTERNAL_ERR_S;
		msg_len = MI_INTERNAL_ERR_LEN;
	} else {
		status = 200;
		msg = MI_OK_S;
		msg_len = MI_OK_LEN;
	}

	return init_mi_tree(status,msg,msg_len);
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
	it->is_used = 1;

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

		default_col->col_name.s = DEFAULT_COLLECTION_NAME;
		default_col->col_name.len = sizeof(DEFAULT_COLLECTION_NAME) - 1;
		default_col->size = (1 << HASH_SIZE_DEFAULT);
		if (lcache_htable_init(&default_col->col_htable, default_col->size) < 0) {
			LM_ERR("failed to initialize for <%s> collection!\n",
						DEFAULT_COLLECTION_NAME);
			return -1;
		}

		/* the default collection is special; it's always there, it doesn't have
		 * to be used in order to keep backwards compatibility */
		default_col->is_used = 1;

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

	/* check to see if we've got unused collections */
	for ( col_it=lcache_collection; col_it; col_it=col_it->next ) {
		if ( !col_it->is_used ) {
			LM_WARN("collection <%.*s> is not assigned to any url!\n",
					col_it->col_name.len, col_it->col_name.s);
		}
	}

	/* register timer to delete the expired entries */
	register_timer("localcache-expire",localcache_clean, 0,
		cache_clean_period, TIMER_FLAG_DELAY_ON_DELAY);

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

	for ( it=lcache_collection; it; it=it->next) {
		lcache_htable_destroy(&it->col_htable, it->size);
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
		cache_htable = it->col_htable;

		for(i = 0; i< it->size; i++)
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
						shm_free(me1);
						me1 = me2->next;
					}
					else
					{
						cache_htable[i].entries = me1->next;
						shm_free(me1);
						me1 = cache_htable[i].entries;
					}
				}
				else
				{
					me2 = me1;
					me1 = me1->next;
				}
			}

			lock_release(&cache_htable[i].lock);
		}
	}
}

/* !!!WARNNG!!! unsafe function
 * input and output strings must be allocated
 * input string will be modified
 * returns 0 if no element in list,*/
static inline int get_next_collection(str* lst, str* cname, unsigned int* csize)
{
	char* tok_end;

	str token;
	str csize_s;

	static const char lst_delim=';', size_delim = '=';

	/* no more elements in list */
	if ( lst->len == 0 || lst->s == NULL)
		return 0;

	tok_end = q_memchr(lst->s, lst_delim, lst->len);

	if ( tok_end == NULL ) {
		token.s = lst->s;
		token.len = lst->len;

		lst->s = NULL;
		lst->len = 0;
	} else if ( tok_end - lst->s  == (lst->len - 1) )  {
		token.s = lst->s;
		token.len = lst->len - 1;

		lst->s = NULL;
		lst->len = 0;
	} else {
		token.s = lst->s;
		token.len = tok_end - lst->s;

		lst->len -= (tok_end - lst->s + 1);
		lst->s = tok_end + 1;
	}

	tok_end = q_memchr(token.s, size_delim, token.len);
	if ( tok_end ) {
		cname->s = token.s;
		cname->len = tok_end - cname->s;

		csize_s.s = tok_end + 1;
		csize_s.len = token.len - (cname->len + 1);

		if ( csize_s.len == 0 ) {
			LM_ERR("no collection size after '=' given!\n");
			return -1;
		}

		if ( str2int( &csize_s, csize ) < 0 ) {
			LM_ERR("invalid hash size <%.*s>!\n", csize_s.len, csize_s.s);
			return -1;
		}
	} else {
		cname->s = token.s;
		cname->len = token.len;

		*csize = HASH_SIZE_DEFAULT;
	}

	return 1;
}

static int parse_collections(unsigned int type, void* val)
{
	int rc;
	unsigned coll_size;
	str collection_list, coll;

	lcache_col_t *new_col, *it;

	if ( !val ) {
		LM_ERR("null collection list!\n");
		return -1;
	}

	collection_list.s = (char *) val;
	collection_list.len = strlen( collection_list.s );

	str_trim_spaces_lr(collection_list);

	while ((rc=get_next_collection(&collection_list, &coll, &coll_size)) != 0) {
		if ( rc < 0 ) {
			LM_ERR("error occurred!\n");
			return -1;
		}

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

		new_col->col_name = coll;
		new_col->size = (1 << coll_size);
		if (lcache_htable_init(&new_col->col_htable, new_col->size) < 0) {
			LM_ERR("failed to initialize htable for collection <%.*s>!\n",
					coll.len, coll.s);
			return -1;
		}

		/* add the newly created collection to the list */
		if (!lcache_collection) {
			lcache_collection = new_col;
		} else {
			for ( it=lcache_collection; it->next; it = it->next);
			it->next = new_col;
		}

	}

	return 0;
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

