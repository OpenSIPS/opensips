/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Andrei Dragus
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
 *
 * History:
 * ---------
 *  2009-07-15  first version (andreidragus)
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

#include "cachedb_memcached.h"
#include <libmemcached/memcached.h>

#if !defined(LIBMEMCACHED_VERSION_HEX) || LIBMEMCACHED_VERSION_HEX < 0x00037000
typedef memcached_return memcached_return_t;
#endif


static str cache_mod_name = str_init("memcached");

struct cachedb_url *memcached_script_urls = NULL;
static int memcache_exec_threshold=0;

int mc_set_connection(unsigned int type, void *val)
{
	return cachedb_store_url(&memcached_script_urls,(char *)val);
}

typedef struct mem_server_list_t
{
	char * servers;
	char * name;
	memcached_st * memc;
	struct mem_server_list_t * next;

}mem_server;




static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

mem_server * servers;

/** module parameters */
static param_export_t params[]={
	{"cachedb_url",        STR_PARAM|USE_FUNC_PARAM, (void*)&mc_set_connection },
	{"exec_threshold",     INT_PARAM,                &memcache_exec_threshold  },
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"cachedb_memcached",        /* module name */
	MOD_TYPE_CACHEDB,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,				            /* load function */
	NULL,            /* OpenSIPS module dependencies */
	0,                          /* exported functions */
	0,                          /* exported async functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
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


int wrap_memcached_insert(cachedb_con *con,str* attr, str* value,int expires)
{
	memcached_return_t  rc;
	memcached_con *connection;
	struct timeval start;

	start_expire_timer(start,memcache_exec_threshold);
	connection = (memcached_con *)con->data;

	rc = memcached_set(connection->memc,attr->s, attr->len , value->s,
				value->len, (time_t)expires, (uint32_t)0);

	_stop_expire_timer(start,memcache_exec_threshold,
		"cachedb_memcached insert",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);

	if( rc != MEMCACHED_SUCCESS)
	{
		LM_ERR("Failed to insert: %s\n",memcached_strerror(connection->memc,rc));
		return -1;
	}

	return 0;
}

int wrap_memcached_remove(cachedb_con *connection,str* attr)
{
	memcached_return_t  rc;
	memcached_con *con;
	struct timeval start;

	start_expire_timer(start,memcache_exec_threshold);
	con = (memcached_con *)connection->data;

	rc = memcached_delete(con->memc,attr->s,attr->len,0);

	_stop_expire_timer(start,memcache_exec_threshold,
		"cachedb_memcached remove",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);

	if( rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND)
	{
		LM_ERR("Failed to remove: %s\n",memcached_strerror(con->memc,rc));
		return -1;
	}

	return 0;
}

int wrap_memcached_get(cachedb_con *connection,str* attr, str* res)
{
	memcached_return_t  rc;
	char * ret;
	size_t ret_len;
	uint32_t fl;
	char * err;
	char * value;
	memcached_con *con;
	struct timeval start;

	start_expire_timer(start,memcache_exec_threshold);
	con = (memcached_con *)connection->data;

	ret = memcached_get(con->memc,attr->s, attr->len,
				&ret_len,&fl,&rc);

	if(ret == NULL)
	{
		if(rc == MEMCACHED_NOTFOUND)
		{
			res->s = NULL;
			res->len = 0;
			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached get",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		else
		{
			err = (char*)memcached_strerror(con->memc,rc);
			LM_ERR("Failed to get: %s\n",err );
			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached get",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}
	}

	value = pkg_malloc(ret_len);
	if( value == NULL)
	{
		LM_ERR("Memory allocation");
		_stop_expire_timer(start,memcache_exec_threshold,
			"cachedb_memcached get",attr->s,attr->len,0,
			cdb_slow_queries, cdb_total_queries);
		return -1;
	}

	memcpy(value,ret,ret_len);
	res->s = value;
	res->len = ret_len;

	free(ret);

	_stop_expire_timer(start,memcache_exec_threshold,
		"cachedb_memcached get",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 0;
}

/* TODO - once memcached_touch gets into libmemcached, also take care of expires */
int wrap_memcached_add(cachedb_con *connection,str* attr,int val,
		int expires,int *new_val)
{
	memcached_return_t  rc;
	memcached_con *con;
	uint64_t res;
	str ins_val;
	struct timeval start;

	start_expire_timer(start,memcache_exec_threshold);
	con = (memcached_con *)connection->data;

	rc = memcached_increment(con->memc,attr->s,attr->len,val,&res);

	if( rc != MEMCACHED_SUCCESS ) {
		if (rc == MEMCACHED_NOTFOUND) {
			ins_val.s = sint2str(val,&ins_val.len);
			if (wrap_memcached_insert(connection,attr,&ins_val,expires) < 0) {
				LM_ERR("failed to insert value\n");
				_stop_expire_timer(start,memcache_exec_threshold,
					"cachedb_memcached add",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			if (new_val)
				*new_val = val;

			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return 0;
		} else {
			LM_ERR("Failed to add: %s\n",memcached_strerror(con->memc,rc));
			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}
	}

	if (new_val)
		*new_val = (int)res;

	_stop_expire_timer(start,memcache_exec_threshold,
		"cachedb_memcached add",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 0;
}

/* TODO - once memcached_touch gets into libmemcached, also take care of expires */
int wrap_memcached_sub(cachedb_con *connection,str* attr,int val,
		int expires,int *new_val)
{
	memcached_return_t  rc;
	memcached_con *con;
	uint64_t res;
	str ins_val;
	struct timeval start;

	start_expire_timer(start,memcache_exec_threshold);
	con = (memcached_con *)connection->data;

	rc = memcached_decrement(con->memc,attr->s,attr->len,val,&res);

	if( rc != MEMCACHED_SUCCESS ) {
		if (rc == MEMCACHED_NOTFOUND) {
			ins_val.s = sint2str(val,&ins_val.len);
			if (wrap_memcached_insert(connection,attr,&ins_val,expires) < 0) {
				LM_ERR("failed to insert value\n");
				_stop_expire_timer(start,memcache_exec_threshold,
					"cachedb_memcached sub",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			if (new_val)
				*new_val = val;

			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached sub",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return 0;
		} else {
			LM_ERR("Failed to sub: %s\n",memcached_strerror(con->memc,rc));
			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached sub",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}
	}

	if (new_val)
		*new_val = (int)res;

	_stop_expire_timer(start,memcache_exec_threshold,
		"cachedb_memcached sub",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);

	return 0;
}

int wrap_memcached_get_counter(cachedb_con *connection,str* attr, int* res)
{
	memcached_return_t  rc;
	char * ret;
	size_t ret_len;
	uint32_t fl;
	char * err;
	memcached_con *con;
	struct timeval start;
	str rpl;

	start_expire_timer(start,memcache_exec_threshold);
	con = (memcached_con *)connection->data;

	ret = memcached_get(con->memc,attr->s, attr->len,
				&ret_len,&fl,&rc);

	if(ret == NULL)
	{
		if(rc == MEMCACHED_NOTFOUND)
		{
			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached counter fetch",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -2;
		}
		else
		{
			err = (char*)memcached_strerror(con->memc,rc);
			LM_ERR("Failed to get: %s\n",err );
			_stop_expire_timer(start,memcache_exec_threshold,
				"cachedb_memcached counter fetch",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return -1;
		}
	}

	rpl.len = (int)ret_len;
	rpl.s = ret;
	
	if (str2sint(&rpl,res) < 0) {
		LM_ERR("Failed to convert %.*s to int\n",(int)ret_len,ret);
		_stop_expire_timer(start,memcache_exec_threshold,
			"cachedb_memcached counter fetch",attr->s,attr->len,0,
			cdb_slow_queries, cdb_total_queries);
		free(ret);
		return -1;
		
	}

	_stop_expire_timer(start,memcache_exec_threshold,
		"cachedb_memcached counter fetch",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	free(ret);
	return 0;
}

#define MAX_HOSTPORT_SIZE 80
static char host_buff[MAX_HOSTPORT_SIZE];

memcached_con* memcached_new_connection(struct cachedb_id *id)
{
	memcached_con *con;
	memcached_server_st *server_list;
	memcached_return_t  rc;

	char *srv_list;
	int ret;

	if (id == NULL) {
		LM_ERR("null cached_id\n");
		return 0;
	}

	con = pkg_malloc(sizeof(memcached_con));
	if (con == NULL) {
		LM_ERR("no more pkg\n");
		return 0;
	}

	memset(con,0,sizeof(memcached_con));
	con->id = id;
	con->ref = 1;

	con->memc = memcached_create(NULL);

	memset(host_buff,0,MAX_HOSTPORT_SIZE);

	if (id->flags & CACHEDB_ID_MULTIPLE_HOSTS)
		srv_list = id->host;
	else {
		ret = snprintf(host_buff,MAX_HOSTPORT_SIZE,"%s:%d",id->host,id->port);
		if (ret<0 || ret>MAX_HOSTPORT_SIZE) {
			LM_ERR("failed to init con\n");
			pkg_free(con);
			return 0;
		}
		srv_list = host_buff;
	}

	server_list = memcached_servers_parse(srv_list);
	rc = memcached_server_push(con->memc,server_list);

	if( rc != MEMCACHED_SUCCESS) {
		LM_ERR("Push:%s\n",memcached_strerror(con->memc,rc));
		pkg_free(con);
		return 0;
	}


	rc = memcached_behavior_set(con->memc,
		MEMCACHED_BEHAVIOR_NO_BLOCK,1);

	if( rc != MEMCACHED_SUCCESS) {
		LM_ERR("Behavior Set:%s\n",memcached_strerror(con->memc,rc));
		pkg_free(con);
		return 0;
	}

	LM_DBG("successfully inited memcached connection\n");
	return con;
}

cachedb_con *memcached_init(str *url)
{
	return cachedb_do_init(url,(void *)memcached_new_connection);
}

void memcached_free_connection(cachedb_pool_con *con)
{
	memcached_con * c;

	if (!con) return;
	c = (memcached_con *)con;

	memcached_free(c->memc);
}

void memcached_destroy(cachedb_con *con) {
	cachedb_do_close(con,memcached_free_connection);
}


/**
 * init module function
 */

static int mod_init(void)
{
	cachedb_engine cde;

	LM_NOTICE("initializing module cachedb_memcached\n");
	memset(&cde, 0, sizeof cde);

	cde.name = cache_mod_name;

	cde.cdb_func.init = memcached_init;
	cde.cdb_func.destroy = memcached_destroy;
	cde.cdb_func.get = wrap_memcached_get;
	cde.cdb_func.get_counter = wrap_memcached_get_counter;
	cde.cdb_func.set = wrap_memcached_insert;
	cde.cdb_func.remove = wrap_memcached_remove;
	cde.cdb_func.add = wrap_memcached_add;
	cde.cdb_func.sub = wrap_memcached_sub;

	cde.cdb_func.capability = CACHEDB_CAP_BINARY_VALUE;

	if (register_cachedb(&cde) < 0) {
		LM_ERR("failed to initialize cachedb_memcached\n");
		return -1;
	}

	LM_DBG("successfully inited cachedb_memcached\n");
	return 0;
}

/**
 * Initialize children
 */
static int child_init(int rank)
{
	struct cachedb_url *it;
	cachedb_con *con;

	for (it = memcached_script_urls;it;it=it->next) {
		con = memcached_init(&it->url);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			return -1;
		}

		if (cachedb_put_connection(&cache_mod_name,con) < 0) {
			LM_ERR("failed to insert connection\n");
			return -1;
		}
	}

	cachedb_free_url(memcached_script_urls);
	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module cachedb_memcached ...\n");
	cachedb_end_connections(&cache_mod_name);
	return;
}
