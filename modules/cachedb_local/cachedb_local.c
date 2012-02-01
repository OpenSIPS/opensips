/*
 * $Id: localcache.c 6910 2010-05-26 09:23:27Z bogdan_iancu $
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "cachedb_local.h"
#include "hash.h"

str cache_mod_name = str_init("local");
static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

lcache_t* cache_htable = NULL;
int cache_htable_size = 9;
int cache_clean_period = 600;

void localcache_clean(unsigned int ticks,void *param);

static param_export_t params[]={
	{ "cache_table_size",   INT_PARAM, &cache_htable_size },
	{ "cache_clean_period", INT_PARAM, &cache_clean_period},
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"cachedb_local",               /* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	0,                          /* exported functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init                  /* per-child init function */
};

lcache_con* lcache_new_connection(struct cachedb_id* id)
{
	lcache_con *con;
	
	if (id->flags != CACHEDB_ID_NO_URL) {
		LM_ERR("bogus url for local cachedb\n");
		return 0;
	}

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
	
	if(cache_htable_size< 1)
		cache_htable_size= 512;
	else
		cache_htable_size= 1<< cache_htable_size;

	if(lcache_htable_init(cache_htable_size) < 0)
	{
		LM_ERR("failed to initialize cache hash table\n");
		return -1;
	}

	/* register the cache system */
	cde.name = cache_mod_name;

	cde.cdb_func.init = lcache_init;
	cde.cdb_func.destroy = lcache_destroy;
	cde.cdb_func.get = lcache_htable_fetch;
	cde.cdb_func.set = lcache_htable_insert;
	cde.cdb_func.remove = lcache_htable_remove;
	cde.cdb_func.add = lcache_htable_add;
	cde.cdb_func.sub = lcache_htable_sub;
	
	cde.cdb_func.capability = CACHEDB_CAP_BINARY_VALUE;

	if(cache_clean_period <= 0 )
	{
		LM_ERR("Worng parameter cache_clean_period - need a postive value\n");
		return -1;
	}

	if( register_cachedb(&cde)< 0)
	{
		LM_ERR("failed to register to core memory store interface\n");
		return -1;
	}

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

	/* register timer to delete the expired entries */
	register_timer(localcache_clean, 0, cache_clean_period);

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
	lcache_htable_destroy();
}

void localcache_clean(unsigned int ticks,void *param)
{
	int i;
	lcache_entry_t* me1, *me2;

	LM_DBG("start\n");
	for(i = 0; i< cache_htable_size; i++)
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
