/*
 * $Id$
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

#include "localcache.h"
#include "hash.h"




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
	"localcache",               /* module name */
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


/**
 * init module function
 */
static int mod_init(void)
{
	memcache_t ms;
	
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
	ms.name.s = "local";
	ms.name.len = 5;
        ms.store = lcache_htable_insert;
	ms.remove = lcache_htable_remove;
	ms.fetch = lcache_htable_fetch;
	ms.data = NULL;

	if( register_memcache(&ms)< 0)
	{
		LM_ERR("failed to register to core memory store interface\n");
		return -1;
	}

	if(cache_clean_period <= 0 )
	{
		LM_ERR("Worng parameter cache_clean_period - need a postive value\n");
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
