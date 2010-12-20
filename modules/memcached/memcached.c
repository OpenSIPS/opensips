/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include "../../memcache.h"
#include <libmemcached/memcached.h>






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
static int add_server( unsigned int type, void *val);


mem_server * servers;

/** module parameters */
static param_export_t params[]={
	{"server",        STR_PARAM|USE_FUNC_PARAM, (void*)&add_server },
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"memcached",               /* module name */
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


int wrap_memcached_insert(str* attr, str* value,
				unsigned int expires,void * memc)
{
	memcached_return  rc;

	rc = memcached_set((memcached_st*)memc,attr->s, attr->len , value->s,
				value->len, (time_t)expires, (uint32_t)0);

	if( rc != MEMCACHED_SUCCESS)
	{
		LM_ERR("Failed to insert: %s\n",memcached_strerror(memc,rc));
		return -1;
	}

	return 1;
}

void wrap_memcached_remove(str* attr,void * memc)
{
	memcached_return  rc;

	rc = memcached_delete((memcached_st*)memc,attr->s,attr->len,0);

	if( rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND)
	{
		LM_ERR("Failed to remove: %s\n",memcached_strerror(memc,rc));
	}
}

int wrap_memcached_get(str* attr, str* res,void * memc)
{
	memcached_return  rc;
	char * ret;
	size_t ret_len;
	uint32_t fl;
	char * err;
	char * value;
    


    
	ret = memcached_get((memcached_st*)memc,attr->s, attr->len,
				&ret_len,&fl,&rc);



	if(ret == NULL)
	{
		if(rc == MEMCACHED_NOTFOUND)
		{
			res->s = NULL;
			res->len = 0;
			return -2;
		}
		else
		{
			err = (char*)memcached_strerror(memc,rc);
			LM_ERR("Failed to get: %s\n",err );
			return -1;
		}
	}

	
	value = pkg_malloc(ret_len);
	if( value == NULL)
	{
		LM_ERR("Memory allocation");
		return -1;
	}

	memcpy(value,ret,ret_len);
	res->s = value;
	res->len = ret_len;

	free(ret);

	return 1;
}


/*
 * Parse method for parameters.
 * Parameters should be in the form:
 * [$WHITESPACE]$NAME[$WHITESPACE]=[$WHITESPACE]$LIST
 * where $LIST = list of comma separated $HOST[:$PORT]
 * E.g: x= localhost:9999,localhost,192.168.2.136:8888
 *
 * */
int parse_param(char* source, char **res_name,char ** res_value)
{
	char *name,*value;
	char *name_start,*value_start;
	int name_len, value_len;
	char * err;

	/* parse first whitespace */
	while(isspace(*source))
	{
		if(*source == 0)
		{
			err = "Missing name";
			goto parse_error;
		}
		source++;

	}

	/* extract name */
	name_start = source;
	name_len = 0;

	while( !isspace(*source) && *source != '=')
	{
		if(*source == 0)
		{
			err = "Missing '='";
			goto parse_error;
		}
		source++;
		name_len++;

	}

	/* parse second whitespace equal sign and third whitespace */
	while(isspace(*source) || *source == '=')
	{
		if(*source == 0)
		{
			err = "Missing value";
			goto parse_error;
		}
		source++;

	}

	/* parse list of adresses */
	value_start = source;
	value_len = 0;

	while(*source)
	{
		if(*source == 0)
		{
			err = "Missing value";
			goto parse_error;
		}
		source++;
		value_len++;
	}

	//place them in the desired retun fields
	name = (char*) pkg_malloc(name_len+1);
	if( name == NULL)
	{
		LM_ERR("Memory allocation");
		return -1;
	}

	value = (char*) pkg_malloc(value_len+1);
	if( value == NULL)
	{
		LM_ERR("Memory allocation");
		return -1;
	}

	memcpy(name,name_start,name_len);
	name[name_len]=0;

	memcpy(value,value_start,value_len);
	value[value_len]=0;

	*res_name = name;
	*res_value = value;

	LM_DBG("Name: %s\n",*res_name);
	LM_DBG("Value: %s\n",*res_value);


	return 0;
parse_error:
	LM_ERR("Parameter parse error - %s\n",err);
	return -1;

}

/*
 *
 * Method that adds a group of servers  to the server list.
 * It also allocates a new memcached_st structure that will
 * be used for initialization in each child
 *
 *
 * */
int add_server( unsigned int type, void *val)
{
	char * name;
	char * value;
	int ret;
	mem_server * node;

	ret = parse_param((char*)val,&name,&value);

	if( ret != 0)
		return ret;


	node = pkg_malloc(sizeof(mem_server));

	node->next = servers;
	node->memc = pkg_malloc(sizeof(memcached_st));
	node->name = name;
	node->servers = value;

	servers = node;
	return 0;
    
}

/**
 * init module function
 */

static int mod_init(void)
{
	memcache_t ms;
	mem_server *cur = servers;

	/* register each cache system */

	while(cur)
	{
		/* form the new name as "memcached_$NAME" */
		int full_len = 10+strlen(cur->name);
		char * full_name = (char*)pkg_malloc( full_len +1);
		sprintf(full_name,"memcached_%s",cur->name);

		/* set the information required */
		ms.name.s = full_name;
		ms.name.len = full_len;
		ms.store = wrap_memcached_insert;
		ms.remove = wrap_memcached_remove;
		ms.fetch = wrap_memcached_get;
		ms.data = cur->memc;

		if( register_memcache(&ms)< 0)
		{
			LM_ERR("failed to register to core memory "
					"store interface\n");
			return -1;
		}

		cur = cur -> next;

	}


	return 0;
}

/**
 * Initialize children
 */
static int child_init(int rank)
{

	memcached_return  rc;
	memcached_server_st *server_list;

	mem_server *cur;

	if(rank == PROC_MAIN || rank == PROC_TCP_MAIN)
	{
		return 0;
	}

	
	/* for each cache system and each child initialize the
	*  memcached_st structure that was previously allocated
	*/

	cur = servers;

	while(cur)
	{
		cur->memc = memcached_create(cur->memc);
		server_list = memcached_servers_parse( cur->servers );
		rc = memcached_server_push(cur->memc, server_list);

		if( rc != MEMCACHED_SUCCESS)
		{
			LM_ERR("Push:%s\n",memcached_strerror(cur->memc,rc));
			return -1;
		}


		rc = memcached_behavior_set(cur->memc,
			MEMCACHED_BEHAVIOR_NO_BLOCK,1);

		if( rc != MEMCACHED_SUCCESS)
		{
			LM_ERR("Behavior Set:%s\n",
				memcached_strerror(cur->memc,rc));
			return -1;
		}

		cur = cur->next;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	return;
}
