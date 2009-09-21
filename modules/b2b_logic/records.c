/*
 * $Id: records.c $
 *
 * back-to-back logic module
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../presence/hash.h"
#include "records.h"

b2bl_tuple_t* b2bl_insert_new(unsigned int hash_index, b2b_scenario_t* scenario,
		str* args[], str** b2bl_key_s)
{
	b2bl_tuple_t * it, *prev_it;
	b2bl_tuple_t* tuple;
	str* b2bl_key;
	int i;

	tuple = (b2bl_tuple_t*)shm_malloc(sizeof(b2bl_tuple_t));
	if(tuple == NULL)
	{
		LM_ERR("No more shared memory\n");
		return NULL;
	}
	memset(tuple, 0,sizeof(b2bl_tuple_t) );
	tuple->scenario = scenario;

	lock_get(&b2bl_htable[hash_index].lock);
	
	it = b2bl_htable[hash_index].first;

	if(it == NULL)
	{
		b2bl_htable[hash_index].first = tuple;
		tuple->prev = tuple->next = NULL;
		tuple->id = 0;
	}
	else
	{
		while(it)
		{
			prev_it = it;
			it = it->next;
		}
		prev_it->next = tuple;
		tuple->prev = prev_it;
		tuple->id = prev_it->id +1;
	}

	b2bl_key = b2bl_generate_key(hash_index, tuple->id);
	if(b2bl_key == NULL)
	{
		LM_ERR("failed to generate b2b logic key\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return NULL;
	}

	tuple->key = b2bl_key;

	/* copy the function parameters that customize the scenario */

	memset(tuple->scenario_params, 0, 5* sizeof(str));

	if(scenario && args)
	{
		for(i = 0; i< scenario->param_no; i++)
		{
			if(args[i] == NULL)
			{
				LM_ERR("Too few parameters. This scenario requires %d parameters\n",
						scenario->param_no);
				goto error;
			}
			
			tuple->scenario_params[i].s = (char*)shm_malloc(args[i]->len);
			if(tuple->scenario_params[i].s == NULL)
			{
				LM_ERR("No more shared memory\n");
				goto error;
			}
			memcpy(tuple->scenario_params[i].s, args[i]->s, args[i]->len);
			tuple->scenario_params[i].len = args[i]->len;
		}
	}

	lock_release(&b2bl_htable[hash_index].lock);

	*b2bl_key_s = b2bl_key;

	return tuple;
error:
	lock_release(&b2bl_htable[hash_index].lock);
	return 0;
}

void b2bl_delete(b2bl_tuple_t* tuple, unsigned int hash_index)
{
	b2bl_entity_id_t* entity, *next_entity;
	int i;

	LM_DBG("Delete record, hash_index=[%d], local_index=[%d]\n",
			hash_index, tuple->id);

	if(b2bl_htable[hash_index].first == tuple)
	{
		b2bl_htable[hash_index].first = tuple->next;
		if(tuple->next)
			tuple->next->prev = NULL;
	}
	else
	{
		if(tuple->prev)
			tuple->prev->next = tuple->next;
		if(tuple->next)
			tuple->next->prev = tuple->prev;
	}

	if(tuple->server)
	{
		if(tuple->server->key.s && tuple->server->key.len)
			b2b_api.entity_delete(B2B_SERVER, &tuple->server->key);
		shm_free(tuple->server);
	}
	entity = tuple->clients;
	while(entity)
	{
		next_entity = entity->next;
		if(entity->key.s && entity->key.len)
			b2b_api.entity_delete(B2B_CLIENT, &entity->key);
		shm_free(entity);
		entity = next_entity;
	}

//	if(tuple->bridge_entities[1] && tuple->bridge_entities[1]->key.s != NULL)
//		shm_free(tuple->bridge_entities[1]->key.s);

	for(i = 0; i< 5; i++)
	{
		if(tuple->scenario_params[i].s)
			shm_free(tuple->scenario_params[i].s);
	}

	if(tuple->key)
		shm_free(tuple->key);

	shm_free(tuple);
}

/* key format : hash_index.local *
 */

int b2bl_parse_key(str* key, unsigned int* hash_index,
		unsigned int* local_index)
{
	char* p;
	int hi_len;
	str s;

	if(!key || !key->s || !key->len)
		return -1;

	p= strchr(key->s, '.');
	if(p == NULL)
	{
		LM_ERR("Wrong b2b logic key\n");
		return -1;
	}

	hi_len = p - key->s;
	s.s = key->s;
	s.len = hi_len;
	if(str2int(&s, hash_index)< 0)
		return -1;
	
	s.s = p+1;
	s.len = key->s + key->len - s.s;
	if(str2int(&s, local_index)< 0)
		return -1;

	LM_DBG("hash_index = [%d]  - local_index= [%d]\n", *hash_index, *local_index);
	return 0;
}


str* b2bl_generate_key(unsigned int hash_index, unsigned int local_index)
{
	char buf[15];
	str* b2b_key;
	int len;

	len = sprintf(buf, "%d.%d", hash_index, local_index);

	b2b_key = (str*)shm_malloc(sizeof(str)+ len);
	if(b2b_key== NULL)
	{
		LM_ERR("no more shared memory\n");
		return NULL;
	}
	b2b_key->s = (char*)b2b_key + sizeof(str);
	memcpy(b2b_key->s, buf, len);
	b2b_key->len = len;

	return b2b_key;
}

b2bl_tuple_t* b2bl_search_tuple_safe(unsigned int hash_index, unsigned int local_index)
{
	b2bl_tuple_t* tuple;

	tuple = b2bl_htable[hash_index].first;
	while(tuple && tuple->id != local_index)
		tuple = tuple->next;

	return tuple;
}

int init_b2bl_htable(void)
{
	int i;
	b2bl_htable = (b2bl_table_t)shm_malloc(b2bl_hsize* sizeof(b2bl_entry_t));
	if(!b2bl_htable)
		ERR_MEM(SHARE_MEM);
	
	memset(b2bl_htable, 0, b2bl_hsize* sizeof(b2bl_entry_t));
	for(i= 0; i< b2bl_hsize; i++)
	{
		lock_init(&b2bl_htable[i].lock);
		b2bl_htable[i].first = NULL;
	}

	return 0;
error:
	return -1;
}

void destroy_b2bl_htable(void)
{
	int i;
	b2bl_tuple_t* tuple;


	for(i= 0; i< b2bl_hsize; i++)
	{
		lock_destroy(&b2bl_htable[i].lock);
		tuple = b2bl_htable[i].first;

		while(tuple)
		{
			b2bl_delete(tuple, i);
			tuple = b2bl_htable[i].first;
		}
	}
	shm_free(b2bl_htable);
}
