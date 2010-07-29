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


void b2bl_print_clients_list(b2bl_tuple_t* tuple)
{
	if(tuple)
	{
		/* parcurg lista de clienti */
		b2bl_entity_id_t* c;
		c = tuple->clients;
		while(c)
		{
			LM_INFO("[%p] %.*s->\n", c, c->key.len, c->key.s);
			c = c->next;
		}
		LM_INFO("0\n");
	}
}

/* Function that inserts a new b2b_logic record - the lock remains taken */
b2bl_tuple_t* b2bl_insert_new(struct sip_msg* msg,
		unsigned int hash_index, b2b_scenario_t* scenario,
		str* args[], str* body, str** b2bl_key_s)
{
	b2bl_tuple_t * it, *prev_it;
	b2bl_tuple_t* tuple;
	str* b2bl_key;
	int i;
	static char buf[256];
	int buf_len= 255;
	int size;
	str extra_headers={0, 0};

	size = sizeof(b2bl_tuple_t);
	if(body && use_init_sdp)
	{
		size+= body->len;
	}

	tuple = (b2bl_tuple_t*)shm_malloc(size);
	if(tuple == NULL)
	{
		LM_ERR("No more shared memory\n");
		return NULL;
	}
	memset(tuple, 0, size);

	if(body && use_init_sdp)
	{
		tuple->sdp.s = (char*)tuple + sizeof(b2bl_tuple_t);
		memcpy(tuple->sdp.s, body->s, body->len);
		tuple->sdp.len =  body->len;
	}

	LM_DBG("pointer [%p]\n", tuple);

	tuple->scenario = scenario;

	tuple->lifetime = 60 + (int)time(NULL);

	if(msg)
	{
		if(b2b_extra_headers(msg, 0, &extra_headers)< 0)
		{
			LM_ERR("Failed to create extra headers\n");
			goto error;
		}
		if(extra_headers.s)
		{
			tuple->extra_headers = (str*)shm_malloc(sizeof(str) + extra_headers.len);
			if(tuple->extra_headers == NULL)
			{
				LM_ERR("No more shared memory\n");
				goto error;
			}
			tuple->extra_headers->s = (char*)tuple->extra_headers + sizeof(str);
			memcpy(tuple->extra_headers->s, extra_headers.s, extra_headers.len);
			tuple->extra_headers->len = extra_headers.len;
			pkg_free(extra_headers.s);
		}
	}

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
			/* must print the value of the argument */
			if(msg)
			{
				buf_len= 255;
				if(pv_printf(msg, (pv_elem_t*)args[i], buf, &buf_len)<0)
				{
					LM_ERR("cannot print the format\n");
					goto error;
				}

				tuple->scenario_params[i].s = (char*)shm_malloc(buf_len);
				if(tuple->scenario_params[i].s == NULL)
				{
					LM_ERR("No more shared memory\n");
					goto error;
				}
				memcpy(tuple->scenario_params[i].s, buf, buf_len);
				tuple->scenario_params[i].len = buf_len;
				LM_DBG("Printed parameter [%.*s]\n", buf_len, buf);
			}
			else
			{
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
	}
	tuple->scenario_state = B2B_NOTDEF_STATE;

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

	*b2bl_key_s = b2bl_key;
	tuple->db_flag = INSERTDB_FLAG;

	return tuple;
error:
	lock_release(&b2bl_htable[hash_index].lock);
	return 0;
}

void b2bl_delete_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple)
{
	b2bl_entity_id_t* prev;
	int found = 0;

	LM_DBG("Delete entity = %p\n", entity);

	if(tuple->server == entity)
	{
		tuple->server = NULL;
		found = 1;
	}
	else
	{
		/* search the entity to delete */
		if(tuple->clients == entity)
		{
			tuple->clients = entity->next;
			found = 1;
		}
		else
		{
			prev = tuple->clients;
			while(prev && prev->next != entity)
			{
				prev = prev->next;
			}
			if(prev)
			{
				prev->next = entity->next;
				found= 1;
			}
		}
	}
	if(found)
		b2b_api.entity_delete(entity->type, &entity->key, entity->dlginfo);

	if(entity->dlginfo)
		shm_free(entity->dlginfo);

	if(entity->peer && entity->peer->peer==entity)
		entity->peer->peer = NULL;

	shm_free(entity);

	/* for debuging */
	LM_INFO("delete [%.*s]\n", tuple->key->len, tuple->key->s);
	b2bl_print_clients_list(tuple);
}

void b2bl_add_client_list(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity)
{
	entity->next = tuple->clients;
	tuple->clients= entity;
	LM_INFO("add [%.*s]\n", tuple->key->len, tuple->key->s);
	b2bl_print_clients_list(tuple);
}


void b2bl_delete(b2bl_tuple_t* tuple, unsigned int hash_index,
		int not_del_b2be)
{
	b2bl_entity_id_t* entity, *next_entity;
	int i;

	LM_DBG("Delete record, hash_index=[%d], local_index=[%d]\n",
			hash_index, tuple->id);
	LM_DBG("pointer [%p]\n", tuple);

	if(!not_del_b2be)
		b2bl_db_delete(tuple);
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
		if(tuple->server->key.s && tuple->server->key.len && !not_del_b2be)
			b2b_api.entity_delete(B2B_SERVER, &tuple->server->key,
					tuple->server->dlginfo);
		if(tuple->server->dlginfo)
			shm_free(tuple->server->dlginfo);
		shm_free(tuple->server);
	}
	entity = tuple->clients;
	while(entity)
	{
		next_entity = entity->next;
		if(entity->key.s && entity->key.len && !not_del_b2be)
			b2b_api.entity_delete(B2B_CLIENT, &entity->key,
				entity->dlginfo);
		if(entity->dlginfo)
			shm_free(entity->dlginfo);
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

	if(tuple->extra_headers)
		shm_free(tuple->extra_headers);

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

	if(!b2bl_htable)
		return;

	for(i= 0; i< b2bl_hsize; i++)
	{
		lock_destroy(&b2bl_htable[i].lock);
		tuple = b2bl_htable[i].first;

		while(tuple)
		{
			b2bl_delete(tuple, i, 1);
			tuple = b2bl_htable[i].first;
		}
	}
	shm_free(b2bl_htable);
}

/* Take headers to pass on the other side:
 *	Content-Type: 
 *	Allow: 
 *	Supported:
 *	Require
 *	RSeq
 *	Session-Expires
 *	Min-SE
*/
int b2b_extra_headers(struct sip_msg* msg, str* b2bl_key, str* extra_headers)
{
	char* p;
	struct hdr_field* require_hdr;
	struct hdr_field* rseq_hdr;
	struct hdr_field* hdr;
	struct hdr_field* hdrs[HDR_LST_LEN + HDR_DEFAULT_LEN];
	int hdrs_no = 0;
	int len = 0;
	int i;

	if(msg->content_type)
		hdrs[hdrs_no++] = msg->content_type;
	if(msg->supported)
		hdrs[hdrs_no++] = msg->supported;
	if(msg->allow)
		hdrs[hdrs_no++] = msg->allow;
	if(msg->proxy_require)
		hdrs[hdrs_no++] = msg->proxy_require;
	if(msg->session_expires)
		hdrs[hdrs_no++] = msg->session_expires;
	if(msg->min_se)
		hdrs[hdrs_no++] = msg->min_se;

	require_hdr = get_header_by_static_name( msg, "Require");
	if(require_hdr)
		hdrs[hdrs_no++] = require_hdr;

	rseq_hdr = get_header_by_static_name( msg, "RSeq");
	if(rseq_hdr)
		hdrs[hdrs_no++] = rseq_hdr;


	/* add also the custom headers */
	for(i = 0; i< custom_headers_lst_len; i++)
	{
		hdr = get_header_by_name( msg, custom_headers_lst[i].s,
				custom_headers_lst[i].len);
		if(hdr)
		{
			hdrs[hdrs_no++] = hdr;
		}
	}

	/* calculate the length*/
	for(i = 0; i< hdrs_no; i++)
		len += hdrs[i]->len;

	if(len == 0)
		return 0;

	extra_headers->s = (char*)pkg_malloc(len);
	if(extra_headers->s == NULL)
	{
		LM_ERR("No more memory\n");
		return -1;
	}

	p = extra_headers->s;

	/* construct the headers string */
	for(i = 0; i< hdrs_no; i++)
	{
		memcpy(p, hdrs[i]->name.s, hdrs[i]->len);
		p += hdrs[i]->len;
	}
	extra_headers->len = p - extra_headers->s;

	return 0;
}

