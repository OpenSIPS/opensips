/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "../../pt.h"
#include "../presence/hash.h"
#include "../presence/utils_func.h"
#include "records.h"
#include "entity_storage.h"

static void _print_entity(int index, b2bl_entity_id_t* e, int level)
{
	b2bl_entity_id_t* c = e;

	while (c)
	{
		LM_GEN1(level, ".type=[%d] index=[%d] [%p]->[%.*s] state=%d no=%d"
			" dlginfo=[%p] peer=[%p] prev:next=[%p][%p]\n",
			c->type, index, c, c->key.len, c->key.s, c->state, c->no,
			c->dlginfo, c->peer, c->prev, c->next);
		if (c->dlginfo)
			LM_GEN1(level, "..........dlginfo=[%p]->[%.*s][%.*s][%.*s]\n",
				c->dlginfo, c->dlginfo->callid.len, c->dlginfo->callid.s,
				c->dlginfo->fromtag.len, c->dlginfo->fromtag.s,
				c->dlginfo->totag.len, c->dlginfo->totag.s);
		c = c->next;
	}
}

void b2bl_print_tuple(b2bl_tuple_t* tuple, int level)
{
	int index;
	b2bl_entity_id_t* e;

	if(tuple)
	{
		LM_GEN1(level, "[%p]->[%.*s] to_del=[%d] lifetime=[%d]"
			" bridge_entities[%p][%p][%p]\n",
			tuple, tuple->key->len, tuple->key->s,
			tuple->to_del, tuple->lifetime,
			tuple->bridge_entities[0], tuple->bridge_entities[1],
			tuple->bridge_entities[2]);
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			e = tuple->servers[index];
			if (e) _print_entity(index, e, level);
		}
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			e = tuple->clients[index];
			if (e) _print_entity(index, e, level);
		}
		for (index = 0; index < MAX_BRIDGE_ENT; index++)
		{
			e = tuple->bridge_entities[index];
			if (e)
				LM_GEN1(level, ".type=[%d] index=[%d] [%p]"
					" peer=[%p] prev:next=[%p][%p]\n",
					e->type, index, e, e->peer, e->prev, e->next);
		}
	}
}

/* Function that inserts a new b2b_logic record - the lock remains taken */
b2bl_tuple_t* b2bl_insert_new(struct sip_msg* msg,
		unsigned int hash_index, b2b_scenario_t* scenario,
		str* args[], str* body, str* custom_hdrs, int local_index,
		str** b2bl_key_s, int db_flag, int repl_flag)
{
	b2bl_tuple_t *it, *prev_it;
	b2bl_tuple_t* tuple = NULL;
	str* b2bl_key;
	int i;
	int size;
	str extra_headers={0, 0};
	str local_contact= server_address;

	if(msg)
	{
		if (get_local_contact(msg->rcv.bind_address, NULL, &local_contact) < 0)
		{
			LM_ERR("Failed to get received address\n");
			local_contact= server_address;
		}
	}

	size = sizeof(b2bl_tuple_t) + local_contact.len;
	tuple = (b2bl_tuple_t*)shm_malloc(size);
	if(tuple == NULL)
	{
		LM_ERR("No more shared memory\n");
		goto error;
	}
	memset(tuple, 0, size);

	tuple->local_contact.s = (char*)(tuple + 1);
	memcpy(tuple->local_contact.s, local_contact.s, local_contact.len);
	tuple->local_contact.len = local_contact.len;

	tuple->scenario = scenario;

	if(msg)
	{
		if(b2b_extra_headers(msg, NULL, custom_hdrs, &extra_headers)< 0)
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
	} else if (repl_flag == TUPLE_REPL_RECV && custom_hdrs->s) {
		/* all extra headers are received for replicated tuples */
		tuple->extra_headers = shm_malloc(sizeof(str) + custom_hdrs->len);
		if(tuple->extra_headers == NULL)
		{
			LM_ERR("No more shared memory\n");
			goto error;
		}
		tuple->extra_headers->s = (char*)tuple->extra_headers + sizeof(str);
		memcpy(tuple->extra_headers->s, custom_hdrs->s, custom_hdrs->len);
		tuple->extra_headers->len = custom_hdrs->len;
	}

	if(use_init_sdp || (scenario && scenario->use_init_sdp))
	{
		if (!body && scenario && scenario->body.len)
		{
			body = &scenario->body;
			/* we also have to add the content type here */
			tuple->extra_headers = (str *)shm_realloc(tuple->extra_headers,
					sizeof(str) + extra_headers.len +
					14/* "Content-Type: " */ + 2/* "\r\n\" */ +
					scenario->body_type.len);
			if (!tuple->extra_headers)
			{
				LM_ERR("cannot add extra headers\n");
				goto error;
			}
			/* restore initial data */
			tuple->extra_headers->s = (char*)tuple->extra_headers + sizeof(str);
			tuple->extra_headers->len = extra_headers.len;
			memcpy(tuple->extra_headers->s + tuple->extra_headers->len,
					"Content-Type: ", 14);
			tuple->extra_headers->len += 14;
			memcpy(tuple->extra_headers->s + tuple->extra_headers->len,
					scenario->body_type.s, scenario->body_type.len);
			tuple->extra_headers->len += scenario->body_type.len;
			memcpy(tuple->extra_headers->s + tuple->extra_headers->len, "\r\n", 2);
			tuple->extra_headers->len += 2;
		}
		if (body) {
			/* alloc separate memory for sdp */
			tuple->sdp.s = shm_malloc(body->len);
			if (!tuple->sdp.s) {
				LM_ERR("no more shm memory for sdp body\n");
				goto error;
			}
			memcpy(tuple->sdp.s, body->s, body->len);
			tuple->sdp.len = body->len;
		}
	}


	/* copy the function parameters that customize the scenario */
	memset(tuple->scenario_params, 0, MAX_SCENARIO_PARAMS* sizeof(str));
	if(scenario && args)
	{
		for(i = 0; i< scenario->param_no; i++)
		{
			if (args[i]==NULL || args[i]->s==NULL || args[i]->len==0)
			{
				LM_DBG("Fewer parameters, expected [%d] received [%d]\n",
						scenario->param_no, i);
				break;
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
	tuple->scenario_state = B2B_NOTDEF_STATE;

	if (repl_flag != TUPLE_REPL_RECV)
		lock_get(&b2bl_htable[hash_index].lock);

	if(local_index>= 0) /* a local index specified */
	{
		tuple->id = local_index;
		if(b2bl_htable[hash_index].first == NULL)
		{
			b2bl_htable[hash_index].first = tuple;
			tuple->prev = tuple->next = NULL;
		}
		else
		{
			prev_it = 0;
			/*insert it in the proper place  */
			for(it = b2bl_htable[hash_index].first; it && it->id<local_index; it=it->next)
			{
				prev_it = it;
			}
			if(!prev_it)
			{
				b2bl_htable[hash_index].first = tuple;
				tuple->prev = 0;
				tuple->next = it;
				it->prev = tuple;
			}
			else
			{
				tuple->prev = prev_it;
				prev_it->next = tuple;
				tuple->next = it;
				if(it)
					it->prev = tuple;
			}
		}
	}
	else
	{

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
	}
	LM_DBG("hash index [%d]:\n", hash_index);
	for(it = b2bl_htable[hash_index].first; it; it=it->next)
	{
		LM_DBG("id [%d]", it->id);
	}

	b2bl_key = b2bl_generate_key(hash_index, tuple->id);
	if(b2bl_key == NULL)
	{
		LM_ERR("failed to generate b2b logic key\n");
		goto error;
	}
	tuple->key = b2bl_key;

	*b2bl_key_s = b2bl_key;

	tuple->db_flag = db_flag;
	tuple->repl_flag = repl_flag;

	tuple->hash_index = hash_index;

	LM_DBG("new tuple [%p]->[%.*s]\n", tuple, b2bl_key->len, b2bl_key->s);

	return tuple;
error:
	if (tuple) {
		if (tuple->sdp.s)
			shm_free(tuple->sdp.s);
		shm_free(tuple);
	}
	if (repl_flag != TUPLE_REPL_RECV)
		lock_release(&b2bl_htable[hash_index].lock);
	return 0;
}

b2bl_entity_id_t* b2bl_search_entity(b2bl_tuple_t* tuple, str* key, int src,
	b2bl_entity_id_t*** head)
{
	int index;
	b2bl_entity_id_t* e;

	/* search the entity */
	if(src == B2B_SERVER)
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			*head = &tuple->servers[index];
			e= tuple->servers[index];
			while (e)
			{
				LM_DBG("Key [%.*s]\n",e->key.len,e->key.s);
				if (e->key.len == key->len &&
					strncmp(e->key.s, key->s, key->len) == 0)
					return e;
				e = e->next;
			}
		}
	else
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			*head = &tuple->clients[index];
			e = tuple->clients[index];
			while (e)
			{
				LM_DBG("Key [%.*s]\n",e->key.len,e->key.s);
				if (e->key.len == key->len &&
					strncmp(e->key.s, key->s, key->len) == 0)
					return e;
				e = e->next;
			}
		}

	return e;
}

void unchain_ent(b2bl_entity_id_t *ent, b2bl_entity_id_t **first_ent)
{
	if(*first_ent == ent)
	{
		*first_ent = ent->next;
		if(ent->next)
			ent->next->prev = NULL;
	}
	else
	{
		if(ent->prev)
			ent->prev->next = ent->next;
		if(ent->next)
			ent->next->prev = ent->prev;
	}
	ent->prev = NULL;
	ent->next = NULL;
}


int b2bl_drop_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple)
{
	b2bl_entity_id_t* e;
	unsigned int index;
	int found = 0;
	int i;

	for (index = 0; index < MAX_B2BL_ENT; index++)
	{
		e = tuple->servers[index];
		if (e == entity)
		{
			found = 1;
			switch(index)
			{
				case 0:
					tuple->servers[0] = tuple->servers[1];
					/* fall through */
				case 1:
					tuple->servers[1] = tuple->servers[2];
					/* fall through */
				case 2:
					tuple->servers[2] = NULL;
					for ( i=0 ; i<index ; i++ ) {
						if (tuple->servers[index] == NULL)
							LM_ERR("inconsistent tuple [%p]->[%.*s]\n",
							tuple, tuple->key->len, tuple->key->s);
					}
					break;
				default:
					LM_CRIT("we should never end up here\n");
			}
			break;
		}
		e = tuple->clients[index];
		if (e == entity)
		{
			found = 1;
			switch(index)
			{
				case 0:
					tuple->clients[0] = tuple->clients[1];
					/* fall through */
				case 1:
					tuple->clients[1] = tuple->clients[2];
					/* fall through */
				case 2:
					tuple->clients[2] = NULL;
					for ( i=0 ; i<index ; i++ ) {
						if (tuple->clients[index] == NULL)
							LM_ERR("inconsistent tuple [%p]->[%.*s]\n",
							tuple, tuple->key->len, tuple->key->s);
					}
					break;
				default:
					LM_CRIT("we should never end up here\n");
			}
			break;
		}
	}
	return found;
}

void b2bl_remove_single_entity(b2bl_entity_id_t *entity, b2bl_entity_id_t **head,
	unsigned int hash_index)
{
	unchain_ent(entity, head);
	b2bl_htable[hash_index].locked_by = process_no;
	b2b_api.entity_delete(entity->type, &entity->key, entity->dlginfo, 0, 1);
	b2bl_htable[hash_index].locked_by = -1;
	LM_DBG("destroying dlginfo=[%p]\n", entity->dlginfo);
	if(entity->dlginfo)
		shm_free(entity->dlginfo);
	shm_free(entity);

	return;
}

void b2bl_delete_entity(b2bl_entity_id_t* entity, b2bl_tuple_t* tuple,
	unsigned int hash_index, int b2be_del)
{
	unsigned int i;
	int found = 0;

	if (entity->next || entity->prev)
	{
		LM_ERR("Inconsistent entity [%p]\n", entity);
		b2bl_print_tuple(tuple, L_CRIT);
		return;
	}

	found = b2bl_drop_entity(entity, tuple);

	if(found)
	{
		LM_DBG("delete entity [%p]->[%.*s] from tuple [%.*s]\n",
			entity, entity->key.len, entity->key.s, tuple->key->len, tuple->key->s);
		if (b2be_del) {
			b2bl_htable[hash_index].locked_by = process_no;
			b2b_api.entity_delete(entity->type, &entity->key, entity->dlginfo, 1, 1);
			b2bl_htable[hash_index].locked_by = -1;
		}
	}
	else if (entity->key.len)
	{
		LM_WARN("entity [%p]->[%.*s] not found for tuple [%.*s]\n",
			entity, entity->key.len, entity->key.s, tuple->key->len, tuple->key->s);
	}

	if(entity->dlginfo)
		shm_free(entity->dlginfo);

	for(i = 0; i< MAX_BRIDGE_ENT; i++)
		if(tuple->bridge_entities[i] == entity)
			tuple->bridge_entities[i] = NULL;

/*	if(entity->peer && entity->peer->peer==entity)
		entity->peer->peer = NULL;
*/

	for(i = 0; i< MAX_B2BL_ENT; i++)
	{
		if(tuple->servers[i] && tuple->servers[i]->peer==entity)
			tuple->servers[i]->peer= NULL;
		if(tuple->clients[i] && tuple->clients[i]->peer==entity)
			tuple->clients[i]->peer= NULL;
	}

	LM_INFO("delete tuple [%.*s], entity [%.*s]\n",
			tuple->key->len, tuple->key->s, entity->key.len, entity->key.s);
	shm_free(entity);

	/* for debuging */
	b2bl_print_tuple(tuple, L_DBG);
}


int b2bl_add_client(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity)
{
	int i, pos;
	LM_INFO("adding entity [%p]->[%.*s] to tuple [%p]->[%.*s]\n",
		entity, entity->key.len, entity->key.s,
		tuple, tuple->key->len, tuple->key->s);

	for (pos = 0; pos < MAX_B2BL_ENT && tuple->clients[pos]; pos++);

	if (pos == MAX_B2BL_ENT) {
 		LM_ERR("unable to add entity [%p]->[%.*s] to tuple [%p]->[%.*s], all spots taken\n",
 			entity, entity->key.len, entity->key.s,
 			tuple, tuple->key->len, tuple->key->s);
 		return -1;
 	}


	/* check for inconsistencies */
	for (i = pos + 1; i < MAX_B2BL_ENT; i++)
		if (tuple->clients[i]) {
			LM_ERR("inconsistent clients state for tuple [%p]->[%.*s] pos %d\n",
				tuple, tuple->key->len, tuple->key->s, i);
			return -1;
		}
	tuple->clients[pos] = entity;

	b2bl_print_tuple(tuple, L_DBG);
	return 0;
}


int b2bl_add_server(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity)
{
	LM_INFO("adding entity [%p]->[%.*s] to tuple [%p]->[%.*s]\n",
		entity, entity->key.len, entity->key.s,
		tuple, tuple->key->len, tuple->key->s);

	if (tuple->servers[0] == NULL)
	{
		if (tuple->servers[1])
		{
			LM_ERR("inconsistent servers state for tuple [%p]->[%.*s]\n",
				tuple, tuple->key->len, tuple->key->s);
			return -1;
		}
		tuple->servers[0] = entity;
	}
	else if (tuple->servers[1] == NULL)
		tuple->servers[1] = entity;
	else
	{
		LM_ERR("unable to add entity [%p]->[%.*s] to tuple [%p]->[%.*s], all spots taken\n",
			entity, entity->key.len, entity->key.s,
			tuple, tuple->key->len, tuple->key->s);
		return -1;
	}

	b2bl_print_tuple(tuple, L_DBG);
	return 0;
}


void b2bl_delete(b2bl_tuple_t* tuple, unsigned int hash_index,
		int db_del, int del_entities)
{
	b2bl_entity_id_t *e;
	int i;
	int index;
	b2bl_cb_params_t cb_params;
	struct b2b_ctx_val *v;

	LM_DBG("Delete record [%p]->[%.*s], hash_index=[%d], local_index=[%d]\n",
			tuple, tuple->key->len, tuple->key->s, hash_index, tuple->id);

	/*
	 * razvanc: if the tuple is not actually deleted, we do not have to call
	 * the DESTROY callback
	 */
	if(db_del && tuple->cbf && tuple->cb_mask&B2B_DESTROY_CB)
	{
		memset(&cb_params, 0, sizeof(b2bl_cb_params_t));
		cb_params.param = tuple->cb_param;
		cb_params.stat = NULL;
		cb_params.msg = NULL;
		/* setting it to 0 but it has no meaning in this callback type */
		cb_params.entity = 0;
		tuple->cbf(&cb_params, B2B_DESTROY_CB);
	}
	if(db_del)
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

	for (index = 0; index < MAX_B2BL_ENT; index++)
	{
		e = tuple->servers[index];
		if (e)
		{
			if (e->key.s && e->key.len && del_entities) {
				b2bl_htable[hash_index].locked_by = process_no;
				b2b_api.entity_delete(e->type, &e->key, e->dlginfo, 0, 1);
				b2bl_htable[hash_index].locked_by = -1;
			}
			if(e->dlginfo)
				shm_free(e->dlginfo);
			shm_free(e);
		}
		e = tuple->clients[index];
		if (e)
		{
			if (e->key.s && e->key.len && del_entities) {
				b2bl_htable[hash_index].locked_by = process_no;
				b2b_api.entity_delete(e->type, &e->key, e->dlginfo, 0, 1);
				b2bl_htable[hash_index].locked_by = -1;
			}
			if(e->dlginfo)
				shm_free(e->dlginfo);
			shm_free(e);
		}
	}
	/* clean up all entities in b2b_entities from db */
	if(del_entities)
		b2b_api.entities_db_delete(*tuple->key);

//	if(tuple->bridge_entities[1] && tuple->bridge_entities[1]->key.s != NULL)
//		shm_free(tuple->bridge_entities[1]->key.s);

	for(i = 0; i< MAX_SCENARIO_PARAMS; i++)
	{
		if(tuple->scenario_params[i].s)
			shm_free(tuple->scenario_params[i].s);
	}

	if(tuple->key)
		shm_free(tuple->key);

	if(tuple->extra_headers)
		shm_free(tuple->extra_headers);

	if(tuple->b1_sdp.s)
		shm_free(tuple->b1_sdp.s);

	if (tuple->sdp.s && tuple->sdp.s != tuple->b1_sdp.s)
		shm_free(tuple->sdp.s);

	while (tuple->vals) {
		v = tuple->vals;
		tuple->vals = tuple->vals->next;
		shm_free(v);
	}

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
	{
		tuple = tuple->next;
	}

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
			b2bl_delete(tuple, i, 0, 0);
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
#define HDR_BUF_SIZE  256
int b2b_extra_headers(struct sip_msg* msg, str* b2bl_key, str* custom_hdrs,
															str* extra_headers)
{
	char* p;
	struct hdr_field* require_hdr;
	struct hdr_field* rseq_hdr;
	struct hdr_field* subscription_state_hdr;
	struct hdr_field* hdr;
	struct hdr_field* hdrs[HDR_LST_LEN + HDR_DEFAULT_LEN];
	regmatch_t pmatch;
	int hdrs_no = 0;
	int len = 0;
	int i;
	int custom_hdrs_len = 0;
	char tmp;

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
	if(msg->event)
		hdrs[hdrs_no++] = msg->event;


	require_hdr = get_header_by_static_name( msg, "Require");
	if(require_hdr)
		hdrs[hdrs_no++] = require_hdr;

	rseq_hdr = get_header_by_static_name( msg, "RSeq");
	if(rseq_hdr)
		hdrs[hdrs_no++] = rseq_hdr;

	subscription_state_hdr = get_header_by_static_name( msg,
		"Subscription-state");
	if(subscription_state_hdr)
		hdrs[hdrs_no++] = subscription_state_hdr;

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

	if (custom_headers_re)
	{
		for (hdr=msg->headers; hdr; hdr=hdr->next) {
			tmp = hdr->name.s[hdr->name.len];
			hdr->name.s[hdr->name.len] = '\0';
			i = regexec(custom_headers_re, hdr->name.s, 1, &pmatch, 0);
			hdr->name.s[hdr->name.len] = tmp;

			if (i == 0)
			{
				/* check if added twice */
				for(i = 0; i < hdrs_no; i++)
				{
					if ( hdrs[i]->name.len == hdr->name.len &&
					strncmp(hdrs[i]->name.s, hdr->name.s, hdr->name.len)==0 )
						break;
				}
				if (i == hdrs_no) /* Doubles not found -> add it */
					hdrs[hdrs_no++] = hdr;
			}
		}
	}

	/* calculate the length*/
	for(i = 0; i< hdrs_no; i++)
		len += hdrs[i]->len;

	if(init_callid_hdr.len && msg->callid)
		len+= init_callid_hdr.len + msg->callid->len;

	if(custom_hdrs && custom_hdrs->s && custom_hdrs->len)
	{
		custom_hdrs_len = custom_hdrs->len;
		len += custom_hdrs_len;
	}

	if(len == 0) return 0;

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
	if(custom_hdrs_len)
	{
		memcpy(p, custom_hdrs->s, custom_hdrs_len);
		p += custom_hdrs_len;
	}

	if(init_callid_hdr.s && msg->callid)
	{
		memcpy(p, init_callid_hdr.s, init_callid_hdr.len);
		p += init_callid_hdr.len;
		len = sprintf(p, ": %.*s",
			(int)(msg->callid->name.s +msg->callid->len -msg->callid->body.s),
			msg->callid->body.s);
		p += len;
	}

	extra_headers->len = p - extra_headers->s;

	return 0;
}
