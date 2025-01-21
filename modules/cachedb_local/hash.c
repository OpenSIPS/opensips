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

#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "cachedb_local.h"
#include "cachedb_local_replication.h"
#include "hash.h"

void lcache_htable_remove_safe(osips_free_f free_f, str attr, lcache_entry_t** it);

int lcache_htable_init(struct lcache_col *col)
{
	int i = 0, j;

	col->col_htable = func_malloc(col->malloc, sizeof *col->col_htable);
	if (!col->col_htable) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(col->col_htable, 0, sizeof *col->col_htable);

	col->col_htable->size = col->size;

	col->col_htable->htable = func_malloc(col->malloc, col->col_htable->size *
		sizeof(lcache_t));
	if(col->col_htable->htable == NULL)
	{
		LM_ERR("no more shared memory\n");
		func_free(col->free, col->col_htable);
		return -1;
	}
	memset(col->col_htable->htable, 0, col->col_htable->size * sizeof(lcache_t));

	for(i= 0; i< col->col_htable->size; i++)
	{
		if(lock_init(&col->col_htable->htable[i].lock)== 0)
		{
			LM_ERR("failed to initialize lock [%d]\n", i);
			goto error;
		}
	}

	return 0;

error:
	for(j = 0; j< i; j++)
	{
		lock_destroy(&col->col_htable->htable[j].lock);
	}
	func_free(col->free, col->col_htable->htable);
	func_free(col->free, col->col_htable);
	return -1;
}

void lcache_htable_destroy(lcache_htable_t *htable, osips_free_f free_f)
{
	int i;
	lcache_entry_t* me1, *me2;

	if(!htable || !htable->htable)
		return;

	for(i = 0; i< htable->size; i++)
	{
		lock_destroy(&htable->htable[i].lock);
		me1 = htable->htable[i].entries;
		while(me1)
		{
			me2 = me1->next;
			func_free(free_f, me1);
			me1 = me2;
		}
	}
	func_free(free_f, htable->htable);
	func_free(free_f, htable);
}

int lcache_htable_insert(cachedb_con *con,str* attr, str* value, int expires)
{
	lcache_col_t *cache_col;

	cache_col = ((lcache_con*)con->data)->col;
	if ( !cache_col ) {
		LM_ERR("url <%.*s> does not have any collection associated with!",
				con->url.len, con->url.s);
		return -1;
	}

	return _lcache_htable_insert(cache_col, attr, value, expires, 0);
}

int _lcache_htable_insert(lcache_col_t *cache_col, str* attr, str* value,
	int expires, int isrepl)
{
	lcache_entry_t* me, *it;
	int hash_code;
	int size;
	struct timeval start;
	lcache_t* cache_htable;

	cache_htable = cache_col->col_htable->htable;

	size= sizeof(lcache_entry_t) + attr->len + value->len;

	me = (lcache_entry_t*)func_malloc(cache_col->malloc, size);
	if(me == NULL)
	{
		LM_ERR("no more shared memory\n");
		return -1;
	}
	memset(me, 0, size);

	start_expire_timer(start,local_exec_threshold);

	me->attr.s = (char*)me + (sizeof(lcache_entry_t));
	memcpy(me->attr.s, attr->s, attr->len);
	me->attr.len = attr->len;

	me->value.s = (char*)me + (sizeof(lcache_entry_t)) + attr->len;
	memcpy(me->value.s, value->s, value->len);
	me->value.len = value->len;
	if( expires != 0) {
		me->expires = get_ticks() + expires;
		me->ttl = expires;
	}

	if (isrepl)
		me->synced = 1;

	hash_code= core_hash( attr, NULL, cache_col->col_htable->size);
	lock_get(&cache_htable[hash_code].lock);

	it = cache_htable[hash_code].entries;

	/* if a previous record for the same attr delete it */
	lcache_htable_remove_safe(cache_col->free, *attr, &it);

	me->next = it;
	cache_htable[hash_code].entries = me;

	lock_release(&cache_htable[hash_code].lock);

	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local insert",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);

	/* replicate */
	if (cluster_id && isrepl != 1 && cache_col->replicated)
		replicate_cache_insert(&cache_col->col_name, attr, value, expires);

	return 1;
}

void lcache_htable_remove_safe(osips_free_f free_f, str attr, lcache_entry_t** it_p)
{
	lcache_entry_t* me = NULL, *it= *it_p;

	while(it)
	{
		if(it->attr.len == attr.len &&
				(strncmp(it->attr.s, attr.s, attr.len) == 0))
		{

			if(me)
				me->next = it->next;
			else
				*it_p = it->next;

			func_free(free_f, it);

			return;
		}
		me = it;
		it = it->next;
	}
	LM_DBG("entry not found\n");
}

int lcache_htable_remove(cachedb_con *con,str* attr)
{
	lcache_col_t *cache_col;

	cache_col = ((lcache_con*)con->data)->col;
	if ( !cache_col ) {
		LM_ERR("url <%.*s> does not have any collection associated with!",
				con->url.len, con->url.s);
		return -1;
	}

	return _lcache_htable_remove(cache_col, attr, 0);
}

int _lcache_htable_remove(lcache_col_t *cache_col, str* attr, int isrepl)
{
	int hash_code;
	struct timeval start;
	lcache_t* cache_htable;

	cache_htable = cache_col->col_htable->htable;


	start_expire_timer(start,local_exec_threshold);

	hash_code= core_hash( attr, NULL, cache_col->col_htable->size);
	lock_get(&cache_htable[hash_code].lock);

	lcache_htable_remove_safe(cache_col->free, *attr, &cache_htable[hash_code].entries);

	lock_release(&cache_htable[hash_code].lock);

	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local remove",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);

	if (cluster_id && isrepl != 1 && cache_col->replicated)
		replicate_cache_remove(&cache_col->col_name, attr);

	return 0;
}

int lcache_htable_add(cachedb_con *con,str *attr,int val,int expires,int *new_val)
{
	int hash_code;
	lcache_entry_t *it=NULL,*it_prev=NULL;
	int old_value;
	char *new_value;
	int new_len;
	str ins_val;
	struct timeval start;
	int ttl;

	lcache_t* cache_htable;
	lcache_col_t* cache_col;

	cache_col = ((lcache_con*)con->data)->col;
	if ( !cache_col ) {
		LM_ERR("url <%.*s> does not have any collection associated with!",
				con->url.len, con->url.s);
		return -1;
	}

	cache_htable = cache_col->col_htable->htable;

	start_expire_timer(start,local_exec_threshold);

	hash_code = core_hash(attr, NULL,cache_col->col_htable->size);
	lock_get(&cache_htable[hash_code].lock);

	it = cache_htable[hash_code].entries;
	while (it) {
		if (it->attr.len == attr->len &&
				memcmp(it->attr.s,attr->s,attr->len) == 0) {
			if (it->expires !=0 && it->expires < get_ticks()) {
				/* found an expired entry  -> delete it */
				if(it_prev)
					it_prev->next = it->next;
				else
					cache_htable[hash_code].entries = it->next;

				func_free(cache_col->free, it);
				lock_release(&cache_htable[hash_code].lock);

				ins_val.s = sint2str(val,&ins_val.len);
				if (lcache_htable_insert(con,attr,&ins_val,expires) < 0) {
					LM_ERR("failed to insert value\n");
					_stop_expire_timer(start,local_exec_threshold,
						"cachedb_local add",attr->s,attr->len,0,
						cdb_slow_queries, cdb_total_queries);
					return -1;
				}

				if (new_val)
					*new_val = val;

				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local add",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return 0;
			}

			/* found our valid entry */
			if (str2sint(&it->value,&old_value) < 0) {
				LM_ERR("not an integer\n");
				lock_release(&cache_htable[hash_code].lock);
				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local add",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}

			old_value+=val;
			expires = it->expires;
			ttl = it->ttl;
			new_value = sint2str(old_value,&new_len);
			it = func_realloc(cache_col->realloc,
				it, sizeof(lcache_entry_t) + attr->len +new_len);
			if (it == NULL) {
				LM_ERR("failed to realloc struct\n");
				lock_release(&cache_htable[hash_code].lock);
				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local add",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}

			if (it_prev)
				it_prev->next = it;
			else
				cache_htable[hash_code].entries = it;

			it->attr.s = (char*)(it + 1);
			it->value.s =(char *)(it + 1) + attr->len;
			it->expires = expires;
			it->ttl = ttl;

			memcpy(it->value.s,new_value,new_len);
			it->value.len = new_len;
			lock_release(&cache_htable[hash_code].lock);
			if (new_val)
				*new_val = old_value;
			_stop_expire_timer(start,local_exec_threshold,
				"cachedb_local add",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return 0;
		}

		it_prev = it;
		it = it->next;
	}

	lock_release(&cache_htable[hash_code].lock);

	/* not found */
	ins_val.s = sint2str(val,&ins_val.len);
	if (lcache_htable_insert(con,attr,&ins_val,expires) < 0) {
		LM_ERR("failed to insert value\n");
		_stop_expire_timer(start,local_exec_threshold,
			"cachedb_local add",attr->s,attr->len,0,
			cdb_slow_queries, cdb_total_queries);
		return -1;
	}

	if (new_val)
		*new_val = val;
	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local add",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return 0;
}

int lcache_htable_sub(cachedb_con *con,str *attr,int val,int expires,int *new_val)
{
	return lcache_htable_add(con,attr,-val,expires,new_val);
}

/*
 *	return :
 *		1  - if found
 *		-2 - if not found
 *		-1 - if error
 * */
int lcache_htable_fetch(cachedb_con *con,str* attr, str* res)
{
	int hash_code;
	lcache_entry_t* it = NULL, *it_aux = NULL;
	char* value;
	struct timeval start;

	lcache_t* cache_htable;
	lcache_col_t* cache_col;

	cache_col = ((lcache_con*)con->data)->col;

	if ( !cache_col ) {
		LM_ERR("url <%.*s> does not have any collection associated with!",
				con->url.len, con->url.s);
		return -1;
	}

	cache_htable = cache_col->col_htable->htable;

	start_expire_timer(start,local_exec_threshold);

	hash_code= core_hash( attr, NULL, cache_col->col_htable->size);
	lock_get(&cache_htable[hash_code].lock);

	it = cache_htable[hash_code].entries;

	while(it)
	{
		if(it->attr.len == attr->len &&
				(strncmp(it->attr.s, attr->s, attr->len) == 0))
		{
			if( it->expires != 0 && it->expires < get_ticks())
			{
				/* found an expired entry  -> delete it */
				if(it_aux)
					it_aux->next = it->next;
				else
					cache_htable[hash_code].entries = it->next;

				func_free(cache_col->free, it);

				lock_release(&cache_htable[hash_code].lock);
				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local fetch",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -2;
			}
			value = (char*)pkg_malloc(it->value.len);
			if(value == NULL)
			{
				LM_ERR("no more memory\n");
				lock_release(&cache_htable[hash_code].lock);
				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local fetch",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -1;
			}
			memcpy(value, it->value.s, it->value.len);
			res->len = it->value.len;
			res->s = value;
			lock_release(&cache_htable[hash_code].lock);
			_stop_expire_timer(start,local_exec_threshold,
				"cachedb_local fetch",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return 1;
		}

		it_aux = it;
		it = it->next;
	}

	lock_release(&cache_htable[hash_code].lock);
	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local fetch",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return -2;
}

int lcache_htable_fetch_counter(cachedb_con* con,str* attr,int *val)
{
	int hash_code;
	lcache_entry_t* it = NULL, *it_aux = NULL;
	int ret;
	struct timeval start;

	lcache_t* cache_htable;
	lcache_col_t* cache_col;

	cache_col = ((lcache_con*)con->data)->col;
	if ( !cache_col ) {
		LM_ERR("url <%.*s> does not have any collection associated with!",
				con->url.len, con->url.s);
		return -1;
	}

	cache_htable = cache_col->col_htable->htable;

	start_expire_timer(start,local_exec_threshold);

	hash_code= core_hash( attr, NULL, cache_col->col_htable->size);
	lock_get(&cache_htable[hash_code].lock);

	it = cache_htable[hash_code].entries;

	while(it)
	{
		if(it->attr.len == attr->len &&
				(strncmp(it->attr.s, attr->s, attr->len) == 0))
		{
			if( it->expires != 0 && it->expires < get_ticks())
			{
				/* found an expired entry  -> delete it */
				if(it_aux)
					it_aux->next = it->next;
				else
					cache_htable[hash_code].entries = it->next;

				func_free(cache_col->free, it);

				lock_release(&cache_htable[hash_code].lock);
				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local fetch_counter",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -2;
			}
			if (str2sint(&it->value,&ret) != 0) {
				LM_ERR("Not a counter key\n");
				lock_release(&cache_htable[hash_code].lock);
				_stop_expire_timer(start,local_exec_threshold,
					"cachedb_local fetch_counter",attr->s,attr->len,0,
					cdb_slow_queries, cdb_total_queries);
				return -3;
			}
			if (val)
				*val = ret;
			lock_release(&cache_htable[hash_code].lock);
			_stop_expire_timer(start,local_exec_threshold,
				"cachedb_local fetch_counter",attr->s,attr->len,0,
				cdb_slow_queries, cdb_total_queries);
			return 1;
		}

		it_aux = it;
		it = it->next;
	}

	lock_release(&cache_htable[hash_code].lock);
	_stop_expire_timer(start,local_exec_threshold,
		"cachedb_local fetch_counter",attr->s,attr->len,0,
		cdb_slow_queries, cdb_total_queries);
	return -2;
}

int lcache_htable_iter_keys(cachedb_con *con,
                            int (*kv_func)(const str *_k, const str *_v))
{
	lcache_t* cache_htable;
	lcache_col_t* cache_col;
	lcache_entry_t* it;
	int i, n = 0;

	cache_col = ((lcache_con *)con->data)->col;
	if (!cache_col) {
		LM_ERR("url <%.*s> does not have any collection associated with!",
		       con->url.len, con->url.s);
		return -1;
	}

	cache_htable = cache_col->col_htable->htable;

	for (i = 0; i < cache_col->size; i++) {
		lock_get(&cache_htable[i].lock);

		for (it = cache_htable[i].entries; it; it = it->next)
			if (kv_func(&it->attr, &it->value) == 0)
				n++;

		lock_release(&cache_htable[i].lock);
	}

	/* number of successfully processed keys */
	return n;
}
