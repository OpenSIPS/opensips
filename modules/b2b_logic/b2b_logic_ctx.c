/*
 * Copyright (C) 2022 OpenSIPS Solutions
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
 */

#include "records.h"
#include "b2b_logic_ctx.h"

/* The function will return with the lock aquired if successful */
static b2bl_tuple_t *b2bl_ctx_get_tuple(str *key)
{
	b2bl_tuple_t *tuple = b2bl_get_tuple(key);
	if (!tuple) {
		LM_ERR("could not find logic tuple [%.*s]\n", key->len, key->s);
		return NULL;
	}
	return tuple;
}

static void b2bl_ctx_release_tuple(b2bl_tuple_t *tuple)
{
	lock_release(&b2bl_htable[tuple->hash_index].lock);
}


int b2bl_ctx_register_int(context_destroy_f f)
{
	return context_register_int(CONTEXT_B2B_LOGIC, f);
}

int b2bl_ctx_register_str(context_destroy_f f)
{
	return context_register_str(CONTEXT_B2B_LOGIC, f);
}

int b2bl_ctx_register_ptr(context_destroy_f f)
{
	return context_register_ptr(CONTEXT_B2B_LOGIC, f);
}

void b2bl_ctx_put_int(str *key, int pos, int data)
{
	b2bl_tuple_t *tuple = b2bl_ctx_get_tuple(key);

	if (!tuple) {
		LM_ERR("Failed to store data in b2b logic context\n");
		return;
	}

	context_put_int(CONTEXT_B2B_LOGIC, context_of(tuple), pos, data);
	b2bl_ctx_release_tuple(tuple);
}

void b2bl_ctx_put_str(str *key, int pos, str *data)
{
	b2bl_tuple_t *tuple = b2bl_ctx_get_tuple(key);

	if (!tuple) {
		LM_ERR("Failed to store data in b2b logic context\n");
		return;
	}

	context_put_str(CONTEXT_B2B_LOGIC, context_of(tuple), pos, data);
	b2bl_ctx_release_tuple(tuple);
}

void b2bl_ctx_put_ptr(str *key, int pos, void *data)
{
	b2bl_tuple_t *tuple = b2bl_ctx_get_tuple(key);

	if (!tuple) {
		LM_ERR("Failed to store data in b2b logic context\n");
		return;
	}

	context_put_ptr(CONTEXT_B2B_LOGIC, context_of(tuple), pos, data);
	b2bl_ctx_release_tuple(tuple);
}

int b2bl_ctx_get_int(str *key, int pos)
{
	int ret;
	b2bl_tuple_t *tuple = b2bl_ctx_get_tuple(key);

	if (!tuple) {
		LM_ERR("Failed to retrieve data from b2b logic context\n");
		return 0;
	}

	ret = context_get_int(CONTEXT_B2B_LOGIC, context_of(tuple), pos);
	b2bl_ctx_release_tuple(tuple);
	return ret;
}

str *b2bl_ctx_get_str(str *key, int pos)
{
	str *ret;
	b2bl_tuple_t *tuple = b2bl_ctx_get_tuple(key);
	static str nullstr = {0,0};

	if (!tuple) {
		LM_ERR("Failed to retrieve data from b2b logic context\n");
		return &nullstr;
	}

	ret = context_get_str(CONTEXT_B2B_LOGIC, context_of(tuple), pos);
	b2bl_ctx_release_tuple(tuple);
	return ret;
}

void *b2bl_ctx_get_ptr(str *key, int pos)
{
	void *ret;
	b2bl_tuple_t *tuple = b2bl_ctx_get_tuple(key);

	if (!tuple) {
		LM_ERR("Failed to retrieve data from b2b logic context\n");
		return NULL;
	}

	ret = context_get_ptr(CONTEXT_B2B_LOGIC, context_of(tuple), pos);
	b2bl_ctx_release_tuple(tuple);
	return ret;
}
