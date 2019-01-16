/*
 * generic key-value storage support
 *
 * Copyright (C) 2018 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef __KV_STORE_H__
#define __KV_STORE_H__

#include "../../map.h"

int_str_t *kv_get(map_t _store, const str* _key);
int_str_t *kv_put(map_t _store, const str* _key, const int_str_t* _val);
void       kv_del(map_t _store, const str* _key);

/*
 * Serialize the given K/V store as a JSON, SHM mem string.
 * On oom, a NULL string is returned.
 */
str store_serialize(map_t _store);

/* Free a buffer returned by store_serialize() */
void store_free_buffer(str *serialized);

/*
 * De-serialize the given JSON string into an SHM map_t object
 * On oom, a NULL map_t is returned.
 */
map_t store_deserialize(const str *input);

void store_destroy(map_t _store);

#endif /* __KV_STORE_H__ */
