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
 *  2009-09-04  first version (andreidragus)
 *  2017-12-12  use opensips_json_c_helper.h (besser82)
 */

#include "opensips_json_c_helper.h"

#if JSON_C_VERSION_NUM < JSON_C_VER_013
void array_list_del_idx(struct array_list * arr, int idx)
{
	int i;

	if(idx >= arr->length)
		return;


	arr->free_fn(arr->array[idx]);
	arr->length--;

	for(i=idx; i<arr->length; i++)
		arr->array[i]  = arr->array[i+1];
};
#endif

void json_object_array_del(struct json_object* obj, int idx)
{
#if JSON_C_VERSION_NUM >= JSON_C_VER_013
	struct array_list * arr = json_object_get_array(obj);
	array_list_del_idx(arr, idx, arr->length);
#else
	array_list_del_idx(obj->o.c_array, idx);
#endif
};
