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
 *  2009-09-04  first version (andreidragus)
 */

#include <json/json.h>
#include <json/json_object_private.h>

void array_list_del_idx( struct array_list * arr, int idx)
{
	int i;

	if( idx >= arr->length)
		return;


	arr->free_fn(arr->array[idx]);
	arr->length--;

	for( i=idx; i<arr->length; i++ )
		arr->array[i]  = arr->array[i+1];
};

void json_object_array_del(struct json_object* obj, int idx)
{
	array_list_del_idx(obj->o.c_array, idx);
};