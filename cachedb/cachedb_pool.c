/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * history:
 * ---------
 *  2011-09-xx  created (vlad-paiu)
 */


#include "../dprint.h"
#include "../mem/mem.h"
#include "cachedb_pool.h"
#include <string.h>

static cachedb_pool_con *cachedb_pool = NULL;

cachedb_pool_con* cachedb_pool_get(struct cachedb_id *id)
{
	cachedb_pool_con *it;

	for (it=cachedb_pool;it;it=it->next)
		if (cmp_cachedb_id(id,it->id)) {
			it->ref++;
			return it;
		}

	return 0;
}

cachedb_pool_con** filter_pool_by_scheme(str *scheme,int* lst_size)
{
	cachedb_pool_con *it;
	cachedb_pool_con **lst=NULL;
	int size = 0;
	int alloc_size = 0;
	
	for (it=cachedb_pool;it;it=it->next) {
		if (memcmp(scheme->s,it->id->scheme,scheme->len) == 0) {
			if (alloc_size - size == 0) {
				alloc_size=(alloc_size==0)?2:2*alloc_size;
				lst = pkg_realloc(lst,alloc_size * sizeof(cachedb_pool_con*));
				if (lst == NULL) {
					LM_ERR("No more pkg \n");
					*lst_size = 0;
					return NULL;
				}
			}

			lst[size]=it;
			size++;
		}
	}

	*lst_size = size;
	return lst;
}

void cachedb_pool_insert(cachedb_pool_con *con)
{
	if (!con)
		return;

	con->next = cachedb_pool;
	cachedb_pool = con;
}

int cachedb_pool_remove(cachedb_pool_con *con)
{
	cachedb_pool_con *it;

	if (!con)
		return -2;

	if (con->ref > 1) {
		con->ref--;
		return 0;
	}

	if (cachedb_pool == con) {
		cachedb_pool = cachedb_pool->next;
	} else {
		it = cachedb_pool;
		while (it) {
			if (it->next == con)
				break;
			it = it->next;
		}

		if (!it) {
			LM_ERR("BUG - conn not found in pool\n");
			return -1;
		}

		it->next = con->next;
	}

	return 1;
}
