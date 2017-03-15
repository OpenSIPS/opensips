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

#ifndef _CACHEDB_POOL_H
#define _CACHEDB_POOL_H

#include "../str.h"
#include "cachedb_id.h"

typedef struct cachedb_pool_con_t{
	/* IMPORTANT: A structure overwriting this one defined
	 * in a module implementing this interface MUST always
	 * also overwrite these 3 fields, have them in the
	 * beginning
	 * EXMAPLE: modules/cachedb_local/cachedb_local.h lcache_con
	 * structure definition*/
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;
} cachedb_pool_con;

cachedb_pool_con* cachedb_pool_get(struct cachedb_id* id);
cachedb_pool_con** filter_pool_by_scheme(str *scheme,int *size);
void cachedb_pool_insert(cachedb_pool_con *con);
int cachedb_pool_remove(cachedb_pool_con *con);

#endif /* _CACHEDB_POOL_H */
