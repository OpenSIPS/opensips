/*
 * $Id: localcache.h 5236 2009-01-30 16:18:37Z bogdan_iancu $
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-01-30  initial version (Anca Vamanu)
 */

#ifndef _MEMCACHE_
#define _MEMCACHE_

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"
#include "hash.h"

extern lcache_t* cache_htable;
extern int cache_htable_size;

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;
} lcache_con;

#endif
