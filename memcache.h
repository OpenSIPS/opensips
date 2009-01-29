/*
 * $Id: memcache.h $
 *
 * Copyright (C) 2009 Anca Vamanu
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
 *  2009-01-29  first version (Anca Vamanu)
 */
#ifndef _MEM_CACHE_H_
#define _MEM_CACHE_H_

#include "str.h"

typedef int (memcache_store_f)(char* name, char* value, unsigned int expires);
typedef void (memcache_remove_f)(char* name);
typedef int (memcache_fetch_f)(char* name, char** val);

typedef struct memcache {
	str name;
	memcache_store_f* store;
	memcache_remove_f* remove;
	memcache_fetch_f* fetch;
}memcache_t;


int register_memcache(memcache_t* cs);

/* functions to be used from script */
int cache_store(char* memcache, char* attr, char* val,
		unsigned int expires);
int cache_remove(char* memcache, char* attr);
int cache_fetch(char* memcache, char* attr, char** val);

#endif
