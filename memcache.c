/*
 * $Id$
 *
 * Copyright (C) 2009 Anca Vamanu
 *
 * This file is part of OpenSIPS, a free SIP server.
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

/*
 * OpenSIPS Management Memory Store
 *
 * The OpenSIPS memory store is a interface to memcache systems used for to
 * alleviate database load by storing objects in memory.
 *
 * Modules containing specific memcache implementations must register
 * the control functions to this interface.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "dprint.h"
#include "mem/mem.h"
#include "memcache.h"

struct memcache_node 
{
	memcache_t cs;
	struct memcache_node* next;
};

static struct memcache_node* memcache_list = NULL;

static inline memcache_t* lookup_memcache(str name)
{
	struct memcache_node* cs_node;

	cs_node = memcache_list;

	while(cs_node)
	{
		if (name.len == cs_node->cs.name.len &&
				strncmp(name.s, cs_node->cs.name.s, name.len) == 0)
			return &cs_node->cs;

		cs_node = cs_node->next;
	}

	return 0;
}


int register_memcache(memcache_t* cs_entry)
{
	struct memcache_node* cs_node;

	if(cs_entry == NULL)
	{
		LM_ERR("null argument\n");
		return -1;
	}

	if (lookup_memcache( cs_entry->name))
	{
		LM_ERR("memcache system <%.*s> already registered\n",
				cs_entry->name.len, cs_entry->name.s);
		return -1;
	}

	cs_node = (struct memcache_node*)pkg_malloc(
		sizeof(struct memcache_node) + cs_entry->name.len);
	if (cs_node== NULL)
	{
		LM_ERR("no more shared memory\n");
		return -1;
	}

	cs_node->cs.name.s = (char*)cs_node + sizeof(struct memcache_node);
	memcpy(cs_node->cs.name.s, cs_entry->name.s, cs_entry->name.len);
	cs_node->cs.name.len = cs_entry->name.len;

	cs_node->cs.store = cs_entry->store;
	cs_node->cs.remove = cs_entry->remove;
	cs_node->cs.fetch = cs_entry->fetch;
	cs_node->cs.data = cs_entry -> data;

	cs_node->next = memcache_list;
	memcache_list = cs_node;

	LM_DBG("registered cache system [%.*s]\n", cs_node->cs.name.len,
			cs_node->cs.name.s);

	return 0;
}

int cache_store(str* memcache_system, str* attr, str* val,
		unsigned int expires)
{
	memcache_t* cs;

	if(memcache_system == NULL || attr == NULL || val == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	cs = lookup_memcache(*memcache_system);
	if(cs == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no memory memcache system with"
				" this name registered\n",
				memcache_system->len,memcache_system->s);
		return -1;
	}

	return cs->store(attr, val, expires,cs->data);

}

int cache_remove(str* memcache_system, str* attr)
{
	memcache_t* cs;

	if(memcache_system == NULL || attr == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	cs = lookup_memcache(*memcache_system);
	if(cs == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no memory memcache system with"
				" this name registered\n",
				memcache_system->len,memcache_system->s);
		return -1;
	}
	cs->remove(attr,cs->data);

	return 1;
}

int cache_fetch(str* memcache_system, str* attr, str* val)
{
	memcache_t* cs;

	if(memcache_system == NULL || attr == NULL )
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	cs = lookup_memcache(*memcache_system);
	if(cs == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no memory memcache system with"
				" this name registered\n",
				memcache_system->len,memcache_system->s);
		return -1;
	}
	

	return cs->fetch(attr, val,cs->data);
}

