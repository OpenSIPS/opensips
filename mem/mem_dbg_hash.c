/*
 * Copyright (C) 2015-2016 OpenSIPS Solutions
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
 *  2015-11-18 initial version (Vlad Patrascu)
 */

#include "mem_dbg_hash.h"
#include <stdlib.h>
#include <string.h>

void dbg_ht_init(mem_dbg_htable_t htable)
{
	memset(htable, 0, sizeof(mem_dbg_htable_t));
}

int dbg_ht_update(mem_dbg_htable_t htable, const char *file, const char *func, unsigned long line, unsigned long size)
{
	unsigned int hash_code;
	struct mem_dbg_entry *entry, *new;

	hash_code = get_dbg_hash(file, func, line);
	entry = htable[hash_code];

	if (!entry) {
		/* insert first entry in this bucket */
		entry = malloc(sizeof(struct mem_dbg_entry));
		if (!entry)
			return -1;
		entry->file = file;
		entry->func	= func;
		entry->line = line;
		entry->size = size;
		entry->no_fragments = 1;
		entry->next = NULL;
		htable[hash_code] = entry;
		return 0;
	} else {
		/* find entry and update */
		if (!strcmp(entry->file, file) && !strcmp(entry->func, func)
			&& entry->line == line) {
			entry->size += size;
			entry->no_fragments++;
			return 0;
		}

		for (; entry->next; entry = entry->next)
			if (!strcmp(entry->next->file, file) && !strcmp(entry->next->func, func)
				&& entry->next->line == line) {
				entry->next->size += size;
				entry->next->no_fragments++;
				return 0;
			}

		/* not found, append a new entry to the end of this bucket */
		new = malloc(sizeof(struct mem_dbg_entry));
		if (!new)
			return -1;

		new->file = file;
		new->func = func;
		new->line = line;
		new->size = size;
		new->no_fragments = 1;
		new->next = NULL;
		entry->next = new;

		return 0;
	}
}

void dbg_ht_free(mem_dbg_htable_t htable)
{
	struct mem_dbg_entry *it, *tmp;
	int i;

	for(i=0; i < DBG_HASH_SIZE; i++) {
		it = htable[i];
		while (it) {
			tmp = it;
			it = it->next;
			free(tmp);
		}
		htable[i] = NULL;
	}
}
