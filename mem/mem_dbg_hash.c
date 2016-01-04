#include "mem_dbg_hash.h"
#include <stdlib.h>
#include <string.h>

void dbg_ht_init(mem_dbg_htable_t htable) {
	int i;

	for(i=0; i < DBG_HASH_SIZE; i++)
		htable[i] = NULL;
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
		for(; entry->next; entry = entry->next)
			if (!strcmp(entry->next->file, file) && !strcmp(entry->next->func, func)
				&& entry->next->line == line) {
				entry->next->size += size;
				entry->next->no_fragments++;
				break;
			}
		/* not found, insert new entry in this bucket */
		if (!entry->next) {
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
		}

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