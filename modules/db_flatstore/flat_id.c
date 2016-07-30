/*
 * Flatstore module connection identifier
 *
 * Copyright (C) 2004 FhG Fokus
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
 */

#include <string.h>
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "flat_id.h"



/*
 * Create a new connection identifier
 */
struct flat_id* new_flat_id(const str* dir, const str* table)
{
	struct flat_id* ptr;

	if (!dir || !table || !dir->len || !table->len) {
		LM_ERR("invalid parameter(s)\n");
		return 0;
	}

	ptr = (struct flat_id*)pkg_malloc(sizeof(struct flat_id) +
			dir->len + table->len);
	if (!ptr) {
		LM_ERR("no pkg memory left\n");
		return 0;
	}
	memset(ptr, 0, sizeof(struct flat_id));

	ptr->dir.s = (char *)(ptr + 1);
	ptr->dir.len = dir->len;
	memcpy(ptr->dir.s, dir->s, dir->len);
	ptr->table.s = ptr->dir.s + dir->len;
	ptr->table.len = table->len;
	memcpy(ptr->table.s, table->s, table->len);

	return ptr;
}


/*
 * Compare two connection identifiers
 */
unsigned char cmp_flat_id(struct flat_id* id1, struct flat_id* id2)
{
	if (!id1 || !id2) return 0;
	if (id1->dir.len != id2->dir.len) return 0;
	if (id1->table.len != id2->table.len) return 0;

	if (memcmp(id1->dir.s, id2->dir.s, id1->dir.len)) return 0;
	if (memcmp(id1->table.s, id2->table.s, id1->table.len)) return 0;
	return 1;
}


/*
 * Free a connection identifier
 */
void free_flat_id(struct flat_id* id)
{
	if (!id) return;
	pkg_free(id);
}
