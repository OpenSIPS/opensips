/*
 * Hash functions for cached domain table
 *
 * Copyright (C) 2002-2008 Juha Heinanen
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


#include "../../dprint.h"
#include "../../ut.h"
#include "../../hash_func.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "domain_mod.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define dom_hash(_s)  core_case_hash( _s, 0, DOM_HASH_SIZE)


/* Add domain to hash table */
int hash_table_install (struct domain_list **hash_table, str *d, str *a)
{
	struct domain_list *np;
	unsigned int hash_val;

	np = (struct domain_list *) shm_malloc(sizeof(*np) + d->len + a->len);
	if (np == NULL) {
		LM_ERR("Cannot allocate memory for hash table entry\n");
		return -1;
	}
	memset(np, 0, sizeof(*np));

	np->domain.len = d->len;
	np->domain.s = (char *)(np + 1);
	memcpy(np->domain.s, d->s, d->len);

	np->attrs.len = a->len;
	/* check to see if there is a value there */
	if (a->s) {
		np->attrs.s = np->domain.s + d->len;
		memcpy(np->attrs.s, a->s, a->len);
	} else {
		np->attrs.s = NULL;
	}

	hash_val = dom_hash(&np->domain);
	np->next = hash_table[hash_val];
	hash_table[hash_val] = np;

	return 1;
}


/* Check if domain exists in hash table */
int hash_table_lookup (struct sip_msg *msg, str *domain, pv_spec_t *pv)
{
	struct domain_list *np;
	pv_value_t val;

	for (np = (*hash_table)[dom_hash(domain)]; np != NULL; np = np->next) {
		if ((np->domain.len == domain->len) &&
			(strncasecmp(np->domain.s, domain->s, domain->len) == 0)) {
			if (pv && np->attrs.s) {
				val.rs = np->attrs;
				val.flags = PV_VAL_STR;
				if (pv_set_value(msg, pv, 0, &val) != 0)
					LM_ERR("cannot set attributes value\n");
			}
			return 1;
		}
	}

	return -1;
}


int hash_table_mi_print(struct domain_list **hash_table, mi_item_t *domains_arr)
{
	int i;
	struct domain_list *np;
	mi_item_t *domain_item;

	if(hash_table==0)
		return -1;
	for (i = 0; i < DOM_HASH_SIZE; i++) {
		np = hash_table[i];
		while (np) {
			domain_item = add_mi_object(domains_arr, NULL, 0);
			if (!domain_item)
				return -1;

			if (add_mi_string(domain_item, MI_SSTR("name"),
				np->domain.s, np->domain.len) < 0)
				return -1;
			if (np->attrs.s)
				if (add_mi_string(domain_item, MI_SSTR("attributes"),
					np->attrs.s, np->attrs.len) < 0)
					return -1;

			np = np->next;
		}
	}
	return 0;
}

/* Free contents of hash table */
void hash_table_free (struct domain_list **hash_table)
{
	int i;
	struct domain_list *np, *next;

	if(hash_table==0)
		return;

	for (i = 0; i < DOM_HASH_SIZE; i++) {
		np = hash_table[i];
		while (np) {
			next = np->next;
			shm_free(np);
			np = next;
		}
		hash_table[i] = NULL;
	}
}
