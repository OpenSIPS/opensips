/*
 * PERMISSIONS module
 *
 * Copyright (C) 2003 Miklós Tirpák (mtirpak@sztaki.hu)
 * Copyright (C) 2006 Juha Heinanen
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
 */
#include <stdio.h>
#include "address.h"
#include "partitions.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../db/db.h"
#include "../../lib/csv.h"

#define ERR 1

str part_db_url = str_init("db_url");
str part_table_name = str_init("table_name");

/* since default partition will probably be used the most
 * it deserves a pointer for its own*/
struct pm_partition *partitions, *default_partition;

struct pm_part_struct *part_structs;

static void *alloc_partitions(void)
{
	partitions = pkg_malloc(sizeof(struct pm_partition));
	if (partitions)
		memset(partitions, 0, sizeof(struct pm_partition));
	return partitions;
}

static void *alloc_default_partition(void)
{
	default_partition = pkg_malloc(sizeof(struct pm_partition));
	if (default_partition) {
		memset(default_partition, 0, sizeof(struct pm_partition));
		default_partition->name = def_part;

		default_partition->next = partitions;
		partitions = default_partition;
	}

	return default_partition;
}

struct pm_partition *get_partitions(void)
{
	return partitions;
}

struct pm_partition *get_partition(str *part_name)
{

	struct pm_partition *it;

	for (it=get_partitions(); it; it=it->next) {
		if (!str_strcmp(part_name, &it->name))
			break;
	}

	return it;
}

struct pm_partition *partition_set(void)
{
	return partitions;
}

int init_address_df_part(void)
{
	if (!db_url.s || default_partition)
		return 0;

	if (!alloc_default_partition()) {
		LM_ERR("oom\n");
		return -1;
	}

	default_partition->url = db_url;
	default_partition->table = address_table;
	return 0;
}


/*
 * parse a partition parameter of type
 * <part_name>: attr1=val1; attr2=val2
 */
int parse_partition(modparam_t t, void *val)
{
	csv_record *name, *props, *params, *it;
	str rem;
	struct pm_partition *el, *part;

	str in = {(char*)val, strlen((char *)val)};

	if (get_partitions() == NULL) {
		if (alloc_partitions() == NULL)
				goto out_memfault;
		el=get_partitions();
	} else {
		el=pkg_malloc(sizeof(struct pm_partition));
		if (el == NULL)
			goto out_memfault;
		memset(el, 0, sizeof(struct pm_partition));

		for (part=get_partitions(); part->next; part=part->next);
		part->next = el;
	}

	name = __parse_csv_record(&in, 0, ':');
	if (!name)
		goto bad_input;

	el->name = name->s;
	if (str_match(&name->s, &def_part))
		default_partition = el;

	if (!name->next) {
		free_csv_record(name);
		goto empty_part;
	}

	rem.s = name->next->s.s;
	rem.len = in.len - (rem.s - in.s);
	props = __parse_csv_record(&rem, 0, ';');
	if (!props)
		goto bad_input;

	free_csv_record(name);

	for (it = props; it; it = it->next) {
		params = __parse_csv_record(&it->s, 0, '=');
		if (!params)
			goto bad_input;

		if (str_match(&params->s, &part_db_url)) {
			el->url = params->next->s;
		} else if (str_match(&params->s, &part_table_name)) {
			el->table = params->next->s;
		} else if (!ZSTR(params->s)) {
			LM_ERR("invalid token '%.*s' in partition '%.*s'\n",
			       params->s.len, params->s.s, el->name.len, el->name.s);
			goto bad_input;
		}

		free_csv_record(params);
	}

	free_csv_record(props);

empty_part:
	if (!el->url.s) {
		if (db_url.s) {
			init_str(&el->url, db_url.s);
		} else if (db_default_url) {
			init_str(&el->url, db_default_url);
		} else {
			LM_ERR("partition '%.*s' has no 'db_url'\n",
			       el->name.len, el->name.s);
			return -1;
		}
	}

	if (!el->table.s)
		init_str(&el->table, address_table.s);

	return 0;

bad_input:
	LM_ERR("failed to parse partition: '%.*s'\n", in.len, in.s);
	return -1;

out_memfault:
	LM_ERR("no more memory\n");
	return -1;
}


/* part struct API */
void add_part_struct(struct pm_part_struct *part_struct)
{
	struct pm_part_struct *it;

	if (part_structs == NULL) {
		part_structs = part_struct;
	} else {
		for (it=part_structs; it->next; it = it->next);
		it->next = part_struct;
	}
}

void remove_part_struct(struct pm_part_struct *part_struct)
{
	struct pm_part_struct *before, *el;

	if (!part_structs)
		LM_BUG("no part structs; what are you asking for?\n");

	before = el =  part_structs;
	while (el) {
		if (part_struct == el) {
			if (el->next)
				before->next = el->next;
			pkg_free(el);
		}

		if (before != el)
			before = before->next;

		el = el->next;
	}
}

struct pm_part_struct *get_part_structs(void)
{
	return part_structs;
}

struct pm_part_struct *get_part_struct(str *name)
{
	struct pm_part_struct *it;

	for (it=part_structs; it; it = it->next) {
		if (str_strcmp(name, &it->name) == 0)
			return it;
	}

	return NULL;
}
