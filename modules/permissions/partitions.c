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
#include "partitions.h"
#include "../../str.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../db/db.h"

#define ERR 1

str part_db_url = {"db_url", sizeof("db_url") - 1};
str part_table_name = {"table_name", sizeof("table_name") - 1};

/* since default partition will probably be used the most
 * it deserves a pointer for its own*/
struct pm_partition *partitions=NULL, *default_partition=NULL;

struct pm_part_struct *part_structs=NULL;

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
		default_partition->name.s = "default";
		default_partition->name.len = sizeof("default") - 1;

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

/*
 * set default partition url
 */
int set_default_db_url(modparam_t type, void *val)
{
	str db_str;

	db_str.s = (char *)val;
	db_str.len = strlen(db_str.s);

	str_trim_spaces_lr(db_str);

	if (default_partition == NULL)
		if (alloc_default_partition() == NULL)
			goto out_nomem;

	default_partition->url.s = (char *)val;
	init_db_url( default_partition->url, 1 /* can be null */);

	return 0;

out_nomem:
	LM_ERR("no more memory!\n");
	return -1;

}

/*
 * set default partition table
 */
int set_default_table(modparam_t type, void *val)
{
	str db_table;

	db_table.s = (char *)val;
	db_table.len = strlen(db_table.s);

	str_trim_spaces_lr(db_table);

	if (default_partition == NULL)
		if (alloc_default_partition() == NULL)
			goto out_nomem;

	default_partition->table = db_table;

	return 0;

out_nomem:
	LM_ERR("no more memory!\n");
	return -1;

}



/*
 * parse a partition parameter of type
 * <part_name> : attr1=val1; attr2=val2;
 */
int parse_partition(modparam_t t, void *val)
{
	str type, value, token;
	char *tok_end;
	struct pm_partition *el, *it;

	str decl = {(char*)val, strlen((char *)val)};

	if (get_partitions() == NULL) {
		if (alloc_partitions() == NULL)
				goto out_memfault;
		el=get_partitions();
	} else {
		el=pkg_malloc(sizeof(struct pm_partition));
		if (el == NULL)
			goto out_memfault;
		memset(el, 0, sizeof(struct pm_partition));

		for (it=get_partitions(); it->next; it=it->next);
		it->next = el;
	}

	tok_end = q_memchr(decl.s, ':', decl.len);
	if (tok_end == NULL)
		goto out_invdef;

	value.s = decl.s;
	value.len = tok_end - decl.s;

	str_trim_spaces_lr(value);

	el->name = value;

	decl.len = decl.len - (++tok_end - decl.s);
	decl.s = tok_end;

	while (decl.len > 0 && decl.s) {
		tok_end = q_memchr(decl.s, ';', decl.len);
		if (tok_end == NULL)
			break;

		token.s = decl.s;
		token.len = tok_end - token.s;

		tok_end = q_memchr(token.s, '=', token.len);
		if (tok_end == NULL)
			break;

		type.s = token.s;
		type.len = tok_end - type.s;

		value.s = tok_end + 1;
		value.len = (token.s + token.len) - value.s;

		decl.s += token.len + 1;
		decl.len -= (token.len + 1);

		str_trim_spaces_lr(type);
		str_trim_spaces_lr(value);

		if (!str_strcmp( &type, &part_db_url))
			el->url = value;
		 else if (!str_strcmp( &type, &part_table_name))
			el->table = value;
		else
			goto out_invdef;
	}

	if (el->url.s == NULL) {
		LM_ERR("you should define an URL for this partition %.*s\n",
				el->name.len, el->name.s);
		return -1;
	}

	return 0;

out_invdef:
	LM_ERR("invalid partition definition!\n");
	return -ERR;

out_memfault:
	LM_ERR("no more memory\n");
	return -ERR;
}

int check_addr_param1(str *s, struct part_var *pv)
{
	char *end;
	unsigned int gid;
	int ret;
	str spart, sval;

	ret=0;

	spart.s = s->s;

	end = q_memchr(s->s, ':', s->len);

	ret = -1;
	if (end == NULL) {
		ret = str2int(s, &gid);
		pv->u.parsed_part.partition.s = NULL;
		if (0 == ret)
			pv->u.parsed_part.v.ival = gid;
		else {
			pv->u.parsed_part.v.sval.s = s->s;
			pv->u.parsed_part.v.sval.len = s->len;
		}
	} else {
		spart.len = end - spart.s;
		sval.s = end + 1;
		sval.len = (s->s + s->len) - sval.s;

		str_trim_spaces_lr(sval);
		str_trim_spaces_lr(spart);

		pv->u.parsed_part.partition = spart;
		ret = str2int(&sval, &gid);
		if (0 == ret)
			pv->u.parsed_part.v.ival = gid;
		else
			pv->u.parsed_part.v.sval = sval;
	}

	return 0;
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
