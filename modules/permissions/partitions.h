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

#ifndef PM_PARTITIONS_H
#define PM_PARTITIONS_H 1
#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../db/db.h"

#define TYPE_PV 0
#define TYPE_PARSED 1

struct pm_partition {
	str name;
	str url;
	str table;
	struct pm_partition *next;
};

struct pm_part_struct {
	str url;
	str name;
	str table;

	struct address_list ***hash_table;     /* Pointer to current hash table pointer */
	struct address_list **hash_table_1;   /* Pointer to hash table 1 */
	struct address_list **hash_table_2;   /* Pointer to hash table 2 */

	struct subnet **subnet_table;        /* Ptr to current subnet table */
	struct subnet *subnet_table_1;       /* Ptr to subnet table 1 */
	struct subnet *subnet_table_2;       /* Ptr to subnet table 2 */

	db_con_t* db_handle;
	db_func_t perm_dbf;

	struct pm_part_struct *next;
};


int init_address_df_part(void);
int parse_partition(modparam_t, void*);
struct pm_partition *partition_set(void);
struct pm_part_struct *get_part_structs(void);
struct pm_part_struct *get_part_struct(str *name);
struct pm_partition *get_partitions(void);
void add_part_struct(struct pm_part_struct *part_struct);

#endif
