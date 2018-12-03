/*
 * Header file for hash table functions
 *
 * Copyright (C) 2002-2003 Juha Heinanen
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


#ifndef _DOM_HASH_H_
#define _DOM_HASH_H_

#include <stdio.h>
#include "domain_mod.h"
#include "../../mi/mi.h"

int hash_table_install (struct domain_list **hash_table, str *d, str *a);
int hash_table_lookup (struct sip_msg *msg, str *domain, pv_spec_t *pv);
int hash_table_mi_print(struct domain_list **hash_table, mi_item_t *domains_arr);
void hash_table_free (struct domain_list **hash_table);

#endif
