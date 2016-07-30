/**
 * dispatcher module fixup functions
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * History
 * -------
 *  2014-07-08  initial version (Andrei Datcu)
*/


#ifndef _DS_FIXUPS_H_
#define _DS_FIXUPS_H_


#include "dispatch.h"
#include "../../mod_fix.h"

#define MAX_LIST_TYPE_STR (1<<0)
#define MAX_LIST_TYPE_PV (1<<1)

/* Structure that contains a general description of a partition:
 * either its name through a pv_spec or a pointer to the coresponding
 * ds_partition_t partition
*/
typedef struct
{
	union {
		ds_partition_t *p;
		pv_spec_t *pvs;
	} v;
	enum gparttype_t {GPART_TYPE_POINTER, GPART_TYPE_PVS} type;
} gpartition_t;


typedef struct _int_list_t
{
	union {
		int ival;
		pv_spec_t *pvs;
	} v;
	int type;

	int flags;

	struct _int_list_t *next;
} int_list_t;

/* Structure that describes a general pair of a partition and a set list */
typedef struct
{
	gpartition_t partition;
	int_list_t *sets;
} ds_param_t;

typedef struct max_list_param {
	union {
		int_list_t* list;
		pv_elem_t* elem;
	} lst;
	int type;
} max_list_param_t, *max_list_param_p;

extern int_list_t *ds_probing_list;

int_list_t *set_list_from_pvs(struct sip_msg *msg, pv_spec_t *pvs, int_list_t *end);
void free_int_list(int_list_t *start, int_list_t *end);
int in_int_list(int_list_t *list, int val);

int fixup_get_partition(struct sip_msg *msg, const gpartition_t *gpart,
		ds_partition_t **partition);
int fixup_get_partition_set(struct sip_msg *msg, const ds_param_t *param,
		ds_partition_t **partition, unsigned int *uset);
int fixup_partition_sets(void **param);
int fixup_partition_one_set(void **param);
int fixup_int_list(void **param);

int ds_next_fixup(void **param, int param_no);
int ds_mark_fixup(void **param, int param_no);
int in_list_fixup(void** param, int param_no);
int ds_select_fixup(void** param, int param_no);
int ds_count_fixup(void** param, int param_no);
int fixup_flags(str* param);
int set_list_from_string(str input, int_list_t **result);

#endif
