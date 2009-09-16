/*
 * $Id$
 *
 * Copyright (C) 2008 Voice System SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2008-04-20  initial version (bogdan)
 * 2009-09-16  speed optimization (andreidragus)
 *
 */

#include "../../map.h"

#ifndef _DIALOG_DLG_PROFILE_H_
#define _DIALOG_DLG_PROFILE_H_

#include "../../parser/msg_parser.h"
#include "../../locking.h"
#include "../../str.h"



struct lock_set_list
{
	gen_lock_set_t * locks;
	struct lock_set_list * next;
	
};

struct dlg_profile_link {
	str value;
	int hash_idx;
	struct dlg_profile_link  *next;
	struct dlg_profile_table *profile;
};




struct dlg_profile_table {
	str name;
	unsigned int has_value;


	unsigned int size;
	gen_lock_set_t * locks;

	/*
	 * information for profiles with values
	 */
	
	map_t * entries;

	/*
	 * information for profiles without values
	 */

	int * counts;


	struct dlg_profile_table *next;
};

typedef int (*set_dlg_profile_f)(struct sip_msg *msg, str *value,
										struct dlg_profile_table *profile);

typedef unsigned int (*get_profile_size_f)(struct dlg_profile_table *profile,
										str *value);

typedef int (*add_profiles_f)(char* profiles, unsigned int has_value);

typedef struct dlg_profile_table* (*search_dlg_profile_f)(str *name);

struct dlg_profile_value_name {
	int size;
	str **values_string;
	int *values_count;
};


int add_profile_definitions( char* profiles, unsigned int has_value);

void destroy_dlg_profiles();

struct dlg_profile_table* search_dlg_profile(str *name);

void destroy_linkers(struct dlg_profile_link *linker);

int set_dlg_profile(struct sip_msg *msg, str *value,
		struct dlg_profile_table *profile);

int unset_dlg_profile(struct sip_msg *msg, str *value,
		struct dlg_profile_table *profile);

int is_dlg_in_profile(struct sip_msg *msg, struct dlg_profile_table *profile,
		str *value);

unsigned int get_profile_size(struct dlg_profile_table *profile, str *value);

struct mi_root * mi_get_profile(struct mi_root *cmd_tree, void *param );

struct mi_root * mi_get_profile_values(struct mi_root *cmd_tree, void *param );

struct mi_root * mi_profile_list(struct mi_root *cmd_tree, void *param );

void get_value_names(struct dlg_profile_table *profile, struct dlg_profile_value_name *);

#endif

