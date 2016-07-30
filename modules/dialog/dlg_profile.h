/*
 * Copyright (C) 2009-2014 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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



struct repl_prof_novalue;

enum repl_types {REPL_NONE=0, REPL_CACHEDB=1, REPL_PROTOBIN};
struct dlg_profile_table {
	str name;
	unsigned int has_value;
	enum repl_types repl_type;


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

	/*
	 * information used for profile replication without values
	 */
	struct repl_prof_novalue *repl;

	struct dlg_profile_table *next;
};

struct dialog_list{
	struct dlg_cell *dlg;
	struct dialog_list *next;
};

typedef int (*set_dlg_profile_f)(struct dlg_cell *dlg, str *value,
                        struct dlg_profile_table *profile, char is_replicated);

typedef int (*unset_dlg_profile_f)(struct dlg_cell *dlg, str *value,
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
struct dlg_profile_table *get_dlg_profile(str *name);

void destroy_linkers(struct dlg_profile_link *linker, char is_replicated);

int set_dlg_profile(struct dlg_cell *dlg, str *value,
		struct dlg_profile_table *profile, char is_replicated);

int unset_dlg_profile(struct dlg_cell *dlg, str *value,
		struct dlg_profile_table *profile);

int is_dlg_in_profile(struct dlg_cell *dlg, struct dlg_profile_table *profile,
		str *value);

unsigned int get_profile_size(struct dlg_profile_table *profile, str *value);

struct mi_root * mi_get_profile(struct mi_root *cmd_tree, void *param );

struct mi_root * mi_get_profile_values(struct mi_root *cmd_tree, void *param );

struct mi_root * mi_profile_list(struct mi_root *cmd_tree, void *param );

struct mi_root * mi_list_all_profiles(struct mi_root *cmd_tree, void *param );

struct mi_root * mi_profile_terminate(struct mi_root *cmd_tree, void *param );

void get_value_names(struct dlg_profile_table *profile, struct dlg_profile_value_name *);

/* cachedb interface */
extern str cdb_val_prefix;
extern str cdb_noval_prefix;
extern str cdb_size_prefix;
extern str cdb_url;
extern int profile_timeout;
extern int profile_replicate_cluster;

extern struct dlg_profile_table *profiles;

int init_cachedb();
void destroy_cachedb(int);
int init_cachedb_utils(void);

#endif

