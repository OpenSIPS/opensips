/*
 * Copyright (C) 2009-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
	int it_marker;
	struct dlg_profile_link  *next;
	struct dlg_profile_table *profile;
};

struct prof_rcv_count;

struct prof_local_count {
	int n;
	str shtag;
	struct prof_local_count *next;
};

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
	struct prof_local_count **noval_local_counters;
	struct prof_rcv_count *noval_rcv_counters;

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

void destroy_linkers(struct dlg_cell *dlg);
void destroy_linkers_unsafe(struct dlg_cell *dlg);
void remove_dlg_prof_table(struct dlg_cell *dlg, char cachedb_dec);

int set_dlg_profile(struct dlg_cell *dlg, str *value,
		struct dlg_profile_table *profile, char is_replicated);

int unset_dlg_profile(struct dlg_cell *dlg, str *value,
		struct dlg_profile_table *profile);

int is_dlg_in_profile(struct dlg_cell *dlg, struct dlg_profile_table *profile,
		str *value);

int noval_get_local_count(struct dlg_profile_table *profile);

unsigned int get_profile_size(struct dlg_profile_table *profile, str *value);

mi_response_t *mi_get_profile_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_get_profile_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_get_profile_values(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_profile_list_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_profile_list_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_list_all_profiles(const mi_params_t *params,
								struct mi_handler *async_hdl);

mi_response_t *mi_profile_terminate_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_profile_terminate_2(const mi_params_t *params,
								struct mi_handler *async_hdl);

void get_value_names(struct dlg_profile_table *profile, struct dlg_profile_value_name *);

/* cachedb interface */
extern str cdb_val_prefix;
extern str cdb_noval_prefix;
extern str cdb_size_prefix;
extern str cdb_url;
extern int profile_timeout;

extern struct dlg_profile_table *profiles;

int init_cachedb();
void destroy_cachedb(int);
int init_cachedb_utils(void);

#endif

