/*
 * Copyright (C) 2015 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * history:
 * ---------
 *  2015-07-07  created  by Marius Cristian Eseanu
 */

#ifndef CLUSTERER_H
#define	CLUSTERER_H

#include "../../str.h"
#include "api.h"

#define INT_VALS_CLUSTER_ID_COL     0
#define INT_VALS_MACHINE_ID_COL     1
#define INT_VALS_STATE_COL          2
#define STR_VALS_DESCRIPTION_COL    0
#define STR_VALS_URL_COL            1
#define INT_VALS_CLUSTERER_ID_COL   3
#define INT_VALS_FAILED_ATTEMPTS_COL    4
#define INT_VALS_NO_TRIES_COL           5
#define INT_VALS_DURATION_COL           6

extern str clusterer_db_url;
extern str db_table;
extern str cluster_id_col;
extern str machine_id_col;
extern int server_id;
extern int persistent_state;
extern str id_col;
extern str last_attempt_col;
extern str duration_col;
extern str failed_attempts_col;
extern str no_tries_col;

/* define proper state for the machine */

typedef struct table_entry_ table_entry_t;
typedef struct table_entry_info_ table_entry_info_t;
typedef struct table_entry_value_ table_entry_value_t;

struct module_list{
   str mod_name;
   int proto;
   void (*cb)(int, struct receive_info *, int);
   int timeout;
   int duration;
   int auth_check;
   int accept_cluster_id;
   table_entry_value_t *values;
   struct module_list *next;
};

struct module_timestamp{
    enum cl_machine_state state;
    uint64_t timestamp;
    struct module_list *up;
    struct module_timestamp *next;
};

struct table_entry_value_{
    /* machine id */
    int machine_id;
    /* cluster id */
    int id;
    /* state */
    int state;
    /* dirty bit */
    int dirty_bit;
    /* description string */
    str description;
    /* path */
    str path;
    /* timestamp */
    uint64_t last_attempt;
    /* duration */
    int duration;
    /* previous number of tries */
    int prev_no_tries;
    /* no of tries */
    int no_tries;
    /* failed attempts */
    int failed_attempts;
    /* sock address */   
    union sockaddr_union addr;
    /* module list */
    struct module_timestamp *in_timestamps;
    /* linker in list */
    table_entry_value_t *next;
};

struct table_entry_info_{
    /* protocol */
    int proto;
    /* data */
    table_entry_value_t *value;
    /* linker in the list */
    table_entry_info_t *next;
};


/* data list */
struct table_entry_ {
    /* clusterer_id */
    int cluster_id;
    /* entry info */
    table_entry_info_t *info;
    /* linker in list */
    table_entry_t *next;
};

#endif	/* CLUSTERER_H */

