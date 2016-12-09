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

#ifndef API_H
#define	API_H

#include "../../str.h"

#define STATUS_PERMANENT_DOWN 0
#define STATUS_UP 1
#define STATUS_TEMPORARY_DOWN 2
#define SERVER_TEMP_DISABLED -1
#define SERVER_TIMEOUT -2

enum cl_machine_state {
	CLUSTERER_STATE_ON =		0,
	CLUSTERER_STATE_PROBE =		1,
	CLUSTERER_STATE_OFF =		2
};


typedef struct clusterer_node_ clusterer_node_t;

struct clusterer_node_ {
    /* machine_id */
    int machine_id;
    /* machine state */
    int state;
    /* description */
    str description;
    /* protocol */
    int proto;
    /* sock address */
    union sockaddr_union addr;
    /* linker in list */
    clusterer_node_t *next;
};

typedef clusterer_node_t * (*get_nodes_f) (int, int);
typedef int (*set_state_f) (int, int, enum cl_machine_state, int);
typedef void (*free_nodes_f) (clusterer_node_t *);
typedef int (*check_connection_f) (int, union sockaddr_union*, int, int);
typedef int (*get_my_id_f) (void);
typedef int (*send_to_f) (int, int);
typedef int (*register_module_f) (char *, int,  void (*cb)(int, struct receive_info *, int), 
                                    int, int, int);


struct clusterer_binds {
    get_nodes_f get_nodes;
    free_nodes_f free_nodes;
    set_state_f set_state;
    check_connection_f check;
    get_my_id_f get_my_id;
    send_to_f send_to;
    register_module_f register_module;
};




typedef int(*load_clusterer_f)(struct clusterer_binds *binds);

int load_clusterer(struct clusterer_binds *binds);

static inline int load_clusterer_api(struct clusterer_binds *binds) {
    load_clusterer_f load_clusterer;

    /* import the DLG auto-loading function */
    if (!(load_clusterer = (load_clusterer_f) find_export("load_clusterer", 0, 0)))
        return -1;

    /* let the auto-loading function load all DLG stuff */
    if (load_clusterer(binds) == -1)
        return -1;

    return 0;
}

#endif	/* API_H */
