/*
 * Copyright (C) 2015-2017 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2016-07-xx split from clusterer.h (rvlad-patrascu)
 */

#ifndef CL_NODE_INFO_H
#define CL_NODE_INFO_H

#include "../../db/db.h"
#include "api.h"
#include "clusterer.h"

#define NO_DB_INT_VALS 6
#define NO_DB_STR_VALS 3
#define NO_DB_COLS (NO_DB_INT_VALS + NO_DB_STR_VALS)

#define CLUSTERER_TABLE_VERSION 3
/* also compatible with this version as the current version only removed columns */
#define BACKWARDS_COMPAT_TABLE_VER 2

#define MAX_NO_NODES 64
#define MAX_NO_CLUSTERS 16
#define MAX_MODS_PER_CLUSTER 8

enum db_int_vals_idx {
	INT_VALS_ID_COL,
	INT_VALS_CLUSTER_ID_COL,
	INT_VALS_NODE_ID_COL,
	INT_VALS_STATE_COL,
	INT_VALS_NO_PING_RETRIES_COL,
	INT_VALS_PRIORITY_COL
};

enum db_str_vals_idx {
	STR_VALS_URL_COL,
	STR_VALS_SIP_ADDR_COL,
	STR_VALS_DESCRIPTION_COL
};

struct cluster_mod {
	struct mod_registration *reg;
	struct cluster_mod *next;
};

struct cluster_info;

struct node_info {
	int id;                             /* DB id (PK) */
	int node_id;
	clusterer_link_state link_state;    /* state of the "link" with this node */
	str description;
	str url;
	str sip_addr;
	int priority;                   /* priority to be chosen as next hop for same length paths */
	union sockaddr_union addr;
	struct timeval last_pong;       /* last pong received from this node */
	struct timeval last_ping;       /* last ping sent to this node */
	int no_ping_retries;            /* maximum number of ping retries */
	int curr_no_retries;
	struct cluster_info *cluster;       /* containing cluster */
	struct neighbour *neighbour_list;   /* list of directly reachable neighbours */
	int sp_top_version;                 /* last topology version for which shortest path was computed */
	int ls_seq_no;                      /* sequence number of the last link state update */
	int top_seq_no;                     /* sequence number of the last topology update message */
	int ls_timestamp;
	int top_timestamp;
	struct node_info *next_hop;         /* next hop from the shortest path */
	struct node_search_info *sp_info;   /* shortest path info */
	int flags;
	gen_lock_t *lock;
	struct node_info *next;
};

struct cluster_info {
	int cluster_id;
	struct cluster_mod *modules;    /* modules registered for this cluster */
	struct node_info *node_list;
	int no_nodes;                   /* number of nodes in the cluster */
	struct node_info *current_node; /* current node's info in this cluster */
	clusterer_join_state join_state;
	int top_version;        		/* topology version */
	gen_lock_t *lock;
	struct cluster_info *next;
};

typedef struct node_info node_info_t;
typedef struct cluster_info cluster_info_t;

extern int current_id;
extern rw_lock_t *cl_list_lock;
extern cluster_info_t **cluster_list;

int update_db_state(int state);
int load_db_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table, cluster_info_t **cl_list);
void free_info(cluster_info_t *cl_list);

int add_node_info(node_info_t **new_info, cluster_info_t **cl_list, int *int_vals,
					char **str_vals);

int cl_get_my_id(void);
clusterer_node_t* get_clusterer_nodes(int cluster_id);
void free_clusterer_nodes(clusterer_node_t *nodes);
clusterer_node_t *api_get_next_hop(int cluster_id, int node_id);
void api_free_next_hop(clusterer_node_t *next_hop);

static inline cluster_info_t *get_cluster_by_id(int cluster_id)
{
	cluster_info_t *cl = NULL;

	for (cl = *cluster_list; cl; cl = cl->next)
		if (cl->cluster_id == cluster_id)
			break;

	return cl;
}

static inline node_info_t *get_node_by_id(cluster_info_t *cluster, int node_id)
{
	node_info_t *node = NULL;

	for (node = cluster->node_list; node; node = node->next)
		if (node->node_id == node_id)
			break;

	return node;
}

#endif /* CL_NODE_INFO_H */

