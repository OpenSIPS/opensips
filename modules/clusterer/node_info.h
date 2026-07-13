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
#include "../../rw_locking.h"
#include "api.h"
#include "clusterer.h"

#define NO_DB_INT_VALS 6
#define NO_DB_STR_VALS 4
#define NO_DB_COLS (NO_DB_INT_VALS + NO_DB_STR_VALS)

#define DEFAULT_NO_PING_RETRIES 3
#define DEFAULT_PRIORITY 50

#define CLUSTERER_TABLE_VERSION 4

#define MAX_NO_NODES 128
#define MAX_NO_CLUSTERS 64

#define SEED_NODE_FLAG_STR "seed"

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
	STR_VALS_FLAGS_COL,
	STR_VALS_DESCRIPTION_COL
};

struct cluster_info;

struct node_info {
	/* read-only fields */
	int id;                         /* DB id (PK) */
	int node_id;
	str description;
	str url;
	union sockaddr_union addr;
	enum sip_protos proto;
	str sip_addr;
	int priority;                   /* priority to be chosen as next hop for same length paths */
	int no_ping_retries;            /* maximum number of ping retries */

	/* fields accessed only by timer */
	int curr_no_retries;

	/* fields protected by cluster lock */
	int sp_top_version;                 /* last topology version for which shortest path was computed */
	struct node_search_info *sp_info;   /* shortest path info */

	gen_lock_t *lock;

	/* fields protected by node lock */
	clusterer_link_state link_state;	/* state of the "link" with this node */
	int last_ping_state;				/* state(success/error) of the last ping sent to this node */
	struct timeval last_ping, last_sent;  /* last ping/packet sent to this node */
	struct timeval last_pong, last_recv;  /* last pong/packet received from this node */
	struct neighbour *neighbour_list;   /* list of directly reachable neighbours */
	int ls_seq_no;                      /* sequence number of the last link state update */
	int top_seq_no;                     /* sequence number of the last topology update message */
	int cap_seq_no;
	int ls_timestamp;
	int top_timestamp;
	int cap_timestamp;
	struct node_info *next_hop;         /* next hop from the shortest path */
	struct remote_cap *capabilities;	/* known capabilities of this node */
	int flags;

	/* list linkers */
	struct cluster_info *cluster;       /* containing cluster */
	struct node_info *next;
};

struct cluster_info {
	int cluster_id;
	int no_nodes;                   /* number of nodes in the cluster */
	struct node_info *node_list;
	struct node_info *current_node; /* current node's info in this cluster */
	struct socket_info *send_sock;

	gen_lock_t *lock;

	int top_version;        		/* topology version */
	struct local_cap *capabilities;	/* capabilities registered for this cluster */

	/* Set by clusterer_controller when manage_shtags=1 for this cluster.
	 * Blocks MI and script-variable shtag activation to prevent conflicts
	 * with controller-managed failover. */
	int shtag_managed;

	/* 1 = this cluster's topology and identity are driven at runtime by
	 * clusterer_controller (registered via the 'cluster_id' modparam); it never
	 * touches the DB and behaves as db_mode=0 regardless of the global db_mode.
	 * 0 = a native cluster defined via DB or static my_node_info/neighbor. */
	int controller_managed;

	struct cluster_info *next;
};

typedef struct node_info node_info_t;
typedef struct cluster_info cluster_info_t;

extern int current_id;
extern int *_current_id_shm;
/* Read current_id from shm if available (cross-process after fork) */
#define GET_CURRENT_ID (_current_id_shm ? *_current_id_shm : current_id)

/* This node's node_id *within a specific cluster*.  With the controller a node
 * can hold a different node_id in each cluster, so the per-cluster identity in
 * shared memory (cl->current_node) is authoritative.  Returns -1 (a node_id
 * that matches nothing) when this cluster's identity is not yet established, so
 * a not-yet-joined cluster can never accidentally match or stamp a real id
 * (in particular it never borrows another cluster's id via the legacy global). */
static inline int cluster_self_id(const struct cluster_info *cl)
{
	return (cl && cl->current_node) ? cl->current_node->node_id : -1;
}
extern int db_mode;
extern int use_controller;
extern rw_lock_t *cl_list_lock;
extern cluster_info_t **cluster_list;

/* Effective db_mode *for one cluster*.  Controller-managed clusters never use
 * the DB (their topology is injected at runtime), so they always behave as
 * db_mode=0 even in a hybrid where native clusters are DB-backed (db_mode!=0). */
static inline int cl_db_mode(const struct cluster_info *cl)
{
	return (cl && cl->controller_managed) ? 0 : db_mode;
}

int update_db_state(int cluster_id, int node_id, int state);
int load_db_info(db_func_t *dr_dbf, db_con_t* db_hdl, str *db_table, cluster_info_t **cl_list);
void free_info(cluster_info_t *cl_list);

int add_node_info(node_info_t **new_info, cluster_info_t **cl_list, int *int_vals,
					str *str_vals, int self_id);
void remove_node_list(cluster_info_t *cl, node_info_t *node);

int provision_neighbor(modparam_t type, void* val);
int provision_current(modparam_t type, void *val);

int cl_get_my_id(void);
int cl_get_my_sip_addr(int cluster_id, str *out_addr);
int cl_get_my_index(int cluster_id, str *capability, int *nr_nodes);
clusterer_node_t* get_clusterer_nodes(int cluster_id);
void free_clusterer_nodes(clusterer_node_t *nodes);
clusterer_node_t *api_get_next_hop(int cluster_id, int node_id);
void api_free_next_hop(clusterer_node_t *next_hop);
int match_node(const node_info_t *a, const node_info_t *b,
               enum cl_node_match_op match_op);

static inline cluster_info_t *get_cluster_by_id(int cluster_id)
{
	cluster_info_t *cl;

	if (!cluster_list || !*cluster_list) return NULL;
	for (cl = *cluster_list; cl; cl = cl->next)
		if (cl->cluster_id == cluster_id)
			return cl;

	return NULL;
}

static inline node_info_t *get_node_by_id(cluster_info_t *cluster, int node_id)
{
	node_info_t *node;

	for (node = cluster->node_list; node; node = node->next)
		if (node->node_id == node_id)
			return node;

	return NULL;
}

static inline int validate_update(int seq_no, int msg_seq_no, int timestamp,
									int msg_timestamp, int val_type, int node_id)
{
	if (msg_seq_no == 0) {
		if (seq_no == 0 && msg_timestamp <= timestamp)
			return -1;
	} else if (msg_seq_no <= seq_no)
		return -1;

	return 0;
}

#endif /* CL_NODE_INFO_H */

