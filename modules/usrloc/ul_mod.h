/*
 * User location module interface
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * ---------
 */

/*! \file
 *  \brief USRLOC - Usrloc module interface
 *  \ingroup usrloc
 */

#ifndef UL_MOD_H
#define UL_MOD_H


#include "../../db/db.h"
#include "../../str.h"
#include "../../cachedb/cachedb.h"

#include "usrloc.h"

extern enum ul_cluster_mode cluster_mode;
extern enum ul_rr_persist rr_persist;
extern enum ul_sql_write_mode sql_wmode;
extern enum ul_pinging_mode pinging_mode;

/* manner in which node data should be restored (or not) following a restart */
typedef enum ul_rr_persist {
	RRP_NONE,
	RRP_LOAD_FROM_SQL,
	RRP_SYNC_FROM_CLUSTER,
} ul_rr_persist_t;
#define bad_rr_persist(rrp) ((rrp) < RRP_NONE || (rrp) > RRP_SYNC_FROM_CLUSTER)

/* if using SQL for restart persistency,
 * should runtime SQL blocking writes be performed eagerly or lazily? */
typedef enum ul_sql_write_mode {
	SQL_NO_WRITE,
	SQL_WRITE_THROUGH,
	SQL_WRITE_BACK,
} ul_sql_write_mode_t;
#define bad_sql_write_mode(wm) ((wm) < SQL_NO_WRITE || (wm) > SQL_WRITE_BACK)

typedef enum ul_pinging_mode {
	PMD_OWNERSHIP,
	PMD_COOPERATION,
} ul_pinging_mode_t;
#define bad_pinging_mode(pm) ((pm) < PMD_OWNERSHIP || (pm) > PMD_COOPERATION)

#define bad_cluster_mode(mode) ((mode) < CM_NONE || (mode) > CM_SQL_ONLY)

/* TODO: rewrite/optimize these 4 checks at mod init */
#define have_sql_con() \
	(cluster_mode == CM_SQL_ONLY || rr_persist == RRP_LOAD_FROM_SQL)

#define have_cdb_con() \
	(cluster_mode == CM_FEDERATION_CACHEDB || \
	 cluster_mode == CM_FULL_SHARING_CACHEDB)

static inline int have_mem_storage(void)
{
	return cluster_mode == CM_NONE ||
	       cluster_mode == CM_FEDERATION_CACHEDB ||
	       cluster_mode == CM_FULL_SHARING;
}

static inline int tags_in_use(void)
{
	return pinging_mode == PMD_OWNERSHIP;
}

#define have_data_replication() \
	(cluster_mode == CM_FEDERATION_CACHEDB || \
	 cluster_mode == CM_FULL_SHARING)

/*
 * Module parameters
 */


#define UL_TABLE_VERSION 1013

#define UL_COLS 19
extern str contactid_col;
extern str user_col;
extern str domain_col;
extern str contact_col;
extern str expires_col;
extern str q_col;
extern str callid_col;
extern str cseq_col;
extern str flags_col;
extern str cflags_col;
extern str user_agent_col;
extern str received_col;
extern str path_col;
extern str sock_col;
extern str methods_col;
extern str kv_store_col;
extern str attr_col;
extern str last_mod_col;
extern str sip_instance_col;

extern str db_url;
extern enum usrloc_modes db_mode;
extern int skip_replicated_db_ops;
extern int use_domain;
extern int desc_time_order;
extern int cseq_delay;
extern int ul_hash_size;
extern int latency_event_min_us_delta;
extern int latency_event_min_us;

extern db_con_t* ul_dbh;   /* Database connection handle */
extern db_func_t ul_dbf;

extern cachedb_funcs cdbf;
extern cachedb_con *cdbc;

extern int matching_mode;

#endif /* UL_MOD_H */
