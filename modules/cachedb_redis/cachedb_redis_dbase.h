/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 *  2011-09-xx  created (vlad-paiu)
 */

#ifndef CACHEDBREDIS_DBASE_H
#define CACHEDBREDIS_DBASE_H

#include <hiredis/hiredis.h>
#include "../../cachedb/cachedb.h"
#include "../tls_mgm/api.h"

#ifdef HAVE_REDIS_SSL
#include <hiredis/hiredis_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

typedef struct cluster_nodes {
	char *ip;                       /* ip of this cluster node */
	unsigned short port;            /* port of this cluster node */
	unsigned short start_slot;      /* first slot for this server */
	unsigned short end_slot;        /* last slot for this server */

	redisContext *context;          /* actual connection to this node */
	struct tls_domain *tls_dom;

	struct cluster_nodes *next;
} cluster_node;


#define CACHEDB_REDIS_DEFAULT_TIMEOUT 5000

#define MAP_GET_SCAN_COUNT 1000

#define HASH_FIELD_VAL_NULL  '0'
#define HASH_FIELD_VAL_STR   '1'
#define HASH_FIELD_VAL_INT32 '2'

#define REDIS_ARGV_MAX_LEN 16
#define MAP_SET_MAX_FIELDS 128

extern int redis_query_tout;
extern int redis_connnection_tout;
extern int shutdown_on_error;
extern int use_tls;
extern int fts_max_results;
extern str fts_index_name;
extern str fts_json_prefix;
extern int fts_json_mset_expire;

extern struct tls_mgm_binds tls_api;

enum redis_flag {
	REDIS_SINGLE_INSTANCE  = 1 << 0,
	REDIS_CLUSTER_INSTANCE = 1 << 1,
	REDIS_INIT_NODES       = 1 << 2,
	REDIS_JSON_SUPPORT     = 1 << 3,

	/* failover set (combination of single and/or cluster instances) */
	REDIS_MULTIPLE_HOSTS   = 1 << 4,
};

typedef struct _redis_con {
	/* ------ Fixed conn header -------- */
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;
	/* --------------------------------- */

	char *host;            // Note: the .id may contain multi-hosts, so the
	unsigned short port;   // host/port of this connection are extracted here

	enum redis_flag flags;
	unsigned short slots_assigned; /* total slots for cluster */
	cluster_node *nodes; /* one or more Redis nodes */
	char *json_keyspace; /* currently, only one JSON keyspace per connection */

	/* circular list of Redis instances to be attempted in failover fashion */
	struct _redis_con *next_con;
	/* only populated for 1st item in the list: the "last-known-to-work" con */
	struct _redis_con *current;
} redis_con;

cachedb_con* redis_init(str *url);
void redis_destroy(cachedb_con *con);
int redis_get(cachedb_con *con,str *attr,str *val);
int redis_set(cachedb_con *con,str *attr,str *val,int expires);
int redis_remove(cachedb_con *con,str *attr);
int _redis_remove(cachedb_con *con, str *attr, const str *key);
int redis_add(cachedb_con *con,str *attr,int val,int expires,int *new_val);
int redis_sub(cachedb_con *con,str *attr,int val,int expires,int *new_val);
int redis_query(cachedb_con *con, const cdb_filter_t *filter, cdb_res_t *res);
int redis_update(cachedb_con *con, const cdb_filter_t *row_filter,
                     const cdb_dict_t *pairs);
int redis_get_counter(cachedb_con *connection,str *attr,int *val);
int redis_raw_query(cachedb_con *connection,str *attr,cdb_raw_entry ***reply,int expected_kv_no,int *reply_no);
int redis_map_get(cachedb_con *con, const str *key, cdb_res_t *res);
int redis_map_set(cachedb_con *con, const str *key, const str *subkey,
	const cdb_dict_t *pairs);
int redis_map_remove(cachedb_con *con, const str *key, const str *subkey);

#endif /* CACHEDBREDIS_DBASE_H */

