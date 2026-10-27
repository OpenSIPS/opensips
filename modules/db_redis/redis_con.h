/*
 * Copyright (C) 2026 OpenSIPS Solutions
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

#ifndef REDIS_CON_H
#define REDIS_CON_H

#include <hiredis/hiredis.h>

/* RESP3 map replies only exist in hiredis >= 1.0; with the default RESP2
 * protocol these arrive as flat arrays, so on older hiredis the constant
 * just needs to exist for the (never-matching) comparisons */
#ifndef REDIS_REPLY_MAP
#define REDIS_REPLY_MAP 9
#endif

#include "../../db/db_pool.h"
#include "../../db/db_id.h"
#include "../../str.h"

#define RDB_NR_SLOTS 16384

#define RDB_HOST_MAX 128

/* one TCP connection to one Redis server (a cluster master, or the
 * single endpoint in non-cluster mode) */
typedef struct redis_node {
	char host[RDB_HOST_MAX];
	unsigned short port;
	redisContext *ctx;               /* NULL when disconnected */
	struct redis_node *next;
} redis_node;

struct rdb_schema;

struct redis_con {
	struct db_id* id;            /**< Connection identifier */
	unsigned int ref;            /**< Reference count */
	struct pool_con *async_pool; /**< Subpool of identical database handles */
	int no_transfers;            /**< Number of async queries to this backend */
	struct db_transfer *transfers; /**< Array of ongoing async operations */
	struct pool_con *next;       /**< Next element in the pool (different id) */

	int mode;                    /* RDB_MODE_SINGLE or RDB_MODE_CLUSTER */
	redis_node *nodes;           /* master pool (single mode: one node) */
	redis_node *slot_map[RDB_NR_SLOTS]; /* cluster: slot owner (NULL=unknown) */
	int need_refresh;            /* topology refresh requested (cluster) */

	struct rdb_schema *schemas;  /* cached table schemas */
	long long last_insert_id;    /* per-connection last auto-generated id */
};

#define CON_REDIS(db_con) ((struct redis_con *)((db_con)->tail))

struct redis_con* db_redis_new_connection(const struct db_id* id);
void db_redis_free_connection(struct pool_con* con);

/* run a command routed by 'key' (row key), redirect- and reconnect-aware;
 * returns a reply that the caller must freeReplyObject(), or NULL */
redisReply *rdb_cmd_key(struct redis_con *con, const str *key,
		int argc, const char **argv, const size_t *argvlen);

/* run a command on an explicit node, with one reconnect attempt */
redisReply *rdb_cmd_node(struct redis_con *con, redis_node *node,
		int argc, const char **argv, const size_t *argvlen);

/* attempt a topology refresh if one was requested (cluster mode) */
void rdb_maybe_refresh(struct redis_con *con);

unsigned int rdb_key_slot(const char *key, int len);

#endif /* REDIS_CON_H */
