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

#ifndef CACHEDB_REDIS_UTILSH
#define CACHEDB_REDIS_UTILSH

#define REDIS_DF_PORT  6379

#define MOVED_PREFIX "MOVED "
#define MOVED_PREFIX_LEN (sizeof(MOVED_PREFIX) - 1)

#define ASK_PREFIX "ASK "
#define ASK_PREFIX_LEN (sizeof(ASK_PREFIX) - 1)

#define ERR_INVALID_REPLY -1
#define ERR_INVALID_SLOT -2
#define ERR_INVALID_PORT -3

#include "cachedb_redis_dbase.h"

cluster_node *get_redis_connection(redis_con *con,str *key);
cluster_node *get_redis_connection_by_endpoint(redis_con *con, redis_moved *redis_info);
void destroy_cluster_nodes(redis_con *con);
int parse_redirect_reply(redisReply *reply, redis_moved *out,
		const char *prefix, size_t prefix_len);

static inline int parse_moved_reply(redisReply *reply, redis_moved *out) {
	return parse_redirect_reply(reply, out, MOVED_PREFIX, MOVED_PREFIX_LEN);
}

static inline int parse_ask_reply(redisReply *reply, redis_moved *out) {
	return parse_redirect_reply(reply, out, ASK_PREFIX, ASK_PREFIX_LEN);
}

int probe_cluster_command(redis_con *con, redisContext *ctx);
int parse_cluster_shards(redis_con *con, redisReply *reply);
int parse_cluster_slots(redis_con *con, redisReply *reply);
cluster_node *find_or_create_node(redis_con *con, const char *ip,
    int ip_len, unsigned short port);
int refresh_cluster_topology(redis_con *con);

static inline int match_prefix(const char *buf, size_t len, const char *prefix, size_t prefix_len) {
	size_t i;
	if (len < prefix_len) return 0;
	for (i = 0; i < prefix_len; ++i) {
		if (buf[i] != prefix[i]) return 0;
	}
	return 1;
}

#endif
