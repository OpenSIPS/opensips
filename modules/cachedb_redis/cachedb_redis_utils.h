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

#define ERR_INVALID_REPLY -1
#define ERR_INVALID_SLOT -2
#define ERR_INVALID_PORT -3

#include "cachedb_redis_dbase.h"

int build_cluster_nodes(redis_con *con,char *info,int size);
cluster_node *get_redis_connection(redis_con *con,str *key);
cluster_node *get_redis_connection_by_endpoint(redis_con *con, redis_moved *redis_info);
void destroy_cluster_nodes(redis_con *con);
int parse_moved_reply(redisReply *reply, redis_moved *out);

static inline int match_prefix(const char *buf, size_t len, const char *prefix, size_t prefix_len) {
	size_t i;
	if (len < prefix_len) return 0;
	for (i = 0; i < prefix_len; ++i) {
		if (buf[i] != prefix[i]) return 0;
	}
	return 1;
}

#endif
