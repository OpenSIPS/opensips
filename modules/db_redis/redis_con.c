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

#include <string.h>
#include <stdlib.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../db/db.h"
#include "db_redis.h"
#include "redis_con.h"
#include "schema.h"

#define RDB_MAX_REDIRECTS 3

/* CRC16 (CCITT) as used by Redis Cluster for key hash slots,
 * reference implementation from the Redis Cluster specification */
static const uint16_t crc16tab[256] = {
	0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
	0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
	0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
	0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
	0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
	0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
	0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
	0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
	0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
	0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
	0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
	0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
	0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
	0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
	0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
	0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
	0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
	0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
	0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
	0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
	0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
	0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
	0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
	0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
	0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
	0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
	0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
	0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
	0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
	0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
	0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
	0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

static uint16_t rdb_crc16(const char *buf, int len)
{
	int i;
	uint16_t crc = 0;

	for (i = 0; i < len; i++)
		crc = (crc << 8) ^ crc16tab[((crc >> 8) ^ *buf++) & 0x00FF];
	return crc;
}

/* hash slot of a key, honoring {hash tags} as per the cluster spec */
unsigned int rdb_key_slot(const char *key, int len)
{
	int s, e;

	for (s = 0; s < len; s++)
		if (key[s] == '{')
			break;

	if (s < len) {
		for (e = s+1; e < len; e++)
			if (key[e] == '}')
				break;
		if (e < len && e != s+1)
			return rdb_crc16(key+s+1, e-s-1) % RDB_NR_SLOTS;
	}

	return rdb_crc16(key, len) % RDB_NR_SLOTS;
}


static redisContext *rdb_connect_ctx(const char *host, unsigned short port)
{
	struct timeval tv;
	redisContext *ctx;

	tv.tv_sec = rdb_connect_timeout / 1000;
	tv.tv_usec = (rdb_connect_timeout % 1000) * 1000;

	ctx = redisConnectWithTimeout(host, port, tv);
	if (!ctx) {
		LM_ERR("failed to allocate redis context for %s:%u\n", host, port);
		return NULL;
	}
	if (ctx->err) {
		LM_ERR("failed to connect to redis %s:%u (%s)\n",
			host, port, ctx->errstr);
		redisFree(ctx);
		return NULL;
	}

	tv.tv_sec = rdb_query_timeout / 1000;
	tv.tv_usec = (rdb_query_timeout % 1000) * 1000;
	redisSetTimeout(ctx, tv);

	return ctx;
}


/* authenticate + select database on a fresh context, using the db URL id */
static int rdb_setup_ctx(struct redis_con *con, redisContext *ctx)
{
	redisReply *reply;
	int dbno;
	str s;

	if (con->id->password) {
		if (con->id->username && con->id->username[0])
			reply = redisCommand(ctx, "AUTH %s %s",
					con->id->username, con->id->password);
		else
			reply = redisCommand(ctx, "AUTH %s", con->id->password);
		if (!reply || reply->type == REDIS_REPLY_ERROR) {
			LM_ERR("redis AUTH failed (%s)\n",
				reply ? reply->str : ctx->errstr);
			if (reply) freeReplyObject(reply);
			return -1;
		}
		freeReplyObject(reply);
	}

	/* database number only makes sense outside cluster mode */
	if (con->mode != RDB_MODE_CLUSTER &&
	con->id->database && con->id->database[0]) {
		s.s = con->id->database;
		s.len = strlen(s.s);
		if (str2sint(&s, &dbno) == 0 && dbno > 0) {
			reply = redisCommand(ctx, "SELECT %d", dbno);
			if (!reply || reply->type == REDIS_REPLY_ERROR) {
				LM_ERR("redis SELECT %d failed (%s)\n", dbno,
					reply ? reply->str : ctx->errstr);
				if (reply) freeReplyObject(reply);
				return -1;
			}
			freeReplyObject(reply);
		}
	}

	return 0;
}


static redis_node *rdb_find_node(struct redis_con *con,
		const char *host, unsigned short port)
{
	redis_node *n;

	for (n = con->nodes; n; n = n->next)
		if (n->port == port && strcmp(n->host, host) == 0)
			return n;
	return NULL;
}


/* add a node to the pool and (eagerly) connect it */
static redis_node *rdb_add_node(struct redis_con *con,
		const char *host, unsigned short port)
{
	redis_node *n;

	n = pkg_malloc(sizeof *n);
	if (!n) {
		LM_ERR("no more pkg memory for redis node\n");
		return NULL;
	}
	memset(n, 0, sizeof *n);
	strncpy(n->host, host, RDB_HOST_MAX-1);
	n->port = port;

	n->ctx = rdb_connect_ctx(n->host, n->port);
	if (n->ctx && rdb_setup_ctx(con, n->ctx) < 0) {
		redisFree(n->ctx);
		n->ctx = NULL;
	}
	if (!n->ctx)
		LM_WARN("redis node %s:%u added disconnected, "
			"will retry on first use\n", n->host, n->port);

	n->next = con->nodes;
	con->nodes = n;
	return n;
}


static void rdb_disconnect_node(redis_node *n)
{
	if (n->ctx) {
		redisFree(n->ctx);
		n->ctx = NULL;
	}
}


/* (re)establish the TCP connection of a node */
static int rdb_reconnect_node(struct redis_con *con, redis_node *n)
{
	rdb_disconnect_node(n);
	n->ctx = rdb_connect_ctx(n->host, n->port);
	if (!n->ctx)
		return -1;
	if (rdb_setup_ctx(con, n->ctx) < 0) {
		rdb_disconnect_node(n);
		return -1;
	}
	return 0;
}


/* assign [start,end] slot range to a node */
static void rdb_map_slots(struct redis_con *con, redis_node *n,
		int start, int end)
{
	int i;

	if (start < 0 || end >= RDB_NR_SLOTS || start > end)
		return;
	for (i = start; i <= end; i++)
		con->slot_map[i] = n;
}


/* parse one "host port" pair out of a CLUSTER SHARDS node map */
static int rdb_shards_node_endpoint(redisReply *node_map,
		char *host, size_t host_len, unsigned short *port, int *is_master,
		int *is_online)
{
	size_t i;
	redisReply *k, *v;

	host[0] = 0;
	*port = 0;
	*is_master = 0;
	*is_online = 1;

	if (node_map->type != REDIS_REPLY_ARRAY &&
	    node_map->type != REDIS_REPLY_MAP)
		return -1;

	for (i = 0; i+1 < node_map->elements; i += 2) {
		k = node_map->element[i];
		v = node_map->element[i+1];
		if (k->type != REDIS_REPLY_STRING)
			continue;
		if (strcmp(k->str, "ip") == 0 || strcmp(k->str, "endpoint") == 0) {
			if (v->type == REDIS_REPLY_STRING && v->str[0] && !host[0]) {
				strncpy(host, v->str, host_len-1);
				host[host_len-1] = 0;
			}
		} else if (strcmp(k->str, "port") == 0) {
			if (v->type == REDIS_REPLY_INTEGER)
				*port = (unsigned short)v->integer;
		} else if (strcmp(k->str, "role") == 0) {
			if (v->type == REDIS_REPLY_STRING &&
			    strcmp(v->str, "master") == 0)
				*is_master = 1;
		} else if (strcmp(k->str, "health") == 0) {
			if (v->type == REDIS_REPLY_STRING &&
			    strcmp(v->str, "online") != 0)
				*is_online = 0;
		}
	}

	return (host[0] && *port) ? 0 : -1;
}


/* build topology from a CLUSTER SHARDS reply (Redis 7.0+) */
static int rdb_parse_shards(struct redis_con *con, redisReply *reply)
{
	size_t i, j, r;
	redisReply *shard, *k, *v, *slots = NULL, *rnodes = NULL;
	redis_node *n;
	char host[RDB_HOST_MAX];
	unsigned short port;
	int is_master, is_online, mapped = 0;

	if (reply->type != REDIS_REPLY_ARRAY || reply->elements == 0)
		return -1;

	for (i = 0; i < reply->elements; i++) {
		shard = reply->element[i];
		if (shard->type != REDIS_REPLY_ARRAY &&
		    shard->type != REDIS_REPLY_MAP)
			continue;

		slots = NULL;
		rnodes = NULL;
		for (j = 0; j+1 < shard->elements; j += 2) {
			k = shard->element[j];
			v = shard->element[j+1];
			if (k->type != REDIS_REPLY_STRING)
				continue;
			if (strcmp(k->str, "slots") == 0)
				slots = v;
			else if (strcmp(k->str, "nodes") == 0)
				rnodes = v;
		}
		if (!slots || !rnodes || rnodes->type != REDIS_REPLY_ARRAY)
			continue;

		/* find the online master of this shard */
		n = NULL;
		for (r = 0; r < rnodes->elements; r++) {
			if (rdb_shards_node_endpoint(rnodes->element[r], host,
			sizeof host, &port, &is_master, &is_online) < 0)
				continue;
			if (!is_master || !is_online)
				continue;
			n = rdb_find_node(con, host, port);
			if (!n)
				n = rdb_add_node(con, host, port);
			break;
		}
		if (!n)
			continue;

		/* slots is a flat array of start,end pairs */
		if (slots->type == REDIS_REPLY_ARRAY) {
			for (r = 0; r+1 < slots->elements; r += 2) {
				if (slots->element[r]->type != REDIS_REPLY_INTEGER ||
				    slots->element[r+1]->type != REDIS_REPLY_INTEGER)
					continue;
				rdb_map_slots(con, n,
					(int)slots->element[r]->integer,
					(int)slots->element[r+1]->integer);
				mapped = 1;
			}
		}
	}

	return mapped ? 0 : -1;
}


/* build topology from a CLUSTER SLOTS reply (Redis 3.0+) */
static int rdb_parse_slots(struct redis_con *con, redisReply *reply)
{
	size_t i;
	redisReply *range, *master;
	redis_node *n;
	int start, end, mapped = 0;

	if (reply->type != REDIS_REPLY_ARRAY || reply->elements == 0)
		return -1;

	for (i = 0; i < reply->elements; i++) {
		range = reply->element[i];
		if (range->type != REDIS_REPLY_ARRAY || range->elements < 3)
			continue;
		if (range->element[0]->type != REDIS_REPLY_INTEGER ||
		    range->element[1]->type != REDIS_REPLY_INTEGER)
			continue;
		start = (int)range->element[0]->integer;
		end = (int)range->element[1]->integer;

		/* element[2] is the master: [host, port, id...] */
		master = range->element[2];
		if (master->type != REDIS_REPLY_ARRAY || master->elements < 2 ||
		    master->element[0]->type != REDIS_REPLY_STRING ||
		    master->element[1]->type != REDIS_REPLY_INTEGER)
			continue;

		n = rdb_find_node(con, master->element[0]->str,
				(unsigned short)master->element[1]->integer);
		if (!n)
			n = rdb_add_node(con, master->element[0]->str,
					(unsigned short)master->element[1]->integer);
		if (!n)
			continue;

		rdb_map_slots(con, n, start, end);
		mapped = 1;
	}

	return mapped ? 0 : -1;
}


/* fetch and apply the full cluster topology using any usable node;
 * newly discovered masters are eagerly connected */
static int rdb_load_topology(struct redis_con *con, redisContext *seed_ctx)
{
	redisReply *reply;
	int rc = -1;

	/* CLUSTER SHARDS first (7.0+), CLUSTER SLOTS as fallback */
	reply = redisCommand(seed_ctx, "CLUSTER SHARDS");
	if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements) {
		rc = rdb_parse_shards(con, reply);
		freeReplyObject(reply);
		if (rc == 0) {
			LM_DBG("cluster topology loaded via CLUSTER SHARDS\n");
			return 0;
		}
	} else if (reply) {
		freeReplyObject(reply);
	}

	reply = redisCommand(seed_ctx, "CLUSTER SLOTS");
	if (reply && reply->type == REDIS_REPLY_ARRAY && reply->elements) {
		rc = rdb_parse_slots(con, reply);
		freeReplyObject(reply);
		if (rc == 0) {
			LM_DBG("cluster topology loaded via CLUSTER SLOTS\n");
			return 0;
		}
		return -1;
	}
	if (reply)
		freeReplyObject(reply);

	return -1;
}


/* refresh the slot map from any connected master; prune masters that
 * no longer own slots */
static int rdb_refresh_topology(struct redis_con *con)
{
	redis_node *n, **prev;
	int i, rc = -1;

	memset(con->slot_map, 0, sizeof con->slot_map);

	for (n = con->nodes; n; n = n->next) {
		if (!n->ctx && rdb_reconnect_node(con, n) < 0)
			continue;
		rc = rdb_load_topology(con, n->ctx);
		if (rc == 0)
			break;
	}
	if (rc < 0) {
		LM_ERR("failed to refresh cluster topology from any known node\n");
		return -1;
	}

	/* drop nodes that own no slots anymore (demoted/removed) */
	prev = &con->nodes;
	while ((n = *prev) != NULL) {
		for (i = 0; i < RDB_NR_SLOTS; i++)
			if (con->slot_map[i] == n)
				break;
		if (i == RDB_NR_SLOTS) {
			LM_INFO("dropping redis node %s:%u (owns no slots)\n",
				n->host, n->port);
			*prev = n->next;
			rdb_disconnect_node(n);
			pkg_free(n);
		} else {
			prev = &n->next;
		}
	}

	con->need_refresh = 0;
	return 0;
}


void rdb_maybe_refresh(struct redis_con *con)
{
	if (con->mode == RDB_MODE_CLUSTER && con->need_refresh)
		rdb_refresh_topology(con);
}


/* determine whether the endpoint is a cluster ("cluster_enabled:1"
 * in CLUSTER INFO); on any error assume non-cluster */
static int rdb_probe_cluster(redisContext *ctx)
{
	redisReply *reply;
	int enabled = 0;

	reply = redisCommand(ctx, "CLUSTER INFO");
	if (!reply)
		return 0;
	if (reply->type == REDIS_REPLY_STRING || reply->type == REDIS_REPLY_STATUS) {
		if (reply->str && strstr(reply->str, "cluster_enabled:1"))
			enabled = 1;
	}
	freeReplyObject(reply);
	return enabled;
}


struct redis_con* db_redis_new_connection(const struct db_id* id)
{
	struct redis_con *con;
	redisContext *seed;
	unsigned short port;
	int is_cluster;

	if (!id || !id->host) {
		LM_ERR("invalid db URL for redis connection\n");
		return NULL;
	}

	con = pkg_malloc(sizeof *con);
	if (!con) {
		LM_ERR("no more pkg memory for redis connection\n");
		return NULL;
	}
	memset(con, 0, sizeof *con);
	con->id = (struct db_id *)id;
	con->ref = 1;
	con->mode = RDB_MODE_SINGLE; /* until probed otherwise */

	port = id->port ? id->port : 6379;

	seed = rdb_connect_ctx(id->host, port);
	if (!seed)
		goto error;
	if (rdb_setup_ctx(con, seed) < 0) {
		redisFree(seed);
		goto error;
	}

	is_cluster = rdb_probe_cluster(seed);

	if (rdb_mode == RDB_MODE_SINGLE && is_cluster) {
		LM_ERR("mode pinned to single but %s:%u is a redis cluster node\n",
			id->host, port);
		redisFree(seed);
		goto error;
	}
	if (rdb_mode == RDB_MODE_CLUSTER && !is_cluster) {
		LM_ERR("mode pinned to cluster but %s:%u has cluster "
			"support disabled\n", id->host, port);
		redisFree(seed);
		goto error;
	}

	if (is_cluster) {
		con->mode = RDB_MODE_CLUSTER;
		/* discover all masters and connect them eagerly, so MOVED
		 * redirects can be served over already-open connections */
		if (rdb_load_topology(con, seed) < 0) {
			LM_ERR("failed to load cluster topology from %s:%u\n",
				id->host, port);
			redisFree(seed);
			goto error;
		}
		/* the seed served its purpose; the pool holds the masters
		 * (the seed itself is in the pool if it is a master) */
		redisFree(seed);
		LM_INFO("connected to redis cluster via %s:%u\n", id->host, port);
	} else {
		con->mode = RDB_MODE_SINGLE;
		/* the seed becomes the single pooled node */
		if (!rdb_add_node(con, id->host, port)) {
			redisFree(seed);
			goto error;
		}
		/* rdb_add_node opened its own ctx; keep that one, drop seed */
		redisFree(seed);
		if (!con->nodes->ctx) {
			LM_ERR("failed to connect single redis node %s:%u\n",
				id->host, port);
			goto error;
		}
		LM_INFO("connected to redis server %s:%u\n", id->host, port);
	}

	return con;

error:
	db_redis_free_connection((struct pool_con *)con);
	return NULL;
}


void db_redis_free_connection(struct pool_con* pcon)
{
	struct redis_con *con = (struct redis_con *)pcon;
	redis_node *n, *next;

	if (!con)
		return;

	for (n = con->nodes; n; n = next) {
		next = n->next;
		rdb_disconnect_node(n);
		pkg_free(n);
	}
	rdb_free_schemas(con);
	pkg_free(con);
}


/* pick the node a key routes to */
static redis_node *rdb_route(struct redis_con *con, const str *key)
{
	redis_node *n;

	if (con->mode != RDB_MODE_CLUSTER)
		return con->nodes;

	n = con->slot_map[rdb_key_slot(key->s, key->len)];
	if (!n) {
		/* unknown slot owner - any node will answer or redirect us */
		con->need_refresh = 1;
		n = con->nodes;
	}
	return n;
}


/* parse "MOVED <slot> <host>:<port>" / "ASK <slot> <host>:<port>" */
static int rdb_parse_redirect(const char *err, int *slot,
		char *host, size_t host_len, unsigned short *port)
{
	const char *p, *colon;
	size_t hlen;

	p = strchr(err, ' ');
	if (!p)
		return -1;
	*slot = atoi(p+1);
	p = strchr(p+1, ' ');
	if (!p)
		return -1;
	p++;
	colon = strrchr(p, ':');
	if (!colon || colon == p)
		return -1;
	hlen = colon - p;
	if (hlen >= host_len)
		return -1;
	memcpy(host, p, hlen);
	host[hlen] = 0;
	*port = (unsigned short)atoi(colon+1);
	return (*port != 0) ? 0 : -1;
}


redisReply *rdb_cmd_node(struct redis_con *con, redis_node *node,
		int argc, const char **argv, const size_t *argvlen)
{
	redisReply *reply;
	int retried = 0;

again:
	if (!node->ctx && rdb_reconnect_node(con, node) < 0)
		return NULL;

	reply = redisCommandArgv(node->ctx, argc, argv, argvlen);
	if (!reply) {
		/* I/O error - reconnect once (covers LB-reaped idle
		 * connections and failed-over endpoints) */
		LM_DBG("redis I/O error on %s:%u (%s), reconnecting\n",
			node->host, node->port,
			node->ctx ? node->ctx->errstr : "no ctx");
		rdb_disconnect_node(node);
		if (!retried) {
			retried = 1;
			goto again;
		}
		LM_ERR("redis command failed on %s:%u after reconnect\n",
			node->host, node->port);
		return NULL;
	}

	/* -READONLY: we are talking to a demoted master (e.g. the LB has
	 * not yet cut over) - reconnect through the same endpoint once */
	if (reply->type == REDIS_REPLY_ERROR && reply->str &&
	strncmp(reply->str, "READONLY", 8) == 0 && !retried) {
		LM_INFO("redis node %s:%u went read-only, reconnecting\n",
			node->host, node->port);
		freeReplyObject(reply);
		rdb_disconnect_node(node);
		if (con->mode == RDB_MODE_CLUSTER)
			con->need_refresh = 1;
		retried = 1;
		goto again;
	}

	return reply;
}


redisReply *rdb_cmd_key(struct redis_con *con, const str *key,
		int argc, const char **argv, const size_t *argvlen)
{
	redisReply *reply;
	redis_node *node, *target;
	char host[RDB_HOST_MAX];
	unsigned short port;
	int slot, redirects;
	const char *asking = "ASKING";
	size_t asking_len = 6;
	redisReply *ask_reply;

	node = rdb_route(con, key);
	if (!node) {
		LM_ERR("no redis node available\n");
		return NULL;
	}

	for (redirects = 0; redirects <= RDB_MAX_REDIRECTS; redirects++) {

		reply = rdb_cmd_node(con, node, argc, argv, argvlen);
		if (!reply)
			return NULL;

		if (reply->type != REDIS_REPLY_ERROR || !reply->str)
			return reply;

		if (strncmp(reply->str, "MOVED ", 6) == 0 &&
		con->mode == RDB_MODE_CLUSTER) {
			if (rdb_parse_redirect(reply->str, &slot, host,
			sizeof host, &port) < 0) {
				LM_ERR("unparsable MOVED reply <%s>\n", reply->str);
				return reply;
			}
			freeReplyObject(reply);

			/* serve the redirect from the warm pool when possible */
			target = rdb_find_node(con, host, port);
			if (!target)
				target = rdb_add_node(con, host, port);
			if (!target)
				return NULL;
			if (slot >= 0 && slot < RDB_NR_SLOTS)
				con->slot_map[slot] = target;
			/* the map is stale beyond this slot - refresh before
			 * the next operation, not in the hot path */
			con->need_refresh = 1;
			node = target;
			continue;
		}

		if (strncmp(reply->str, "ASK ", 4) == 0 &&
		con->mode == RDB_MODE_CLUSTER) {
			if (rdb_parse_redirect(reply->str, &slot, host,
			sizeof host, &port) < 0) {
				LM_ERR("unparsable ASK reply <%s>\n", reply->str);
				return reply;
			}
			freeReplyObject(reply);

			/* one-shot redirect: ASKING + command, no map change */
			target = rdb_find_node(con, host, port);
			if (!target)
				target = rdb_add_node(con, host, port);
			if (!target)
				return NULL;
			ask_reply = rdb_cmd_node(con, target, 1, &asking, &asking_len);
			if (ask_reply)
				freeReplyObject(ask_reply);
			node = target;
			continue;
		}

		if (strncmp(reply->str, "TRYAGAIN", 8) == 0 &&
		con->mode == RDB_MODE_CLUSTER) {
			/* slot migration in progress; brief backoff and retry */
			freeReplyObject(reply);
			usleep(20000);
			continue;
		}

		/* genuine command error - hand it to the caller */
		return reply;
	}

	LM_ERR("redis redirect limit exceeded for key <%.*s>\n",
		key->len, key->s);
	return NULL;
}
