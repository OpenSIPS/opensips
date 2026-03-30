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

#include "../../dprint.h"
#include "cachedb_redis_dbase.h"
#include "cachedb_redis_utils.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../cachedb/cachedb.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>
#define is_valid(p,end) ((p) && (p)<(end))

static const uint16_t crc16tab[256]= {
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

uint16_t crc16(const char *buf, int len)
{
    int counter;
    uint16_t crc = 0;
    for (counter = 0; counter < len; counter++)
            crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *buf++)&0x00FF];
    return crc;
}

#define REDIS_CLUSTER_HASH_SLOTS 16384

/*
 * Extract the hash tag from a key per the Redis Cluster specification:
 *   - Find the first '{'. If found, find the first '}' after it.
 *   - If the substring between them is non-empty, hash only that substring.
 *   - Otherwise, hash the entire key.
 */
static void extract_hash_tag(const char *key, int key_len,
                             const char **tag, int *tag_len)
{
	int i, open = -1;

	if (!key || key_len <= 0) {
		*tag = key;
		*tag_len = key_len > 0 ? key_len : 0;
		return;
	}

	for (i = 0; i < key_len; i++) {
		if (key[i] == '{') {
			open = i;
			break;
		}
	}

	if (open >= 0) {
		for (i = open + 1; i < key_len; i++) {
			if (key[i] == '}') {
				if (i - open - 1 > 0) {
					*tag = key + open + 1;
					*tag_len = i - open - 1;
					return;
				}
				break;
			}
		}
	}

	*tag = key;
	*tag_len = key_len;
}

unsigned int redisHash(str *key)
{
	const char *tag;
	int tag_len;

	extract_hash_tag(key->s, key->len, &tag, &tag_len);
	return crc16(tag, tag_len) % REDIS_CLUSTER_HASH_SLOTS;
}

cluster_node *get_redis_connection(redis_con *con,str *key)
{
	unsigned short hash_slot;

	if (con->flags & REDIS_SINGLE_INSTANCE) {
		LM_DBG("Single redis connection, returning %p\n",con->nodes);
		return con->nodes;
	}

	hash_slot = redisHash(key);
	LM_DBG("Redis cluster connection, slot %u -> %p\n",
		hash_slot, con->slot_table[hash_slot]);
	return con->slot_table[hash_slot];
}

cluster_node *get_redis_connection_by_endpoint(redis_con *con, redis_moved *redis_info)
{
	cluster_node *it;

	if (con->flags & REDIS_SINGLE_INSTANCE) {
		LM_DBG("Single redis connection, returning %p\n",con->nodes);
		return con->nodes;
	}

	for (it=con->nodes;it;it=it->next) {
		str host_str = {it->ip, strlen(it->ip)};
		str ep_str = {(char *)redis_info->endpoint.s, redis_info->endpoint.len};
		if (str_match(&host_str, &ep_str) && it->port == redis_info->port) {
			LM_DBG("Redis cluster connection, matched con %p for "
				"endpoint: %.*s:%d\n", it,
				redis_info->endpoint.len, redis_info->endpoint.s,
				redis_info->port);
			return it;
		}
	}

	LM_ERR("Redis cluster connection, No match found for endpoint: "
		"%.*s:%d slot %u\n", redis_info->endpoint.len,
		redis_info->endpoint.s, redis_info->port, redis_info->slot);
	return NULL;
}

void destroy_cluster_nodes(redis_con *con)
{
	cluster_node *node, *next;

	LM_DBG("destroying cluster %p\n",con);

	node = con->nodes;
	while (node) {
		next = node->next;
		redisFree(node->context);
		node->context = NULL;
		if (use_tls && node->tls_dom)
			tls_api.release_domain(node->tls_dom);
		pkg_free(node->ip);
		if (node->unix_socket_path)
			pkg_free(node->unix_socket_path);
		pkg_free(node);
		node = next;
	}
	con->nodes = NULL;
	memset(con->slot_table, 0, sizeof(con->slot_table));
}

cluster_node *find_or_create_node(redis_con *con, const char *ip,
	int ip_len, unsigned short port)
{
	cluster_node *node;
	str src, dst;

	/* walk existing node list, compare using str_match */
	for (node = con->nodes; node; node = node->next) {
		if (node->port == port) {
			str host_str = {node->ip, strlen(node->ip)};
			str ip_str = {(char *)ip, ip_len};
			if (str_match(&host_str, &ip_str)) {
				node->seen = 1;
				return node;
			}
		}
	}

	/* not found — allocate new node */
	node = pkg_malloc(sizeof(cluster_node));
	if (!node) {
		LM_ERR("pkg_malloc failed for cluster_node\n");
		return NULL;
	}
	memset(node, 0, sizeof(cluster_node));

	/* duplicate IP using OpenSIPS safe string copy */
	src.s = (char *)ip;
	src.len = ip_len;
	if (pkg_nt_str_dup(&dst, &src) != 0) {
		LM_ERR("pkg_nt_str_dup failed for node IP\n");
		pkg_free(node);
		return NULL;
	}
	node->ip = dst.s;
	node->port = port;
	node->seen = 1;

	/* connect to the new node */
	if (redis_connect_node(con, node) < 0) {
		LM_ERR("failed to connect to new node %.*s:%d\n", ip_len, ip, port);
		/* keep the node in the list even if connect fails —
		 * it will be retried on next use via redis_reconnect_node() */
	}

	/* insert at head of node list */
	node->next = con->nodes;
	con->nodes = node;

	LM_DBG("created new cluster node %s:%d (%p)\n", node->ip, node->port, node);
	return node;
}

int parse_cluster_shards(redis_con *con, redisReply *reply)
{
	size_t i, j, k, n, s;
	redisReply *shard, *key, *val, *slots_array, *nodes_array;
	redisReply *node_map, *nk, *nv;
	const char *master_ip, *role;
	long long master_port;
	long long start, end;
	cluster_node *node;

	if (!reply || reply->type != REDIS_REPLY_ARRAY)
		return -1;

	for (i = 0; i < reply->elements; i++) {
		shard = reply->element[i];
		if (!shard || shard->type != REDIS_REPLY_ARRAY)
			continue;

		slots_array = NULL;
		nodes_array = NULL;

		/* walk key-value pairs to find "slots" and "nodes" */
		for (j = 0; j + 1 < shard->elements; j += 2) {
			key = shard->element[j];
			val = shard->element[j + 1];
			if (!key || !key->str || !val)
				continue;
			if (strcmp(key->str, "slots") == 0)
				slots_array = val;
			else if (strcmp(key->str, "nodes") == 0)
				nodes_array = val;
		}

		if (!slots_array || !nodes_array)
			continue;

		/* find master node in nodes array */
		master_ip = NULL;
		master_port = 0;
		for (n = 0; n < nodes_array->elements; n++) {
			node_map = nodes_array->element[n];
			if (!node_map || node_map->type != REDIS_REPLY_ARRAY)
				continue;

			const char *ip = NULL;
			long long port = 0;
			role = NULL;

			for (k = 0; k + 1 < node_map->elements; k += 2) {
				nk = node_map->element[k];
				nv = node_map->element[k + 1];
				if (!nk || !nk->str || !nv)
					continue;
				if (strcmp(nk->str, "ip") == 0 && nv->str)
					ip = nv->str;
				else if (strcmp(nk->str, "port") == 0)
					port = nv->integer;
				else if (strcmp(nk->str, "role") == 0 && nv->str)
					role = nv->str;
			}

			if (role && strcmp(role, "master") == 0) {
				master_ip = ip;
				master_port = port;
				break;
			}
		}

		if (!master_ip || master_port <= 0 || master_port > 65535)
			continue;

		node = find_or_create_node(con, master_ip, strlen(master_ip),
			(unsigned short)master_port);
		if (!node)
			continue;

		/* assign slot ranges — pairs of [start, end] integers */
		for (s = 0; s + 1 < slots_array->elements; s += 2) {
			if (!slots_array->element[s] || !slots_array->element[s + 1])
				continue;
			start = slots_array->element[s]->integer;
			end = slots_array->element[s + 1]->integer;
			for (long long slot = start; slot <= end; slot++) {
				if (slot >= 0 && slot < 16384)
					con->slot_table[slot] = node;
			}
		}
	}

	return 0;
}

int parse_cluster_slots(redis_con *con, redisReply *reply)
{
	size_t i;
	redisReply *entry, *master;
	long long start, end;
	const char *ip;
	long long port;
	cluster_node *node;

	if (!reply || reply->type != REDIS_REPLY_ARRAY)
		return -1;

	for (i = 0; i < reply->elements; i++) {
		entry = reply->element[i];
		if (!entry || entry->type != REDIS_REPLY_ARRAY || entry->elements < 3)
			continue;

		if (!entry->element[0] || !entry->element[1] || !entry->element[2])
			continue;
		start = entry->element[0]->integer;
		end = entry->element[1]->integer;
		master = entry->element[2];

		if (!master || master->type != REDIS_REPLY_ARRAY || master->elements < 2)
			continue;

		ip = master->element[0]->str;
		port = master->element[1]->integer;

		/* empty IP means "use the queried node's address" */
		if (!ip || strlen(ip) == 0)
			ip = con->host;

		if (port < 1 || port > 65535)
			continue;

		node = find_or_create_node(con, ip, strlen(ip), (unsigned short)port);
		if (!node)
			continue;

		for (long long slot = start; slot <= end; slot++) {
			if (slot >= 0 && slot < 16384)
				con->slot_table[slot] = node;
		}
	}

	return 0;
}

int probe_cluster_command(redis_con *con, redisContext *ctx)
{
	redisReply *reply;

	/* try CLUSTER SHARDS first (Redis 7.0+) */
	reply = redisCommand(ctx, "CLUSTER SHARDS");
	if (reply && reply->type == REDIS_REPLY_ARRAY) {
		con->cluster_cmd = CLUSTER_CMD_SHARDS;
		LM_DBG("using CLUSTER SHARDS for topology\n");
		if (parse_cluster_shards(con, reply) < 0) {
			freeReplyObject(reply);
			return -1;
		}
		freeReplyObject(reply);
		return 0;
	}
	if (reply)
		freeReplyObject(reply);

	/* fall back to CLUSTER SLOTS (Redis 3.0+) */
	reply = redisCommand(ctx, "CLUSTER SLOTS");
	if (reply && reply->type == REDIS_REPLY_ARRAY) {
		con->cluster_cmd = CLUSTER_CMD_SLOTS;
		LM_DBG("using CLUSTER SLOTS for topology\n");
		if (parse_cluster_slots(con, reply) < 0) {
			freeReplyObject(reply);
			return -1;
		}
		freeReplyObject(reply);
		return 0;
	}
	if (reply)
		freeReplyObject(reply);

	con->cluster_cmd = CLUSTER_CMD_NONE;
	return -1;
}

int refresh_cluster_topology(redis_con *con)
{
	cluster_node *node, *prev, *next;
	redisReply *reply = NULL;
	time_t now;
	int s;

	if (!(con->flags & REDIS_CLUSTER_INSTANCE))
		return 0;

	/* rate-limit: at most once per second */
	now = time(NULL);
	if ((now - con->last_topology_refresh) < 1)
		return 0;

	/* query a reachable node using the cached command */
	for (node = con->nodes; node; node = node->next) {
		if (!node->context)
			continue;
		if (con->cluster_cmd == CLUSTER_CMD_SHARDS)
			reply = redisCommand(node->context, "CLUSTER SHARDS");
		else
			reply = redisCommand(node->context, "CLUSTER SLOTS");
		if (reply && reply->type == REDIS_REPLY_ARRAY)
			break;
		if (reply) {
			freeReplyObject(reply);
			reply = NULL;
		}
	}

	if (!reply) {
		LM_ERR("all nodes unreachable, cannot refresh topology\n");
		return -1;
	}

	/* mark all existing nodes as unseen */
	for (node = con->nodes; node; node = node->next)
		node->seen = 0;

	/* clear slot table */
	memset(con->slot_table, 0, sizeof(con->slot_table));

	/* parse — each parser calls find_or_create_node and fills slot_table */
	if (con->cluster_cmd == CLUSTER_CMD_SHARDS)
		parse_cluster_shards(con, reply);
	else
		parse_cluster_slots(con, reply);

	freeReplyObject(reply);

	/* remove nodes no longer in the cluster */
	prev = NULL;
	node = con->nodes;
	while (node) {
		next = node->next;
		if (!node->seen) {
			/* unlink from list */
			if (prev)
				prev->next = next;
			else
				con->nodes = next;
			/* defensive: clear any stale slot_table pointers */
			for (s = 0; s < 16384; s++) {
				if (con->slot_table[s] == node)
					con->slot_table[s] = NULL;
			}
			LM_DBG("removing stale node %s:%d\n", node->ip, node->port);
			redisFree(node->context);
			if (use_tls && node->tls_dom)
				tls_api.release_domain(node->tls_dom);
			pkg_free(node->ip);
			if (node->unix_socket_path)
				pkg_free(node->unix_socket_path);
			pkg_free(node);
		} else {
			prev = node;
		}
		node = next;
	}

	con->last_topology_refresh = now;
	con->topology_refresh_count++;
	update_stat(redis_stat_topology_refreshes, 1);
	LM_DBG("topology refresh #%u complete\n", con->topology_refresh_count);
	return 0;
}

/*
 When Redis is operating as a cluster, it is possible (very likely)
 that a MOVED redirection will be returned by the Redis nodes that
 received the request. The general format of the reply from Redis is:
 PREFIX slot [IP|FQDN]:port

 This routine will parse the Redis redirect reply into its components.
 Note that the redisReply struct MUST be released outside of this routine
 to avoid a memory leak. The out->endpoint pointer must not be used after
 the redisReply has been released.

 The parsed data is stored into the following redis_moved struct:

 typedef struct {
	int slot;
	const_str endpoint;
	int port;
 } redis_moved;

*/
static int parse_redirect_reply(redisReply *reply, redis_moved *out,
	const char *prefix, size_t prefix_len) {
	int i;
	int slot = 0;
	const char *p;
	const char *end;
	const char *host_start;
	const char *colon = NULL;
	const char *port_start;
	int port = REDIS_DF_PORT; // Default to Redis standard port

	if (!reply || !reply->str || reply->len < prefix_len || !out)
		return ERR_INVALID_REPLY;

	p = reply->str;
	end = reply->str + reply->len;

	for (i = 0; i < prefix_len; ++i) {
		if (p[i] != prefix[i]) {
		return ERR_INVALID_REPLY;
		}
	}
	p += prefix_len;

	// Parse slot number
	while (p < end && *p >= '0' && *p <= '9') {
		slot = slot * 10 + (*p - '0');
		p++;
	}
	if (slot == 0 && (p == reply->str + prefix_len || *(p - 1) < '0' || *(p - 1) > '9'))
		return ERR_INVALID_SLOT;
	if (slot > 16383)
		return ERR_INVALID_SLOT;

	// Skip spaces
	while (p < end && *p == ' ') p++;

	// Parse host and port
	host_start = p;
	while (p < end) {
		if (*p == ':') {
			colon = p;
			break;
		}
		p++;
	}

	out->endpoint.s = NULL;
	out->endpoint.len = 0;

	if (colon) {
		out->endpoint.s = host_start;
		out->endpoint.len = colon - host_start;

		// Parse port
		port_start = colon + 1;
		p = port_start;
		if (p < end) {
			port = 0;
			while (p < end && *p >= '0' && *p <= '9') {
				port = port * 10 + (*p - '0');
				if (port > 65535)
					return ERR_INVALID_PORT;
				p++;
			}
			if (port < 0 || port > 65535 || port_start == p)
				return ERR_INVALID_PORT;
		}
	} else if (p < end) {
		out->endpoint.s = host_start;
		out->endpoint.len = end - host_start;
	}

	// Fill output
	out->slot = slot;
	out->port = port;

	return 0;
}

int parse_moved_reply(redisReply *reply, redis_moved *out) {
	return parse_redirect_reply(reply, out, MOVED_PREFIX, MOVED_PREFIX_LEN);
}

