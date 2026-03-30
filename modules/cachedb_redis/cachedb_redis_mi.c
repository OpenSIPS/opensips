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
 */

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mi/mi.h"
#include "../../cachedb/cachedb_pool.h"
#include "cachedb_redis_dbase.h"
#include "cachedb_redis_utils.h"
#include "cachedb_redis_mi.h"

#include <sys/time.h>
#include <string.h>
#include <time.h>

extern str cache_mod_name;

static int count_node_slots(redis_con *con, cluster_node *node)
{
	int i, count = 0;

	for (i = 0; i < 16384; i++)
		if (con->slot_table[i] == node)
			count++;

	return count;
}

static int count_total_slots(redis_con *con)
{
	int i, count = 0;

	for (i = 0; i < 16384; i++)
		if (con->slot_table[i] != NULL)
			count++;

	return count;
}

static int mi_add_redis_con(mi_item_t *arr, redis_con *con)
{
	mi_item_t *con_obj, *nodes_arr, *node_obj;
	cluster_node *node;
	int is_cluster;

	con_obj = add_mi_object(arr, NULL, 0);
	if (!con_obj)
		return -1;

	if (!con->id->group_name || !con->id->initial_url)
		return -1;

	if (add_mi_string(con_obj, MI_SSTR("group"),
			con->id->group_name, strlen(con->id->group_name)) < 0)
		return -1;

	if (add_mi_string(con_obj, MI_SSTR("url"),
			con->id->initial_url, strlen(con->id->initial_url)) < 0)
		return -1;

	is_cluster = (con->flags & REDIS_CLUSTER_INSTANCE) ? 1 : 0;

	if (is_cluster) {
		if (add_mi_string(con_obj, MI_SSTR("mode"),
				MI_SSTR("cluster")) < 0)
			return -1;
	} else {
		if (add_mi_string(con_obj, MI_SSTR("mode"),
				MI_SSTR("single")) < 0)
			return -1;
	}

	if (con->flags & REDIS_UNIX_SOCKET) {
		if (add_mi_string(con_obj, MI_SSTR("transport"),
				MI_SSTR("unix")) < 0)
			return -1;
		if (con->unix_socket_path) {
			if (add_mi_string(con_obj, MI_SSTR("socket_path"),
					con->unix_socket_path,
					strlen(con->unix_socket_path)) < 0)
				return -1;
		}
	} else {
		if (add_mi_string(con_obj, MI_SSTR("transport"),
				MI_SSTR("tcp")) < 0)
			return -1;
	}

	if (is_cluster) {
		if (con->cluster_cmd == CLUSTER_CMD_SHARDS) {
			if (add_mi_string(con_obj, MI_SSTR("cluster_command"),
					MI_SSTR("SHARDS")) < 0)
				return -1;
		} else {
			if (add_mi_string(con_obj, MI_SSTR("cluster_command"),
					MI_SSTR("SLOTS")) < 0)
				return -1;
		}
	}

	if (add_mi_number(con_obj, MI_SSTR("topology_refreshes"),
			con->topology_refresh_count) < 0)
		return -1;

	if (add_mi_number(con_obj, MI_SSTR("last_topology_refresh"),
			(double)con->last_topology_refresh) < 0)
		return -1;

	nodes_arr = add_mi_array(con_obj, MI_SSTR("nodes"));
	if (!nodes_arr)
		return -1;

	for (node = con->nodes; node; node = node->next) {
		node_obj = add_mi_object(nodes_arr, NULL, 0);
		if (!node_obj)
			return -1;

		if (node->unix_socket_path) {
			if (add_mi_string(node_obj, MI_SSTR("socket_path"),
					node->unix_socket_path,
					strlen(node->unix_socket_path)) < 0)
				return -1;
		} else {
			if (add_mi_string(node_obj, MI_SSTR("ip"),
					node->ip, strlen(node->ip)) < 0)
				return -1;

			if (add_mi_number(node_obj, MI_SSTR("port"), node->port) < 0)
				return -1;
		}

		if (node->context) {
			if (add_mi_string(node_obj, MI_SSTR("status"),
					MI_SSTR("connected")) < 0)
				return -1;
		} else {
			if (add_mi_string(node_obj, MI_SSTR("status"),
					MI_SSTR("disconnected")) < 0)
				return -1;
		}

		if (is_cluster) {
			if (add_mi_number(node_obj, MI_SSTR("slots_assigned"),
					count_node_slots(con, node)) < 0)
				return -1;
		}

		if (add_mi_number(node_obj, MI_SSTR("queries"), node->queries) < 0)
			return -1;
		if (add_mi_number(node_obj, MI_SSTR("errors"), node->errors) < 0)
			return -1;
		if (add_mi_number(node_obj, MI_SSTR("moved"), node->moved) < 0)
			return -1;

		if (node->last_activity > 0) {
			if (add_mi_number(node_obj, MI_SSTR("last_activity"),
					(double)(time(NULL) - node->last_activity)) < 0)
				return -1;
		} else {
			if (add_mi_number(node_obj, MI_SSTR("last_activity"), -1) < 0)
				return -1;
		}
	}

	if (is_cluster) {
		if (add_mi_number(con_obj, MI_SSTR("total_slots_mapped"),
				count_total_slots(con)) < 0)
			return -1;
	}

	return 0;
}

static mi_response_t *mi_cluster_info_impl(const char *group, int group_len)
{
	mi_response_t *resp;
	mi_item_t *resp_arr;
	cachedb_pool_con **cons;
	redis_con *con;
	int i, size = 0;

	cons = filter_pool_by_scheme(&cache_mod_name, &size);
	if (!cons || size == 0) {
		if (cons)
			pkg_free(cons);
		return init_mi_result_string(MI_SSTR("No redis connections"));
	}

	resp = init_mi_result_array(&resp_arr);
	if (!resp) {
		pkg_free(cons);
		return 0;
	}

	for (i = 0; i < size; i++) {
		con = (redis_con *)cons[i];

		if (group && (!con->id->group_name ||
				strlen(con->id->group_name) != group_len ||
				memcmp(con->id->group_name, group, group_len) != 0))
			continue;

		if (mi_add_redis_con(resp_arr, con) < 0) {
			pkg_free(cons);
			free_mi_response(resp);
			return 0;
		}
	}

	pkg_free(cons);
	return resp;
}

mi_response_t *mi_redis_cluster_info(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	return mi_cluster_info_impl(NULL, 0);
}

mi_response_t *mi_redis_cluster_info_1(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	char *group;
	int group_len;

	if (get_mi_string_param(params, "group", &group, &group_len) < 0)
		return init_mi_param_error();

	return mi_cluster_info_impl(group, group_len);
}

static mi_response_t *mi_cluster_refresh_impl(const char *group, int group_len)
{
	mi_response_t *resp;
	mi_item_t *resp_arr, *con_obj;
	cachedb_pool_con **cons;
	redis_con *con;
	int i, size = 0;

	cons = filter_pool_by_scheme(&cache_mod_name, &size);
	if (!cons || size == 0) {
		if (cons)
			pkg_free(cons);
		return init_mi_result_string(MI_SSTR("No redis connections"));
	}

	resp = init_mi_result_array(&resp_arr);
	if (!resp) {
		pkg_free(cons);
		return 0;
	}

	for (i = 0; i < size; i++) {
		con = (redis_con *)cons[i];

		if (group && (!con->id->group_name ||
				strlen(con->id->group_name) != group_len ||
				memcmp(con->id->group_name, group, group_len) != 0))
			continue;

		con_obj = add_mi_object(resp_arr, NULL, 0);
		if (!con_obj) {
			pkg_free(cons);
			free_mi_response(resp);
			return 0;
		}

		if (!con->id->group_name ||
				add_mi_string(con_obj, MI_SSTR("group"),
				con->id->group_name, strlen(con->id->group_name)) < 0) {
			pkg_free(cons);
			free_mi_response(resp);
			return 0;
		}

		if (con->flags & REDIS_CLUSTER_INSTANCE) {
			/* bypass rate limit */
			con->last_topology_refresh = 0;
			if (refresh_cluster_topology(con) < 0) {
				if (add_mi_string(con_obj, MI_SSTR("status"),
						MI_SSTR("error")) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
			} else {
				if (add_mi_string(con_obj, MI_SSTR("status"),
						MI_SSTR("ok")) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
			}
		} else {
			if (add_mi_string(con_obj, MI_SSTR("status"),
					MI_SSTR("skipped (not cluster mode)")) < 0) {
				pkg_free(cons);
				free_mi_response(resp);
				return 0;
			}
		}
	}

	pkg_free(cons);
	return resp;
}

mi_response_t *mi_redis_cluster_refresh(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	return mi_cluster_refresh_impl(NULL, 0);
}

mi_response_t *mi_redis_cluster_refresh_1(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	char *group;
	int group_len;

	if (get_mi_string_param(params, "group", &group, &group_len) < 0)
		return init_mi_param_error();

	return mi_cluster_refresh_impl(group, group_len);
}

static mi_response_t *mi_ping_nodes_impl(const char *group, int group_len)
{
	mi_response_t *resp;
	mi_item_t *resp_arr, *con_obj, *nodes_arr, *node_obj;
	cachedb_pool_con **cons;
	redis_con *con;
	cluster_node *node;
	redisReply *rpl;
	struct timeval t_start, t_end;
	long latency_us;
	int i, size = 0;

	cons = filter_pool_by_scheme(&cache_mod_name, &size);
	if (!cons || size == 0) {
		if (cons)
			pkg_free(cons);
		return init_mi_result_string(MI_SSTR("No redis connections"));
	}

	resp = init_mi_result_array(&resp_arr);
	if (!resp) {
		pkg_free(cons);
		return 0;
	}

	for (i = 0; i < size; i++) {
		con = (redis_con *)cons[i];

		if (group && (!con->id->group_name ||
				strlen(con->id->group_name) != group_len ||
				memcmp(con->id->group_name, group, group_len) != 0))
			continue;

		con_obj = add_mi_object(resp_arr, NULL, 0);
		if (!con_obj) {
			pkg_free(cons);
			free_mi_response(resp);
			return 0;
		}

		if (!con->id->group_name ||
				add_mi_string(con_obj, MI_SSTR("group"),
				con->id->group_name, strlen(con->id->group_name)) < 0) {
			pkg_free(cons);
			free_mi_response(resp);
			return 0;
		}

		nodes_arr = add_mi_array(con_obj, MI_SSTR("nodes"));
		if (!nodes_arr) {
			pkg_free(cons);
			free_mi_response(resp);
			return 0;
		}

		for (node = con->nodes; node; node = node->next) {
			node_obj = add_mi_object(nodes_arr, NULL, 0);
			if (!node_obj) {
				pkg_free(cons);
				free_mi_response(resp);
				return 0;
			}

			if (node->unix_socket_path) {
				if (add_mi_string(node_obj, MI_SSTR("socket_path"),
						node->unix_socket_path,
						strlen(node->unix_socket_path)) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
			} else {
				if (add_mi_string(node_obj, MI_SSTR("ip"),
						node->ip, strlen(node->ip)) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}

				if (add_mi_number(node_obj, MI_SSTR("port"), node->port) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
			}

			if (!node->context) {
				if (add_mi_string(node_obj, MI_SSTR("status"),
						MI_SSTR("disconnected")) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
				if (add_mi_number(node_obj, MI_SSTR("latency_us"), -1) < 0) {
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
				continue;
			}

			gettimeofday(&t_start, NULL);
			rpl = redisCommand(node->context, "PING");
			gettimeofday(&t_end, NULL);

			latency_us = (t_end.tv_sec - t_start.tv_sec) * 1000000 +
			             (t_end.tv_usec - t_start.tv_usec);

			if (rpl && rpl->type == REDIS_REPLY_STATUS) {
				if (add_mi_string(node_obj, MI_SSTR("status"),
						MI_SSTR("reachable")) < 0) {
					freeReplyObject(rpl);
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
				if (add_mi_number(node_obj, MI_SSTR("latency_us"),
						latency_us) < 0) {
					freeReplyObject(rpl);
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
			} else {
				if (add_mi_string(node_obj, MI_SSTR("status"),
						MI_SSTR("unreachable")) < 0) {
					if (rpl) freeReplyObject(rpl);
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
				if (add_mi_number(node_obj, MI_SSTR("latency_us"), -1) < 0) {
					if (rpl) freeReplyObject(rpl);
					pkg_free(cons);
					free_mi_response(resp);
					return 0;
				}
			}

			if (rpl) freeReplyObject(rpl);
		}
	}

	pkg_free(cons);
	return resp;
}

mi_response_t *mi_redis_ping_nodes(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	return mi_ping_nodes_impl(NULL, 0);
}

mi_response_t *mi_redis_ping_nodes_1(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
	char *group;
	int group_len;

	if (get_mi_string_param(params, "group", &group, &group_len) < 0)
		return init_mi_param_error();

	return mi_ping_nodes_impl(group, group_len);
}
