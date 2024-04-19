/*
 * Copyright (C) 2024 - OpenSIPS Solutions
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
 */

#include "ipsec_user.h"
#include "../../lib/list.h"
#include "../../locking.h"

struct ipsec_map_node {
	unsigned char n;
	unsigned int size;
	union {
		struct ipsec_map_node *nodes;
		struct list_head *users;
	};
};

struct ipsec_map {
	unsigned int size;
	struct ipsec_map_node *nodes;
	gen_lock_t lock;
};

struct ipsec_user_impi {
	str impi;
	struct list_head list;
	struct list_head users;
	char _buf[0];
};

struct ipsec_map *ipsec_map_ipv4;
struct ipsec_map *ipsec_map_ipv6;

static struct ipsec_map *ipsec_map_create(void)
{
	struct ipsec_map *map = shm_malloc(sizeof *map);
	if (!map)
		return NULL;
	memset(map, 0, sizeof *map);
	if (!lock_init(&map->lock)) {
		shm_free(map);
		return NULL;
	}
	return map;
}

static void ipsec_remove_node_ip(struct ip_addr *ip);

static void _ipsec_map_destroy(struct ipsec_map *map)
{
	/* TODO: remove entries */
	lock_destroy(&map->lock);
	shm_free(map);
}

int ipsec_map_init(void)
{
	ipsec_map_ipv4 = ipsec_map_create();
	if (!ipsec_map_ipv4) {
		LM_ERR("could not initialize IPv4 map\n");
		return -1;
	}
	ipsec_map_ipv6 = ipsec_map_create();
	if (!ipsec_map_ipv6) {
		LM_ERR("could not initialize IPv6 map\n");
		return -1;
	}
	return 0;
}

void ipsec_map_destroy(void)
{
	if (ipsec_map_ipv4)
		_ipsec_map_destroy(ipsec_map_ipv4);
	if (ipsec_map_ipv6)
		_ipsec_map_destroy(ipsec_map_ipv6);
}

void ipsec_dump_users_rec(struct ipsec_map_node *nodes, int size, unsigned char *buf, int level)
{
	int n;
	struct list_head *it, *it2;
	struct ipsec_user_impi *impi;
	struct ipsec_user *user;
	if (level == 4) {
		list_for_each(it, (struct list_head *)nodes) {
			impi = list_entry(it, struct ipsec_user_impi, list);
			list_for_each(it2, &impi->users) {
				user = list_entry(it2, struct ipsec_user, list);
				LM_DBG("print %hu.%hu.%hu.%hu - %.*s/%.*s\n", buf[0], buf[1], buf[2], buf[3],
						user->impi.len, user->impi.s, user->impu.len, user->impu.s);
			}
		}
		return;
	}
	for (n = 0; n < size; n++) {
		buf[level] = nodes[n].n;
		ipsec_dump_users_rec(nodes[n].nodes, nodes[n].size, buf, level + 1);
	}
}

static void ipsec_dump_users(struct ipsec_map *map)
{
	unsigned char buf[4];
	lock_get(&map->lock);
	ipsec_dump_users_rec(map->nodes, map->size, buf, 0);
	lock_release(&map->lock);
}

static struct ipsec_map_node *ipsec_get_node(struct ip_addr *ip, int level,
		struct ipsec_map_node **nodes_list, unsigned int *size)
{
	int i;
	unsigned char n;
	struct ipsec_map_node *nodes = *nodes_list;
	int leaf = (ip->len - 1 == level);
	n = ip->u.addr[level];

	/* first, check if there is an already existing node for this level */
	if (nodes && *size) {
		for (i = 0; i < *size; i++) {
			if (nodes[i].n == n) {
				if (leaf)
					return &nodes[i];
				else
					return ipsec_get_node(ip, level + 1,
							&nodes[i].nodes, &nodes[i].size);
			} else if (nodes[i].n > n) {
				break;
			}
		}
	} else {
		i = 0;
	}
	/* node does not exist - we need to add it */
	nodes = shm_realloc(nodes, ((*size) + 1) * sizeof(*nodes));
	if (!nodes) {
		LM_ERR("oom for nodes\n");
		return NULL;
	}
	/* make room for the new element */
	memmove(nodes + i + 1, nodes + i, ((*size) - i) * sizeof (*nodes));
	*nodes_list = nodes;
	(*size)++;
	memset(&nodes[i], 0, sizeof *nodes);
	nodes[i].n = n;
	if (leaf)
		return &nodes[i];
	else
		return ipsec_get_node(ip, level + 1, &nodes[i].nodes, &nodes[i].size);
}

static struct ipsec_user_impi *ipsec_find_user_impi(struct list_head *list, str *impi)
{
	struct ipsec_user_impi *uimpi;
	struct list_head *it;
	list_for_each(it, list) {
		uimpi = list_entry(it, struct ipsec_user_impi, list);
		if (str_match(&uimpi->impi, impi))
			return uimpi;
	}
	return NULL;
}

struct ipsec_user *ipsec_find_user_in_impi(struct list_head *list, str *impu)
{
	struct ipsec_user *user;
	struct list_head *it;
	list_for_each(it, list) {
		user = list_entry(it, struct ipsec_user, list);
		if (str_match(&user->impu, impu))
			return user;
	}
	return NULL;
}

static struct ipsec_user *ipsec_get_create_user(struct ipsec_map_node *node,
		struct ip_addr *ip, str *impi, str *impu)
{
	struct ipsec_user_impi *uimpi = NULL;
	struct ipsec_user *user;
	if (node->users) {
		uimpi = ipsec_find_user_impi(node->users, impi);
		if (uimpi) {
			user = ipsec_find_user_in_impi(&uimpi->users, impu);
			if (user) {
				lock_get(&user->lock);
				user->ref++;
				lock_release(&user->lock);
				return user;
			}
		}
	} else {
		node->users = shm_malloc(sizeof *node->users);
		if (!node->users)
			return NULL;
		INIT_LIST_HEAD(node->users);
	}
	if (!uimpi) {
		uimpi = shm_malloc(sizeof(*uimpi) + impi->len);
		if (!uimpi)
			goto error;
		memset(uimpi, 0, sizeof *uimpi);
		uimpi->impi.s = uimpi->_buf;
		memcpy(uimpi->impi.s, impi->s, impi->len);
		uimpi->impi.len = impi->len;
		INIT_LIST_HEAD(&uimpi->users);
		list_add(&uimpi->list, node->users);
	}
	user = shm_malloc(sizeof(*user) + impu->len);
	if (!user) {
		LM_ERR("oom for creating a new user\n");
		goto error;
	}
	memset(user, 0, sizeof *user);
	user->impi = uimpi->impi;
	user->impu.s = user->_buf;
	user->impu.len = impu->len;
	memcpy(user->impu.s, impu->s, impu->len);
	memcpy(&user->ip, ip, sizeof *ip);
	lock_init(&user->lock);
	user->ref = 1;
	INIT_LIST_HEAD(&user->list);
	INIT_LIST_HEAD(&user->sas);
	list_add(&user->list, &uimpi->users);
	return user;
error:
	if (list_empty(&uimpi->users)) {
		list_del(&uimpi->list);
		shm_free(uimpi);
	}
	if (list_empty(node->users)) {
		shm_free(node->users);
		node->users = NULL;
	}
	return NULL;
}

struct ipsec_user *ipsec_get_user(struct ip_addr *ip, str *impi, str *impu)
{
	struct ipsec_map *map;
	struct ipsec_map_node *node;
	struct ipsec_user *user = NULL;

	if (ip->af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	node = ipsec_get_node(ip, 0, &map->nodes, &map->size);
	if (node) {
		user = ipsec_get_create_user(node, ip, impi, impu);
		if (!user) {
			LM_ERR("could not create user!\n");
			ipsec_remove_node_ip(ip);
		}
	}
	lock_release(&map->lock);
	ipsec_dump_users(map);
	return user;
}

static struct ipsec_map_node *ipsec_find_node(struct ip_addr *ip, int level,
		struct ipsec_map_node *nodes, unsigned int size)
{
	int n;
	for (n = 0; n < size; n++) {
		if (nodes[n].n == ip->u.addr[level]) {
			if (ip->len - 1 == level)
				return &nodes[n];
			else
				return ipsec_find_node(ip, level + 1, nodes[n].nodes, nodes[n].size);
		}
	}
	return NULL;
}

struct ipsec_user *ipsec_find_user(struct ip_addr *ip, str *impi, str *impu)
{
	struct ipsec_map *map;
	struct ipsec_map_node *node;
	struct ipsec_user_impi *uimpi;
	struct ipsec_user *user = NULL;

	if (ip->af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	node = ipsec_find_node(ip, 0, map->nodes, map->size);
	if (node) {
		uimpi = ipsec_find_user_impi(node->users, impi);
		if (uimpi) {
			user = ipsec_find_user_in_impi(&uimpi->users, impu);
			if (user) {
				lock_get(&user->lock);
				user->ref++;
				lock_release(&user->lock);
			}
		}
	} else {
		user = NULL;
	}
	lock_release(&map->lock);
	ipsec_dump_users(map);
	return user;
}

static void ipsec_destroy_user(struct ipsec_user *user)
{
	struct ipsec_map *map;
	struct ipsec_map_node *node;
	struct ipsec_user_impi *uimpi;

	if (user->ip.af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	node = ipsec_find_node(&user->ip, 0, map->nodes, map->size);
	if (node) {
		uimpi = ipsec_find_user_impi(node->users, &user->impi);
		if (uimpi) {
			list_del(&user->list);
			if (list_empty(&uimpi->users)) {
				list_del(&uimpi->list);
				shm_free(uimpi);
				if (list_empty(node->users)) {
					shm_free(node->users);
					node->users = NULL;
				}
			}
		} else {
			LM_ERR("user impi %.*s not found!\n", user->impi.len, user->impi.s);
		}
	} else {
		LM_ERR("user not found!\n");
	}
	lock_release(&map->lock);
	ipsec_remove_node_ip(&user->ip);
	lock_destroy(&user->lock);
	shm_free(user);
}

static void ipsec_release_user_count(struct ipsec_user *user, int count)
{
	int free = 0;
	lock_get(&user->lock);
	if (user->ref < count) {
		LM_BUG("invalid unref of %d with %d for user %p\n", user->ref, count, user);
	} else {
		user->ref -= count;
		free = (user->ref == 0);
	}
	lock_release(&user->lock);
	if (free)
		ipsec_destroy_user(user);
}

void ipsec_release_user(struct ipsec_user *user)
{
	ipsec_release_user_count(user, 1);
}

static int ipsec_remove_node(struct ip_addr *ip, int level,
		struct ipsec_map_node **nodes_list, unsigned int *size)
{
	int n;
	struct ipsec_map_node *nodes;
	int remove = 0;
	int leaf = (ip->len - 1 == level);

	nodes = *nodes_list;
	for (n = 0; n < *size; n++) {
		if (nodes[n].n == ip->u.addr[level]) {
			if (leaf)
				remove = (nodes[n].users == NULL);
			else
				remove = ipsec_remove_node(ip, level + 1, &nodes[n].nodes, &nodes[n].size);
			break;
		}
	}
	if (remove) {
		/* user found - remove the node */
		if (*size == 1) {
			shm_free(nodes);
			*nodes_list = NULL;
			*size = 0;
		} else {
			memmove(&nodes[n + 1], &nodes[n], ((*size) - n - 1) * sizeof (*nodes));
			(*size)--;
			*nodes_list = nodes;
		}
	}
	return remove;
}

static void ipsec_remove_node_ip(struct ip_addr *ip)
{
	struct ipsec_map *map;

	if (ip->af == AF_INET)
		map = ipsec_map_ipv4;
	else
		map = ipsec_map_ipv6;
	lock_get(&map->lock);
	ipsec_remove_node(ip, 0, &map->nodes, &map->size);
	lock_release(&map->lock);
	ipsec_dump_users(map);
}

struct ipsec_ctx *ipsec_get_ctx_user(struct ipsec_user *user, struct receive_info *ri)
{
	struct list_head *it;
	struct ipsec_ctx *ctx = NULL;
	lock_get(&user->lock);
	list_for_each(it, &user->sas) {
		ctx = list_entry(it, struct ipsec_ctx, list);
		if (ctx->ue.port_c == ri->src_port && ctx->me.port_s == ri->dst_port)
			break;
		ctx = NULL;
	}
	lock_release(&user->lock);
	return ctx;
}
