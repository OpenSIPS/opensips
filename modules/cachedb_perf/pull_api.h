/*
 * Copyright (C) 2026 Yury Kirsanov
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Asynchronous cross-node pull: bind with load_pcache_pull_api() at
 * mod_init, start() a pull, wait on the returned fd, then finish().
 */

#ifndef PCACHE_PULL_API_H
#define PCACHE_PULL_API_H

#include "../../str.h"
#include "../../sr_module.h"
#include "../../cachedb/cachedb.h"

/* Pull @key for @con's collection; @fd turns readable when the request is
 * settled.  1 = started, 0 = known absent, -1 = cannot pull. */
typedef int (*pcache_pull_start_f)(cachedb_con *con, str *key, int *fd,
		unsigned int *handle);

/* As start(), but ask @node_id first; an invalid hint falls back to a
 * broadcast, @node_id <= 0 is plain start(). */
typedef int (*pcache_pull_start_at_f)(cachedb_con *con, str *key,
		int node_id, int *fd, unsigned int *handle);

/* this node's cluster id, 0 if none */
typedef int (*pcache_my_node_id_f)(cachedb_con *con);

/* Collect and release a started pull (also after a timeout).  On a hit
 * @val is pkg memory owned by the caller and the value is cached locally.
 * 1 = value in @val, 0 = absent, -1 = no answer. */
typedef int (*pcache_pull_finish_f)(cachedb_con *con, str *key,
		unsigned int handle, str *val);

typedef struct pcache_pull_api {
	pcache_pull_start_f    start;
	pcache_pull_finish_f   finish;
	pcache_pull_start_at_f start_at;
	pcache_my_node_id_f    my_node_id;
} pcache_pull_api_t;

typedef int (*load_pcache_pull_f)(pcache_pull_api_t *api);

static inline int load_pcache_pull_api(pcache_pull_api_t *api)
{
	load_pcache_pull_f load_it;

	load_it = (load_pcache_pull_f)(void *)find_export("load_pcache_pull", 0);
	if (!load_it)
		return -1;
	return load_it(api);
}

#endif /* PCACHE_PULL_API_H */
