/*
 * Copyright (C) 2026 VoIPcloud
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
 * Asynchronous cross-node pull, for a consumer that would rather suspend
 * a transaction than occupy a process while the cluster answers.
 *
 *     pcache_pull_api_t pull;
 *     if (load_pcache_pull_api(&pull) == 0) ...        (mod_init)
 *
 *     rc = pull.start(con, &key, &fd, &handle);
 *     if (rc == 1)  -> wait on @fd, then call finish()
 *     if (rc == 0)  -> the cluster has already answered: nobody has it
 *     if (rc < 0)   -> cannot pull (not enabled, no peers, no free slot)
 *
 * Binding is optional by design: a consumer that cannot find this simply
 * does not do cross-node lookups, exactly as today.
 */

#ifndef PCACHE_PULL_API_H
#define PCACHE_PULL_API_H

#include "../../str.h"
#include "../../sr_module.h"
#include "../../cachedb/cachedb.h"

/* Begin a pull for @key on @con's collection.  On success @fd becomes
 * readable once an answer has landed (or the request has been settled),
 * and @handle identifies it to finish().
 * @return 1 = started, 0 = already known absent, -1 = cannot pull. */
typedef int (*pcache_pull_start_f)(cachedb_con *con, str *key, int *fd,
		unsigned int *handle);

/* As start(), but ask one node first instead of the whole cluster.  The
 * caller supplies @node_id from whatever knowledge it has of where the
 * key was put; it is treated as a hint and validated against current
 * membership, so a stale or nonsensical one costs nothing but the usual
 * broadcast.  @node_id <= 0 behaves exactly like start(). */
typedef int (*pcache_pull_start_at_f)(cachedb_con *con, str *key,
		int node_id, int *fd, unsigned int *handle);

/* This node's id in the cluster the cache is part of, 0 if it has none.
 * A consumer that wants to record where it stored something needs this,
 * and getting it from here saves it from binding the clusterer itself. */
typedef int (*pcache_my_node_id_f)(cachedb_con *con);

/* Collect a started pull.  Safe to call after a timeout as well as after
 * the descriptor fires - it releases the request either way, so a caller
 * that gives up leaks nothing.  On a hit @val is pkg memory the caller
 * owns; the value has also been stored locally, so an ordinary get will
 * now find it.
 * @return 1 = value in @val, 0 = definitively absent, -1 = no answer. */
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
