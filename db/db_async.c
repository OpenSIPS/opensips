/*
 * MySQL async connection array management
 *
 * Copyright (C) 2015 OpenSIPS Solutions
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
 * History:
 * --------
 *  2015-01-XX initial version (liviu)
 */

#include <stdlib.h>

#include "db_async.h"
#include "db_pool.h"
#include "../dprint.h"
#include "../error.h"

/*
 * aux variable which holds the default connection (used in blocking mode)
 * while async database operations are done (separate connections & queries)
 */
static struct pool_con *sync_con;

struct pool_con *db_init_async(db_con_t *_h, get_con_fd_f get_fd, int **fd_ref,
                               void *(*new_connection)(const struct db_id *))
{
	struct pool_con *con = (struct pool_con *)_h->tail;
	void *new;

	if (con->no_transfers == db_max_async_connections)
		return NULL;

	/* no idle connections for async queries? open a new one! */
	if (!con->async_pool) {
		new = new_connection(con->id);
		if (!new) {
			LM_ERR("failed to open new DB connection on "
				   "%s://XXXX:XXXX@%s:%d/%s\n", con->id->scheme,
					con->id->host, con->id->port, con->id->database);
			return NULL;
		}
	} else {
		new = con->async_pool;
		con->async_pool = con->async_pool->next;
	}

	*fd_ref = &con->transfers[con->no_transfers].fd;

	con->transfers[con->no_transfers].fd = get_fd(new);
	con->transfers[con->no_transfers].con = new;

	LM_DBG(">>    %d/%d transfers: (%d - %p)\n", con->no_transfers + 1,
			db_max_async_connections, con->transfers[con->no_transfers].fd,
			con->transfers[con->no_transfers].con);

	con->no_transfers++;

	/* switch to the new async con */
	db_switch_to_async(_h, new);

	return new;
}

void db_switch_to_async(db_con_t *_h, struct pool_con *async_con)
{
	sync_con = (struct pool_con *)_h->tail;
	_h->tail = (unsigned long)async_con;
}

void db_switch_to_sync(db_con_t *_h)
{
	if (!sync_con) {
		LM_BUG("sync_con == NULL");
		abort();
	}

	/* switch to sync con */
	_h->tail = (unsigned long)sync_con;
}

void db_store_async_con(db_con_t *_h, struct pool_con *con)
{
	int i;
	struct pool_con *tail = (struct pool_con *)_h->tail;

	con->next = tail->async_pool;
	tail->async_pool = con;

	LM_DBG(">> restore conn %p\n", con);

	for (i = 0; i < tail->no_transfers; i++) {
		if (tail->transfers[i].con == con) {
			tail->no_transfers--;
			for (; i < tail->no_transfers; i++)
				tail->transfers[i] = tail->transfers[i + 1];

			return;
		}
	}

	LM_BUG("DB con %p not found", con);
	abort();
}

struct pool_con *db_match_async_con(int fd, db_con_t *_h)
{
	int i, max;
	struct db_transfer *transfers;

	LM_DBG(">> match fd %d\n", fd);

	transfers = ((struct pool_con *)_h->tail)->transfers;
	max = ((struct pool_con *)_h->tail)->no_transfers;

	for (i = 0; i < max; i++)
		if (fd == transfers[i].fd)
			return (struct pool_con *)_h->tail;

	return NULL;
}
