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

/**
 * Basic primitives which enable async DB support on top of existing code
 * while keeping the existing logic working exactly as before
 */

#ifndef DB_ASYNC_H
#define DB_ASYNC_H

#include "db_con.h"

typedef int (*get_con_fd_f) (void *con);

/**
 * Sets up the DB handle for an asynchronous query. A new connection is
 * opened if necessary, otherwise one is grabbed from the idle pool.
 *
 * params:
 * _h     - DB handle
 * get_fd - function which returns a read file descriptor (used for polling)
 *			from the backend's connection structure
 * fd_ref - if the connection fetched from the pool disconnected
 *			(requiring a reconnect operation), or if you happen to know its fd
 *			has changed, make sure you also update the reference passed on here
 * new_connection - backend-specific function to allocate and set up a new con
 */
struct pool_con *db_init_async(db_con_t *_h, get_con_fd_f get_fd, int **fd_ref,
                               void *(*new_connection)(const struct db_id *));

/**
 * Replaces the currently in use connection of the DB handle with "async_con"
 *
 * Must not be called twice in a row
 */
void             db_switch_to_async(db_con_t *_h, struct pool_con *async_con);

/**
 * Restores the DB handle in its normal state (i.e. ready for blocking queries)
 * after a previous call to "db_switch_to_async"
 *
 * MUST be called after initiating async operations and/or if:
 *		* a previous db_switch_to_async() was done
 *		* a previous db_match_async_con() was done
 */
void             db_switch_to_sync(db_con_t *_h);

/**
 * Places the given connection back into the async idle pool.
 *
 * MUST be called after db_switch_to_sync().
 *
 * MUST be called if:
 *		* errors occurred while starting up a new async transfer
 *		* a transfer is fully completed.
 */
void             db_store_async_con(db_con_t *_h, struct pool_con *con);

/**
 * Attempts to match the given fd to one of the ongoing async DB transfers.
 * Returns the DB connection of the given fd or NULL if not found
 */
struct pool_con *db_match_async_con(int fd, db_con_t *_h);

#endif /* DB_ASYNC_H */
