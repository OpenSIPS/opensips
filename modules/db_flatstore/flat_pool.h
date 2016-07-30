/*
 * Flatstore module connection pool
 *
 * Copyright (C) 2004 FhG Fokus
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
 */

#ifndef _FLAT_POOL_H
#define _FLAT_POOL_H

#include "flat_con.h"

/*
 * Get a connection from the pool, reuse existing
 * if possible, otherwise create a new one
 */
struct flat_con* flat_get_connection(const str* dir, const str* table);


/*
 * Release a connection, the connection will be left
 * in the pool if ref count != 0, otherwise it
 * will be delete completely
 */
void flat_release_connection(struct flat_con* con);


/*
 * Close and reopen all opened connections
 */
int flat_rotate_logs(void);

#endif /* _FLAT_POOL_H */
