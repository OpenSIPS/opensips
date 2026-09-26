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

#ifndef DB_REDIS_H
#define DB_REDIS_H

/* connection mode selection (modparam "mode") */
#define RDB_MODE_AUTO		0
#define RDB_MODE_SINGLE		1
#define RDB_MODE_CLUSTER	2

extern int rdb_connect_timeout;   /* ms */
extern int rdb_query_timeout;     /* ms */
extern int rdb_scan_count;        /* SCAN COUNT hint */
extern int rdb_mode;              /* RDB_MODE_* */

int db_redis_bind_api(const str* mod, db_func_t *dbb);

#endif /* DB_REDIS_H */
