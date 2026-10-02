/*
 * cachedb_perf - DB persistence
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * cachedb_perf - whole-collection snapshots to a db_* backend.  Expiry is
 * stored as absolute wall-clock time so TTLs survive a restart.
 */
#ifndef _PCACHE_DB_H_
#define _PCACHE_DB_H_

#include "../../str.h"
#include "cachedb_perf.h"

/* bind the db_* module at @db_url; 0 ok, -1 error */
int pcache_db_init(const str *db_url, const str *db_table);

int pcache_db_enabled(void);

/* replace the collection's rows with its live entries; rows written or -1 */
int pcache_db_save(pcache_col_t *col);

/* load unexpired rows into the collection; rows loaded or -1 */
int pcache_db_load(pcache_col_t *col);

#endif /* _PCACHE_DB_H_ */
