/*
 * cachedb_perf - DB persistence of whole collections to a db_* backend.
 *
 * The DB is a shared source of truth; the in-memory cache is a view over it.
 * A collection is saved as a full snapshot (delete its rows, insert all live
 * entries) and loaded back the same way.  TTLs are stored as absolute wall-
 * clock time, so they survive a restart (the cache's own expiry is in
 * monotonic ticks, which reset on reboot).
 */
#ifndef _PCACHE_DB_H_
#define _PCACHE_DB_H_

#include "../../str.h"
#include "cachedb_perf.h"

/* bind the db_* module at @db_url and remember the table.  0 ok, -1 error. */
int pcache_db_init(const str *db_url, const str *db_table);

/* is a DB backend configured? */
int pcache_db_enabled(void);

/* save a collection as a full snapshot (DELETE its rows, then INSERT every
 * live entry with an absolute-unix expiry).  Returns rows written, -1 error. */
int pcache_db_save(pcache_col_t *col);

/* load a collection from the DB into its table, skipping rows that have
 * already expired.  Returns rows loaded, -1 error. */
int pcache_db_load(pcache_col_t *col);

#endif /* _PCACHE_DB_H_ */
