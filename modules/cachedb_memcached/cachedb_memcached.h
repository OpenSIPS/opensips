#ifndef CACHEDB_MEMCACHEDH
#define CACHEDB_MEMCACHEDH

#include <libmemcached/memcached.h>
#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"

typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	memcached_st *memc;
} memcached_con;

#endif /* CACHEDB_MEMCACHEDH */
