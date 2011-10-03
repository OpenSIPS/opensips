#ifndef CACHEDBREDIS_DBASE_H
#define CACHEDBREDIS_DBASE_H

#include <hiredis/hiredis.h>
#include "../../cachedb/cachedb.h"

typedef struct cluster_nodes {
	char ip[16];					/* ip of this cluster node */
	short port;						/* port of this cluster node */
	unsigned short start_slot;		/* first slot for this server */
	unsigned short end_slot;		/* last slot for this server */

	redisContext *context;			/* actual connection to this node */
	struct cluster_nodes *next;
} cluster_node;

#define REDIS_SINGLE_INSTANCE	(1<<0)
#define REDIS_CLUSTER_INSTANCE	(1<<1)
typedef struct {
	struct cachedb_id *id;
	unsigned int ref;
	struct cachedb_pool_con_t *next;

	int type; /* single node or cluster node */
	cluster_node *nodes; /* one or more Redis nodes */
} redis_con;

cachedb_con* redis_init(str *url);
void redis_destroy(cachedb_con *con);
int redis_get(cachedb_con *con,str *attr,str *val);
int redis_set(cachedb_con *con,str *attr,str *val,int expires);
int redis_remove(cachedb_con *con,str *attr);
int redis_add(cachedb_con *con,str *attr,int val);
int redis_sub(cachedb_con *con,str *attr,int val);

#endif /* CACHEDBREDIS_DBASE_H */

