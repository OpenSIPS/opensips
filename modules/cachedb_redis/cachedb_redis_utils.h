#ifndef CACHEDB_REDIS_UTILSH
#define CACHEDB_REDIS_UTILSH

#include "cachedb_redis_dbase.h"

int build_cluster_nodes(redis_con *con,char *info,int size);
inline cluster_node *get_redis_connection(redis_con *con,str *key);

#endif
