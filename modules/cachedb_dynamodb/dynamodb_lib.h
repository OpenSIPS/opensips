#ifndef DYNAMODB_LIB
#define DYNAMODB_LIB
#include <stdbool.h>
#include "../../cachedb/cachedb_id.h"
#include "../../cachedb/cachedb_pool.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {      
    void *options;
    void *clientConfig;   
} dynamodb_config;

typedef struct dynamodb_con {
    cachedb_pool_con cache_con;

	char *host;            // Note: the .id may contain multi-hosts, so the
	unsigned short port;   // host/port of this connection are extracted here
    char *endpoint;
    char *region;
    char *key;
    char *value;
    char *tableName;
    dynamodb_config config;
} dynamodb_con;


dynamodb_config init_dynamodb(dynamodb_con *con);
void shutdown_dynamodb(dynamodb_config *config);
bool create_table(dynamodb_config *config, const char *tableName, const char *partitionKey);
bool put_item(dynamodb_config *config, const char *tableName, const char *partitionKey,
                const char *partitionValue, const char *founder, int employeeCount, int yearFounded,
                int qualityRanking);
int insert_item(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue,
                  const char *attributeName, const char* attributeValue);
//db_res_t *scan_table(dynamodb_config *config, const char *tableName);
bool delete_item(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue);
char *query_item(dynamodb_config *config, const char *tableName, const char *partitionKey,
                 const char *partitionValue, const char *attributeKey);
char *query_items(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue);

#ifdef __cplusplus
}
#endif

#endif // DYNAMODB_LIB
