/*
 * hash_under_test.c - Compilation wrapper for cachedb_redis_utils.c
 *
 * Pre-defines include guards and provides minimal type stubs, then
 * #includes the real cachedb_redis_utils.c. This compiles the actual
 * crc16() and redisHash() functions without the full OpenSIPS build tree.
 *
 * Functions that depend on OpenSIPS internals (build_cluster_nodes, etc.)
 * compile with stub types/macros but should never be called from tests.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================== */
/* Block ALL external headers by pre-defining their include guards    */
/* ================================================================== */
#define dprint_h              /* ../../dprint.h */
#define ut_h                  /* ../../ut.h */
#define _CACHEDB_H            /* ../../cachedb/cachedb.h */
#define mem_h                 /* ../../mem/mem.h */
#define TLS_API_H             /* ../tls_mgm/api.h */
#define str_h                 /* ../../str.h */
#define __HIREDIS_H           /* <hiredis/hiredis.h> */
#define CACHEDBREDIS_DBASE_H  /* cachedb_redis_dbase.h */
#define CACHEDB_REDIS_UTILSH  /* cachedb_redis_utils.h (self-include) */
#define statistics_h          /* ../../statistics.h */

/* ================================================================== */
/* Minimal type stubs matching OpenSIPS definitions                   */
/* ================================================================== */

/* str type — matches struct __str from opensips/str.h */
struct __str {
    char *s;
    int len;
};
typedef struct __str str;

/* cachedb_id — matches cachedb/cachedb_id.h (fields accessed by build_cluster_nodes) */
struct cachedb_id {
    char *scheme;
    char *group_name;
    char *username;
    char *password;
    char *host;
    unsigned short port;
    char *database;
    char *extra_options;
    char *initial_url;
    int flags;
};

/* Forward declarations for pointer-only types */
struct cachedb_pool_con_t;
struct tls_domain;
struct tls_mgm_binds { void (*release_domain)(struct tls_domain *); };

/* hiredis types — used as pointers in cluster_node */
typedef struct redisContext { int fd; } redisContext;
typedef struct redisReply {
    int type;
    long long integer;
    size_t len;
    char *str;
    size_t elements;
    struct redisReply **element;
} redisReply;

/* hiredis constants */
#define REDIS_REPLY_STRING 1
#define REDIS_REPLY_ARRAY 2
#define REDIS_REPLY_INTEGER 3
#define REDIS_REPLY_NIL 4
#define REDIS_REPLY_STATUS 5
#define REDIS_REPLY_ERROR 6

/* hiredis function stubs */
static inline void redisFree(redisContext *c) { (void)c; }
static inline void freeReplyObject(void *r) { (void)r; }
static inline void *redisCommand(redisContext *c, const char *fmt, ...) {
    (void)c; (void)fmt; return NULL;
}

/* cluster_node — matches cachedb_redis_dbase.h */
typedef struct cluster_nodes {
    char *ip;
    unsigned short port;
    unsigned short start_slot;
    unsigned short end_slot;
    redisContext *context;
    struct tls_domain *tls_dom;
    uint8_t seen;
    /* per-node, per-process counters (pkg memory) */
    unsigned long queries;
    unsigned long errors;
    unsigned long moved;
    struct cluster_nodes *next;
} cluster_node;

typedef struct {
    const char *s;
    int len;
} const_str;

typedef struct {
    int slot;
    const_str endpoint;
    int port;
} redis_moved;

enum redis_flag {
    REDIS_SINGLE_INSTANCE  = 1 << 0,
    REDIS_CLUSTER_INSTANCE = 1 << 1,
    REDIS_INIT_NODES       = 1 << 2,
    REDIS_JSON_SUPPORT     = 1 << 3,
    REDIS_MULTIPLE_HOSTS   = 1 << 4,
};

enum cluster_cmd {
    CLUSTER_CMD_NONE,
    CLUSTER_CMD_SHARDS,
    CLUSTER_CMD_SLOTS
};

/* redis_con — matches cachedb_redis_dbase.h */
typedef struct _redis_con {
    struct cachedb_id *id;
    unsigned int ref;
    struct cachedb_pool_con_t *next;
    char *host;
    unsigned short port;
    enum redis_flag flags;
    cluster_node *nodes;
    char *json_keyspace;
    cluster_node *slot_table[16384];
    enum cluster_cmd cluster_cmd;
    time_t last_topology_refresh;
    unsigned int topology_refresh_count;
    struct _redis_con *next_con;
    struct _redis_con *current;
} redis_con;

/* ================================================================== */
/* Stub macros/globals for code in utils.c we don't test              */
/* ================================================================== */

/* Logging — no-op */
#define LM_DBG(...)
#define LM_ERR(...)
#define LM_WARN(...)
#define LM_INFO(...)

/* Memory — map to standard malloc/free */
#define pkg_malloc  malloc
#define pkg_free    free

/* str_match — compare two str values */
static inline int str_match(const str *a, const str *b) {
    return a->len == b->len && memcmp(a->s, b->s, a->len) == 0;
}

/* pkg_nt_str_dup — null-terminated str dup */
static inline int pkg_nt_str_dup(str *dst, const str *src) {
    dst->s = (char *)malloc(src->len + 1);
    if (!dst->s) return -1;
    memcpy(dst->s, src->s, src->len);
    dst->s[src->len] = '\0';
    dst->len = src->len;
    return 0;
}

/* redis_connect_node stub */
static inline int redis_connect_node(void *con, cluster_node *node) {
    (void)con; (void)node; return 0;
}

/* Globals referenced by destroy_cluster_nodes */
static int use_tls = 0;
static struct tls_mgm_binds tls_api;

/* stat_var stubs — referenced by utils.c via update_stat() */
typedef void stat_var;
#define update_stat(_var, _n)
static stat_var *redis_stat_topology_refreshes = NULL;

/* Constants from cachedb_redis_utils.h */
#define REDIS_DF_PORT 6379
#define MOVED_PREFIX "MOVED "
#define MOVED_PREFIX_LEN (sizeof(MOVED_PREFIX) - 1)
#define ERR_INVALID_REPLY -1
#define ERR_INVALID_SLOT  -2
#define ERR_INVALID_PORT  -3

/* match_prefix from cachedb_redis_utils.h */
static inline int match_prefix(const char *buf, size_t len,
                               const char *prefix, size_t prefix_len) {
    size_t i;
    if (len < prefix_len) return 0;
    for (i = 0; i < prefix_len; ++i) {
        if (buf[i] != prefix[i]) return 0;
    }
    return 1;
}

/* ================================================================== */
/* Include the REAL source — compiles actual crc16() and redisHash()  */
/* ================================================================== */
#include "../cachedb_redis_utils.c"
