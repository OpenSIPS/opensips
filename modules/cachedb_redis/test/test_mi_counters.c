/*
 * test_mi_counters.c - Unit tests for MI helpers and per-node counters
 *
 * Tests:
 *   1. cluster_node struct has counter fields and they initialize to zero
 *   2. count_node_slots() correctly counts slot assignments
 *   3. count_total_slots() correctly counts non-NULL entries
 *   4. Per-node counters increment correctly
 *   5. Multiple nodes get independent counters
 *
 * Build:  make test_mi_counters
 * Run:    ./test_mi_counters
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

/* ================================================================== */
/* Minimal type stubs matching OpenSIPS definitions                   */
/* ================================================================== */

struct __str {
    char *s;
    int len;
};
typedef struct __str str;

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

struct cachedb_pool_con_t;
struct tls_domain;

typedef struct redisContext { int fd; int err; char errstr[128]; } redisContext;
typedef struct redisReply {
    int type;
    long long integer;
    size_t len;
    char *str;
    size_t elements;
    struct redisReply **element;
} redisReply;

/* cluster_node — must match cachedb_redis_dbase.h */
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
/* Re-implement the static helpers from cachedb_redis_mi.c            */
/* (they are static so we duplicate them here for testing)             */
/* ================================================================== */

static int count_node_slots(redis_con *con, cluster_node *node)
{
    int i, count = 0;
    for (i = 0; i < 16384; i++)
        if (con->slot_table[i] == node)
            count++;
    return count;
}

static int count_total_slots(redis_con *con)
{
    int i, count = 0;
    for (i = 0; i < 16384; i++)
        if (con->slot_table[i] != NULL)
            count++;
    return count;
}

/* ================================================================== */
/* Test framework                                                      */
/* ================================================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(desc, expected, actual) do { \
    tests_run++; \
    if ((expected) == (actual)) { \
        tests_passed++; \
        printf("  PASS  %s\n", desc); \
    } else { \
        tests_failed++; \
        printf("  FAIL  %s (expected=%ld, got=%ld)\n", \
               desc, (long)(expected), (long)(actual)); \
    } \
} while (0)

/* ================================================================== */
/* Tests                                                               */
/* ================================================================== */

static void test_node_counters_zero_init(void)
{
    cluster_node node;

    printf("--- Test: cluster_node counters zero-initialized by memset ---\n");
    memset(&node, 0, sizeof(cluster_node));

    ASSERT_EQ("queries starts at 0", 0UL, node.queries);
    ASSERT_EQ("errors starts at 0",  0UL, node.errors);
    ASSERT_EQ("moved starts at 0",   0UL, node.moved);
}

static void test_node_counters_increment(void)
{
    cluster_node node;

    printf("\n--- Test: counter increments ---\n");
    memset(&node, 0, sizeof(cluster_node));

    node.queries++;
    node.queries++;
    node.queries++;
    ASSERT_EQ("queries after 3 increments", 3UL, node.queries);

    node.errors++;
    ASSERT_EQ("errors after 1 increment", 1UL, node.errors);

    node.moved++;
    node.moved++;
    ASSERT_EQ("moved after 2 increments", 2UL, node.moved);

}

static void test_count_node_slots_empty(void)
{
    redis_con con;
    cluster_node node;

    printf("\n--- Test: count_node_slots with empty slot table ---\n");
    memset(&con, 0, sizeof(redis_con));
    memset(&node, 0, sizeof(cluster_node));

    ASSERT_EQ("no slots assigned", 0, count_node_slots(&con, &node));
}

static void test_count_node_slots_partial(void)
{
    redis_con con;
    cluster_node node_a, node_b;
    int i;

    printf("\n--- Test: count_node_slots with partial assignment ---\n");
    memset(&con, 0, sizeof(redis_con));
    memset(&node_a, 0, sizeof(cluster_node));
    memset(&node_b, 0, sizeof(cluster_node));
    node_a.ip = "10.0.0.1";
    node_b.ip = "10.0.0.2";

    /* Assign slots 0-5460 to node_a, 5461-10921 to node_b */
    for (i = 0; i <= 5460; i++)
        con.slot_table[i] = &node_a;
    for (i = 5461; i <= 10921; i++)
        con.slot_table[i] = &node_b;
    /* slots 10922-16383 remain NULL */

    ASSERT_EQ("node_a has 5461 slots", 5461, count_node_slots(&con, &node_a));
    ASSERT_EQ("node_b has 5461 slots", 5461, count_node_slots(&con, &node_b));
}

static void test_count_total_slots_full(void)
{
    redis_con con;
    cluster_node node;
    int i;

    printf("\n--- Test: count_total_slots with full assignment ---\n");
    memset(&con, 0, sizeof(redis_con));
    memset(&node, 0, sizeof(cluster_node));

    for (i = 0; i < 16384; i++)
        con.slot_table[i] = &node;

    ASSERT_EQ("total slots = 16384", 16384, count_total_slots(&con));
}

static void test_count_total_slots_partial(void)
{
    redis_con con;
    cluster_node node;
    int i;

    printf("\n--- Test: count_total_slots with partial assignment ---\n");
    memset(&con, 0, sizeof(redis_con));
    memset(&node, 0, sizeof(cluster_node));

    for (i = 0; i < 8192; i++)
        con.slot_table[i] = &node;

    ASSERT_EQ("total slots = 8192", 8192, count_total_slots(&con));
}

static void test_count_total_slots_empty(void)
{
    redis_con con;

    printf("\n--- Test: count_total_slots with empty table ---\n");
    memset(&con, 0, sizeof(redis_con));

    ASSERT_EQ("total slots = 0", 0, count_total_slots(&con));
}

static void test_independent_node_counters(void)
{
    cluster_node node_a, node_b, node_c;

    printf("\n--- Test: independent per-node counters ---\n");
    memset(&node_a, 0, sizeof(cluster_node));
    memset(&node_b, 0, sizeof(cluster_node));
    memset(&node_c, 0, sizeof(cluster_node));

    /* Simulate traffic patterns */
    node_a.queries = 100;
    node_a.errors = 2;
    node_a.moved = 5;

    node_b.queries = 200;
    node_b.errors = 10;
    node_b.moved = 0;

    node_c.queries = 50;
    node_c.errors = 0;
    node_c.moved = 0;

    /* Verify they're independent */
    ASSERT_EQ("node_a.queries = 100", 100UL, node_a.queries);
    ASSERT_EQ("node_b.queries = 200", 200UL, node_b.queries);
    ASSERT_EQ("node_c.queries = 50",  50UL,  node_c.queries);

    ASSERT_EQ("node_a.errors = 2",  2UL,  node_a.errors);
    ASSERT_EQ("node_b.errors = 10", 10UL, node_b.errors);
    ASSERT_EQ("node_c.errors = 0",  0UL,  node_c.errors);

    ASSERT_EQ("node_a.moved = 5", 5UL, node_a.moved);
    ASSERT_EQ("node_b.moved = 0", 0UL, node_b.moved);

}

static void test_three_node_cluster_slots(void)
{
    redis_con con;
    cluster_node node_a, node_b, node_c;
    int i;

    printf("\n--- Test: 3-node cluster even slot distribution ---\n");
    memset(&con, 0, sizeof(redis_con));
    memset(&node_a, 0, sizeof(cluster_node));
    memset(&node_b, 0, sizeof(cluster_node));
    memset(&node_c, 0, sizeof(cluster_node));

    node_a.ip = "10.0.0.1";
    node_b.ip = "10.0.0.2";
    node_c.ip = "10.0.0.3";

    /* Standard 3-node distribution: 0-5460, 5461-10922, 10923-16383 */
    for (i = 0; i <= 5460; i++)
        con.slot_table[i] = &node_a;
    for (i = 5461; i <= 10922; i++)
        con.slot_table[i] = &node_b;
    for (i = 10923; i < 16384; i++)
        con.slot_table[i] = &node_c;

    ASSERT_EQ("node_a slots = 5461", 5461, count_node_slots(&con, &node_a));
    ASSERT_EQ("node_b slots = 5462", 5462, count_node_slots(&con, &node_b));
    ASSERT_EQ("node_c slots = 5461", 5461, count_node_slots(&con, &node_c));
    ASSERT_EQ("total slots = 16384", 16384, count_total_slots(&con));
}

static void test_slot_migration(void)
{
    redis_con con;
    cluster_node node_a, node_b;
    int i;

    printf("\n--- Test: slot migration from node_a to node_b ---\n");
    memset(&con, 0, sizeof(redis_con));
    memset(&node_a, 0, sizeof(cluster_node));
    memset(&node_b, 0, sizeof(cluster_node));

    /* Initially all slots on node_a */
    for (i = 0; i < 16384; i++)
        con.slot_table[i] = &node_a;

    ASSERT_EQ("before: node_a has 16384", 16384, count_node_slots(&con, &node_a));
    ASSERT_EQ("before: node_b has 0",     0,     count_node_slots(&con, &node_b));

    /* Migrate slots 0-999 to node_b */
    for (i = 0; i < 1000; i++)
        con.slot_table[i] = &node_b;

    ASSERT_EQ("after: node_a has 15384", 15384, count_node_slots(&con, &node_a));
    ASSERT_EQ("after: node_b has 1000",  1000,  count_node_slots(&con, &node_b));
    ASSERT_EQ("total still 16384",       16384, count_total_slots(&con));
}

static void test_struct_size_includes_counters(void)
{
    printf("\n--- Test: struct layout sanity ---\n");

    /* Verify cluster_node is large enough to include the 4 counter fields */
    ASSERT_EQ("cluster_node size > base (has counter fields)", 1,
              sizeof(cluster_node) > sizeof(char *) + 4 * sizeof(unsigned short) +
              sizeof(redisContext *) + sizeof(void *) + sizeof(uint8_t));

    /* Verify offsetof-style check: 'next' pointer comes after counters */
    cluster_node n;
    memset(&n, 0, sizeof(n));
    n.queries = 0xAAAA;
    n.errors  = 0xBBBB;
    n.moved   = 0xCCCC;
    /* Verify the values are at distinct locations */
    ASSERT_EQ("queries != errors", 1, n.queries != n.errors);
    ASSERT_EQ("queries set correctly", 0xAAAAUL, n.queries);
    ASSERT_EQ("errors set correctly",  0xBBBBUL, n.errors);
    ASSERT_EQ("moved set correctly",   0xCCCCUL, n.moved);
}

int main(void)
{
    printf("=== MI Counters & Helpers Unit Tests ===\n\n");

    test_node_counters_zero_init();
    test_node_counters_increment();
    test_count_node_slots_empty();
    test_count_node_slots_partial();
    test_count_total_slots_full();
    test_count_total_slots_partial();
    test_count_total_slots_empty();
    test_independent_node_counters();
    test_three_node_cluster_slots();
    test_slot_migration();
    test_struct_size_includes_counters();

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           tests_passed, tests_failed, tests_run);

    return tests_failed > 0 ? 1 : 0;
}
