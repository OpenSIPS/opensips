/*
 * OpenSIPS cachedb_tarantool - Unit Tests for Connection URL Parser
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../cachedb_tarantool_dbase.h"

static void test_url_parsing_full(void) {
    const char *url_str = "tarantool:cluster1://admin:secret@192.168.1.100:3301/my_space";
    str url = { .s = (char *)url_str, .len = (int)strlen(url_str) };

    tarantool_init_without_tnt = 1;
    cachedb_con *con = tarantool_init(&url);
    assert(con != NULL);

    tnt_cluster_con_t *tcon = (tnt_cluster_con_t *)con;
    assert(strncmp(tcon->name.s, "cluster1", tcon->name.len) == 0);
    assert(strncmp(tcon->user.s, "admin", tcon->user.len) == 0);
    assert(strncmp(tcon->pass.s, "secret", tcon->pass.len) == 0);
    assert(strncmp(tcon->host.s, "192.168.1.100", tcon->host.len) == 0);
    assert(tcon->port == 3301);
    assert(strncmp(tcon->space.s, "my_space", tcon->space.len) == 0);

    tarantool_destroy(con);
    printf("  [PASS] Full URL with credentials & space\n");
}

static void test_url_parsing_simple(void) {
    const char *url_str = "tarantool://127.0.0.1:3301/rtpe_calls";
    str url = { .s = (char *)url_str, .len = (int)strlen(url_str) };

    tarantool_init_without_tnt = 1;
    cachedb_con *con = tarantool_init(&url);
    assert(con != NULL);

    tnt_cluster_con_t *tcon = (tnt_cluster_con_t *)con;
    assert(strncmp(tcon->host.s, "127.0.0.1", tcon->host.len) == 0);
    assert(tcon->port == 3301);
    assert(strncmp(tcon->space.s, "rtpe_calls", tcon->space.len) == 0);

    tarantool_destroy(con);
    printf("  [PASS] Simple URL (no auth, default port)\n");
}

int main(void) {
    printf("=========================================================\n");
    printf("  cachedb_tarantool Unit Test: Connection URL Parser     \n");
    printf("=========================================================\n");
    test_url_parsing_full();
    test_url_parsing_simple();
    printf("=========================================================\n");
    printf("  ALL URL PARSER TESTS PASSED (100%% OK)                  \n");
    printf("=========================================================\n");
    return 0;
}
