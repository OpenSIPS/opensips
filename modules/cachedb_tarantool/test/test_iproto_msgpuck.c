/*
 * OpenSIPS cachedb_tarantool - Unit Tests for MsgPack & IProto Encoder
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "../msgpuck.h"

static void test_msgpack_primitives(void) {
    char buf[256];
    char *w = buf;
    
    // 1. Encode Integer
    w = mp_encode_uint(w, 42);
    assert(w > buf);
    const char *r = buf;
    assert(mp_decode_uint(&r) == 42);
    printf("  [PASS] mp_encode_uint / mp_decode_uint\n");

    // 2. Encode String
    w = buf;
    const char *test_str = "tarantool_voip_test";
    w = mp_encode_str(w, test_str, strlen(test_str));
    r = buf;
    uint32_t len = 0;
    const char *dec_str = mp_decode_str(&r, &len);
    assert(len == strlen(test_str));
    assert(strncmp(dec_str, test_str, len) == 0);
    printf("  [PASS] mp_encode_str / mp_decode_str\n");

    // 3. Encode Map
    w = buf;
    w = mp_encode_map(w, 2);
    w = mp_encode_uint(w, 0x00); // IPROTO_REQUEST_TYPE
    w = mp_encode_uint(w, 0x06); // IPROTO_CALL
    w = mp_encode_uint(w, 0x01); // IPROTO_SYNC
    w = mp_encode_uint(w, 1001);
    
    r = buf;
    assert(mp_decode_map(&r) == 2);
    assert(mp_decode_uint(&r) == 0x00);
    assert(mp_decode_uint(&r) == 0x06);
    assert(mp_decode_uint(&r) == 0x01);
    assert(mp_decode_uint(&r) == 1001);
    printf("  [PASS] mp_encode_map (IProto Header Serialization)\n");
}

static void test_msgpack_array(void) {
    char buf[256];
    char *w = buf;

    w = mp_encode_array(w, 3);
    w = mp_encode_str(w, "arg1", 4);
    w = mp_encode_uint(w, 12345);
    w = mp_encode_str(w, "arg3", 4);

    const char *r = buf;
    assert(mp_decode_array(&r) == 3);
    uint32_t len = 0;
    const char *s1 = mp_decode_str(&r, &len);
    assert(strncmp(s1, "arg1", 4) == 0);
    assert(mp_decode_uint(&r) == 12345);
    const char *s3 = mp_decode_str(&r, &len);
    assert(strncmp(s3, "arg3", 4) == 0);
    printf("  [PASS] mp_encode_array (IProto Argument Tuple)\n");
}

int main(void) {
    printf("=========================================================\n");
    printf("  cachedb_tarantool Unit Test: MsgPack & IProto Encoder  \n");
    printf("=========================================================\n");
    test_msgpack_primitives();
    test_msgpack_array();
    printf("=========================================================\n");
    printf("  ALL MSGPACK & IPROTO TESTS PASSED (100%% OK)             \n");
    printf("=========================================================\n");
    return 0;
}
