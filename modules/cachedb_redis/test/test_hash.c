/*
 * test_hash.c - Regression test for redisHash() from cachedb_redis_utils.c
 *
 * Links against the REAL crc16() and redisHash() compiled from
 * ../cachedb_redis_utils.c (via hash_under_test.c stub wrapper).
 *
 * Prerequisites:
 *   - C compiler (gcc or clang)
 *   - Build: make test_hash
 *   - Run:   ./test_hash
 *
 * Reference values: redis-cli CLUSTER KEYSLOT <key>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* OpenSIPS str type — must match struct __str from opensips/str.h */
struct __str {
    char *s;
    int len;
};
typedef struct __str str;

/* Declarations for the real functions from cachedb_redis_utils.c */
extern uint16_t crc16(const char *buf, int len);
extern unsigned int redisHash(str *key);

/* ================================================================== */
/* Test framework                                                      */
/* ================================================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static void test_slot(const char *key,
                      unsigned int expected, const char *desc)
{
    str k;
    k.s = (char *)key;
    k.len = strlen(key);

    unsigned int actual = redisHash(&k);
    tests_run++;

    if (actual == expected) {
        tests_passed++;
        printf("  PASS  %-45s  slot=%5u\n", desc ? desc : key, actual);
    } else {
        tests_failed++;
        printf("  FAIL  %-45s  expected=%5u  got=%5u\n",
               desc ? desc : key, expected, actual);
    }
}

/* Test with explicit length (for keys with embedded special chars) */
static void test_slot_len(const char *key, int len,
                          unsigned int expected, const char *desc)
{
    str k;
    k.s = (char *)key;
    k.len = len;

    unsigned int actual = redisHash(&k);
    tests_run++;

    if (actual == expected) {
        tests_passed++;
        printf("  PASS  %-45s  slot=%5u\n", desc, actual);
    } else {
        tests_failed++;
        printf("  FAIL  %-45s  expected=%5u  got=%5u\n",
               desc, expected, actual);
    }
}

int main(void)
{
    printf("=== redisHash() Regression Test ===\n");
    printf("Testing real redisHash() from cachedb_redis_utils.c\n");
    printf("Reference: redis-cli CLUSTER KEYSLOT <key>\n\n");

    /* ---------------------------------------------------------- */
    /* Basic keys (no hash tags)                                  */
    /* ---------------------------------------------------------- */
    printf("--- Basic keys (no hash tags) ---\n");
    test_slot("testkey",      4757,  "testkey");
    test_slot("foo",          12182, "foo");
    test_slot("user",         5474,  "user");
    test_slot("world",        9059,  "world");

    /* ---------------------------------------------------------- */
    /* Edge case: empty and single-char keys                      */
    /* ---------------------------------------------------------- */
    printf("\n--- Edge cases: short keys ---\n");
    test_slot("",             0,     "empty string");
    test_slot("a",            15495, "single char 'a'");
    test_slot("0",            13907, "single char '0'");

    /* ---------------------------------------------------------- */
    /* Edge case: keys with special characters                    */
    /* ---------------------------------------------------------- */
    printf("\n--- Edge cases: special characters ---\n");
    test_slot("key with spaces",     13638, "key with spaces");
    test_slot("key:with:colons",     12379, "key:with:colons");
    test_slot("key.with.dots",       16282, "key.with.dots");
    test_slot("key/with/slashes",    3738,  "key/with/slashes");
    test_slot("key\twith\ttabs",     7294,  "key with literal tabs");

    /* ---------------------------------------------------------- */
    /* Edge case: long keys                                       */
    /* ---------------------------------------------------------- */
    printf("\n--- Edge cases: long keys ---\n");
    {
        char longkey[1025];
        unsigned int expected;
        memset(longkey, 'x', 1024);
        longkey[1024] = '\0';
        expected = crc16(longkey, 1024) % 16384;
        test_slot(longkey, expected, "1024-byte key (all 'x')");
    }

    /* ---------------------------------------------------------- */
    /* Hash tag extraction                                        */
    /* ---------------------------------------------------------- */
    printf("\n--- Hash tag extraction ---\n");
    printf("--- {user}.name and {user}.email should map to slot 5474 ---\n");
    printf("--- hello{world} should map to slot 9059 (same as \"world\") ---\n");
    test_slot("{user}.name",  5474,  "{user}.name  -> should be 5474");
    test_slot("{user}.email", 5474,  "{user}.email -> should be 5474");
    test_slot("hello{world}", 9059,  "hello{world} -> should be 9059");
    test_slot("{}bar",        6479,  "{}bar (empty tag = full key)");
    test_slot("{foo}",        12182, "{foo} -> should be 12182");
    test_slot("a{foo}b",      12182, "a{foo}b -> should be 12182");
    test_slot("{}{foo}",      2263,  "{}{foo} (empty first tag = full key)");

    /* ---------------------------------------------------------- */
    /* Hash tag edge cases                                        */
    /* ---------------------------------------------------------- */
    printf("\n--- Hash tag edge cases ---\n");
    /* Nested braces: first { to first } after it → hashes "{foo" */
    test_slot("{{foo}}",      13308, "{{foo}} -> hashes '{foo'");
    /* Only opening brace, no closing */
    test_slot("{unclosed",    470,   "{unclosed (no close = full key)");
    /* Closing before opening */
    test_slot("}reversed{",   15992, "}reversed{ (close before open = full key)");
    /* Multiple hash tags: only first valid one counts → hashes "a" */
    test_slot("{a}{b}",       15495, "{a}{b} -> hashes 'a' (first tag)");
    /* Hash tag with just one char */
    test_slot("{x}.suffix",   16287, "{x}.suffix -> hashes 'x'");
    /* Hash tag at end */
    test_slot("prefix{tag}",  8338,  "prefix{tag} -> hashes 'tag'");
    /* Empty first tag, then content with dot */
    test_slot("{}.{real}",    8956,  "{}.{real} (empty first = full key)");
    /* Brace inside tag: {a{b}c → first { at 0, first } at 3 → hashes "a{b" */
    test_slot("{a{b}c",       13340, "{a{b}c -> hashes 'a{b'");

    /* ---------------------------------------------------------- */
    /* Co-location verification                                   */
    /* Keys with same hash tag must map to same slot              */
    /* ---------------------------------------------------------- */
    printf("\n--- Co-location verification ---\n");
    {
        str k1, k2;
        unsigned int s1, s2;

        /* {session}.data and {session}.meta should co-locate */
        k1.s = "{session}.data"; k1.len = strlen(k1.s);
        k2.s = "{session}.meta"; k2.len = strlen(k2.s);
        s1 = redisHash(&k1);
        s2 = redisHash(&k2);
        tests_run++;
        if (s1 == s2) {
            tests_passed++;
            printf("  PASS  {session}.data == {session}.meta       slot=%5u\n", s1);
        } else {
            tests_failed++;
            printf("  FAIL  {session}.data != {session}.meta       %u != %u\n", s1, s2);
        }

        /* {usrloc}.alice and {usrloc}.bob should co-locate */
        k1.s = "{usrloc}.alice"; k1.len = strlen(k1.s);
        k2.s = "{usrloc}.bob";   k2.len = strlen(k2.s);
        s1 = redisHash(&k1);
        s2 = redisHash(&k2);
        tests_run++;
        if (s1 == s2) {
            tests_passed++;
            printf("  PASS  {usrloc}.alice == {usrloc}.bob         slot=%5u\n", s1);
        } else {
            tests_failed++;
            printf("  FAIL  {usrloc}.alice != {usrloc}.bob         %u != %u\n", s1, s2);
        }

        /* Different tags must (almost certainly) NOT co-locate */
        k1.s = "{alpha}.key"; k1.len = strlen(k1.s);
        k2.s = "{beta}.key";  k2.len = strlen(k2.s);
        s1 = redisHash(&k1);
        s2 = redisHash(&k2);
        tests_run++;
        if (s1 != s2) {
            tests_passed++;
            printf("  PASS  {alpha}.key != {beta}.key              %u != %u\n", s1, s2);
        } else {
            tests_failed++;
            printf("  FAIL  {alpha}.key == {beta}.key (collision)  slot=%u\n", s1);
        }
    }

    /* ---------------------------------------------------------- */
    /* Slot range validation                                      */
    /* All slots must be in [0, 16383]                            */
    /* ---------------------------------------------------------- */
    printf("\n--- Slot range validation ---\n");
    {
        int range_pass = 1;
        int i;
        char buf[32];
        for (i = 0; i < 10000; i++) {
            snprintf(buf, sizeof(buf), "key:%d", i);
            str k;
            k.s = buf;
            k.len = strlen(buf);
            unsigned int slot = redisHash(&k);
            if (slot > 16383) {
                printf("  FAIL  key:%d produced slot %u (> 16383)\n", i, slot);
                range_pass = 0;
                tests_failed++;
                tests_run++;
                break;
            }
        }
        if (range_pass) {
            tests_run++;
            tests_passed++;
            printf("  PASS  10000 keys all in [0, 16383]\n");
        }
    }

    /* ---------------------------------------------------------- */
    /* CRC16 direct verification against known values             */
    /* ---------------------------------------------------------- */
    printf("\n--- CRC16 direct verification ---\n");
    {
        uint16_t crc;
        unsigned int slot;

        crc = crc16("test", 4);
        slot = crc % 16384;
        tests_run++;
        if (slot == 6918) {
            tests_passed++;
            printf("  PASS  crc16(\"test\") %% 16384 = %u\n", slot);
        } else {
            tests_failed++;
            printf("  FAIL  crc16(\"test\") %% 16384 = %u (expected 6918)\n", slot);
        }

        /* Verify CRC16 of empty string is 0 */
        crc = crc16("", 0);
        tests_run++;
        if (crc == 0) {
            tests_passed++;
            printf("  PASS  crc16(\"\", 0) = 0\n");
        } else {
            tests_failed++;
            printf("  FAIL  crc16(\"\", 0) = %u (expected 0)\n", crc);
        }
    }

    /* ---------------------------------------------------------- */
    /* Partial cluster regression (slots_assigned=10922)           */
    /* After fix: results are identical to full cluster — modulo   */
    /* is constant (% 16384), not dependent on slots_assigned.    */
    /* Retained for regression coverage.                          */
    /* ---------------------------------------------------------- */
    printf("\n--- Partial cluster (slots_assigned=10922) ---\n");
    printf("--- After fix: results are identical to full cluster (modulo is constant) ---\n");
    test_slot("testkey",      4757,  "testkey  (partial cluster)");
    test_slot("foo",          12182, "foo      (partial cluster)");
    test_slot("user",         5474,  "user     (partial cluster)");

    printf("\n=== Results: %d passed, %d failed, %d total ===\n",
           tests_passed, tests_failed, tests_run);

    return tests_failed > 0 ? 1 : 0;
}
