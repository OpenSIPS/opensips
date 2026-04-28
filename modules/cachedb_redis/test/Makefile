# Makefile for cachedb_redis test suite
#
# Usage:
#   make              - build all unit tests
#   make test         - build and run all unit tests
#   make clean        - remove built binaries and object files
#
# Requirements:
#   - GCC or compatible C compiler
#   - No external libraries required (tests are self-contained)

CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wno-unused-function -Wno-unused-variable -O2

UNIT_TESTS = test_hash test_mi_counters

# Path to the real source (relative to this test directory)
UTILS_SRC = ../cachedb_redis_utils.c

.PHONY: all test clean

all: $(UNIT_TESTS)

test: $(UNIT_TESTS)
	@echo "=== Running unit tests ==="
	@failed=0; \
	for t in $(UNIT_TESTS); do \
		echo "--- $$t ---"; \
		./$$t; \
		if [ $$? -ne 0 ]; then failed=$$((failed + 1)); fi; \
	done; \
	echo "=== Done ($$failed failure(s)) ==="; \
	exit $$failed

# hash_under_test.c #includes the real ../cachedb_redis_utils.c with
# OpenSIPS headers blocked and minimal type stubs provided.
# This compiles the actual crc16() and redisHash() functions.
hash_under_test.o: hash_under_test.c $(UTILS_SRC)
	$(CC) $(CFLAGS) -c -o $@ hash_under_test.c

# test_hash.c contains the test cases; links against real redisHash().
test_hash: test_hash.c hash_under_test.o
	$(CC) $(CFLAGS) -o $@ test_hash.c hash_under_test.o

# test_mi_counters.c is self-contained (no external dependencies)
test_mi_counters: test_mi_counters.c
	$(CC) $(CFLAGS) -o $@ test_mi_counters.c

clean:
	rm -f $(UNIT_TESTS) *.o
