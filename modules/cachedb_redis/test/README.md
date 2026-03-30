# cachedb_redis Test Suite

Tests for the OpenSIPS `cachedb_redis` module's Redis Cluster support,
organized by PR.

## Directory Contents

| File | Type | PR | Description |
|------|------|----|-------------|
| `Makefile` | Build | All | Builds C unit tests. Targets: `make`, `make test`, `make clean` |
| `hash_under_test.c` | Stub wrapper | PR 1 | Compiles the **real** `crc16()` and `redisHash()` from `../cachedb_redis_utils.c` by blocking OpenSIPS headers and providing minimal type stubs. |
| `test_hash.c` | Unit test | PR 1 | Tests the real `redisHash()` against `redis-cli CLUSTER KEYSLOT` reference values. Links against `hash_under_test.o`. **Fails before PR 1** (demonstrating both bugs), **passes after**. |
| `test_topology_refresh.sh` | Integration test | PR 3 | Verifies OpenSIPS adapts to topology changes (slot migrations, CLUSTER SHARDS/SLOTS probing). Migrates a slot, confirms OpenSIPS follows MOVED redirects, then restores. |
| `README.md` | Documentation | — | This file. |

## How the Unit Test Links Against Real Code

The test does **not** copy the hash function. Instead:

1. `hash_under_test.c` pre-defines OpenSIPS include guards (`dprint_h`,
   `_CACHEDB_H`, `mem_h`, etc.) and provides minimal type stubs (`str`,
   `redis_con`, logging no-ops, `pkg_malloc` mapped to `malloc`).
2. It then `#include`s the real `../cachedb_redis_utils.c`, compiling the
   actual `crc16()` and `redisHash()` into `hash_under_test.o`.
3. `test_hash.c` declares `extern` references to those functions and links
   against `hash_under_test.o`.

When `cachedb_redis_utils.c` is modified (by PR 1), rebuilding the test
automatically picks up the changes — no manual sync required.

## Requirements

### PR 1: Unit Test (`test_hash`)

| Requirement | Notes |
|-------------|-------|
| C compiler (gcc or clang) | Any version supporting C99 |

No external libraries are needed. Build and run:

```bash
make test_hash
./test_hash
# or: make test  (builds and runs all unit tests)
```

**Expected results before PR 1:**

- Basic key tests (no hash tags, full cluster): PASS
- Hash tag tests (`{user}.name`, `{user}.email`): **FAIL** — bug 2, no extraction
- Partial cluster tests (`slots_assigned != 16383`): **FAIL** — bug 1, bitmask vs modulo

**Expected results after PR 1:**

- All tests: PASS (just run `make clean && make test` — no code changes needed in the test)

### PR 2 & PR 3: Integration Tests

| Requirement | Notes |
|-------------|-------|
| `redis-cli` | From the `redis-tools` package (Debian/Ubuntu) or `redis` package (RHEL/Fedora) |
| `curl` | For OpenSIPS MI HTTP interface |
| 3-node Redis Cluster | Default: `10.0.0.23`, `10.0.0.24`, `10.0.0.25` on port `6379` |
| Running OpenSIPS | With `mi_http` module loaded, listening on port `8888` |
| `cachedb_redis` module | Loaded in cluster mode, connected to the above cluster |

Both scripts accept environment variables to override defaults:

```bash
export REDIS_PASS="your_password"
export REDIS_NODE_1="10.0.0.23"
export REDIS_NODE_2="10.0.0.24"
export REDIS_NODE_3="10.0.0.25"
export REDIS_PORT="6379"
export MI_URL="http://127.0.0.1:8888/mi"
```

Run:

```bash
./test_topology_refresh.sh
```

If OpenSIPS MI is not reachable, the integration tests will skip
OpenSIPS-specific assertions and only test direct Redis cluster operations.

## Test Environment Warning

The integration tests perform **live slot migrations** on the Redis Cluster.
They restore the original configuration afterward, but should only be run
in a **test or staging environment**, never in production.

## Adding New Tests

- **Unit tests** (C): Add the source file and a build target in the `Makefile`.
  Append the binary name to the `UNIT_TESTS` variable so `make test` picks it up.
- **Integration tests** (shell): Follow the existing pattern — preflight checks,
  assert helpers, cleanup, and environment variable overrides. Name the file
  `test_<description>.sh` and make it executable.
