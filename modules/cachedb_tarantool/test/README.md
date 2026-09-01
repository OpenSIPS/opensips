# cachedb_tarantool Test Suite

Self-contained unit and integration test suite for the OpenSIPS `cachedb_tarantool` module.

## Directory Contents

| File | Type | Description |
|------|------|-------------|
| `Makefile` | Build | Builds C unit tests. Targets: `make`, `make test`, `make clean` |
| `test_iproto_msgpuck.c` | Unit test | Validates MessagePack primitive, array, and map encoding/decoding for IProto requests. |
| `test_url_parser.c` | Unit test | Validates URL parsing (`cachedb_url`), credential extraction, host/port parsing, and connection pooling options. |
| `run_tests.sh` | Shell script | Automated test runner. |
| `README.md` | Documentation | This file. |

## Running the Unit Tests

```bash
make test
```

### Expected Output:

```text
=========================================================
  cachedb_tarantool Unit Test: MsgPack & IProto Encoder  
=========================================================
  [PASS] mp_encode_uint / mp_decode_uint
  [PASS] mp_encode_str / mp_decode_str
  [PASS] mp_encode_map (IProto Header Serialization)
  [PASS] mp_encode_array (IProto Argument Tuple)
=========================================================
  ALL MSGPACK & IPROTO TESTS PASSED (100% OK)             
=========================================================

=========================================================
  cachedb_tarantool Unit Test: Connection URL Parser     
=========================================================
  [PASS] Full URL with credentials & space
  [PASS] Simple URL (no auth, default port)
=========================================================
  ALL URL PARSER TESTS PASSED (100% OK)                  
=========================================================
```
