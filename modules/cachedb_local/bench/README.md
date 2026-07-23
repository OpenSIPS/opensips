# cachedb_local benchmarks

Standalone reproductions of every figure in `../PERF-PLAN.md`. No OpenSIPS
build required — each program embeds `core_hash()` verbatim from
`hash_func.h` and models the module's data layout directly.

```bash
make && make run
```

Common workload across all five: **50 000 keys**, 16-byte hex keys shaped like
`th_store` thids, 200-byte values, and allocations deliberately interleaved
with junk allocations so entries are scattered the way `shm_malloc` leaves them
after a busy run. Measurements are of **successful** point lookups — the hot
path — not misses.

| program | question it answers |
|---|---|
| `hashtest` | Is `core_hash()` a bad hash? (chi², empty buckets, max chain vs FNV-1a) |
| `lookup` | What does load factor cost? (512 vs 65536 buckets) |
| `structs` | Chained vs sorted-array vs cache-line bucket vs flat open addressing |
| `worker` | Does moving the sort off the hot path pay? (eager vs deferred + merge cost) |
| `expire2` | Full sweep vs per-bucket min-expires hint vs timer wheel |

## Caveats

Single-threaded. They measure structure and cache behaviour, not lock
contention — real gains under 8 concurrent workers will differ, and false
sharing on the per-bucket locks (4 buckets share a cache line today) is
deliberately *not* modelled here. Treat the numbers as ranking the designs,
not as absolute throughput predictions.

`expire2.c` supersedes an earlier `expire.c` that was unsound: its
min-expires hint was reset to a value that defeated skipping, its wheel loop
was dead-code-eliminated because the counter was never printed, and its
expiry spread put ~50% of entries due per sweep rather than a realistic ~0.03%.
Do not resurrect it.
