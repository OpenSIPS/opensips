# cachedb_perf design benchmarks

Standalone reproductions of every figure in `../DESIGN.md`. No OpenSIPS build
required — each program embeds `core_hash()` verbatim from `hash_func.h` and
models the data layouts directly.

```bash
make && make run
```

Common workload: **50 000 keys**, 16-byte hex keys shaped like `th_store`
thids, 200-byte values, and allocations deliberately interleaved with junk
allocations so entries are scattered the way `shm_malloc` leaves them after a
busy run. Measurements are of **successful** point lookups — the hot path —
not misses.

| program | question it answers |
|---|---|
| `hashtest` | Is `core_hash()` a bad hash? (chi², empty buckets, max chain vs FNV-1a) |
| `lookup` | What does load factor cost? (512 vs 65536 buckets) |
| `structs` | Chained vs sorted-array vs cache-line bucket vs flat open addressing |
| `worker` | Does moving the sort off the hot path pay? (eager vs deferred + merge cost) |
| `expire2` | Full sweep vs per-bucket min-expires hint vs timer wheel |
| `concur` | Does the lock-on-every-read path limit scaling? (1/2/4/8 threads) |
| `wbuf` | Does a write-staging buffer help? (shared vs per-process, + read penalty) |
| `queue` | Does a queued producer/consumer write path help? (fixed thread budget) |
| `warmup` | What does first-touch page faulting cost, and does pre-warming help? |
| `hugetlb` | Do 2M huge pages help? Needs `sysctl -w vm.nr_hugepages=160` first |
| `hugetlb2` | Modern routes: `MADV_COLLAPSE`, THP-shmem, overcommit pool, 1GB pages. Takes a mode arg (`base`/`collapse`/`madvise`/`hugetlb`/`huge1g`) and verifies pages went huge via meminfo |
| `mlockt` | Can the arena be pinned against swap? mlock cost, fork inheritance, meminfo verification |
| `rpath` | Is the seqlock the fastest read protocol? seqlock vs versionless-bump hybrid vs QSBR pointer-publication, with seqlock retries/1k reads (DESIGN 2.7) |

## Caveats

These are **models, not the module**. They measure structure and cache
behaviour in a single process; they do not model shm allocation, multi-process
coherence, or OpenSIPS locking primitives. Treat the numbers as ranking
designs, not predicting throughput.

`concur.c` and `rpath.c` are the threaded ones, and both results went
*against* the hypothesis each was written to test. `concur.c` **refuted**
lock-on-every-read as a scaling killer: `cachedb_local` scales 8.4× on 8
threads, because with 65 536 buckets workers rarely collide on a bucket lock.
The proposed design's 3–4× is a per-operation constant factor — no atomic RMW
on reads, one cache line per bucket, tag filtering — not a scaling win. Do
not quote it as one. Note also that it gives `cachedb_local` its best case, a
perfectly sized table; against the shipped 512-bucket default the gap is
~90×. `rpath.c` showed dropping the seqlock for QSBR pointer-publication
reads is worth nothing at 100% reads — the version loads are free on x86/TSO
— and pays only under single-hot-bucket write contention SIP traffic does not
exhibit; only the versionless TTL bump survived into the design (CP-04).
Note `concur.c`'s writers only bump versions (no slot churn), and its
`tag | 1` mapping halves the tag alphabet — both fine for what it measures,
neither to be copied into the module.

`expire2.c` supersedes an earlier `expire.c` that was unsound: its
min-expires hint was reset to a value that defeated skipping, its wheel loop
was dead-code-eliminated because the counter was never printed, and its
expiry spread put ~50% of entries due per sweep rather than a realistic ~0.03%.
Do not resurrect it.
