# cachedb_perf — design

A new `cachedb` backend written from scratch for large, high-churn local
caches. Not a fork of `cachedb_local`: it shares that module's **public
interface** (the `cachedb_funcs` vtable) so it is a drop-in replacement chosen
by URL scheme, but none of its internals.

- Module: `cachedb_perf`
- Scheme: `perf://`
- Branch: `feature/cachedb-local-perf-devel` on `10.22.20.223:/dn/opensips-devel`

`cachedb_local` is left **completely untouched** by this branch.

```opensips
loadmodule "cachedb_perf.so"
modparam("topology_hiding", "th_state_url", "perf://th")
```

> `DESIGN.md` and `bench/` are working documents. `git rm` both before
> proposing anything upstream.

---

## 1. Why a new module

`cachedb_local` is a fixed-size chained hash table whose size is set once from
`cache_collections` and never changes. The default is `HASH_SIZE_DEFAULT 9` →
**512 buckets**, and most deployments never set the parameter.

Found while benchmarking `topology_hiding`'s `th_store` backend for PR #4114:
`cache_collections "th=16"` cut LB CPU from **45% to 29%** at 4 000 CPS. At 50 000
entries the default is a load factor of 97.7 — roughly 50 string compares and 50
dependent cache misses per lookup.

That is fixable in place, and §2 measures exactly how far in-place fixes get.
But the ceiling of the existing layout is low enough — and the changes deep
enough (entry struct, bucket representation, allocator, lock strategy all
change) — that a clean module is less risky than progressively rewriting a
module that every existing deployment depends on. A separate module also means
no migration: operators opt in per collection by changing a URL.

## 2. Measured evidence

From `bench/` (see §7 for reproduction). 50 000 keys, 16-byte hex keys shaped
like `th_store` thids, 200-byte values, allocations scattered to mimic shm
fragmentation.

### 2.1 The hash function is not at fault

`core_hash()` is an additive `h += v ^ (v>>3)` over 4-byte words, which looks
weak but measures clean on thids, dialog ids, usrloc AoRs and call-ids:
chi²/df **0.65–1.18** vs **0.91–1.07** for FNV-1a + a murmur finalizer.
Statistically indistinguishable. **`cachedb_perf` keeps `core_hash()`.**

### 2.2 Single-threaded structure comparison

| design | @512 buckets | @65536 buckets |
|---|---|---|
| chained + `strncmp` (cachedb_local today) | 2484 ns | 111 ns |
| chained + hash cached in node | 1837 ns | 86 ns |
| sorted array per bucket + binary search | 134 ns | 100 ns |
| 64B cache-line bucket, inline slots | 84 ns | |
| flat open addressing, linear probe | 78 ns | |

Load factor alone is a **20× spread**. Note the sorted-array result: at the
pathological 512-bucket default it lands within 21% of a correctly-sized
chained table, i.e. an ordered container *inside* the bucket makes table size
nearly irrelevant. That remains the cheapest possible fix **to
`cachedb_local`** if anyone wants one.

### 2.3 Concurrency — hypothesis refuted, result stands

`cachedb_local` takes a **write lock on every read** (`lcache_htable_fetch`
does `lock_get` before walking). The expectation was that this ping-pongs
bucket cache lines between workers and destroys scaling. **It does not:**

| threads | current (Mops/s) | proposed (Mops/s) | ratio |
|---|---|---|---|
| 1 | 8.57 | 35.74 | 4.17× |
| 2 | 18.83 | 69.35 | 3.68× |
| 4 | 36.13 | 135.66 | 3.76× |
| 8 | 71.96 | 288.95 | 4.02× |
| **scaling 1→8** | **8.40×** | 8.09× | |

Both scale linearly. With 65 536 buckets and 50 000 keys two workers almost
never collide on the same bucket lock, so the lock is uncontended.

The 3–4× is therefore a **per-operation constant factor**, not a scalability
fix. It comes from three things: no atomic read-modify-write on the read path,
one cache line touched per bucket, and 1-byte tags that reject non-matching
slots without dereferencing a pointer. State it that way — do not claim a
scaling win.

Two caveats worth keeping honest: this gave `cachedb_local` its **best case**
(a perfectly sized table); against the shipped 512-bucket default the gap is
~90×. And it is threads, not processes — cache coherence behaves identically,
but OpenSIPS workers are processes sharing shm.

### 2.4 Expiry is not a CPU problem

50 000 entries, 65 536 buckets, TTLs over 3 600 ticks, ~13 due per sweep:

| strategy | per sweep | locks/sweep |
|---|---|---|
| full sweep, lock every bucket | 1.3075 ms | 65 536 |
| per-bucket `min_expires`, unlocked skip | 0.0439 ms | **13** |
| timer wheel, O(expired) | 0.0005 ms | — |

Even the full sweep is 0.131% of one core at a 1-second interval. The real
defect is *reclamation latency*, not CPU: an entry that expires and is never
fetched again squats in shm for up to `cache_clean_period` (default 600 s).
The `min_expires` hint gets that for **zero hot-path cost and zero extra
per-entry memory**; the wheel's further 84× buys nothing and costs
74 ns/insert plus 16 B/entry.

## 3. Design

Two designs from the literature converge on the same shape for precisely this
workload (a memcached-style KV cache with variable-length keys):

- **CLHT** — cache-line-sized buckets, so an operation completes with at most
  one cache-line transfer.
- **MemC3** (NSDI'13) — 1-byte tags plus optimistic version counters; reports
  30% less memory and up to 3× QPS over memcached.

### 3.1 Bucket

Exactly one cache line, verified `sizeof == 64`:

```c
struct pcache_bucket {          /* __attribute__((aligned(64))) */
    volatile unsigned version;  /* seqlock: even = stable, odd = writer inside */
    volatile unsigned lock;     /* writers only */
    unsigned char     tags[6];  /* 1 byte of hash per slot, never 0 */
    unsigned char     used;
    unsigned char     _pad;
    pcache_rec       *slot[6];
};
```

Lookup: mask to a bucket, compare 6 one-byte tags, and only dereference a slot
whose tag matches. A tag rejects ~255/256 of non-matching slots without
touching a second cache line — which is the whole point, since the pointer
chase is the expensive part.

### 3.2 Optimistic reads, and why they are safe here

Readers take **no lock**:

```
do {
    v1 = load_acquire(version);
    if (v1 & 1) continue;              /* writer inside, retry */
    ... scan tags, deref match, COPY the value out ...
    fence_acquire();
    v2 = load_relaxed(version);
} while (v1 != v2 || (v1 & 1));
```

Writers take the bucket lock, bump `version` to odd, mutate, bump to even.

The usual blocker is that a reader may dereference a pointer a writer is
concurrently freeing — `libcuckoo` takes read locks specifically for this, at a
documented 5–20% cost. **OpenSIPS removes the blocker**: shm is mapped once
before fork and never unmapped, so a stale pointer read is *garbage but not a
fault*, and the version re-check discards the result. The value must be
**copied out inside the optimistic section and only trusted after the version
check** — never return a pointer into the table.

This is exactly why the slab arena (§3.3) is not optional: entries must never
leave the arena, or the guarantee breaks.

### 3.3 Slab arena

Large chunks taken from shm once, entries sub-allocated in size classes inside
them. Three reasons:

1. It is what makes §3.2 sound — memory is never returned to the shm allocator,
   so addresses stay readable.
2. It bounds fragmentation. `cachedb_local`'s insert path mallocs a new entry
   and frees the old one on **every overwrite**, even when the value is the
   same size — the `th_store` TTL-bump pattern exactly. `cachedb_perf` updates
   in place when the value fits.
3. It is the precondition for any compaction. You cannot compact `shm_malloc`
   directly — no placement control.

Optional later: address entries by 32-bit arena offset instead of 8-byte
pointer, which raises slots-per-bucket from 6 to ~11 at the same 64 bytes.

### 3.4 Growth

Segmented directory (a directory of fixed 4096-bucket segments) plus linear
hashing. Growth appends a segment, so **existing buckets never move** — no
pointer invalidation and no RCU/epoch problem across processes. Splits happen
one bucket at a time under that bucket's lock. Publish `(level, split)` as a
single 64-bit word only *after* a split completes, so a racing reader sees
either pre- or post-split state; both are correct.

### 3.5 Expiry

Per-bucket `min_expires` (§2.4), swept frequently. Expired entries are also
treated as absent on read, as in `cachedb_local`, so expiry timing is memory
reclamation only and never correctness.

### 3.6 Deliberately deferred

**Cuckoo displacement.** It mainly buys load factor / memory efficiency, and it
badly complicates concurrent resize across processes. Overflow chaining in v1;
measure occupancy; revisit only if memory becomes the constraint.

## 4. Ruled out — do not re-litigate

- **B-tree / skip list as the primary index.** Exact-match KV store; a hash is
  the better structure. Point lookup would become ~3 dependent cache misses.
  An ordered structure is right in exactly one place — a secondary index for
  glob/prefix operations (CP-12).
- **Replacing `core_hash()`** — measured clean (§2.1).
- **Flat open addressing**, despite being fastest single-threaded (78 ns):
  resize is stop-the-world, every slot moves, impossible to do cheaply across
  processes in shm.
- **ART / radix trie** — 16-byte keys still cost 3–5 hops, no better than a
  hash, and concurrent ART in shm is a serious undertaking.
- **Per-key expiry timers or per-key expiry events** — optimise 0.13% of a core
  while adding a second index whose reverse lock-acquisition order in the
  reaper is a genuine deadlock hazard.
- **EVI as the expiry *mechanism*** — the core has no one-shot timer
  (`register_timer`/`register_utimer` are periodic only, `timer.h:92`) and EVI
  is a synchronous publish bus, so it cannot schedule anything. EVI as
  *notification* is a separate legitimate feature (CP-11).

## 5. Compatibility

`cachedb_perf` implements the same `cachedb_funcs` vtable as every other
backend, so any module taking a `cachedb_url` works unchanged:
`get`, `set` (with `expires`), `remove`, `add`, `sub`, `get_counter`,
`iter_keys`, plus `cache_remove_chunk` / `fetch_chunk`.

Internal function names deliberately mirror `cachedb_local`'s
(`lcache_htable_insert` → `pcache_htable_insert` and so on) so the two are
diffable. This is safe: OpenSIPS loads modules with **`RTLD_NOW`, not
`RTLD_GLOBAL`** (`sr_module.h:98`), so identical symbol names across two loaded
modules do not collide. Verified before relying on it.

Feature parity to decide per task: clusterer replication (`cluster_id`) and
restart persistency (`enable_restart_persistency` / rpm) are **not** in v1.

## 6. Tasks

**Phase 1 — module skeleton**
- **CP-01** Module scaffold: directory, Makefile, `module_exports`,
  `register_cachedb` with scheme `perf://`, URL/collection parsing, doc stubs.
  Clamp the configured size to `[4,24]` — `cachedb_local`'s
  `1 << coll_size` on an unbounded unsigned (`cachedb_local.c:895,940`) is UB
  at `th=32` and yields a zero-size table at `th=64`; do not reproduce it.
- **CP-02** Slab arena: size classes, alloc/free, never returns to shm.
- **CP-03** Bucket + tags + seqlock: the 64-byte layout, optimistic read,
  writer path. Assert `sizeof(bucket) == 64` at compile time.
- **CP-04** `cachedb_funcs` vtable: get/set/remove/add/sub/get_counter,
  in-place update when the value fits.

**Phase 2 — correctness and operability**
- **CP-05** Expiry: per-bucket `min_expires`, frequent sweep, expired-as-absent
  on read.
- **CP-06** Statistics + MI dump: entries, buckets, load factor, avg/max probe,
  arena occupancy, bytes. `cachedb_local` exports **zero** statistics, which is
  why the 20× cliff was invisible; do not repeat that.
- **CP-07** `iter_keys`, `cache_remove_chunk`, `fetch_chunk`.
- **CP-08** Docs: `doc/cachedb_perf_admin.xml` + generated README.

**Phase 3 — scale**
- **CP-09** Segmented directory + linear-hashing growth (§3.4).
- **CP-10** Background maintenance worker via `proc_export_t` (pattern
  `rtpengine.c:795`): incremental splits, arena compaction. Rules: never hold
  more than one bucket lock at a time; bounded work per wakeup with a yield;
  `PROC_FLAG_HAS_IPC` if MI-triggered.

**Phase 4 — optional**
- **CP-11** `E_CACHEDB_PERF_EXPIRED` event, gated by `evi_probe_event()`
  (`evi/evi_modules.h:125`) so it costs nothing with no subscribers. Opt-in per
  collection. EVI delivery is synchronous — a sweep reaping thousands of
  entries must not raise them inline.
- **CP-12** Ordered secondary index for glob ops. `cachedb_local`'s
  `remove_chunk_f` is a full scan with a `memcpy` and `fnmatch` per key; SIP
  keys are heavily prefixed, so a prefix range scan is O(log n + matches).
  Only if these turn out to be hot.
- **CP-13** 32-bit arena offsets instead of pointers (6 → ~11 slots/bucket).
- **CP-14** Cuckoo displacement, if occupancy proves to be the constraint.
- **CP-15** Clusterer replication and restart persistency, if wanted.

**Validation**
- **CP-16** Correctness suite: concurrent readers/writers, TTL boundaries,
  overwrite-in-place, arena reuse, seqlock retry under contention (ThreadSanitizer
  or equivalent), and a soak test against `cachedb_local` as oracle.
- **CP-17** Re-run the `th_store` benchmark from PR #4114 with `perf://` and
  compare against the `cachedb_local` and dialog rows.

## 7. Reproduction

```bash
cd bench && make run
```

Figures in §2 were taken on **10.22.20.222** (Ubuntu 20.04, gcc 9.4) and
reproduce on **10.22.20.223** (Ubuntu 24) within ~10%: the sorted-bucket result
measures 16.5× there vs 18.6×, the expiry hint 26.7× vs 29.8×. Absolute
nanoseconds differ with CPU; the ranking and order-of-magnitude conclusions do
not. `concur.c` needs `-pthread` and reports Mops/s at 1/2/4/8 threads.

The rig is a model, not the module: it measures structure and cache behaviour
in a single process with threads. It does not model shm allocation, multi-process
coherence, or OpenSIPS locking primitives. Treat it as ranking designs, not as
predicting throughput.

## 8. References

- CLHT — <https://github.com/LPD-EPFL/CLHT>
- MemC3 (NSDI'13) — <https://www.usenix.org/system/files/conference/nsdi13/nsdi13-final197.pdf>
- Algorithmic Improvements for Fast Concurrent Cuckoo Hashing (EuroSys'14) —
  <https://www.cs.princeton.edu/~mfreed/docs/cuckoo-eurosys14.pdf>
- libcuckoo — <https://github.com/efficient/libcuckoo>
