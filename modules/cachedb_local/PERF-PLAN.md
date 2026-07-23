# cachedb_local — performance & scalability plan

Branch: `feature/cachedb-local-perf-devel` (off `master`, 4.1-dev)
Working tree: `10.22.20.223:/dn/opensips-devel`

> This file and `bench/` are working documents for the branch. Drop both
> (`git rm`) before proposing anything upstream — they are not part of any
> intended PR.

---

## 1. Why

`cachedb_local` is a fixed-size chained hash table whose size is set once from
`cache_collections` and **never changes**. The default is
`HASH_SIZE_DEFAULT 9` → **512 buckets** (`cachedb_local.h:34`), and most
deployments never set the parameter at all.

At 50 000 live entries that is a load factor of 97.7, i.e. ~50 string compares
and ~50 dependent cache misses per lookup. This was found the hard way while
benchmarking `topology_hiding`'s `th_store` backend (PR #4114): setting
`cache_collections "th=16"` cut LB CPU from **45% to 29%** at 4 000 CPS. That
is a one-line config change nobody can be expected to discover — the module
gives no signal that it is in this state.

Goal: make the module fast at tens of thousands of entries **without** requiring
the operator to know the right hash size in advance.

## 2. Measured baseline

All figures from `bench/` on this host: 50 000 keys (16-byte hex, `th_store`
shaped), 200-byte values, allocations deliberately scattered to mimic shm
fragmentation after a busy run. Successful point lookups.

### 2.1 Is the hash function to blame? No.

`core_hash()` is an additive `h += v ^ (v>>3)` over 4-byte words, which looks
weak, but measures clean on every realistic key shape (thids, dialog ids,
usrloc AoRs, call-ids):

| | chi²/df @512 | chi²/df @65536 |
|---|---|---|
| `core_hash` | 0.65 – 0.99 | 0.99 – 1.18 |
| FNV-1a + murmur finalizer | 0.91 – 1.07 | 0.99 – 1.00 |

Statistically indistinguishable. **Do not replace the hash function** — it is
not the problem and changing it buys nothing.

### 2.2 Index structure shootout

| design | @512 buckets | @65536 buckets |
|---|---|---|
| **A** current: chained + `strncmp` | 2484 ns | 111 ns |
| **B** chained + 32-bit hash cached in node | 1837 ns (1.35×) | 86 ns (1.28×) |
| **C** sorted array per bucket + binary search | **134 ns (18.6×)** | 100 ns |
| **D** 64B cache-line bucket, 4 inline slots | 84 ns (1.32× vs B@64k) | |
| **E** flat open addressing, linear probe | 78 ns (1.42× vs B@64k) | |

The whole effect is load factor: **20× between a bad and a good table size**,
and the micro-optimisations are worth only 1.04–1.35×.

Key result: **C is within 21% of a correctly-sized chained table while running
on the pathological 512-bucket default.** An ordered container *inside the
bucket* makes table size nearly irrelevant — which is a far smaller and safer
change than online resizing in shared memory.

### 2.3 Insert cost and deferred sorting

| | ns/insert |
|---|---|
| chain prepend (current) | 254 |
| eager sorted insert (memmove) | 374 |
| append to unsorted tail, worker merges | 306 |
| append + merge inline | 694 |

Merging: 5 967 merges, 19.4 ms total, **3.3 µs each**. Lookup with a
sorted prefix + ≤8-entry unsorted tail is 146 ns vs 143 ns fully sorted — the
tail scan is free.

Conclusion: deferring the sort to a worker saves 68 ns/insert (18%) over eager
sorted insert. **That does not justify a worker on its own** — do the eager
version first; move the sort onto the worker later if the worker exists anyway.

### 2.4 Expiry

50 000 entries, 65 536 buckets, TTLs spread over 3 600 ticks, ~13 due per sweep:

| strategy | per sweep | locks/sweep | vs current |
|---|---|---|---|
| **A** current full sweep, lock every bucket | 1.3075 ms | 65 536 | 1× |
| **B** per-bucket `min_expires`, unlocked skip | 0.0439 ms | **13** | **29.8×** |
| **C** timer wheel, O(expired) | 0.0005 ms | — | 2514× |

Wheel maintenance costs 74.4 ns/insert (+24%) and 16 B/entry (15.3 MB @ 1M).

**Expiry is not a CPU problem.** Even the current full sweep is 0.131% of one
core at a 1-second interval — and it runs every 600 s. The actual defect is
*reclamation latency*: an entry that expires and is never fetched again squats
in shm for up to 10 minutes. B fixes that for zero hot-path cost and zero extra
memory; C's further 84× buys nothing.

Note also that expired entries are **already invisible** — `lcache_htable_fetch`
checks `expires < get_ticks()` and returns not-found (`hash.c:424`, and the same
in `fetch_counter`/`add`). Expiry timing is memory reclamation only, never
correctness.

## 3. Ruled out — do not re-litigate

- **B-tree / skip list replacing the hash.** Exact-match KV store; a hash is
  already the better structure. Point lookup would become ~3 dependent cache
  misses and every measurement above beats it. Concurrent rebalancing across
  processes in shm is the worst option available.
- **Replacing `core_hash()`.** Measured clean (§2.1).
- **Flat open addressing (E)** despite being fastest at 78 ns: resize is
  stop-the-world (every slot moves), which is exactly what cannot be done
  cheaply across processes in shm, and probe sequences don't map onto
  per-bucket locks.
- **ART / radix trie.** 16-byte keys still cost 3–5 hops, no better than the
  hash, and concurrent ART in shm is a serious undertaking.
- **Per-key timers or per-key expiry events.** §2.4 — optimises 0.13% of a core
  while adding a second index with a different lock (bucket vs wheel), whose
  reverse acquisition order in the reaper is a real deadlock hazard.
- **EVI as the expiry mechanism.** There is no one-shot timer in the core
  (`register_timer`/`register_utimer` are periodic only, `timer.h:92`) and EVI
  is a synchronous publish bus — it cannot schedule anything. EVI as
  *notification* is a separate, legitimate feature (CL-13).
- **Compacting `shm_malloc()` directly.** Compaction needs placement control,
  which the shm allocator does not offer. Only viable behind a private slab
  arena (CL-10).

---

## 4. Tasks

Phases are ordered by risk-adjusted return. Phase 1 and 2 are independently
shippable; nothing in them depends on the later phases.

### Phase 1 — diagnosability and low-risk fixes

**CL-01 — Export statistics and an MI command**
The module exports *zero* statistics (`cachedb_local.c:141`). There is currently
no way to discover you are in the 2484 ns regime; it took a benchmark to find.
Export per-collection: entry count, bucket count, load factor, average and max
chain length, bytes used. Add an MI command to dump it per collection.
*Rationale:* turns a silent 20× cliff into a visible one. Highest value per line
of code in this plan.
*Files:* `cachedb_local.c`. *Risk:* none.

**CL-02 — Clamp the configured hash size**
`parse_collections` reads `coll_size` as an unbounded `unsigned` and then does
`1 << coll_size` (`cachedb_local.c:895,940`). `th=32` is undefined behaviour;
`th=64` yields a zero-size table. Clamp to `[4, 24]` and reject out-of-range
values at startup with a clear error.
*Files:* `cachedb_local.c`. *Risk:* none. Genuine bug.

**CL-03 — Warn on sustained high load factor**
Once CL-01 exists, log a one-shot `LM_WARN` when a collection's load factor
crosses ~8, naming the collection and suggesting the `cache_collections` size.
*Rationale:* the fix is a one-line config change; the problem is purely that
nobody knows to make it.
*Files:* `cachedb_local.c`, `hash.c`. *Risk:* none.

**CL-04 — Per-bucket `min_expires` hint; run the sweep often**
Add a 4-byte `min_expires` to `lcache_t`, lowered on insert, recomputed while
sweeping that bucket. `localcache_clean` skips any bucket whose hint is in the
future using a plain unlocked read. Then drop `cache_clean_period`'s default
from 600 s to ~1 s.
*Gain:* 29.8× cheaper sweep, 13 locks instead of 65 536, and dead entries
reclaimed in ~1 s instead of up to 10 min. No hot-path cost, no extra
per-entry memory, no second index.
*Files:* `hash.h`, `hash.c`, `cachedb_local.c`. *Risk:* low — the hint is
advisory; correctness still comes from the per-entry `expires` check.

**CL-05 — `memcmp` over `strncmp`, one source of truth for table size**
`fetch`/`fetch_counter`/`remove_safe` use `strncmp` while `add` uses `memcmp`;
keys are length-checked first so `memcmp` is correct and faster. Separately,
`lcache_htable_iter_keys` iterates `cache_col->size` while every other function
uses `col_htable->size` (`hash.c:563`) — they must be one field, especially once
the table can grow.
*Files:* `hash.c`. *Risk:* none.

### Phase 2 — hot-path constants

**CL-06 — Cache the 32-bit hash in the entry**
Store the full hash in each entry and compare it before `memcmp`. Worth
1.28–1.35× (§2.2) and it makes CL-09's binary search possible without touching
keys.
*Files:* `hash.h`, `hash.c`. *Risk:* low.

**CL-07 — Shrink the entry from 56 to 24 bytes**
`attr.s` and `value.s` are *always* `(char*)me + sizeof(entry)` and `+attr.len`
— 16 bytes of redundant pointers per entry. Replace the two `str`s with
lengths and a flexible array member; fold `synced` into a flag byte; keep `ttl`
only for the rpm path. Reuse the freed space for CL-06's hash.
*Gain:* ~32 MB at 1M entries. Memory is the binding constraint at scale
(PR #4114 measured ~1 GB holding 50 k calls).
*Files:* `hash.h`, `hash.c`, `cachedb_local.c`, `cachedb_local_replication.c`.
*Risk:* medium — touches every accessor and the rpm layout. Note
`fix_rpm_cache_entries` and the restart-persistency format.

**CL-08 — In-place update on overwrite**
`_lcache_htable_insert` (`hash.c:122`) mallocs a new entry, walks the chain to
free the old one, then prepends — **even when overwriting the same key with a
same-sized value**. That is the `th_store` TTL-bump pattern exactly. When the
existing entry's value buffer fits, `memcpy` the value and update `expires` in
a single walk.
*Gain:* removes one shm malloc/free pair per overwrite; shm allocation is a
known global contention point. Also the largest single source of the module's
shm fragmentation.
*Files:* `hash.c`. *Risk:* low.

### Phase 3 — the structural win

**CL-09 — Sorted array per bucket, binary search**
Replace the per-bucket linked list with a contiguous array of
`{hash32, entry*}` kept sorted by hash; binary search on lookup, insertion sort
(memmove) on insert. At bucket occupancies of 10–100 a sorted array beats a
tree outright — it is the cache-optimal degenerate tree at this scale.
*Gain:* **18.6× at load 97.7**, landing within 21% of a correctly-sized table,
for +120 ns/insert. Makes the module tolerant of the wrong hash size rather
than requiring the right one.
*Cost:* +16 B/entry for the slot array. Slightly *slower* than a plain chain
when the table is already well-sized (100 vs 86 ns) — its value is robustness.
*Files:* `hash.h`, `hash.c`, plus the direct chain walks in `cachedb_local.c`
(`remove_chunk_f`, `localcache_clean`, the MI dump) and
`cachedb_local_replication.c`.
*Risk:* medium — it changes the bucket representation everywhere. Depends on
CL-06.

### Phase 4 — larger, optional

**CL-10 — Private slab arena for entries**
Take large chunks from shm once and sub-allocate size-classed entries inside
them. Bounds fragmentation, improves locality, and is the **precondition for
any compaction** (you cannot compact `shm_malloc` — no placement control).
Feasible here because entries are relocatable: every `lcache_entry_t*` in the
module is a stack local inside a bucket-lock critical section, and
`lcache_htable_fetch` returns a `pkg_malloc`'d *copy*, so no caller ever
retains a pointer. That is not true of dialogs or transactions.
*Do CL-08 first* and re-measure `shm:fragments` — it may remove the need.
*Risk:* high.

**CL-11 — Background maintenance worker**
One dedicated process via `proc_export_t` (pattern: `rtpengine.c:795`; also
`httpd`, `stun`, `event_kafka`), owning: incremental resize (CL-12), slab
compaction (CL-10), and optionally the tail merges of a deferred-sort variant
of CL-09. Expiry stays in the timer unless CL-04 proves insufficient.
*Rules:* never hold more than one bucket lock at a time (workers take exactly
one, so lock order stays trivially safe); bounded work per wakeup with a yield
so SIP traffic is never starved; `PROC_FLAG_HAS_IPC` if MI-triggered.
*Risk:* high. Only justified once CL-10 or CL-12 is wanted.

**CL-12 — Incremental online resize**
Segmented directory (directory of fixed 4096-bucket segments) plus linear
hashing. Growth appends a segment, so **existing buckets never move** — no
pointer invalidation, no RCU/epoch problem across processes. Splits happen one
bucket at a time under that bucket's lock. Publish `(level, split)` as a single
64-bit word only *after* a split completes, so a racing reader sees either
pre- or post-split state, both correct.
*Note:* after CL-09 this is worth roughly 20%, not 20×. Re-evaluate then.
*Risk:* high.

**CL-13 — `E_CACHEDB_LOCAL_EXPIRED` event**
Raise an EVI event carrying collection + key when an entry is reaped, gated by
`evi_probe_event()` (`evi/evi_modules.h:125`) so the cost is zero with no
subscribers. Opt-in per collection. For `topology_hiding` this is the "state is
gone, stop expecting it" signal.
*Caveat:* EVI delivery is synchronous in the raising process — a sweep reaping
thousands of entries must not raise them inline.
*Risk:* low. Independent of everything else.

**CL-14 — Ordered secondary index for glob operations (conditional)**
`remove_chunk_f` (`cachedb_local.c:202`) and the `fetch_chunk` MI are full table
scans: every bucket lock taken, every key `memcpy`'d to a buffer, `fnmatch` on
all n keys. SIP keys are heavily prefixed (`th_`, `dlg_`, collection
namespaces), so a secondary ordered index would turn a prefix glob into
O(log n + matches). **This is the one place a B+tree or radix trie is the right
answer** — as a secondary index alongside the hash, never as a replacement.
*Only worth it if these are called on a hot path* — it costs memory and write
amplification. Measure first.
*Risk:* medium-high.

### Supporting

**CL-00 — Benchmark rig** *(done — `bench/`)*
Standalone reproductions of every figure above. `make && make run` in `bench/`.

---

## 5. Recommended order

1. **CL-02, CL-01, CL-03, CL-05** — one small PR. Zero risk, and CL-01 makes
   everything after it measurable.
2. **CL-04** — expiry hint. Self-contained, 30×, could ride in the same PR.
3. **CL-08, CL-06** — hot path, low risk.
4. **CL-09** — the 18.6×. Its own PR; needs CL-06.
5. Re-measure. Decide whether CL-07, CL-10/11/12 are still worth it.
6. **CL-13** whenever — independent.

Steps 1–4 get essentially all of the available win. Everything in Phase 4 is a
real project and should be justified by numbers taken *after* step 4.

---

## 6. Reproduction

Figures in §2 were taken on **10.22.20.222** (`compile`, Ubuntu 20.04, gcc 9.4).
They reproduce on **10.22.20.223** (`au-compile24`, Ubuntu 24) within ~10%:
CL-09's sorted-bucket win measures 16.5x there vs 18.6x here, and CL-04's
expiry hint 26.7x vs 29.8x. Absolute nanoseconds differ with CPU; the ranking
and the order-of-magnitude conclusions do not.

Re-run anywhere with `cd bench && make run`.
