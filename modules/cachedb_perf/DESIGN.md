# cachedb_perf — design

A new `cachedb` backend written from scratch for large, high-churn local
caches. Not a fork of `cachedb_local`: it shares that module's **public
interface** (the `cachedb_funcs` vtable) so it is a drop-in replacement chosen
by URL scheme, but none of its internals.

- Module: `cachedb_perf`
- Scheme: `perf://`
- Branch: `feature/cachedb-perf-devel` on `10.22.20.223:/dn/opensips-devel`

`cachedb_local` is left **completely untouched** by this branch.

```opensips
loadmodule "cachedb_perf.so"
modparam("topology_hiding", "th_state_url", "perf://th")
```

### Scope of v1 — decided, not open

**`cachedb_perf` v1 is a fast single-node in-memory cache. Nothing else.**
No clusterer replication, no restart persistency, no remote backend. Every
node keeps its own copy and shares nothing.

This is a deliberate scope decision, not an omission to be quietly filled in
later. It keeps v1 to one job — be the fastest local cache available — and it
keeps the lock-free read path (§3.2) free of any cross-node coordination that
would compromise it.

The consequence to be aware of: v1 is a drop-in for **non-shared** uses such as
`topology_hiding`'s `th_store` on a single node, but it is **not** a drop-in
wherever `cachedb_local` is used with `cluster_id` for shared state — e.g. the
staging RGSs' usrloc full-sharing. Those must stay on `cachedb_local` until
§5.3 is built.

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

### 3.6 Threads vs processes — use neither pthreads nor thread-local state

`cachedb_perf` uses **`__atomic_*` builtins and `gen_lock_t`**, nothing else.
Both are process-agnostic: shm is `MAP_SHARED` and mapped before fork
(`mem/shm_mem.c:252`), and cache coherence is hardware-level, so the seqlock in
§3.2 behaves identically across processes and threads. pthreads would add
nothing — the cache is shared across *processes*, so a thread pool inside one
worker cannot help the other seven, the read path is already lock-free, and the
worker processes already saturate the cores.

The maintenance worker (CP-10) is a **process** via `proc_export_t`, not a
thread: that inherits process-table registration, IPC/MI, logging and signal
handling.

Threads are not foreign to the codebase — `net/net_tcp.c` runs a pthread pool
(`pthread_create`, line 1376, gated on `tcp_threads`; the 4.1 TCP single-IO
mode) and `lock_ops.h:105` offers a `pthread_mutex_t` lock backend. No
OpenSIPS *module* calls `pthread_create`. So if anyone reaches for them later,
two hazards:

1. **A pthread primitive in shm is silently broken across processes unless
   initialised `PTHREAD_PROCESS_SHARED`** — the default is `PROCESS_PRIVATE`,
   which is undefined behaviour in shared memory. OpenSIPS's own backend does
   this correctly (`lock_ops.h:114`, `pthread_mutexattr_setpshared`).
   **`bench/concur.c` is thread-based and would pass such a bug.** The rig
   cannot catch this class of defect by construction — only CP-16's
   multi-process validation can.
2. **fork and threads, in that order, do not mix.** Workers are forked at
   startup. A thread created in `mod_init` (pre-fork) is not inherited by the
   children, and any lock it held at fork time stays locked forever in every
   child. Threads may only be created in `child_init`, post-fork, if at all.

### 3.7 Deliberately deferred

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

Feature parity: restart persistency (`enable_restart_persistency` / rpm) is
**not** in v1. Clusterer replication is **not** in v1 either — see §5.1.

### 5.1 Why clusterer replication is not inherited as-is

`cachedb_local`'s replication does **not** hold bucket locks — the lock is
released (`hash.c:171`) before `replicate_cache_insert` is called
(`hash.c:178`), and likewise on remove. That concern does not apply.

It is slow for a different reason: `clusterer_api.send_all()` runs
**synchronously in the SIP worker on every `set()` and every `remove()`** —
one BIN packet fanned out to every node in the cluster, per write, with the
full value copied into the packet each time. There is no batching, no
coalescing and no async queue. Under the `th_store` TTL-bump pattern this
replicates a value that has not changed, on every refresh.

Two further defects worth not reproducing:

- **Fire-and-forget.** No ack, no retry. A node that misses a packet stays
  silently wrong until that key is written again.
- **`LM_ERR` per failed write** (`cachedb_local_replication.c:139`). During a
  peer outage this emits one error log per write — a log flood on top of an
  outage.

If replication is ever added (CP-15), it must be batched and driven from the
maintenance worker (CP-10), never inline in the SIP worker.

### 5.3 If sharing is needed later — two options, neither in v1

v1 shares nothing. If a deployment later needs state shared across nodes,
there are two routes, to be chosen on evidence at that time:

**(a) Clusterer replication.** Reuse the existing `clusterer` capability, but
fix what §5.1 documents: batch writes, coalesce repeated writes to the same
key (the `th_store` TTL bump rewrites an unchanged value on every refresh),
drive the send from the maintenance worker instead of the SIP worker, and rate-
limit the failure logging. Cheapest to build, inherits clusterer's node
membership and sync-on-startup. Still eventually-consistent and fire-and-forget
unless acks are added.

**(b) A shared backend behind `cachedb_perf`.** Keep the fast local table as a
cache, and back it with a shared store — either speaking to an external
Redis-like server, or exposing our own store over a Redis-like protocol so
nodes share one authoritative copy. Turns `cachedb_perf` into a local cache in
front of shared state rather than a replicated peer. More work, but it gives a
single source of truth instead of N converging copies, and it reuses a wire
protocol operators already have tooling for.

Note the interaction with §5.2: option (b) makes `keys`/`scan` genuinely
useful, because there is then one authoritative keyspace to enumerate rather
than a per-node view. It also raises questions v1 does not have to answer —
write-through vs write-back, what happens to the local copy on backend failure,
and whether TTLs are authoritative locally or remotely.

Do not start either until a real deployment needs it. PR #4114's measurements
are the reminder here: a remote store cost the proxy its throughput ceiling
(~5 300 CPS vs ~9 000 for a dialog) because the round-trip is synchronous and
a worker blocks for its duration. Any shared backend must be asynchronous or it
will undo exactly the performance this module exists to deliver.

## 5.2 Introspection: keys, scan, and single-key access

`cachedb_local` is **not** missing key enumeration — `cachedb_local:fetch_chunk
<glob> [collection]` exists and is documented (`doc/cachedb_local_admin.xml:350`).
It is simply not usable at scale:

1. **Always returns values as well as names** — no keys-only mode. `"*"` over
   50 000 entries with 200-byte values is a ~10 MB MI response.
2. **Full table scan holding every bucket lock**, with a `memcpy` and an
   `fnmatch` per key. On a large cache this stalls SIP traffic — the same
   reason Redis deprecated `KEYS` for production use.
3. **No limit, no cursor, no pagination.** Redis's answer is `SCAN`; there is
   no equivalent.
4. **No TTL in the output**, so you cannot see what is about to expire.

`cachedb_perf` provides instead:

| command | purpose |
|---|---|
| `keys <glob> [collection] [limit]` | names only, bounded. The `KEYS th*` equivalent. |
| `scan <cursor> [glob] [count]` | cursor-based incremental iteration, Redis `SCAN` semantics |
| `dump <glob> [collection] [limit]` | names **and** values — explicit opt-in, never the default |
| `get <key> [collection]` | single key: value + TTL + size |
| `set <key> <value> [ttl] [collection]` | single key write |
| `del <key> [collection]` | single key delete |
| `stats [collection]` | CP-06 |

Two properties make `scan` sound here, both falling out of choices already made
for other reasons:

- **Buckets never move** (§3.4 — growth appends a segment), so a cursor is just
  a `(segment, bucket)` index and stays valid across a resize. This is the same
  property Redis's SCAN guarantee rests on: an element present for the whole
  iteration is returned at least once.
- **Seqlock reads take no locks** (§3.2), so unlike `cachedb_local`'s scan a
  `keys`/`scan` pass cannot stall writers, and `count` bounds the work per call.

`keys` and `dump` must still enforce a default limit, and `scan` is the
documented answer for anything large.

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
- **CP-07** `iter_keys` plus the `cache_remove_chunk` script function and the
  `remove_chunk` MI, matching `cachedb_local` semantics for parity.
- **CP-08** Docs: `doc/cachedb_perf_admin.xml` + generated README.
- **CP-18** Introspection MI (§5.2): `keys`, `scan`, `dump`, `get`, `set`,
  `del`. `scan` is cursor-based and lock-free; `keys` is names-only with a
  default limit; `dump` returns values only on explicit request. This is the
  operability gap that makes `cachedb_local` hard to run — treat it as core,
  not optional.

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
- **CP-15** Sharing state across nodes — **explicitly out of scope for v1**
  (see "Scope of v1" and §5.3). Two candidate routes when a deployment
  actually needs it: **(a)** clusterer replication, batched and driven from the
  maintenance worker, fixing the defects in §5.1; or **(b)** a shared
  Redis-like backend behind the local table, either talking to an external
  server or exposing our own store over a Redis-like protocol. Option (b) also
  makes `keys`/`scan` authoritative rather than per-node. Whichever is chosen
  must be **asynchronous** — PR #4114 measured a synchronous remote store
  costing ~5 300 CPS against ~9 000 for a dialog, because the worker blocks for
  the round trip.
- **CP-19** Restart persistency (rpm), if wanted. Also not in v1.

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
