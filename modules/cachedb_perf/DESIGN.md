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

### 2.5 Write staging and queueing — both measured, both rejected

Two variants of "make writes cheaper by not writing to the table directly"
were tested (`bench/wbuf.c`, `bench/queue.c`).

**Staging buffer.** A ~1 MB buffer that writes append to, drained later by a
worker. Write throughput, 1→8 threads:

| threads | per-bucket lock | **shared** buffer | **per-process** buffer |
|---|---|---|---|
| 1 | 20.16 | 25.67 | 35.76 |
| 8 | **130.12** | **18.52** | **291.72** |
| scaling | 6.45× | **0.72×** | 8.16× |

A *shared* buffer **loses throughput as threads are added** — the single atomic
append offset is the hottest cache line in the system, and at 8 threads it is
7× worse than the per-bucket locks it was meant to replace. Removing the lock
did not remove the coordination, it concentrated it. Per-bucket locks are only
uncontended *because* they are spread over thousands of buckets.

*Per-process* buffers do scale (8.16×, 2.24× faster than bucket locks). But
staging live entries penalises the read path, because a reader must consult the
buffers to see writes not yet applied: 48.9 → 52.7 ns with 8 buffer probes.
With ~95% reads that trade is a net loss:

```
baseline  0.95(49.0) + 0.05(49.0) = 49.0
staged    0.95(52.7) + 0.05(21.9) = 51.2   <- worse
```

**Break-even is ~12% writes.** Nothing measured in SIP workloads is close. The
read-side model was also generous (one hot array index per buffer, where a real
staging index needs a hash lookup and a pointer chase), so the true break-even
is higher still. Three further costs: 1 MB holds 4 519 entries — 0.75 s of
headroom at 6 000 CPS, so the drain must keep up or writers fall back; the
`th_store` TTL-bump pattern fills the buffer with duplicate versions of keys
that never changed; and deletes need tombstones on the read path.

**Queued (producer/consumer) writes.** Same idea shaped as a message queue.
At a fixed 8-thread budget, counting *applied* writes:

| split | applied Mops/s | vs direct | ring full |
|---|---|---|---|
| 8 direct writers | **116.33** | 1.00× | — |
| 7 prod + 1 cons | 24.09 | 0.21× | 99% |
| 4 prod + 4 cons | 54.64 | **0.47×** | 97% |
| 2 prod + 6 cons | 45.14 | 0.39× | 94% |

The best split does less than half the work of writing directly. The consumer
performs *exactly the work the producer would have done* — take the bucket
lock, mutate, release — so the queue adds enqueue/dequeue overhead and then
leaves fewer threads to do the actual applying. Note the ring-full column:
producers are back-pressured 94–99% of the time, so writes block anyway, and
now they block on a **global** queue rather than on **one of 16 384** buckets.

Correctness objections are independent of the numbers: async writes break
read-your-writes (a `set()` that returns before the value is visible), and
`add`/`sub` cannot be queued at all since they must return the new value to the
caller — so a synchronous path would be needed regardless, and both paths
maintained.

**The rule this establishes:** queue when the consumer is genuinely slower than
the producer, or does something the producer must not wait for. Never queue
when the consumer does the same work the producer could have done inline. The
design already applies this correctly in the three places it holds — deferred
frees, replication (§5.3), and EVI events (CP-11) — all of which have a
genuinely slow consumer.

### 2.6 Memory backing: huge pages and pre-faulting

OpenSIPS shm is `mmap(MAP_SHARED|MAP_ANONYMOUS)` (`mem/shm_mem.c:252`) with
**no `MAP_POPULATE`, no `MAP_HUGETLB`, no `mlock` and no `madvise` anywhere**
in `mem/` or `main.c`. So pages are demand-faulted on first touch, and a
multi-hundred-MB cache runs entirely on 4 KB pages.

Both effects were measured over a 256 MB region (`bench/hugetlb.c`), on the
build target **223** (Xeon E5-2699 v4, kernel 6.8 — the same CPU as the
PR #4114 benchmark host) and confirmed on **224** (kernel 6.12):

| access pattern | 4K pages | 2M hugepages | gain (223 / 224) |
|---|---|---|---|
| independent random reads | 29.82 ns | 20.86 ns | **1.43× / 1.46×** |
| dependent pointer chase | 172.37 ns | 145.14 ns | **1.19× / 1.24×** |

Note the *independent* pattern benefits more, which is the opposite of the
intuition that a dependent chain exposes TLB cost: in the chase, serialized
DRAM latency dominates and hides the page walk, whereas parallel access makes
page-walk bandwidth the bottleneck that huge pages relieve.

Pre-fault cost for the same 256 MB:

| mechanism | 223 | 224 |
|---|---|---|
| `memset` whole region | 1414.0 ms | 899.1 ms |
| touch 1 byte per 4 K page | 291.2 ms | 198.2 ms |
| **`MADV_POPULATE_WRITE`** | **177.4 ms** | **154.8 ms** |

**Use `MADV_POPULATE_WRITE` where available, touch-per-page below Linux 5.14,
never `memset`.** `mmap(MAP_ANON)` already returns zeroed pages, so zeroing
buys nothing for correctness and costs 8× the bandwidth. Kernel spread matters
even across our own build hosts: 223 is 6.8 and 224 is 6.12 (both have it),
222 is **5.4** (does not).

Note also what pre-faulting does and does not do: it **moves** the fault cost
to startup rather than removing it. First touch costs ~287 ns/entry against a
41 ns write, so the benefit is latency predictability during traffic, not
throughput.

**Caveats on statically reserved `MAP_HUGETLB`.** `vm.nr_hugepages` pages are
exclusive and unswappable — on a 3 GB VM like 223, a 320 MB reservation is over
10% of the machine, gone whether the cache uses it or not. SBC VMs are
frequently sized like this. See §2.6.1 for the modern routes that remove this
objection.

(Both build hosts are the same silicon — Xeon E5-2699 v4, 16 vCPU, the same
CPU as the PR #4114 benchmark host — so differences between their numbers are
kernel/VM noise, not hardware.)

### 2.6.1 Modern-kernel routes (measured on 6.8 and 6.12)

Four ways to get 2 MB pages onto a `MAP_SHARED|MAP_ANON` region, ranked by
admin burden (`bench/hugetlb2.c`; every run verified by the `ShmemHugePages` /
`HugePages_Free` delta — never assume the pages went huge, see below):

| route | admin action | 223 (6.8) | 224 (6.12) | chase |
|---|---|---|---|---|
| `MADV_COLLAPSE` after fill | **none** | works even with `shmem_enabled=never` | EINVAL — needs `advise` | 177→156 ns |
| THP-shmem: `shmem_enabled=advise` + `MADV_HUGEPAGE` | one sysfs write | works | works | 177→158 ns |
| `vm.nr_overcommit_hugepages` + `MAP_HUGETLB` | one sysctl | works, **no reservation** | works | **177→125 ns (1.42×)** |
| static `vm.nr_hugepages` | reservation | works | works | 172→145 ns |

Findings:

- **`MADV_COLLAPSE` (5.14 anon / 6.1 shmem) is the zero-config route, but
  kernel-fickle**: 6.8 collapses the existing mapping with no configuration at
  all; 6.12 tightened it to respect `shmem_enabled`, so the identical call
  fails EINVAL there until `advise` is set. One-time cost 221 ms–1.9 s per
  256 MB depending on memory fragmentation. Because it retrofits an *existing*
  mapping, the maintenance worker could in principle point it at the whole
  OpenSIPS shm segment — a core-wide TLB win beyond this module.
- **`vm.nr_overcommit_hugepages` removes the reservation objection**: pages are
  taken from free memory at fault time and returned on exit — nothing is held
  hostage while the cache is not running. Best numbers of everything tested,
  and the fastest pre-fault: **85 ms vs 318–509 ms** for 256 MB, since faulting
  at 2 MB granularity is ~4–5× cheaper. `mmap` fails cleanly if memory is
  fragmented, which the fallback ladder absorbs.
- **1 GB pages: ruled out.** `pdpe1gb` is present on both hosts, but runtime
  allocation fails even with 6 GB free (no contiguous aligned GB exists after
  any uptime — boot-cmdline only), and the arithmetic says skip it regardless:
  Broadwell's STLB holds ~1536 2 MB entries = 3 GB of TLB coverage, so a ≤1 GB
  arena already fits entirely in TLB on 2 MB pages.
- **Verify, never infer.** One 6.12 run came back fully huge yet benchmarked
  *worse* than base (single-run VM noise), and the 6.12 EINVAL proves kernel
  version does not predict behaviour. The module must check the region's smaps
  and report the achieved tier through CP-06.

### 2.6.2 Swap pinning (measured on 223, verified against the live SBC)

Swap is real in this deployment: 223 carries 3.8 GB of swap and **test SBC 191
has 1 GB with 20 MB already in use**. A swapped-out cache page turns a 130 ns
read into a disk fault — and can occur *inside a writer's critical section*,
violating §3.5b through the page-fault handler. The ladder also makes
swappability inconsistent by accident: tier 1 (`MAP_HUGETLB`) is inherently
unswappable, tiers 2–4 are shmem, which swaps.

**Mechanism: `mlock()` the arena in `mod_init`.** All verified empirically
(`bench/mlockt.c`), counters read from `/proc/meminfo`, never assumed:

- `mlock` of 256 MB shows **Mlocked/Unevictable +255 MB**; `munlock` returns
  it to baseline.
- **Locks are not inherited across fork, but the pages are shared** — a child
  with no lock of its own still sees the pages Mlocked globally, because the
  pre-fork process holds the lock. So one `mlock` in `mod_init` pins the arena
  for every worker, for as long as the main process lives. Post-fork chunks
  (CP-09 growth) are locked by the allocating process; OpenSIPS workers are
  permanent, so any long-lived process's lock suffices.
- **Cold `mlock` doubles as the pre-fault**: it must populate to pin.
  212–298 ms per 256 MB, versus 179 + 21 ms for `MADV_POPULATE_WRITE` + warm
  lock — same work, one syscall. On kernels without `POPULATE_WRITE` (222's
  5.4), `mlock` *is* the portable populate.
- Order on the THP tiers: **collapse first, then lock**.
- Tier 1 skips `mlock` entirely — hugetlb pages cannot swap and do not count
  against `RLIMIT_MEMLOCK`.

**The production blocker found while checking:** the SBC unit runs
`User=opensips` with the systemd default `LimitMEMLOCK=65536` — the live
opensips process on 191 has **Max locked memory = 64 KB**. `mlock` of any real
arena fails there today. The fix is a one-line drop-in
(`systemctl edit opensips` → `[Service] LimitMEMLOCK=infinity`), documented in
CP-08. Ubuntu 24's defaults are ~484 MB, so the build host misleads here —
another "verify on the real unit" case.

Failure handling follows the ladder's rule: if `mlock` fails, log **one**
warning naming `LimitMEMLOCK`, continue unpinned, and export the pinned state
through CP-06 (`locked_mb`) — never fail startup over it.

**Consequence for CP-20 — the fallback ladder**, all inside the single
`pcache_chunk_alloc()`:

```
1. MAP_HUGETLB              (static pool or overcommit present)   best, 1.42x
2. + MADV_HUGEPAGE          (shmem_enabled permits)               huge at fault
3. + MADV_COLLAPSE post-fill (zero-config on 6.8-class kernels)   retrofit
4. plain 4K                 (always works)                        today
```

Each tier degrades to the next; no tier can prevent startup; CP-06 reports the
tier actually achieved and the huge-page coverage in MB.

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
    gen_lock_t        lock;     /* writers only */
    unsigned char     tags[6];  /* 1 byte of hash per slot, never 0 */
    unsigned short    used:4,   /* 0..6 */
                      owner:12; /* process_no of the writer holding the lock */
    pcache_rec       *slot[6];
};
```

**Owner tracking — decided.** The writer stores its `process_no` in `owner`
after acquiring the lock and clears it before releasing. This exists so the
maintenance worker can detect a bucket whose lock is held by a process that
has since died (§3.5b, irreducible residue) and recover it, rather than that
bucket being unreachable for the lifetime of the server.

Two ways to carry this were considered. Putting the PID in the lock word
itself (CAS `0 -> pid` rather than `0 -> 1`) costs no space, but means
hand-rolling the lock and so forfeits the adaptive futex sleep that §3.5b
requires. Taking it from the bucket's own spare bytes costs nothing and keeps
`gen_lock_t`: `used` needs only 3 bits, so `used:4 / owner:12` fits the two
bytes already there and covers 4096 processes. The bucket stays **exactly 64
bytes** — assert it.

Recovery is the *worker's* job, never a reader's or writer's: they must treat
a stuck lock as simply contended (the §3.2 fallback already handles waiting).
Only the worker checks liveness via the process table and only it may force a
release, after confirming the owner is gone.

Lookup: mask to a bucket, compare 6 one-byte tags, and only dereference a slot
whose tag matches. A tag rejects ~255/256 of non-matching slots without
touching a second cache line — which is the whole point, since the pointer
chase is the expensive part.

### 3.2 Optimistic reads, and why they are safe here

Readers take **no lock**:

```
for (tries = 0; tries < PCACHE_SEQ_RETRIES; tries++) {
    v1 = load_acquire(version);
    if (v1 & 1) { cpu_relax(); continue; }   /* writer inside */
    ... scan tags, deref match, COPY the value out ...
    fence_acquire();
    v2 = load_relaxed(version);
    if (v1 == v2)
        return HIT;                          /* copy is trustworthy */
}
/* fell through: a writer is stalled mid-update. Do NOT keep spinning -
 * take the bucket lock, which sleeps under futex, and read under it. */
lock_get(&b->lock); ... read ... lock_release(&b->lock);
```

Writers take the bucket lock, bump `version` to odd, mutate, bump to even.

**The bounded retry is not optional.** An unbounded `while (v1 != v2)` livelocks
if the writer is preempted between the two version bumps: every reader spins on
a value that cannot change until the writer is rescheduled. The fallback
converts that into a bounded wait. See §3.7.

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

**The arena takes its chunks through a one-function backing-store interface**,
so where the memory comes from stays a late-binding decision:

```c
void *pcache_chunk_alloc(size_t size);   /* (a) shm_malloc  - default, always works
                                            (b) mmap MAP_HUGETLB - opt-in, CP-20 */
```

v1 ships on (a). §2.6 measures (b) as worth 1.19–1.43×, but it depends on a
sysctl we do not control, so it is an opt-in follow-up rather than a v1
dependency. Keeping it behind this one function means adding it later touches
nothing in the bucket, read path or vtable.

Whichever backing is used, the region must be created in `mod_init`
(pre-fork, `MAP_SHARED`) and **never unmapped** — that is the invariant §3.2
depends on. A dedicated mapping satisfies it even more clearly than shm does.
Pre-fault it per §2.6: `MADV_POPULATE_WRITE`, else touch-per-page, never
`memset`.

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

### 3.5b Preemption: it cannot be prevented, only made harmless

There is **no userspace primitive on Linux to prevent preemption**. A worker
can be descheduled at any instruction, including while holding a bucket lock,
and nothing in the module can stop that. So the design target is not "do not
get interrupted" — it is "being interrupted costs nobody anything". Four rules:

**1. Readers never block anyone.** The lock-free read path (§3.2) means a
preempted reader has zero effect on other processes. This is the single most
valuable property here and it is why the seqlock design was chosen.

**2. Bounded retry on the read path.** Without it, a writer preempted between
its two version bumps livelocks every reader (§3.2). Bounded retries plus a
lock fallback turn an unbounded spin into a bounded wait.

**3. Nothing slow inside a writer's critical section.** Between `lock_get` and
`lock_release` a writer must not: allocate or free, log, make a syscall, or
call into any other subsystem that takes a lock. Target is tens of nanoseconds
— a few stores and a `memcpy`.

`cachedb_local` violates this in five places, and it is instructive: it calls
the shm allocator while holding a bucket lock — `func_free` at `hash.c:166`
(via `lcache_htable_remove_safe`), `:290`, `:432`, `:510`, and `func_realloc`
at `:325`. That nests the bucket lock inside the shm allocator's own lock,
making the critical section unboundedly long and creating a lock-order
dependency between two unrelated subsystems. A preemption there stalls every
process that wants that bucket.

`cachedb_perf` avoids it structurally: the slab arena (§3.3) sub-allocates
without a global lock, updates in place when the value fits, and **defers
frees** — a writer pushes a dead entry onto a per-process free list and the
maintenance worker (CP-10) reclaims it later. No allocator call ever happens
under a bucket lock.

**4. Let the lock sleep rather than spin.** `futex_lock.h` implements an
adaptive lock that spins briefly and then sleeps (`USE_FUTEX`, documented in
`Makefile.defs:609`). Use `gen_lock_t` and inherit whatever the build selects —
do not hand-roll a spinlock, which would burn cores while a preempted holder
waits to be rescheduled.

**What not to do.** Real-time scheduling (`SCHED_FIFO`) is worse, not better:
an RT process spinning on a lock held by a preempted normal-priority process
can prevent that process from ever running — classic priority inversion, and it
can hang the box. CPU pinning does not prevent preemption. Neither belongs
here.

**What is and is not atomic.** Being uninterrupted is not the same as being
atomic, and the guarantee offered should be stated exactly:

- A single `get` / `set` / `remove` is atomic with respect to other processes.
  A reader sees the state either fully before or fully after a write, never a
  torn one — that is what the version counter enforces.
- `add` / `sub` are atomic read-modify-write: the writer holds the bucket lock
  across the whole read-compute-write, so two processes incrementing the same
  counter cannot lose an update.
- **Operations on different keys are not atomic with respect to each other.**
  There are no multi-key transactions and none are planned. A caller needing
  two keys to change together must not assume it.

**The irreducible residue.** If a process is `SIGKILL`ed while holding a bucket
lock, that lock is stuck forever — there is no owner left to release it. This
is true of *every* shm spinlock in OpenSIPS, not just this module, and it is
not solved anywhere in the codebase. The only real mitigation is rule 3: a
critical section of tens of nanoseconds makes the window vanishingly small.
**Decided:** the bucket carries the writer's `process_no` in its `owner` field
(§3.1) so the maintenance worker can detect a dead holder and recover the
bucket. Recovery is the worker's job alone — readers and writers treat a stuck
lock as ordinary contention and use the §3.2 fallback. Only the worker checks
liveness against the process table, and only after confirming the owner is gone
may it force a release.

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
- **A shared write-staging buffer** — §2.5. Negative scaling (0.72× at 8
  threads); one atomic append offset is worse than thousands of bucket locks.
- **Staging live entries in per-process buffers** — §2.5. Scales well on the
  write side but penalises the ~95% of operations that are reads. Break-even is
  ~12% writes, which no measured SIP workload approaches. Revisit only if
  CP-06's statistics show a real deployment above that.
- **Queued / producer-consumer writes** — §2.5. 0.21–0.47× of direct writes at
  a fixed thread budget, producers back-pressured 94–99% of the time, and it
  breaks read-your-writes while being unable to express `add`/`sub` at all.
- **A `cache_ratio` (expected read/write mix) modparam.** This would be the
  `cache_collections` mistake in a new place: a static number the operator
  cannot reasonably know, that silently degrades when reality diverges — and
  that parameter is the entire reason this module exists. The module counts
  reads and writes itself (CP-06), continuously and per collection, so it never
  needs to be told. More generally: **adapt on the effect, not the cause** —
  key off observed seqlock retry rate (real contention), observed load factor,
  and observed expiry rate; never off a predicted workload mix.

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
- **CP-20** Huge-page backing for the arena (§2.6, §2.6.1, §3.3): the
  four-tier fallback ladder inside `pcache_chunk_alloc()` —
  `MAP_HUGETLB` (static or overcommit pool; best, 1.42×) → `MADV_HUGEPAGE`
  (THP-shmem, huge at fault time) → `MADV_COLLAPSE` post-fill (zero-config on
  6.8-class kernels; needs `shmem_enabled=advise` on 6.12+) → plain 4 K.
  Every tier is runtime-detected by *trying it*, never by kernel version (the
  6.8/6.12 `MADV_COLLAPSE` divergence proves version checks lie); no tier may
  prevent startup. Verify achieved coverage via the region's smaps and export
  tier + huge-MB through CP-06 — memory taken outside shm is invisible to
  `shm:` statistics otherwise. Pre-fault per §2.6: `MADV_POPULATE_WRITE`
  (5.14+; 223/224 yes, 222 no), else touch-per-page, never memset — and note
  a hugetlb-backed region pre-faults ~4–5× faster (85 ms vs 318–509 ms per
  256 MB). Warm-up size modparam is acceptable — it degrades gracefully
  (too small: pages fault later; too large: wasted RAM), unlike
  `cache_collections`; default to the arena's initial chunk size. 1 GB pages
  ruled out (§2.6.1): runtime allocation is unobtainable and 2 MB pages
  already give a ≤1 GB arena full TLB residency on Broadwell.

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
