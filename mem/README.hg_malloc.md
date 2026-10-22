# HG_MALLOC

A memory allocator for shared and private memory, selected at runtime with `-a HG_MALLOC`. This document covers how it works, how to configure, run and monitor it. Measurements: https://github.com/Lt-Flash/opensips/blob/hg_malloc/docs/benchmarks.md

## 1. Allocation

**Size classes.** Requests up to 64 KB (including an 8-byte cell header) are served from 21 fixed size classes, 64 B to 64 KB. Every cell carries a small hidden header with its class, so a free needs no lookup. Larger requests go to a coalescing large tier that packs into whole pages.

**The common path takes no lock.** Each process (and each thread of a threaded process) keeps a private free list per class. An allocation pops from it and a free pushes to it - no lock, no shared cache line. When a private list runs dry it refills a batch from a shared per-class pool; when it grows past its threshold it donates a batch back. Only those batch transfers take the arena lock.

**Blocks and the buddy allocator.** The arena is a grid of pages the size of the host's huge page - 2 MB on x86-64, larger on arm64 kernels with 16 KB or 64 KB base pages - whichever of the four tiers backs them. A buddy allocator inside each page hands out blocks, and a block is carved into cells of one class. The shared pool keeps each block's free cells on that block and refills from the fullest partially-used block, so emptier blocks drain completely. A block whose cells are all free goes back to the buddy and can be re-cut for any class - memory used by a burst of one size is not stranded there.

**Small arenas.** An arena with an INIT under one huge page settles its page size by the backing it gets. On plain 4 KB memory it runs in small mode, on 256 KB pages: at least 256 KB with a cap, 512 KB without. On huge pages its INIT is raised to one huge page, and an arena whose cap leaves no room above that page is refused at startup.

**Idle caches are swept.** Every 30 s each process flushes what its private lists hold back to the shared pool (staggered, a process or two per second), keeping a small residue for the classes it is actively using; TCP main's I/O threads, which IPC cannot reach, flush at their next job after a sweep. A process that leaves for good - an auto-scaled worker going away - first hands back everything it holds, the unused rest of the blocks it carved included. Without these, a worker that went idle or left would keep its cells forever; one that crashes still does, until restart.

**Integrity checks.** Each block keeps a map of which of its cells are in the shared pool. A cell that reaches the pool twice is an exact double free: the second copy is refused and counted. Every link the pool follows is checked against the map, so a scribbled free-list link stops the walk instead of leading it off the arena. A cell freed twice in a row is caught earlier, on the freeing thread's private list, in every build; HG_MALLOC_DBG checks that whole list on every free; a large fragment is tagged when freed, so a second free of it is refused. All are counted in `core:hg_stats` (`corruption`) and logged at CRITICAL on each detection; the process keeps running. Not caught in a normal build: a cell freed twice with other frees in between and taken again by the same process before its next flush.

## 2. Backing memory

The arena is acquired through four tiers, best first, each verified from the kernel's own counters rather than assumed:

| tier | mechanism | notes |
|---|---|---|
| 1 | `mmap(MAP_HUGETLB)` | huge pages from the hugetlb pool; unswappable |
| 2 | THP: `MADV_HUGEPAGE` before first touch | huge pages at fault, from general memory |
| 3 | THP: `MADV_COLLAPSE` after fill | pages collapsed into huge pages afterwards |
| 4 | plain 4 KB pages | always available |

Tiers 2-4 pin the committed arena with `mlock()`. The startup log names the tier achieved, and says why when THP is turned off by a host setting. Huge pages make the allocator's own work cheaper but are not required; an arena on 4 KB pages behaves the same.

**Each growth step negotiates its own backing.** A step may land on a different tier than the memory before it, so `core:hg_stats` reports `tier_bytes` - the split by tier - whenever more than one tier holds bytes. On tier 3 a step taken by a worker that ran out of memory is published on 4 KB pages at once and collapsed by the maintenance process afterwards - one page at a time, with the arena lock released, for up to 100 ms a second, retrying a page the kernel cannot collapse yet up to 16 times - so the worker never waits for `MADV_COLLAPSE` (about 36 ms per 16 MB step); a step taken ahead of demand collapses straight away. `core:hg_stats` counts these pages as `collapse_deferred`, `collapsed_late`, `collapse_retries` and `collapse_late_failed`.

**Tier 1 reserves the whole cap from the pool when the arena is created.** Growth on tier 1 therefore cannot fail half-way, and the pool must be sized for the caps (section 7). Pages the arena gives back when it shrinks return to the pool for anyone to take, so growing back into them can fail if something else took them meanwhile. If the pool can hold the initial size but not the cap, the arena keeps huge pages at its initial size, cannot grow, and says so at startup. If it cannot hold even the initial size, the arena starts on THP with its full cap and stays elastic.

## 3. Elastic arenas

`-m INIT:CAP` (and `-M INIT:CAP` for the private arenas) makes an arena elastic. Without a cap it is fixed at its size. For the smallest INIT see Small arenas (section 1).

**One mapping, created before fork.** The whole cap is mapped once, shared, before any worker forks. Growth and shrink never create or change mappings - they populate and release ranges of that one shared object, which every process sees immediately. An untouched reserved range costs only page-table entries.

**Committed and reserved.** `committed` is what is backed, pinned and usable; `cap` is the size of the reservation. The buddy's page descriptors are laid out for the whole cap at startup, so a grow only publishes pages - it never needs to find room for metadata in an arena that is full.

### 3.1 Growth

Three triggers, one mechanism:

- **Exhaustion** - always armed once a cap exists. An allocation that finds no memory grows the arena and retries once.
- **Headroom** (`hg_grow_ahead`, default on) - when the free part of the arena drops below twice its reserve floor, one step is grown ahead of demand.
- **Profile** - with an `auto_scaling_profile`, usage is sampled once per cycle; at the end of each block of W cycles, if it was at or above the up-threshold in at least C of them, one step is grown before anything fails.

**A grow is a three-phase commit.** The step is reserved under the arena lock; the expensive part - faulting the pages in, pinning them, verifying their backing - runs with the lock released; the new pages are published under the lock again, in constant time. Other allocations keep running throughout. One grow is in flight at a time: a process that runs out while it is in progress waits for the publish without holding the lock (up to 2 s, then the request fails and `grow_wait_timeouts` counts it).

**The maintenance process.** Elastic shared arenas (the shm arena and module arenas) get a dedicated core process, `HG maintenance`. It serves no requests; every second it applies the headroom rule, every `hg_scaling_cycle` seconds it evaluates the profile and the shrink policy, and it does the populate of any step it grows itself - so no SIP worker waits on a proactive grow. Private arenas have no maintenance process: each process runs its own arena's policy in its 30 s cache sweep.

**Step size.** `shm_grow_granule` / `pkg_grow_granule`, default 16 MB, rounded to the arena page. Smaller steps track demand more closely and make each commit shorter.

### 3.2 Limits

Growth stops at the smallest of three limits:

| limit | what | refusal |
|---|---|---|
| admin | the profile's scale-up target, else the cap | logged as a notice - a limit doing its job |
| backing | the kernel failing to back the memory; on tier 1 also the hugetlb pool (checked at startup) or the memory-lock limit | resource refusal |
| host memory | `MemAvailable` must stay above `hg_ram_floor_mb` (default max(256 MB, MemTotal/20)) | resource refusal |

The host-memory check charges a private-arena step once per OpenSIPS process, since every process grows its own under the same load. Tier 1 skips it: hugetlb pages were taken from host memory when the pool was created.

The same floor guards the INITs: at startup every process's private arena is checked against RAM (and the hugetlb pool, if the host has one) before anything forks, and each later fork - the auto-scaler's included - is skipped if its INIT does not fit (see [Host memory checks](#host-memory-checks)).

On hugetlb pages every grow is an `mlock()` of the new range, and `mlock()` checks `RLIMIT_MEMLOCK` on hugetlb mappings too, so there a low limit refuses growth: the arena warns at startup, and a refused grow names the resource that ran out - the limit, or the hugetlb pool. On tiers 2-4 the pin is a latency guarantee, not a requirement: an arena that could not pin its initial size runs unpinned, and a grow the limit cannot cover continues unpinned instead of being refused (section 8).

### 3.3 GROW-BLOCKED

Only resource refusals count: on any tier the host floor or the kernel failing to back the memory, and on hugetlb pages also the memory-lock limit or the pool. Reaching the cap or the profile's scale-up target is a limit doing its job: it is logged once as a notice and counted in `grow_refused`, and never latches.

A resource refusal that persists is an incident; a single one is not. The first refusal arms the state. It latches at the next 30 s sweep tick if refusals continued, or sooner if a reclaim pass did not help. It clears on the next successful grow, or when free space recovers above twice the reserve floor. Isolated refusals never latch.

When latched: the `hg_shm_grow_blocked` statistic is 1, one warning is logged, and the `E_CORE_SHM_GROW_BLOCKED` event is raised at the next sweep tick - from the sweep timer, never under the arena lock - with `arena`, `committed_mb`, `cap_mb` and `grow_refused`. While it lasts the event is raised again periodically.

```
event_route[E_CORE_SHM_GROW_BLOCKED] {
    xlog("L_CRIT", "shm arena cannot grow: $param(committed_mb) of $param(cap_mb) MB committed, $param(grow_refused) refusals\n");
}
```

Refusal details are logged once per episode; `grow_refused` carries the count.

### 3.4 Shrink

**Only whole free pages are released.** A page is released only when the buddy has merged it back into one free top-level block - which means no cell in it is in use or sitting in any process's private cache. No coordination with other processes is needed: nothing can hold a pointer into it.

**The drain.** The shrink decision is made per policy cycle. With a profile, the arena starts draining after usage has stayed at or below the down-threshold for the profile's C consecutive cycles; a profile without a `scale down` clause never shrinks. Without a profile, an elastic arena drains after 4 quiet sweeps (2 minutes) in which its free space exceeds one grow step plus four times the reserve floor. A shared arena then releases up to `hg_shrink_step` (default 64 MB) per maintenance tick from the top of the arena, and with `hg_interior_release = 1` up to another `hg_shrink_step` from inside it; a private arena releases one step per quiet window. The gates are re-checked every tick, and the drain stops at the headroom line, so a release never triggers the grow that would undo it. Any grow ends the drain, and shrink counting resumes only after a cool-off of 10 x C cycles (C = the profile's scale-down cycle count).

**The release.** Pages leave the free list first, under the lock; the release itself (`MADV_REMOVE` on the shared arena, `MADV_DONTNEED` on a private one) runs with the lock dropped; if the kernel refuses, the pages go straight back. On tier 1 released pages return to the hugetlb pool. A kernel that does not support the advice leaves the arena grown and is noted once; no further release is attempted.

## 4. Private (pkg) arenas

- Each process creates its own private arena at fork, after the configuration is parsed, so `-M INIT:CAP` and `pkg_auto_scaling_profile` apply to every process individually. The pre-fork parent arena never uses hugetlb, so no child can fault on the pool through a copy-on-write page, and never gets the profile; it keeps the `-M` cap and can still grow on exhaustion.
- A process grows and shrinks only its own arena; its policy, and its GROW-BLOCKED latch, run in its own 30 s sweep, whatever `hg_scaling_cycle` is set to. Each process publishes its refusals and GROW-BLOCKED state at that sweep, summed as `hg_pkg_grow_refused` and `hg_pkg_grow_blocked`.
- Host cost multiplies with the process count - and on tier 1, so does the pool reservation, since each process's arena reserves its own cap.

## 5. Module arenas

A module can ask for its own HG-managed arena with `mem/mem_arena.h` - for a cache whose size and lifetime have nothing to do with transactions. It gets the same size classes, caches, reclaim and elastic growth, independent of the core `-a` choice, and appears in `core:hg_stats` (not in the `hgmem:` statistics, which describe the core shm arena). When HG_MALLOC is not built, the API compiles to stubs that return NULL, so the module must fall back to ordinary shm itself.

## 6. Monitoring

**MI:** `core:hg_stats` returns, per arena (the shared arena, every module arena, and the calling process's private one):

| field | meaning |
|---|---|
| `tier`, `tier_bytes` | backing achieved at startup; per-tier split when growth mixed tiers |
| `committed`, `cap`, `grow_headroom` | elastic state |
| `grows`, `grows_proactive`, `grows_exhaustion`, `grow_refused`, `grow_blocked` | growth history and the latched gauge |
| `shrinks`, `punches`, `draining`, `whole_free_pages` | release history and what could be released now |
| `live_committed`, per-class carve and reuse | what is in use and where |
| `lock` | hold and wait histograms per reason (refill, return, flush, large, policy, stats, other), stalls, the worst hold and its reason, commit and release times |
| `corruption` | double frees, foreign pointers, bad classes, counted per kind |

**Statistics:** `hg_shm_*` counters in the `hgmem:` group (growth, refusals, the GROW-BLOCKED gauge), plus `hg_pkg_grow_refused` and `hg_pkg_grow_blocked` summed over every process's private arena, suitable for Prometheus.

**Events:** `E_CORE_SHM_GROW_BLOCKED` (section 3.3) and `E_CORE_HG_LOCK_STALL`, raised for a shared-arena lock hold at or above `hg_lock_stall_us` (default 1000 us), with `reason`, `hold_us`, `process` and `stalls`.

**Note on `shmem:free_size`.** It counts only memory not yet carved into size-class blocks. Free cells already carved - in private caches or the shared pool - are reusable for their class but not counted as free, so free memory reads lower than what is reusable. Alert on `grow_blocked` and on the lock statistics, not on `free_size`.

## 7. Sizing

1. **Memory lock limit:** `LimitMEMLOCK=infinity` in the service unit (or `ulimit -l unlimited`). Required for an elastic arena on hugetlb pages; recommended on the other tiers, where without it the arena runs unpinned and can be swapped.
2. **Tier 1 pool:** reserve `shm_cap + pkg_cap x processes`, in 2 MB pages, plus a margin of about 12%. A pool that cannot fit the caps gives fixed arenas on huge pages, or pushes late processes to THP.
   **Tiers 2-3 instead of a pool:** THP `enabled` = `madvise` or `always` (private arenas) and `shmem_enabled` = `advise` or `always` (shared arena). With neither a pool nor THP, every arena runs on 4 KB pages.
3. **Private caps multiply:** `-M 16:64` on 30 processes is up to 1.9 GB of potential pinned growth.
4. **Tier 1 releases go back to the pool,** not to general memory; shrink `vm.nr_hugepages` to give them to the host.
5. **Measuring the pool:** `HugePages_Free` alone also moves with private hugetlb use; the shared arena's pages are `(HugePages_Total - HugePages_Free) - sum of Private_Hugetlb over all processes`.
6. **Memory per object:** a little more than the other allocators, from size-class rounding - +2% live memory on 400k registrations, 5-13% on tm's 1-4 KB objects at rates with no drops. Under overload the total is lower, because nothing waits in memory for retransmissions: see [memory under load](https://github.com/Lt-Flash/opensips/blob/hg_malloc/docs/benchmarks.md#memory-under-load). `used_size` counts each object at its class size, so it reads higher than the bytes requested.

## 8. Troubleshooting

| symptom | cause | fix |
|---|---|---|
| startup: `RLIMIT_MEMLOCK is N KB, but growing on hugetlb pages needs M KB locked` | memory lock limit too low for growth on hugetlb pages | `LimitMEMLOCK=infinity` in the unit |
| `cannot grow ...: RLIMIT_MEMLOCK is N KB` | the same, at grow time | the same |
| `hugetlb pool cannot back a ... cap` at startup | `vm.nr_hugepages` smaller than the caps | grow the pool (section 7), restart |
| startup: `below the 512 KB minimum viable arena` | a fixed arena (no cap) under 512 KB | give a cap (`-M 256k:2m`) or INIT of at least 512 KB |
| startup: `on huge pages INIT is at least one huge page ... no room to grow` | INIT under 2 MB on huge pages with a cap of 2 MB or less | raise the cap, or give INIT as 2 MB for a fixed arena |
| notice: `INIT raised from ... to 2 MB` | INIT under 2 MB on huge pages | expected; give INIT as 2 MB to silence it |
| startup: `the N processes started now need ... MB of RAM` | `-M` INIT x processes does not fit in RAM above the floor (plus the hugetlb pool, if any) | lower `-M` INIT or the worker counts, or add memory or huge pages |
| `not forking more processes until memory frees up` | the auto-scaler wants a process whose INIT does not fit | lower the scale-up maximum or `-M` INIT; OpenSIPS keeps running meanwhile |
| `no more HG_MALLOC arena memory ...`, then `N allocations failed in the last 30 s` | the arena is full and cannot grow (cap reached, or growth refused) | raise the cap or the host's free memory; `core:hg_stats` shows what fills it. The first failure of an episode is logged in full, the rest are summarised every 30 s |
| `the arena has no growth room` | a profile is attached but `-m`/`-M` has no cap | add the cap: `-m 128:1024` |
| `scale-up target ... exceeds the ... reservation` | the profile wants more than the cap | raise the cap or lower the target |
| startup: `RLIMIT_MEMLOCK is N KB, less than the ... cap`, `continuing unpinned`, or `cannot pin a ... grow` | memory lock limit too low on tiers 2-4 | `LimitMEMLOCK=infinity` to keep the arena pinned; meanwhile it grows unpinned (swappable) rather than refusing |
| grown pages on 4 KB on a THP host | each step negotiates its own backing | expected; see `tier_bytes`, or use tier 1 |
| never shrinks | usage above the down-threshold, inside the post-grow cool-off, a profile without `scale down`, or the top page in use | check `core:hg_stats`; enable `hg_interior_release` to release from inside the arena |
| `DRY RUN - would grow` and allocations fail past the initial size | `hg_autoscale_dry_run = 1` blocks all growth | set 0 to act |
| testing under `ulimit -l` shows no refusals | running as root: `CAP_IPC_LOCK` lifts the limit | test as an unprivileged user (`setpriv`) |

## 9. Testing

`modules/hgstress` (excluded from the default build; `include_modules= hgstress`) is a multi-process soak: every worker churns stamped cells across all classes and the large tier, verifies the stamps while the others churn, and reports `PASS`/`FAIL` per worker. Its MI commands park and release stamped memory (`hgstress:hgs_hold`, `hgstress:hgs_release`, to drive grow and shrink) and inject a double free or a scribbled link (`hgstress:hgs_fault`, to exercise the integrity checks). It runs under any `-a` allocator.

The unit tests run under HG_MALLOC with `make test UT_ALLOC=HG_MALLOC UT_MEM="-m 64:1024 -M 16:256"` (`UT_ALLOC=HG_MALLOC_DBG` for the debug variant): the core suites, the allocator stress suite (`mem/test/test_malloc.c`, enabled when HG serves shm and pkg) and the HG cases in `mem/test/test_hg_malloc.c` - pkg memory from before `fork()` realloc'ed and freed in a child, cells freed by another process, the large tier, growth past INIT, a process leaving for good, double frees. CI runs both variants on every compiler and architecture of the unit-test matrix.

## 10. Configuration

### Command line

| option | meaning |
|---|---|
| `-a HG_MALLOC` | use HG_MALLOC for shared and private memory (`-s` / `-k` select them separately) |
| `-m INIT[:CAP]` | shared arena: initial size, and the cap it may grow to |
| `-M INIT[:CAP]` | private (per-process) arena, same form |

Sizes are MB, or take a `k`/`m`/`g` suffix (either case): `-m 128:1g`, `-M 512k:16m`. Without a cap the arena is fixed.

The smallest INIT depends on the backing the arena gets:

- **Huge pages:** an arena holds at least one whole huge page (2 MB on x86-64). A smaller INIT is raised to it, with a notice. If the cap leaves no room above that page (`-M 1m:2m`), OpenSIPS refuses to start.
- **Plain 4 KB pages:** the arena runs on 256 KB pages. INIT can be 256 KB when a cap gives it room to grow (`-M 256k:2m`), 512 KB without one.

These are the allocator's limits, not OpenSIPS's needs: the shared arena must also fit core startup, which makes one allocation of about 540 KB, so give `-m` a cap of 2 MB or more. With a cap, an allocation that would fail commits one more grow step and retries, up to the cap. The cap is on the command line because the reservation is made before the configuration is parsed.

### Memory autoscaling profiles

The worker autoscaler's `auto_scaling_profile` grammar also sizes memory arenas. For an arena the numbers are MB (or k/m/g):

```
auto_scaling_profile = MEM_SHM
    scale up to 1024 on 80% for 3 cycles within 10
    scale down to 256 on 30% for 120 cycles

auto_scaling_profile = MEM_PKG
    scale up to 32 on 80% for 2 cycles within 5
    scale down to 8 on 20% for 60 cycles

shm_auto_scaling_profile = MEM_SHM
pkg_auto_scaling_profile = MEM_PKG
```

| element | meaning for an arena |
|---|---|
| `up to N` | growth ceiling: above the initial size and within the `-m`/`-M` cap |
| `on P% for C cycles within W` | usage is sampled once per cycle; at the end of each block of W cycles, if it was at or above P% of the committed arena in at least C of them, one step is grown |
| `down to M` | shrink floor - may be below the initial size, must be below `up to N` |
| `on Q% for C cycles` | release memory after C consecutive cycles at or below Q%; after any grow, shrink counting waits 10 x C cycles |

Usage is live usage - what is handed out - not the carved footprint. A shared-arena cycle is `hg_scaling_cycle` seconds; a pkg profile runs in each process's 30 s cache sweep and governs every process's private arena separately, so its numbers are per process. A profile without a `scale down` clause never shrinks the arena; an elastic arena with no profile at all still releases memory after 2 quiet minutes. A profile written with size suffixes, or with a target of 1000 or more, is refused if it is attached to a process group, so a memory profile cannot be mistaken for a worker count.

Choosing the numbers: `P` is the occupancy you want the arena to run at (70-80% is the usual shape) and `Q` should sit well below it (20-40%), so the band between them absorbs normal swings without growing and shrinking back and forth.

### Global parameters

All optional.

| parameter | default | meaning |
|---|---|---|
| `shm_auto_scaling_profile` | none | profile that drives the shared arena |
| `pkg_auto_scaling_profile` | none | profile that drives each process's private arena |
| `shm_grow_granule` | 16m (one page on a small arena) | size of one grow step of the shared arena, rounded to the arena page |
| `pkg_grow_granule` | 16m (one page on a small arena) | the same for every process's private arena |
| `hg_ram_floor_mb` | 0 = max(256 MB, MemTotal/20) | host free memory no commit may take the host below: checked at startup, before each new process is forked, and on every grow |
| `hg_autoscale_dry_run` | 0 | 1 = advise only: no growth of any kind and no shrink; logs what it would have done once per episode and counts suppressed grows in `hg_shm_grow_refused`. Allocations beyond the initial size fail |
| `hg_grow_ahead` | 1 | keep free headroom by growing one step before an allocation has to |
| `hg_scaling_cycle` | 30 | seconds per policy cycle of shared arenas (the profile's "cycles"); private arenas use the fixed 30 s sweep |
| `hg_shrink_step` | 64m | most a shared arena releases from its top per maintenance tick (plus up to as much again from inside with `hg_interior_release`); a private arena releases one step per quiet window |
| `hg_interior_release` | 0 | 1 = give back whole free pages from anywhere in the arena, not only the top |
| `hg_lock_stall_us` | 1000 | an arena-lock hold at or above this is a stall: counted per arena, and raises `E_CORE_HG_LOCK_STALL` for the shared arena; 0 disables |

Example:

```
shm_auto_scaling_profile = MEM_SHM
shm_grow_granule = 32m
hg_ram_floor_mb = 1024
hg_lock_stall_us = 2000
```

### Events

Both events describe the shared arena and are raised from the 30 s cache-sweep timer, never while the arena lock is held. Catch them in the script with `event_route` or send them out with any event transport (`event_datagram`, `event_stream`, `event_rabbitmq`, ...).

#### E_CORE_SHM_GROW_BLOCKED

The shared arena needs to grow and a resource refuses: on any tier the host floor (`hg_ram_floor_mb`) or the kernel failing to back the memory, and on hugetlb pages also the memory-lock limit or the pool. Reaching the `-m` cap or the profile's scale-up target does not raise it - that is logged once as a notice and counted in `hg_shm_grow_refused`. A single refusal does not raise it either: the first refusal arms the state, which latches at the next 30 s sweep tick if refusals continued (or sooner if a reclaim pass did not help). The event is raised at the sweep tick after the state latches and again periodically while it lasts. A successful grow, or free space recovering above twice the reserve floor, clears it.

| parameter | meaning |
|---|---|
| `arena` | `shm` |
| `committed_mb` | memory the arena holds now |
| `cap_mb` | the `-m` cap - committed is below it, since a full arena does not raise this event |
| `grow_refused` | refused grows so far |

What to do: free or add host memory, or on hugetlb pages raise the memory-lock limit or the pool - whichever the log names - or find what is filling the arena (`core:hg_stats`, `core:hg_advise`). With no subscriber the same moment is logged as a warning, and the `hgmem:hg_shm_grow_blocked` statistic reads 1 while it lasts.

#### E_CORE_HG_LOCK_STALL

A process held the shared arena's lock for `hg_lock_stall_us` (default 1000 us) or longer. Raised at most once per 30 s, carrying the most recent stall; `hg_lock_stall_us = 0` turns it off.

| parameter | meaning |
|---|---|
| `arena` | `shm` |
| `reason` | what the lock was held for: `refill` (taking cells or a new block), `return` (giving cells or a block back), `flush` (a process emptying its private cache), `large` (an allocation too big for the 64 KB class), `policy` (a grow or shrink decision), `stats` (a statistics walk), `other` |
| `hold_us` | how long it was held |
| `process` | OpenSIPS process number that held it, as listed by `opensips-cli -x mi ps` |
| `stalls` | stalls since startup |

What to do: an occasional stall during a growth spurt is normal. A steady stream, or one `reason` dominating, is worth a look at the per-reason hold histogram in `core:hg_stats`.

#### Examples

In the script:

```
loadmodule "event_route.so"

event_route[E_CORE_SHM_GROW_BLOCKED] {
    xlog("L_CRIT", "HG: shm arena cannot grow - $param(committed_mb) of $param(cap_mb) MB committed, $param(grow_refused) refusals\n");
}

event_route[E_CORE_HG_LOCK_STALL] {
    xlog("L_WARN", "HG: shm lock held $param(hold_us) us by process $param(process) for $param(reason), $param(stalls) stalls so far\n");
}
```

which logs, for example:

```
CRITICAL:HG: shm arena cannot grow - 896 of 1024 MB committed, 37 refusals
WARNING:HG: shm lock held 1262 us by process 9 for return, 2 stalls so far
```

To another system, with `event_datagram` loaded:

```bash
opensips-cli -x mi event_subscribe E_CORE_SHM_GROW_BLOCKED udp:10.0.0.10:9999
```

### Monitoring

```bash
opensips-cli -x mi core:hg_stats      # per arena: tier, committed and cap, grows and shrinks, lock holds per reason, corruption counters
opensips-cli -x mi core:hg_advise     # what -m and -M should be, from the peak each arena actually reached
opensips-cli -x mi statistics:get hgmem:
```

`core:hg_stats` answers for the process that receives the MI command, so its `pkg` section is that process's private arena; `core:hg_advise` covers the worst process.

The `hgmem:` statistics group holds the shared arena's figures, plus two that sum every process's private arena (each process publishes its own at its 30 s cache sweep). The ones worth alerting on:

| statistic | alert when |
|---|---|
| `hg_shm_grow_blocked` | 1 - growth refused for a sustained period |
| `hg_pkg_grow_blocked` | above 0 - that many processes' private arenas cannot grow (no event for these: alert on this) |
| `hg_pkg_grow_refused` | rising - private-arena grows refused, all processes together |
| `hg_shm_corruption` | above 0 - memory was corrupted and the allocator caught it |
| `hg_shm_repin_failed` | above 0 - memory taken back from the host could not be pinned again |
| `hg_shm_lock_stalls` | rising steadily |
| `hg_shm_committed` against `hg_shm_cap` | committed close to the cap |

Others for graphs: `hg_shm_grows`, `hg_shm_grows_proactive`, `hg_shm_grows_exhaustion`, `hg_shm_grow_refused`, `hg_shm_shrinks`, `hg_shm_shrink_bytes`, `hg_shm_live`, `hg_shm_live_peak`, `hg_shm_carved`, `hg_shm_free_to_carve`, `hg_shm_lock_hold_max_us`, `hg_shm_tier`.

Note that `shmem:free_size` counts only memory not yet carved into size-class blocks; free cells already carved are reusable for their class but not counted, so it reads lower than what is reusable. Alert on the figures above, not on `free_size`.

### Host requirements

- `LimitMEMLOCK=infinity` in the service unit, or `ulimit -l unlimited`, so the arena stays pinned. Required for an elastic arena on hugetlb pages: every grow there is an `mlock()`, which checks the limit on hugetlb mappings too, and a refused grow names the limit or the hugetlb pool, whichever ran out. Recommended on tiers 2-4: without it the arena runs and grows unpinned (swappable) instead of refusing. HG warns at startup when the limit is too low.
- Huge pages are optional; without them every arena runs on plain 4 KB pages. To use them, provide either or both of:
  - a hugetlb pool (tier 1): `vm.nr_hugepages` large enough for the shared cap plus the private arenas, in huge pages (2 MB on x86-64). On this tier the whole cap is reserved from the pool when the arena is created. A pool that can hold the initial size but not the cap gives a fixed arena on huge pages instead of an elastic one, and says so; a pool that cannot hold even the initial size leaves the arena on THP, still elastic.
  - transparent huge pages (tiers 2-3): `/sys/kernel/mm/transparent_hugepage/enabled` set to `madvise` or `always` for the private arenas, and `/sys/kernel/mm/transparent_hugepage/shmem_enabled` set to `advise` or `always` for the shared arena. Many distributions ship `shmem_enabled=never`. `MADV_COLLAPSE` (tier 3) needs Linux 6.1 or later.

### Host memory checks

The shared arena commits its `-m` INIT at startup, and every process then creates its own private arena and commits its `-M` INIT, so the number of processes matters as much as the sizes. HG checks before it commits, on every tier: THP and 4 KB memory against `MemAvailable` above `hg_ram_floor_mb`, and memory on hugetlb pages against the pool. The shared arena is checked first (against the default floor - the config is not read yet), and every later check counts what is left after it.

- **Shared arena:** its INIT is refused if the host cannot hold it; its growth is refused at the floor (GROW-BLOCKED, `hg_shm_grow_blocked`).
- **Private arenas at startup, before anything forks:** every process's private arena is simulated against RAM above the floor, after whatever the hugetlb pool (if the host has one) can take. OpenSIPS refuses to start if the processes started at startup do not fit, and warns if the auto-scaling maximum does not, or if the `-m` cap plus `-M` cap x processes exceeds `MemTotal`. An INFO line gives the numbers.
- **Each new process, auto-scaler forks included:** not forked if its INIT does not fit. The auto-scaler keeps the processes it has and tries again on its next cycle, so a profile that allows more processes than the host holds stops short instead of running into the OOM killer.
- **Every arena:** an INIT the host cannot hold is refused when the arena is created.
- **Every grow:** refused if it would cross the floor; a private-arena step is counted once per process. Private-arena refusals show in `hg_pkg_grow_refused` and `hg_pkg_grow_blocked`.

```
INFO:  pkg: 14 processes at startup, up to 16 with auto-scaling, -M INIT 32 MB: 192 MB from the hugetlb pool, 224 MB (288 MB at the maximum) from RAM; 0 MB of RAM available above the 11778 MB floor
ERROR: pkg: the 14 processes started now need 224 MB of RAM for their -M INIT of 32 MB (after 192 MB from the hugetlb pool), but 0 MB is available above the 11778 MB floor. ...
ERROR: new process's pkg arena: committing 32 MB now does not fit - ... not forking more processes until memory frees up
```

## 11. For reviewers

### Reading order

| file | what it holds |
|---|---|
| `mem/hg_malloc.h` | the data structures: `struct hg_block` (one arena), the cell header, size classes, corruption kinds, lock instrumentation |
| `mem/hg_malloc_dyn.h` | the public entry points (`hg_malloc`/`hg_free`/`hg_realloc`, debug and normal) |
| `mem/hg_arena.c` | size classes, the per-thread caches, the shared per-class pool, block reclaim, the sweeps, corruption checks, statistics |
| `mem/hg_buddy.c` | the page grid and buddy allocator; grow, shrink, interior release and re-growth into holes; deferred collapse |
| `mem/hg_large.c` | requests above 64 KB: a coalescing tier carved from buddy blocks |
| `mem/hg_malloc.c` | backing memory: the four-tier ladder and its verification, host memory checks, memlock, init and per-child init, status |
| `mem/hg_maint.c` | the maintenance process |
| integration | `mem/mem.c`, `mem/shm_mem.c`, `mem/common.c`, `mem/rpm_mem.c`, `pt.c`, `pt_scaling.c`, `main.c`, `cfg.y`, `core_stats.c`, `mi/mi_core.c`, `evi/evi_core.c` |
| tests | `mem/test/test_hg_malloc.c`, `modules/hgstress` |

### Invariants

1. **One lock per arena.** `hb->lock` (a `gen_lock_t` on its own cache line) guards all shared state of an arena: pools, block lists, the buddy tree, the large tier. No path holds two arena locks, the lock is never re-entered, and the slow system calls - commit, release, re-pin, collapse - run with it released.
2. **The common path takes no lock.** Each thread keeps, per class, a private free list and a bump region. A hit touches only thread-local state, the cell's class byte and link word, fields fixed at init, and the process's statistics slot. The lock is taken to refill (32 cells), to give back half of a full cache, or to carve a block.
3. **Ownership is by address.** A pointer belongs to the arena whose reserved range holds it (`hg_owns()`, then a registry of at most 8 arenas inherited across `fork()` - `hg_owner()`); its class is one header byte; its block is computed from the address only when the cell enters the shared pool. A pointer of another arena - pre-fork pkg memory in a child, a module arena - bypasses the private cache and goes to its owner's pool.
4. **A block is reused only when every cell is back.** A block returns to the buddy, and can be re-cut for another class or the large tier, only when all its cells are in the shared pool (`in_gpool == cells`). A cell in any thread's private cache or bump region still counts as live, so caching can delay a reclaim but never cause a premature one.
5. **`fork()` never shares private state.** Before allocating anything, a child discards the private cache state it inherited for the shared arenas - otherwise parent and child would hand out the same cells - and gets a pkg arena of its own; pre-fork pkg pointers stay valid and are freed into the child's copy of the inherited arena (`hg_arena_child_init()`, `pt.c`).
6. **One range operation per arena at a time.** Grow, re-grow, trim and punch take a single in-flight token (`grow_inflight`) under the lock. New pages are published only after they are committed; pages to release are first taken off the free lists and marked `releasing`; a page is released only when it is wholly free; the arena never shrinks below INIT. A grower that finds the token taken waits without the lock and retries only if a grow published pages (`grow_gen`).
7. **Host memory is checked before it is committed.** Every arena's INIT at creation; all startup processes before the first fork (`hg_capacity_check()`); each child's INIT before its fork - forks are serialized; every grow, under the arena lock, with a pkg grow charged for every process (`hg_grow_ram_refused()`). Concurrent pkg grows therefore cannot together cross the floor. Tier 1 skips the RAM check: its pool pages are reserved at creation.
8. **The maintenance process owns proactive work** - headroom grows, the profile and shrink gates, deferred collapse - and a worker that runs out still grows the arena itself.

### Known limits

- A double free in a normal build is missed if other frees come between the two and the process takes the cell again before its next flush (see Integrity checks, section 1).
- A process that crashes keeps its cached cells counted as live until restart; one that exits normally or is scaled down hands them back.
- The floor checks are not reservations: independent arenas (shm, module arenas, a child's pkg INIT) growing at the same moment can together pass the floor by one step each.
- If the maintenance process exits, OpenSIPS shuts down. If it hung in the middle of a grow, a worker that runs out would wait 2 s and fail its allocation.
- TCP main's I/O threads share one statistics slot, so their counters can drift. `E_CORE_HG_LOCK_STALL` is raised for the core shm arena only.

### Properties and the tests that show them

| property | shown by | runs | gap |
|---|---|---|---|
| a cell is never handed to two processes at once | `hgstress`: every worker stamps each word of its blocks and re-verifies them; a foreign stamp is a double hand-out | by hand | not in CI |
| alloc / free / realloc under load, many processes, mixed sizes | the allocator stress suite under HG_MALLOC and HG_MALLOC_DBG | CI | checks alignment and the used-size statistic, not content |
| a cell freed by another process comes back intact | `test_hg_malloc.c` | CI | |
| pkg memory from before `fork()` can be realloc'ed and freed in a child | `test_hg_malloc.c`, normal and debug builds | CI | |
| a process leaving for good gives its cells back | `test_hg_malloc.c`: a child leaves through `dynamic_process_final_exit()` and the arena returns to its baseline | CI | |
| a double free is refused and counted, not handed out twice | `test_hg_malloc.c` (twice in a row; large fragment); `hgstress` fault injection | CI; by hand | the in-between case (Known limits) |
| large tier (> 64 KB) | `test_hg_malloc.c` (128 KB - 8 MB, realloc), `hgstress` (1 in 64 allocations) | CI; by hand | |
| an elastic arena grows past INIT on demand | `test_hg_malloc.c` (one process); `hgstress hold_mb` (every worker, growth seen by all) | CI; by hand | multi-process growth not in CI |
| the debug status dump walks only valid cells | the HG_MALLOC_DBG unit-test run ends with the shm status dump | CI | |
| shrink and interior release never free memory still in use | - | by hand, production | no automated test |
| backing ladder: hugetlb, THP advice, THP collapse, 4 KB | startup log, `core:hg_stats` | by hand | not in CI (runners have no hugetlb pool) |
| memlock limit: unpinned growth on 4 KB / THP, refusal on hugetlb | - | by hand | not in CI |
| growth refused at the cap or the host floor returns NULL and raises the event | - | - | no automated test |
| builds: gcc and clang `-Werror`, x86-64, i386, arm32/arm64, glibc and musl, HG compiled out | upstream CI matrix; i386 and musl by hand | CI; by hand | |
