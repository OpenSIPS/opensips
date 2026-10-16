---
title: "cachedb_perf Module"
description: "A high-performance local memory cache implementing the CacheDB interface, with lock-free reads and a table that grows at runtime."
---

## Admin Guide


### Overview


This module is a high-performance local memory cache implementing
the Key-Value interface exported by the OpenSIPS core. It is a
drop-in alternative to *cachedb_local*, selected
by URL scheme (*perf://* instead of
*local://*), designed for large, high-churn
caches: lock-free reads, cache-line-sized buckets and a table that
grows at runtime instead of being sized once at startup.


Each OpenSIPS instance keeps its own in-memory copy, but a whole
collection can be persisted to an SQL backend so it survives a
restart (see [DB persistence](#db-persistence)), and refreshed
cluster-wide from that shared DB with *perf_sync*
(see [Cluster sync](#cluster-sync)). What the module does
*not* do is *cachedb_local*-style
per-operation replication (a *cluster_id* write
streamed between nodes on every operation) - that would tax the
lock-free path the module exists to keep fast; sharing here is the
pull-from-DB refresh model. Deployments that need per-operation
replication must stay on *cachedb_local*.


Data is organized in named *collections* (hash
tables), declared via the *cache_collections*
parameter. Each *cachedb_url* points to one
collection; a URL naming no collection uses the collection named
"default", which always exists. Keys are hashed with
MurmurHash3 rather than the core's hash function: the latter sums
its per-word mixes, so sequential or numeric keys (phone numbers,
"user123456") collide on the full 32 bits - measured
65k distinct values for 500,000 such keys, which put 38% of the
entries into the overflow table behind a single lock. MurmurHash3
gives the uniform 0.2%.


### DB persistence


With [db_url](#db_url-string) set, a whole collection can be
saved to and loaded from an SQL backend. A save is a full snapshot:
the collection's rows are deleted and every live entry is re-inserted,
with its TTL stored as an absolute wall-clock time so it survives a
restart (already-expired entries are skipped on both save and load).
Native counters round-trip as their decimal value.


Trigger it on demand with the *perf_save* /
*perf_load* MI commands, or automatically via
[db_mode](#db_mode-int). This is single-node durability;
for cross-node sharing over the same DB, see
[Cluster sync](#cluster-sync) (still not per-operation replication).


> [!WARNING]
> A save/load is a *full, blocking snapshot* of the
> collection: one SQL statement per entry, run synchronously in the
> process that issued it. On a large collection (this module is built
> for millions of entries) or a slow backend such as
> *db_text* or *db_sqlite*, that
> can take a long time and stall that process for its duration. Treat
> it as a *maintenance / bootstrap* operation -
> startup warm-up, shutdown flush, an occasional snapshot or a
> *perf_sync* refresh - never on a per-request path
> and not on a tight timer. Frequent whole-collection persistence is an
> anti-pattern; if you need durable per-key writes on every operation,
> this is the wrong tool.


The table (default "cachedb_perf") needs these columns:


```
collection   string   - the collection name
pkey         string   - the cache key
pvalue       binary   - the value (BLOB; binary-safe)
expires      int      - absolute unix expiry, 0 = never
```


### Cluster sync


Built on the same DB: with [sync_cluster_id](#sync_cluster_id-int)
set, *perf_sync* (MI command and script function)
saves a collection to the DB and then signals every node in the
cluster to reload it from there. The signal is one small message per
sync - *not* per cache operation - so it costs
nothing on the hot path.


> [!WARNING]
> A reload *overwrites* a peer's copy from the DB, so
> *perf_sync* is for single-writer / read-replica
> topologies: one node (or the application writing the DB directly) is
> the authority for a collection, the others refresh from it. A node
> that also takes its own local writes would lose the unsaved ones on a
> reload - this is convergence to a shared source of truth, not a merge
> of divergent copies, and deliberately not per-operation replication.


A node that reloads because of a peer's *perf_sync*
raises *E_CACHEDB_PERF_SYNCED*. With no clusterer
or *sync_cluster_id* 0, *perf_sync*
still saves to the DB, just without the peer signal.


When active, the module's capability shows in the clusterer's
*clusterer_list_cap* MI command as
"cachedb-perf-sync". Note that the
*state* the clusterer reports there
("Ok") only means the capability is registered and
enabled: this module does not take part in the clusterer's
startup data-sync, so that field never reflects whether the caches
have converged. It would read "not synced" only if the
capability were disabled administratively. To see the sync activity
itself, use the *last_sync_out* /
*last_sync_in* / *last_sync_source*
fields of *perf_stats*, which report how many
seconds ago this node last pushed a snapshot and last reloaded one at
a peer's request (-1 = never), or subscribe to
*E_CACHEDB_PERF_SYNCED*. Between syncs the nodes
are expected to differ - convergence is on demand, by design.


Because it runs a full save first, *perf_sync*
carries the same blocking cost as *perf_save* (see
the warning under [DB persistence](#db-persistence)): it is an occasional
refresh, not something to fire on a timer or per request.


```opensips title="Cluster-sync setup (one authority, two read replicas)"
# on every node - clusterer must load before cachedb_perf (the module
# declares a soft dependency, so init order is handled either way):
loadmodule "clusterer.so"
modparam("clusterer", "my_node_id", 1)          # 2 and 3 on the other nodes
...
loadmodule "cachedb_perf.so"
modparam("cachedb_perf", "cache_collections", "profiles")
modparam("cachedb_perf", "db_url", "mysql://opensips:pw@dbhost/opensips")
modparam("cachedb_perf", "sync_cluster_id", 1)

# on the authority node, after it has updated the "profiles" collection:
#   opensips-cli -x mi cachedb_perf:perf_sync profiles
#     -> saves "profiles" to the DB, signals nodes 2 and 3 to reload it
#
# or from script (e.g. after a reload route), same save-then-broadcast:
#   perf_sync("profiles");
#
# the replicas raise E_CACHEDB_PERF_SYNCED when they finish reloading:
event_route[E_CACHEDB_PERF_SYNCED] {
    xlog("L_INFO", "reloaded $param(collection) from node $param(source_node)\n");
}
```


### Operation without the clusterer


The cache itself never depends on the cluster plane. Every cluster
feature - cross-node pull, the *perf_sync* peer signal and the
*sync_shtag* failover - rides the *clusterer* module. When it is not
loaded the module still starts, serves node-local traffic, and says at
startup exactly what it turned off:


```
WARNING:cachedb_perf:mod_init: clusterer module not available -
    the cluster features are disabled; load clusterer before
    cachedb_perf
WARNING:cachedb_perf:mod_init: replicate_collections is set but
    the cluster is not available (needs sync_cluster_id +
    clusterer) - cross-node pull disabled
```


(the second line only when *replicate_collections* is set; a
*sync_shtag* adds "clusterer module not available - failover sync
disabled").


*Unaffected either way*: every local surface.
The cachedb script API (cache_store / cache_fetch / cache_add /
cache_sub / cache_remove on "perf"), the glob functions (perf_del,
perf_mget, perf_mget_json), the local MI set (perf_get / perf_set /
perf_probe / perf_keys / perf_scan / perf_dump / perf_ttl / perf_del /
perf_stats / perf_stats_reset), DB persistence (perf_save / perf_load,
db_mode), and the four local events (E_CACHEDB_PERF_EXPIRED / NOMEM /
GROWN / MEM_DEGRADED).


*perf_pull* - with the clusterer, on a single node (or when no peer
holds the key) it reports where the answer did not come from; without
it, it refuses:


```json
# with the clusterer, no peer holding the key:
{ "source": "no-answer" }

# without the clusterer:
{ "code": 500,
  "message": "cross-node pull not active
              (replicate_collections)" }
```


*perf_cluster_probe* - with the clusterer it probes the peers (on a
lone node: error 500, "could not start the probe - no peers, or no free
pull slot"); without it, error 400, "cross-node pull is not active
for this collection (replicate_collections)".


*perf_sync* (MI and script function) - never fails
for cluster reasons. With the clusterer it saves and signals the peers;
without it, it degrades to the DB save alone and says so:


```json
# with the clusterer:
{ "collections": 2, "saved": 1, "broadcast": 2 }

# without the clusterer:
{ "collections": 2, "saved": 1, "broadcast": 0,
  "note": "cluster sync inactive (no clusterer /
           cluster_id 0) - saved to the DB only" }
```


*perf_stats* - the per-collection and memory
sections are the same either way (the pulled_from_cluster /
served_to_cluster counters simply stay 0 without a cluster).
The difference is the *cluster* object: present with the clusterer
(ids, membership, the pull counters and slot count, and a
topology array), absent without it.


```json
# with the clusterer only:
"cluster": {
    "cluster_id": 1, "my_node_id": 1, "peers_up": 0,
    ...
    "pull_slots": 64,
    "topology": [ { "node_id": 1, "role": "self", "membership": "up" } ]
}
```


*cache_fetch with pull_on_miss=1* - with the clusterer, a miss
on an opted-in collection blocks up to pull_timeout_ms asking the
cluster, exactly as documented under [pull_on_miss](#pull_on_miss-int).
Without it no pull exists, so a miss is a plain immediate miss - no
blocking, no timeout, no negative cache.


*E_CACHEDB_PERF_SYNCED* - only ever raised when a
peer's sync signal arrives, so it can never fire without the
clusterer. Subscribing to it costs nothing either way.


### Dependencies


#### OpenSIPS Modules


None required. Optional:


- *clusterer* - enables the cluster features:
cross-node pull, the perf_sync peer signal and the sync_shtag
failover hook. Without it the module runs purely node-local (see
[Operation without the clusterer](#operation-without-the-clusterer)).
- a *db_\** module, only when [db_url](#db_url-string) is set.


#### External Libraries or Applications


None.


### Exported Parameters


#### cache_collections (string)


Declares the collections and, optionally, their initial hash
table size, as a semicolon-separated list of
*name* or *name=size*
entries. The size is the power-of-2 exponent of the initial
bucket count (as in *cachedb_local*) and only
sets the starting point - the table grows at runtime as entries
accumulate. Values are clamped to the [4, 24] range; the default
is 14 (16384 buckets).


The *cachedb_local* replication marker ("/r") is not accepted here;
see [replicate_collections](#replicate_collections-string).


```opensips title="Set cache_collections parameter"
...
# "th" starts at 2^16 buckets, "profiles" at the default 2^14
modparam("cachedb_perf", "cache_collections", "th=16;profiles")
...
```


#### cachedb_url (string)


URL(s) usable from the script or by other modules. The collection
is given by the URL's database part
(*perf:///name*) or, equivalently, its host
part (*perf://name*) - a host has no meaning
for a local cache, so both forms select the collection. A URL
naming no collection (*perf://*) uses the
"default" collection. Naming an undefined collection
is a startup error. Multiple URLs may share one collection; use a
group (*perf:group_name:///name*) to address a
specific URL from the script.


```opensips title="Set cachedb_url parameter"
...
modparam("cachedb_perf", "cachedb_url", "perf:///th")
modparam("cachedb_perf", "cachedb_url", "perf:prof:///profiles")

# usage from script:
#   cache_store("perf", ...)        - collection "th"
#   cache_store("perf:prof", ...)   - collection "profiles"
...
```


#### expiry_sweep_period (int)


How often, in seconds, expired records are reclaimed. Expired
entries are already invisible to reads the moment they expire -
the sweep only frees their memory, guided by per-bucket hints so
idle collections cost next to nothing. Default is 1 second; 0
disables the sweep (expired records then hold their memory until
overwritten or deleted).


```opensips title="Set expiry_sweep_period parameter"
...
modparam("cachedb_perf", "expiry_sweep_period", 5)
...
```


#### growth_load_factor (int)


The target number of entries per bucket the maintenance timer grows
the table toward. As entries accumulate the timer splits buckets to
keep the load factor near this value, so lookups stay flat as the
cache scales - the behaviour *cachedb_local*
lacks. 0 disables growth, leaving the table fixed at its declared
size. Default is 2.


```opensips title="Set growth_load_factor parameter"
...
modparam("cachedb_perf", "growth_load_factor", 2)
...
```


#### growth_budget (int)


The maximum number of bucket splits the maintenance timer performs
on a single run, bounding the work of one growth pass so the timer
never stalls under a burst of inserts. Default is 4096.


```opensips title="Set growth_budget parameter"
...
modparam("cachedb_perf", "growth_budget", 4096)
...
```


#### arena_hugepage_mb (int)


Size, in megabytes, of a huge-page-backed reservation for the cache
entries. When set, the module reserves this much memory at startup
and backs it with 2 MB pages to cut TLB misses on a large cache. It
does not pick a mechanism: it climbs a detect-by-trying ladder -
overcommit hugetlb pool (*MAP_HUGETLB*) then
transparent huge pages (*MADV_HUGEPAGE*) then
*MADV_COLLAPSE* then plain 4 KB - and keeps the
best tier the running kernel actually grants, which it reports at
startup and through the *memory_tier_active* statistic
and *perf_stats*. 0 (default) uses plain
demand-faulted shared memory.


To make the faster tiers available: allow on-demand huge pages with
*sysctl vm.nr_overcommit_hugepages=N* (N >=
*arena_hugepage_mb*/2), and/or enable shmem THP
with *echo advise > /sys/kernel/mm/transparent_hugepage/shmem_enabled*.
Except for the hugetlb tier (which is unswappable and exempt), the
reservation is *mlock*-pinned against swap; that
needs *LimitMEMLOCK=infinity* in the systemd unit,
otherwise the module warns and runs the arena unpinned.


```opensips title="Set arena_hugepage_mb parameter"
...
modparam("cachedb_perf", "arena_hugepage_mb", 512)
...
```


#### reclaim_keep (int)


The module's allocator
cuts its memory into 256 KB slots, one size class per slot, and
keeps a free list per slot, so a slot whose every cell has come
home is provably drained. A reclaim process of the module's own
(*cachedb_perf reclaim*, one tick a second, off
every request path) retires drained slots beyond this many per
size class; a retired slot is re-cut for any class on the next
carve, so the footprint follows the peak total of the cache, not
the sum of every class's peak. The same count of whole shm pages
(16 slots) is kept resident instead of being given back. Default
1.


A process's private free stack and the remainder of the slot it
is carving from would pin their chunks for as long as that process
stays quiet, so when chunks linger partially home for a quiet
window the reclaim process asks every process, through the core's
IPC, to send its private cells home; the next allocation refills
from the arena. What stays after a mass expiry is therefore
bounded by this many drained slots per class, one spare page, and
the hash tables, which grow and never shrink.


```opensips title="Set reclaim_keep parameter"
...
modparam("cachedb_perf", "reclaim_keep", 4)
...
```


#### reclaim_quiet_s (int)


Seconds a retired slot has to
stay free before its memory is given back to the host: a whole 2 MB
group of the dedicated reservation is punched out with
*MADV_REMOVE* (the mapping stays, a later carve
re-faults it; hugetlb pages return to the pool), a whole shm page
goes back through *shm_free*. Carves take the
lowest free slot of the reservation and the fullest page, so the
give-back units do become empty. Default 5.


```opensips title="Set reclaim_quiet_s parameter"
...
modparam("cachedb_perf", "reclaim_quiet_s", 30)
...
```


#### reclaim_cooloff_s (int)


No memory is given back for
this many seconds after the last carve, so a release can never
re-trigger the growth that follows it. Default 10.


```opensips title="Set reclaim_cooloff_s parameter"
...
modparam("cachedb_perf", "reclaim_cooloff_s", 60)
...
```


#### reclaim_giveback (int)


0 keeps every retired slot
resident (re-cut for any class, never returned to the host); 1
(default) gives whole empty groups and pages back as described
under [reclaim_quiet_s](#reclaim_quiet_s-int). If the kernel
refuses *MADV_REMOVE* on the reservation the
module logs it once and behaves as 0 from then on.


```opensips title="Set reclaim_giveback parameter"
...
modparam("cachedb_perf", "reclaim_giveback", 0)
...
```


#### arena_selftest (int)


When set to 1, the slab arena runs a self-test at startup and aborts
startup on any mismatch - a permanent, cheap diagnostic. Default is 0
(off).


```opensips title="Set arena_selftest parameter"
...
modparam("cachedb_perf", "arena_selftest", 1)
...
```


#### htable_selftest (int)


When set to 1, the hash table and its runtime-growth machinery run a
self-test at startup and abort startup on any mismatch. Default is 0
(off).


```opensips title="Set htable_selftest parameter"
...
modparam("cachedb_perf", "htable_selftest", 1)
...
```


#### event_expired_collections (string)


Comma-separated list of the collections that raise
*E_CACHEDB_PERF_EXPIRED* (one event per reaped key)
as the sweep reclaims them. It is opt-in per collection because a
high-churn collection can reap in bulk, and event delivery is
synchronous - a collection should pay for the per-key events only if
something is listening for them. Empty (default) means no collection
raises the event. See [Exported Events](#exported-events).


```opensips title="Set event_expired_collections parameter"
...
modparam("cachedb_perf", "event_expired_collections", "sessions,subscriptions")
...
```


#### db_url (string)


URL of a *db_\** (SQL) backend used to persist
collections - see [DB persistence](#db-persistence). The matching
*db_\** module must be loaded. When unset,
persistence is disabled. The DB is a shared, durable store; the
in-memory cache is a view over it.


```opensips title="Set db_url parameter"
...
modparam("cachedb_perf", "db_url", "mysql://opensips:pw@localhost/opensips")
...
```


#### db_table (string)


Table that holds the persisted entries. Default is
"cachedb_perf". See [DB persistence](#db-persistence) for
the schema.


```opensips title="Set db_table parameter"
...
modparam("cachedb_perf", "db_table", "cache_snapshot")
...
```


#### db_mode (int)


Automatic persistence for the collections listed in
[persist_collections](#persist_collections-string): 0 = off (default;
load/save only on the *perf_load*/*perf_save* MI commands),
1 = load them from the DB at startup, 2 = load at startup and save on
a graceful shutdown.


```opensips title="Set db_mode parameter"
...
modparam("cachedb_perf", "db_mode", 2)
...
```


#### persist_collections (string)


Comma-separated list of the collections that
[db_mode](#db_mode-int) loads at startup and saves at
shutdown. Empty (default) means none are persisted automatically -
though *perf_save*/*perf_load*
still work on any collection on demand.


```opensips title="Set persist_collections parameter"
...
modparam("cachedb_perf", "persist_collections", "sessions,profiles")
...
```


#### sync_cluster_id (int)


Cluster to signal on *perf_sync* - see
[Cluster sync](#cluster-sync). 0 (default) = off. When set, the
*clusterer* module must be loaded (before
*cachedb_perf*) and [db_url](#db_url-string)
configured; if either is missing, *perf_sync*
degrades to a DB save with no peer signal (a soft dependency, never
fatal).


```opensips title="Set sync_cluster_id parameter"
...
loadmodule "clusterer.so"
loadmodule "cachedb_perf.so"
modparam("cachedb_perf", "sync_cluster_id", 1)
...
```


#### sync_shtag (string)


A clusterer sharing tag, as "name/cluster_id", that
arms the failover sync. A node whose tag turns
*active* warms every declared collection from
the DB snapshot before the redirected traffic arrives; a node
gracefully demoted to *backup* saves its
state and signals the peers to reload it - so a failover moves
the cache as one snapshot instead of a storm of misses.


Requires *db_url*. The tag only schedules
these bulk operations - lookups are never gated on its state.
On a crash failover the last saved snapshot is the only source,
so pair this with periodic *perf_save* (or
*db_mode* 2) on the active node.


*Default value is unset (failover sync off).*


```opensips title="Set sync_shtag parameter"
modparam("clusterer", "sharing_tag", "vip1/1=backup")
modparam("cachedb_perf", "sync_shtag", "vip1/1")
```


#### replicate_collections (string)


Comma-separated collections whose keys may be fetched from
another node when this one misses ("pull on miss").
Nothing is pulled unless it is listed here, and the default is
to list nothing.


This replaces *cachedb_local*'s "/r" collection suffix: declare
the collection in *cache_collections* as usual and list it here.
It is not per-operation replication - a node that misses a key
asks its peers for it.


The opt-in is deliberate and cannot be inferred: a key is only
worth asking the cluster about if it means the same thing on
every node. That holds for keys derived from the call - the
topology hiding state, for instance - and fails for anything a
script names after something local, where a peer's answer would
be wrong rather than merely useless. Values must be portable
too: a blob that embeds a node's own address is not.


Requires *sync_cluster_id* and the clusterer.


A pulled key is *kept*: the next request for it
is answered locally and the cluster is never asked again, which is
what makes this a repair rather than a relay. The copy keeps the
expiry the owner had - never a fresh lifetime - so it dies when
the original does instead of outliving it. Note the consequence
for sizing: as traffic spreads, every node tends toward holding
every key, so size the arena for the whole keyspace rather than
its share of it.


Native counters (created with *cache_add*) are
never served to a peer. A counter records what happened on the
node holding it, so handing it over would import one node's tally
into another; the requester is told the key is not there, which
from its side is true.


*Default value is unset (no collection is pulled).*


```opensips title="Set replicate_collections parameter"
...
# cachedb_local:  modparam("cachedb_local", "cache_collections", "th/r")
modparam("cachedb_perf", "cache_collections", "th")
modparam("cachedb_perf", "sync_cluster_id", 1)
modparam("cachedb_perf", "replicate_collections", "th")
...
```


#### pull_transport (string)


How cross-node pulls travel:


- *bin* (default when
[pull_bind](#pull_bind-string) is not set) - the clusterer's
BIN links: nothing to configure, but every request and reply is one
TCP message the core's TCP dispatcher hands to a receiver and back,
and those processes allocate per message. At a few thousand pulls a
second the dispatcher is one process at the edge of a core, the
receivers contend on the shared-memory allocator, and any stall on
the receiving side queues everything behind it. Measured on a
three-node 1,000,000-entry rig: pull p50 1.2 ms over bin, 0.75 ms
over udp. *bins* is the same choice - whether the
links are bin or bins is the clusterer's node URLs, not this
parameter.
- *udp* (recommended; the default
when *pull_bind* is set) - the module's own
datagram socket: requests leave the asking process directly, replies
arrive in a dedicated *cachedb_perf transport*
process that only parses, copies into the pull slot and wakes the
waiter. No core dispatcher, no allocator traffic on the way.
Loss is handled by [pull_timeout_ms](#pull_timeout_ms-int)
as for every transport. Payloads above the MTU ride on IP
fragmentation (DF cleared), which is for one LAN or a path the
operator knows passes fragments.
- *tcp* - the module's own stream
connections, one per direction per peer, owned by the transport
process (other processes hand it their sends through IPC): ordered,
reliable, no MTU ceiling on values.
- *tls* - reserved for the tcp
transport under TLS; refused at startup for now.


With udp and tcp the nodes learn each other's transport address
from a HELLO the module announces over the clusterer links (every
2 s until every cluster member is known, then every 30 s, and
whenever a node comes up); [pull_port](#pull_port-int) gives
an address to use before the first HELLO. The transport in use and
its counters are in *perf_stats*
(*pull_transport*, *pull_peers_known*,
*xport_tx* / *xport_tx_failed* /
*xport_rx* / *xport_rx_bad* /
*xport_tcp_connects* / *xport_tcp_accepts* /
*xport_tcp_errors*).


```opensips title="Set pull_transport parameter"
...
modparam("cachedb_perf", "pull_transport", "udp")
modparam("cachedb_perf", "pull_bind", "10.0.0.5:5580")
...
```


#### pull_bind (string)


The local *ip:port* (or *\[ip6\]:port*)
the module's own pull transport binds: the udp socket, or the tcp
listener. Setting it selects *udp* unless
*pull_transport* says otherwise; required for udp,
tcp and tls; announced to the peers in the HELLO.


```opensips title="Set pull_bind parameter"
...
modparam("cachedb_perf", "pull_bind", "10.0.0.5:5580")
...
```


#### pull_port (int)


Optional. A port to assume for a peer whose HELLO has not arrived
yet, combined with the peer's address from the clusterer's node
table: lets the first pulls after a start go out before the
announcements have converged when every node binds its transport
on the same port. An announced address always outranks the
assumption. Default 0 (wait for the HELLO).


```opensips title="Set pull_port parameter"
...
modparam("cachedb_perf", "pull_port", 5580)
...
```


#### pull_timeout_ms (int)


How long a pull waits for the cluster, in milliseconds (1..5000).
It is a backstop, not the normal cost: with every peer answering
either way, a pull finishes as soon as the last one has spoken -
on a LAN, in a couple of milliseconds. The timeout only decides
how long an unanswered request lingers.


*Default value is "50".*


```opensips title="Set pull_timeout_ms parameter"
...
modparam("cachedb_perf", "pull_timeout_ms", 20)
...
```


#### pull_slots (int)


How many pulls may be in flight at once (8..16384). A miss that
finds the pool dry is not queued - it is answered as a miss, and
counted in *pulls_skip_noslot*.


The default suits the blocking mode, where concurrency is capped
by the worker count anyway. Asynchronous users
(*async()* script wrappers over this module's
pull API) suspend transactions instead of workers, so hundreds of
pulls can be in flight at once: size this for the expected
concurrent miss burst - the peak miss rate times
*pull_timeout_ms* - not for the worker count.
Each slot costs roughly *pull_max_key* +
*pull_max_value* bytes of shared memory, plus one
file descriptor *in every OpenSIPS process*: the
wakeup eventfds must be created before the fork, so a reply landing
in any process can wake the one that asked. A large pool therefore
needs a matching *open_files_limit*; startup fails
with a clear error when the fd limit is too low.


*Default value is "64".*


```opensips title="Set pull_slots parameter"
...
modparam("cachedb_perf", "pull_slots", 512)
...
```


#### pull_max_key (int)


The longest key, in bytes, that can be pulled from the cluster
(1..256). It sizes every pull slot, so it is a per-slot memory cost,
not just a limit; a miss on a longer key is not asked for and counts
in *pulls_skip_toolong*. Set the same value on every node.


*Default value is "128".*


```opensips title="Set pull_max_key parameter"
...
modparam("cachedb_perf", "pull_max_key", 64)
...
```


#### pull_max_value (int)


The largest value, in bytes, a pull can carry (1..8192). Like
*pull_max_key* it sizes every pull slot. A peer
holding a larger value answers that it has the key but cannot ship
it, counted in *pulls_oversize* - the cost is a key
not pulled cross-node, never a wrong answer. Collections of large
serialised values (*dns_cache*, for instance) need
this raised on every node.


*Default value is "512".*


```opensips title="Set pull_max_value parameter"
...
modparam("cachedb_perf", "pull_max_value", 4096)
...
```


#### pull_authoritative_serve (int)


In a converged cluster several nodes hold most keys, and a
broadcast pull is answered by every one of them - with the full
value each, of which the requester uses exactly one. With this
set, a node answers with the value only for keys it
*wrote* (its own *set()*s -
the authoritative copies); for a copy that arrived through a
pull it answers a compact "held" instead, so each
pull moves one value however many nodes hold the key.


A "held" answer still proves the key exists. When
every peer has answered and only held copies were on offer - the
writer is dead, or restarted empty - the requester re-asks one of
the holders directly with a force flag and receives the value:
one extra LAN round trip, paid only in the degraded case.
Counters: *pulls_served_held* (this node
withheld a passive copy), *pulls_held* (held
answers received), *pulls_forced* (follow-up
targeted asks).


Off by default, and it must stay off until *every*
cluster member runs a build that understands the held answer: an
older peer treats it as silence and degrades to a pull timeout
whenever no authoritative holder is left. Entries restored from
DB persistence lose the passive mark and are served as
authoritative again - harmless, it merely restores the old
every-holder-answers behavior for those keys.


*Default value is "0" (every holder answers with the value).*


```opensips title="Set pull_authoritative_serve parameter"
...
modparam("cachedb_perf", "pull_authoritative_serve", 1)
...
```


#### pull_linger_ms (int)


A pull whose answer arrives after
*pull_timeout_ms* is no longer anyone's answer -
the caller has moved on - but it is still a perfectly good value.
The module keeps the request slot around and stores such a late
answer into the cache, so the next lookup hits locally instead of
asking the cluster again. Without this, the cache never converges
on exactly the keys that are hardest to fetch.


This parameter is an *optional* extra bound on
how late is too late, in milliseconds past the pull timeout. The
default of "0" means no time bound: what makes a late
answer valid is that the *value* is still
valid, and the value carries its own expiry, computed against
this node's clock. The practical ceiling is the request slot's
own lifetime.


Set it non-zero only where the script *deletes*
keys from a replicated collection: a late store cannot tell
"never had it" from "deleted a moment
ago", so a peer's copy could resurrect a key the script
removed. A deployment that only writes and lets TTLs expire
cannot hit that. A late answer never overwrites a live local
entry in any case - it fills gaps, it does not compete with
fresher writes.


*Default value is "0" (no extra bound).*


```opensips title="Set pull_linger_ms parameter"
...
modparam("cachedb_perf", "pull_linger_ms", 200)
...
```


#### pull_negative_ms (int)


How long to remember that the whole cluster answered "not
here" for a key, in milliseconds (0..2000; 0 disables it).
A SIP retransmit asks the same question a few hundred
milliseconds later, and without this every retransmit repeats the
round of questions.


Keep it short. A key may legitimately be created on another node
a moment from now, and a negative that outlives that turns a
transient miss into a hard failure - which is why the parameter
is capped rather than left open. Only a verdict the whole
cluster gave is remembered: a timeout is not absence, and neither
is an answer from a set of nodes that has since changed. A local
write to the key clears it at once.


Negatives are held outside the cache, so they never appear in
*perf_keys* or *perf_dump*
and never count as entries.


*Default value is "300".*


```opensips title="Set pull_negative_ms parameter"
...
modparam("cachedb_perf", "pull_negative_ms", 500)
...
```


#### pull_on_miss (int)


Repair a miss on the ordinary read path: when a lookup finds
nothing locally, ask the cluster and return whatever comes back
as though it had been here all along. A consumer needs no
changes - cross-node lookups simply start working for the
collections listed in
[replicate_collections](#replicate_collections-string).


> [!WARNING]
> Off by default, and it should stay off on a SIP path for now.
> The lookup blocks until the cluster
> answers or *pull_timeout_ms* elapses, and a
> blocked lookup means a process serving nothing else in the
> meantime. A LAN pull takes a couple of milliseconds and the
> negative cache absorbs retransmits, but that is a statement about
> the common case, not a guarantee under load. Enable it for
> maintenance, migration or test paths; a startup warning repeats
> this when it is on.


*Default value is "0" (disabled).*


```opensips title="Set pull_on_miss parameter"
...
modparam("cachedb_perf", "pull_on_miss", 1)
...
```


### Exported Functions


Single-key operations go through the core cache functions
(*cache_store()*,
*cache_fetch()*, ...) with the
"perf" backend. The functions below are the module's
own glob (multi-key) operations. All of them match keys with
shell-style globs (*fnmatch*), walk the table
lock-free and give the Redis SCAN class of guarantee: an entry
mutated concurrently may be seen once, twice or not at all.
Unlike *cachedb_local*'s
*cache_remove_chunk()*, these are
*perf_*-prefixed - scripts migrating from
*cachedb_local* must rename those calls.
When the optional *collection* argument is
omitted, they operate on the collection of the default
(groupless) *cachedb_url* - exactly where
*cache_store("perf", ...)* writes.


#### perf_del(glob[, collection])


Deletes every key matching the glob (expired entries included).
Returns the number of keys removed, or -1 (false) if none
matched.


Parameters:


- *glob* (string)
- *collection* (string, optional)


This function can be used from any route.


```opensips title="perf_del() usage"
...
perf_del("session-*");
perf_del("th-*", "th");
...
```


#### perf_mget(glob, keys_avp, vals_avp[, collection[, limit]])


Returns every live key/value pair matching the glob into two
writable variables (use AVPs - each match adds one value to
each, and the indexes correspond pairwise; ordering is
unspecified). *limit* bounds the number of
matches, default 1000, 0 = unbounded. Returns the match count,
or -1 (false) if none matched.


Parameters:


- *glob* (string)
- *keys_avp* (var)
- *vals_avp* (var)
- *collection* (string, optional)
- *limit* (int, optional)


This function can be used from any route.


```opensips title="perf_mget() usage"
...
if (perf_mget("user-*", $avp(k), $avp(v))) {
    xlog("first match: $(avp(k)[0]) = $(avp(v)[0])\n");
}
...
```


#### perf_mget_json(glob, dst_var[, collection[, limit]])


Like *perf_mget()*, but returns all matches
as one JSON object *{"key":"value",...}* in a
single writable variable (*{}* when nothing
matches). Quote, backslash and control bytes are escaped, so
binary values survive; bytes above 0x7F pass through unescaped -
strict JSON consumers therefore need UTF-8 values. Returns the
match count, or -1 (false) if none matched.


Parameters:


- *glob* (string)
- *dst_var* (var)
- *collection* (string, optional)
- *limit* (int, optional)


This function can be used from any route.


```opensips title="perf_mget_json() usage"
...
if (perf_mget_json("user-*", $var(blob), , 100))
    xlog("users: $var(blob)\n");
...
```


#### perf_sync([collection])


Saves a collection to the DB and signals the cluster to reload it -
the script face of the *perf_sync* MI command (see
[Cluster sync](#cluster-sync)); every declared collection if none is
named.


Parameters:


- *collection* (string, optional)


This function can be used from any route.


```opensips title="perf_sync() usage"
...
perf_sync("profiles");
...
```


### Exported MI Functions


#### cachedb_perf:perf_stats


Reports per-collection statistics (entries, buckets, overflow,
hits/misses/stores/removes, load factor, seqlock retries and
retries-per-1k-reads) plus the arena occupancy and the achieved
memory tier. With no parameter it reports every collection; an
optional collection name restricts it to one.


It also reports *hit_rate_pct* - hits / (hits + misses) as a
percentage. On a healthy server the large majority of lookups hit
(upwards of 80% under steady dialog traffic); a persistently low or
falling hit rate means the cached state is being lost or is expiring
before it is used. The same guidance rides inline in the
*hit_rate_note* field.


Parameters:


- *collection* (optional)


```bash
opensips-cli -x mi cachedb_perf:perf_stats
opensips-cli -x mi cachedb_perf:perf_stats th
```


#### cachedb_perf:perf_stats_reset


The counters behind *perf_stats* - hits,
misses, stores, removes, expired, destroyed, retries - are
running totals since startup, so every rate derived from them is
a lifetime average. A burst of misses right after a restart, when
sequential requests arrive for dialogs older than the cache,
keeps dragging the hit rate down long after the cache has
recovered. This command re-baselines them so the next reading
covers a fresh interval, without restarting OpenSIPS.


The counters themselves are not rewound: each process owns its
own counter cache line and must never have it written from
another process. Only a baseline is recorded, and the reported
figures are the difference. Live gauges - entries, buckets,
overflow, load factor and the arena figures - are read from
current state rather than from the counters, so a reset does not
disturb them.


Parameters:


- *collection* (optional) - with no parameter every collection is reset


```bash
opensips-cli -x mi cachedb_perf:perf_stats_reset
opensips-cli -x mi cachedb_perf:perf_stats_reset th
```


#### Key introspection


The commands below give an operator the visibility that
*cachedb_local* lacks. All are lock-free: the
walkers take no bucket locks (seqlock reads), so unlike a
*cachedb_local* key scan they never stall SIP
traffic. Every command carries the *perf_* prefix,
matching the script functions and staying clear of the core's bare
*get*/*set*. The optional
*collection* selects the table; omitted, it is the
groupless *cachedb_url*'s collection.


- *cachedb_perf:perf_keys glob [collection] [limit]*
- names (and TTL) of the keys matching a shell glob, bounded (default
1000; the reply carries a note when it truncates). The
*KEYS* equivalent.
- *cachedb_perf:perf_scan cursor [glob] [count]*
- cursored incremental iteration with Redis *SCAN*
semantics over the default collection: start with cursor 0 and
repeat with the returned cursor until it comes back 0. An entry
present throughout is returned at least once; *count*
bounds the buckets visited per call. This is the answer for a large
cache, where *perf_keys* would truncate.
- *cachedb_perf:perf_dump glob [collection] [limit]*
- like *perf_keys* but includes the values;
values are opt-in, never the default.
- *cachedb_perf:perf_get key [collection]*
- one key: its value, remaining TTL (-1 = never) and size.
- *cachedb_perf:perf_probe key [collection]*
- is the key here: its size and remaining TTL, but never the value.
Not merely a cheaper *perf_get* - it shares the
whole read path (same optimistic loop, lock fallback and expiry
rules) and stops before the copy-out, so it cannot disagree with a
read about whether a key is present; it allocates nothing and never
touches the record's payload. Use it to answer "do you have
this key?", where a read would pay for bytes nobody
wants.
- *cachedb_perf:perf_set key value [ttl] [collection]*
- write one key; *ttl* is seconds (0 or omitted =
never expires).
- *cachedb_perf:perf_ttl glob ttl [collection]*
- re-arm the TTL of every key matching the glob without rewriting its
value (one atomic expiry store under the bucket lock, so lock-free
readers are undisturbed); *ttl* is seconds (0 =
never). Returns the count updated; a literal key matches exactly
one.
- *cachedb_perf:perf_del glob [collection]*
- delete every key matching the glob; returns the count. The MI face
of the *perf_del()* script function.


```bash
opensips-cli -x mi cachedb_perf:perf_keys "session-*"
opensips-cli -x mi cachedb_perf:perf_keys "session-*" th 50
opensips-cli -x mi cachedb_perf:perf_scan 0
opensips-cli -x mi cachedb_perf:perf_scan 384 "user-*" 128
opensips-cli -x mi cachedb_perf:perf_dump "profile-*"
opensips-cli -x mi cachedb_perf:perf_get session-abc123
opensips-cli -x mi cachedb_perf:perf_set greeting hello 300
opensips-cli -x mi cachedb_perf:perf_ttl "session-*" 1800
opensips-cli -x mi cachedb_perf:perf_del "session-abc*"
```


#### cachedb_perf:perf_pull


Fetches one key from the cluster, for a collection listed in
*replicate_collections*. Reports where the answer
came from: *local* (this node had it after all),
*cluster* (a peer had it, with its remaining
TTL), *absent* (every peer answered, none has
it) or *no-answer* (nobody answered in time, or
there was nobody to ask). The last two are deliberately different:
absence is a fact only when the whole cluster has said so.


Parameters:


- *key*
- *collection* (optional)


```bash
opensips-cli -x mi cachedb_perf:perf_pull session-abc123 th
```


#### cachedb_perf:perf_cluster_probe


Asks every peer for a key that cannot exist, to see which ones
actually answer a pull. Reports how many were asked and answered,
the timeout and transport in use, and per peer whether it answered
the probe.


Parameters:


- *collection* (optional)


```bash
opensips-cli -x mi cachedb_perf:perf_cluster_probe th
```


#### cachedb_perf:perf_cluster_size


Asks every cluster member for its LIVE entry count in one collection
and reports them side by side, the local count included. For a
replicated collection this is the convergence gauge: each node's
count climbs toward the full set as its pulls decay toward zero.
Because the answers are live there is nothing to age or interpret -
a node that does not answer within the wait is exactly as
unreachable as it would be for a pull, and is listed with
*no reply* (the reported total then says it
covers the answering nodes only). One query runs at a time; it is
an operator path.


Parameters:


- *collection*


```bash
opensips-cli -x mi cachedb_perf:perf_cluster_size ul
{ "collection": "ul",
  "nodes": [
    { "node_id": 2, "entries": 25350, "source": "local" },
    { "node_id": 1, "entries": 25350 },
    { "node_id": 3, "status": "no reply" } ],
  "peers_answered": 1, "peers_asked": 2,
  "total_entries": 50700,
  "note": "total covers answering nodes only" }
```


#### cachedb_perf:perf_save / cachedb_perf:perf_load


Persist a collection to, or restore it from, the
[db_url](#db_url-string) backend (see
[DB persistence](#db-persistence)). With no argument they operate on
every declared collection; with a collection name, only that one.
The reply reports how many collections and entries were written or
read.


Parameters:


- *collection* (optional)


```bash
opensips-cli -x mi cachedb_perf:perf_save
opensips-cli -x mi cachedb_perf:perf_save sessions
opensips-cli -x mi cachedb_perf:perf_load sessions
```


#### cachedb_perf:perf_sync


Save a collection to the DB and signal the cluster to reload it (see
[Cluster sync](#cluster-sync)); all declared collections if none is
named. Also available as the *perf_sync()* script function.


Parameters:


- *collection* (optional)


```bash
opensips-cli -x mi cachedb_perf:perf_sync sessions
```


### Exported Statistics


All counters are aggregated per-process and summed only when read,
so instrumentation never touches a shared cache line on the hot
path. Query with *get_statistics cachedb_perf:*.
The *perf_stats* MI command gives the same figures broken down per
collection, plus load factor, overflow occupancy, retries-per-1k-reads
and the memory-backing description.


#### hits / misses


Fetch outcomes (expired counts as a miss).


#### stores / removes


Write and explicit delete operations (*removes* counts only
*remove*/*perf_del*, never TTL expiry).


#### expired


Records reclaimed by the TTL expiry sweep (this is where timed-out keys
are accounted, separate from *removes*).


#### destroyed


Total records whose cells were freed back to the arena, from any cause;
it equals *removes* + *expired*. Overwriting an existing key does not
count here (the cell is reused in place), so *entries* = created -
*destroyed*. A large gap between *stores* and *entries* with a small
*destroyed* means most churn is same-key overwrites rather than expiry
or deletes.


#### stores_immortal


Stores made with an expiry of 0, i.e. records that never time out. This
is a count of store OPERATIONS, not a live population: such a record can
still be dropped by an explicit remove (accounted in *removes*, never in
*expired*), and re-storing a key with a TTL does not unwind the earlier
count. Its purpose is to give *expired* an honest denominator - on a
collection mixing timed and never-expiring records, measuring expiry
against every store understates it, which is why *perf_stats* reports
*expired_pct_of_expirable* rather than a share of all stores.


#### entries


Live records across all collections.


#### seqlock_retries


Optimistic-read retries (the contention signal).


#### lock_fallbacks


Reads that fell back to the bucket lock.


#### arena_bytes / arena_chunks


Memory taken by the cache's chunks. Where that memory comes from -
OpenSIPS shared memory, or the separate arena of
[arena_hugepage_mb](#arena_hugepage_mb-int) - is reported at startup
and as *arena.backing* in *perf_stats*.


The *arena* object of *perf_stats* also
reports the reclaim state: *slots_total*, *slots_free_warm*
(retired, resident), *slots_free_cold* (retired, punched out),
*chunks_strand* (slots held by classes with nothing live - the
class-mix ratchet), *chunks_retired*, *flush_broadcasts* (rounds of
asking every process to send its private cells home), *pages* /
*pages_freed*, *released_bytes* (cumulative give-back),
*cold_bytes*, *reclaim_ticks*, *last_carve_age_s*, and *classes* =
"size:slots/peak/cells_not_home" per class in use (cells not home are
live records plus what processes hold privately - their free stacks
and the remainder of the slot each is carving from).


#### memory_tier_probe / memory_tier_active


The huge-page tier the host was probed for, and the one the module's
own arena actually runs on (1 hugetlb .. 4 plain 4K). They differ when
*arena_hugepage_mb* could not be satisfied.


#### hugepage_arena_active / hugepage_arena_total_bytes / hugepage_arena_used_bytes / hugepage_arena_free_bytes


The module's own hugepage arena, which is SEPARATE from the OpenSIPS
shm arena. Records live in one or the other, never both, so these do
not add to *arena_bytes*.


#### Cross-node pull statistics


These exist only when *pull_on_miss* is enabled.
They are grouped so that two identities hold, which is the point of
having them: every miss is accounted on the way out, and every
request is accounted on the way back. A missing counter here is not
cosmetic - it is a miss that vanished.


- *pulls_requested* - misses that turned into a request on the wire.
*pulls_served* - requests from peers this node answered.
- *pulls_suppressed* - asks absorbed by an already-cached negative
(*pull_negative_ms*); the second and later asker for a key a peer has
already denied.
- *pulls_skip_notreplicated*, *pulls_skip_toolong*,
*pulls_skip_nopeers*, *pulls_skip_noslot* - misses refused at the
gate before anything was sent. They are kept apart because each calls
for a different action: pull is off for that collection; the key or
collection name is too long to ask for at all; no live cluster member
to ask; or the slot table is full and nothing was evictable.
- *pulls_received* - a value came back. *pulls_negative* - a peer
answered that it does not have the key. *pulls_oversize* - a peer has
it but it exceeds the cluster transport limit. *pulls_timed_out* -
nothing came back in *pull_timeout_ms*. *pulls_send_failed* - the
transport refused the datagram, so no peer was ever asked.
*pulls_held* - a peer answered that it holds a passive copy but defers
to the authoritative holder (*pull_authoritative_serve*); its
serve-side twin is *pulls_served_held*. *pulls_forced* - every peer
answered yet only held copies were on offer, so one holder was
re-asked directly with the force flag.
- *pulls_stored* - answers written into the cache. *pulls_in_flight* -
requests outstanding right now (a gauge, not a total).
- *pulls_orphaned* - a waiter gave up but the slot was kept in case the
answer still arrives, for *pull_linger_ms*. Its outcomes:
*pulls_late_stored* (arrived and was stored - convergence that would
otherwise be lost), *pulls_late_superseded* (a local write had already
filled the key), *pulls_late_expired* (arrived past the linger and was
refused as stale), *pulls_orphan_expired* (no late answer ever came -
the ordinary end of a timeout), *pulls_orphan_evicted* (the slot was
reclaimed early because the pool ran dry).
- *pulls_abandoned* - slots the reaper released because the caller
never collected them. Distinct from a timeout, which the caller DID
collect: a non-zero value here is a defect signal, not tuning.


The two identities:


```
misses          = pulls_requested + pulls_suppressed
                  + pulls_skip_notreplicated + pulls_skip_toolong
                  + pulls_skip_nopeers + pulls_skip_noslot

pulls_requested = pulls_received + pulls_negative + pulls_oversize
                  + pulls_timed_out + pulls_send_failed + pulls_in_flight
```


The second holds exactly on a two-node cluster.
*pulls_negative* is counted per REPLY, so with
more peers one request can raise it more than once.


### Exported Events


Every event is gated by *evi_probe_event()*, so
with no subscriber it costs a single shared read and nothing more;
none of them sit on the lock-free get/set path.


#### E_CACHEDB_PERF_EXPIRED


Raised by the sweep for each expired record it reclaims, but only for
the collections named in
[event_expired_collections](#event_expired_collections-string) (opt-in,
since a high-churn collection reaps in bulk and delivery is synchronous).


Parameters:


- *collection*
- *key*


#### E_CACHEDB_PERF_NOMEM


Raised when a write is dropped because the arena is full - the cache
is out of memory and rejecting stores. One event per dropped write
(subscribers should expect bursts under memory pressure).


Parameters:


- *collection*
- *key*
- *size* - the value's byte length


#### E_CACHEDB_PERF_GROWN


Raised by the maintenance timer after it grows a collection's table.


Parameters:


- *collection*
- *prev_buckets*
- *buckets*
- *splits*
- *entries*


#### E_CACHEDB_PERF_MEM_DEGRADED


Raised once at startup when
*arena_hugepage_mb* was set but the arena settled
on a tier below hugetlb (missing *vm.nr_overcommit_hugepages*,
for instance) - the node is running slower than intended.


Parameters:


- *requested_mb*
- *tier* - 1 hugetlb .. 4 plain 4K
- *backing* - its description
- *overcommit_pages*


#### E_CACHEDB_PERF_SYNCED


Raised on a node that reloaded a collection from the DB because a peer
issued *perf_sync* (see [Cluster sync](#cluster-sync)).


Parameters:


- *collection*
- *source_node* - the cluster id of the node that issued the sync
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
