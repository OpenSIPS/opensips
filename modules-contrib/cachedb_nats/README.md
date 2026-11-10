---
title: "cachedb_nats Module"
description: "The cachedb_nats module implements the OpenSIPS CacheDB engine interface on top of NATS JetStream Key-Value stores."
---

## Admin Guide


### Overview


The *cachedb_nats* module implements the OpenSIPS CacheDB
engine interface on top of *NATS JetStream Key-Value* stores.
It provides persistent, replicated, cluster-aware key-value storage accessible
from OpenSIPS routing scripts via the standard
`cache_store`/`cache_fetch`/`cache_remove`
operations, together with several NATS-native extensions.


The module connects to a NATS JetStream-enabled server or cluster, creates a
named KV bucket on first use, and maps all CacheDB operations onto NATS KV
primitives.  Reconnection and bucket handle refresh are fully automatic:
an epoch-based staleness check at the top of every operation transparently
re-opens the KV handle after any NATS disconnect/reconnect cycle.


Beyond the standard CacheDB API the module provides:


- **Atomic CAS counters** —
`cache_add` and `cache_sub`
use compare-and-swap with a configurable retry budget
([cas_retries](#cas_retries-integer), default 10), giving safe concurrent
counter increments from multiple OpenSIPS worker processes.
- **JSON secondary index (optional)** —
when the [cachedb_nats_fts](../cachedb_nats_fts/README.md) module is
loaded, JSON documents stored under keys that begin with
[fts_json_prefix](#fts_json_prefix-string) are indexed in shared memory, and
`cache_query` answers equality filters on their string fields from
the index.  Primary-key lookups always go straight to `kvStore_Get`.
Any other filter -- integer values, ranges (`<`, `<=`, `>`, `>=`), or
every non-key filter when *cachedb_nats_fts* is not loaded (the usual
choice for usrloc) -- is answered by one pass over the documents under
[fts_json_prefix](#fts_json_prefix-string).  This is how usrloc's NAT
pinging query (`aorhash` in a range) is served.
- **Live KV watcher** —
with [kv_watch](#kv_watch-string) set, a dedicated process watches the
bucket, raises the [E_NATS_KV_CHANGE](#e_nats_kv_change) event for every
put, delete and purge, and keeps the *cachedb_nats_fts* index (if
loaded) in step with writes made by other OpenSIPS instances.
- **[nats_kv_history()](#nats_kv_historykey-result_pvar)** —
retrieves the version history of a KV key as a JSON array.
- **Raw query commands** —
*KV KEYS*, *KV PURGE*, and
*KV BUCKET INFO* via
`cache_raw_query` (see [Raw Query Commands](#raw-query-commands)).
- **Map operations** —
composite *key:subkey* addressing for get, set,
and remove of individual fields within JSON documents.


### TLS


NATS-side TLS for *cachedb_nats* is
configured via OpenSIPS's central *tls_mgm*
module — the same way *proto_tls*,
*event_rabbitmq*,
*rest_client*, and other TLS-using modules
do it.  *cachedb_nats* does not carry its
own `tls_*` modparams.


To use TLS, define a *tls_mgm* client
domain named `"nats"`, and either set [nats_url](#nats_url-string) to
`tls://` URLs or, without a nats_url, add `?tls_domain=nats` to the
[cachedb_url](#cachedb_url-string) (the *cachedb_redis* syntax).  All
NATS modules share one connection, so `"nats"` is the only domain
name accepted.


```opensips title="tls_mgm-driven NATS TLS"
loadmodule "tls_mgm.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "certificate", "[nats]/etc/opensips/nats-cert.pem")
modparam("tls_mgm", "private_key", "[nats]/etc/opensips/nats-key.pem")
modparam("tls_mgm", "ca_list",     "[nats]/etc/opensips/nats-ca.pem")
modparam("tls_mgm", "verify_cert", "[nats]1")

loadmodule "tls_openssl.so"

loadmodule "nats.so"
loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats://nats.example.org:4222/")
modparam("cachedb_nats", "nats_url", "tls://nats.example.org:4222")
```


```opensips title="TLS from cachedb_url alone"
loadmodule "nats.so"
loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url",
    "nats://nats1.example.org:4222,nats2.example.org:4222/?tls_domain=nats")
```


Plaintext-only deployments (`nats://` URLs)
don't need *tls_mgm* loaded —
*cachedb_nats* declares it
`DEP_SILENT` and only attempts the lookup
when a `tls://` URL is actually used.
Operators who configure `tls://` without a
*tls_mgm* "nats" domain see a clear error
at connect time pointing at the missing config.


*tls_mgm*'s
`ca_directory` field (a directory of PEM
files) is supported: *cachedb_nats* reads
every `.pem` in the directory in
lexicographic order, concatenates the contents in memory,
and hands the result to libnats via the PEM-string API.
This mirrors OpenSSL's
`SSL_CTX_load_verify_locations(NULL, dir)`
semantics.


### CacheDB Operations


All standard OpenSIPS CacheDB script functions are supported.  The
engine identifier in every call must match the group name used in
[cachedb_url](#cachedb_url-string) (default: *nats*).


#### KV Key Validation


NATS KV keys may contain only letters, digits and the characters
`.` `_` `-` `/` `\` `=`, must not be empty, and must not start or
end with a dot or contain two dots in a row.  Dots separate tokens
(`call.abc123`, `counter.calls.alice`).  An operation with an invalid
key fails with -1 and an error in the log.


SIP values rarely fit these rules: a Call-ID usually contains `@`,
and an E.164 user part starts with `+`.  Hash such values before
using them in a key, for example `"call.$(ci{s.md5})"`.


#### cache_store — KV put


Stores a string value under the given key in the NATS KV bucket.
The key may contain letters, digits and `.` `_` `-` `/` `\` `=` only
(see [KV Key Validation](#kv-key-validation)).
If the key already exists it is overwritten.


`cache_store` itself does not touch the search index.  With
*cachedb_nats_fts* loaded and a [kv_watch](#kv_watch-string) pattern
covering the key, a JSON object stored under
[fts_json_prefix](#fts_json_prefix-string) is indexed when the watcher
sees the put.


```opensips title="cache_store with nats"
...
# Plain key-value
cache_store("nats", "call.$(ci{s.md5})", "$fu|$tu");

# JSON document (indexed by the watcher: key starts with "json_")
cache_store("nats", "json_user.alice",
    "{\"name\":\"alice\",\"domain\":\"example.com\",\"status\":\"active\"}");
...
```


#### cache_fetch — KV get


Retrieves the current value of a key from the NATS KV bucket and
stores it in the given pseudo-variable.  Returns 1 on success, -2
if the key does not exist, and -1 on error.


```opensips title="cache_fetch with nats"
...
cache_fetch("nats", "call.$(ci{s.md5})", $var(call_info));
if ($retcode == -2) {
    xlog("no active call record for $ci\n");
}
...
```


#### cache_remove — KV delete


Removes a key from the NATS KV bucket.  The operation is a soft
delete that creates a deletion tombstone while preserving revision
history.  Use the [KV PURGE](#kv-purge-key) raw query command to
permanently remove a key and its full history.


```opensips title="cache_remove with nats"
...
cache_remove("nats", "call.$(ci{s.md5})");
...
```


#### cache_add — atomic counter increment


Atomically increments an integer counter stored in the KV bucket.
The operation uses compare-and-swap (CAS) with up to
[cas_retries](#cas_retries-integer) retry
attempts, safely handling concurrent increments from multiple OpenSIPS
worker processes.  If the key does not yet exist it is created with
an initial value equal to *increment*.


The counter is stored as a plain decimal integer string in the KV
bucket.  The *expires* argument is accepted for
API compatibility but does not set a per-key TTL (see
[kv_ttl](#kv_ttl-integer)).


```opensips title="cache_add with nats"
...
cache_add("nats", "counter.calls.$(fU{s.md5})", 1, 0);
cache_counter_fetch("nats", "counter.calls.$(fU{s.md5})", $var(call_count));
xlog("$fU has $var(call_count) active calls\n");
...
```


#### cache_sub — atomic counter decrement


Atomically decrements an integer counter.  Equivalent to
`cache_add` with a negated increment value.
Uses the same [cas_retries](#cas_retries-integer) budget as
`cache_add` (default 10).


```opensips title="cache_sub with nats"
...
cache_sub("nats", "counter.calls.$(fU{s.md5})", 1, 0);
...
```


#### cache_counter_fetch — read counter value


Reads the current integer value of a counter key.  Returns 1 on
success (counter value in pvar), -2 if the key does not exist, and
-1 on error.


```opensips title="cache_counter_fetch with nats"
...
cache_counter_fetch("nats", "counter.calls.$(fU{s.md5})", $var(n));
if ($var(n) > 5) {
    sl_send_reply(503, "Too Many Calls");
    exit;
}
...
```


### Map Operations


The module implements the CacheDB map API (`map_get`, `map_set`,
`map_remove`) with the semantics of *cachedb_redis*, so the modules
that use it, *b2b_entities* and *b2b_logic* (their
[cachedb_url](../../modules/b2b_entities/README.md#cachedb_url-str) parameter), keep
their state in NATS and restore it at startup.


A map is a set of fields (a row) under a map key.  Each field is
stored as its own KV entry, `_map.enc(key).enc(field)`, and group
membership as `_mapgrp.enc(group).enc(key)`; `enc()` hex-escapes every
byte that is not valid in a KV key, so keys and fields may contain any
byte.  Values keep their type: string (binary-safe), 32-bit integer or
null.


- *map_set(key, group, fields)* - writes each field (the other fields of
the map are kept); with a group, also records the map as a member of
it.
- *map_get(key)* - returns one row per map: a single pair named after
the map key, holding the fields.  Without a key it returns every map in
the bucket (what b2b does at startup).
- *map_remove(key)* deletes a map; *map_remove(key, group)* also drops
its group membership; *map_remove(NULL, group)* deletes every map of the
group.  Removing what does not exist succeeds.


> [!NOTE]
> b2b loads its state in `mod_init`, before OpenSIPS forks its
> processes.  The NATS connection made for that is closed before the
> fork, and every process then connects on its own.


### JSON Search Index


When the optional [cachedb_nats_fts](../cachedb_nats_fts/README.md)
module is loaded, JSON documents stored under keys that begin with
[fts_json_prefix](#fts_json_prefix-string) are indexed in shared memory:
every top-level *string* field becomes a *field:value* entry pointing at
the document key.  Numbers, booleans and nested values are not indexed.


The index answers the CacheDB `query()` and `update()` calls that
OpenSIPS modules make with non-key filters, using equality matching
only.  There is no script function for it: `cache_store`,
`cache_fetch` and `cache_raw_query` do not consult the index.
Without *cachedb_nats_fts*, those calls accept only single
primary-key equality filters (the form usrloc uses to load a
record), which go straight to `kvStore_Get`; any other filter is
rejected with an error.


**Index lifecycle:**


- *Startup:* the first SIP worker scans the bucket and indexes every
key that matches [fts_json_prefix](#fts_json_prefix-string).  All
processes share the result.
- *Live updates:* with [kv_watch](#kv_watch-string) set, the watcher
process applies every put, delete and purge to the index, including
writes made by other OpenSIPS instances.  Without a watcher, the index
only sees this instance's own writes.
- *Reconnect:* after a reconnect the watcher rebuilds the index from
the bucket ([index_resync_on_reconnect](#index_resync_on_reconnect-integer),
on by default).
[index_resync_interval_secs](#index_resync_interval_secs-integer) adds an
optional periodic rebuild.


Results are capped by the *cachedb_nats_fts*
[fts_max_results](../cachedb_nats_fts/README.md#fts_max_results-integer)
parameter.


### KV Watcher


When at least one [kv_watch](#kv_watch-string) pattern is set, the
module forks one dedicated *NATS Watcher* process.  It subscribes to the
matching keys of the bucket and, for every change:


- raises the [E_NATS_KV_CHANGE](#e_nats_kv_change) event with the key,
the operation, the value (for puts) and the revision;
- updates the *cachedb_nats_fts* index, if that module is loaded.


After a disconnect the watcher waits for the connection and resumes
right after the last revision it delivered, so changes made while it
was disconnected still raise *E_NATS_KV_CHANGE*, once each, after the
reconnect.  With [kv_history](#kv_history-integer) set to 1 the bucket
keeps only the newest value of a key, so a key changed several times
during the outage is reported once, with its latest value.  If the
bucket was deleted and recreated meanwhile, the watcher logs a warning
and starts at the new bucket's end.  With the index loaded, the watcher
also rebuilds it after a reconnect.


### Cluster Configuration


For production deployments a three-node NATS JetStream cluster is
recommended.  The [nats_url](#nats_url-string) parameter is a seed
list used only for the initial bootstrap connection.  After the first
connection is established, nats.c discovers all cluster peers via
the INFO protocol gossip mechanism
(*connect_urls*) and maintains the full topology
automatically.  Adding or removing nodes from the cluster is
transparent to the OpenSIPS module.


Use DNS hostnames rather than IP addresses in
[nats_url](#nats_url-string).  The nats.c library calls
`getaddrinfo` on each reconnection attempt,
so DNS-based hostnames automatically pick up topology changes such
as node replacement or IP address reassignment.


The [kv_replicas](#kv_replicas-integer) parameter controls the JetStream
replication factor and only takes effect when the KV bucket is first
created.  A value of 3 on a three-node cluster tolerates one-node
failure without data loss or availability impact.  To change the
replication factor on an existing bucket use the NATS CLI:


```bash
nats kv update opensips --replicas=3
```


The internal reconnection loop is unlimited at runtime: nats.c will
never permanently remove a server from its routing pool.  The
[max_reconnect](#max_reconnect-integer) parameter only caps startup
connection attempts in `child_init`; a broker unreachable at startup
does not use it up (the process starts degraded).


Without NATS at startup -- the broker is unreachable, or no usable
server URL is configured -- *cachedb_nats* starts degraded with a
warning (`cachedb_nats: NATS is unavailable at startup; starting
degraded`): cache operations fail until the connection is up, then
work without a restart.  The startup checks of the bucket -- and the
build of the [cachedb_nats_fts](../cachedb_nats_fts/README.md) search
index -- run in the reaper process once the connection is up.  With
[require_usrloc_safe_bucket](#require_usrloc_safe_bucket-integer)
set to `1`, the module refuses to start instead.


```opensips title="Three-node cluster configuration"
...
loadmodule "nats.so"
loadmodule "cachedb_nats.so"

modparam("cachedb_nats", "cachedb_url", "nats://nats-1:4222/")
modparam("cachedb_nats", "nats_url",
    "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
modparam("cachedb_nats", "kv_bucket",   "opensips")
modparam("cachedb_nats", "kv_replicas", 3)
modparam("cachedb_nats", "kv_history",  1)
modparam("cachedb_nats", "kv_ttl",      0)
modparam("cachedb_nats", "fts_json_prefix", "usrloc.")
modparam("cachedb_nats", "kv_watch",    "usrloc.>")
...
```


```opensips title="Single-node development configuration"
...
loadmodule "nats.so"
loadmodule "cachedb_nats.so"

modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")
modparam("cachedb_nats", "kv_replicas", 1)
modparam("cachedb_nats", "kv_watch",    ">")
...
```


### Operator playbook: NATS as backend store for usrloc


This section is for operators deploying
*usrloc* in
`cluster_mode = full-sharing-cachedb` with
*cachedb_nats* as the cachedb engine.  In
this configuration JetStream KV is the authoritative store
for AoR / contact records:


- SIP REGISTER → `save("location")`
→ usrloc → CacheDB `update()` → a compare-and-swap create or
update of one JSON document per AoR, stored under the key
`<fts_json_prefix><encoded AoR>`.
- SIP lookup → usrloc → CacheDB `query()` with a primary-key filter
→ one `kvStore_Get`.  No index is involved.
- Process restart → nothing to reload: every lookup reads the bucket.


Multiple OpenSIPS instances pointing at the same bucket
converge on a consistent view of usrloc state without any
clusterer-driven binary replication; the only
synchronization between writers is JetStream's per-key CAS.


#### Topology by DC count


**Single DC, single broker**


[kv_replicas](#kv_replicas-integer) = 1,
[kv_history](#kv_history-integer) = 1,
File storage.  Use this for development and
small single-DC deployments.  Restart hydration
is fast (one round-trip per key).


**Single DC, clustered NATS (3 servers)**


[kv_replicas](#kv_replicas-integer) = 3.  Survives a
single broker failure with no AoR loss.  Recommended
production baseline.  Inter-broker replication is
NATS-internal and adds ~1-2 ms to write latency.


**Multiple DCs, one global bucket**


Recommended only when the inter-DC RTT is
< 50 ms and concurrent same-AoR writes are
rare.  Every `kvStore_UpdateString`
CAS pays full inter-DC RTT.  Across the default
[cas_retries](#cas_retries-integer) = 10 attempts the
jittered backoff adds at most ~16 ms of sleep, plus
one inter-DC RTT per attempt; raise the budget if cross-DC
contention drives `cas_exhausted`
above zero.


**Multiple DCs, bucket per DC + leafnodes**


Lower per-write latency at the cost of cross-DC
visibility being asynchronous.  Each DC reads
its local bucket; cross-DC AoR resolution
happens out of band (e.g.  GSLB or local-fail-
through-to-remote logic).  Conflict resolution
becomes operator-defined; the simplest policy is
"the first DC to see a REGISTER owns the AoR."


#### Bucket sizing


- *Storage:*
`File` (default).  Memory storage
loses AoRs on broker restart, defeating the purpose
of using NATS as the backend store.
- *Replicas:* match
broker cluster size up to 3.  Replicas > 3 add
latency without meaningful availability gains for
usrloc workloads.
- *History:*
[kv_history](#kv_history-integer) = 1.  The module
does not check the history depth: expiry is the periodic
cleanup scan (correct, but up to
[reap_interval](#reap_interval-integer) seconds late)
at any history depth.  Use a history-keeping bucket only
when routing logic genuinely needs
[nats_kv_history()](#nats_kv_historykey-result_pvar), and keep it
OFF the registration bucket if possible.
- *TTL:*
[kv_ttl](#kv_ttl-integer) = 0 (no bucket-wide
max age — it would delete permanent contacts; the
module refuses to start otherwise).  Expired
registrations are removed by the periodic cleanup
scan ([reap_interval](#reap_interval-integer)).  To keep expired records readable for
a while (forensics), see
[expired_linger](#expired_linger-integer).
- *Max bytes / max age:*
NATS defaults are typically appropriate.  For
bounded environments, size the stream for at least
`(active_aors × avg_doc_size × kv_history)`
bytes.  An average AoR JSON document with a single
contact is roughly 400-600 bytes.


#### Snapshot and restore


JetStream KV buckets are JetStream streams named
`KV_<bucket>` under the hood, so
they snapshot and restore through the standard stream
tooling:


```bash
nats stream snapshot KV_USRLOC ./usrloc-2026-05-08.tar.gz
nats stream restore  KV_USRLOC ./usrloc-2026-05-08.tar.gz
```


Snapshot during a low-traffic window for a
point-in-time copy.  After restore, every connected
OpenSIPS instance must rebuild its in-memory index;
either bounce the instances (cleanest), set
[index_resync_on_reconnect](#index_resync_on_reconnect-integer) = 1 and
cycle the broker, or set
[index_resync_interval_secs](#index_resync_interval_secs-integer) to a
value ≤ the longest tolerable staleness window so
the periodic timer pulls the new state.  The lazy
self-heal in the query path
only evicts stale entries it already holds; it does
not add keys introduced by the restore, so an explicit
rebuild (or the periodic timer) is required, not merely
faster.


#### Scale tuning: PK fast path and the optional index


usrloc's read and write path is exclusively
*primary-key*: both the record load (read) and the
record flush (write) use a single primary-key filter.
The in-memory JSON search index is therefore *optional weight*
for any deployment that uses the module purely as a
usrloc backend.  Two operator knobs control the index
behaviour.


**Loading the *cachedb_nats_fts* module**


Loading the optional *cachedb_nats_fts* module is the
switch for the JSON search index.  Pure usrloc
workloads simply do not load it — primary-key operation (other
queries, such as NAT pinging, scan the bucket), no index SHM, no
watcher-feed CPU.


**Index size**


The *cachedb_nats_fts*
[index_buckets](../cachedb_nats_fts/README.md#index_buckets-integer)
parameter sets the hash bucket count of the index; its entry gives the
recommended values per deployment size.  It is ignored when
*cachedb_nats_fts* is not loaded.


**PK fast path**


Always on; no modparam.  When the filter is a
single primary-key equality condition on a string value, the
query encodes the value into the KV key, prefixes it, calls
`kvStore_Get`, parses the
returned JSON, and returns one row.  No mutex
acquired, no chain walk.  Any other filter goes to the index (string
equalities, with *cachedb_nats_fts*) or to a bucket scan.


Scaling guidance:


- *Pure usrloc workloads at any scale:*
do not load *cachedb_nats_fts*.
No index memory and no per-write index update.
- *Mixed workloads (modules issuing non-key CacheDB
queries on the same bucket):* load
*cachedb_nats_fts* and tune
[index_buckets](../cachedb_nats_fts/README.md#index_buckets-integer).
The KV watcher always runs in its own dedicated
child process, so it never competes with SIP
request handling in the workers.
- *1MM endpoints:* the index off
is essentially mandatory (~250 MB SHM saved per
instance); the watcher would otherwise saturate
one core at the steady-state event rate.  If
the index is still kept on for mixed-workload
reasons, budget one core for the dedicated
watcher process.
- *10MM endpoints:* the index
off is mandatory.  Sharding remains required for
SIP-side reasons.


#### SHM allocator selection


OpenSIPS defaults the shared-memory allocator to
`Q_MALLOC`, which is single-mutex
and serialises every `shm_malloc`
/ `shm_free` across all worker
processes.  At populated index sizes (10k+ AoRs) and
sustained REGISTER churn this becomes the dominant
tail-latency contributor: the per-CAS path triggers
3-5 SHM allocations to add a doc to the in-memory
JSON search index, and Q_MALLOC's lock pinches every
worker on every alloc.


Recommendation: launch `opensips`
with `-s HP_MALLOC` to select
`HP_MALLOC` ("optimized for shared
memory multiprocessing").  Measured on a single instance:


- 10k AoRs:
p99 84 ms → 54 ms (−36%);
p50 35 ms → 21 ms (−40%).
- 20k AoRs:
p99 185 ms → 142 ms (−23%);
p50 41 ms → 25 ms (−39%).


Pkg memory (`-k`) is per-process
and not contended, so the default
`Q_MALLOC` there is fine.  Only
the SHM allocator (`-s`) needs the
switch.


#### MI counters and alert thresholds


[cachedb_nats:nats_cdb_stats](#cachedb_natsnats_cdb_stats) returns,
among others, four counters tracking the
cachedb path:


- *cas_retry* - bumped per CAS
conflict in `cache_add` / `cache_sub` / CacheDB `update()`, and per
retried fetch in `update()`.  Steady
non-zero values are normal under contention; a
sustained high rate suggests
[cas_retries](#cas_retries-integer) is too low
or the CAS hot key is genuinely contended.
- *cas_exhausted* - bumped when
a CAS gave up after exhausting the budget.
*Should always be 0* in a
healthy deployment; non-zero indicates lost
writes.  Page on
`delta(cas_exhausted) > 0`
over any reasonable interval.
- *create_doc* - bumped per
first insert of a document (a create at
revision 0) by CacheDB `update()`.  Roughly equal to the rate of
genuinely new AoRs.  A spike usually maps to a
burst of new registrations.
- *index_miss_kv* - bumped when
a query hit an
index entry whose KV key was already deleted.
Self-heal evicts the entry; a non-zero rate is
expected in multi-instance deployments.  A
*large* sustained rate
suggests cross-instance churn higher than the
self-heal pace; consider enabling
[index_resync_interval_secs](#index_resync_interval_secs-integer).


#### Migration from full-sharing-cachedb-cluster


The legacy mode `full-sharing-cachedb-cluster`
additionally relies on clusterer to broadcast cachedb
invalidation events.  With cachedb_nats, the KV watcher
process + stale-entry self-heal subsume that role.  To
migrate:


1. Take a snapshot of the current bucket (above).
2. On each instance, change `cluster_mode`
to `full-sharing-cachedb`;
keep the existing `location_cluster`
(clusterer is still required for shtag /
pinging coordination).
3. Roll instances one at a time.  With
*cachedb_nats_fts* loaded, each rolled
instance rebuilds its index from KV on
`child_init` and is
immediately consistent with peers still on the
old mode.
4. After all instances are migrated, the
clusterer-driven cachedb broadcast capabilities
become idle and can be removed at the next
maintenance window.


#### Related parameters


See [Scale tuning](#scale-tuning-pk-fast-path-and-the-optional-index)
for loading *cachedb_nats_fts* and sizing its index.  The other knobs
are [index_resync_on_reconnect](#index_resync_on_reconnect-integer)
(full index rebuild after each reconnect, on by default),
[index_resync_interval_secs](#index_resync_interval_secs-integer)
(periodic full rebuild, off by default) and
[cas_retries](#cas_retries-integer) (CAS budget per write).


### Limitations


- **[kv_ttl](#kv_ttl-integer) must be 0.**  Keys expire through the
reaper, up to [reap_interval](#reap_interval-integer) +
[reap_grace](#reap_grace-integer) seconds (35 s by default) after their
expiry time.
- **Bucket settings apply only when the module creates the bucket.**
[kv_replicas](#kv_replicas-integer), [kv_history](#kv_history-integer)
and [kv_ttl](#kv_ttl-integer) are ignored for an existing
bucket.  An existing bucket with a maximum age only produces a warning,
unless [require_usrloc_safe_bucket](#require_usrloc_safe_bucket-integer)
is set.
- **The `expires` argument of `cache_store` and `cache_add` is
ignored.**  Only usrloc rows expire.
- **Keys** are at most 511 bytes and may contain only letters, digits
and `.` `_` `-` `/` `\` `=` (see [KV Key Validation](#kv-key-validation)).
- **Values:** usrloc rows are limited by
[max_value_size](#max_value_size-integer) (1 MiB by
default); JSON documents over 1 MiB or nested deeper than 64 levels are
rejected.
- **Revisions are 32-bit in the script.**
[nats_kv_update()](#nats_kv_updatebucket-key-value-expected_rev) compares
against a revision truncated to 32 bits, so a compare-and-swap fails
once a key passes revision 2 147 483 647.
- **The nats_kv_\* functions create a missing bucket** on first use,
with this module's [kv_replicas](#kv_replicas-integer),
[kv_history](#kv_history-integer) and [kv_ttl](#kv_ttl-integer)
settings; pre-create a bucket that needs other settings.
- **Queries the index cannot answer read the whole bucket.**  Each such
`cache_query` is one pass over the documents under
[fts_json_prefix](#fts_json_prefix-string).  usrloc NAT pinging in
`full-sharing-cachedb` mode is one of them: nathelper queries once per
second per `natping_partitions`, so pinging reads the bucket that often
(e.g. 100 000 registrations of about 1 KB each are about 100 MB/s per
partition).  `update` still accepts only primary-key filters without
*cachedb_nats_fts*.
- **A recreated bucket is not replayed.**  If the bucket is deleted
and recreated while the KV watcher is disconnected, the watcher starts
at the new bucket's end: changes made to the new bucket before the
reconnect do not raise *E_NATS_KV_CHANGE*.  (With
[index_resync_on_reconnect](#index_resync_on_reconnect-integer) = 1, the
default, the *cachedb_nats_fts* index is rebuilt after the reconnect and
is not affected.)
- **MI listings** return at most 200 rows;
[cachedb_nats:nats_reg_list](#cachedb_natsnats_reg_list) scans at
most 100 000 records and
[cachedb_nats:nats_reg_summary](#cachedb_natsnats_reg_summary) counts at
most 64 domains.  Per-process statistics cover process numbers below
512.
- **No per-key access control.**  NATS KV cannot restrict access per
key, so separate trust domains need separate buckets (and NATS
accounts).
- **Latency:** each REGISTER makes two synchronous round trips to the
broker; one bucket shared across data centres is recommended only
below about 50 ms round-trip time.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *nats*: the connection shared by the NATS modules; see the
[nats module](../nats/README.md).
- *tls_mgm* if the connection uses TLS: `tls://` URLs in
[nats_url](#nats_url-string), or `?tls_domain=nats` in
[cachedb_url](#cachedb_url-string) (see [TLS](#tls)).


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libnats* (the [nats.c](https://github.com/nats-io/nats.c) client),
3.14 or later: the module needs the per-key KV TTL API
(`kvStore_CreateWithTTL`).  The libnats loaded at run time must have
the same major.minor version as the one OpenSIPS was built against;
see the [nats module](../nats/README.md#requirements).
For `tls://` URLs, libnats must be built with TLS
(`-DNATS_BUILD_WITH_TLS=ON`).
- *NATS Server with JetStream enabled:*
2.10 or later (*jetstream: {}* in the server configuration).
For production deployments a three-node JetStream cluster is
recommended to survive single-node failures with
[kv_replicas](#kv_replicas-integer) set to 3.


### Exported Parameters


#### cachedb_url (string)


The CacheDB URL that associates this module with a named cache group
in the OpenSIPS script.  The URL format follows the standard OpenSIPS
CacheDB convention:


**nats[:`<group>`]://[`<user>`:`<password>`@]`<host>`:`<port>`[,`<host>`:`<port>`...]/[?tls_domain=nats]**


The optional `<group>` label (e.g.
*nats:mycluster://*) distinguishes multiple cache
namespaces in the same script.  Without a [nats_url](#nats_url-string),
the first cachedb_url also gives the NATS servers: every host becomes a
`nats://` URL (`tls://` with `?tls_domain=nats`), carrying the
credentials if any.  When nats_url is set it takes precedence, and the
URL is then used solely for group registration.


This parameter may be set more than once to register multiple cache
group names backed by the same NATS connection.


```opensips title="Set cachedb_url parameter"
...
modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")
modparam("cachedb_nats", "cachedb_url", "nats:calls://127.0.0.1:4222/")
...
```


```opensips title="Use the nats cache group in a routing script"
...
cache_store("nats", "call.$(ci{s.md5})", "$fu");
cache_fetch("nats:calls", "call.$(ci{s.md5})", $var(caller));
...
```


#### nats_url (string)


Comma-separated list of NATS server URLs used as the bootstrap seed
list for the connection pool.  After the initial connection is
established, nats.c discovers all cluster peers via the INFO protocol
gossip mechanism and maintains the full topology automatically.
This parameter only needs to contain enough servers to bootstrap the
initial connection.


Use DNS hostnames rather than IP addresses so that
`getaddrinfo` re-resolves on each reconnect attempt,
automatically following topology changes in the cluster.


When this parameter is set it takes precedence over the hosts in
[cachedb_url](#cachedb_url-string).  When it is not set, the server
list comes from the first cachedb_url (see there); if that cannot be
parsed, or names a `tls_domain` other than `"nats"`, OpenSIPS refuses to
start.  With no cachedb_url at all, `nats://localhost:4222` is used
(unless another NATS module configures servers) and a warning is
logged.


A server can also be given as a DNS domain whose SRV records list
the servers: `nats+srv://example.com` (`tls+srv://example.com` for
TLS).  OpenSIPS looks up the SRV records of `_nats._tcp.example.com`
(RFC 2782) through its own resolver, so any libnats works, and gives
libnats one `nats://` (or `tls://`) URL per target, `host:port`, in
place of the SRV URL: lowest priority first and, inside a priority, a
random choice weighted by the record weights (with
[no_randomize](#no_randomize-integer), decreasing weight, then target
name).  So that the priorities hold, libnats keeps the order of the
server list whenever it contains an SRV URL, as with
[no_randomize](#no_randomize-integer) set to `1`: other servers listed
next to it are tried in the configured order.  Credentials are written
as usual (`nats+srv://user:password@example.com`) and apply to every
target;
there is no port (the records provide it) and no path: a port or a
path is dropped with a warning, and an SRV URL without a usable domain
name is ignored with a warning.  Each OpenSIPS process looks up the
records once, when it connects; servers added to the cluster later
are learned from the cluster (see above), and a target removed from
DNS stays in the process's list until it restarts.  A lookup that
gives no server (no answer, no record, or a target of `.`) is warned
about; when no server is left, the process continues without NATS and
looks up again at most every 5 seconds.  At most 16 servers are used
in all; the targets past that are left out with a warning.


*Default value is "NULL" (servers taken from the first cachedb_url).*


```opensips title="Set nats_url parameter"
...
modparam("cachedb_nats", "nats_url",
    "nats://nats-1:4222,nats://nats-2:4222,nats://nats-3:4222")
...
```


```opensips title="Set nats_url parameter to a DNS SRV domain"
...
modparam("cachedb_nats", "nats_url", "nats+srv://example.com")
...
```


#### kv_bucket (string)


The name of the NATS JetStream KV bucket that this module will use
for all key-value operations.  If the bucket does not yet exist it
will be created during `child_init` with the
replication, history, and TTL settings defined by the
[kv_replicas](#kv_replicas-integer), [kv_history](#kv_history-integer),
and [kv_ttl](#kv_ttl-integer) parameters.


If the bucket already exists the creation parameters are ignored and
the existing bucket configuration is used as-is.  To change
replication on an existing bucket use the NATS CLI:
`nats kv update <bucket> --replicas=N`.


Bucket names must be valid NATS subject tokens (alphanumeric, hyphens,
and underscores; no spaces or dots).


*Default value is "opensips".*


```opensips title="Set kv_bucket parameter"
...
modparam("cachedb_nats", "kv_bucket", "opensips-prod")
...
```


#### kv_replicas (integer)


The JetStream replication factor for the KV bucket.  A value of 3
means every key-value entry is replicated to three NATS nodes,
tolerating single-node failure without data loss.  This parameter
only takes effect when the bucket is first created; it is ignored
if the bucket already exists.


For development or single-node deployments use a value of 1.


*Default value is "3".*


```opensips title="Set kv_replicas parameter"
...
modparam("cachedb_nats", "kv_replicas", 1)
...
```


#### kv_history (integer)


The number of value revisions to retain per key.  This parameter
only takes effect when the bucket is first created.


**Keep this at 1 for registration
buckets** unless you use
[nats_kv_history()](#nats_kv_historykey-result_pvar).  Expiry is
performed by the periodic cleanup scan (the reaper) — see
[reap_interval](#reap_interval-integer).


Raise this only if your script uses
[nats_kv_history()](#nats_kv_historykey-result_pvar) to inspect old
versions of keys and you accept scan-only expiry.


*Default value is "1" (current version only).*


```opensips title="Set kv_history parameter"
...
modparam("cachedb_nats", "kv_history", 10)
...
```


#### kv_ttl (integer)


Bucket-level maximum age, in seconds.  It must be `0`: any other
value stops OpenSIPS at startup.  A bucket-wide maximum age would
expire every key, including permanent registrations
(*expires=0*), so expiry is left to the reaper (see
[reap_interval](#reap_interval-integer)).  The parameter is kept so that
existing configurations that set it to 0 still load.


The *expires* argument to `cache_store` and `cache_add` is accepted
for API compatibility but sets no per-key TTL.  Per-key expiry
applies only to usrloc rows.


*Default value is "0".*


```opensips title="Set kv_ttl parameter"
...
modparam("cachedb_nats", "kv_ttl", 0)
...
```


#### require_secure_url (integer)


Strict security mode for the connection URL.  The registration
bucket is a PII / lawful-intercept-relevant store (subscriber
IP, user-agent, call-id, path) and NATS KV has no per-key ACL,
so a plaintext `nats://` URL, or a connection without
credentials (neither in the URL nor in [user](#user-string),
[token](#token-string), [creds_file](#creds_file-string) or
[nkey](#nkey-string)), always draws a loud startup warning.  With this set
to `1` the module *refuses to
start* instead: use `tls://` with an
authenticated account and one bucket per trust domain.


Recommended *usrloc production profile*:
`require_secure_url=1` together with
[require_usrloc_safe_bucket](#require_usrloc_safe_bucket-integer)`=1`.
The default stays `0` for lab / development brokers and
for generic (non-PII) cachedb use.


*Default value is "0" (warn only).*


```opensips title="Set require_secure_url parameter"
...
modparam("cachedb_nats", "require_secure_url", 1)
...
```


#### require_usrloc_safe_bucket (integer)


Strict bucket-shape mode.  Binding to a pre-existing bucket
whose backing stream carries a non-zero `MaxAge`
would silently expire *all* keys, including
permanent contacts (`expires==0`); by default
this is detected once at startup and warned about loudly.  With
this set to `1` the module *refuses to
start* instead -- recreate the bucket with
`MaxAge=0` ([kv_ttl](#kv_ttl-integer) = 0) and
migrate the data.


It also refuses to start when NATS is unavailable at startup: the
bucket cannot be checked then.


*Default value is "0" (warn only).*


```opensips title="Set require_usrloc_safe_bucket parameter"
...
modparam("cachedb_nats", "require_usrloc_safe_bucket", 1)
...
```


#### fts_json_prefix (string)


Key name prefix that marks JSON documents for the search index
kept by the optional *cachedb_nats_fts* module (see
[JSON Search Index](#json-search-index)).  Documents stored under
other keys are still available through the normal KV operations but
are not indexed.


The prefix applies with or without *cachedb_nats_fts*: usrloc rows are
stored under the prefix followed by the encoded AoR, and the reaper and
the *nats_reg_\** MI commands only scan keys that start with it.


*Default value is "json_".*


```opensips title="Set fts_json_prefix parameter"
...
modparam("cachedb_nats", "fts_json_prefix", "usrloc.")
...
```


#### kv_watch (string)


A key pattern for the KV watcher (see [KV Watcher](#kv-watcher)).
Setting at least one pattern starts the watcher process; with no
pattern there is no watcher, no
[E_NATS_KV_CHANGE](#e_nats_kv_change) event and no
cross-instance index updates.


Patterns use NATS wildcards on dot-separated tokens: `>` matches the
rest of the key (`usrloc.>` watches every key under `usrloc.`,
and `>` alone watches the whole bucket), and `*` matches exactly one
token.  Wildcards must be whole tokens, so a prefix such as `json_`
cannot be watched as `json_>`; watch `>` or use a dotted prefix.


The parameter may be set more than once; all patterns are watched
through one subscription.


*Default value is "NULL" (watcher disabled unless
at least one pattern is configured).*


```opensips title="Set kv_watch parameter"
...
modparam("cachedb_nats", "kv_watch", ">")
...
```


#### cas_retries (integer)


Total number of compare-and-swap attempts (the first try included)
made by atomic counter increments (`cache_add()`) and JSON field
updates (`cache_update()`); a value of 0 or less is treated as 1.
Each attempt reads the key and writes it back conditionally; between
attempts a jittered backoff (50 us base, doubling, 5 ms cap) sleeps
at most ~16 ms in total at the default.  When the retry
budget is exhausted the operation is dropped and a warning naming the
affected key is logged, and the `cas_exhausted` counter of
[cachedb_nats:nats_cdb_stats](#cachedb_natsnats_cdb_stats) is bumped.
Raise it only if `cas_exhausted` shows non-zero rates (for example on
hot-contested keys); lowering it risks lost writes under contention.


*Default value is "10" (minimum 1).*


```opensips title="Set cas_retries parameter"
...
modparam("cachedb_nats", "cas_retries", 20)
...
```


#### index_resync_on_reconnect (integer)


Whether the KV watcher rebuilds the in-memory search
index in full after each reconnect to NATS.  The
watcher replays the changes it missed while disconnected
(see [KV Watcher](#kv-watcher)), but not when the bucket
was recreated meanwhile, and the stale-entry self-heal
in the query path only evicts index entries the KV store
reports as gone; it cannot discover a key that was never
indexed locally.  The default is therefore on, so the
index always converges after an outage.


Set to **0** only in
large-index or hot-reconnect deployments that cannot
afford the O(N) bulk rebuild on every reconnect; bound
the staleness window with
[index_resync_interval_secs](#index_resync_interval_secs-integer) (the
periodic resync) instead, since per-query
self-heal does not recover missed inserts.


Ignored when
the *cachedb_nats_fts* module is not loaded.


*Default value is "1".*


```opensips title="Set index_resync_on_reconnect parameter"
...
modparam("cachedb_nats", "index_resync_on_reconnect", 0)
...
```


#### index_resync_interval_secs (integer)


Periodic full rebuild of the in-memory search index, in seconds.
Belt-and-braces upper bound on per-process index
staleness regardless of reconnect cadence or self-heal
pace.  A tick that cannot get a KV handle (NATS disconnected) is
skipped; the next tick retries.
Runs in the dedicated "NATS Reaper" module
process, not the shared core timer process.


Set to a value <= the longest tolerable staleness
window in deployments where the lazy self-heal pace is
insufficient.  Each tick costs one
`kvStore_WatchAll` snapshot drain.


Ignored when
the *cachedb_nats_fts* module is not loaded.


*Default value is "0" (disabled).*


```opensips title="Set index_resync_interval_secs parameter"
...
modparam("cachedb_nats", "index_resync_interval_secs", 300)
...
```


#### drain_timeout_ms (integer)


Shutdown drain timeout in milliseconds for the shared
connection pool of the *nats* module.
Controls how long the pool waits for
in-flight publishes / requests to complete before
forcibly closing connections.  Cross-DC deployments
with high RTT may need to extend the budget.  The value is passed to
the *nats* module, as its
[drain_timeout_ms](../nats/README.md#drain_timeout_ms-integer) (also
accepted by *event_nats*'s
[drain_timeout_ms](../event_nats/README.md#drain_timeout_ms-integer)):
the first value set replaces the default (even a lower one), after
that the largest value wins.  A negative value refuses startup.


*Default value is "5000" (milliseconds).*


```opensips title="Set drain_timeout_ms parameter"
...
modparam("cachedb_nats", "drain_timeout_ms", 15000)
...
```


#### no_randomize (integer)


Server order of the connection shared by all NATS modules.  With
`0` (the default) libnats shuffles the configured servers, so the
OpenSIPS processes, each with its own connection, spread over them.
With `1`, every process tries the servers in the order they are
configured in [nats_url](#nats_url-string): the first reachable
server takes all the connections and the others are backups.


libnats then also stops shuffling the addresses of a hostname that
resolves to several IPs, and orders the targets of a DNS SRV URL by
priority, then by decreasing weight, instead of a weighted random
choice among the targets of the same priority.


The value is passed to the *nats* module, as its
[no_randomize](../nats/README.md#no_randomize-integer), which
*event_nats*, *cachedb_nats* and *nats_consumer* all accept: if any of
them sets it to `1`, the shared connection keeps the configured order.
A value other than `0` or `1` refuses startup.


When several NATS modules set their own [nats_url](#nats_url-string),
their servers are merged into one list, in module initialization
order.  To control the order, list all the servers in the
[nats_url](#nats_url-string) of one module and leave it unset in the
others: a module without it adds no server of its own when another
one configures servers.


*Default value is "0" (randomized).*


```opensips title="Set no_randomize parameter"
...
modparam("cachedb_nats", "no_randomize", 1)
...
```


#### reconnect_buf_size (integer)


Size, in bytes, of the buffer that keeps what is sent on the connection
shared by the NATS modules while it is reconnecting; it is sent once
the connection is back, and a send that the full buffer refuses fails.
Each OpenSIPS process has its own connection, so each has its own
buffer.


The value is passed to the *nats* module, as its
[reconnect_buf_size](../nats/README.md#reconnect_buf_size-integer),
which *event_nats*, *cachedb_nats* and *nats_consumer* all accept: the
first value set replaces the default, and if several modules set it,
the largest wins.  A value below `1` refuses startup.


*Default value is "8388608" (8 MB, the libnats default).*


```opensips title="Set reconnect_buf_size parameter"
...
modparam("cachedb_nats", "reconnect_buf_size", 33554432)
...
```


#### user (string)


User name for the connection shared by the NATS modules, sent with
[password](#password-string).  Together they replace credentials in the
server URL (`nats://user:pass@host`), which must then not carry any:
credentials both in a URL and in these parameters refuse startup, as do
a user without a password, and more than one way to authenticate
(user/password, [token](#token-string), [creds_file](#creds_file-string),
[nkey](#nkey-string)).  The user and password are sent in the CONNECT
message: over a `nats://` URL OpenSIPS warns that they travel in plain
text.  A value is never logged.


The credential parameters are passed to the *nats* module, as its
[user](../nats/README.md#user-string) and the others, which
*event_nats*, *cachedb_nats* and *nats_consumer* all accept: setting
one in any module sets it for the shared connection; two modules
setting different values refuse startup.


*Default value is "NULL" (no user).*


```opensips title="Set user parameter"
...
modparam("cachedb_nats", "user", "opensips")
modparam("cachedb_nats", "password", "s3cret")
...
```


#### password (string)


Password for [user](#user-string); both must be set.


*Default value is "NULL" (no password).*


```opensips title="Set password parameter"
...
modparam("cachedb_nats", "password", "s3cret")
...
```


#### token (string)


Authentication token for the shared connection (the server's
`authorization { token }`), instead of `nats://token@host`.  Sent in the
CONNECT message: over a `nats://` URL OpenSIPS warns that it travels in
plain text.  Not combinable with the other credential parameters (see
[user](#user-string)).


*Default value is "NULL" (no token).*


```opensips title="Set token parameter"
...
modparam("cachedb_nats", "token", "s3cr3t-t0ken")
...
```


#### creds_file (string)


Path of a NATS credentials file (`.creds`, holding the user JWT and its
NKey seed) for servers in operator (JWT) mode.  libnats reads it at
each connect and signs the server's nonce with the seed; no secret is
sent.  The file must be readable when OpenSIPS starts.  Not combinable
with the other credential parameters (see [user](#user-string)).


*Default value is "NULL" (no credentials file).*


```opensips title="Set creds_file parameter"
...
modparam("cachedb_nats", "creds_file", "/etc/opensips/nats/opensips.creds")
...
```


#### nkey (string)


Public NKey of the user (`U...`), for servers that list it in
`authorization { users = [ { nkey: ... } ] }`.  Set with
[nkey_seed_file](#nkey_seed_file-string); libnats signs the server's
nonce with the seed, no secret is sent.  Not combinable with the other
credential parameters (see [user](#user-string)).


*Default value is "NULL" (no NKey).*


```opensips title="Set nkey parameter"
...
modparam("cachedb_nats", "nkey", "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4")
modparam("cachedb_nats", "nkey_seed_file", "/etc/opensips/nats/opensips.nk")
...
```


#### nkey_seed_file (string)


Path of the file holding the NKey seed (`SU...`) of
[nkey](#nkey-string); both must be set.  The file must be readable when
OpenSIPS starts.


*Default value is "NULL" (no seed file).*


```opensips title="Set nkey_seed_file parameter"
...
modparam("cachedb_nats", "nkey_seed_file", "/etc/opensips/nats/opensips.nk")
...
```


#### reconnect_wait_ms (integer)


The time in milliseconds to wait between reconnection attempts when
the NATS connection is lost.  Applies to the shared connection pool
managed by the *nats* module.


*Default value is "2000" (milliseconds).*


```opensips title="Set reconnect_wait_ms parameter"
...
modparam("cachedb_nats", "reconnect_wait_ms", 1000)
...
```


#### max_reconnect (integer)


Maximum number of connection attempts made during `child_init`
for failures other than the ones below.  A broker that is
unreachable at startup counts no attempts: the process starts
degraded and keeps connecting in the background.  A broker that
refuses the connection (authentication, TLS handshake) looks the same,
since the first connect is asynchronous: the process starts degraded
and the broker logs why.  A connection that cannot be set up with the
configured servers (a `tls://` URL without *tls_mgm*, for instance)
fails startup at once.  Once connected,
the nats.c library reconnects with no limit.  The pool is shared, so
the largest value set by any NATS module wins.


*Default value is "60" (attempts).*


```opensips title="Set max_reconnect parameter"
...
modparam("cachedb_nats", "max_reconnect", 30)
...
```


#### reap_interval (integer)


Period, in seconds, of the reaper pass that CAS-prunes expired
bindings from the bucket.  The reaper is the module's authoritative
expiry mechanism, so this periodic prune is what guarantees an
expired binding is physically reclaimed.  The value must be
**> 0**; a non-positive value is
refused at startup (it would leave expired bindings
unreclaimed).


The pass runs in a dedicated "NATS Reaper" module
process, so a full-bucket scan at scale never stalls the shared
core timer process that other modules' timers depend on.


*Default value is "30" (seconds).*


```opensips title="Set reap_interval parameter"
...
modparam("cachedb_nats", "reap_interval", 60)
...
```


#### reap_grace (integer)


Clock-skew slack, in seconds, applied to every expiry decision
(the write-side expiry hygiene, the read-side filter and the
reaper).  A binding is treated as expired only once it is more
than this many seconds past its TTL, so
a node whose clock leads its peers never deletes or hides another
node's still-live registration.  Set this to at least the real
maximum clock skew between the nodes sharing the bucket.


*Default value is "5" (seconds).*


```opensips title="Set reap_grace parameter"
...
modparam("cachedb_nats", "reap_grace", 10)
...
```


#### expired_linger (integer)


How long, in seconds, an *expired* registration
record stays physically present in the bucket after it stops being
served.  This is a retention-policy knob with
**zero effect on call routing**: once
a contact's time is up (plus the [reap_grace](#reap_grace-integer)
clock-skew margin) it is never used again, whatever this is set to.


**0** (the default) deletes expired
records as promptly as possible — on the next cleanup-scan pass.  A value such as **30**
keeps each expired record around for ~30 more seconds, which is
useful when troubleshooting registration problems (the record stays
visible to `nats kv get` and
[nats_kv_history()](#nats_kv_historykey-result_pvar)) and damps
delete/re-create churn from endpoints that flap around their expiry
time.


Cost of raising it: bucket size — roughly
`expired-records-per-second × linger` extra
records resident at any time.  A re-registration during the linger
window simply overwrites the lingering record; phones are never
locked out by it.  Range 0–86400; out-of-range values refuse
startup.


*Default value is "0" (reclaim as soon as
possible).*


```opensips title="Set expired_linger parameter"
...
modparam("cachedb_nats", "expired_linger", 30)
...
```


#### max_value_size (integer)


Maximum stored value size, in bytes, for a usrloc row.  An
oversize row is detected before the CAS write and the offending
contact's save fails cleanly — never a silent truncation or
corruption.  Set this to the deployment's real per-message cap
(and no larger than the stream's `max_msg_size`).
A value **<= 0** disables the guard.


*Default value is "1048576" (1 MiB, the
NATS `max_payload` default).*


```opensips title="Set max_value_size parameter"
...
modparam("cachedb_nats", "max_value_size", 65536)
...
```


#### kv_op_timeout_ms (integer)


Per-request timeout, in milliseconds, of the shared JetStream
context of the *nats* module's pool, so a slow-but-connected broker cannot
block a process for the full library default (5 s).  It applies to
every JetStream and KV request made through the shared pool in every
process, including those of *event_nats* and *nats_consumer*, not only
to the usrloc read/write path.  The usrloc update path performs two
synchronous round-trips per REGISTER, so the per-REGISTER worst
case is roughly twice this value.  A value
**<= 0** removes the cap (the libnats
default applies).


*Default value is "1000" (ms; bounds the
per-REGISTER worst case at ~2 s).*


```opensips title="Set kv_op_timeout_ms parameter"
...
modparam("cachedb_nats", "kv_op_timeout_ms", 500)
...
```


### Exported Functions


#### nats_kv_history(key, result_pvar)


Retrieves the revision history for a KV key in the
[kv_bucket](#kv_bucket-string) bucket and stores it as a JSON
array string in *result_pvar*.  Each array element
is an object with the fields *rev* (revision
number, integer) and *value* (the stored string at
that revision), oldest revision first.  A history longer than the
8 KB result buffer is truncated (a warning is logged).


The depth of history available depends on the
[kv_history](#kv_history-integer) bucket setting.  With the default of
1 only the current value is kept, so the array holds one element;
raise [kv_history](#kv_history-integer) (when the bucket is created)
to keep past values.


Meaning of the parameters is as follows:


- *key* (string) - KV key to retrieve history for.  May contain
pseudo-variables.
- *result_pvar* (var) - pseudo-variable to receive the JSON history
array.


Return values:


- **1** - history retrieved successfully.
- **-1** - error (NATS failure or allocation error).
- **-2** - key not found or no history available.


This function can be used from any route.


```opensips title="nats_kv_history usage"
...
nats_kv_history("usrloc.alice", $var(hist));
if ($retcode == 1) {
    # $var(hist) = [{"rev":1,"value":"sip:alice@192.0.2.3"},
    #               {"rev":2,"value":"sip:alice@192.0.2.2"},
    #               {"rev":3,"value":"sip:alice@192.0.2.1"}]
    xlog("history for alice: $var(hist)\n");
}
...
```


#### nats_kv_get(bucket, key, value_pvar, [revision_pvar])


Reads a key from the JetStream KV bucket and stores its value
in *value_pvar*.  The optional
*revision_pvar* receives the current
revision number; pass it to a subsequent
[nats_kv_update()](#nats_kv_updatebucket-key-value-expected_rev) call to
perform a Compare-And-Swap update.


An empty *bucket* means the [kv_bucket](#kv_bucket-string) bucket.
A bucket that does not exist yet is created on first use, with the
[kv_replicas](#kv_replicas-integer), [kv_history](#kv_history-integer)
and [kv_ttl](#kv_ttl-integer) settings; this applies to all the
*nats_kv_\** functions.


**CAS contract for
*revision_pvar*:** the function
populates the script var with both string and integer views
so it can drive a subsequent
[nats_kv_update()](#nats_kv_updatebucket-key-value-expected_rev) CAS.
NATS revisions are
64-bit; the OpenSIPS script integer type is 32-bit.  In the
(unrealistic) case that a key passes
`INT_MAX` revisions the function logs a
warning and the truncated value will fail any
subsequent CAS.


Meaning of the parameters is as follows:


- *bucket* (string) - the KV bucket name.
- *key* (string) - the key to read.
- *value_pvar* (var) - receives the value.
- *revision_pvar* (var, optional) - receives the current revision.


Return values:


- **1** - success.
- **-1** - error (no NATS connection, bucket bind/create failure, etc).
- **-2** - key not found.


This function can be used from any route.


```opensips title="nats_kv_get usage"
$var(rev) = 0;
if (nats_kv_get("calls", "$ci", $var(state), $var(rev))) {
    xlog("call $ci is in state $var(state) at rev $var(rev)\n");
}
```


#### nats_kv_put(bucket, key, value)


Unconditionally writes *value* at
*key* in *bucket*.  Any
concurrent writer's revision is overwritten.  Use
[nats_kv_update()](#nats_kv_updatebucket-key-value-expected_rev) instead
when you need to preserve optimistic-concurrency semantics.


Meaning of the parameters is as follows:


- *bucket* (string) - the KV bucket name.
- *key* (string) - the key to write.
- *value* (string) - the value to store.


Return values:


- **1** - success.
- **-1** - error.


This function can be used from any route.


```opensips title="nats_kv_put usage"
nats_kv_put("calls", "$ci", "ringing");
```


#### nats_kv_update(bucket, key, value, expected_rev)


Compare-And-Swap update: writes
*value* at *key* only
if the bucket's current revision for that key equals
*expected_rev*.  Read the revision with
[nats_kv_get()](#nats_kv_getbucket-key-value_pvar-revision_pvar) and pass
it back here.


*expected_rev* accepts both a
literal integer and a script variable (e.g.
`$var(rev)`).  When passing a variable the
var must have been written by
[nats_kv_get()](#nats_kv_getbucket-key-value_pvar-revision_pvar) /
[nats_kv_revision()](#nats_kv_revisionbucket-key-revision_pvar) -- those
functions mark the var with the int type flag the OpenSIPS fixup engine
requires.


Meaning of the parameters is as follows:


- *bucket* (string) - the KV bucket name.
- *key* (string) - the key to write.
- *value* (string) - the value to store.
- *expected_rev* (integer) - the revision the key must currently have.


Return values:


- **1** - CAS succeeded.
- **-1** - error (connection,
permissions, malformed publish, etc — *not*
retryable).
- **-2** - CAS mismatch — the key's
current revision is not *expected_rev*; a
concurrent writer beat us, so re-read the revision and retry.


-2 is returned only for a
genuine revision conflict (the broker's
*wrong last sequence*, JetStream error code 10071),
while any other failure is -1, so a CAS retry loop cannot spin
on a non-retryable error.  In script,
the result is FALSE for both -1 and -2; if
you need to distinguish them inspect `$retcode`
directly.


This function can be used from any route.


```opensips title="nats_kv_update usage"
$var(rev) = 0;
if (!nats_kv_get("calls", "$ci", $var(s), $var(rev)))
    return;

if (!nats_kv_update("calls", "$ci", "ringing", $var(rev))) {
    xlog("CAS failed: someone else updated $ci, rc=$retcode\n");
    # caller can retry, surface 503, etc.
}
```


#### nats_kv_delete(bucket, key)


Removes *key* from
*bucket*.  A subsequent
[nats_kv_get()](#nats_kv_getbucket-key-value_pvar-revision_pvar) on the
same key returns -2 (not found).  Past revisions remain visible to
[nats_kv_history()](#nats_kv_historykey-result_pvar) until the bucket's
history window rolls them off.


Meaning of the parameters is as follows:


- *bucket* (string) - the KV bucket name.
- *key* (string) - the key to delete.


Return values:


- **1** - success.
- **-1** - error.


This function can be used from any route.


```opensips title="nats_kv_delete usage"
nats_kv_delete("calls", "$ci");
```


#### nats_kv_revision(bucket, key, revision_pvar)


Convenience wrapper around
[nats_kv_get()](#nats_kv_getbucket-key-value_pvar-revision_pvar)
that fetches only the current revision number, without
copying the value out.  Same int-type contract on the
returned var as
[nats_kv_get()](#nats_kv_getbucket-key-value_pvar-revision_pvar) -- safe
to drive [nats_kv_update()](#nats_kv_updatebucket-key-value-expected_rev).


Meaning of the parameters is as follows:


- *bucket* (string) - the KV bucket name.
- *key* (string) - the key to look up.
- *revision_pvar* (var) - receives the current revision.


Return values:


- **1** - success.
- **-1** - error.
- **-2** - key not found.


This function can be used from any route.


```opensips title="nats_kv_revision usage"
if (nats_kv_revision("calls", "$ci", $var(rev)))
    nats_kv_update("calls", "$ci", "answered", $var(rev));
```


### Exported MI Functions


The observability commands
([cachedb_nats:nats_reg_summary](#cachedb_natsnats_reg_summary),
[cachedb_nats:nats_reg_list](#cachedb_natsnats_reg_list),
[cachedb_nats:nats_reg_show](#cachedb_natsnats_reg_show),
[cachedb_nats:nats_stream_list](#cachedb_natsnats_stream_list),
[cachedb_nats:nats_stream_info](#cachedb_natsnats_stream_info),
[cachedb_nats:nats_kv_keys](#cachedb_natsnats_kv_keys))
default to structured JSON output and can render their result table
as *CSV* (RFC 4180: CRLF records, header first,
quote-and-double escaping) or *plain text*
(TAB-separated lines, "# "-prefixed header) instead:
pass `format=csv` / `format=txt`
as a filter key on the list commands, or as the optional *format*
parameter of [cachedb_nats:nats_reg_summary](#cachedb_natsnats_reg_summary),
[cachedb_nats:nats_reg_show](#cachedb_natsnats_reg_show) and
[cachedb_nats:nats_stream_info](#cachedb_natsnats_stream_info) (e.g.
`cachedb_nats:nats_reg_show alice@example.com csv`; the
parameter also accepts `csv;eol=lf;header=0`).
The formatted table is returned as a single `data`
string inside the usual JSON-RPC envelope — line endings survive
JSON escaping exactly, so
`| jq -r '.result.data'` yields clean CSV/text
while counts such as `matched` stay directly
accessible as JSON.  Options: `eol=lf` (default is
CRLF), `header=0`.  An unrecognized format value
refuses the command rather than silently falling back to JSON.


The examples below show a small sample deployment (two subscribers
of `example.com`: alice with a Yealink and a
Zoiper contact, bob with a Grandstream) against the default
`opensips` bucket.  Timestamp, sequence and size fields
naturally vary.


#### cachedb_nats:nats_kv_status


Returns a JSON object with the current KV bucket configuration
and NATS connection state.  Useful for monitoring and diagnostics.


Parameters: *none*


Response fields:


- *bucket* (string) - name of the configured KV bucket.
- *replicas* (integer) - configured replication factor.
- *history* (integer) - configured history depth per key.
- *ttl* (integer) - configured bucket TTL in seconds (0 = no expiry).
- *connected* (string) - *yes* if the NATS connection pool is
currently connected, *no* otherwise.


```bash
opensips-cli -x mi cachedb_nats:nats_kv_status
```


```json
{
    "bucket": "opensips",
    "replicas": 3,
    "history": 1,
    "ttl": 0,
    "connected": "yes"
}
```


#### cachedb_nats:nats_cdb_stats


Returns a snapshot of the cachedb_nats counter set,
summed across the per-process slots maintained in
shared memory.  Used for alerting and capacity
planning; see
[MI counters and alert thresholds](#mi-counters-and-alert-thresholds)
for recommended thresholds.


Parameters: *none*


Counters in the response include:


- *cas_retry* - total CAS
retries across all `cache_add`
/ `cache_sub` / CacheDB `update()` calls: bumped
once per CAS conflict, and once per retried fetch in `update()`.
- *cas_exhausted* - total
CacheDB calls that ran out of
[cas_retries](#cas_retries-integer) attempts and
dropped the write.  Should be 0 in steady state;
any non-zero value means writes were lost.
- *create_doc* - total first inserts by CacheDB `update()`: a
seed document created at revision 0.
- *index_miss_kv* - query/update
found a key in the in-memory search index but the
KV store said NOT_FOUND.  Flags index staleness,
typically from a sibling-instance delete.
Sustained non-zero values indicate cross-instance
churn worth investigating.


It also carries the `contacts_pruned` counter
(individual expired bindings removed by the reaper's survivor-writes;
`rows_reaped` counts whole rows) and the
`reap_last_*` gauges — bucket-wide registration
totals recorded by the reaper's periodic pass at zero extra broker
cost: `reap_last_run` (epoch) /
`_ms` / `_keys` /
`_aors` / `_contacts` /
`_active` / `_permanent` /
`_due`.  These describe the last complete pass and refresh every
[reap_interval](#reap_interval-integer) seconds; a pass whose bucket
scan failed or stopped early keeps the previous values and increments
the `reap_enum_failures` counter instead; a tick skipped because no KV
handle is available (broker unreachable) changes neither.  They are the
recommended monitoring feed for registration counts (poll this, not
[cachedb_nats:nats_reg_summary](#cachedb_natsnats_reg_summary), on large
buckets).


```bash
opensips-cli -x mi cachedb_nats:nats_cdb_stats
```


```json
{
    "cas_retry": 0,
    "cas_exhausted": 0,
    "create_doc": 2,
    "index_miss_kv": 0,
    "fastfail_rejected": 0,
    "op_failed": 0,
    "watcher_restarts": 0,
    "watcher_handle_leaks": 0,
    "nul_fields_rejected": 0,
    "poison_values_rejected": 0,
    "value_oversize_rejected": 0,
    "rows_reaped": 0,
    "contacts_pruned": 0,
    "reap_last_run": 1783008230,
    "reap_last_ms": 9,
    "reap_last_keys": 2,
    "reap_last_aors": 2,
    "reap_last_contacts": 3,
    "reap_last_active": 3,
    "reap_last_permanent": 0,
    "reap_last_due": 0,
    "reap_enum_failures": 0
}
```


#### cachedb_nats:nats_reg_summary


High-level registration totals, computed by scanning the KV bucket
(the source of truth — in full-sharing-cachedb mode usrloc's own
`ul_dump` is empty by design, because records are
freed from memory after every flush).  Reports AoR and contact
counts split by state: *active* (would be served:
unexpired, or within the [reap_grace](#reap_grace-integer) margin),
*expired* (still stored — lingering per
[expired_linger](#expired_linger-integer), or awaiting cleanup) and
*permanent*, plus the soonest upcoming expiry and
scan cost.


The scan is one streaming, value-carrying watch pass over the bucket
(not one request per AoR), but it still reads every stored row; on very
large buckets
prefer the free `reap_last_*` gauges in
[cachedb_nats:nats_cdb_stats](#cachedb_natsnats_cdb_stats) for
monitoring, and reserve this command for interactive use.


Parameters:


- *domains* (optional) - `1` adds a per-domain breakdown (the part
after the last "@" of each AoR, compared case-insensitively).
- *format* (optional) - `csv` or `txt` output (see above).


```bash
opensips-cli -x mi cachedb_nats:nats_reg_summary domains=1
```


```json
{
    "bucket": "opensips",
    "aors": 2,
    "contacts": 3,
    "active_contacts": 3,
    "expired_contacts": 0,
    "permanent_contacts": 0,
    "soonest_expiry": 1783008325,
    "soonest_expiry_in": 118,
    "scanned_keys": 2,
    "other_docs": 0,
    "scan_ms": 14,
    "domains": [{
        "domain": "example.com",
        "aors": 2, "contacts": 3, "active_contacts": 3
    }]
}
```


```bash
opensips-cli -x mi cachedb_nats:nats_reg_summary domains=1 format=csv
```


```text
{
    "bucket": "opensips", ...,
    "format": "csv",
    "data": "scope,domain,aors,contacts,active,expired,permanent\r\ntotal,,2,3,3,0,0\r\ndomain,example.com,2,3,3,,\r\n"
}
```


#### cachedb_nats:nats_reg_list


Per-AoR registration listing with filtering, sorting and pagination.
An unknown key or malformed value refuses the whole command (a
mistyped filter must never silently list the wrong subset).


Parameters:


- *filter* (optional) - a string of ";"-separated `key=value` pairs:
  - `aor=<glob>` - shell-style wildcard over the AoR (e.g.
  `aor=*@example.com`);
  - `domain=<host>` - case-insensitive exact match on the AoR's
  domain part;
  - `ua=<substring>` / `contact=<substring>` - substring match over a
  contact's user-agent / contact URI;
  - `state=active|expired|permanent|all` - rows having at least one
  contact in that state; default `active`;
  - `expiring_within=<secs>` - rows whose next expiry is at most this
  far away;
  - `min_contacts=<n>` - rows holding at least n stored contacts;
  - `sort=aor|expiry|contacts|last_mod` (+ `desc=1`) - `expiry` puts
  whatever dies next first; ties always break by AoR ascending, so
  pagination is deterministic;
  - `limit=<n>` (default 50, hard cap 200 — MI datagram size) and
  `offset=<n>`;
  - `format=csv|txt` (see above).


```bash
opensips-cli -x mi cachedb_nats:nats_reg_list 'domain=example.com;sort=expiry;limit=2'
```


```json
{
    "matched": 2, "returned": 2, "offset": 0,
    "scanned_aors": 2, "scan_ms": 12,
    "aors": [{
        "aor": "alice@example.com",
        "contacts": 2, "active": 2, "expired": 0, "permanent": 0,
        "expires_next": 1783008325, "expires_in": 118,
        "last_mod": 1783008207
    }, {
        "aor": "bob@example.com",
        "contacts": 1, "active": 1, "expired": 0, "permanent": 0,
        "expires_next": 1783011805, "expires_in": 3598,
        "last_mod": 1783008207
    }]
}
```


```bash
## find every Yealink, as CSV
opensips-cli -x mi cachedb_nats:nats_reg_list 'ua=Yealink;format=csv'
```


```text
{
    "matched": 1, "returned": 1, "offset": 0, ...,
    "format": "csv",
    "data": "aor,contacts,active,expired,permanent,expires_next,expires_in,last_mod\r\nalice@example.com,2,2,0,0,1783008325,118,1783008207\r\n"
}
```


#### cachedb_nats:nats_reg_show


Full detail of one AoR: every stored contact with all its attributes
(contact URI, expires, q, callid, cseq, user-agent, socket, received,
path, flags, last_mod, ...), each annotated with its computed
`state` and `expires_in`, plus the
row's KV metadata (revision, created timestamp,
`row_exp`, `schema_version`) — the
support view for "what exactly does the cluster believe about
this subscriber?".


Parameters:


- *aor* - the AoR to show.
- *format* (optional) - `csv` or `txt` output (see above).


```bash
opensips-cli -x mi cachedb_nats:nats_reg_show alice@example.com
```


```text
{
    "aor": "alice@example.com",
    "key": "json_alice=40example.com",
    "revision": 2, "created": 1783008207,
    "row_exp": 1783008325, "schema_version": 1,
    "contacts": [{
        "id": "c2lwOmFsaWNlQDEwLjAuMC4xOjUwNjA=",
        "contact": "sip:alice@10.0.0.1:5060",
        "expires": 1783011805, "ua": "Yealink T54W",
        "state": "active", "expires_in": 3598, ...
    }, {
        "id": "c2lwOmFsaWNlQDEwLjAuMC4yOjUwNjA=",
        "contact": "sip:alice@10.0.0.2:5060",
        "expires": 1783008325, "ua": "Zoiper 5",
        "state": "active", "expires_in": 118, ...
    }]
}
```


```bash
opensips-cli -x mi cachedb_nats:nats_reg_show alice@example.com csv
```


```text
{
    "aor": "alice@example.com", ..., "revision": 2,
    "format": "csv",
    "data": "aor,id,contact,state,expires,expires_in,q,cseq,callid,ua,sock,received,path,flags,cflags,last_mod\r\nalice@example.com,...,sip:alice@10.0.0.1:5060,active,...\r\n..."
}
```


#### cachedb_nats:nats_stream_list


Lists the JetStream streams on the connected server: name, message
and byte counts, subject and consumer counts, storage type.  A KV
bucket's backing stream (`KV_<bucket>`) also
reports the derived bucket name (the *kv_bucket* field), so operators
can think in bucket terms.  Results sort by name, so
pagination is deterministic.


Parameters:


- *filter* (optional) - a string of ";"-separated `key=value` pairs:
`name=<glob>`, `kv=1` (KV
backing streams only), `limit` (default 50, cap
200), `offset` and `format`.


```bash
opensips-cli -x mi cachedb_nats:nats_stream_list 'kv=1'
```


```json
{
    "matched": 1, "returned": 1, "offset": 0,
    "streams": [{
        "name": "KV_opensips", "kv_bucket": "opensips",
        "messages": 2, "bytes": 1044,
        "subjects": 2, "consumers": 1, "storage": "file"
    }]
}
```


#### cachedb_nats:nats_stream_info


Full configuration and state of one stream — the direct operator
check of a registration bucket's backing-stream expiry
preconditions: `max_age_s` must be 0 (a non-zero
stream MaxAge silently expires permanent contacts), with
`max_msgs_per_subject` showing the KV history
depth.  State reports messages, bytes, first/last
sequence, subject count, deleted count and consumers.


Parameters:


- *stream* - the stream name.
- *format* (optional) - `csv` or `txt` output (see above).


```bash
opensips-cli -x mi cachedb_nats:nats_stream_info KV_opensips
```


```json
{
    "name": "KV_opensips", "kv_bucket": "opensips",
    "config": {
        "subjects": ["$KV.opensips.>"],
        "storage": "file", "retention": "limits", "replicas": 1,
        "max_msgs_per_subject": 1, "max_age_s": 0,
        "allow_msg_ttl": true, "subject_delete_marker_ttl_s": 30
    },
    "state": {
        "messages": 2, "bytes": 1044,
        "first_seq": 1, "last_seq": 3,
        "subjects": 2, "deleted": 1, "consumers": 1
    }
}
```


```bash
## plain text, cut/awk-ready
opensips-cli -x mi cachedb_nats:nats_stream_info KV_opensips txt
```


```text
{
    "name": "KV_opensips", "kv_bucket": "opensips",
    "format": "txt",
    "data": "# field\tvalue\r\nname\tKV_opensips\r\nkv_bucket\topensips\r\nstorage\tfile\r\n...\r\nallow_msg_ttl\t1\r\nsubject_delete_marker_ttl_s\t30\r\n..."
}
```


#### cachedb_nats:nats_kv_keys


Lists the LIVE keys of a KV bucket — server-side delete markers are
never listed, so what this returns is what a reader can actually
Get.  Keys sort by name.


Read-only by construction: the bucket is *bound*,
never created, so a mistyped bucket name returns
"no such bucket" instead of materializing an empty
stream on the server.


Parameters:


- *filter* (optional) - a string of ";"-separated `key=value` pairs:
`bucket=<name>` (default: the module's
[kv_bucket](#kv_bucket-string)), `key=<glob>`,
`detail=1` (adds revision / created / value size
for each RETURNED key — one extra round-trip per key, bounded by
the limit cap), `limit` (default 50, cap 200), `offset` and
`format`.


```bash
opensips-cli -x mi cachedb_nats:nats_kv_keys 'key=json_alice*;detail=1'
```


```json
{
    "bucket": "opensips", "live_keys": 2,
    "matched": 1, "returned": 1, "offset": 0,
    "keys": [{
        "key": "json_alice=40example.com",
        "revision": 2, "created": 1783008207, "size": 731
    }]
}
```


### Exported Events


#### E_NATS_KV_CHANGE


Raised by the KV watcher process for every mutation received from
the NATS KV bucket (see [KV Watcher](#kv-watcher)).  This event allows
OpenSIPS routing scripts to react to changes made by any client in the
cluster — not just changes made through OpenSIPS itself.


Parameters:


- *key* (string) - the KV key that was modified.
- *operation* (string) - the type of mutation: *put* (value created
or updated), *delete* (soft delete tombstone), or
*purge* (hard delete with history removal).  A put with an empty
value (how a TTL or MaxAge expiry is delivered) is raised as
*delete*.
- *value* (string) - the new value of the key.  Present only for a
*put* with a non-empty value; absent for
*delete* and *purge*.
- *revision* (integer) - the NATS JetStream sequence number
(revision) of this mutation.
Revisions are monotonically increasing and globally ordered
within the KV bucket.


```opensips title="E_NATS_KV_CHANGE usage"
...
startup_route {
    subscribe_event("E_NATS_KV_CHANGE", "nats:opensips-events");
}

event_route[E_NATS_KV_CHANGE] {
    xlog("KV change: key=$param(key) op=$param(operation) rev=$param(revision)\n");
    if ($param(operation) == "put") {
        xlog("  new value: $param(value)\n");
    }
}
...
```


### Raw Query Commands


The module exposes NATS KV administrative operations via the standard
CacheDB `cache_raw_query` interface.  The
following commands are supported:


#### KV KEYS


Lists all keys currently present in the KV bucket.  The result has
one row per key, so the output AVP receives one value per key.


```opensips title="KV KEYS raw query"
...
cache_raw_query("nats", "KV KEYS", "$avp(keys)");
xlog("first KV key: $avp(keys)\n");
...
```


#### KV PURGE `<key>`


Permanently removes a key and its entire revision history from the
KV bucket.  Unlike a soft delete (which leaves a deletion tombstone),
a purge is irreversible and frees the storage used by all historical
revisions.  Wildcard or invalid keys are refused; purging a
non-existent key succeeds.


```opensips title="KV PURGE raw query"
...
cache_raw_query("nats", "KV PURGE json_user.alice");
...
```


#### KV BUCKET INFO


Returns one row of six columns describing the KV bucket: bucket
name, number of values, history depth, TTL in seconds, replica count
and bytes stored.


```opensips title="KV BUCKET INFO raw query"
...
cache_raw_query("nats", "KV BUCKET INFO",
    "$avp(bucket);$avp(values);$avp(history);$avp(ttl);$avp(replicas);$avp(bytes)");
xlog("bucket $avp(bucket): $avp(values) values, $avp(bytes) bytes\n");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
