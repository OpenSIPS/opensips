---
title: "cachedb_nats_fts Module"
description: "Optional secondary index for JSON documents stored through the cachedb_nats module."
---

## Admin Guide


### Overview


Optional secondary index for JSON documents stored in a NATS
JetStream KV bucket through the
[cachedb_nats](../cachedb_nats/README.md) module.  Loading this
module turns the index on; there is no separate switch.


When it is loaded, *cachedb_nats* feeds it from its write path and
from its KV watcher process: every top-level string field of a JSON
document whose key starts with the *cachedb_nats*
[fts_json_prefix](../cachedb_nats/README.md#fts_json_prefix-string)
becomes a *field:value* entry pointing at the document key.  The
index lives in shared memory, so all OpenSIPS processes use the
same copy.


The index serves the CacheDB `query()` and `update()` calls that
OpenSIPS modules make with non-key equality filters.  Without this
module, *cachedb_nats* accepts only single primary-key filters.
That is the recommended setup for a bucket used only as a usrloc
store: it saves the index memory and the per-write index update.


The index is built at startup by scanning the bucket.  It picks up
changes made by other OpenSIPS instances only through the
*cachedb_nats* KV watcher, so set at least one
[kv_watch](../cachedb_nats/README.md#kv_watch-string) pattern when
several instances share the bucket.


### Limitations


- The index answers AND lists of equality filters on string values.
Only top-level string fields are indexed; numbers, booleans and nested
values are skipped.  *cachedb_nats* sends any other query -- ranges or
integer values, such as usrloc's NAT-pinging `aorhash` range -- to a
scan of the bucket instead (see the
[cachedb_nats limitations](../cachedb_nats/README.md#limitations)).
- There is no script interface.  `cache_store`, `cache_fetch` and
`cache_raw_query` do not consult the index; only modules calling the
CacheDB `query()` and `update()` API use it.
- Only keys that start with the *cachedb_nats*
[fts_json_prefix](../cachedb_nats/README.md#fts_json_prefix-string) are indexed.
- The index is kept per OpenSIPS instance.  Without a
[kv_watch](../cachedb_nats/README.md#kv_watch-string) pattern it
never sees other instances' writes.  Writes made while
the watcher was disconnected appear after the post-reconnect rebuild
([index_resync_on_reconnect](../cachedb_nats/README.md#index_resync_on_reconnect-integer),
on by default); a restore of the bucket
from a snapshot appears only after a rebuild or restart.
- The module must be loaded after *cachedb_nats*.  Load order is not
enforced.
- Under heavy registration churn the default Q_MALLOC shared-memory
allocator becomes a point of contention; see the *cachedb_nats*
[allocator guidance](../cachedb_nats/README.md#shm-allocator-selection).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *nats* and *cachedb_nats*, see the [nats module](../nats/README.md).


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None* beyond those of *cachedb_nats*.


### Exported Parameters


#### index_buckets (integer)


Number of hash buckets in the index.  More buckets mean shorter
chains on lookup, at about 24 bytes of shared memory per bucket
(three tables of 8-byte heads), so 4096 -> 8192 adds about 96 KB.
The value is rounded up to the next power of two, with a minimum of
16; a value of 0 or less uses the default.


Recommended values: **4096** up to 20 000 AoRs, **16384** at
100 000, **65536** at 1 000 000.  Above about 1 000 000 endpoints,
do not load this module: the index then costs roughly 250 MB of
shared memory per instance and one CPU core in the watcher process.


*Default value is "4096".*


```opensips title="Set index_buckets parameter"
...
modparam("cachedb_nats_fts", "index_buckets", 16384)
...
```


#### fts_max_results (integer)


Maximum number of documents returned by one query.  It bounds the
memory used by broad filters that match a large part of the index.
A value of 0 or less removes the limit.


*Default value is "100".*


```opensips title="Set fts_max_results parameter"
...
modparam("cachedb_nats_fts", "fts_max_results", 500)
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
