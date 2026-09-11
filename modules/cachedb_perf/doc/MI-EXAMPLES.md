# cachedb_perf: MI examples

Every command below is real — signatures come straight from the module's
`mi_export_t` table, and every response shape shown is the module's actual
field set, not a paraphrase. Two invocation surfaces work identically
(assuming `mi_fifo`/`mi_http` are loaded):

```bash
# opensips-cli, over mi_fifo
opensips-cli -x mi perf_stats

# raw JSON-RPC, over mi_http
curl -s http://127.0.0.1:8888/mi -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"perf_stats","params":[]}'
```

**Two rules that cost real debugging time if skipped:**

1. **Named parameters only, and the exact set the recipe expects.** A
   positional call (`perf_set foo bar`) fails with `"Ambiguous call"`; an
   unlisted subset of named params fails with `"Named parameters do not
   match"`. Every example below uses the named form for exactly this reason.
2. **Invoke as `cachedb_perf:<command>`.** `register_mi_mod` namespaces by
   module (same as `dispatcher:list`, `dialog:list`). A bare name works by
   accident over raw `mi_datagram` JSON-RPC on some builds, but the
   documented, portable form is always module-qualified — used throughout
   below.

1. [Read & introspect](#1-read--introspect) — `perf_stats`, `perf_stats_reset`, `perf_keys`, `perf_scan`, `perf_dump`
2. [Single-key operations](#2-single-key-operations) — `perf_get`, `perf_set`, `perf_probe`
3. [Bulk operations](#3-bulk-operations) — `perf_del`, `perf_ttl`
4. [Cross-node pull (CP-15)](#4-cross-node-pull-cp-15) — `perf_pull`, `perf_cluster_probe`, `perf_cluster_size`
5. [Persistence & cluster sync (CP-19)](#5-persistence--cluster-sync-cp-19) — `perf_save`, `perf_load`, `perf_sync`
6. [All 16 commands at a glance](#6-all-16-commands-at-a-glance)

---

## 1. Read & introspect

### `perf_stats [collection]`

No argument reports every collection; naming one reports just that one (404
if it doesn't exist). This is the one command worth reading field-by-field —
it's the fastest way to answer "is this cache healthy right now."

```bash
opensips-cli -x mi cachedb_perf:perf_stats collection=th
```
```json
{
    "collections": [{
        "name": "th", "buckets": 65536, "entries": 18796, "overflow": 0,
        "hits": 412009, "misses": 214, "stores": 18796, "removes": 3021,
        "expired": 9880, "stores_immortal": 0, "destroyed": 12901,
        "seqlock_retries": 0, "lock_fallbacks": 0,
        "hit_rate_pct": "99.94", "reads_per_store": "21.94",
        "expired_pct_of_expirable": "52.6",
        "hit_rate_note": "18796 stores, 9880 (52.6%) of the expirable ones expired, 3021 removed explicitly",
        "load_factor": "0.29", "retries_per_1k_reads": "0.00"
    }],
    "arena": { "chunks": 412, "bytes": 26963968, "backing": "core-shm" },
    "memory_tier_probe": 1, "memory_backing_probe": "MAP_HUGETLB",
    "memory_tier_active": 99, "memory_backing_active": "core shm arena",
    "hugepage_reservation": { "active": 0, "total_bytes": 0, "used_bytes": 0, "free_bytes": 0 }
}
```

`hit_rate_note` is generated, not graded — it states `reads_per_store` and
`expired_pct_of_expirable` and stops; there is no healthy/warning banding
(see the module's design notes on why grading this number is a trap).
`memory_tier_active`/`memory_backing_active` is the tier **actually** in use
right now; `_probe` is only what the host was capable of at startup — the
two can and do disagree (an unset `arena_hugepage_mb` means every store rides
the core's own shm arena, `memory_backing_active: "core shm arena"`,
regardless of what tier 1 probing found available). The `cluster` object
(peer counts, membership generation, pull counters) only appears when
`sync_cluster_id` is set and the cluster has actually formed — see §4/§5.

### `perf_stats_reset [collection]`

Re-baselines the cumulative counters (hits/misses/stores/...) so the
percentages in the next `perf_stats` cover a fresh interval. Live gauges
(`entries`, `overflow`, `buckets`) are untouched — resetting counters can't
make the table forget what's actually stored.

```bash
opensips-cli -x mi cachedb_perf:perf_stats_reset
```
```json
{ "collections_reset": 3 }
```

### `perf_keys <glob> [collection] [limit]`

Names + TTL for keys matching a glob, default limit 1000. **`<glob>` comes
first, `collection` second** — `perf_keys glob=default` matches keys
literally named "default", not the default collection. Quote globs in a
shell so `*` doesn't get expanded.

```bash
opensips-cli -x mi cachedb_perf:perf_keys glob='call-*' collection=default limit=5
```
```json
{ "keys": ["call-a1b2", "call-c3d4"], "returned": 2 }
```

A truncated result adds `"note": "limit reached - truncated; narrow the
glob or use perf_scan"` — that note is the signal to switch tools, not to
raise the limit indefinitely.

### `perf_scan <cursor> [glob] [count]`

Redis-`SCAN`-style cursored walk over the **default (groupless) collection
only** — there's no `collection` parameter, by design (see the gotcha at
the end of this section). Pass `cursor=0` to start; a returned `cursor` of
`0` means the walk is complete. Whole-bucket steps mean no duplicate within
one resumed page, and it stays correct across a concurrent table resize.

```bash
opensips-cli -x mi cachedb_perf:perf_scan cursor=0 count=500
# ...
opensips-cli -x mi cachedb_perf:perf_scan cursor=8192 count=500
```
```json
{ "keys": ["k1", "k2", "..."], "cursor": 16384, "returned": 500 }
```

Keep the cursor value verbatim between calls — it's a routing/bucket index
into the live table, not a page number.

### `perf_dump <glob> [collection] [limit]`

Same shape and same param order as `perf_keys`, but each entry carries its
value too — opt in only when you actually need the values, since dumping is
strictly more expensive than listing names.

```bash
opensips-cli -x mi cachedb_perf:perf_dump glob='*' collection=default limit=10
```
```json
{ "keys": [...], "values": [...], "returned": 10 }
```

---

## 2. Single-key operations

These three are the only commands that take `<key>` first — everything else
in this doc takes a glob or a collection first.

### `perf_get <key> [collection]`

```bash
opensips-cli -x mi cachedb_perf:perf_get key=call-a1b2 collection=default
```
```json
{ "key": "call-a1b2", "value": "answered", "size": 8, "ttl": 3421 }
```
`404 "key not found"` on a miss or an expired key. `ttl: -1` means the key
never expires (stored with `ttl=0`).

### `perf_set <key> <value> [ttl] [collection]`

`ttl` defaults to `0` (never expires) when omitted.

```bash
opensips-cli -x mi cachedb_perf:perf_set key=call-a1b2 value=ringing ttl=60 collection=default
```
```json
{ "code": 200, "message": "OK" }
```

### `perf_probe <key> [collection]`

Existence + TTL + size, **never the value** — deliberately, so this command
costs exactly what a cross-node existence check costs (no copy, no
allocation, the payload is never touched). Use `perf_get` when you actually
need the value.

```bash
opensips-cli -x mi cachedb_perf:perf_probe key=call-a1b2
```
```json
{ "key": "call-a1b2", "size": 8, "ttl": 3421 }
```

---

## 3. Bulk operations

Both collect matches with a lock-free walk, then act on each individually —
not an atomic snapshot, so a key that changes mid-walk may or may not be
included, same as `perf_keys`/`perf_dump`.

### `perf_del <glob> [collection]`

The MI face of the `perf_del()` script function — same glob-first param
order as `perf_keys`.

```bash
opensips-cli -x mi cachedb_perf:perf_del glob='stale-*' collection=default
```
```json
{ "deleted": 42 }
```

### `perf_ttl <glob> <ttl> [collection]`

Re-arms the TTL of every matching **live** key in place — a versionless
bump (one atomic `expires` store under the bucket lock), never a value
rewrite, and never revives an already-expired key. `ttl=0` re-arms to
never-expire.

```bash
opensips-cli -x mi cachedb_perf:perf_ttl glob='call-*' ttl=7200 collection=default
```
```json
{ "updated": 18796 }
```

---

## 4. Cross-node pull (CP-15)

These exist to exercise and observe the cross-node pull protocol on their
own terms, independent of a SIP path — the MI face is what makes a failing
pull diagnosable instead of just silently falling through to a miss.

### `perf_pull <key> [collection]`

Asks the cluster for one key. If the key is already local, no cluster
traffic happens at all — `perf_pull` says so plainly rather than pretending
it asked:

```bash
opensips-cli -x mi cachedb_perf:perf_pull key=call-a1b2 collection=th
```
```json
{ "source": "local", "size": 8, "ttl": 3421 }
```

A genuine miss resolved by the cluster, or one that came back empty:

```json
{ "source": "cluster", "value": "ringing", "size": 7, "ttl": 55 }
```
```json
{ "source": "absent" }
```

`source: "no-answer"` means no peer replied inside `pull_timeout_ms` — the
same three-way distinction the pull layer itself uses internally
(`local` / `cluster` / `absent` / `no-answer`), so this command is a direct
window into what a real miss on the SIP path would have seen. `500` if
`replicate_collections` doesn't cover this collection at all — pulling only
ever makes sense for a collection the cluster actually shares.

### `perf_cluster_probe [collection]`

Asks **every** peer for a key that provably cannot exist, purely to see who
answers. This is the liveness check for the pull transport itself, cheap
by construction — a negative reply costs the responder one bucket tag-word
comparison, nothing else.

```bash
opensips-cli -x mi cachedb_perf:perf_cluster_probe collection=th
```
```json
{
    "asked": 2, "answered": 2, "timeout_ms": 100, "transport": "bin",
    "peers": [
        { "node_id": 2, "answered_probe": "yes" },
        { "node_id": 3, "answered_probe": "yes" }
    ]
}
```
`400` if cross-node pull isn't active for the collection at all.

### `perf_cluster_size [collection]`

Live per-node entry counts across the whole cluster for one collection —
the convergence gauge: watch this trend toward `N × per-node-count` as a
freshly-joined node's misses get pulled in.

```bash
opensips-cli -x mi cachedb_perf:perf_cluster_size collection=th
```
```json
{
    "collection": "th",
    "nodes": [
        { "node_id": 1, "entries": 18796, "source": "local" },
        { "node_id": 2, "entries": 18801 },
        { "node_id": 3, "entries": 18779 }
    ],
    "peers_answered": 2, "peers_asked": 2, "total_entries": 56376
}
```
A node that doesn't reply reports `"status": "no reply"` instead of a count,
and `total_entries` gets a `"note": "total covers answering nodes only"` so
a partial answer is never silently read as the whole cluster's size. With
no cluster formed at all, `"cluster": "not formed - local view only"` and
the response covers only this node.

---

## 5. Persistence & cluster sync (CP-19)

Both need a DB backend configured (`db_url`) — `500 "no DB backend
configured (set db_url)"` otherwise. With no `collection` argument, both
operate on every declared collection.

### `perf_save [collection]` / `perf_load [collection]`

Full blocking synchronous snapshot — one SQL statement per entry. Fine for
maintenance/bootstrap, never for anything on a hot path.

```bash
opensips-cli -x mi cachedb_perf:perf_save collection=th
```
```json
{ "collections": 1, "saved": 18796 }
```
```bash
opensips-cli -x mi cachedb_perf:perf_load
```
```json
{ "collections": 3, "loaded": 41207 }
```

### `perf_sync [collection]`

Save-then-broadcast: writes the collection to the DB, then signals cluster
peers to reload it from there. This **overwrites** a peer's copy — it's
single-writer/read-replica convergence, not a merge, and not per-operation
replication. A node that also takes local writes loses its unsaved ones on
the next sync it receives.

```bash
opensips-cli -x mi cachedb_perf:perf_sync collection=th
```
```json
{ "collections": 1, "saved": 18796, "broadcast": 1 }
```

Without a clusterer, or with `sync_cluster_id` unset/`0`, this degrades to a
DB-only save rather than failing — `broadcast` reads `0` and a note explains
why:

```json
{
    "collections": 1, "saved": 18796, "broadcast": 0,
    "note": "cluster sync inactive (no clusterer / cluster_id 0) - saved to the DB only"
}
```

---

## 6. All 16 commands at a glance

| command | named params | what it does |
|---|---|---|
| `perf_stats` | `[collection]` | per-collection health: entries, hit rate, memory tier, cluster view |
| `perf_stats_reset` | `[collection]` | re-baseline the rate counters; live gauges untouched |
| `perf_keys` | `glob`, `[collection]`, `[limit]` | names + TTL of keys matching a glob |
| `perf_scan` | `cursor`, `[glob]`, `[count]` | cursored SCAN-style walk, default collection only |
| `perf_dump` | `glob`, `[collection]`, `[limit]` | names + values matching a glob |
| `perf_get` | `key`, `[collection]` | one key: value, TTL, size |
| `perf_set` | `key`, `value`, `[ttl]`, `[collection]` | write one key |
| `perf_probe` | `key`, `[collection]` | one key: TTL + size, value never touched |
| `perf_del` | `glob`, `[collection]` | delete every key matching a glob |
| `perf_ttl` | `glob`, `ttl`, `[collection]` | re-arm the TTL of every key matching a glob |
| `perf_pull` | `key`, `[collection]` | ask the cluster for one key on a local miss |
| `perf_cluster_probe` | `[collection]` | ask every peer a provably-absent key, to check who answers |
| `perf_cluster_size` | `[collection]` | live per-node entry counts across the cluster |
| `perf_save` | `[collection]` | snapshot to the DB backend |
| `perf_load` | `[collection]` | load from the DB backend |
| `perf_sync` | `[collection]` | save to the DB, then signal peers to reload |

`perf_get`/`perf_set`/`perf_probe` take `<key>` first; every other command
that touches a set of keys takes `<glob>` first, `collection` second — the
one param-order gotcha worth memorizing before scripting against this API.
