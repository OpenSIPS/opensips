# cachedb_perf: configuration examples

Three deployment shapes, smallest first. Every example is complete — copy it,
adjust addresses, and it starts. The pull/sync parameters are explained where
they first become meaningful; a summary of the pull modes and transports closes
the page.

1. [Standalone](#1-standalone) — one node, no cluster modules at all
2. [Clustered via the stock clusterer](#2-clustered-via-the-stock-clusterer) — peers over the clusterer's bin links or the module's own udp/tcp sockets
3. [Clustered via clusterer_controller](#3-clustered-via-clusterer_controller) — zero-config membership on the controller's encrypted plane
4. [Pull modes and transports at a glance](#4-pull-modes-and-transports-at-a-glance)

---

## 1. Standalone

`cachedb_perf` is first of all a node-local cache. Without a cluster it is a
drop-in replacement for `cachedb_local` — the URL scheme is the whole
migration, and every cluster-facing parameter is simply inert.

### 1.1 Minimal drop-in

```
loadmodule "cachedb_perf.so"
modparam("cachedb_perf", "cachedb_url", "perf://")
```

```
# script: the backend id is "perf"
cache_store("perf", "call-$ci", "$var(state)", 3600);
cache_fetch("perf", "call-$ci", $var(state));
```

The default collection (`default`, 2^14 starting buckets) is created
automatically, and tables grow at runtime — the starting size is a hint, not
a capacity.

### 1.2 Named collections and URL groups

Separate keyspaces get separate collections; a consumer picks its collection
through the URL's path. A second URL under a *group* label lets one script use
several collections side by side:

```
modparam("cachedb_perf", "cache_collections", "th=16")
modparam("cachedb_perf", "cache_collections", "auth=12")
modparam("cachedb_perf", "cachedb_url", "perf:///th")
modparam("cachedb_perf", "cachedb_url", "perf:auth:///auth")

loadmodule "topology_hiding.so"
modparam("topology_hiding", "th_state_url", "perf:///th")
```

```
# ungrouped URL -> id "perf"; grouped URL -> id "perf:auth"
cache_store("perf:auth", "acct-$si", "$var(acct)", 86400);
```

The number after `=` is `log2(starting buckets)` — `th=16` starts at 65,536
buckets. Start near the expected entry count divided by ~4; growth covers the
rest.

### 1.3 Persistence across restarts

```
loadmodule "db_sqlite.so"
modparam("cachedb_perf", "db_url", "sqlite:///usr/local/etc/opensips/cachedb_perf.db")
modparam("cachedb_perf", "db_mode", 2)              ; 1 = load at startup,
                                                    ; 2 = also save on shutdown
modparam("cachedb_perf", "persist_collections", "th,auth")
```

The module ships no schema file — create the table once by hand (any `db_*`
backend works; `expires` is absolute wall-clock time, 0 = never):

```sql
CREATE TABLE cachedb_perf (
    collection TEXT    NOT NULL,
    pkey       TEXT    NOT NULL,
    pvalue     BLOB,
    expires    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collection, pkey)
);
CREATE INDEX cachedb_perf_purge ON cachedb_perf (collection, expires);
```

Entries come back after a restart with their original absolute expiry. The
save is a full snapshot (shutdown or explicit `perf_save` over MI) — a warm
handover, not a write-through store.

### 1.4 Memory backing

Where the records physically live is a policy, not a fixed property:

```
modparam("cachedb_perf", "memory_backing", "auto")   ; the default
```

* `core` — records are ordinary shm cells. With the HG_MALLOC core allocator
  this already means huge-page backing with the core's own reclaim; `auto`
  picks this on an HG core.
* `own-hg` — a dedicated HG arena named "cachedb_perf"
  (`arena_hugepage_mb` sets its size, `arena_hugepage_cap_mb` its growth
  cap), maintained by HG's own machinery. Works under **any** `-a` allocator
  as long as HG_MALLOC is compiled in; `auto` picks this when
  `arena_hugepage_mb` is set.
* `own` — the module's own slab inside plain shm, with its full reclaim:
  drained chunks are retired and re-cut for any size class, and whole quiet
  regions are given back to the OS. Tuning:

```
modparam("cachedb_perf", "memory_backing", "own")
modparam("cachedb_perf", "reclaim_keep", 1)        ; chunks kept per class
modparam("cachedb_perf", "reclaim_quiet_s", 5)     ; quiet window before give-back
modparam("cachedb_perf", "reclaim_cooloff_s", 10)  ; pause after a give-back
modparam("cachedb_perf", "reclaim_giveback", 1)    ; 0 = retire only, keep pages
```

An explicit value that is unavailable on the host (e.g. `own-hg` without
HG_MALLOC compiled in) refuses to start rather than silently degrading;
`perf_stats` reports the backing actually in effect under `arena.backing`.

---

## 2. Clustered via the stock clusterer

Adding the clusterer gives the cache two independent cluster behaviours, each
opt-in:

* **warm-up sync** (`sync_cluster_id` + `db_url`): `perf_sync` saves a
  collection to the DB and tells the peers to reload it — coarse, explicit
  convergence for failover/maintenance, not per-write replication;
* **pull-on-miss** (`replicate_collections` + a pull transport): a local miss
  asks the cluster for that one key and stores the answer locally — lazy read
  repair, hits stay local and cost nothing.

A minimal static two-node cluster (no DB needed by the clusterer itself):

```
loadmodule "proto_bin.so"
socket = bin:10.0.0.1:5555            # this node's cluster link

loadmodule "clusterer.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "my_node_id", 1)
modparam("clusterer", "my_node_info", "cluster_id=1, url=bin:10.0.0.1:5555")
modparam("clusterer", "neighbor_node_info",
         "cluster_id=1, node_id=2, url=bin:10.0.0.2:5555")

loadmodule "cachedb_perf.so"
modparam("cachedb_perf", "cache_collections", "th=16")
modparam("cachedb_perf", "cachedb_url", "perf:///th")

# --- warm-up sync (optional; needs db_url from example 1.3) ---
modparam("cachedb_perf", "sync_cluster_id", 1)

# --- pull-on-miss ---
modparam("cachedb_perf", "replicate_collections", "th")
modparam("cachedb_perf", "pull_transport", "bin")   ; the default
modparam("cachedb_perf", "pull_timeout_ms", 50)
modparam("cachedb_perf", "pull_negative_ms", 300)
modparam("cachedb_perf", "pull_on_miss", 1)
```

(The second node swaps the ids and addresses.)

### 2.1 The two pull modes

With `pull_on_miss = 0` (the default), nothing pulls implicitly. Cross-node
lookups happen only where explicitly asked for: the `perf_pull` MI command,
and consumers using the module's async pull API (e.g. `topology_hiding`'s
`async(topology_hiding_match(), resume)`), which suspend the transaction
instead of blocking a worker.

With `pull_on_miss = 1`, every miss on a replicated collection transparently
asks the cluster before being reported as a miss — zero script changes, at
the price of the calling process blocking for up to `pull_timeout_ms` on a
genuine cluster-wide miss. Peers answer negatives explicitly, so a key nobody
holds usually resolves in ~1 ms, not the full timeout; with no peers up, the
pull short-circuits instantly. `pull_negative_ms` then remembers a
cluster-wide "nobody has it" verdict briefly, so retransmissions and
key-storms do not re-ask.

### 2.2 Transports without a controller

`bin` (the default) rides the clusterer's existing TCP links — nothing to
configure, but every message passes through the core's TCP main dispatcher.
At high pull rates the module's own sockets are leaner, with a dedicated
receive process and no per-message hand-off:

```
modparam("cachedb_perf", "pull_transport", "udp")   ; or "tcp"
modparam("cachedb_perf", "pull_bind", "10.0.0.1")
modparam("cachedb_perf", "pull_port", 5688)
```

Peers discover each other's pull sockets automatically (announcements over
the clusterer links, repeated every 30 s; `pull_port` also acts as the
fallback guess before the first announcement lands). Choosing:

* `udp` — cheapest; a lost datagram is simply a pull that waits out
  `pull_timeout_ms`. Setting `pull_bind` without naming a transport selects
  udp implicitly.
* `tcp` — persistent per-peer connections owned by the module's receive
  process: ordered, reliable, and value sizes are not limited by the MTU.
* `bins` — BIN over TLS via the clusterer links, when the links themselves
  are TLS-secured (`proto_bins`); encrypted, but still dispatched centrally
  like `bin`.
* `tls` is reserved and refused at startup for now.

### 2.3 Tuning knobs that matter at scale

```
modparam("cachedb_perf", "pull_slots", 64)      ; concurrent in-flight pulls
modparam("cachedb_perf", "pull_max_key", 128)   ; per-key/value wire caps -
modparam("cachedb_perf", "pull_max_value", 512) ; oversize degrades to local-only
modparam("cachedb_perf", "pull_linger_ms", 0)   ; hold slots for late answers
modparam("cachedb_perf", "pull_authoritative_serve", 0)
```

`pull_authoritative_serve = 1` makes nodes that hold only a *pulled copy* of
a key answer "held" instead of shipping the bytes, so a converged cluster
returns one value per pull instead of one per holder; the requester falls
back to forcing a copy out when the original writer is gone. Enable it only
once the whole cluster runs a version that understands it — older peers read
the "held" answer as silence.

### 2.4 Sharing-tag failover hook

```
modparam("cachedb_perf", "sync_shtag", "vip/1")
```

Paired with the clusterer's sharing tags: the node *losing* the active tag
saves its collections, the node *gaining* it reloads them — a one-shot bulk
warm-up at failover time instead of a pull storm.

---

## 3. Clustered via clusterer_controller

The `clusterer_controller` module replaces static node provisioning with
multicast discovery, master election and runtime node-id assignment — and
gives `cachedb_perf` an encrypted datagram plane to pull over. The clusterer
stays loaded (it still carries the bin links and the node table); it is just
told the controller owns this cluster:

```
loadmodule "proto_bin.so"
socket = bin:10.0.0.1:5555

loadmodule "clusterer.so"
modparam("clusterer", "db_mode", 0)
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")

# load the controller BEFORE cachedb_perf
loadmodule "clusterer_controller.so"
modparam("clusterer_controller", "interface", "eth1")
modparam("clusterer_controller", "password", "a-strong-shared-secret")
modparam("clusterer_controller", "cluster",
         "id=1,multicast=239.255.1.1:3333,bin_socket=bin:10.0.0.1:5555")

loadmodule "cachedb_perf.so"
modparam("cachedb_perf", "cache_collections", "th=16")
modparam("cachedb_perf", "cachedb_url", "perf:///th")
modparam("cachedb_perf", "sync_cluster_id", 1)
modparam("cachedb_perf", "replicate_collections", "th")
modparam("cachedb_perf", "pull_transport", "clctr")
modparam("cachedb_perf", "pull_timeout_ms", 50)
modparam("cachedb_perf", "pull_on_miss", 1)
```

Every node ships the identical block apart from its own addresses — no node
ids, no neighbor lists; a booting node joins the multicast group, gets a
node id assigned, and `cachedb_perf` tracks the membership through the
clusterer's node events.

What `clctr` buys over the other transports:

* **encrypted** — pulls ride the controller's XChaCha20-Poly1305 session,
  keyed from the shared password (Argon2id + a Noise handshake); nothing
  else on the pull path is encrypted today (`bin`, `udp`, `tcp` are
  plaintext, trusted-LAN transports);
* **no central dispatcher** — requests go out as one multicast datagram,
  replies return as unicast datagrams, none of it queuing behind the core's
  TCP main;
* **membership-aware by construction** — peers appear and disappear with the
  controller's own join/leave handling.

On a dual-homed host pin `interface` (or `my_ip`) explicitly — auto-detection
follows the default route, which is routinely the wrong (public) NIC.

Degraded operation is explicit, never silent: `pull_transport=clctr` with the
controller module absent logs a warning and falls back to `bin`; with no
clusterer at all, pull and sync switch off and the cache runs node-local —
the standalone behaviour of example 1.

---

## 4. Pull modes and transports at a glance

| | mechanism | when |
|---|---|---|
| `pull_on_miss=0` + async API / `perf_pull` | explicit, suspending lookups only | SIP-path deployments that must never block a worker |
| `pull_on_miss=1` | every miss on a replicated collection asks the cluster, blocking up to `pull_timeout_ms` | zero-code adoption; misses rare or a peer answer cheaper than the fallback (DB/REST) |
| `perf_sync` / `sync_shtag` | snapshot to DB + peers reload | bulk convergence at failover or maintenance, not per-key |

| transport | path | encrypted | notes |
|---|---|---|---|
| `bin` (default) | clusterer TCP links | no | zero config; centrally dispatched |
| `bins` | clusterer TLS links | yes | needs `proto_bins` links; centrally dispatched |
| `udp` | module's own socket + receive process | no | cheapest; loss = one timed-out pull |
| `tcp` | module's own per-peer connections | no | ordered, no MTU limit on values |
| `clctr` | clusterer_controller datagram plane | yes | needs the controller (section 3) |

Observability for all of the above lives in `perf_stats` (per-collection
`pulled_from_cluster`/`served_to_cluster`, the `pulls_*` counters explaining
every miss, `cluster.topology` with per-peer answer health) — see the module
README.
