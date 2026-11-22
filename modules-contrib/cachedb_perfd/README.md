---
title: "cachedb_perfd Module"
description: "CacheDB backend for perfcached - a multithreaded, self-clustering cache daemon reached over a Noise-authenticated binary protocol."
---

## Admin Guide


### Overview


This module serves the core Key-Value interface (`cache_store()`,
`cache_fetch()`, `cache_add()` and friends) from
[perfcached](https://github.com/Lt-Flash/perfcached), a multithreaded,
self-clustering cache daemon, the same way `cachedb_redis` or
`cachedb_memcached` serve theirs.  The module holds no data of its own.

It talks to the daemon through **libperfd**, perfcached's client library,
inside a **Noise** channel: a shared client secret is the whole
handshake, with no TLS certificates.  Given one seed node, libperfd
learns the cluster's members, sends each key straight to the node that
owns it and fails over to an already-open standby connection when a node
dies.  See the [perfcached documentation](https://github.com/Lt-Flash/perfcached/blob/master/README.md)
and [libperfd](https://github.com/Lt-Flash/perfcached/blob/master/lib/README.md).

Connections are lazy and per-process: the first cache operation in a
worker opens that worker's connection, so a daemon that is down at
startup does not fail it.  The Noise key is derived once in the parent
and inherited by every worker.  When no seed answers, the worker waits
1 second before dialling again, doubling to 30 seconds while the outage
lasts; operations in between fail at once.


### Limitations


- *no query/update/map API (`cachedb_redis`'s usrloc support): keys,
  counters and raw commands only*
- *only `perfd_fetch()` is asynchronous; the other operations block the
  worker for one round trip*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


- **libperfd** 0.7.6.1 or later (MIT), found with pkg-config:
  `libperfd-dev` from the [perfcached release packages](https://github.com/Lt-Flash/perfcached/releases)
  (Debian, Ubuntu, Alpine), or `make install-lib` in a perfcached source
  tree.  Build with `PERFD_STATIC=1` to link `libperfd.a`.
- **libsodium**, which libperfd depends on.

The module is in `modules-contrib/` and is not built by default:

    make modules=modules-contrib/cachedb_perfd modules-contrib
    make modules=modules-contrib/cachedb_perfd install-modules-all

The Debian and RPM packages build it as
`opensips-module-contrib-cachedb-perfd` only with the `perfd` build
profile (`DEB_BUILD_PROFILES=perfd`) or `--with perfd`.


### Exported Parameters


#### cachedb_url (string)


The URL of a perfcached node or cluster.  May be set more than once;
the group part of the URL is the name used from the script.

```
perfd[:group]://[:secret@]host:port[,host:port...]/collection[?opt,opt,...]
```

The password is the daemon's client secret (empty means plaintext,
which perfcached accepts only on localhost).  The port and the
collection are required.  Up to 8 seeds, comma separated; IPv6 literals
keep their brackets.  The options `route`, `encrypt`, `spares` and
`policy` are those of [libperfd URLs](https://github.com/Lt-Flash/perfcached/blob/master/lib/README.md#urls-conditional-json-sets-describing-a-handle);
an unknown option or a bad value refuses the URL.

```opensips title="Set cachedb_url parameter"
...
modparam("cachedb_perfd", "cachedb_url",
    "perfd://:s3cr3t@10.0.0.5:6479,10.0.0.6:6479,10.0.0.7:6479/subs")
modparam("cachedb_perfd", "cachedb_url",
    "perfd:grp://:s3cr3t@10.0.1.9:6479/acct?spares=0")
...
```

Keys are 1 to 511 bytes with no NUL byte.  `cache_store()` with an
expiry of `0` stores the value without one; `cache_add()` and
`cache_sub()` with `0` keep the counter's current expiry.

```opensips title="Use perfcached from the script"
...
cache_store("perfd", "sess_$ci", "$fu", 300);
cache_fetch("perfd", "sess_$ci", $avp(sess));
cache_add("perfd:grp", "calls_$fU", 1, 60, $avp(n));
...
```


#### connect_timeout (integer)


Milliseconds to wait for the TCP connection and the Noise handshake to
a node.

*Default value is "5000" (0 keeps the default).*

```opensips title="Set connect_timeout parameter"
modparam("cachedb_perfd", "connect_timeout", 1000)
```


#### query_timeout (integer)


Milliseconds to wait for each send or receive during an operation.  A
read whose owner does not answer in time fails (`-1`); it is never
reported as a miss.

*Default value is "5000" (0 keeps the default).*

```opensips title="Set query_timeout parameter"
modparam("cachedb_perfd", "query_timeout", 500)
```


#### fleet_refresh (integer)


The longest time, in milliseconds, between two refreshes of the
cluster's member list.

*Default value is "30000" (0 keeps the default).*

```opensips title="Set fleet_refresh parameter"
modparam("cachedb_perfd", "fleet_refresh", 5000)
```


#### keepalive (integer)


TCP keepalive idle time, in seconds.  `-1` turns keepalive off.

*Default value is "30" (0 keeps the default).*

```opensips title="Set keepalive parameter"
modparam("cachedb_perfd", "keepalive", 10)
```


#### idle_ping (integer)


Milliseconds after which an idle standby connection is pinged.  `-1`
turns it off.

*Default value is "30000" (0 keeps the default).*

```opensips title="Set idle_ping parameter"
modparam("cachedb_perfd", "idle_ping", 10000)
```


#### async_conns (integer)


Size of the per-process connection pool used by `perfd_fetch()`, from
1 to 1024.

*Default value is "8".*

```opensips title="Set async_conns parameter"
modparam("cachedb_perfd", "async_conns", 16)
```


### Exported Functions


#### perfd_fetch(group, key, var)


Asynchronous `cache_fetch()`, for an `async()` statement.  `group` is
the group of the `cachedb_url` (`""` for an unnamed one).  Return codes
match `cache_fetch()`: `1` on a hit, `-2` on a miss, `-1` on error,
including no reply within `query_timeout` (rounded up to a whole second
while the request is suspended).

Each request in flight uses a connection of its own from the
`async_conns` pool.  With every connection busy the call falls back to
a blocking fetch and logs a warning at most once a minute; when no node
can be reached it fails at once.

```opensips title="perfd_fetch usage"
...
route {
    async(perfd_fetch("grp", "$fU", $avp(profile)), resume_lookup);
}
...
```


### Raw Queries


`cache_raw_query()` runs a Redis-style command on the URL's collection,
routed to the key's owner: `GET`, `SET`, `SETEX`, `DEL`, `EXISTS`,
`EXPIRE`, `TTL`, `INCR`/`INCRBY`/`DECR`/`DECRBY`, `MGET`, `MSET`, the
`H*` hash commands and `JSON.GET`/`JSON.SET`/`JSON.DEL`; other commands
are refused.  Replies come back as with `cachedb_redis`.  `MSET` is not
atomic across nodes.  A literal `$` is written `$$` in a script string.

The query is split on spaces, and quotes keep an argument together, so
a variable holding a space or a quote changes the command.  Do not put
values taken from a SIP message into a raw query unchecked.

```opensips title="cache_raw_query usage"
...
cache_raw_query("perfd:grp", "MGET sess_a sess_b sess_c", "$avp(vals)");
cache_raw_query("perfd:grp", "JSON.SET acct_$fU $$.calls 0 NX");
...
```

<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
