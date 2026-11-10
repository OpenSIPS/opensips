---
title: "nats Module"
description: "The NATS connection shared by the OpenSIPS NATS modules: the libnats loader, the per-process connection pool and the settings of that connection."
---

## Admin Guide


### Overview


OpenSIPS talks to [NATS](https://nats.io) and its JetStream persistence
layer through four modules, built on this one. The *nats* module holds
the NATS connection of each OpenSIPS process: it loads libnats, keeps
the connection pool, the JetStream context and the KV bucket handles,
and takes the settings of that connection (server order, reconnect
buffer, drain timeout, credentials). It has no script functions of its
own. The three modules that talk to NATS (*event_nats*, *cachedb_nats*,
*nats_consumer*) share its connection; *cachedb_nats_fts* works through
*cachedb_nats*.

| Module | Direction | What it gives you |
| ------ | --------- | ----------------- |
| [event_nats](../event_nats/README.md) | OpenSIPS → NATS | Event Interface transport (`nats:<subject>` sockets), [nats_publish()](../event_nats/README.md#nats_publishsubject-payload-msg_id), optional JetStream publishing, stream management over MI, core-NATS [subscribe](../event_nats/README.md#subscribe-string) into script events |
| [cachedb_nats](../cachedb_nats/README.md) | OpenSIPS ↔ NATS KV | CacheDB backend on a JetStream KV bucket, usrloc `full-sharing-cachedb` storage, KV change events, registration MI views |
| [cachedb_nats_fts](../cachedb_nats_fts/README.md) | inside OpenSIPS | Optional secondary index for *cachedb_nats* JSON documents; loading it turns non-key queries on |
| [nats_consumer](../nats_consumer/README.md) | NATS → OpenSIPS | JetStream pull consumers delivered to SIP workers, explicit ack/nak/term, [nats_request()](../nats_consumer/README.md#nats_requestsubject-payload-timeout_ms) request/reply (sync and async) |

Load `nats.so` and the modules you need. *event_nats*, *cachedb_nats*
and *nats_consumer* each run on their own, and any combination shares
the same connection; *cachedb_nats_fts* needs *cachedb_nats*. Load
order does not matter, except that *cachedb_nats_fts* must be loaded
after *cachedb_nats*: each NATS module declares a dependency on *nats*,
so OpenSIPS initializes *nats* first, and a configuration that loads a
NATS module without `nats.so` does not start:

```text title="A NATS module loaded without nats.so"
WARNING:core:solve_module_dependencies: module event_nats depends on module nats, but it was not loaded!
ERROR:core:main: failed to solve module dependencies
```

These modules live in `modules-contrib/`, outside the default build.
Build them explicitly:

```bash title="Build the NATS modules"
make modules="modules-contrib/nats modules-contrib/event_nats modules-contrib/cachedb_nats modules-contrib/cachedb_nats_fts modules-contrib/nats_consumer" modules-contrib
```


### Requirements


- **nats-server** with JetStream enabled. Versions 2.10 and 2.11+ are
  tested.
- **libnats** (the [nats.c](https://github.com/nats-io/nats.c) client),
  **3.14 or later**. The modules need the per-key KV TTL API
  (`kvStore_CreateWithTTL`), which first shipped in 3.14. CI builds the
  commit pinned in `scripts/build/install_libnats.sh`, which can also
  build and install it for you:

  ```bash title="Build and install the pinned libnats"
  sudo LIBNATS_TLS=ON sh scripts/build/install_libnats.sh
  ```

- **The libnats you run must match the one you built against.** The
  modules do not link libnats; the *nats* module loads it with
  `dlopen()` at startup and refuses a library whose major.minor version
  differs from the headers OpenSIPS was compiled with (JetStream option
  structs change size between minor releases). A mismatch stops
  OpenSIPS with an error naming both versions. Rebuild the NATS modules
  after upgrading libnats.
- **TLS** needs a libnats built with TLS (`-DNATS_BUILD_WITH_TLS=ON`,
  `LIBNATS_TLS=ON` above) and the *tls_mgm* module; see [TLS](#tls).

If the build cannot find libnats (`pkg-config libnats`), the NATS
modules are skipped with a `[skip]` build message.


### Quick start


Start a broker with JetStream:

```bash title="Local broker"
nats-server -js
```

Then load what you need. This configuration publishes SIP events,
stores cache data in a KV bucket and consumes a work queue, all over one
connection. The KV bucket is created on first start; with a single
broker it must use one replica (the default is three):

```opensips title="All four modules on one broker"
loadmodule "nats.so"

loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "nats://127.0.0.1:4222")

loadmodule "cachedb_nats.so"
modparam("cachedb_nats", "cachedb_url", "nats://127.0.0.1:4222/")
modparam("cachedb_nats", "kv_bucket", "opensips")
modparam("cachedb_nats", "kv_replicas", 1)

loadmodule "cachedb_nats_fts.so"

loadmodule "nats_consumer.so"
modparam("nats_consumer", "bind",
    "id=jobs;stream=JOBS;filter=jobs.>;durable=jobs_worker")

route {
    nats_publish("sip.requests", "$rm $ru");

    cache_store("nats", "call.$(ci{s.md5})", "$fu");

    if (nats_fetch("jobs")) {
        xlog("job $nats_subject: $nats_data\n");
        nats_ack();
    }
}
```

The consumer binds to the stream `JOBS`, which must exist. Create it
with the `nats` CLI or through OpenSIPS once it is running:

```bash title="Create the JOBS stream"
opensips-cli -x mi event_nats:nats_stream_create JOBS 'jobs.>'
```

Until the stream exists the consumer logs a failed subscribe and keeps
retrying; it binds within a few seconds of the stream appearing.

At startup OpenSIPS logs which libnats it loaded, and each process logs
when it has connected:

```text title="Startup log"
INFO:nats:nats_dl_load: nats_dl: loaded 'libnats.so'; 134 libnats symbols resolved
INFO:nats:pool_register: NATS pool: registered by 'event_nats' with 1 server(s), TLS=no, reconnect_wait=2000ms, max_reconnect=60
INFO:nats:nats_pool_get: NATS pool: connected to nats://127.0.0.1:4222 (1 server(s) configured)
```

If the broker is down at startup, OpenSIPS still starts. The pool logs
`NATS pool: not connected at startup (broker unreachable, or credentials
or TLS refused); continuing degraded with background connect retries` and
connects when the broker appears. libnats reports a refused password or
TLS handshake at startup the same way, without saying which, so check
the credentials and TLS settings if the broker is up.


### TLS


TLS is configured in *tls_mgm*, in a client domain that must be named
`nats`. None of the NATS modules has TLS parameters of its own. A
`tls://` server URL switches the connection to TLS; `nats://` URLs ignore
the `nats` domain.

```opensips title="NATS over TLS"
loadmodule "tls_mgm.so"
loadmodule "tls_openssl.so"
modparam("tls_mgm", "client_domain", "nats")
modparam("tls_mgm", "verify_cert",   "[nats]1")
modparam("tls_mgm", "require_cert",  "[nats]1")
modparam("tls_mgm", "certificate",   "[nats]/etc/opensips/tls/client.pem")
modparam("tls_mgm", "private_key",   "[nats]/etc/opensips/tls/client.key")
modparam("tls_mgm", "ca_list",       "[nats]/etc/opensips/tls/ca.pem")
# or a directory of .pem files:
# modparam("tls_mgm", "ca_directory", "[nats]/etc/opensips/tls/ca.d/")

loadmodule "nats.so"
loadmodule "event_nats.so"
modparam("event_nats", "nats_url", "tls://nats-1:4222,tls://nats-2:4222")
```

The settings are applied when the pool connects (`apply_tls_from_mgm()`
in `nats_pool.c`), not when the modules load. There is no silent
downgrade to plaintext. The connection fails with an error naming the
missing piece in any of these cases:

- a `tls://` URL is used and *tls_mgm* is not loaded;
- *tls_mgm* is loaded but has no `nats` client domain;
- the libnats in use was built without TLS.

For a `ca_directory`, `nats_ca_dir.c` reads every `.pem` file in the
directory in name order and passes them to libnats as one PEM bundle
(`natsOptions_SetCATrustedCertificates`), matching OpenSSL's
directory-lookup behaviour.

libnats does its own TLS. Which TLS library it uses is fixed when
libnats is built, and it does not have to match the *tls_openssl* or
*tls_wolfssl* module OpenSIPS uses for SIP. One libnats is loaded per
process. To choose a specific build, set `NATS_DL_LIBNATS_PATH` in
OpenSIPS's environment (for example with `Environment=` in the systemd
unit):

```bash title="Load a specific libnats build"
NATS_DL_LIBNATS_PATH=/opt/libnats-tls/lib/libnats.so.3.15
```

To check which libraries a running instance mapped:

```bash title="Inspect a running instance"
lsof -p "$(pgrep -o opensips)" | grep -E 'libnats|libssl|libwolfssl'
```

*tls_mgm* certificate reloads take effect on the next reconnect.
Switching to a different libnats build needs a restart.


### How the modules share a connection


The *nats* module is loaded once per OpenSIPS process, so the
connection state it keeps (the connection, the JetStream context, the
KV handles, the reconnect epoch, the reconnect buffer) is one copy for
every NATS module. The other modules call it through the API they bind
in `mod_init` (`load_nats_api()`, see [The nats module API](#the-nats-module-api)).

Each module that talks to NATS calls
`nats_pool_register(const char *url, const char *module, int
reconnect_wait, int max_reconnect)` from `mod_init`, before OpenSIPS
forks. Registrations merge:

- the pool keeps the union of all modules' server URLs (duplicates are
  dropped; more than 16 URLs in the first registration is a startup
  error, while a later registration's URLs past 16 are skipped with a
  warning);
- for the reconnect settings, the larger value wins, whatever the module
  load order;
- TLS settings are not registration parameters; they come from
  *tls_mgm* (`nats_pool_bind_tls()`). A `tls://` or `tls+srv://` URL
  (any case) turns TLS on;
- DNS SRV URLs (`nats+srv://domain`, `tls+srv://domain`) are resolved
  by the nats module, not libnats, so any libnats takes them: in each
  process, at connect time, the SRV records of `_nats._tcp.<domain>`
  (looked up with the OpenSIPS core resolver, `nats_srv_core.c`) are put
  in RFC 2782 order and become plain `nats://` / `tls://` URLs in place
  of the SRV URL (`nats_srv.c`, `nats_srv_expand()`), at most 16 servers
  in all; libnats is then told to keep the list order
  (`natsOptions_SetNoRandomize()`), so the priorities hold. An SRV URL
  with a port or a path is corrected (both dropped) with a warning; one
  without a usable domain name is left out with a warning. A lookup that
  gives no server is warned about; when no server is left the process
  goes on without NATS (`nats_pool_has_servers()` returns 0) and looks
  up again at most every `nats_pool_srv_retry_s` (5) seconds.

The settings of the shared connection are the parameters of this
module: [no_randomize](#no_randomize-integer),
[reconnect_buf_size](#reconnect_buf_size-integer),
[drain_timeout_ms](#drain_timeout_ms-integer) and the credentials
([user](#user-string), [password](#password-string),
[token](#token-string), [creds_file](#creds_file-string),
[nkey](#nkey-string), [nkey_seed_file](#nkey_seed_file-string)).
*event_nats*, *cachedb_nats* and *nats_consumer* accept the same names
and pass each value to this module in their `mod_init`, with the same
rules as if it was set here; a value this module refuses then stops
startup.

*event_nats*, *cachedb_nats* and *nats_consumer* always register;
*cachedb_nats_fts* has no connection of its own. A module whose
server URL is unset registers its localhost default with
`nats_pool_register_default()`: the pool uses it only if no module
configures servers, whatever the module load order. Configured
servers registered after it replace it, and it is never added to
them -- with a DNS SRV URL whose lookups fail, a localhost default
would otherwise be the only server. `test/test_pool_merge.c` and
`test/test_pool_connect_opts.c` cover these rules.

After the fork, each process opens its own connection on first use
(`nats_pool_get()`, `nats_pool_get_js()` for JetStream). SIP workers,
module processes and timer processes connect; the attendant and the
TCP main process do not (`nats_rank.c`).

A module may still use NATS before the fork (b2b_entities restores its
state through *cachedb_nats* in `mod_init`). nats.c is not fork-safe, so
the attendant then closes everything -- KV handles, the JetStream
context, the connection and the library -- right before it forks
(a `pthread_atfork()` handler), and bumps the reconnect epoch so handles
kept from before the fork are fetched again. A worker that forks (for
example through the exec module) keeps its connection.
`test/test_pool_fork.c` covers this.


#### Handle lifetime and the reconnect epoch


`nats_pool_get_kv()` returns KV handles owned by the pool. A reconnect
marks them stale, and they are destroyed and re-created, so a
`kvStore *` kept across a reconnect is a use-after-free. Code that caches
one tags it with a `nats_epoch_t` (`nats_epoch.h`) and checks it before
use: snapshot, compare with `nats_epoch_current`, re-acquire, and call
`nats_epoch_adopt` only on success. The disconnect callback sets the
stale flag; the reconnect callback (also run on the first connect after
a degraded start) sets it and bumps the epoch.


### Behaviour during broker outages


| Situation | What happens |
| --------- | ------------ |
| Broker down at startup | OpenSIPS starts; each process connects in the background (`NATS pool: not connected at startup ...`). Operations fail fast until then. *cachedb_nats* starts degraded too, unless [require_usrloc_safe_bucket](../cachedb_nats/README.md#require_usrloc_safe_bucket-integer) is set to 1. |
| Connection lost mid-operation | The operation ends at its own timeout; the next one fails fast. A dead broker is detected in about 20 s (10 s pings, 2 outstanding). |
| JetStream publish (*event_nats*) without an ack | The ack wait ([js_ack_timeout_ms](../event_nats/README.md#js_ack_timeout_ms-integer)) expires and the pool's ack handler resends the message with its `Nats-Msg-Id`, at most [js_publish_retries](../event_nats/README.md#js_publish_retries-integer) times (`nats_js_retry.h`); the server drops a resend whose first copy was stored. `test/test_pool_js_ack.c` covers it. |
| Broker down when an operation starts | Operations return an error immediately instead of blocking a SIP worker (table below). |
| Broker comes back | KV handles are refreshed, consumer subscriptions are rebuilt (durables resume where they stopped), the KV watcher resumes after the last change it delivered (so changes made during the outage still raise E_NATS_KV_CHANGE), and the async RPC inbox is re-created. No restart needed. |
| Stream, consumer or bucket deleted on the server | Ephemeral consumers are re-created automatically. A durable consumer on a deleted stream stays failed until an operator unbinds it and binds it again after re-creating the stream. |

Return values while disconnected:

| Operation | Returns |
| --------- | ------- |
| *cachedb_nats* operations (`cache_*`, `nats_kv_*`, map, raw, query) | `-1` |
| [nats_publish()](../event_nats/README.md#nats_publishsubject-payload-msg_id) (*event_nats*) and Event Interface publishes | `1`: the message waits in the reconnect buffer and is sent after the reconnect. `-1` once the buffer ([reconnect_buf_size](#reconnect_buf_size-integer)) is full, counted in *failed* and *reconnect_buf_dropped* |
| [nats_fetch()](../nats_consumer/README.md#nats_fetchid-timeout_ms) / [nats_fetch_batch()](../nats_consumer/README.md#nats_fetch_batchid-opts) | `-2` |
| [nats_request()](../nats_consumer/README.md#nats_requestsubject-payload-timeout_ms), synchronous | `-3` |
| [nats_request()](../nats_consumer/README.md#nats_requestsubject-payload-timeout_ms), async | `-2` |
| [nats_ack()](../nats_consumer/README.md#nats_ack) and the other ack functions | `-2` |

Outage logging is rate limited: one warning per interval per process,
with per-call details at debug level. The log lines to look for:

| Log line | Meaning |
| -------- | ------- |
| `NATS pool: not connected at startup (broker unreachable, or credentials or TLS refused); continuing degraded with background connect retries` | Started without a connection: the broker is down, or it refused the credentials or the TLS handshake (libnats does not say which). |
| `NATS pool: disconnected` | Operations fail fast from here. |
| `NATS pool: reconnected to <url>` | Recovered; handles and subscriptions are rebuilt on next use. |
| `nats_request: NATS disconnected; failing fast instead of blocking <n> ms` | A route called synchronous [nats_request()](../nats_consumer/README.md#nats_requestsubject-payload-timeout_ms) during an outage. |
| `watcher: disconnect detected, stopping watcher ...` | The KV watcher paused; it resumes after reconnect. |
| `nats_consumer_proc: consumer for <id> vanished (...); will recreate` | An ephemeral consumer was removed by the server (normal), or a durable was deleted (investigate). |

On a failed call, *cachedb_nats* still leaves the caller's output
arguments in a defined state (result sets initialised, reply pointers
NULL), because usrloc, b2b and the script engine free or read them after
an error. `modules-contrib/cachedb_nats/test/test_disconnected_ops.c` covers this.

Credentials in server URLs (`nats://user:pass@host`,
`nats://token@host`) are never logged: every log line that prints a URL
passes it through `nats_redact_url()` (`nats_redact.c`), which replaces
the whole user-info part with `[redacted]`, per URL in a seed list. The
connection itself uses the real URL. The credential parameters
([user](#user-string) and the others) keep secrets out of the URLs.


### Developer Notes


#### Files


| File | Purpose |
| ---- | ------- |
| `nats.c` | The module: its parameters, `load_nats` (fills `struct nats_binds`) and `set_param()` |
| `nats_api_types.h`, `nats_api.h` | `struct nats_binds` and `load_nats_api()`: the API the other NATS modules bind |
| `nats_bind.h`, `nats_bind_mod.h` | For the other NATS modules: the pool and libnats names mapped onto the bound API, and the bind step with the forwarding of their connection settings |
| `nats_pool.c/.h` | Connection pool, JetStream context, KV bucket cache |
| `nats_dl.c/.h` + `nats_dl_table.def` | The `dlopen()` shim. Every libnats function the tree uses is resolved into the `nats_dl` table (one `NATS_DL_FN` line per symbol in the `.def`), so the modules have no link-time libnats dependency. Also checks the libnats version at load. |
| `nats_ca_dir.c/.h` | Loads a *tls_mgm* `ca_directory` as one PEM bundle |
| `nats_epoch.h` | The reconnect-epoch idiom (snapshot / current / adopt / lost) for cached pool handles |
| `nats_rank.c` | `nats_pool_should_init()`: which process ranks connect |
| `nats_redact.c/.h` | Credential redaction for logged URLs |
| `nats_rl.h` | Once-per-interval log gate used by the outage logging policy |
| `nats_url_scheme.h` | Classifies the configured server URLs: TLS (`tls://`, `tls+srv://`) and DNS SRV (`nats+srv://`, `tls+srv://`) |
| `nats_str.h` | `str` → bounded NUL-terminated buffer for the libnats C-string edge (keys, subjects); rejects embedded NUL |
| `nats_validate.c/.h` | Subject and KV-key validator used by every publish and KV path |
| `nats_js_opts.h` | Shared JetStream publish options (async queue limits) |
| `nats_js_retry.h` + `nats_js_retry.c` | JetStream async publish retry policy (which ack errors are resent, how often) and the table counting the resends of each message |
| `nats_srv.c/.h` | DNS SRV server discovery: RFC 2782 order, target URLs, server-list expansion (pure, unit-tested by `test/test_srv_order.c`) |
| `nats_srv_core.c` | The SRV lookup through the OpenSIPS core resolver (`get_record()`) |
| `nats_auth.h` | Credential parameters of the shared connection: merge, validation, which method; the URL user-info and insecure-URL rules |
| `Makefile.nats` | `pkg-config` probe that gates the module builds on libnats |


#### The nats module API


A module binds the API the way *tls_mgm*'s is bound, and declares
*nats* as a dependency (`DEP_ABORT`) so it is initialized first:

```c title="Binding the nats module API"
#include "../nats/nats_api.h"

static struct nats_binds nats;

static int mod_init(void)
{
	if (load_nats_api(&nats) < 0) {
		LM_ERR("cannot bind the nats module API (loadmodule \"nats.so\")\n");
		return -1;
	}
	...
}
```

`load_nats_api()` finds the `load_nats` export of `nats.so` and fills
`struct nats_binds` (`nats_api_types.h`): the libnats function table
(`dl`), the pool functions, the shared tunables, `set_param()` and the
redaction and validation helpers. The four NATS modules use
`nats_bind_mod.h` in their main file and `nats_bind.h` in the others
instead: the names they used before the API existed (`nats_pool_get()`,
`nats_dl.<fn>`, `nats_redact_url()`, ...) resolve to the bound
`nats_api`, and their copies of the connection settings are kept by a
`nats_alias_<name>` setter until `nats_bind_api()` forwards them with
`set_param()`. The unit suites swap a module's `nats_api` for fakes
(`test/nats_ut_fake.c` here, `test/*_ut_fake.c` in each module).

> [!NOTE]
> Adding or removing a `NATS_DL_FN` entry shifts every later member of
> `nats_dl_funcs_t`, so every NATS module, `nats.so` included, must be
> recompiled. The `-MMD` depfiles track `nats_dl_table.def`, so a plain
> `make` does this. A NATS module built against another table than the
> loaded `nats.so` crashes at startup.


#### Allocator policy


- **pkg** for memory private to one process and owned by its main
  thread: the JSON hot path, MI staging, consumer configuration strings,
  async resume parameters.
- **shm** only for data shared between processes: the search index,
  intern table, rings, RPC slots, statistics, IPC payloads. It is the
  slowest allocator here, so moving private data to shm makes things
  slower.
- **Handing work from a libnats callback thread to a worker** uses
  `shm_malloc` plus `ipc_dispatch_rpc`; both are safe from foreign
  threads. `event_nats_sub.c`'s message callback is the reference.
  `pkg_malloc` and `LM_*` must not be used on those threads.
- **libc `malloc`** is kept in four places: memory owned by libnats
  (its API requires `free()`); thread-local allocations on libnats
  callback threads; large buffers sized by configuration (message-ref
  rows up to about 1.5 MB × 256 handles, worst-case MI listings), since
  pkg pools are sized at fork; and the files of this module that compile
  standalone for unit tests (`nats_ca_dir.c`, `nats_redact.c`,
  `nats_validate.c`, the `nats_str.h` helpers).

**Strings:** `str` at every OpenSIPS edge; NUL-terminated C strings at
the libnats edge (keys, subjects and bucket names through
`nats_str_to_buf`, which rejects embedded NUL); `(ptr, len)` inside the
JSON layer. Values go through the length-aware `kvStore_Put/Create/Update`,
never the `*String` variants, which stop at the first NUL.

> [!NOTE]
> Any new log statement that prints a URL or server string must pass it
> through `nats_redact_url()` first. `test/test_redact_url.c` covers
> the redaction rules.


#### Tests


| Suite | How to run |
| ----- | ---------- |
| `modules-contrib/<module>/test/` | `make test-<module>` from the source root (needs `-DUNIT_TESTS`; see `.github/workflows/unittests.yml`): the module's unit suite, run by `opensips -T <module>` inside a running OpenSIPS. A suite whose module was not built (no libnats) is skipped. |
| [sipssert-opensips-tests](https://github.com/OpenSIPS/sipssert-opensips-tests) sets `nats`, `event_nats`, `cachedb_nats`, `nats_consumer` | SIPssert scenarios against a real NATS server: the shared pool, publishing and JetStream de-duplication, user/password and mutual TLS, a broker that comes up late, usrloc on NATS KV, the script KV functions and MI, a refused insecure start, the consumer's work queue and request/reply. They need an image with the NATS modules (`-E opensips_image=<image>`). |


### Limitations


These apply to all the NATS modules. Each module's README lists its own.

- **libnats must be 3.14 or later, with the same major.minor as the
  build.** Older libraries lack required symbols; any other major.minor
  is refused at load time, with no fallback to another library. Only
  a `NATS_DL_LIBNATS_PATH` that cannot be opened at all falls back to
  the default `libnats.so`, with a warning.
- **One libnats per process.** All connections in an OpenSIPS instance
  use the same library; switching builds needs a restart.
- **The NATS side does not support wolfSSL.** Upstream nats.c has no wolfSSL
  backend, so NATS connections need an OpenSSL-backed libnats.
- **The packages need a libnats 3.14 or later at build time.** The
  `opensips-module-contrib-*` packages of the NATS modules build against
  the libnats headers of the build host; distribution `libnats-dev`
  packages older than 3.14 cannot build them. OpenSIPS does not ship
  libnats.
- **Builds skip the NATS modules** (with a `[skip]` build message) when
  libnats is not found. The helper script builds libnats only on x86_64
  and aarch64 and skips cross-compiles.
- **Pool limits:** at most 16 server URLs; at most 16 KV buckets open per
  process, with names up to 127 characters; at most 4096 pending
  asynchronous JetStream publishes per process (a publish then waits up
  to 50 ms and fails).
- **Dead-broker detection takes about 20 seconds.** Operations issued in
  that window wait for their own timeouts.
- **The attendant and TCP main processes have no NATS connection.**
  Script code running there cannot use the NATS functions.
- **A connection setting given to another NATS module is checked at its
  `mod_init`.** The value is passed to this module then, so a refused
  value stops startup after the configuration is parsed, not while it
  is parsed.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* if a server URL is a `tls://` or `tls+srv://` URL, with a
client domain named `nats` (see [TLS](#tls)).  No other module is
needed.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libnats* (the [nats.c](https://github.com/nats-io/nats.c) client),
3.14 or later, with the same major.minor version at run time as at
build time.  For TLS it must be built with TLS.  See
[Requirements](#requirements).


### Exported Parameters


#### no_randomize (integer)


Server order of the shared connection.  With `0` (the default) libnats
shuffles the configured servers, so the OpenSIPS processes, each with
its own connection, spread over them.  With `1`, every process tries
the servers in the order of the merged server list (module
initialization order): the first reachable server takes all the
connections and the others are backups.


libnats then also stops shuffling the addresses of a hostname that
resolves to several IPs, and orders the targets of a DNS SRV URL by
priority, then by decreasing weight, instead of a weighted random
choice among the targets of the same priority.


*event_nats*, *cachedb_nats* and *nats_consumer* accept the same
parameter and pass it here: if any of them, or this module, sets it to
`1`, the shared connection keeps the configured order.  A value other
than `0` or `1` refuses startup.


*Default value is "0" (randomized).*


```opensips title="Set no_randomize parameter"
...
modparam("nats", "no_randomize", 1)
...
```


#### reconnect_buf_size (integer)


Size, in bytes, of the libnats buffer that keeps what is sent while the
connection is reconnecting (`natsOptions_SetReconnectBufSize()`); it is
sent once the connection is back.  Each OpenSIPS process has its own
connection, so each has its own buffer.


*event_nats*, *cachedb_nats* and *nats_consumer* accept the same
parameter and pass it here: the first value set replaces the default,
and of several, the largest wins.  A value below `1` refuses startup.


*Default value is "8388608" (8 MB, the libnats default).*


```opensips title="Set reconnect_buf_size parameter"
...
modparam("nats", "reconnect_buf_size", 33554432)
...
```


#### drain_timeout_ms (integer)


Shutdown drain timeout, in milliseconds.  When OpenSIPS shuts down,
every NATS connection is drained so in-flight publish acks land on the
broker before the process exits; this parameter caps how long that
drain may block per connection.  Cross-DC deployments with high broker
round-trip latency may need a larger budget.


*event_nats* and *cachedb_nats* accept the same parameter and pass it
here: the first value set replaces the default (even a lower one),
after that the largest value wins.  A negative value refuses startup.


*Default value is "5000" (5 seconds).*


```opensips title="Set drain_timeout_ms parameter"
...
modparam("nats", "drain_timeout_ms", 15000)
...
```


#### user (string)


User name for the shared connection, sent with
[password](#password-string).  Together they replace credentials in the
server URL (`nats://user:pass@host`), which must then not carry any:
credentials both in a URL and in these parameters refuse startup, as do
a user without a password, and more than one way to authenticate
(user/password, [token](#token-string), [creds_file](#creds_file-string),
[nkey](#nkey-string)).  The user and password are sent in the CONNECT
message: over a `nats://` URL OpenSIPS warns that they travel in plain
text.  A value is never logged.


The credential parameters are also accepted by *event_nats*,
*cachedb_nats* and *nats_consumer*, which pass them here: setting one
in any module sets it for the shared connection; two different values
refuse startup.  A TLS client certificate comes from the *tls_mgm*
`nats` domain (`certificate`, `private_key`) and works with or without
them.


*Default value is "NULL" (no user).*


```opensips title="Set user parameter"
...
modparam("nats", "user", "opensips")
modparam("nats", "password", "s3cret")
...
```


#### password (string)


Password for [user](#user-string); both must be set.


*Default value is "NULL" (no password).*


```opensips title="Set password parameter"
...
modparam("nats", "password", "s3cret")
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
modparam("nats", "token", "s3cr3t-t0ken")
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
modparam("nats", "creds_file", "/etc/opensips/nats/opensips.creds")
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
modparam("nats", "nkey", "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4")
modparam("nats", "nkey_seed_file", "/etc/opensips/nats/opensips.nk")
...
```


#### nkey_seed_file (string)


Path of the file holding the NKey seed (`SU...`) of
[nkey](#nkey-string); both must be set.  The file must be readable when
OpenSIPS starts.


*Default value is "NULL" (no seed file).*


```opensips title="Set nkey_seed_file parameter"
...
modparam("nats", "nkey_seed_file", "/etc/opensips/nats/opensips.nk")
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
