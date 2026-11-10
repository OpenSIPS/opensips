---
title: "nats_consumer Module"
description: "The nats_consumer module turns OpenSIPS into a pull-mode NATS JetStream consumer."
---

## Admin Guide


### Overview


The *nats_consumer* module turns OpenSIPS
into a pull-mode
[NATS](https://nats.io) JetStream consumer.
A dedicated module process subscribes to JetStream streams,
populates a per-handle SHM ring, and exposes the messages to
OpenSIPS routing scripts via [nats_fetch()](#nats_fetchid-timeout_ms)
and [nats_fetch_batch()](#nats_fetch_batchid-opts).  Acknowledgements
([nats_ack()](#nats_ack),
[nats_ack_next()](#nats_ack_next),
[nats_ack_progress()](#nats_ack_progress),
[nats_nak()](#nats_nak),
[nats_term()](#nats_term)) travel back to the
consumer process over an IPC socket and are then relayed to
NATS.


*nats_consumer* is the receive side of the OpenSIPS NATS
modules; see the [nats module](../nats/README.md)
for the others.


Consumer handles are declared with the [bind](#bind-string) parameter, or
added with the [nats_consumer_bind()](#nats_consumer_bindconfig) script
function (from `startup_route`) or, at run time, the
[nats_consumer:nats_consumer_bind](#nats_consumernats_consumer_bind) MI
command.  Only [bind](#bind-string)-declared handles come back after a
restart.


The module uses the connection of the [nats](../nats/README.md)
module, shared by all NATS modules, so an OpenSIPS process holds one
NATS connection whichever NATS modules are loaded.


#### Process Model and Failure Handling


*nats_consumer* registers a single
dedicated worker named `[NATS consumer]`
whose only job is to drive the JetStream pull loop and
hand messages to the SHM ring.  Acks travel back over a
Unix-domain IPC socket.


**If the consumer worker dies for
any reason** (signal, segfault, OOM kill) the
OpenSIPS core treats it as a fatal child death and
shuts the entire instance down — exactly the same path
a SIP UDP receiver crash takes.  There is
*no per-process auto-restart*; the
consumer is not registered with the
`OSS_PROC_SELFEXIT` flag.


Operationally this means the supervisor that runs
OpenSIPS (systemd, Kubernetes, etc.) is responsible for
restarting the whole OpenSIPS instance after a consumer
death.  Bound handles survive that restart only when
declared via the [bind](#bind-string) parameter;
otherwise the registry must
be repopulated by re-issuing
[nats_consumer_bind()](#nats_consumer_bindconfig).  In-flight
messages whose ack didn't reach NATS before the
restart will be re-delivered after
`ack_wait`.


#### When you need this module / when you don't


**Load
*nats_consumer* when:**


- you need explicit-ack JetStream pull-mode
consumption from script
([nats_fetch()](#nats_fetchid-timeout_ms),
[nats_ack()](#nats_ack),
[nats_nak()](#nats_nak),
[nats_term()](#nats_term),
[nats_ack_progress()](#nats_ack_progress));
- you need durable consumers with bounded
redelivery or replay semantics
(`deliver_policy = by_start_seq`);
- you need synchronous request/reply with NATS as
a transport ([nats_request()](#nats_requestsubject-payload-timeout_ms))
from a non-request route;
- you need fine-grained per-handle counters and a
watchdog endpoint
([nats_consumer:nats_consumer_health](#nats_consumernats_consumer_health)).


**You don't need it when:**
plain fire-and-forget core-NATS subscription with
`event_route[]` dispatch is
sufficient — that path is handled by
*event_nats*'s
[subscribe](../event_nats/README.md#subscribe-string) modparam.  The
*event_nats* subscribe path has no
script-visible ack, no durable consumer state, no
replay, and no per-message flow control, but is also
a much smaller config and one fewer dedicated
process.  If your handler can tolerate
at-most-once-effective semantics from EVI dispatch,
prefer that path.


### Usage Patterns


#### Durable Work Queue


Two or more OpenSIPS instances binding the same durable
name on the same stream load-balance deliveries via
JetStream's consumer machinery.  No duplicates unless
[nats_nak()](#nats_nak) or `ack_wait`
expiry triggers a redelivery.


```opensips title="startup_route + timer_route drain loop"
startup_route {
    nats_consumer_bind("id=jobs;stream=WORK;durable=jobs_worker;filter=work.jobs;ack_wait=30s;max_deliver=5");
}

timer_route[drain, 1] {
    # At most 100 messages x 5 ms wait = 500 ms, inside the 1 s
    # interval; for higher rates use the nats_fetch_batch() pattern.
    $var(n) = 0;
    while ($var(n) < 100 && nats_fetch("jobs", 5)) {
        xlog("L_INFO", "job $nats_seq: $nats_data\n");
        nats_ack_next();
        $var(n) = $var(n) + 1;
    }
}
```


#### Ephemeral Advisory Subscriber


JetStream advisories
(`$JS.EVENT.ADVISORY.>`) are a
natural fit for an ephemeral consumer — the subscription
lives only while OpenSIPS does, and
`inactive_threshold` keeps the broker
tidy if the process dies unexpectedly.  Script strings expand
`$` variables, so the `$JS` subject prefix is written `$$JS`
(`$$` is a literal `$`); in a [bind](#bind-string) modparam it is
written as-is.


```opensips title="Subscribe to max-delivery advisories"
startup_route {
    nats_consumer_bind("id=dlq;stream=_SYS_JS;ephemeral=1;filter=$$JS.EVENT.ADVISORY.MAX_DELIVERIES.>;inactive_threshold=5m");
}

timer_route[check_dlq, 5] {
    # at most 40 x 100 ms = 4 s, inside the 5 s interval
    $var(n) = 0;
    while ($var(n) < 40 && nats_fetch("dlq", 100)) {
        xlog("L_ALERT", "dead letter: $nats_subject $nats_data\n");
        nats_ack();
        $var(n) = $var(n) + 1;
    }
}
```


#### Request / Reply


The responder side binds a durable consumer on a stream
covering the request subject; the requester side calls
[nats_request()](#nats_requestsubject-payload-timeout_ms) from a
`timer_route` or
`startup_route`.


```opensips title="Two-route RPC on the same instance"
startup_route {
    nats_consumer_bind("id=rpc_srv;stream=RPC;durable=srv;filter=rpc.call;ack_wait=5s");
}

timer_route[rpc_srv, 1] {
    # at most 50 requests x 10 ms wait = 500 ms, inside the 1 s interval
    $var(n) = 0;
    while ($var(n) < 50 && nats_fetch("rpc_srv", 10)) {
        nats_hdr_set("X-Trace-Id", "$nats_hdr(X-Trace-Id)");
        if (nats_reply("echo: $nats_data"))
            nats_ack();
        else
            nats_nak();
        $var(n) = $var(n) + 1;
    }
}

timer_route[rpc_cli, 5] {
    if (nats_request("rpc.call", "ping", 2000))
        xlog("L_INFO", "reply: $nats_data\n");
}
```


### Limitations


- **At most 256 bound handles.**  Binding more fails: the
[nats_consumer_bind()](#nats_consumer_bindconfig) script function returns
-1 and the [nats_consumer:nats_consumer_bind](#nats_consumernats_consumer_bind)
MI command answers with error 507.
- **One consumer process.**  If it dies, OpenSIPS shuts down; there is
no automatic restart of the process alone.
- **Handles bound through MI are lost on restart.**  Only handles from
the [bind](#bind-string) parameter and `startup_route` come back.
- **Message size:** payloads over 16 384 bytes and subjects over 256
bytes are terminated (`term`), not delivered.  Headers beyond 1024
bytes are truncated.
- **[nats_request()](#nats_requestsubject-payload-timeout_ms):** replies
are truncated to 16 384 bytes, async request payloads over 16 384 bytes
are rejected, and at most 16 headers can be staged per request.
- **Fetch limits:** [nats_fetch_batch()](#nats_fetch_batchid-opts)
returns at most 32 messages per call; [fetch_batch](#fetch_batch-integer)
is limited to 1..4096 and [fetch_timeout_ms](#fetch_timeout_ms-integer)
to 1..60 000.
- **Ring size:** `ring_capacity` is at most 65 536; the default 128
slots use about 2.3 MB of shared memory per handle.
- **Async requests** are limited by [async_rpc_slots](#async_rpc_slots-integer)
(64 by default, for the whole instance).
- **Synchronous [nats_request()](#nats_requestsubject-payload-timeout_ms)
blocks.**  It is refused in request, failure, branch and error routes
unless [allow_sync_anywhere](#allow_sync_anywhere-integer) is set.
A `failure_route` entered on `fr_timer` expiry has no non-blocking
alternative.
- **A durable consumer on a deleted stream** stays failed until the
stream is re-created: the consumer process retries the subscription
with a backoff capped at 60 s (see *ensure_failures* in
[nats_consumer:nats_consumer_list](#nats_consumernats_consumer_list)).
- **Poison messages:** a message delivered more than
[poison_max_deliver](#poison_max_deliver-integer) times (20 by default)
is terminated.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *nats*: the connection shared by the NATS modules; see the
[nats module](../nats/README.md).  The module configures its own
servers and shares the connection with any other NATS module that is
loaded, in any load order.
- *tls_mgm* if [nats_url](#nats_url-string) holds a `tls://` URL, with a
client domain named `nats`.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libnats* (the [nats.c](https://github.com/nats-io/nats.c) client),
3.14 or later, with the same major.minor version at run time as at
build time.  See the
[nats module](../nats/README.md#requirements).
- *NATS Server* 2.10 or later with JetStream enabled.


### Exported Parameters


#### bind (string)


Declarative handle bind.  Each value uses the same
`key=value;key=value` config grammar as
[nats_consumer_bind()](#nats_consumer_bindconfig) and is bound
into the registry at module init, before any worker
forks.  The parameter may be set multiple times, one
handle per value.


A malformed value, an unknown key, or a duplicate
`id` is a configuration error and
aborts startup.  Handles bound at runtime through the
MI command remain available but are ephemeral: after a
restart only [bind](#bind-string)-declared handles
exist.


*Default value is "NULL" (no handle).*


```opensips title="Set bind parameter"
...
modparam("nats_consumer", "bind",
    "id=jobs;stream=JOBS;filter=jobs.>;durable=jobs_worker")
modparam("nats_consumer", "bind",
    "id=audit;stream=AUDIT;filter=audit.>;ephemeral=1")
...
```


#### fetch_batch (integer)


Module-global default for the JetStream pull-Fetch
batch size used by the dedicated consumer process
when calling `natsSubscription_Fetch`.
Each handle may override this with a per-handle
`fetch_batch=` bind key.


Range: `1`..`4096`.
Larger batches reduce the number of pull requests the
consumer process issues against the broker (lower
`pulls_requested` in MI counters,
lower broker CPU per consumer).  The consumer process
clamps the request to the ring's currently-free slot
count before each `natsSubscription_Fetch`
call, so a fetch batch that
exceeds the worker's transient drain rate does not
trigger ring-full defer-drops; the broker simply
holds the un-fetched messages until the next loop
iteration.  Pair with a generous
`ring_capacity`
(`>= 4 * fetch_batch` is the
recommended ratio) and
`max_ack_pending`
(`>= ring_capacity`) so the
clamp has room to deliver full batches.


The drain pattern in the script matters more than
this knob alone.  Reference numbers, single-instance
aarch64 loopback at N=100 000:


- [nats_fetch()](#nats_fetchid-timeout_ms) + [nats_ack()](#nats_ack)
per-message: ~2 000 msgs/sec, gated by the
OpenSIPS script-interpreter overhead.
- [nats_fetch_batch()](#nats_fetch_batchid-opts)
+ [nats_batch_select()](#nats_batch_selectidx)
+ [nats_ack()](#nats_ack) at
`fetch_batch=10`:
~9 800 msgs/sec.
- Same pattern at
`fetch_batch=64`:
~37 500 msgs/sec.
- Same pattern at
`fetch_batch=256`:
~89 000 msgs/sec.


At very high batches
(>= 256) the broker's
`max_ack_pending` becomes the next
bottleneck; raising it (with
`ring_capacity` raised to match)
lifts the ceiling further at the cost of broker
memory.


*Default value is "10".*


```opensips title="Set fetch_batch parameter"
modparam("nats_consumer", "fetch_batch", 32)

startup_route {
    # Per-handle override: throughput-bound durable wants 256 per Fetch
    # with a 4x ring and a >= ring max_ack_pending.  Empirical
    # ~89 000 msgs/sec on loopback at this configuration.
    nats_consumer_bind("id=ingest;stream=EVENTS;durable=ingest;fetch_batch=256;ring_capacity=1024;max_ack_pending=4096");
}
```


#### fetch_timeout_ms (integer)


Module-global default for the per-Fetch upper-bound
wait, in milliseconds.  Each handle may override this
with a per-handle `fetch_timeout_ms=`
bind key.


Range: `1`..`60000`
(1 ms .. 60 s).  Lower values reduce shutdown latency
(the consumer process polls this timeout between
checking for retire/shutdown signals) at the cost of
more wakeups on quiet streams.  Higher values reduce
idle CPU on streams that rarely have messages, at the
cost of slower shutdown.


*Default value is "1000".*


```opensips title="Set fetch_timeout_ms parameter"
modparam("nats_consumer", "fetch_timeout_ms", 1000)

startup_route {
    # RPC responder: stays responsive at shutdown by polling more often.
    nats_consumer_bind("id=rpc;stream=API;durable=rpc;fetch_batch=4;fetch_timeout_ms=100");
}
```


#### poison_max_deliver (integer)


Consumer-side poison-message cap.  With the JetStream
default `max_deliver=0` the broker
redelivers a message that always fails processing
forever, broker-paced, with no dead-letter -- a single
poison message can wedge a handle indefinitely.  When
this is greater than `0`, the dedicated
consumer process terminates
(`natsMsg_Term`) any message whose
`NumDelivered` exceeds the cap, instead
of pushing it to the worker ring, and bumps the
per-handle `poisoned` counter (visible
in [nats_consumer:nats_consumer_list](#nats_consumernats_consumer_list) and
[nats_consumer:nats_consumer_stats](#nats_consumernats_consumer_stats)).


This is a global backstop independent of any per-handle
`max_deliver=` bind key: where a handle
sets its own `max_deliver` the broker
terminates first and the cap never fires.  It exists
mainly to bound redelivery for handles left at the
unlimited default.


*Default value is "20".  Set to "0" to
disable the backstop (unlimited broker-paced
redelivery).*


```opensips title="Set poison_max_deliver parameter"
modparam("nats_consumer", "poison_max_deliver", 20)
```


#### allow_sync_anywhere (integer)


Opt-in switch that widens the route mask of the
synchronous [nats_request()](#nats_requestsubject-payload-timeout_ms)
entry point so it may be called from SIP-worker contexts
(*REQUEST_ROUTE*,
*FAILURE_ROUTE*,
*BRANCH_ROUTE*,
*ERROR_ROUTE*).  When unset (the
default), the OpenSIPS parser rejects any call to
a synchronous [nats_request()](#nats_requestsubject-payload-timeout_ms)
from those routes with the diagnostic
"Command <nats_request> cannot be used
in the block"; only
*STARTUP_ROUTE*,
*TIMER_ROUTE*,
*LOCAL_ROUTE*,
*EVENT_ROUTE*, and
*ONREPLY_ROUTE* remain accepted.


The guard exists because a synchronous request
blocks the calling worker for up to
`timeout_ms`.  A SIP UDP/TCP worker
that blocks on the RPC cannot read its next packet
for that long, which on a production proxy with a
steady inbound rate quickly stalls SIP throughput.
Operators who know their deployment can absorb the
worst case (low RPS, a thin SIP gateway in front,
generous worker pool sizing) may opt in to the
simpler synchronous ergonomics by setting this to
`1`; the setting widens the route mask of
[nats_request()](#nats_requestsubject-payload-timeout_ms)
to *ALL_ROUTES* at the moment the
modparam directive is parsed, before any route block
is checked.


*Per-route blocking consequences.*
Each of the newly-opened routes has its own
distinct operational blast radius.  A warning is logged
at config-parse time
spelling these out so an operator who flips the
switch cannot miss them:


- *REQUEST_ROUTE* - runs on the SIP worker that received the
request.  The worker cannot read its next SIP packet for
the duration; under sustained load the receive
backlog grows on this worker's interface.
- *FAILURE_ROUTE* - has two invocation paths with different
blast radius and different async support:
  - *negative-reply trigger* - when an upstream branch returns a
  final non-2xx, the SIP worker that received the reply runs the
  failure route inline.  The blast radius is the same as
  blocking in REQUEST_ROUTE on that worker; `async()` IS
  available from this trigger path because a SIP worker has a
  full reactor.
  - *`fr_timer` / `fr_inv_timer` expiry* - the failure route
  runs inline on the *timer ticker* process, the single-threaded
  tick driver that fires the C-level timer callbacks of the core
  and the modules (including the *tm* final-response timer) and
  has no reactor.  Blocking it delays every other transaction's
  fr_timer and every other module's tick callback
  (retransmissions, watchdogs, etc.) until the block clears.  This
  is a worse blast radius than blocking a single SIP worker, and
  `async()` is *not* available from this trigger path because the
  ticker has no reactor -- there is no non-blocking option in this
  module for fr_timer-triggered failure_route.
- *BRANCH_ROUTE* - runs on the SIP worker that is fanning out the
transaction's outbound branches.  The per-branch INVITE/REGISTER
send is delayed by up to `timeout_ms`; subsequent branches in the
same transaction also wait.
- *ERROR_ROUTE* - runs on the SIP worker that hit a parse error
on an inbound request or that tripped an in-action error.
Blocking delays the error response back to the peer.


> [!NOTE]
> `timer_route { ... }` blocks (not to be confused with the C-level
> timer callbacks described under FAILURE_ROUTE above) execute on a
> separate *Timer handler* process that has a full reactor and
> supports `async()`.  Synchronous
> [nats_request()](#nats_requestsubject-payload-timeout_ms) calls from
> `timer_route` are accepted by the default mask (TIMER_ROUTE is in
> the safe allow-list) and `async()` works there too.  The
> ticker-process limitation discussed under FAILURE_ROUTE / fr_timer
> is a different process and a different code path.


*The recommended pattern for any worker
route is the async form*, which yields
on a per-call timerfd while the reply is in flight
and does not block SIP processing:


```opensips title="Async request from the main route"
route {
    async(nats_request("rpc.lookup", "$fU", 200), rpc_reply);
}

route[rpc_reply] {
    if ($rc > 0)
        xlog("L_INFO", "reply: $nats_data\n");
}
```


The async form is accepted from every route that
supports `async()` regardless of
this modparam -- request_route, branch_route,
error_route, timer_route, event_route,
onreply_route, and the reply-triggered branch of
failure_route.  The only worker-blocking
situation without a non-blocking alternative is
failure_route entered through fr_timer /
fr_inv_timer expiry; lifting that requires a
change in *tm* that
dispatches fr_timer expiry through a Timer
handler instead of running it inline on the
ticker.  See [nats_request()](#nats_requestsubject-payload-timeout_ms).


Range: `0` (default, safer) or
`1` (opt-in, permissive).  Any
other value is rejected at config-parse time so a
typo cannot silently disarm the guard.


*Default value is "0".*


```opensips title="Set allow_sync_anywhere parameter"
modparam("nats_consumer", "allow_sync_anywhere", 1)

route {
    # Operator has accepted that this call blocks the worker
    # for up to 200 ms; udp_workers sized accordingly.
    nats_request("rpc.lookup", $var(payload), 200);
    if ($retcode == 1) {
        xlog("got reply: $nats_data()\n");
    }
}
```


```opensips title="Default -- async from request_route, sync only in startup"
# No modparam set; the default (0) keeps the safety guard in place.

startup_route {
    # Allowed -- no SIP worker is being stalled.
    nats_request("rpc.health", "ping", 1000);
}

route {
    # Async form -- worker yields to the reactor while the
    # RPC is in flight.  Accepted regardless of the modparam.
    async(nats_request("rpc.lookup", $var(payload), 200), got_reply);
}
route[got_reply] {
    if ($retcode == 1) {
        xlog("got reply: $nats_data()\n");
    }
}
```


#### request_id_header (string)


Outbound header name used to carry the per-call
*UUIDv7* correlation id auto-minted by both the sync and async
[nats_request()](#nats_requestsubject-payload-timeout_ms) start paths.
The id is also exposed to the script via the
[$nats_request_id](#nats_request_id) pseudo-variable and
persists across an
`async()` yield so the resume
route can read it back for log / trace
correlation.


*Per-call cost.* One
`clock_gettime(CLOCK_REALTIME)`
+ one `getrandom(GRND_NONBLOCK)`
of 10 bytes per request, plus a 36-byte snprintf.
Measured at roughly 200 ns on aarch64; below
the noise floor of the libnats round-trip.


*UUIDv7 layout.* RFC 9562
lexicographically-sortable Type-7 UUID:
48-bit unix milliseconds, 4-bit version (7),
12 random bits, 2 variant bits (10b), 62 random
bits.  Globally unique across instances and time;
grep-able as one string from OpenSIPS logs through
the NATS subject to the responder's logs.


*Auto-stage behaviour.* When the
modparam is non-empty, every
[nats_request()](#nats_requestsubject-payload-timeout_ms) call stages
`<header-name>: <uuid>`
onto the outbound natsMsg
*iff* the script has not
already staged the same header explicitly via
[nats_hdr_set()](#nats_hdr_setname-value).  A header staged that way
wins -- the auto-stage observes the existing entry and steps aside:


```opensips title="Stage the request id header yourself"
timer_route[rpc_tick, 5] {
    nats_hdr_set("X-Request-Id", "my-custom-id");
    nats_request("rpc.x", "ping", 200);
}
```


*Disabling the header.* Setting
the modparam to the empty string
(`""`) suppresses the auto-stage
without affecting the mint: the id is still
generated and the
[$nats_request_id](#nats_request_id) pseudo-variable still
works, but no header is added to the outbound
msg.  Use this when you want client-side
correlation but the responder cannot accept (or
will reject) the extra header.


Range: any string that is a valid NATS header
name.  Common choices include
`X-Request-Id`,
`Request-Id`,
`X-Correlation-Id`, or a
vendor-prefixed
`X-MyOrg-Request-Id`.


*Default value is "X-Request-Id".*


```opensips title="Set request_id_header parameter"
modparam("nats_consumer", "request_id_header", "X-Request-Id")

route {
    xlog("L_INFO", "issuing rpc id=$nats_request_id\n");
    async(nats_request("rpc.lookup", $var(payload), 200), on_reply);
}

route[on_reply] {
    if ($retcode == 1) {
        # Responder echoed the header back -- verify it matches
        # what we issued (a responder that does not echo means
        # the operator has to grep their logs by the outgoing id
        # only).
        if ($nats_hdr(X-Request-Id) == $nats_request_id) {
            xlog("L_INFO", "rpc id=$nats_request_id ok: $nats_data()\n");
        } else {
            xlog("L_WARN", "rpc id=$nats_request_id reply id mismatch\n");
        }
    } else if ($retcode == -1) {
        xlog("L_WARN", "rpc id=$nats_request_id timed out\n");
    }
}
```


```opensips title="Vendor-prefixed header for a specific responder service"
modparam("nats_consumer", "request_id_header", "X-MyOrg-Trace-Id")
```


```opensips title="Mint id locally but do not put it on the wire"
modparam("nats_consumer", "request_id_header", "")

route {
    # $nats_request_id still has the UUIDv7, log it locally,
    # but the outbound natsMsg carries no Request-Id header.
    xlog("L_INFO", "rpc id=$nats_request_id (header suppressed)\n");
    async(nats_request("rpc.x", $var(payload), 200), on_reply);
}
```


#### nats_url (string)


Comma-separated list of NATS server URLs (`nats://` or `tls://`).
The URLs are merged into the connection shared by all NATS modules
(see the [nats module](../nats/README.md)).  When
this parameter is not set and no other NATS module has configured a
server, the module uses `nats://localhost:4222`.  TLS settings come
from the *tls_mgm* client domain named `nats`.


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


*Default value is "NULL" (use the servers configured by other NATS
modules, or `nats://localhost:4222`).*


```opensips title="Set nats_url parameter"
...
modparam("nats_consumer", "nats_url", "nats://nats-1:4222,nats://nats-2:4222")
...
```


```opensips title="Set nats_url parameter to a DNS SRV domain"
...
modparam("nats_consumer", "nats_url", "nats+srv://example.com")
...
```


#### async_rpc_slots (integer)


Size of the SHM slot pool that backs in-flight
asynchronous [nats_request()](#nats_requestsubject-payload-timeout_ms-1)
calls across all SIP
workers.  Each concurrent async RPC occupies one slot for its
lifetime; when the pool is exhausted a new call fails (-5) and
the script can retry or shed load.  Clamped to the range
1..65536.


*Default value is "64".*


```opensips title="Set async_rpc_slots parameter"
...
modparam("nats_consumer", "async_rpc_slots", 256)
...
```


#### async_rpc_poll_ms (integer)


Tick interval, in milliseconds, of the per-call
worker-private guard timerfd behind an asynchronous
[nats_request()](#nats_requestsubject-payload-timeout_ms-1).  The reply
itself does
not wait for this timer: the consumer process signals the
calling worker over OpenSIPS IPC the moment the reply is
delivered (or the call is abandoned), so the resume runs at
wire latency.  The guard tick only bounds how quickly a
request timeout - or a lost wake signal - is noticed; the
value is clamped to the range 1..1000.


*Default value is "100" (milliseconds).*


```opensips title="Set async_rpc_poll_ms parameter"
...
modparam("nats_consumer", "async_rpc_poll_ms", 50)
...
```


#### reconnect_wait_ms (integer)


Delay, in milliseconds, between reconnect attempts.  The
connection is shared by all NATS modules; when several set this
value, the largest wins.  A value of **0** keeps the
shared default (2000 ms).  The value is ignored unless this module
registers servers with the pool: its own [nats_url](#nats_url-string)
is set, or no NATS module loaded before it registered one.


*Default value is "0" (use the shared default).*


```opensips title="Set reconnect_wait_ms parameter"
...
modparam("nats_consumer", "reconnect_wait_ms", 1000)
...
```


#### max_reconnect (integer)


Number of connection attempts made at startup for failures other
than an unreachable broker, which starts the process at once without
a connection, retrying in the background.  A broker that refuses the
connection (authentication, TLS handshake) looks the same, since the
first connect is asynchronous, and a connection that cannot be set up
with the configured servers (a `tls://` URL without *tls_mgm*, for
instance) leaves the module without NATS; both are logged.  Once connected,
reconnection after an outage is not limited.  When several NATS
modules set this value, the largest wins.  A value of **0** keeps the
shared default (60).  As with
[reconnect_wait_ms](#reconnect_wait_ms-integer), the value is ignored
unless this module registers servers with the pool.


*Default value is "0" (use the shared default).*


```opensips title="Set max_reconnect parameter"
...
modparam("nats_consumer", "max_reconnect", 30)
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
modparam("nats_consumer", "no_randomize", 1)
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
modparam("nats_consumer", "reconnect_buf_size", 33554432)
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
modparam("nats_consumer", "user", "opensips")
modparam("nats_consumer", "password", "s3cret")
...
```


#### password (string)


Password for [user](#user-string); both must be set.


*Default value is "NULL" (no password).*


```opensips title="Set password parameter"
...
modparam("nats_consumer", "password", "s3cret")
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
modparam("nats_consumer", "token", "s3cr3t-t0ken")
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
modparam("nats_consumer", "creds_file", "/etc/opensips/nats/opensips.creds")
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
modparam("nats_consumer", "nkey", "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4")
modparam("nats_consumer", "nkey_seed_file", "/etc/opensips/nats/opensips.nk")
...
```


#### nkey_seed_file (string)


Path of the file holding the NKey seed (`SU...`) of
[nkey](#nkey-string); both must be set.  The file must be readable when
OpenSIPS starts.


*Default value is "NULL" (no seed file).*


```opensips title="Set nkey_seed_file parameter"
...
modparam("nats_consumer", "nkey_seed_file", "/etc/opensips/nats/opensips.nk")
...
```


### Exported Functions


#### nats_fetch(id, [timeout_ms])


Pull a single JetStream message for the handle
*id* off the SHM ring.  Populates the
per-worker `$nats_*` pseudo-variables
with the delivered message's subject, data, sequence,
delivery count, pending count, reply subject, and
headers.  Does not acknowledge the message — call
[nats_ack()](#nats_ack),
[nats_nak()](#nats_nak), or
[nats_term()](#nats_term) explicitly.


Meaning of the parameters is as follows:


- *id* (string) - a previously-bound consumer handle id.
- *timeout_ms* (integer, optional) - block up to this many
milliseconds waiting for a message.  Default `0` = non-blocking.


Return values (no path returns `0` — a
0 return from a script function terminates the
calling route):


- **1** - a message was fetched.
- **-1** - no message arrived within the budget (not an error; the
script may retry).
- **-2** - the NATS connection is down: the ring is empty and the
shared connection reports disconnected, so the call returns at once
instead of waiting out *timeout_ms*; the script can tell a transport
failure from an empty ring and back off.
- **-3** - the handle id is not found or is retiring.
- **-4** - asynchronous flavor only: *timeout_ms* is missing or
not positive and no message is waiting.
- **-6** - asynchronous flavor only: internal error (timerfd setup
or out of memory).


This function can be used from any route.  The asynchronous flavor is
[nats_fetch()](#nats_fetchid-timeout_ms-1).


```opensips title="nats_fetch usage"
timer_route[jobs_drain, 1] {
    # at most 100 messages x 5 ms wait = 500 ms, inside the 1 s interval
    $var(n) = 0;
    while ($var(n) < 100 && nats_fetch("jobs", 5)) {
        xlog("L_INFO", "job $nats_seq: $nats_data\n");
        nats_ack();
        $var(n) = $var(n) + 1;
    }
}
```


#### nats_fetch_batch(id, [opts])


Drain up to *count* messages in a
single call.  The fetched messages are staged in a
per-worker batch buffer.  Use
[nats_batch_select()](#nats_batch_selectidx) to activate
each one, then ack / nak / term it before moving on.


Meaning of the parameters is as follows:


- *id* (string) - a previously-bound consumer handle id.
- *opts* (string, optional) - a semicolon-separated
`k=v` string recognizing
`count` (default 1),
`expires` (duration, default 0 =
non-blocking;
accepts a bare integer interpreted as ms, or a
suffix of `ms` / `s`
/ `m` / `h` /
`d`),
`expires_ms` (alias for
`expires`; bare integer ms),
and `no_wait` (bool, default 0).


Returns the number of messages staged in
`$retcode`, or a negative error
code as for [nats_fetch()](#nats_fetchid-timeout_ms)
(-1 when nothing arrived within the budget).  Malformed *opts* return
-1 from this function and -4 from its asynchronous flavor.
The OpenSIPS script does not allow direct
assignment of a function return to a
`$var()`; capture
`$retcode` immediately after the
call.


When `expires` is positive, the
call blocks on the cross-process ring futex
in slices of up
to 100 ms until the requested
`count` is reached or the deadline
expires.  This wait is bounded by the
worker's request-route processing budget; do not
set `expires` longer than the
request a route is meant to take.


This function can be used from any route.  The asynchronous flavor is
[nats_fetch_batch()](#nats_fetch_batchid-opts-1).


```opensips title="nats_fetch_batch usage"
timer_route[drain, 1] {
    # A fetch waits up to expires_ms for its batch to fill, so while
    # messages keep trickling in every call can take the full wait.
    # Keep batches x expires_ms inside the timer interval
    # (50 x 10 ms = 500 ms here) so passes never overlap; raise count,
    # not the loop bound, for more throughput.
    $var(b) = 0;
    while ($var(b) < 50) {
        nats_fetch_batch("jobs", "count=100;expires_ms=10");
        $var(rc) = $retcode;
        if ($var(rc) <= 0) { break; }
        $var(i) = 0;
        while ($var(i) < $var(rc)) {
            nats_batch_select($var(i));
            nats_ack();
            $var(i) = $var(i) + 1;
        }
        $var(b) = $var(b) + 1;
    }
}
```


#### nats_batch_select(idx)


Activate the *idx*-th message in the
worker's current batch so subsequent
`$nats_*` reads and
[nats_ack()](#nats_ack) /
[nats_nak()](#nats_nak) /
[nats_term()](#nats_term) calls target it.


Selecting an index whose message was already acknowledged succeeds,
but the slot no longer holds a message: a following ack / nak / term
is a no-op that returns -1.


Meaning of the parameters is as follows:


- *idx* (integer) - the message index, `0 .. n-1` where *n* is the
return of the most recent [nats_fetch_batch()](#nats_fetch_batchid-opts).


Returns 1 on success, -1 when there is no current batch or *idx* is
out of range.


This function can be used from any route.


```opensips title="nats_batch_select usage"
nats_fetch_batch("jobs", "count=10");
$var(rc) = $retcode;
$var(i) = 0;
while ($var(i) < $var(rc)) {
    nats_batch_select($var(i));
    xlog("L_INFO", "job $nats_seq: $nats_data\n");
    nats_ack();
    $var(i) = $var(i) + 1;
}
```


#### nats_ack()


Acknowledge the current message successfully.


Returns 1 on success, -1 when there is no current message (or its
ack token has already been consumed), -2 when the ack could not be
queued to the consumer process.


This function can be used from any route.


```opensips title="nats_ack usage"
if (nats_fetch("jobs", 0))
    nats_ack();
```


#### nats_ack_next()


Ack the current message and immediately request another delivery
(reduces round-trips when tight-looping a durable consumer).


Returns 1 on success, -1 when there is no current message, -2 when
the ack could not be queued to the consumer process.


This function can be used from any route.


```opensips title="nats_ack_next usage"
if (nats_fetch("jobs", 0))
    nats_ack_next();
```


#### nats_ack_progress()


Refresh the broker's ack timer to keep the current delivery alive
past the handle's `ack_wait`, without triggering a redelivery.  The
current message stays selected, so a following
[nats_ack()](#nats_ack) / [nats_nak()](#nats_nak) /
[nats_term()](#nats_term) still targets it.  This is the same function
as [nats_in_progress()](#nats_in_progress).


Returns 1 on success, -1 when there is no current message, -2 when
the request could not be queued to the consumer process.


This function can be used from any route.


```opensips title="nats_ack_progress usage"
if (nats_fetch("jobs", 0)) {
    nats_ack_progress();
    # ... long-running work ...
    nats_ack();
}
```


#### nats_nak()


Negative-ack the current message; the broker redelivers it at once,
or after the consumer's `backoff` delay when one is configured.


Returns 1 on success, -1 when there is no current message, -2 when
the nak could not be queued to the consumer process.


This function can be used from any route.


```opensips title="nats_nak usage"
if (nats_fetch("jobs", 0))
    nats_nak();
```


#### nats_nak_delay(delay_ms)


Same as [nats_nak()](#nats_nak) but the broker schedules redelivery for
*delay_ms* milliseconds in the future instead of at once.


Meaning of the parameters is as follows:


- *delay_ms* (integer) - redelivery delay in milliseconds; a value of
0 or less redelivers without delay.


Returns 1 on success, -1 when there is no current message, -2 when
the nak could not be queued to the consumer process.


This function can be used from any route.


```opensips title="nats_nak_delay usage"
if (nats_fetch("jobs", 0))
    nats_nak_delay(5000);
```


#### nats_term()


Terminate the delivery with no retry.  `max_deliver`-style advisory
semantics still apply on the server side.


Returns 1 on success, -1 when there is no current message, -2 when
the request could not be queued to the consumer process.


This function can be used from any route.


```opensips title="nats_term usage"
if (nats_fetch("jobs", 0) && $nats_delivered > 3)
    nats_term();
```


#### nats_in_progress()


Refresh the broker's ack timer to keep the current delivery alive
past `ack_wait`, *without* clearing the worker's current-message
state.  Subsequent [nats_ack()](#nats_ack) /
[nats_nak()](#nats_nak) / [nats_term()](#nats_term) calls still
target the same delivery.  Use when a long handler will continue to
poll progress and eventually finalise with one of the standard acks.


Returns 1 on success, -1 when there is no current message, -2 when
the request could not be queued to the consumer process.


This function can be used from any route.


```opensips title="nats_in_progress usage"
if (nats_fetch("jobs", 0)) {
    nats_in_progress();
    # ... long-running work ...
    nats_ack();
}
```


#### nats_hdr_set(name, value)


Stage a header on the worker-local outgoing header
buffer.  The next [nats_reply()](#nats_replypayload) or
[nats_request()](#nats_requestsubject-payload-timeout_ms) flushes the
staged headers onto the outbound NATS message.  Staging a name that is
already staged (compared case-insensitively) replaces its value.  Up to
16 headers can be staged per worker; attempts to add more
return `-1`.


Staged headers are cleared after every
[nats_reply()](#nats_replypayload) or
[nats_request()](#nats_requestsubject-payload-timeout_ms) regardless of
outcome.


Meaning of the parameters is as follows:


- *name* (string) - the header name.
- *value* (string) - the header value.


Returns 1 on success, -1 on an empty name, a full header table or an
allocation failure.


This function can be used from any route.


```opensips title="nats_hdr_set usage"
timer_route[rpc_lookup, 5] {
    nats_hdr_set("X-Trace-Id", "lookup-$Ts");
    nats_request("rpc.lookup", "ping", 200);
}
```


#### nats_reply(payload)


Publish *payload* to the current
message's `reply_to` subject.  Useful
as the responder side of a request/reply exchange.


Meaning of the parameters is as follows:


- *payload* (string) - the reply payload.


Return values:


- **1** - the reply was published.
- **-1** - there is no current message.
- **-2** - the current message has no `reply_to` subject.
- **-3** - there is no NATS connection.
- **-4** - the `reply_to` subject is invalid, or the message could
not be created or published.


This function can be used from any route.


```opensips title="nats_reply usage"
if (nats_fetch("rpc_srv", 10)) {
    if (nats_reply("echo: $nats_data"))
        nats_ack();
    else
        nats_nak();
}
```


#### nats_request(subject, payload, timeout_ms)


Synchronous NATS request/reply.  Publishes
*payload* to
*subject* and waits for a reply on
a per-call inbox, blocking the calling worker for up to
*timeout_ms* milliseconds.  The non-blocking form is the asynchronous
flavor, [nats_request()](#nats_requestsubject-payload-timeout_ms-1).


On success the reply populates the script-visible
state: `$nats_data`,
`$nats_subject`,
`$nats_hdr(Name)`,
`$nats_reply_to`.  The
[$nats_request_id](#nats_request_id) pseudo-variable holds the
UUIDv7 used as the correlation id, which is also
staged as the outbound header named by
[request_id_header](#request_id_header-string) (`X-Request-Id` by
default; the script can override it).


Meaning of the parameters is as follows:


- *subject* (string) - the request subject.
- *payload* (string) - the request payload.
- *timeout_ms* (integer) - how long to wait for the reply, in
milliseconds; 0 or less means 1000.


Return codes.  No path returns `0` -- a 0 return
from a script function silently
terminates the calling route, which is never
correct for an RPC result.  Every outcome is
therefore a positive success code or a negative
error / non-result code:


- **1** - reply delivered.
- **-1** - timeout: the broker
is still reachable but the responder did not
reply within
*timeout_ms*.  Script may
retry with a longer timeout.
- **-2** - asynchronous flavor only: the NATS connection is down
when the call is issued, or is lost while it is in flight (the pool
reconnect epoch advanced or the shared connection went down).  This is
distinct from a timeout: the script should treat
`-2` as broker-down (alert,
circuit-break, surface 503) rather than
retry-with-longer-timeout.  The resume
function checks the connection epoch on every
guard tick, so a mid-flight disconnect surfaces
`-2` on the next guard tick --
worst case one [async_rpc_poll_ms](#async_rpc_poll_ms-integer)
interval (100 ms default) after the pool notices
the loss, independent of the script's
*timeout_ms*.  A reply that is
already being delivered when the disconnect is
detected still wins: the cancel uses the same
atomic claim as the timeout path and backs off
if the consumer got there first.
- **-3** - synchronous form only: NATS unavailable at
issue time (no pool connection).  Returned
before any publish attempt; the script can
short-circuit without paying the
*timeout_ms* wait.
- **-4** - request error
(subject empty, too long or invalid, payload too long (asynchronous
flavor only), msg create failed, publish or sync-request failed).
- **-5** - asynchronous flavor only: no free slot in the
[async_rpc_slots](#async_rpc_slots-integer) pool, or the request could
not be queued to the consumer process.  Callers should implement
back-pressure when this surfaces.
- **-6** - asynchronous flavor only: internal error
(oom, format failure, timerfd setup failure, etc.).


This function can be used from STARTUP_ROUTE, TIMER_ROUTE,
LOCAL_ROUTE, EVENT_ROUTE and ONREPLY_ROUTE; with
[allow_sync_anywhere](#allow_sync_anywhere-integer) set, from any route.


```opensips title="nats_request usage"
timer_route[rpc_cli, 5] {
    if (nats_request("rpc.call", "ping", 2000))
        xlog("L_INFO", "reply: $nats_data\n");
    else
        xlog("L_WARN", "rpc id=$nats_request_id failed rc=$retcode\n");
}
```


#### nats_consumer_bind(config)


Bind a consumer handle from the script, before the workers start,
like one declared with the [bind](#bind-string) parameter.  The
`startup_route` runs at every start, so a handle bound there is bound
again after a restart.


Meaning of the parameters is as follows:


- *config* (string) - the handle configuration, a semicolon-separated
`k=v` string with the same keys as the
[nats_consumer:nats_consumer_bind](#nats_consumernats_consumer_bind) MI
command.  Script strings expand `$` variables, so a literal `$`
(as in the `$JS` subject prefix) is written `$$`.


Returns 1 on success, -1 when the configuration is malformed, has an
unknown key or a duplicate id, or the handle limit is reached (the
reason is logged).


This function can be used from STARTUP_ROUTE.


```opensips title="nats_consumer_bind usage"
startup_route {
    nats_consumer_bind("id=jobs;stream=WORK;durable=jobs_worker;filter=work.jobs;ack_wait=30s;max_deliver=5");
}
```


### Exported Asynchronous Functions


#### nats_fetch(id, [timeout_ms])


The asynchronous flavor of the [nats_fetch()](#nats_fetchid-timeout_ms)
function. It receives the same parameters, with the same meanings,
except that *timeout_ms* is required and must be > 0; otherwise the
call returns -4 (unless a message is already waiting).


The worker yields immediately after the
call; a worker-private timerfd registered with the
reactor polls the ring on each tick and resumes the
worker when a message arrives, or once the per-call
*timeout_ms* deadline expires.  When a message is already waiting,
the call completes without yielding.


```opensips title="async nats_fetch usage"
route[PROCESS] {
    async(nats_fetch("orders", 5000), ON_MSG);
}

route[ON_MSG] {
    if ($retcode == 1) {
        xlog("L_INFO", "got $nats_subject: $nats_data\n");
        nats_ack();
    } else {
        xlog("L_WARN", "no message, rc=$retcode\n");
    }
}
```


#### nats_fetch_batch(id, [opts])


The asynchronous flavor of the
[nats_fetch_batch()](#nats_fetch_batchid-opts)
function. It receives the same parameters, with the same meanings.


The worker yields while the batch fills; the resume route sees the
number of staged messages (or -1 / -2 when none arrived) in
`$retcode`.


```opensips title="async nats_fetch_batch usage"
route[PROCESS] {
    async(nats_fetch_batch("jobs", "count=10;expires=500ms"), ON_BATCH);
}

route[ON_BATCH] {
    $var(rc) = $retcode;
    $var(i) = 0;
    while ($var(i) < $var(rc)) {
        nats_batch_select($var(i));
        nats_ack();
        $var(i) = $var(i) + 1;
    }
}
```


#### nats_request(subject, payload, timeout_ms)


The asynchronous flavor of the
[nats_request()](#nats_requestsubject-payload-timeout_ms)
function. It receives the same parameters, with the same meanings.


The worker hands the request to the consumer process over IPC and
yields to the reactor on a private guard timerfd.  The consumer
process publishes the request, receives the reply on its persistent
inbox subscription and wakes the worker over IPC; the
resume route runs with the per-worker
current-message state populated.  It is accepted from every route
that supports `async()`, whatever
[allow_sync_anywhere](#allow_sync_anywhere-integer) is set to.  Each
call in flight holds one of the [async_rpc_slots](#async_rpc_slots-integer).


```opensips title="async nats_request usage"
route {
    async(nats_request("rpc.lookup", $var(payload), 200), on_reply);
}

route[on_reply] {
    if ($retcode == 1) {
        # success: reply in $nats_data
    } else if ($retcode == -1) {
        # timeout: responder slow; maybe retry with longer tmo
        xlog("L_WARN", "rpc id=$nats_request_id timeout\n");
    } else if ($retcode == -2) {
        # broker is down: alert / circuit-break
        xlog("L_ERR", "rpc id=$nats_request_id connection lost\n");
        sl_send_reply(503, "Service Unavailable");
    } else {
        # -4 / -5 / -6: request / capacity / internal
        xlog("L_ERR", "rpc id=$nats_request_id failed rc=$retcode\n");
        sl_send_reply(500, "Internal Server Error");
    }
}
```


### Exported MI Functions


#### nats_consumer:nats_consumer_bind


Register a consumer handle.  Unknown keys are rejected as
configuration errors.


Parameters:


- *config* - a semicolon-separated `k=v` string.
Required keys: `id`,
`stream`, and either
`durable=<name>` or
`ephemeral=1`.  Optional keys cover
the full JetStream pull-consumer matrix:
`filter`, `filters`,
`deliver_policy`,
`start_seq`, `start_time`,
`replay_policy`,
`ack_policy`, `ack_wait`,
`max_deliver`, `backoff`,
`max_ack_pending`,
`headers_only`,
`sample_freq`,
`rate_limit`,
`inactive_threshold`,
`js_domain`,
`api_prefix`,
`ring_capacity`,
[fetch_batch](#fetch_batch-integer),
[fetch_timeout_ms](#fetch_timeout_ms-integer).


```bash
opensips-cli -x mi nats_consumer:nats_consumer_bind \
  'id=jobs;stream=WORK;durable=jobs_worker;filter=work.jobs;ack_wait=30s;max_deliver=5'
```


#### nats_consumer:nats_consumer_unbind


Remove a handle by id.  The handle is marked
*retired* immediately so subsequent
lookups miss; the consumer process tears down the
JetStream subscription on its next iteration, and the
registry reaper frees the handle once all in-flight ack
operations drain.  The command
always returns promptly — the deferred teardown is
invisible to the caller.


Parameters:


- *id* - the handle id.


```bash
opensips-cli -x mi nats_consumer:nats_consumer_unbind id=jobs
```


#### nats_consumer:nats_consumer_list


List all registered handles with their bind-time
configuration and current runtime counters
(created_at, last_used_at, pulls_requested, msgs_delivered, acks,
naks, terms, redeliveries, poisoned, fetch_skips_full,
backpressure_drops, fetch_errors, ring_depth,
ring_forced_unwedges).


Parameters: *none*


Each handle entry also carries two backoff-state
fields that surface the consumer process's
subscription retry budget:


- *ensure_failures* - consecutive failures to (re)create the
handle's subscription.  Zero on
a healthy handle; non-zero while the consumer process is in
backoff after the broker rejected
`js_AddConsumer` /
`js_PullSubscribe` (e.g. the
broker-side durable was deleted out from under
OpenSIPS, or the underlying stream is missing).
The next failed retry would push the value to
seven, at which point the backoff saturates at
the 60 s cap and a one-shot WARN names the handle.
- *ensure_next_retry_at* - unix timestamp (CLOCK_REALTIME seconds)
before which the consumer process will skip this handle's reconcile
tick.  Zero means "retry on the next tick".


Both fields reset to zero on the first successful
resubscribe; a corresponding INFO ("recovered after N
failed ensure attempt(s)") fires once per recovery
edge so log forwarders can tell wedge from recovery
without polling.


```bash
opensips-cli -x mi nats_consumer:nats_consumer_list
```


#### nats_consumer:nats_consumer_health


Liveness snapshot of the dedicated consumer process.
Intended for external watchdogs (Prometheus
exporters, Nagios checks, etc.) -- a wedged or
crashed consumer leaves SIP workers blocked on the
per-handle SHM ring's eventfd with no other observable
signal.


Parameters: *none*


Returns a JSON object:


- *tick* - monotonic
loop-iteration counter incremented once per
consumer-loop pass.
- *consumer_pid* - PID of the consumer process.
- *last_tick_ms_ago* - milliseconds since the last tick
(CLOCK_MONOTONIC).
- *stale* - *"true"* when
`last_tick_ms_ago` exceeds 5000 ms
(more than five times the loop's 1 s upper-wait
bound) or no tick has been observed yet.


```bash
opensips-cli -x mi nats_consumer:nats_consumer_health
```


```json
{
    "tick": 12943,
    "consumer_pid": 4711,
    "last_tick_ms_ago": 821,
    "stale": "false"
}
```


#### nats_consumer:nats_consumer_stats


One flat JSON object aggregating the observability
counters an operator needs to spot back-pressure and
IPC saturation.  Safe to call from the attendant/MI
process: the counters live in SHM allocated pre-fork.


Parameters: *none*


- *handles*, *ring_depth* / *ring_capacity* - bound handle count
and ring occupancy summed across handles.
- *msgs_delivered*, *pulls_requested*, *acks*, *naks*, *terms*,
*redeliveries*, *poisoned* - lifetime delivery/ack totals (poisoned
counts messages terminated by the
[poison_max_deliver](#poison_max_deliver-integer) backstop).
- *fetch_skips_full* - Fetches skipped because a ring was full (flow
control, no data loss); *backpressure_drops* - messages fetched but
deferred (the broker redelivers); *fetch_errors* - Fetch calls
returning a hard error.
- *ack_ipc_depth* / *ack_ipc_enqueued* / *ack_ipc_drained* /
*ack_ipc_dropped* - the worker-to-consumer
ack queue: current depth plus lifetime totals.  A
climbing depth or any drops mean the consumer
process is not draining acks fast enough.
- *rpc_ipc_depth* / *rpc_ipc_enqueued* / *rpc_ipc_drained* /
*rpc_ipc_dropped* - same fields for the
async-RPC request queue, plus
*rpc_slot_orphans_reaped*
(slots reclaimed after their worker died).
- *rpc_slots_inflight* / *rpc_slots_total* - async-RPC slot-pool
occupancy; inflight pinned at total means new asynchronous
[nats_request()](#nats_requestsubject-payload-timeout_ms-1) calls return
`-5` (pool full).


```bash
opensips-cli -x mi nats_consumer:nats_consumer_stats
```


```json
{
    "handles": 2,
    "ring_depth": 0,
    "ring_capacity": 2048,
    "msgs_delivered": 15024,
    "pulls_requested": 15060,
    "acks": 15024,
    "naks": 0,
    "terms": 0,
    "redeliveries": 3,
    "poisoned": 0,
    "fetch_skips_full": 0,
    "backpressure_drops": 0,
    "fetch_errors": 0,
    "ack_ipc_depth": 0,
    "ack_ipc_enqueued": 15024,
    "ack_ipc_drained": 15024,
    "ack_ipc_dropped": 0,
    "rpc_ipc_depth": 0,
    "rpc_ipc_enqueued": 240,
    "rpc_ipc_drained": 240,
    "rpc_ipc_dropped": 0,
    "rpc_slot_orphans_reaped": 0,
    "rpc_slots_inflight": 1,
    "rpc_slots_total": 64
}
```


### Exported Pseudo-Variables


#### $nats_subject


NATS subject the current message was delivered on.


#### $nats_data


Message payload.


#### $nats_reply_to


Reply subject (NULL when the publisher did not request a
reply).


#### $nats_seq


JetStream stream sequence number.


#### $nats_consumer_seq


JetStream consumer-side sequence number.


#### $nats_delivered


Broker's delivered counter (1 on first delivery, bumps on each
redelivery).


#### $nats_pending


Broker's estimate of messages still waiting on the stream after this
one.


#### $nats_token


Opaque ack token encoding (handle_idx, slot_idx, generation).


#### $nats_hdr(name)


Read a header from the current message.  Lookup is
case-insensitive.  *name* must be
a literal; dynamic
`$nats_hdr($var(x))` forms are not
supported.


#### $nats_request_id


Read/write.  UUIDv7 correlation id of the most recent
[nats_request()](#nats_requestsubject-payload-timeout_ms) issued by
this worker.  Minted automatically by both the
sync and async start paths at call time and
stashed in per-worker process memory so it is
readable
**before** the
call returns (sync),
**across the
`async()` yield**,
and inside the resume route.  Returns
`NULL` on workers that have
not yet issued any request
call and have no pending script assignment.
The same value is auto-staged as the
`X-Request-Id` outbound header
(header name configurable via the
[request_id_header](#request_id_header-string)
modparam); responders that echo the header on
the reply get end-to-end correlation across
logs and traces.  Set the modparam to an empty
string to mint but not stage.


*Caller-set override.*
Assigning to the pseudo-variable before a
request call swaps
the auto-minted UUIDv7 for the script-supplied
value on that one call (consume-once
semantics): subsequent calls with no further
assignment revert to minting fresh.  Useful
for propagating an inbound trace id (e.g. from
a SIP header, an upstream tracing context, or
a callee-specific correlation token) into the
NATS request so the entire trace shares one
id end-to-end.
Validation: 1..63 bytes, no CR/LF (would
inject pseudo-headers into the NATS wire
format).  Out-of-range assignments are
rejected, a warning is logged
explaining why, and the next call falls
back to minting a fresh UUIDv7.


*Clearing the override.*
Both `$nats_request_id = NULL`
and `$nats_request_id = ""`
clear the pending override and the stash.
After a clear, `$nats_request_id`
reads NULL until the next
request mints fresh.


```opensips title="Correlate an async RPC across log lines"
route {
    xlog("L_INFO", "issuing rpc id=$nats_request_id\n");
    async(nats_request("rpc.lookup", $var(payload), 200), on_reply);
}
route[on_reply] {
    if ($retcode == 1) {
        xlog("L_INFO", "rpc id=$nats_request_id reply=$nats_data()\n");
    } else if ($retcode == -1) {
        xlog("L_WARN", "rpc id=$nats_request_id timed out\n");
    }
}
```


```opensips title="Propagate an inbound SIP X-Trace-Id into the NATS RPC"
route {
    # Reuse the upstream caller's trace id (if present) so the
    # NATS responder logs the same id the SIP gateway logged.
    if ($hdr(X-Trace-Id) != null) {
        $nats_request_id = $hdr(X-Trace-Id);
    }
    async(nats_request("rpc.lookup", $var(payload), 200), on_reply);
}
route[on_reply] {
    # $nats_request_id still holds the id used on this call --
    # the consume-once flag was cleared when nats_request fired,
    # but the stash still reflects the value that went out.
    xlog("L_INFO", "rpc trace=$nats_request_id reply=$nats_data()\n");
}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
