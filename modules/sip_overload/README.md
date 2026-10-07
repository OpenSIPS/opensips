---
title: "sip_overload Module"
description: "RFC 7339 loss-based and RFC 7415 rate-based SIP overload control."
---

## Overview

The `sip_overload` module implements hop-by-hop SIP overload control using the Via parameters defined by RFC 7339 and RFC 7415.

When loaded, OpenSIPS advertises overload-control support on every locally generated Via:

```
;oc;oc-algo="loss,rate"
```

The module can consume overload feedback from downstream responses, keep the feedback in shared memory for all workers, enforce the validity interval and sequence ordering, and make admission decisions for both standardized algorithms:

- `loss`: probabilistic request reduction by the advertised percentage
- `rate`: per-peer maximum request rate, enforced with the RFC 7415 default
  leaky bucket (`T = 1/oc`, burst tolerance `TAU = 4*T`)

It can also act as an overloaded server. Loading the module makes server-side
RFC 7339 support visible immediately: a capable upstream client receives an
idle `oc=0;oc-validity=0` response even when no overload policy has been
activated. `oc_set_local()` configures active feedback, which is automatically
written only into the top Via of locally generated responses (e.g.
`sl_send_reply()`, `t_reply()` or the automatic `100 Trying`) and only when
the upstream client advertised `oc`. The client's `oc` and `oc-algo`
parameters are replaced by the server values, as required by RFC 7339.
Responses relayed from downstream are not modified, and the upstream
client's `oc` parameters are not stripped from requests forwarded
downstream (RFC 7339 recommends it).

The server never selects an algorithm the client did not advertise. Because
`loss` is mandatory in RFC 7339, a local `rate` policy presented to a
loss-only neighbor falls back to an idle loss response instead of sending an
incompatible rate value.

The overload scope is an explicit peer key. A deployment should use a stable key representing the downstream IP/port combination, as required by RFC 7339.

## Parameters

### advertise

Enable automatic Via capability advertisement. Default: `1`.

### advertise_algorithms

Comma-separated algorithms advertised in `oc-algo`. Default:

```
loss,rate
```

The order expresses preference. RFC 7339 requires support for `loss`; RFC 7415 defines `rate`.

Configure this value as an unquoted comma-separated list. Each token must
contain ASCII letters or digits only, matching the RFC 7339 `oc-algo` grammar.
Whitespace, empty tokens, quotes, semicolons and control characters are rejected
at startup rather than copied into a Via header.

When `advertise=1`, startup fails if `loss` is omitted, because an RFC 7339
client must support and advertise the loss-based algorithm.

### max_peers

Maximum number of downstream peer feedback records kept in shared memory.
Default: `4096`.

Expired or explicitly cleared (`oc-validity=0`) peer records are garbage
collected before the module refuses a new peer. This bounds shared-memory use
when peer keys are generated dynamically or a deployment talks to many
destinations.

## Functions

### oc_update()

Use in an `onreply_route`. Parses `oc`, `oc-algo`, `oc-validity` and `oc-seq` from the top Via and stores the state under the response source IP/port.

The peer key is formatted as `<ip>:<port>` (IPv6 addresses are not
enclosed in brackets), e.g. `192.0.2.10:5060`; `oc_check()` must be given
the very same key.

If `oc-validity` is absent, the RFC 7339 default of 500 ms is used.

### oc_update_peer(peer)

Same as `oc_update()`, but stores the feedback under an explicit peer key. This is recommended when routing logic already has a canonical destination identifier.

Example:

```opensips
onreply_route[OC_FEEDBACK] {
    oc_update_peer("$avp(dst_key)");
}
```

### oc_check(peer)

Returns `1` when a request may be sent and `-1` when the current overload state says it should be throttled.

For `loss`, the `oc` value is interpreted as the percentage of traffic to reduce. For `rate`, it is interpreted as the maximum requests per second, allowing bursts of up to five back-to-back requests (RFC 7415 default
algorithm, `TAU = 4*T`).

Example:

```opensips
if (oc_check("$avp(dst_key)") < 0) {
    send_reply(503, "Downstream overload");
    exit;
}
t_on_reply("OC_FEEDBACK");
route(relay);
```

The script remains responsible for SIP request prioritization. This allows deployments to protect ACK/BYE/emergency or other locally important traffic according to policy.

### oc_set_local(algorithm, value, validity_ms)

Enable server-side overload feedback. Supported algorithms are `loss` and `rate`.

Examples:

```opensips
# Ask each supporting upstream peer to reduce offered traffic by 35%.
oc_set_local("loss", 35, 1000);

# Or cap a supporting upstream peer at 500 requests/second.
oc_set_local("rate", 500, 1000);
```

The module maintains an increasing `oc-seq` value and automatically writes the feedback into locally generated SIP responses.

### oc_clear_local()

Signals the end of overload control by sending `oc-validity=0` with a new sequence number.

## Events

### E_SIP_OVERLOAD_UPDATE

Raised when a newer valid feedback record is accepted.

Parameters:

- `peer`
- `algorithm`
- `value`
- `validity_ms`

### E_SIP_OVERLOAD_THROTTLE

Raised when `oc_check()` rejects a request due to active feedback.

## Statistics

- `sip_overload:feedback_updates`
- `sip_overload:feedback_stale`
- `sip_overload:feedback_malformed`
- `sip_overload:requests_allowed`
- `sip_overload:requests_throttled`
- `sip_overload:feedback_expired`
- `sip_overload:peer_states`
- `sip_overload:peer_limit_drops`
- `sip_overload:server_updates`

These can be exported by the existing Prometheus module.

## Standards behavior

- Clients always advertise at least `loss`.
- Servers acknowledge overload-control support even while idle with `oc=0`
  and `oc-validity=0`.
- A response algorithm is selected only from algorithms advertised by that
  upstream client.
- `oc-validity` defaults to 500 ms when omitted.
- `oc-validity=0` immediately ends overload control.
- Older or duplicate `oc-seq` feedback does not restart the validity period.
- Loss values are constrained to 0..100.
- Under rate control, `oc=0` with non-zero validity blocks all controlled requests.
- Overload information is scoped per downstream peer rather than globally.
- Per-peer feedback state is bounded by `max_peers`; expired/cleared state is
  reclaimed before new feedback is rejected.
