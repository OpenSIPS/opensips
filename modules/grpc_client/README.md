---
title: "grpc_client Module"
description: "Native asynchronous generic gRPC client for OpenSIPS."
---

## Admin Guide

### Overview

The `grpc_client` module lets the OpenSIPS routing script call arbitrary unary gRPC methods without generated service stubs. It uses gRPC's `GenericStub` and accepts/returns serialized protobuf payload bytes.

Calls are non-blocking from the SIP worker's point of view. gRPC completes on its own runtime thread and signals the OpenSIPS reactor through a non-blocking pipe; the configured async resume route is then executed normally.

This makes the module suitable for rating, fraud, policy, routing, provisioning and other microservices where blocking a SIP worker on network I/O is undesirable.

Where OpenSIPS cannot suspend the processing (for example `async()` used
from a failure or branch route, or for an end-to-end ACK), the core runs
the function in synchronous mode: the worker then waits for the RPC to
complete or for its deadline to expire.

gRPC is initialized lazily, on the first call made by each worker process,
so no gRPC state or thread exists before OpenSIPS forks its processes.

### Dependencies

The gRPC C++ development package must expose `grpc++` through `pkg-config`.
Version 1.40.0 or newer is required because this is the first release
where the callback `GenericStub::UnaryCall(..., StubOptions, ..., callback)`
signature used by the module is available.

### Parameters

#### default_timeout_ms

Default RPC deadline in milliseconds. Default: `3000`. Set to `0` to
disable the module deadline, in which case only an `async()` timeout (if
any) limits the call.

If the script supplies a shorter OpenSIPS `async()` timeout, the shorter value is also used as the gRPC deadline.
When the script gives no `async()` timeout, the module arms an OpenSIPS
async timeout of the deadline (rounded up to seconds) plus one second, as a
safety net.

#### use_tls

Use TLS channels. Default: `0`.

#### ca_file

Optional PEM CA bundle used to verify the gRPC server.

#### client_cert_file / client_key_file

Optional PEM client certificate and key. Both must be configured together for mTLS.

#### authority

Optional TLS target-name override for deployments where the dial target and certificate authority name differ.


#### max_cached_channels

Maximum number of gRPC channels cached per OpenSIPS worker process. Default:
`64`. Set to `0` to disable channel caching.

Channels are keyed by target and reused across calls, which avoids rebuilding
HTTP/2/TLS transport state for every rating or policy request. If the bounded
cache fills, its map is cleared; in-flight calls are unaffected because they
retain their own shared channel reference.

### Async Function

#### grpc_unary(target, method, request, response_var, code_var [, error_var [, metadata]])

- `target`: gRPC target such as `rating.service.local:443`
- `method`: fully-qualified gRPC method, for example `/rating.RatingService/Authorize`
- `request`: serialized protobuf bytes
- `response_var`: writable variable receiving serialized protobuf response bytes
- `code_var`: writable variable receiving the numeric `grpc::StatusCode`
- `error_var`: optional writable variable receiving the gRPC error message
- `metadata`: optional semicolon-separated `key=value` metadata list, for
  example `authorization=Bearer ...;x-tenant=carrier-a`. Items are split
  on `;` and on the first `=`, and surrounding blanks are trimmed, so values
  cannot contain `;`.

Like any OpenSIPS async function, it must be called through `async()` or
`launch()`. If the call cannot be started (invalid method or metadata,
channel or resource failure), the function returns `-1`, the output
variables are left untouched and the resume route runs with a negative
`$rc`.

Example:

```opensips
async(
    grpc_unary(
        "rating.service.local:50051",
        "/rating.RatingService/Authorize",
        $var(protobuf_request),
        $var(protobuf_response),
        $var(grpc_code),
        $var(grpc_error),
        "x-tenant=carrier-a"
    ),
    GRPC_REPLY
);

route[GRPC_REPLY] {
    if ($var(grpc_code) != 0) {
        xlog("L_ERR", "rating gRPC failed: $var(grpc_error)\n");
        return;
    }

    # Decode $var(protobuf_response) according to your service schema.
}
```

The module deliberately operates on protobuf wire bytes rather than requiring
`.proto` files at OpenSIPS build time. This keeps one OpenSIPS binary able to
call unrelated services.

Metadata is added through `ClientContext::AddMetadata()` before the call
starts. This can carry authentication tokens, tenant identifiers, tracing
baggage or other service-specific headers without changing the protobuf body.

Metadata keys are normalized to lowercase, must use ASCII letters/digits plus
`-`, `_` or `.`, and the reserved `grpc-*` namespace is rejected.
Non-binary metadata values must contain printable ASCII only, so embedded
control characters cannot reach the HTTP/2 metadata layer. Keys ending in
`-bin` retain gRPC's binary metadata semantics.

Method names are validated as canonical protobuf RPC paths in
`/package.Service/Method` form: package/service components and the method
must be valid protobuf-style identifiers, with no empty components or extra
path segments.

### Timeout behavior

On timeout the module:

1. calls `ClientContext::TryCancel()`;
2. reports `DEADLINE_EXCEEDED` in `code_var`;
3. writes `gRPC call timed out` to the optional error variable;
4. lets the gRPC completion callback release its remaining ownership after cancellation finishes.

The completion callback and OpenSIPS timeout path use independent reference ownership so they cannot free the call state out from under each other. The timeout path also checks the callback completion flag before and after publishing the timeout state; if the RPC already completed at the timer boundary, its actual result wins instead of being misreported as `DEADLINE_EXCEEDED`.

### Statistics

- `grpc_client:requests` - RPCs started
- `grpc_client:success` - RPCs completed with status `OK`
- `grpc_client:errors` - RPCs completed with a non-`OK` status, including
  gRPC deadline expirations and OpenSIPS async timeouts
- `grpc_client:timeouts` - RPCs abandoned by an OpenSIPS async timeout
  before gRPC reported completion (a subset of `errors`)
- `grpc_client:inflight` - RPCs started but not yet reported to the script

These can be exported by the existing Prometheus module.

### Security

For production traffic over an untrusted network enable TLS. Configure `client_cert_file` and `client_key_file` when the service requires mutual TLS. The module never logs request or response bodies by default.

TLS key material kept in process-local C++ strings is overwritten before the
module releases those buffers during shutdown.
