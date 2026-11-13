---
title: "opentelemetry Module"
description: "The *opentelemetry* module provides OpenTelemetry tracing for OpenSIPS route execution."
---

## Admin Guide


### Overview


The *opentelemetry* module provides OpenTelemetry
tracing for OpenSIPS route execution. It creates a root span per
processed SIP message and a child span for each route entry.


The root SIP message span follows a local semantic convention inspired
by the OpenTelemetry HTTP span conventions: it uses a method-plus-target
span name, server/client/internal span kinds based on the OpenSIPS route
type, and generic network, client, server and URL attributes wherever
they fit the SIP model.


Spans include common SIP attributes (request method, Call-ID, CSeq,
response status) and connection metadata. While a span is active,
OpenSIPS logs can be attached as OpenTelemetry events for easier
correlation.


Trace data is exported via the OTLP/HTTP exporter from the
OpenTelemetry C++ SDK.


The local SIP span convention emitted by this module is documented in
`modules/opentelemetry/semantic-convention/sip-spans.md`.


### SIP Call Correlation


When enabled (see the `sip_correlation` parameter), all the
SIP messages sharing the same Call-ID are placed in the same
OpenTelemetry trace, even if they are processed independently, by
different OpenSIPS workers. No state is shared between the workers:
the TraceId is derived deterministically from the Call-ID, so the
INVITE, its provisional and final replies, the in-dialog requests and
the final BYE all end up in one trace.


The root span of each SIP message is also given a deterministic
synthetic parent SpanId, derived from the SIP transaction (Call-ID,
CSeq and top Via branch). This parent span is never exported, so trace
backends will display the message root spans as children of a missing
(orphan) parent. Note that a received reply carries the OpenSIPS Via
branch at the top, so it gets a different synthetic parent than the
request it answers.


The root message span is enriched with the following attributes:


- `sip.trace.id` - hash of the Call-ID (equals the TraceId,
unless an async resume parent context was used).
- `sip.transaction.id` - hash of the Call-ID, CSeq and top Via branch.
- `sip.branch.id` - the top Via branch, when available.
- `sip.dialog.id` - hash of the Call-ID and the From and To tags
(direction independent), once both tags exist.
- `sip.correlation.mode` - always `call-id`.


An existing profiling context has precedence: a route resumed after
an async operation continues the trace of the route which launched it,
rather than using the synthetic SIP correlation parent. Timer, event
and startup routes are not correlated.


Keep in mind that SIP traffic re-using one Call-ID for a long time
(e.g. REGISTER refreshes or OPTIONS keepalives from the same UA, or
very long calls) results in very long-lived traces, which some trace
backends may truncate or reject.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before
running OpenSIPS with this module loaded:


- *OpenTelemetry C++ SDK* (opentelemetry-cpp),
with the OTLP/HTTP exporter enabled.


### Exported Parameters


#### enable (integer)


Enables or disables OpenTelemetry tracing at startup. It can also be
changed at runtime using the `opentelemetry:enable`
MI command.


The module is built only when the OpenTelemetry C++ SDK is available
at build time.


*Default value is "0 (disabled)".*


```opensips title="Set enable parameter"
...
modparam("opentelemetry", "enable", 1)
...
```


#### proc_profiling (integer)


If enabled, the module will also profile/trace the OpenSIPS processes,
not only the script.


*Default value is "0 (disabled)".*


```opensips title="Set proc_profiling parameter"
...
modparam("opentelemetry", "proc_profiling", 1)
...
```


#### log_level (integer)


Log level threshold used by the OpenTelemetry log consumer when
attaching log events to the active span.


*Default value is "L_DBG".*


```opensips title="Set log_level parameter"
...
modparam("opentelemetry", "log_level", 3)
...
```


#### use_batch (integer)


Selects the OpenTelemetry span processor. When enabled, the module uses
the batch span processor; otherwise it uses the simple span processor.


*Default value is "1 (enabled)".*


```opensips title="Set use_batch parameter"
...
modparam("opentelemetry", "use_batch", 0)
...
```


#### sip_correlation (integer)


Places all the SIP messages with the same Call-ID into the same trace -
see the [SIP Call Correlation](#sip-call-correlation) section. When
disabled (the default), each processed SIP message starts an
independent trace, as before.


*Default value is "0 (disabled)".*


```opensips title="Set sip_correlation parameter"
...
modparam("opentelemetry", "sip_correlation", 1)
...
```


#### service_name (string)


Sets the OpenTelemetry "service.name" resource attribute.


*Default value is "opensips".*


```opensips title="Set service_name parameter"
...
modparam("opentelemetry", "service_name", "edge-proxy")
...
```


#### exporter_endpoint (string)


Overrides the OTLP/HTTP exporter endpoint. If empty, the OpenTelemetry
SDK default is used.


*Default value is "empty".*


```opensips title="Set exporter_endpoint parameter"
...
modparam("opentelemetry", "exporter_endpoint", "http://127.0.0.1:4318/v1/traces")
...
```


### Exported MI Functions


#### opentelemetry:enable


Replaces obsolete MI command: *otel_enable*.


Enables or disables OpenTelemetry tracing at runtime.


Name: *opentelemetry:enable*


Parameters:


- *opentelemetry:enable* - set to "1" to enable
tracing or "0" to disable it.


MI FIFO Command Format:


```bash
## enable tracing
opensips-cli -x mi opentelemetry:enable enable=1
## disable tracing
opensips-cli -x mi opentelemetry:enable enable=0

```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
