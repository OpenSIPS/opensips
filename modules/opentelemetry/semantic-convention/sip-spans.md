# Semantic conventions for SIP spans

This document defines the local SIP span shape emitted by `modules/opentelemetry`.
It is intentionally modeled after the OpenTelemetry HTTP span conventions, but
adapted to OpenSIPS route execution and SIP message processing.

## Name

Top-level SIP message spans SHOULD be named `{method} {target}` whenever a SIP
request method is available.

- `{method}` comes from the SIP request line for requests.
- `{method}` comes from the `CSeq` method for replies.
- `{target}` is the low-cardinality OpenSIPS route type:
  `request`, `onreply`, `failure`, `branch`, `local`, `error`, `startup`,
  `timer`, or `event`.

If a request method is not available, the span name SHOULD be `SIP {target}`.
Instrumentation MUST NOT use the raw Request-URI as the span name.

Examples:

- `INVITE request`
- `INVITE onreply`
- `REGISTER local`
- `SIP timer`

## Status

Message spans do not currently report a span status.

- Route-entry child spans SHOULD set the status to `Error` only when the route
  itself returns a negative status code.

## SIP message span

The top-level span represents one SIP message processed by OpenSIPS.

**Span kind**

- `local` spans SHOULD use `CLIENT`.
- `request`, `onreply`, `failure`, `branch`, `error`, `startup`, `timer`, and
  `event` spans SHOULD use `SERVER`.

**Attributes**

The module emits the following attributes when the data is available:

| Attribute | Notes |
| --- | --- |
| `network.protocol.name` | Always `sip`. |
| `network.protocol.version` | Always `2.0` for SIP messages. |
| `network.transport` | Exact OpenSIPS receive transport name from `get_proto_name(msg->rcv.proto)` (for example `udp`, `tcp`, `tls`, `ws`, `wss`, or `sctp`). |
| `opensips.route.type` | Low-cardinality OpenSIPS route type used as the span target. |
| `sip.message.type` | `request` or `response`. |
| `sip.request.method` | From the request line or the `CSeq` method for replies. |
| `sip.response.status_code` | Present on SIP replies. |
| `sip.response.reason` | Present on SIP replies when available. |
| `sip.request.uri` | Raw SIP Request-URI for request messages. |
| `url.full` | Mirrors the SIP Request-URI when available. |
| `url.scheme` | Exact parsed URI type string from `uri_type2str()` (for example `sip`, `sips`, `tel`, `tels`, `urn:service`, or `urn:nena:service`). |
| `server.address` / `server.port` | Derived from the Request-URI authority when available. |
| `network.peer.address` / `network.peer.port` | Remote endpoint of the SIP connection, proxy-protocol aware. |
| `network.local.address` / `network.local.port` | Local endpoint that received the SIP message, proxy-protocol aware. |
| `user_agent.original` | SIP `User-Agent` header on request messages. |
| `sip.call_id` | SIP `Call-ID` header value. |
| `sip.cseq` | Raw SIP `CSeq` header value. |
| `sip.raw` | Raw SIP message payload. |

## Route span

The module also emits a child span for every entered OpenSIPS route block.

- Route spans MUST use `INTERNAL`.
- Route span names SHOULD use the concrete route name when available.
- Unnamed top-level routes fall back to `<route>`.

Route spans emit:

| Attribute | Notes |
| --- | --- |
| `opensips.route.type` | Same low-cardinality route type as the message span. |
| `opensips.route.name` | Present for named routes. |
| `opensips.route.is_root` | `1` for the message span, `0` for route-entry spans. |
| `code.filepath` / `code.lineno` | Source location of the route entry when available. |

## Notes

- This is a local module convention, not an upstream OpenTelemetry SIP semantic
  convention.
- The mapping intentionally reuses stable generic attributes such as
  `network.*`, `server.*`, `url.*`, and `error.type` where they fit the
  SIP/OpenSIPS execution model.
