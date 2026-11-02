# OpenSIPS control plane

A dependency-free operational UI and REST gateway for the OpenSIPS Management Interface (MI).

## Features

- browser UI with authenticated live polling
- Server-Sent Events (SSE) endpoint for API clients
- generic JSON MI command endpoint
- read-only commands available without a control token only on localhost
- all API/metrics access authenticated when remote mode is enabled
- mutating commands denied by default and protected with a bearer token
- Prometheus metrics for the control-plane process
- configurable live snapshot methods
- localhost-only default listener
- non-loopback listeners refused unless explicitly enabled

## Start

First expose OpenSIPS MI over HTTP using the normal OpenSIPS `httpd`/`mi_http` configuration, then point the control plane to that URL:

```bash
export OPENSIPS_MI_URL=http://127.0.0.1:8888/mi
export CONTROL_TOKEN='replace-with-a-long-random-value'
python3 tools/control-plane/server.py
```

Open `http://127.0.0.1:8088/`.

Environment variables:

- `OPENSIPS_MI_URL` — JSON-RPC MI endpoint; default `http://127.0.0.1:8888/mi`
- `CONTROL_LISTEN` — listener address; default `127.0.0.1`
- `CONTROL_PORT` — listener port; default `8088`
- `CONTROL_ALLOW_REMOTE` — must be `1` before binding to a non-loopback address
- `CONTROL_TOKEN` — bearer token required for mutating methods; also mandatory for all API/metrics requests when remote mode is enabled
- `OPENSIPS_SNAPSHOT_METHODS` — comma-separated read-only methods for the live
  dashboard; startup fails if a method is not classified read-only, preventing
  refresh loops from accidentally executing mutating MI commands
- `CONTROL_SSE_INTERVAL` — live refresh interval in seconds; minimum `0.5`

## API

### `GET /api/health`

Control-plane health and configured MI target.

### `GET /api/snapshot`

Calls each configured snapshot MI method and returns the results as one JSON object. Individual MI errors remain visible in the response instead of taking down the dashboard.

### `GET /api/events`

SSE stream of live snapshots.

### `GET /metrics`

Prometheus text exposition for the gateway itself:

- HTTP request count
- MI request count
- MI error count
- latest MI latency
- active SSE clients

OpenSIPS process/module metrics remain available through the existing OpenSIPS Prometheus module; this endpoint covers the new control-plane layer.

### `POST /api/mi`

Request:

```json
{
  "method": "get_statistics",
  "params": {}
}
```

Methods beginning with `get_`, `list_` or `show_`, plus the exact methods
`status_report`, `status_report:status`, `status`, `uptime`, `ps` and
`which`, are treated as read-only on localhost. Other methods require:

```text
Authorization: Bearer <CONTROL_TOKEN>
```

This is a deliberate deny-by-default policy. If `CONTROL_TOKEN` is not configured, write-like methods cannot be invoked through the gateway.

## Deployment notes

The built-in HTTP server is intended as a small control surface, not an Internet-facing identity layer. By default it refuses any non-loopback `CONTROL_LISTEN`. If remote binding is intentionally required, set `CONTROL_ALLOW_REMOTE=1`, configure a non-empty `CONTROL_TOKEN`, and place the service behind the same TLS, SSO/VPN and network policy used for other production operations endpoints.

When remote mode is enabled, `/api/*` and `/metrics` require Bearer authentication, including read-only snapshot and SSE requests. The static UI itself remains accessible so an operator can enter the token. The browser does not store the token in local storage; it exists only in the current page input.

In the default loopback-only mode, API and metrics requests also require a
literal loopback `Host` value (`localhost`, `127/8`, or `::1`). Arbitrary
hostnames are not DNS-resolved for this check. This prevents a malicious
website from using DNS rebinding to read the otherwise unauthenticated local
status API.
