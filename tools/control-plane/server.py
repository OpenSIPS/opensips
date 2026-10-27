#!/usr/bin/env python3
"""Small OpenSIPS MI control API, live SSE feed and web UI backend."""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent
UI = ROOT / "index.html"
MI_URL = os.environ.get("OPENSIPS_MI_URL", "http://127.0.0.1:8888/mi")
CONTROL_TOKEN = os.environ.get("CONTROL_TOKEN", "")
SNAPSHOT_METHODS = [m.strip() for m in os.environ.get(
    "OPENSIPS_SNAPSHOT_METHODS", "get_statistics,status_report:status,uptime"
).split(",") if m.strip()]
SSE_INTERVAL = max(0.5, float(os.environ.get("CONTROL_SSE_INTERVAL", "2")))
ALLOW_REMOTE = os.environ.get("CONTROL_ALLOW_REMOTE", "").strip().lower() in ("1", "true", "yes", "on")

READ_PREFIXES = ("get_", "list_", "show_")
READ_METHODS = {"status_report", "status_report:status", "status", "uptime", "ps", "which"}


class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.http_requests = 0
        self.mi_requests = 0
        self.mi_errors = 0
        self.mi_latency_ms = 0.0
        self.sse_clients = 0

    def inc_http(self) -> None:
        with self.lock:
            self.http_requests += 1

    def observe_mi(self, elapsed_ms: float, error: bool) -> None:
        with self.lock:
            self.mi_requests += 1
            self.mi_latency_ms = elapsed_ms
            if error:
                self.mi_errors += 1

    def sse(self, delta: int) -> None:
        with self.lock:
            self.sse_clients += delta

    def prometheus(self) -> str:
        with self.lock:
            return (
                "# TYPE opensips_control_http_requests_total counter\n"
                f"opensips_control_http_requests_total {self.http_requests}\n"
                "# TYPE opensips_control_mi_requests_total counter\n"
                f"opensips_control_mi_requests_total {self.mi_requests}\n"
                "# TYPE opensips_control_mi_errors_total counter\n"
                f"opensips_control_mi_errors_total {self.mi_errors}\n"
                "# TYPE opensips_control_mi_last_latency_ms gauge\n"
                f"opensips_control_mi_last_latency_ms {self.mi_latency_ms:.3f}\n"
                "# TYPE opensips_control_sse_clients gauge\n"
                f"opensips_control_sse_clients {self.sse_clients}\n"
            )


METRICS = Metrics()


def is_read_only(method: str) -> bool:
    value = method.strip().lower()
    return bool(value) and (value in READ_METHODS or value.startswith(READ_PREFIXES))


def is_loopback_listener(host: str) -> bool:
    value = host.strip()
    if not value:
        return False

    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        pass

    try:
        resolved = {
            item[4][0]
            for item in socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        return False

    if not resolved:
        return False
    try:
        return all(ipaddress.ip_address(address).is_loopback for address in resolved)
    except ValueError:
        return False


def is_safe_local_host_header(value: Optional[str]) -> bool:
    """Reject DNS-rebinding hostnames when serving an unauthenticated loopback API."""
    if not value:
        return False
    try:
        # urlsplit correctly handles bracketed IPv6 and optional ports.
        host = urlsplit("//" + value, scheme="http").hostname
    except ValueError:
        return False
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Do not resolve arbitrary hostnames here: accepting a hostname merely
        # because DNS currently maps it to 127/8 would re-introduce DNS rebinding.
        return False


def validate_snapshot_methods(methods: list[str]) -> None:
    unsafe = [method for method in methods if not is_read_only(method)]
    if unsafe:
        raise ValueError(
            "OPENSIPS_SNAPSHOT_METHODS may contain read-only MI methods only; "
            f"refusing: {', '.join(unsafe)}"
        )


def bearer_authorized(auth_header: Optional[str]) -> bool:
    if not CONTROL_TOKEN or not auth_header:
        return False
    expected = f"Bearer {CONTROL_TOKEN}"
    return hmac.compare_digest(auth_header, expected)


def authorized(auth_header: Optional[str], method: str) -> bool:
    if is_read_only(method) and not ALLOW_REMOTE:
        return True
    return bearer_authorized(auth_header)


class MIClient:
    def __init__(self, url: str) -> None:
        self.url = url
        self._id = 0
        self._lock = threading.Lock()

    def call(self, method: str, params: Any = None) -> Dict[str, Any]:
        with self._lock:
            self._id += 1
            request_id = self._id
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params not in (None, {}, []):
            payload["params"] = params
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        error = False
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
            result = json.loads(raw.decode("utf-8"))
            if isinstance(result, dict) and result.get("error"):
                error = True
            return result
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            error = True
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": str(exc)}}
        finally:
            METRICS.observe_mi((time.monotonic() - started) * 1000.0, error)


MI = MIClient(MI_URL)


def snapshot_call(method: str) -> Dict[str, Any]:
    if method == "get_statistics":
        return MI.call(method, {"statistics": ["all"]})
    return MI.call(method)


def snapshot() -> Dict[str, Any]:
    # Environment configuration is validated at startup, but keep this guard
    # here as defense in depth for embedders/tests which mutate the list.
    validate_snapshot_methods(SNAPSHOT_METHODS)
    return {
        "timestamp": time.time(),
        "mi_url": MI_URL,
        "results": {method: snapshot_call(method) for method in SNAPSHOT_METHODS},
    }


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenSIPSControl/1.0"

    def _api_origin_allowed(self) -> bool:
        if ALLOW_REMOTE:
            return True
        return is_safe_local_host_header(self.headers.get("Host"))

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _headers(self, status: int, content_type: str, length: Optional[int] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _json(self, status: int, value: Any) -> None:
        body = json_bytes(value)
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 1024 * 1024:
            raise ValueError("invalid request size")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:
        METRICS.inc_http()
        if self.path.startswith(("/api/", "/metrics")) and not self._api_origin_allowed():
            self._json(HTTPStatus.FORBIDDEN, {"error": "invalid Host for loopback control API"})
            return
        if ALLOW_REMOTE and self.path.startswith(("/api/", "/metrics")):
            if not bearer_authorized(self.headers.get("Authorization")):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Bearer authentication required"})
                return
        if self.path == "/" or self.path == "/index.html":
            data = UI.read_bytes()
            self._headers(HTTPStatus.OK, "text/html; charset=utf-8", len(data))
            self.wfile.write(data)
            return
        if self.path == "/api/health":
            self._json(HTTPStatus.OK, {"ok": True, "mi_url": MI_URL})
            return
        if self.path == "/api/snapshot":
            self._json(HTTPStatus.OK, snapshot())
            return
        if self.path == "/metrics":
            body = METRICS.prometheus().encode("utf-8")
            self._headers(HTTPStatus.OK, "text/plain; version=0.0.4; charset=utf-8", len(body))
            self.wfile.write(body)
            return
        if self.path == "/api/events":
            self._serve_sse()
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        METRICS.inc_http()
        if self.path != "/api/mi":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._api_origin_allowed():
            self._json(HTTPStatus.FORBIDDEN, {"error": "invalid Host for loopback control API"})
            return
        try:
            data = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        if not isinstance(data, dict) or not isinstance(data.get("method"), str):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "body must contain string method"})
            return
        method = data["method"].strip()
        if not method or len(method) > 128:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid method"})
            return
        if not authorized(self.headers.get("Authorization"), method):
            self._json(HTTPStatus.FORBIDDEN, {
                "error": "mutating MI commands require CONTROL_TOKEN and Bearer authentication"
            })
            return
        self._json(HTTPStatus.OK, MI.call(method, data.get("params")))

    def _serve_sse(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        METRICS.sse(1)
        try:
            for _ in range(300):
                payload = json_bytes(snapshot()).decode("utf-8")
                self.wfile.write(f"event: snapshot\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                time.sleep(SSE_INTERVAL)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            METRICS.sse(-1)


def main() -> None:
    host = os.environ.get("CONTROL_LISTEN", "127.0.0.1")
    port = int(os.environ.get("CONTROL_PORT", "8088"))
    try:
        validate_snapshot_methods(SNAPSHOT_METHODS)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if not is_loopback_listener(host) and not ALLOW_REMOTE:
        raise SystemExit(
            "refusing non-loopback CONTROL_LISTEN without CONTROL_ALLOW_REMOTE=1; "
            "keep the service on loopback or explicitly opt in and protect it with TLS/SSO/VPN"
        )
    if ALLOW_REMOTE and not CONTROL_TOKEN:
        raise SystemExit("CONTROL_TOKEN is required whenever CONTROL_ALLOW_REMOTE=1")
    print(f"OpenSIPS control plane: http://{host}:{port} -> {MI_URL}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
