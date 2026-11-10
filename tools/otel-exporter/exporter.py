#!/usr/bin/env python3
"""Export OpenSIPS MI statistics to an OpenTelemetry Collector over OTLP/HTTP JSON."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, MutableMapping, Tuple

NAME_RE = re.compile(r"[^a-zA-Z0-9_.]+")


def sanitize_metric_name(name: str) -> str:
    value = NAME_RE.sub("_", name.strip()).strip("_").lower()
    return "opensips_" + (value or "unknown")


def parse_pairs(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"expected key=value, got {part!r}")
        key, val = part.split("=", 1)
        out[key.strip()] = val.strip()
    return out


def otlp_endpoint(base: str) -> str:
    base = base.rstrip("/")
    if base.endswith("/v1/metrics"):
        return base
    return base + "/v1/metrics"


def json_request(url: str, payload: Dict[str, Any], headers: Dict[str, str] | None = None, timeout: float = 5.0) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    merged = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        merged.update(headers)
    req = urllib.request.Request(url, data=body, headers=merged, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def fetch_statistics(mi_url: str, selectors: List[str]) -> Dict[str, float]:
    response = json_request(mi_url, {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get_statistics",
        "params": {"statistics": selectors},
    })
    if response.get("error"):
        raise RuntimeError(response["error"])
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("MI get_statistics did not return an object")
    metrics: Dict[str, float] = {}
    for name, value in result.items():
        if isinstance(value, bool):
            metrics[name] = 1.0 if value else 0.0
        elif isinstance(value, (int, float)):
            metrics[name] = float(value)
        elif isinstance(value, str):
            try:
                metrics[name] = float(value)
            except ValueError:
                continue
    return metrics


def fetch_stat_types(mi_url: str, selectors: List[str]) -> Dict[str, str]:
    """Return OpenSIPS statistic types as reported by list_statistics."""
    response = json_request(mi_url, {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "list_statistics",
        "params": {"statistics": selectors},
    })
    if response.get("error"):
        raise RuntimeError(response["error"])
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("MI list_statistics did not return an object")

    types: Dict[str, str] = {}
    for name, value in result.items():
        if isinstance(value, str) and value in ("incremental", "non-incremental"):
            types[name] = value
    return types



def resource_attributes(service_name: str, raw: str) -> List[Dict[str, Any]]:
    attrs = {"service.name": service_name}
    attrs.update(parse_pairs(raw))
    return [{"key": key, "value": {"stringValue": val}} for key, val in sorted(attrs.items())]


def is_counter_stat(name: str, patterns: Iterable[str],
                    stat_types: Dict[str, str] | None = None) -> bool:
    # OpenSIPS marks resettable counters as "incremental". Values reported as
    # "non-incremental" may be gauges (active dialogs, in-use transactions) or
    # non-resettable values, so only explicit overrides may promote those.
    if stat_types and stat_types.get(name) == "incremental":
        return True
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def build_otlp(metrics: Dict[str, float], service_name: str, resource_raw: str,
               timestamp_ns: int | None = None,
               counter_patterns: Iterable[str] = (),
               counter_state: MutableMapping[str, Tuple[int, float]] | None = None,
               stat_types: Dict[str, str] | None = None) -> Dict[str, Any]:
    now = timestamp_ns if timestamp_ns is not None else time.time_ns()
    points = []
    used_names: Dict[str, str] = {}
    for original, value in sorted(metrics.items()):
        metric_name = sanitize_metric_name(original)
        previous = used_names.get(metric_name)
        if previous is not None and previous != original:
            suffix = hashlib.sha1(original.encode("utf-8")).hexdigest()[:8]
            metric_name = f"{metric_name}_{suffix}"
        used_names[metric_name] = original

        data_point = {
            "timeUnixNano": str(now),
            "asDouble": value,
            "attributes": [{"key": "opensips.stat", "value": {"stringValue": original}}],
        }
        metric = {
            "name": metric_name,
            "description": f"OpenSIPS statistic {original}",
            "unit": "1",
        }
        if is_counter_stat(original, counter_patterns, stat_types):
            if counter_state is not None:
                state = counter_state.get(original)
                # OTLP permits start==end for the first point of a cumulative
                # stream when the true start is unknown. Keep that start stable
                # until a monotonic counter decreases, which indicates a reset.
                if state is None or value < state[1]:
                    start_ns = now
                else:
                    start_ns = state[0]
                counter_state[original] = (start_ns, value)
            else:
                # Stateless callers can still emit a valid unknown-start point.
                start_ns = now
            data_point["startTimeUnixNano"] = str(start_ns)
            metric["sum"] = {
                "aggregationTemporality": 2,
                "isMonotonic": True,
                "dataPoints": [data_point],
            }
        else:
            metric["gauge"] = {"dataPoints": [data_point]}
        points.append(metric)
    return {
        "resourceMetrics": [{
            "resource": {"attributes": resource_attributes(service_name, resource_raw)},
            "scopeMetrics": [{
                "scope": {"name": "opensips-mi-otel-exporter", "version": "1"},
                "metrics": points,
            }],
        }]
    }

def export_once(mi_url: str, endpoint: str, selectors: List[str], service_name: str,
                resource_raw: str, otlp_headers: Dict[str, str], timeout: float,
                counter_patterns: Iterable[str] = (),
                counter_state: MutableMapping[str, Tuple[int, float]] | None = None,
                stat_types: Dict[str, str] | None = None) -> int:
    stats = fetch_statistics(mi_url, selectors)
    payload = build_otlp(stats, service_name, resource_raw,
                         counter_patterns=counter_patterns,
                         counter_state=counter_state,
                         stat_types=stat_types)
    json_request(otlp_endpoint(endpoint), payload, otlp_headers, timeout=timeout)
    return len(stats)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--once", action="store_true", help="export one batch and exit")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    mi_url = os.environ.get("OPENSIPS_MI_URL", "http://127.0.0.1:8888/mi")
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    service_name = os.environ.get("OTEL_SERVICE_NAME", "opensips")
    resource_raw = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
    selectors = [x.strip() for x in os.environ.get("OPENSIPS_STATS", "all").split(",") if x.strip()]
    headers = parse_pairs(os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", ""))
    counter_patterns = [
        x.strip() for x in os.environ.get("OTEL_COUNTER_STATS", "").split(",")
        if x.strip()
    ]
    interval = max(1.0, float(os.environ.get("OTEL_INTERVAL", "5")))
    timeout = max(0.5, float(os.environ.get("OTEL_TIMEOUT", "5")))
    counter_state: Dict[str, Tuple[int, float]] = {}
    stat_types: Dict[str, str] = {}
    try:
        stat_types = fetch_stat_types(mi_url, selectors)
        if args.debug:
            incremental = sum(1 for value in stat_types.values()
                              if value == "incremental")
            print(f"discovered {incremental} incremental OpenSIPS counters")
    except (OSError, ValueError, RuntimeError, urllib.error.URLError,
            json.JSONDecodeError) as exc:
        # Older/custom MI endpoints may not expose list_statistics. Exporting
        # remains safe: unmatched values stay gauges and OTEL_COUNTER_STATS can
        # explicitly promote known cumulative counters.
        print(f"otel-exporter: statistic type discovery unavailable: {exc}")

    while True:
        try:
            count = export_once(mi_url, endpoint, selectors, service_name,
                                resource_raw, headers, timeout, counter_patterns,
                                counter_state, stat_types)
            if args.debug:
                print(f"exported {count} OpenSIPS statistics to {otlp_endpoint(endpoint)}")
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
            print(f"otel-exporter: {exc}")
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
