#!/usr/bin/env python3
"""Audit exported charging events for per-dialog consistency.

Input: JSON Lines with dialog_id, event (start/interim/stop), at (epoch seconds),
optional request_id, cumulative_used_units and result (ok/timeout/error).
No calls or charging actions are performed.
"""
import argparse
import json
import sys


VALID_EVENTS = {"start", "interim", "stop"}


def audit(events, now, stale_after):
    sessions = {}
    anomalies = []

    def issue(line, dialog_id, kind, detail):
        anomalies.append({"line": line, "dialog_id": dialog_id,
                          "type": kind, "detail": detail})

    for line, evt in enumerate(events, 1):
        if not isinstance(evt, dict):
            issue(line, None, "invalid_event", "expected a JSON object")
            continue
        dialog = evt.get("dialog_id")
        kind = evt.get("event")
        at = evt.get("at")
        if not isinstance(dialog, str) or not dialog or kind not in VALID_EVENTS:
            issue(line, dialog, "invalid_event", "missing dialog_id or unsupported event")
            continue
        if not isinstance(at, (int, float)) or isinstance(at, bool):
            issue(line, dialog, "invalid_event", "at must be epoch seconds")
            continue

        session = sessions.setdefault(dialog, {
            "started": False, "stopped": False, "seen_requests": set(),
            "last_at": at, "last_units": None,
        })
        session["last_at"] = max(at, session["last_at"])
        request_id = evt.get("request_id")
        if request_id is not None:
            if not isinstance(request_id, str) or not request_id:
                issue(line, dialog, "invalid_request_id", "request_id must be a nonempty string")
            elif request_id in session["seen_requests"]:
                issue(line, dialog, "duplicate_request_id", request_id)
            else:
                session["seen_requests"].add(request_id)

        if kind == "start":
            if session["started"]:
                issue(line, dialog, "duplicate_start", "multiple charging starts")
            if session["stopped"]:
                issue(line, dialog, "start_after_stop", "new start on stopped dialog")
            session["started"] = True
        elif kind == "interim":
            if not session["started"]:
                issue(line, dialog, "orphan_interim", "interim without start")
            if session["stopped"]:
                issue(line, dialog, "interim_after_stop", "interim on stopped dialog")
        else:
            if not session["started"]:
                issue(line, dialog, "orphan_stop", "stop without start")
            if session["stopped"]:
                issue(line, dialog, "duplicate_stop", "multiple stops")
            session["stopped"] = True

        used = evt.get("cumulative_used_units")
        if used is not None:
            if (not isinstance(used, int) or isinstance(used, bool) or used < 0):
                issue(line, dialog, "invalid_units", "cumulative units must be >= 0")
            elif session["last_units"] is not None and used < session["last_units"]:
                issue(line, dialog, "usage_regression",
                      "%s < %s" % (used, session["last_units"]))
            else:
                session["last_units"] = used

        if evt.get("result") == "timeout":
            issue(line, dialog, "ambiguous_timeout",
                  "timeout does not prove that the remote charging system rejected the request")

    for dialog, session in sessions.items():
        if session["started"] and not session["stopped"] and now - session["last_at"] >= stale_after:
            issue(None, dialog, "stale_open_session",
                  "no stop observed within configured inactivity window")

    counts = {}
    for item in anomalies:
        counts[item["type"]] = counts.get(item["type"], 0) + 1
    return {"sessions": len(sessions), "anomaly_count": len(anomalies),
            "anomaly_counts": counts, "anomalies": anomalies}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("events", help="JSONL export file")
    p.add_argument("--now", type=float, required=True,
                   help="reference epoch seconds; explicit for repeatable audits")
    p.add_argument("--stale-after", type=float, default=1800.0)
    args = p.parse_args(argv)
    if args.stale_after < 0:
        p.error("--stale-after must be >= 0")
    records = []
    with open(args.events, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            if not raw.strip():
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                print("invalid JSON on line %d: %s" % (number, exc), file=sys.stderr)
                return 2
    result = audit(records, args.now, args.stale_after)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["anomaly_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
