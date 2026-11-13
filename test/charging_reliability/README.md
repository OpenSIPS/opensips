# Charging reliability audit (offline diagnostic)

This is a **standalone diagnostic utility**, not a Diameter implementation,
charging transaction manager, or exactly-once delivery guarantee. It analyzes
a JSON Lines event export to flag charging anomalies that are difficult to
spot in aggregate counters. It does not alter OpenSIPS runtime behavior.

## Input contract

Each line represents a recorded charging action (e.g., emitted by an OpenSIPS
charging/ACC integration, a Diameter adapter or an external event consumer):

```json
{"dialog_id":"call-a","event":"start","at":100,"request_id":"r1","result":"ok"}
{"dialog_id":"call-a","event":"interim","at":110,"request_id":"r2","cumulative_used_units":10}
{"dialog_id":"call-a","event":"stop","at":120,"request_id":"r3","cumulative_used_units":20}
```

Fields: `dialog_id` (required, stable per call), `event` (required:
`start` / `interim` / `stop`), `at` (required epoch seconds),
`request_id` (optional idempotency identifier), `result` (optional;
`timeout` is treated as ambiguous), and `cumulative_used_units`
(optional non-negative integer).

Use an **event time / request ID from the charging adapter**, not a generated
identifier on every retry. Inputs should be in event order. A re-ordered
or incomplete stream may create apparent anomalies; reconcile with authoritative
charging state before acting.

## Run

```sh
python3 test/charging_reliability/audit.py charges.jsonl --now 1790000000 --stale-after 1800
cd test/charging_reliability && python3 -m unittest -v
```

Exit codes: `0` no anomalies, `1` anomalies found, `2` bad JSON/CLI
argument. Output is JSON suitable for ingestion into monitoring pipelines.

## Gaps

No automatic event extraction from OpenSIPS, no persistence, no monitoring
daemon, no recovery/replay, no cluster-wide deduplication. A future native
integration should add stable charging request IDs, terminal-state persistence,
transaction callbacks and reconciliation against the actual rating system.
