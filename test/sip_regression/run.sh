#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
command -v sipp >/dev/null || { echo "Missing SIPp executable" >&2; exit 2; }
command -v timeout >/dev/null || { echo "Missing GNU timeout" >&2; exit 2; }

# OpenSIPS is started separately using opensips.cfg. Both endpoints use UDP.
for case_name in cancel_487 late_200; do
    echo "Running SIPp regression: ${case_name}"
    timeout 30 sipp -sf "uas_${case_name}.xml" -i 127.0.0.1 -p 5072 \
        -t u1 -m 1 -l 1 -trace_err -timeout 20s >/tmp/opensips-uas-${case_name}.log 2>&1 &
    uas_pid=$!
    trap 'kill "$uas_pid" 2>/dev/null || true' EXIT
    sleep 1
    if ! timeout 30 sipp 127.0.0.1:5062 -sf "uac_${case_name}.xml" \
        -i 127.0.0.1 -p 5082 -t u1 -m 1 -l 1 -r 1 \
        -trace_err -timeout 20s; then
        cat "/tmp/opensips-uas-${case_name}.log" >&2
        exit 1
    fi
    if ! wait "$uas_pid"; then
        cat "/tmp/opensips-uas-${case_name}.log" >&2
        exit 1
    fi
    trap - EXIT
    echo "PASS: ${case_name}"
done
