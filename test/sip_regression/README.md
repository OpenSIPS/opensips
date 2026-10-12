# OpenSIPS SIP transaction regression scenarios

Minimal, local, SIPp-driven integration tests for transaction correctness
under CANCEL and late-200 OK races. These are reproducible **scenario
fixtures**, not a complete CI integration or an assertion of passing behavior.

## Prerequisites

Build OpenSIPS with `proto_udp`, `tm`, and `sl`; install SIPp and GNU
`timeout`. No external calls or media endpoints are used. The script binds
`127.0.0.1:5062` (proxy), `5072` (UAS), `5082` (UAC).

In one terminal, run an OpenSIPS instance with
`test/sip_regression/opensips.cfg` (ensure the module search path matches
your local build). In another terminal:

```sh
bash test/sip_regression/run.sh
```

Two scenarios are executed:

1. `cancel_487`: INVITE, 180, CANCEL, 200 (CANCEL), 487 (INVITE),
   ACK for the non-2xx final.
2. `late_200`: the UAS sends a 200 INVITE after accepting CANCEL.
   The UAC must still ACK that 2xx, terminate with BYE and receive
   200 for BYE.

SIPp exits nonzero for message mismatches and timeouts. The harness retains
UAS output in `/tmp/opensips-uas-*.log`. These tests should be run against
a dedicated OpenSIPS process; do not run on a production listener.

## Extension plan

- Run scenarios in a containerized CI job building OpenSIPS and SIPp.
- Assert precise response CSeq and retransmission handling.
- Add forking and multi-branch CANCEL, SIP timer edge conditions,
  Registration expiry, TLS reconnect, and failure injection.
- Include packet captures and OpenSIPS logs as CI artifacts.

**Not executed here:** no OpenSIPS or SIPp binaries were available in the
execution environment.
