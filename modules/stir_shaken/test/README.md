# `stir_shaken` unit tests

The tests use the OpenSIPS TAP unit-test runner and are compiled into the
module only when `UNIT_TESTS` is enabled.

From the repository root:

```console
make -j4 modules/stir_shaken
make -j4 test module=stir_shaken
```

If `UNIT_TESTS` is not enabled yet, the first `make test` invocation updates
`Makefile.conf` and asks for the build to be run again.

The VS fixture is a static signed INVITE. The AS fixture uses a fixed `iat` and
checks the exact JWS protected-header and payload segments. ES256 signatures
are not compared as strings because ECDSA signing may use a fresh nonce; the
signature segment is instead verified cryptographically with the fixture
certificate.

DIV AS tests additionally exercise the exported signing implementation:
default stale-token rejection, trusted prior verification, preservation of the
original caller, canonical targets, fresh `iat`, STI credential requirements,
SOS targets, repeated signing, immediate base-plus-DIV signing, unordered
received headers, and broken/cyclic chain rejection. The DIV signature is
independently checked over the actual encoded header and payload. The fixture
SPC certificate and private key are public test data only.

`test_verstat.c` runs repeated and mixed set/remove calls through the real SIP
serializer and reparses the results. It covers duplicate parameters, multiple
PAI fields and identities, SIP/TEL parameter placement, display/tag preservation,
invalid arguments, removal of pending sets, discarded/foreign lumps, and atomic
failure on malformed multi-PAI input.

`test_vs.c` uses a private test trust anchor and signed SHAKEN/DIV messages to
exercise per-token trust/signatures, dependency ordering, missing links, cycles,
shared roots, per-call inner freshness, stale outermost rejection, malformed
extra headers, re-verification invalidation, and indexed result PVs. The
TNAuthList decoder is checked against individual TN, range, SPC, and malformed
DER cases.
