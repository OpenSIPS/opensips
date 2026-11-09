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
unknown/known-failure rejection, trusted prior verification, preservation of the
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
shared roots, per-call inner and outer freshness, stale outermost rejection, malformed
extra headers, re-verification invalidation, and indexed result PVs. The
TNAuthList decoder is checked against individual TN, range, SPC, and malformed
DER cases. Tri-state AS tests cover cached VS success and failure, delayed
pre-retarget verification, and explicit false overriding cached success.

Additional VS coverage exercises all six header permutations, equal timestamps,
distinct signed roots, ambiguous AS links, incomplete/unrelated branches, SOS/911
equivalence, extra invalid signatures, and a real VS freshness failure followed
by AS refusal. A test-only signer creates correctly signed negative JSON profiles
independently of the production payload builder.

`credentials.h` contains public certificate fixtures for expired/untrusted
credentials, missing or scoped TNAuthList, unsupported JWTClaimConstraints, and
P-384 keys. Valid trust paths use leaves signed by the existing test root;
the deliberately untrusted fixture is self-signed. The DIV-only TN fixture
also checks that authority is evaluated against `div`, rather than `orig`.

The `TEST_VERSTAT_POLICY` route in `opensips.cfg` is executed against real VS
results for A/B/C, bad signature, stale outermost, broken chain, and absent
Identity. Tests check its resulting `verstat` on the serialized request.

Freshness initialization tests cover the normal three-hour inner default,
automatic adjustment to retain a 60-second margin as the outer window grows,
preservation of explicit inner settings and `-1`, invalid explicit limits, and
integer overflow bounds.
