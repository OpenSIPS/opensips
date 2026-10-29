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
