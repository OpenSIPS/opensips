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
