---
title: "STIR/SHAKEN Module"
description: "This module adds support for implementing STIR/SHAKEN (RFC 8224, RFC 8588) Authentication and Verification services in OpenSIPS."
---

## Admin Guide


### Overview


This module adds support for implementing STIR/SHAKEN (RFC 8224, RFC 8588)
Authentication and Verification services in OpenSIPS.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *wolfssl (libwolfssl)*, or *OpenSSL (libcrypto)* when building with
  `STIR_SHAKEN_OPENSSL=1`.

Older wolfSSL releases, such as Ubuntu 20.04's packaged version, cannot handle
the custom TNAuthList OID required by this module. Use the OpenSSL backend on
these systems:

```console
make -B -j4 modules/stir_shaken STIR_SHAKEN_OPENSSL=1
```


### Exported Parameters


#### auth_date_freshness (integer)


The maximum number of seconds that the value in the Date header field
can be older than the current time.


This parameter is only relevant
for the [stir_shaken_auth()](#stir_shaken_authattest-origid-cert-pkey-x5u-orig-dest-out) function.


The default value is *60*.


```opensips title="Set auth_date_freshness parameter"
...
modparam("stir_shaken", "auth_date_freshness", 300)
...
```


#### verify_date_freshness (integer)


The maximum number of seconds that the value in the Date header field can be
older than the current time. Also, if the *iat* value in
the PASSporT is different than the Date value, but remains within the
permitted interval, it will be used in the verification process (for the
reconstructed PASSporT) instead of the Date value.


If the [require_date_hdr](#require_date_hdr-integer) parameter is set to not
required and the Date header is missing, the *iat* value
will be used for this check instead.


The Date/reconstruction behavior above applies to the legacy
[stir_shaken_verify()](#stir_shaken_verifycert-err_code-err_reason-orig-dest) function.
For `stir_shaken_verify_chain()`, this parameter controls signed `iat` freshness
of outermost PASSporTs, regardless of `ppt`: normally the SHAKEN token, with
no DIV present. When the call has been diverted and DIV tokens are present,
the last DIV is outermost instead. It cannot be disabled with an inner-token
override.


The default value is *60*.


```opensips title="Set verify_date_freshness parameter"
...
modparam("stir_shaken", "verify_date_freshness", 300)
...
```


#### verify_date_div_freshness (integer)

Maximum age, in seconds, for earlier PASSporTs in a DIV chain: the original
SHAKEN and earlier DIV tokens. The outermost token uses
[verify_date_freshness](#verify_date_freshness-integer). With only one received
token, this parameter has no effect.

When omitted, the default is `10800` (three hours), or
`verify_date_freshness + 60` if that is larger. An explicit value must exceed
`verify_date_freshness`, or be `-1` to skip inner freshness checking.

The `inner_freshness` argument to `stir_shaken_verify_chain()` overrides this
value per call. This parameter does not affect the legacy `stir_shaken_verify()`.

```opensips
modparam("stir_shaken", "verify_date_div_freshness", 10800)
```

#### ca_list (string)


Path to a file containing trusted CA certificates for the verifier.
The certificates must be in PEM format, one after another.


```opensips title="Set ca_list parameter"
...
modparam("stir_shaken", "ca_list", "/stir_certs/ca_list.pem")
...
```


#### ca_dir (string)


Path to a directory containing trusted CA certificates for the verifier.
The certificates in the directory must be in hashed form, as described
in the [openssl documentation](https://www.openssl.org/docs/manmaster/man3/X509_LOOKUP_hash_dir.html) for the
*Hashed Directory Method*.


```opensips title="Set ca_dir parameter"
...
modparam("stir_shaken", "ca_dir", "/stir_certs/cas")
...
```


#### crl_list (string)


Path to a file containing certificate revocation lists (CRLs) for the verifier.


```opensips title="Set crl_list parameter"
...
modparam("stir_shaken", "crl_list", "/stir_certs/crl_list.pem")
...
```


#### crl_dir (string)


Path to a directory containing certificate revocation lists (CRLs) for
the verifier. The CRLs in the directory must be in hashed form, as described
in the [openssl documentation](https://www.openssl.org/docs/manmaster/man3/X509_LOOKUP_hash_dir.html) for the
*Hashed Directory Method*.


```opensips title="Set crl_dir parameter"
...
modparam("stir_shaken", "crl_dir", "/stir_certs/crls")
...
```


#### e164_strict_mode (integer)


Require a leading *"+"* to be present in
the originating/destination SHAKEN identity, on top of mandating an E.164
telephone number by default.  Additionally, require the URI to be either
a *tel* URI or a *sip* /
*sips* URI with the *user=phone*
parameter.


The default value is *0* (disabled).


```opensips title="Set e164_strict_mode parameter"
...
modparam("stir_shaken", "e164_strict_mode", 1)
...
```


#### e164_max_length (integer)


This parameter allows the 15-digit number length restriction of the E.164
format to be bypassed.  Especially useful in scenarios where various
telephony number prefixes are in use, causing some numbers to exceed
the standard maximum length.


The default value is *15*.


```opensips title="Set e164_max_length parameter"
...
modparam("stir_shaken", "e164_max_length", 16)
...
```


#### require_date_hdr (integer)


Specifies whether the Date header is mandatory when doing verification
with the [stir_shaken_verify()](#stir_shaken_verifycert-err_code-err_reason-orig-dest) function.


A value of *1* means required and *0*
not required.


If the parameter is set to "not required" but the Date header is present in the
message, the header value will be used as normally to check the freshness (as
configured in the [verify_date_freshness](#verify_date_freshness-integer)
parameter). If the Date header is indeed missing, the value of the
*iat* claim in the PASSporT will be used instead.


The default value is *1* (required).


```opensips title="Set require_date_hdr parameter"
...
modparam("stir_shaken", "require_date_hdr", 0)
...
```


### Exported Functions


#### stir_shaken_auth(attest, origid, cert, pkey, x5u, [orig], [dest], [out])


This function performs the steps of an authentication service. Before
calling this function though, you must ensure:


- authority - the server is authoritative for the identity in question;
- authentication - the originator is authorized to claim the given identity.


Meaning of the parameters is as follows:


- *attest (string)* - value of the 'attest' claim
to be included in the PASSporT. The following values can be used:
				- *A* or *full*
				- *B* or *partial*
				- *C* or *gateway*
- *origid (string)* - value of the 'origid' claim
to be included in the PASSporT. Treated by the module as an opaque string.
- *cert (string)* - the X.509 certificate used to
compute the signature, in PEM format.
- *pkey (string)* - the private key used to
compute the signature, in PEM format.
- *x5u (string)* - value of the 'x5u' claim to be
included in the PASSporT. Treated by the module as an opaque string.
- *orig (string, optional)* - telephone number to
be used as the originating identity in the PASSporT. If missing, this value
will be derived from the SIP message.
- *dest (string, optional)* - telephone number to
be used as the destination identity in the PASSporT. If missing, this value
will be derived from the SIP message.
- *out (string, no expand, optional)* - name of an
output variable to store the Identity header or the following flags:
	- *req* - the Identity header will be appended
	- to the current request message;
	- *rpl* - the Identity header will be appended
	- to all replies that will be generated by OpenSIPS for this request.
If this parameter is missing, the Identity header will be appended
to the current request message.
If an output variable is provided, it should be given as a quoted string,
eg. *"$var(identity_hdr)"*.


The function returns the following values:


- 1: Success
- -1: Internal error
- -3: Failed to derive identity from SIP message because the
URI is not a telephone number
- -4: Date header value is older than local policy for freshness
- -5: The current time or Date header value does not fall within
the certificate validity


This function can be used from REQUEST_ROUTE.


```opensips title="stir_shaken_auth() usage"
...
stir_shaken_auth("A", "4437c7eb-8f7a-4f0e-a863-f53a0e60251a",
	$var(cert), $var(privKey), "https://certs.example.org/cert.pem");
...
```


#### stir_shaken_auth_div(cert, pkey, x5u, [orig], [div], [dest], [out], [previously_verified])

Append a full-form `div` PASSporT for an authorized retargeting event, following
[ATIS-1000085.v003](https://access.atis.org/higherlogic/ws/public/download/81654/ATIS-1000085.pdf).
An existing `shaken` PASSporT is required. The function
preserves received Identity headers and follows existing `div` links regardless
of header order. It also sees Identity headers appended by previous
`stir_shaken_auth()` and `stir_shaken_auth_div()` calls in the same request.

Before calling, the script must authorize the retargeting entity and provide
a trusted prior verification result or complete local VS verification. This function
performs structural chain checks; it does not fetch or verify certificates for
received PASSporTs. The signer must be entitled to fully attest the retargeting
identity under ATIS-1000085 clause 5.6.3. Presence of a Diversion or History-Info
header alone does not establish that authorization.

Parameters:

- `cert`, `pkey`, `x5u`: PEM certificate, PEM private key, and certificate URL.
  The certificate must currently be valid, contain TNAuthList, and match a
  P-256 private key. Certificate trust, TNAuthList scope, and customer/TN
  authorization remain SP policy; the function does not infer authority merely
  from the extension's presence.
- `orig`: defaults to the innermost `shaken.orig`. An explicit value must match
  that original TN after canonicalization.
- `div`: defaults to the current outermost destination. An explicit value must
  be one of its destinations. Supply this value to select from a multi-target
  outermost PASSporT.
- `dest`: defaults to the current Request-URI, including changes made by the
  routing script. Unlike base SHAKEN signing, this does not default to To.
- `out`: omit or use `req` to append to the request; alternatively pass a quoted
  writable variable, such as `"$var(identity_hdr)"`. `rpl` is not supported for
  ATIS DIV authentication. Variable output is not considered appended until
  the script actually attaches it to the message.
- `previously_verified`: optional tri-state verification result:
  Integer values are normalized as booleans: zero is `false`, any nonzero
  integer is `true`.
  - `true`: assert trusted prior success. Received PASSporTs are not reverified
    and their historical freshness is not rechecked. Structural chain and
    current signing-credential checks still apply.
  - `false`: assert known prior failure and refuse signing (`-8`). This policy
    covers all known verification failures.
  - omitted or a null-valued variable: unknown. Reuse successful local
    [`stir_shaken_verify_chain()`](#stir_shaken_verify_chainerr_code-err_reason-orig-dest-inner_freshness-outer_freshness)
    verification; otherwise return `-10` to request
    verification, or `-8` for a recorded failure. The script obtains each
    certificate and runs the VS functions before retrying. A locally generated
    SHAKEN PASSporT also permits immediate DIV signing in the same request.

A recorded outermost freshness failure in this processing context always
prevents DIV signing, including with `true`. Select any extended pre-retarget
freshness policy on the initial VS invocation, before recording a failure.

`orig` is a telephone number. `div` and `dest` accept telephone numbers or
RFC 5031 `urn:service:sos` URNs; other URI values are rejected. Leading `+` is
removed from TNs. The canonical destination must change. The generated payload
contains only `dest`, `div`, a current creation-time `iat`, and `orig`.

Return values:

- `1`: success;
- `-1`: internal, key-loading, or output error;
- `-2`: no SHAKEN root;
- `-3`: invalid argument, changed caller identity, or unchanged destination;
- `-4`: recorded outermost freshness failure;
- `-5`: expired/unsuitable certificate, missing TNAuthList, non-P-256 key,
  or certificate/key mismatch;
- `-7`: malformed, broken, cyclic, ambiguous, or excessive chain;
- `-8`: prior verification is known to have failed;
- `-10`: unknown prior result; complete local VS verification first.

This initial AS implementation accepts up to 64 PASSporTs and one SHAKEN root.
Additional PASSporT types may coexist; multiple distinct SHAKEN roots and
branching diversion chains fail rather than selecting one silently.

```opensips
# Authorize the retargeting customer and verify the received chain first.
# Apply retargeting before signing, so Request-URI identifies the new target.
if (!stir_shaken_auth_div($var(cert), $var(key),
        "https://certs.example.net/stir.pem")) {
    xlog("L_WARN", "DIV signing failed: $retcode\n");
}

# Only for a trusted record of successful verification before a call delay:
stir_shaken_auth_div($var(cert), $var(key),
    "https://certs.example.net/stir.pem", , , , , true);

# A saved nullable result: true, false, or NULL (unknown).
$var(previously_verified) = NULL;
stir_shaken_auth_div($var(cert), $var(key),
    "https://certs.example.net/stir.pem", , , , , $var(previously_verified));
```

#### stir_shaken_set_verstat(target, value)

Set the calling-number verification indication in From and/or P-Asserted-Identity.
`target` is `from`, `pai`, or `both`. `value` must be exactly one of:

- `TN-Validation-Passed`
- `TN-Validation-Failed`
- `No-TN-Validation`

This helper edits headers; the script chooses the value from its verification
result and applies the ATIS attestation policy. Values such as
`TN-Validation-Passed-A` are rejected. The helper does not perform verification
or change the AS's recorded freshness result.

All selected header fields and all comma-separated PAI identities are updated.
For SIP/SIPS URIs, the parameter is placed in the subscriber portion before
`@`; for TEL/TELS URIs it is a telephone URI parameter. Existing occurrences
are removed, including duplicates, case variants, host-side SIP parameters,
and misplaced header-level parameters. Display names, From tags, unrelated
parameters, and URI headers are preserved. Bare addresses are enclosed in
angle brackets to keep the resulting parameter placement unambiguous.

Repeated calls are supported, including mixtures of `from`, `pai`, and `both`.
For each selected header, the last successful call wins. Each header uses one
pending replacement instead of accumulating insertions or overlapping deletions.
All selected headers are prepared before any edits are committed, so a failed
`both` call does not partially update the request. Missing selected headers are
a successful no-op; the helper does not create PAI or From headers.

Overlapping edits already made by other header-editing functions are refused.
If the script subsequently removes or alters these managed lumps, a later
helper call returns an error instead of dereferencing stale pointers. These
checks do not make arbitrary text edits performed by other functions safe:
coordinate From/PAI rewriting and check helper return values. Header edits
remain pending lumps; normal parsed-header variables still show the original
message until changes are applied/reparsed.

Both helpers are available in REQUEST_ROUTE. Return values:

- `1`: success (including no matching header);
- `-1`: allocation failure;
- `-2`: malformed or unsupported selected identity/header, or missing context;
- `-3`: invalid target or value;
- `-4`: conflicting, removed, or shared-memory edits.

```opensips
# Strip untrusted indications at ingress; handle failure under local policy.
if (!stir_shaken_remove_verstat("both")) {
    send_reply(400, "Invalid calling identity");
    exit;
}

# After verification and the ATIS attestation-policy decision:
stir_shaken_set_verstat("both", "TN-Validation-Passed");

# Safe replacement: this does not append a second From verstat parameter.
stir_shaken_set_verstat("from", "No-TN-Validation");
```

#### stir_shaken_remove_verstat(target)

Remove all verstat parameters from the selected identities. Targets, return
values, atomicity and repeat-call behavior are the same as for
`stir_shaken_set_verstat()`. Removal also cancels a pending set on those headers.
A subsequent set can safely establish a new value.

#### stir_shaken_verify_passport(index, cert, err_code, err_reason)

Verify the received full-form PASSporT at the zero-based Identity-header
`index`. Headers are indexed in wire order, including malformed entries. The
script supplies that header's PEM certificate/chain, typically fetched using
`$(identity(x5u)[$var(i)])`. No HTTP client is required by this module.

This function validates the `shaken`/`div` claim profile, P-256 ES256 signature
over the exact received encoded `A.B`, certificate validity at signing and
verification time, the configured trust/CRL policy, and TNAuthList authority.
Identity-header `ppt`/`alg`/`info` parameters must agree with the protected
header. For `shaken`, authority applies to `orig`; for `div`, it applies to
`div`. Individual-TN and range restrictions are enforced, including TNAuthList
constraints in the validated certificate path. Trusted SPC certificates use
SHAKEN's provider-attestation model; SPC-to-TN registry lookup is not performed.
Configure the STI trust anchors with the existing `ca_list`/`ca_dir` parameters.

The result is saved per token. A subsequent failed verification replaces an
earlier success. This stage does not decide freshness, chain completeness, or
the relationship to SIP call identities: use `stir_shaken_verify_chain()` after
checking every received token. `status=verified` alone is not call validation.

Unsupported PASSporT types, including `rph`, `rcd`, and `div-o`, fail explicitly;
their type-specific validation is not implemented here. Certificates with
JWTClaimConstraints are rejected until that profile is supported. They are not
silently accepted under weaker checks.

```opensips title="stir_shaken_verify_passport() usage"
# $var(cert) contains the PEM certificate/chain for the first Identity header.
$var(rc) = stir_shaken_verify_passport(
    0, $var(cert), $var(err_code), $var(err_reason));
if ($var(rc) < 0) {
    xlog("L_WARN", "PASSporT verification failed: rc=$var(rc), "
        "code=$var(err_code), reason=$var(err_reason)\n");
}
```

#### stir_shaken_verify_chain(err_code, err_reason, [orig], [dest], [inner_freshness], [outer_freshness])

Validate the dependency graph using only tokens which passed
`stir_shaken_verify_passport()`. Call this after verifying every indexed token.
No request headers are reordered or removed.

- Each `div` requires at least one predecessor with a matching `dest`.
- The graph must be acyclic and ultimately rooted in SHAKEN PASSporTs.
- Every token must preserve the calling TN, matched against P-Asserted-Identity
  or From (or an explicit `orig` override).
- Each terminal PASSporT must name the current Request-URI (or explicit `dest`
  override). Without any DIV tokens, the base destination is taken from To.
- Shared diversion links and multiple complete chains are supported. An
  unrelated/malformed token or a branch ending at a different recipient fails
  the complete request instead of being silently omitted.
- During linking, `911` and RFC 5031 `sos` URNs are equivalent. Header position
  and `iat` are never used to infer diversion order.

The signed claims are matched as follows. Per-token verification checks the
signature, certificate authority, and claim profile first; the chain verifier
then checks these relationships to the call and the other tokens:

| PASSporT / claim | Expected identity or value |
| --- | --- |
| `shaken.orig` | Calling TN from the first P-Asserted-Identity identity, or From when PAI is absent. |
| `shaken.dest`, with DIV tokens present | At least one destination must link to a following token's `div`; it is not compared to To. A terminal SHAKEN token must instead name the current recipient. |
| `shaken.dest`, without DIV tokens | Each SHAKEN token must contain the called TN from To, or its SOS service URN. Request-URI is not used for this base-only case. |
| `div.orig` | The same calling TN as the SHAKEN root and the selected SIP calling identity. |
| `div.div` | A destination in at least one preceding signed PASSporT. Diversion, History-Info, and Referred-By are not used to establish this link. |
| Intermediate `div.dest` | A destination linking to a following token's `div`. |
| Terminal `div.dest` | At least one destination must match the current Request-URI identity, including a script-rewritten `$ru`. Every terminal token is checked. |
| `iat`, either type | Current clock and the selected outer/inner freshness policy; no comparison to the SIP Date header. |
| `shaken.attest` / `shaken.origid` | Signed profile checks: A/B/C attestation and a nonempty string origid. There is no corresponding SIP-header comparison. These claims are rejected on DIV tokens. |

Calling and base-only To identities use the URI user/telephone number after
removing user parameters. SIP/SIPS and TEL/TELS are accepted; the existing
`e164_strict_mode` requirement for `user=phone` applies to SIP/SIPS callers and
base-only To identities. A present but invalid PAI fails rather than falling
back to From. For DIV-chain recipients, the verifier extracts the number from
Request-URI or accepts a supported SOS URN directly. TNs are compared after
removing a leading `+`; `911` and supported SOS URNs are equivalent for chain
links and recipient matching.

The optional `orig` and `dest` arguments replace the expected calling and
recipient identities for this invocation. Supply a TN for `orig`, and a TN or
supported SOS URN for `dest`, rather than a complete SIP URI. An `orig` override
still has to match every token's original caller. A `dest` override replaces
To in a base-only request or Request-URI in a request containing DIV tokens.
Neither override changes signed claims, bypasses signatures/certificate
authority, nor relaxes chain dependencies or freshness checks.

Verify before locally retargeting the call. If Request-URI has already been
rewritten, pass the saved pre-retarget recipient as `dest` when verifying the
received DIV chain:

```opensips
# $var(received_target) was saved before rewriting Request-URI.
# Verify each received token first, then compare its chain to that recipient.
stir_shaken_verify_chain($var(code), $var(reason), , $var(received_target));
```

The `chain_attest` result is available only after successful chain verification.
When multiple SHAKEN roots are present, it reports the weakest attestation
among them (C before B before A), rather than selecting one by header order.

`outer_freshness` overrides `verify_date_freshness` for every outermost/terminal
token on this invocation. It must be nonnegative; `-1` is rejected. When
verifying an unknown result before a delayed retargeting, the script may
explicitly select `10800` seconds (three hours). Ordinary inbound verification
continues to use `verify_date_freshness` when the argument is omitted. Earlier
tokens use `verify_date_div_freshness`, normally **10800 seconds** (three hours).
If that parameter is omitted, its startup default increases when necessary to
exceed `verify_date_freshness`, as described above.
The optional `inner_freshness` argument overrides that value for this call:

- `-1`: skip age checks for earlier tokens;
- a value greater than `verify_date_freshness`: use that extended window;
- omitted: use the module default.

Neither `-1` nor any other inner override disables outermost freshness,
signature, certificate, or dependency checks. An outermost freshness failure
is retained in the processing context and blocks subsequent DIV signing even
with `previously_verified=true`. Inner freshness failure is reported separately.
These APIs use signed `iat` values; they do not reconstruct tokens from Date.

Both verification functions return `1` on success and a negative value on
failure, setting `err_code`/`err_reason` to the corresponding SIP error. On
success the outputs are reset to `0` and an empty string. Error values are:

- `-1`: internal error;
- `-2`: missing token, invalid index, or unavailable Identity collection;
- `-3`: invalid argument or SIP identity;
- `-4`: malformed PASSporT/profile;
- `-5`: unsupported PASSporT type;
- `-6`: stale outermost token;
- `-7`: broken/cyclic chain or final-target mismatch;
- `-8`: invalid, expired, untrusted, or unauthorized credential;
- `-9`: bad signature or changed calling identity;
- `-10`: a token has not been individually verified;
- `-11`: stale earlier token under the selected inner policy.

The collection is limited to 64 Identity fields. Results are scoped to the
current received message; changed/reparsed Identity fields invalidate cached
results. Pending Identity insertions made by unrelated text-editing functions
are not part of the received collection. Complete verification does not set
`verstat` automatically; the script applies attestation and call policy.

```opensips
modparam("stir_shaken", "verify_date_div_freshness", 10800)

# Within the request route, fetch/cache each token's certificate separately.
$var(i) = 0;
while ($var(i) < $identity(count)) {
    # Populate $var(cert) with the PEM chain for this token's signed x5u.
    # URL: $(identity(x5u)[$var(i)])
    stir_shaken_verify_passport($var(i), $var(cert), $var(code), $var(reason));
    $var(i) = $var(i) + 1;
}

if (!stir_shaken_verify_chain($var(code), $var(reason))) {
    xlog("L_WARN", "Chain validation: $identity(chain_status), $var(reason)\n");
}
```

For a call whose local ACL permits skipping only inner freshness, use this
chain-verification invocation instead:

```opensips
stir_shaken_verify_chain($var(code), $var(reason), , , -1);
```

For delayed retargeting with unknown prior verification, choose the extended
outer window on the initial chain-verification invocation, after verifying
each token and before changing Request-URI. A previously recorded outermost
freshness failure still blocks AS, even if a later relaxed check succeeds.

```opensips
if (stir_shaken_verify_chain($var(code), $var(reason), , , , 10800)) {
    $ru = "sip:+12155551217@example.net";
    stir_shaken_auth_div($var(sti_cert), $var(sti_pkey),
        "https://certs.example.net/stir.pem");
}
```

#### stir_shaken_verify(cert, err_code, err_reason, [orig], [dest])


This function performs the steps of an verification service.


Meaning of the parameters is as follows:


- *cert (string)* - the X.509 certificate used to
verify the signature, in PEM format.
- *err_code (var)* - output variable that will
store the SIP response code associated with an eventual error of the
verification process.
- *err_reason (var)* - output variable that will
store the SIP response reason phrase associated with an eventual error of the
verification process.
- *orig (string, optional)* - telephone number to
be used as the originating identity in the verification process. If missing,
this value will be derived from the SIP message.
- *dest (string, optional)* - telephone number to
be used as the destination identity in the verification process. If missing,
this value will be derived from the SIP message.


The function returns the following values:


- 1: Success
- -1: Internal error
- -2: No Identity or Date header found
- -3: Failed to derive identity from SIP message because the
URI is not a telephone number
- -4: Invalid identity header
- -5: Unsupported 'ppt' or 'alg' Identity header parameter
- -6: Date header value is older than local policy for freshness
- -7: The Date header value does not fall within the certificate validity
- -8: Invalid certificate
- -9: Signature does not verify successfully


This function can be used from REQUEST_ROUTE.


```opensips title="stir_shaken_verify() usage"
...
$var(rc) = stir_shaken_verify($var(cert), $var(err_code), $var(err_reason));
if ($var(rc) < 0) {
	send_reply($var(err_code), $var(err_reason));
	exit;
}
...
```


#### stir_shaken_check()


This function checks the Identity header in order to validate the
STIR/SHAKEN information in terms of format. It detects issues such as:
missing or badly formatted PASSporT claims, unsupported extensions etc.


The function returns the following values:


- 1: Success
- -1: Internal error
- -2: No Identity header found
- -3: Invalid identity header
- -4: Unsupported 'ppt' or 'alg' Identity header parameter


This function can be used from REQUEST_ROUTE.


```opensips title="stir_shaken_check() usage"
...
if (stir_shaken_check()) {
	xlog("forwarding call to stir/shaken verification service\n");
	...
}
...
```


#### stir_shaken_check_cert()


This function checks if the current time falls within the given
certificate's validity period.


The function returns the following values:


- 1: Success
- -1: Internal error
- -2: Certificate is not valid


This function can be used from REQUEST_ROUTE.


```opensips title="stir_shaken_check_cert() usage"
...
# update expired cached certificates
cache_fetch("local", $identity(x5u), $var(cert));
if (!stir_shaken_check_cert($var(cert))) {
	rest_get($identity(x5u), $var(cert));
	cache_store("local", $identity(x5u), $var(cert));
}
...
```


#### stir_shaken_disengagement(token)


This function add P-Identity-Bypass header with token value at the end of SIP headers.


Meaning of the parameters is as follows:


- *token (string)* - The token provided by the authority during outage.


The function returns the following values:


- 1: Success
- 0: Failed to add P-Identity-Bypass header


This function can be used from REQUEST_ROUTE.


```opensips title="stir_shaken_disengagement() usage"
...
if ( is_method("INVITE") && !has_totag()) {
	# equivalent to sipmsgops module: append_hf("P-Identity-Bypass: OSIP99-1234567890ABCDEF\r\n");
	stir_shaken_disengagement("OSIP99-1234567890ABCDEF");
}
...
```


### Exported Pseudo-Variables


#### $identity(field)

Without an index, select the first usable SHAKEN PASSporT regardless of header
position. Use the extended PV syntax to inspect a particular received header:

```opensips
$identity(count)                       # number of received Identity fields
$(identity(ppt)[$var(i)])
$(identity(x5u)[$var(i)])
$(identity(status)[$var(i)])
$(identity(div)[$var(i)])
$(identity(dest_type)[$var(i)])          # tn or uri
$identity(chain_status)
$identity(chain_attest)
```

Additional indexed fields are `ppt`, `status`, `raw` (the complete Identity
body), `div`, `orig_type`, `dest_type`, and `div_type`. Existing fields also
support indexing; `dest` returns the first destination TN or SOS URI. A
malformed header remains in the count, with `raw` and `status` available.
Unsupported types are exposed for diagnostics but cannot pass full verification.
Negative and `[*]` indices are not supported.

Per-token `status` is `unverified`, `verified`, `malformed`, `unsupported`, or
`failed`. Whole-call `chain_status` is `unverified`, `passed`, `failed`,
`no-validation`, `broken`, `unsupported`, `stale`, or `inner-stale`.
`chain_attest` is available only after successful chain validation; it reports
the weakest attestation if multiple SHAKEN roots are present. It is separate
from `verstat` and must be considered when deciding which indication to deliver.


This is a read-only pseudo-variable that provides access to the
parsed information from the Identity header, through the following
subnames:


- *header* - the entire PASSporT header;
- *x5u* - the value of the 'x5u' PASSporT claim;
- *payload* - the entire PASSporT payload;
- *attest* - the value of the 'attest' PASSporT claim;
- *dest* - the value of the 'tn' member of the 'dest'
PASSporT claim;
- *iat* - the value of the 'iat' PASSporT claim;
- *orig* - the value of the 'tn' member of the 'orig'
PASSporT claim;
- *origid* - the value of the 'origid' PASSporT claim;


```opensips title="identity usage"
...
	# acquire the certificate to use for the verification process
	$var(rc) = rest_get($identity(x5u), $var(cert));
	if ($var(rc) < 0) {
		send_reply(436, "Bad Identity Info");
		exit;
	}
	...
	xlog("Verified caller:$identity(orig), attestation level: $identity(attest)\n");
...
	
```


### Exported MI Functions


#### stir_shaken:ca_reload


Replaces obsolete MI command: *stir_shaken_ca_reload*.


Reload the file containing trusted CA certificates for the verifier
and the directory containing trusted CA certificates for the verifier.
At least one of *ca_list* or *ca_dir* must be set.


The whole verification store is rebuilt from the current files - trusted CAs,
system-wide CAs and CRLs - so the CRLs remain in use. The new files are
first checked in the MI process; if they fail to load, an error is returned and
nothing changes. Otherwise, every process rebuilds its own store before its
next certificate verification.


Name: *stir_shaken:ca_reload*


Parameters: *none*


MI FIFO Command Format:


```bash
...
$ opensips-cli -x mi stir_shaken:ca_reload
"OK"
...
```


#### stir_shaken:crl_reload


Replaces obsolete MI command: *stir_shaken_crl_reload*.


Reload the file containing certificate revocation lists (CRLs) for the verifier
and the directory containing certificate revocation lists for the verifier.
At least one of *crl_list* or *crl_dir* must be set.


Same as *stir_shaken:ca_reload*, the whole verification store is rebuilt, so
the trusted CAs remain in use, and the change reaches every process.


Name: *stir_shaken:crl_reload*


Parameters: *none*


MI FIFO Command Format:


```bash
...
$ opensips-cli -x mi stir_shaken:crl_reload
"OK"
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
