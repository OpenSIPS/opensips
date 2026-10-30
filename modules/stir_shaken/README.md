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


- *wolfssl (libwolfssl)*.


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
of outermost PASSporTs; it cannot be disabled with an inner-token override.


The default value is *60*.


```opensips title="Set verify_date_freshness parameter"
...
modparam("stir_shaken", "verify_date_freshness", 300)
...
```


#### verify_date_div_freshness (integer)

Default maximum age, in seconds, for earlier PASSporTs when verifying a DIV
chain. The default is `10800`. Use `-1` to skip inner freshness checking, or a
value greater than `verify_date_freshness` to select an extended window.
`stir_shaken_verify_chain()` accepts a final optional argument overriding this
default per call. This parameter does not affect outermost freshness or the
legacy single-PASSporT verifier.

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
ATIS-1000085.v003. An existing `shaken` PASSporT is required. The function
preserves received Identity headers and follows existing `div` links regardless
of header order. It also sees Identity headers appended by previous
`stir_shaken_auth()` and `stir_shaken_auth_div()` calls in the same request.

Before calling, the script must authorize the retargeting entity and ensure
that the received PASSporTs have been cryptographically verified. This function
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
- `previously_verified`: optional boolean, default `false`. When `false`, the
  existing outermost `iat` must satisfy `verify_date_freshness` now. `true`
  asserts trusted prior verification, including freshness before a legitimate
  call-handling delay. It skips only this age check, not structural validation
  or signing-credential checks. A freshness failure recorded by the existing
  verifier in this processing context always prevents DIV signing.

`orig` is a telephone number. `div` and `dest` accept telephone numbers or
RFC 5031 `urn:service:sos` URNs; other URI values are rejected. Leading `+` is
removed from TNs. The canonical destination must change. The generated payload
contains only `dest`, `div`, a current creation-time `iat`, and `orig`.

Return values:

- `1`: success;
- `-1`: internal, key-loading, or output error;
- `-2`: no SHAKEN root;
- `-3`: invalid argument, changed caller identity, or unchanged destination;
- `-4`: stale outermost token or recorded freshness failure;
- `-5`: expired/unsuitable certificate, missing TNAuthList, non-P-256 key,
  or certificate/key mismatch;
- `-7`: malformed, broken, cyclic, ambiguous, or excessive chain.

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

#### stir_shaken_verify_chain(err_code, err_reason, [orig], [dest], [inner_freshness])

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

`verify_date_freshness` applies to every outermost/terminal token. Earlier
tokens use `verify_date_div_freshness`, default **10800 seconds** (three hours).
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

# For a call whose local ACL permits skipping only inner freshness:
stir_shaken_verify_chain($var(code), $var(reason), , , -1);
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
if ($var(rc) < -1) {
	send_reply($var(err_sip_code), $var(err_sip_reason));
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
