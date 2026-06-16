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
		for the [stir shaken auth](#func_stir_shaken_auth) function.


The default value is *60*.


```c title="Set auth_date_freshness parameter"
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


If the [require date hdr](#param_require_date_hdr) parameter is set to not
		required and the Date header is missing, the *iat* value
		will be used for this check instead.


This parameter is only relevant for the
		[stir shaken verify](#func_stir_shaken_verify) function.


The default value is *60*.


```c title="Set verify_date_freshness parameter"
...
modparam("stir_shaken", "verify_date_freshness", 300)
...
```


#### ca_list (string)


Path to a file containing trusted CA certificates for the verifier.
		The certificates must be in PEM format, one after another.


```c title="Set ca_list parameter"
...
modparam("stir_shaken", "ca_list", "/stir_certs/ca_list.pem")
...
```


#### ca_dir (string)


Path to a directory containing trusted CA certificates for the verifier.
		The certificates in the directory must be in hashed form, as described
		in the [openssl documentation](https://www.openssl.org/docs/manmaster/man3/X509_LOOKUP_hash_dir.html) for the
		*Hashed Directory Method*.


```c title="Set ca_dir parameter"
...
modparam("stir_shaken", "ca_dir", "/stir_certs/cas")
...
```


#### crl_list (string)


Path to a file containing certificate revocation lists (CRLs) for the verifier.


```c title="Set crl_list parameter"
...
modparam("stir_shaken", "crl_list", "/stir_certs/crl_list.pem")
...
```


#### crl_dir (string)


Path to a directory containing certificate revocation lists (CRLs) for
		the verifier. The CRLs in the directory must be in hashed form, as described
		in the [openssl documentation](https://www.openssl.org/docs/manmaster/man3/X509_LOOKUP_hash_dir.html) for the
		*Hashed Directory Method*.


```c title="Set crl_dir parameter"
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


```c title="Set e164_strict_mode parameter"
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


```c title="Set e164_max_length parameter"
...
modparam("stir_shaken", "e164_max_length", 16)
...
```


#### require_date_hdr (integer)


Specifies whether the Date header is mandatory when doing verification
	    with the [stir shaken verify](#func_stir_shaken_verify) function.


A value of *1* means required and *0*
	    not required.


If the parameter is set to "not required" but the Date header is present in the
	    message, the header value will be used as normally to check the freshness (as
	    configured in the [verify date freshness](#param_verify_date_freshness)
	    parameter). If the Date header is indeed missing, the value of the
	    *iat* claim in the PASSporT will be used instead.


The default value is *1* (required).


```c title="Set require_date_hdr parameter"
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
			
				
				*A* or *full*
				
				
				*B* or *partial*
				
				
				*C* or *gateway*
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
			
			
				*req* - the Identity header will be appended
				to the current request message;
			
			
				*rpl* - the Identity header will be appended
				to all replies that will be generated by OpenSIPS for this request.
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


```c title="stir_shaken_auth() usage"
...
stir_shaken_auth("A", "4437c7eb-8f7a-4f0e-a863-f53a0e60251a",
	$var(cert), $var(privKey), "https://certs.example.org/cert.pem");
...
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
			be used as the originating identity in the verification prcess. If missing,
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


```c title="stir_shaken_verify() usage"
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
		missing or badly formated PASSporT claims, unsupported extensions etc.


The function returns the following values:


- 1: Success
- -1: Internal error
- -2: No Identity header found
- -3: Invalid identity header
- -4: Unsupported 'ppt' or 'alg' Identity header parameter


This function can be used from REQUEST_ROUTE.


```c title="stir_shaken_check() usage"
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


```c title="stir_shaken_check_cert() usage"
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


```c title="stir_shaken_disengagement() usage"
...
if ( is_method("INVITE") && !has_totag()) {
	# equivalent to sipmsgops module: append_hf("P-Identity-Bypass: OSIP99-1234567890ABCDEF\r\n");
	stir_shaken_disengagement("OSIP99-1234567890ABCDEF");
}
...
```


### Exported Pseudo-Variables


#### $identity(field)


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


```c title="identity usage"
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


```c
...
opensips-cli -x mi stir_shaken:ca_reload
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


```c
...
opensips-cli -x mi stir_shaken:crl_reload
"OK"
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
