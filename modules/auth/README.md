---
title: "Auth Module"
description: "This is a module that provides common functions that are needed by other authentication related modules. Also, it can perform authentication taking username and password from pseudo-variables."
---

## Admin Guide


### Overview


This is a module that provides common functions that are needed by
		other authentication related modules. Also, it can perform 
		authentication taking username and password from pseudo-variables.


#### RFC 8760 Support (Strenghtened Authentication)


Starting with OpenSIPS 3.2, the [auth](../auth),
			[auth_db](../auth_db) and
			[uac_auth](../uac_auth)
			modules include support for two new digest authentication algorithms
			("SHA-256" and "SHA-512-256"), according to the
	        [RFC 8760](https://datatracker.ietf.org/doc/html/rfc8760)
	        specs.


### Nonce Security


The authentication mechanism offers protection against sniffing intrusion.
        The module generates and verifies the nonces so that they can be used only
        once (in an auth response). This is done
        by having a lifetime value and an index associated with every nonce.
        Using only an expiration value is not good enough because,as this value
        has to be of few tens of seconds, it is possible for someone to sniff
        on the network, get the credentials and then reuse them in another packet
        with which to register a different contact or make calls using the others's
        account. The index ensures that this will never be possible since it
		is generated as unique through the lifetime of the nonce.


The default limit for the requests that can be authenticated is 100000 
		in 30 seconds.
		If you wish to adjust this you can decrease the lifetime of a nonce(
		how much time to wait for a reply to a challenge). However, be aware not to
		set it to a too smaller value.


However this mechanism does not work for architectures using a cluster
		of servers that share the same dns name for load balancing. In this case
		you can disable the nonce reusability check by setting the module parameter
		'disable_nonce_check'.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words 
			the listed modules must be loaded before this module):


- *signaling* -- Signaling module


#### External Libraries or Applications


The following libraries or applications must be installed 
			before running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### secret (string)


Secret phrase used to calculate the nonce value.
		Must be exactly 32-character long.


The default is to use a random value generated from the random source in the core.


If you use multiple servers in your installation, and would like to authenticate
		on the second server against the nonce generated at the first one its necessary
		to explicitly set the secret to the same value on all servers. 
		However, the use of a shared (and fixed) secret as nonce is insecure, much better
		is to stay with the default. Any clients should send the reply to the server that
		issued the request.


```c title="secret parameter example"
modparam("auth", "secret", "johndoessecretphrase")
```


#### nonce_expire (integer)


Nonces have limited lifetime. After a given period of time nonces 
		will be considered invalid. This is to protect replay attacks. 
		Credentials containing a stale nonce will be not authorized, but the 
		user agent will be challenged again. This time the challenge will 
		contain `stale` parameter which will indicate to the
		client that it doesn't have to disturb user by asking for username 
		and password, it can recalculate credentials using existing username 
		and password.


The value is in seconds and default value is 30 seconds.


```c title="nonce_expire parameter example"
modparam("auth", "nonce_expire", 15)   # Set nonce_expire to 15s
```


#### rpid_prefix (string)


Prefix to be added to Remote-Party-ID header field just before 
		the URI returned from either radius or database.


Default value is "".


```c title="rpid_prefix parameter example"
modparam("auth", "rpid_prefix", "Whatever <")
```


#### rpid_suffix (string)


Suffix to be added to Remote-Party-ID header field after the URI 
		returned from either radius or database.


Default value is 
			";party=calling;id-type=subscriber;screen=yes".


```c title="rpid_suffix parameter example"
modparam("auth", "rpid_suffix", "@1.2.3.4>")
```


#### realm_prefix (string)


Prefix to be automatically strip from realm. As an alternative to
			SRV records (not all SIP clients support SRV lookup), a subdomain
			of the master domain can be defined for SIP purposes (like 
			sip.mydomain.net pointing to same IP address as the SRV
			record for mydomain.net). By ignoring the realm_prefix 
			"sip.", at authentication, sip.mydomain.net will be
			equivalent to mydomain.net .


Default value is empty string.


```c title="realm_prefix parameter example"
modparam("auth", "realm_prefix", "sip.")
```


#### rpid_avp (string)


Full AVP specification for the AVP which 
			stores the RPID value. It used to transport the RPID value from
			authentication backend modules (auth_db or auth_radius) or from
			script to the auth function append_rpid_hf and is_rpid_user_e164.


If defined to NULL string, all RPID functions will fail at 
			runtime.


Default value is "$avp(rpid)".


```c title="rpid_avp parameter example"
modparam("auth", "rpid_avp", "$avp(caller_rpid)")
		
```


#### username_spec (string)


This name of the pseudo-variable that will hold the username.


Default value is "NULL".


```c title="username_spec parameter usage"
modparam("auth", "username_spec", "$var(username)")
```


#### password_spec (string)


This name of the pseudo-variable that will hold the password.


Default value is "NULL".


```c title="password_spec parameter usage"
modparam("auth", "password_spec", "$var(password)")
```


#### calculate_ha1 (integer)


This parameter tells the server whether it should expect plaintext
		passwords in the pseudo-variable or a pre-calculated HA1 string.


If the parameter is set to 1 then the server will assume that the
		"password_spec" pseudo-variable contains plaintext passwords
		and it will calculate HA1 strings on the fly. If the parameter is set to 0
		then the server assumes the pseudo-variable contains the HA1 strings directly
		and will not calculate them.


Default value of this parameter is 0.


```c title="calculate_ha1 parameter usage"
modparam("auth", "calculate_ha1", 1)
```


#### disable_nonce_check (int)


By setting this parameter you disable the security mechanism 
		that protects against intrusion sniffing and does not allow
		nonces to be reused. But, because of the current implementation,
		having this enabled breaks auth for an architecture where load
		is balanced by having more servers with the same dns name.
		This parameter has to be set in this case.


Default value is "0" (enabled).


```c title="disable_nonce_check parameter usage"
modparam("auth", "disable_nonce_check", 1)
```


### Exported Functions


#### www_challenge(realm[, qop[, algorithms]])


The function challenges a user agent. It will generate one or
		more WWW-Authorize header fields containing a digest challenges, it will
		put the header field(s) into a response generated from the request the
		server is processing and will send the reply. Upon reception of such a
		reply the user agent should compute credentials and retry the
		request. For more information regarding digest authentication 
		see RFC2617, RFC3261 and RFC8760.


Meaning of the parameters is as follows:


- *realm* (string) - Realm is an opaque string that 
			the user agent should present to the user so it can decide what 
			username and password to use. Usually this is domain of the host 
			the server is running on.
If an empty string "" is used then the server will 
			generate it from the request. In case of REGISTER request's To 
			header field, domain will be used (because this header field 
			represents a user being registered), for all other messages From 
			header field domain will be used.
- *qop* (string, optional) - Value of this
			parameter can be either "auth", "auth-int"
			or both (separated by *,*). When this parameter is
			set the server will put a qop parameter in the challenge. It
			is recommended to use the qop parameter, however there are still some
			user agents that cannot handle qop properly so we made this optional.
			On the other hand there are still some user agents that cannot handle
			request without a qop parameter too.
Enabling this parameter does not improve security at the moment,
			because the sequence number is not stored and therefore could not be
			checked. Actually there is no information kept by the module during
			the challenge and response requests.
- *algorithms* (string, optional) - Value of this
			parameter is a comma-separated list of digest algorithms to be offered for
			the UAC to use for authentication. Possible values are:

  - MD5
  - MD5-sess
  - SHA-256
  - SHA-256-sess
  - SHA-512-256
  - SHA-512-256-sess
When the value is empty or not set, the only offered digest
			algorithm is *MD5*, to provide compatibility
			with pre-RFC8760 UAC implementations.
Values can be listed in any order. The actual order of individual
			challenges in SIP response is defined by the RFC8760: from stronger
			algorithm to a weaker one.


This function can be used from REQUEST_ROUTE.


```c title="www_challenge usage"
...
if (!www_authorize("siphub.net", "subscriber")) {
	www_challenge("siphub.net", "auth,auth-int", "MD5,SHA-512-256");
}
...
```


#### proxy_challenge(realm[, qop[, algorithms]])


The function challenges a user agent. It will generate a 
		Proxy-Authorize header field containing a digest challenge, it will 
		put the header field into a response generated from the request the 
		server is processing and will send the reply. Upon reception of such a 
		reply the user agent should compute credentials and retry the request.
		For more information regarding digest authentication see RFC2617,
		RFC3261 and RFC8760.


See the paragraph on [www challenge params](#www_challenge_params) for
		    the description of the parameters.


This function can be used from REQUEST_ROUTE.


```c title="proxy_challenge usage"
...
$var(secure_algorithms) = "sha-256,sha-512-256";
...
if (!proxy_authorize("", "subscriber")) {
...
	proxy_challenge("", "auth", $var(secure_algorithms));  # Realm will be autogenerated
							       # MD5 won't be allowed
}
...
```


#### consume_credentials()


This function removes previously authorized credentials from the 
		message being processed by the server. That means that the downstream 
		message will not contain credentials there were used by this server. 
		This ensures that the proxy will not reveal information about 
		credentials used to downstream elements and also the message will be 
		a little bit shorter. The function must be called after 
		`www_authorize` or 
		`proxy_authorize`.


This function can be used from REQUEST_ROUTE.


```c title="consume_credentials example"
...
if (www_authorize("", "subscriber")) {
    consume_credentials();
}
...
```


#### is_rpid_user_e164()


The function checks if the SIP URI received from the database or 
		radius server and will potentially be used in Remote-Party-ID header 
		field contains an E164 number (+followed by up to 15 decimal digits) 
		in its user part.  Check fails, if no such SIP URI exists 
		(i.e. radius server or database didn't provide this information).


This function can be used from REQUEST_ROUTE.


```c title="is_rpid_user_e164 usage"
...
if (is_rpid_user_e164()) {
    # do something here
}
...
```


#### append_rpid_hf()


Appends to the message a Remote-Party-ID header that contains header
		'Remote-Party-ID: ' followed by the saved value of the SIP URI 
		received from the database or radius server followed by the value of 
		module parameter radius_rpid_suffix.  The function does nothing if 
		no saved SIP URI exists.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE.


```c title="append_rpid_hf usage"
...
append_rpid_hf();  # Append Remote-Party-ID header field
...
```


#### append_rpid_hf(prefix, suffix)


This function is the same as 
		[append rpid hf no params](#func_append_rpid_hf). The only difference is
		that it accepts two parameters--prefix and suffix to be added to 
		Remote-Party-ID header field. This function ignores rpid_prefix and 
		rpid_suffix parameters, instead of that allows to set them in every 
		call.


Meaning of the parameters is as follows:


- *prefix* (string) - Prefix of the 
			Remote-Party-ID URI. The string will be added at the beginning of 
			body of the header field, just before the URI.
- *suffix* (string) - Suffix of the Remote-Party-ID 
			header field. The string will be appended at the end of the 
			header field. It can be used to set various URI parameters, 
			for example.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE.


```c title="append_rpid_hf(prefix, suffix) usage"
...
# Append Remote-Party-ID header field
append_rpid_hf("", ";party=calling;id-type=subscriber;screen=yes");
...
```


#### pv_www_authorize(realm)


The function verifies credentials according to 
		[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If the 
		credentials are verified successfully then the function will succeed 
		and mark the credentials as authorized (marked credentials can be later 
		used by some other functions). If the function was unable to verify the 
		credentials for some reason then it will fail and the script should 
		call `www_challenge` which will 
		challenge the user again.


Negative codes may be interpreted as follows:


- *-5 (generic error)* - some generic error
			occurred and no reply was sent out;
- *-4 (no credentials)* - credentials were not
			found in request;
- *-3 (stale nonce)* - stale nonce;
- *-2 (invalid password)* - valid user, but 
			wrong password;
- *-1 (invalid user)* - authentication user does
			not exist.


Meaning of the parameters is as follows:


- *realm* (string) - Realm is an opaque string that 
			the user agent should present to the user so he can decide what 
			username and password to use. Usually this is domain of the host 
			the server is running on.
If an empty string "" is used then the server will 
			generate it from the request. In case of REGISTER requests To 
			header field domain will be used (because this header field 
			represents a user being registered), for all other messages From 
			header field domain will be used.


This function can be used from REQUEST_ROUTE.


```c title="pv_www_authorize usage"
...
$var(username)="abc";
$var(password)="xyz";
if (!pv_www_authorize("opensips.org")) {
	www_challenge("opensips.org", "auth");
}
...
```


#### pv_proxy_authorize(realm)


The function verifies credentials according to 
		[RFC2617](http://www.ietf.org/rfc/rfc2617.txt). If 
		the credentials are verified successfully then the function will 
		succeed and mark the credentials as authorized (marked credentials can 
		be later used by some other functions). If the function was unable to 
		verify the credentials for some reason then it will fail and
		the script should call 
		`proxy_challenge` which will
		challenge the user again. For more about the negative return codes,
		see the above function.


Meaning of the parameters is as follows:


- *realm* (string) - Realm is an opaque string that 
			the user agent should present to the user so he can decide what 
			username and password to use. Usually this is domain of the host 
			the server is running on.
If an empty string "" is used then the server will 
			generate it from the request. From header field domain will be 
			used as realm.


This function can be used from REQUEST_ROUTE.


```c title="pv_proxy_authorize usage"
...
$var(username)="abc";
$var(password)="xyz";
if (!pv_proxy_authorize("")) {
	proxy_challenge("", "auth");  # Realm will be autogenerated
}
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
