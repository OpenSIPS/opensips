---
title: "Auth_aka Module"
description: "This module contains functions that are used to perform digest authentication using the AKA (Authentication and Key Agreement) security protocol. This mechanism is being used in IMS networks to provide mutual authentication between the UE (device) and the 3G/4G/5G network."
---

## Admin Guide


### Overview


This module contains functions that are used to perform digest
		authentication using the AKA (Authentication and Key Agreement)
		security protocol. This mechanism is being used in IMS networks to
		provide mutual authentication between the UE (device) and the 3G/4G/5G
		network.


The AKA protocol establishes a set of security keys, called
		authentication vectors (or AVs), and uses them to generate the digest
		challenge, as well as for computing the digest result and authenticating
		the UE. AVs are exchanged over a separate communication channel.


Although the AKA protocol also requires to use the AVs to establish a
		secure channel between the UE and the network (by means of IPSec
		tunnels), this module does not handle that part - it just performs the
		authentication of the user and passes along the cyphering and
		integrity keys in the Authorization header, according to
		the *ETSI TS 129 229* specifications. These are later
		on picked up by other components (such as P-CSCFs) to establish the
		secure channel.


### Authentication Vectors


Authentication Vectors (or AVs) consist of a set of five parameter
		(RAND, AUTN, XRES, CK, IK) that are being used for mutual
		authentication. As these need to be exchanged between the device (UE)
		and network through a different channel (i.e. Diameter Cx interface in
		LTE networks), the module does not provide any means to fetch the AV
		information. It does, however, provide a generic interface (called AV
		Manage Interface) to store AVs (that are being fetched by other
		modules/channels), manage them and use them in the digest
		authentication algorithm.


Basic AV operations that the module performs:


- Ask for a new AV to be fetched for a specific user identity
- Manage an AV lifetime, including reuses
- Mark an AV as being used in a digest challeng
- Invalidate or discard an AV (due to various reasons)


A module that implements the AV Manage Interface (called AV Manager)
		should be able to fetch all five parameters of an AV, and push them in
		the AV Storage.


### Supported algorithms


The current implementation only supports the AKAv1 algorithms, with
		the associated hashing functions (such as MD5, SHA-256). In the
		challenge message, we send, one can advertise other algorithms as well,
		but the response cannot be handled by this module, and an appropriate
		error will be returned.


### Dependencies


#### OpenSIPS Modules


The module depends on the following modules (in the other words 
			the listed modules must be loaded before this module):


- *auth* -- Authentication framework
- *AV manage module*
						-- at least one module that fetches AVs and pushes
						them in the AV storage


#### External Libraries or Applications


This module does not depend on any external library.


### Exported Parameters


#### default_av_mgm (string)


The default AV Manager used in case the functions do not provide them explicitly.


```c title="default_av_mgm parameter usage"
		
modparam("auth_aka", "default_av_mgm", "diameter") # fetch AVs through the Cx interface
		
```


#### default_qop (string)


The default qop parameter used during challenge, if the functions
			do not provide them explicitly.


Default value is *auth*.


```c title="default_qop parameter usage"
		
modparam("auth_aka", "default_qop", "auth,auth-int")
		
```


#### default_algorithm (string)


The default algorithm to be advertise during challenge, if the
			functions do not provide them explicitly.
			*Note*
			that at least one of the algorithms provided should be an AKA
			one, otherwise it makes no sense to use this module.


Default value is *AKAv1-MD5*.


*WARNING:* only AKAv1* algorithms are currently supported.


```c title="default_algorithm parameter usage"
		
modparam("auth_aka", "default_algorithm", "AKAv2-MD5")
		
```


#### hash_size (integer)


The size of the hash that stores the AVs for each user.
			Must be a power of 2 number.


Default value is *4096*.


```c title="hash_size parameter usage"
		
modparam("auth_aka", "hash_size", 1024)
		
```


#### sync_timeout (integer)


The amount of milliseconds a synchronous call should
			wait for getting an authentication vector.


Must be a positive value. A value of
			*0* indicates to wait indefinitely.


Default value is *100* ms.


```c title="sync_timeout parameter usage"
		
modparam("auth_aka", "sync_timeout", 200)
		
```


#### async_timeout (integer)


The amount of milliseconds an asynchronous call should
			wait for getting an authentication vector.


Must be a positive value, greater than 0.


*NOTE:* the current timeout mechanism only
			has seconds granularity, therefore you should configure this
			parameter as a multiple of 1000.


Default value is *1000* ms.


```c title="async_timeout parameter usage"
modparam("auth_aka", "async_timeout", 2000)
		
```


#### unused_timeout (integer)


The amount of seconds an authentication vector that has
			not been used can stay in memory. Once this timeout is
			reached, the authentication vector is removed.


Must be a positive value, greater than 0.


Default value is *60* s.


```c title="unused_timeout parameter usage"
modparam("auth_aka", "unused_timeout", 120)
		
```


#### unused_timeout (integer)


The amount of seconds an authentication vector that is being
			used in the authentication process shall stay in memory.
			Once this timeout is reached, the authentication vector is
			removed, and the authentication using it will fail.


Must be a positive value, greater than 0.


Default value is *30* s.


```c title="pending_timeout parameter usage"
modparam("auth_aka", "pending_timeout", 10)
		
```


### Exported Functions


#### aka_www_authorize([realm]])


The function verifies credentials according to
		[RFC3310](http://www.ietf.org/rfc/rfc3310.txt), by using
		an authentication vector priorly allocated by an
		`aka_www_challenge()` call, using
		the *av_mgm* manager. If the credentials are
		verified successfully the function will succeed, otherwise it will fail with
		an appropriate error code, as follows:


- *-6 (sync request)* - the *auts*
			parameter was was present, thus a sync was requested;
- *-5 (generic error)* - some generic error
			occurred and no reply was sent out;
- *-4 (no credentials)* - credentials were not
			found in request;
- *-3 (unknown nonce)* - authentication vector
			with the corresponding nonce was not found;
- *-2 (invalid password)* - password does not
			match the authentication vector;
- *-1 (invalid username)* - no username found
			in the Authorize header;


In case the function succeeds, the *WWW-Authenticate*
			header is being added to the reply, containing the challenge information,
			as well as the *Integrity-Key* and the
			*Confidentiality-Key* values associated to the
			AV being used.


Meaning of the parameters is as follows:


- *realm (string)* - Realm is a opaque string that
			the user agent should present to the user so he can decide what 
			username and password to use.  This is usually
			one of the domains the proxy is responsible for.
			If an empty string "" is used then the server will 
			generate realm from host part of From header field URI.


If the credentials are verified successfully then the function will
		succeed and mark the credentials as authorized (marked credentials
		can be later used by some other functions).


This function can be used from REQUEST_ROUTE.


```c title="aka_www_authorize usage"
		
...
if (!aka_www_authorize("diameter", "siphub.com"))
	aka_www_challenge("diameter", "siphub.com", "auth");
...
```


#### aka_proxy_authorize([realm]])


The function behaves the same as [aka www authorize](#func_aka_www_authorize),
		but it authenticates the user from a proxy perspective. It receives the same
		parameters, with the same meaning, and returns the same values.


This function can be used from REQUEST_ROUTE.


```c title="aka_proxy_authorize usage"
		
...
if (!aka_proxy_authorize("siphub.com"))
	aka_proxy_challenge("diameter", "siphub.com", "auth");
...
```


#### aka_www_challenge([av_mgm[, realm[ ,qop[, alg]]]])


The function challenges a user agent. It fetches an authentication
		vector for each algorigthm used through the
		*av_mgm* Manager and generate one or more
		WWW-Authenticate header fields containing digest challenges. It will
		put the header field(s) into a response generated from the request the
		server is processing and will send the reply. Upon reception of such a
		reply the user agent should compute credentials using the used
		authentication vector annd retry the request.
		For more information regarding digest authentication 
		see RFC2617, RFC3261, RFC3310 and RFC8760.


Meaning of the parameters is as follows:


- *av_mgm* (string, optional) - the AV Manager
			to be used for this challenge, in case an AV is not already available
			for the challenged user identity. In case it is missing the value of the
			[default av mgm](#param_default_av_mgm) is being used.
*realm* (string) - Realm is an opaque string that
			the user agent should present to the user so it can decide what
			username and password to use. Usually this is domain of the host
			the server is running on. If missing, the value of the
			*From domain* is being used.
- *qop* (string, optional) - Value of this
			parameter can be either "auth", "auth-int"
			or both (separated by *,*). When this parameter is
			set the server will put a qop parameter in the challenge. It
			is recommended to use the qop parameter, however there are still some
			user agents that cannot handle qop properly so we made this optional.
			On the other hand there are still some user agents that cannot handle
			request without a qop parameter too. If missing, the value of the
			[default qop](#param_default_qop) is being used.
- *algorithms* (string, optional) - Value of this
			parameter is a comma-separated list of digest algorithms to be offered for
			the UAC to use for authentication. Possible values are:

  - AKAv1-MD5
  - AKAv1-MD5-sess
  - AKAv1-SHA-256
  - AKAv1-SHA-256-sess
  - AKAv1-SHA-512-256
  - AKAv1-SHA-512-256-sess
  - AKAv2-MD5
  - AKAv2-MD5-sess
  - AKAv2-SHA-256
  - AKAv2-SHA-256-sess
  - AKAv2-SHA-512-256
  - AKAv2-SHA-512-256-sess
When the value is empty or not set, the only offered digest
			the value of the [default algorithm](#param_default_algorithm) is being used.


Possible return codes:


- *-1* - generic parsing error, generated
			when there is not enoough data to build the challange
- *-2* - no AV vector could not be fetched
- *-3* - authentication headers could not
			be built
- *-5* - a reply could not be sent
- *positive* - the number of successful
			chalanges being sent in the reply; this value can be lower than
			the number of algorithms being requested in case there was a
			timeout waiting for some AVs.


This function can be used from REQUEST_ROUTE.


```c title="aka_www_challenge usage"
...
if (!aka_www_authorize("siphub.com")) {
	aka_www_challenge(,"siphub.com", "auth-int", "AKAv1-MD5");
}
...
```


#### aka_proxy_challenge([realm]])


The function behaves the same as [aka www challenge](#func_aka_www_challenge),
		but it challenges the user from a proxy perspective. It receives the same
		parameters, with the same meaning, the only difference being that in case of
		the *realm* is missing, then it is taken from the
		the *To domain*, rather than from
		*From domain*. The header added is
		*Proxy-Authenticate*, rather than
		*WWW-Authenticate* The rest of the parameters, behavior,
		as well as return values are the same.


This function can be used from REQUEST_ROUTE.


```c title="aka_proxy_challenge usage"
		
...
if (!aka_proxy_authorize("siphub.com"))
	aka_proxy_challenge(,"siphub.com", "auth");
...
```


#### aka_av_add(public_identity, private_identity, authenticate, authorize, confidentiality_key, integrity_key[, algorithms])


Adds an authentication vector for the user identitied by 
			*public_identity* and
			*private_identity*.


Meaning of the parameters is as follows:


- *public_identity* (string) - the public identity
			(IMPU) of the user to add authentication vector for.
- *private_identity* (string) - the private identity
			(IMPI) of the user to add authentication vector for.
- *authenticate* (string) - the concatenation of the
			authentication challenge RAND and the token AUTN, encoded in hexa format.
- *authorize* (string) - the authorization string
			(XRES) used for authorizing the user, encoded in hexa format.
- *confidentiality_key* (string) - the Confidentiality-Key
			used in the AKA IPSec process, encoded in hexa format.
- *integrity_key* (string) - the Integrity-Key
			used in the AKA IPSec process, encoded in hexa format.
- *algorithms* (string, optional) - AKA algorithms
			this AV should be used for. If missing, the AV can be used for any AKA
			algorithm.


This function can be used from any route.


```c title="aka_av_add usage"
		
...
aka_av_add("sip:test@siphub.com", "test@siphub.com",
			"KFQ/MpR3cE3V9PxucEQS5KED8uUNYIAALFyk59sIJI4=", /* authenticate */
			"00000262c0000014000028af2d6398cbe26eea69", /* authorize */
			"db7f8c4a58e17083974bba3b936d34c4", /* ck */
			"6151667b9ef815c1dcb87473685f062a"  /* ik */);
...
```


#### aka_av_drop(public_identity, private_identity, authenticate)


Drops the authentication vector corresponding to the 
			*authenticate/nonce* value
			for an user identitied by 
			*public_identity* and
			*private_identity*.


Meaning of the parameters is as follows:


- *public_identity* (string) - the public identity
			(IMPU) of the user to drop authentication vector for.
- *private_identity* (string) - the private identity
			(IMPI) of the user to drop authentication vector for.
- *authenticate* (string) - the authenticate/nonce
			that identifies the authentication vector to be dropped.


This function can be used from any route.


```c title="aka_av_drop usage"
		
...
aka_av_drop("sip:test@siphub.com", "test@siphub.com",
			"KFQ/MpR3cE3V9PxucEQS5KED8uUNYIAALFyk59sIJI4=");
...
```


#### aka_av_drop_all(public_identity, private_identity[, count])


Drops all authentication vectors for an user identitied by 
			*public_identity* and
			*private_identity*. This function is useful
			when a synchronization must be done.


Meaning of the parameters is as follows:


- *public_identity* (string) - the public identity
			(IMPU) of the user to drop authentication vectors for.
- *private_identity* (string) - the private identity
			(IMPI) of the user to drop authentication vectors for.
- *count* (variable, optional) - a variable to return the number
			of authentication vectors dropped.


This function can be used from any route.


```c title="aka_av_drop_all usage"
		
...
aka_av_drop_all("sip:test@siphub.com", "test@siphub.com", $var(count));
...
```


#### aka_av_fail(public_identity, private_identity[, count])


Marks the engine that an authentication vector query for a user has
			failed, unlocking the processing of the message.


*Note:* this function is useful when you
			know that fetching a new authentication vector is not possible
			(due to various reasons) - calling it will resume the message
			procesing, using only the available AVs fetched so far.


Meaning of the parameters is as follows:


- *public_identity* (string) - the public identity
			(IMPU) of the user to drop authentication vectors for.
- *private_identity* (string) - the private identity
			(IMPI) of the user to drop authentication vectors for.
- *count* (integer, optional) - the number of
			authentication vectors that failed. If missing,
			*1* is considered.


This function can be used from any route.


```c title="aka_av_fail usage"
...
aka_av_fail("sip:test@siphub.com", "test@siphub.com", 3);
...
```


### Exported MI Functions


#### auth_aka:av_add


Replaces obsolete MI command: *aka_av_add*.


Adds an Authentication Vector through the MI interface.


Parameters:


- *public_identity* (string) - the public identity
				(IMPU) of the user to add authentication vector for.
- *private_identity* (string) - the private identity
				(IMPI) of the user to add authentication vector for.
- *authenticate* (string) - the concatenation of the
				authentication challenge RAND and the token AUTN, encoded in hexa format.
- *authorize* (string) - the authorization string
				(XRES) used for authorizing the user, encoded in hexa format.
- *confidentiality_key* (string) - the Confidentiality-Key
				used in the AKA IPSec process, encoded in hexa format.
- *integrity_key* (string) - the Integrity-Key
				used in the AKA IPSec process, encoded in hexa format.
- *algorithms* (string, optional) - AKA algorithms
				this AV should be used for. If missing, the AV can be used for any AKA
				algorithm.


```c title="auth_aka:av_add usage"
...
## adds an AKA AV
$ opensips-cli -x mi auth_aka:av_add \
				sip:test@siphub.com
				test@siphub.com
				KFQ/MpR3cE3V9PxucEQS5KED8uUNYIAALFyk59sIJI4=
				00000262c0000014000028af2d6398cbe26eea69
				db7f8c4a58e17083974bba3b936d34c4
				6151667b9ef815c1dcb87473685f062a
...
			
```


#### auth_aka:av_drop


Replaces obsolete MI command: *aka_av_drop*.


Invalidates an Authentication Vector of an user identified
				by its authenticate value.


Parameters:


- *public_identity* (string) - the public identity
				(IMPU) of the user to add authentication vector for.
- *private_identity* (string) - the private identity
				(IMPI) of the user to add authentication vector for.
- *authenticate* (string) - the authenticate/nonce
				to indentify the authentication vector.


```c title="auth_aka:av_drop usage"
...
## adds an AKA AV
$ opensips-cli -x mi auth_aka:av_drop \
				sip:test@siphub.com
				test@siphub.com
				KFQ/MpR3cE3V9PxucEQS5KED8uUNYIAALFyk59sIJI4=
...
			
```


#### auth_aka:av_drop_all


Replaces obsolete MI command: *aka_av_drop_all*.


Invalidates all Authentication Vectors of an user through the
                MI interface.


Parameters:


- *public_identity* (string) - the public identity
				(IMPU) of the user to drop authentication vectors for.
- *private_identity* (string) - the private identity
				(IMPI) of the user to drop authentication vectors for.


```c title="auth_aka:av_drop_all usage"
...
## adds an AKA AV
$ opensips-cli -x mi auth_aka:av_drop_all \
				sip:test@siphub.com
				test@siphub.com
...
			
```


#### auth_aka:av_fail


Replaces obsolete MI command: *aka_av_fail*.


Indicates the fact that the fetching of an authentication
				vector has failed, unlocking the processing of the message.


*Note:* this function is useful when you
				know that fetching a new authentication vector is not possible
				(due to various reasons) - calling it will resume the message
				procesing, using only the available AVs fetched so far.


Parameters:


- *public_identity* (string) - the public identity
				(IMPU) of the user to add authentication vector for.
- *private_identity* (string) - the private identity
				(IMPI) of the user to add authentication vector for.
- *count* (integer, optional) - the number of
				authentication vectors failures.


```c title="aka_av_drop usage"
...
## adds an AKA AV
$ opensips-cli -x mi aka_av_drop \
				sip:test@siphub.com
				test@siphub.com
				KFQ/MpR3cE3V9PxucEQS5KED8uUNYIAALFyk59sIJI4=
...
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
