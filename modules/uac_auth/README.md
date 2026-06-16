---
title: "UAC AUTH Module"
description: "UAC AUTH (User Agent Client Authentication) module provides a common API for building authentication headers."
---

## Admin Guide


### Overview


UAC AUTH (User Agent Client Authentication) module provides a
		common API for building authentication headers.


It also provides a common set of authentication credetials to
		be used by other modules.


Note that authentication provided by this module supports both
		qop "auth" and qop "auth-int" but if both values are presented
		by the server, "auth" will be prefered.


#### RFC 8760 Support (Strenghtened Authentication)


Starting with OpenSIPS 3.2, the [auth](../auth),
			[auth_db](../auth_db) and
			[uac_auth](../uac_auth)
			modules include support for two new digest authentication algorithms
			("SHA-256" and "SHA-512-256"), according to the
	        [RFC 8760](https://datatracker.ietf.org/doc/html/rfc8760)
	        specs.


### Dependencies


#### OpenSIPS Modules


- *None.*


#### External Libraries or Applications


The following libraries or applications must be installed 
				before running OpenSIPS with this module loaded:


- *None*


### Exported Parameters


#### credential (string)


Contains a multiple definition of credentials used to perform
			authentication.


NOTE that the password can be provided as a plain text password or
			as a precalculated HA1 as a hexa (lower case) string
			(of 32 chars) prefixed with "0x" (so a total of 34 chars).


*This parameter is required if UAC authentication is used.*


```c title="Set credential parameter"
...
modparam("uac_auth","credential","username:domain:password")
modparam("uac_auth","credential","username:domain:0xc17ba8157756f263d07e158504204629")
...
				
```


#### auth_realm_avp (string)


The definition of an AVP that might contain the realm to be used
			to perform authentication.


*If you define it, you also need to define 
				"auth_username_avp" 
				([auth username avp](#param_auth_username_avp)) and 
				"auth_password_avp" 
				([auth password avp](#param_auth_password_avp)).*


```c title="Set auth_realm_avp parameter"
...
modparam("uac_auth","auth_realm_avp","$avp(10)")
...
				
```


#### auth_username_avp (string)


The definition of an AVP that might contain the username to be used
			to perform authentication.


*If you define it, you also need to define 
				"auth_realm_avp" 
				([auth realm avp](#param_auth_realm_avp)) and 
				"auth_password_avp" 
				([auth password avp](#param_auth_password_avp)).*


```c title="Set auth_username_avp parameter"
...
modparam("uac_auth","auth_username_avp","$avp(11)")
...
				
```


#### auth_password_avp (string)


The definition of an AVP that might contain the password to be used
			to perform authentication. The password can be provided as a plain
			text password or as a precalculated HA1 as a hexa (lower case) string
			(of 32 chars) prefixed with "0x" (so a total of 34 chars) (for example 
			"0xc17ba8157756f263d07e158504204629")


*If you define it, you also need to define 
				"auth_realm_avp" 
				([auth realm avp](#param_auth_realm_avp)) and 
				"auth_username_avp" 
				([auth username avp](#param_auth_username_avp)).*


```c title="Set auth_password_avp parameter"
...
modparam("uac_auth","auth_password_avp","$avp(12)")
...
				
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
