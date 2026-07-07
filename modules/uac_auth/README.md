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


Known limitations in this version:


- authentication does not support qop auth-int, just qop auth;


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


```opensips title="Set credential parameter"
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
				([auth username avp id](#param_auth_username_avp)) and 
				"auth_username_avp" 
				([auth password avp id](#param_auth_password_avp)).*


```opensips title="Set auth_realm_avp parameter"
...
modparam("uac_auth","auth_realm_avp","$avp(10)")
...
				
```


#### auth_username_avp (string)


The definition of an AVP that might contain the username to be used
			to perform authentication.


*If you define it, you also need to define 
				"auth_realm_avp" 
				([auth realm avp id](#param_auth_realm_avp)) and 
				"auth_username_avp" 
				([auth password avp id](#param_auth_password_avp)).*


```opensips title="Set auth_username_avp parameter"
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
				"auth_password_avp" 
				([auth password avp id](#param_auth_password_avp)) and 
				"auth_username_avp" 
				([auth password avp id](#param_auth_password_avp)).*


```opensips title="Set auth_password_avp parameter"
...
modparam("uac_auth","auth_password_avp","$avp(12)")
...
				
```


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
