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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
