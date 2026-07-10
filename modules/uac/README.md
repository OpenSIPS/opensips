---
title: "UAC Module"
description: "UAC (User Agent Client) module provides some basic UAC functionalities like FROM header manipulation (anonymization) or client authentication."
---

## Admin Guide


### Overview


UAC (User Agent Client) module provides some basic UAC
functionalities like FROM header manipulation (anonymization)
or client authentication.


Known limitations in this version:


- authentication does not support qop auth-int, just qop auth;
- CSeq not increased during authentication - the response 
may be rejected.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM - Transaction Module*
- *RR - Record-Route Module*, but only if
restore mode for FROM URI is set to "auto".


#### External Libraries or Applications


The following libraries or applications must be installed 
before running OpenSIPS with this module loaded:


- *None*


### Exported Parameters


#### rr_store_param (string)


Name of Record-Route header parameter that will be used to store 
(encoded) the original FROM URI.


*This parameter is optional, it's default value being 
"vsf".*


```opensips title="Set rr_store_param parameter"
...
modparam("uac","rr_store_param","my_param")
...
				
```


#### from_restore_mode (string)


There are 3 mode of restoring the original FROM URI:


- "none" - no information about original URI is 
stored; restoretion is not possible.
- "manual" - all following replies will be restored,
but not also the sequential requests - this must be manually 
updated based on original URI.
- "auto" - all sequential requests and replies will 
be automatically updated based on stored original URI.


*This parameter is optional, it's default value being 
"auto".*


```opensips title="Set from_restore_mode parameter"
...
modparam("uac","from_restore_mode","auto")
...
```


#### from_passwd (string)


String password to be used to encrypt the RR storing paramter. If
empty, no encryption will be used.


*Default value of this parameter is empty.*


```opensips title="Set from_passwd parameter"
...
modparam("uac","from_passwd","my_secret_passwd")
...
```


#### credential (string)


Contains a multiple definition of credentials used to perform
authentication.


*This parameter is required if UAC authentication is used.*


```opensips title="Set credential parameter"
...
modparam("uac","credential","username:domain:password")
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
modparam("uac","auth_realm_avp","$avp(i:10)")
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
modparam("uac","auth_username_avp","$avp(i:11)")
...
				
```


#### auth_password_avp (string)


The definition of an AVP that might contain the password to be used
to perform authentication.


*If you define it, you also need to define 
"auth_password_avp" 
([auth password avp id](#param_auth_password_avp)) and 
"auth_username_avp" 
([auth password avp id](#param_auth_password_avp)).*


```opensips title="Set auth_password_avp parameter"
...
modparam("uac","auth_password_avp","$avp(i:12)")
...
```


### Exported Functions


#### uac_replace_from(display,uri)


Replace in FROM header the *display* name and
the *URI* part.


*display* and *URI* 
parameters can include pseudo-variables.


> [!IMPORTANT]
> Calling the function more than once per branch will lead
> to inconsistent changes over the request. Be sure you do the change
> only ONCE per branch. Note that calling the function from REQUEST
> ROUTE affects all the branches!, so no other change will be 
> possible in the future. For per branch changes use BRANCH and 
> FAILURE route.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
FAILURE_ROUTE.


```opensips title="uac_replace_from usage"
...
# replace both display and uri
uac_replace_from("$avp(s:display)","$avp(s:uri)");
# replace only display and do not touch uri
uac_replace_from("batman","");
# remove display and replace uri
uac_replace_from("","sip:robin@gotham.org");
# remove display and do not touch uri
uac_replace_from("","");
...
				
```


#### uac_replace_from(uri)


Replace in FROM header the *URI* part
without altering the display name.


*URI* parameter can include pseudo-variables.


This function can be used from REQUEST_ROUTE.


```opensips title="uac_replace_from usage"
...
uac_replace_from("sip:batman@gotham.org");
...
				
```


#### uac_restore_from()


This function will check if the FROM URI was modified and will
use the information stored in header parameter to restore
the original FROM URI value.


This function can be used from REQUEST_ROUTE.


```opensips title="uac_restore_from usage"
...
uac_restore_from();
...
```


#### uac_auth()


This function can be called only from failure route and will 
build the authentication response header and insert it into the
request without sending anything.


This function can be used from FAILURE_ROUTE.


```opensips title="uac_auth usage"
...
uac_auth();
...
				
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
