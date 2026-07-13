---
title: "UAC Module"
description: "UAC (User Agent Client) module provides some basic UAC functionalities like FROM / TO header manipulation (anonymization) or client authentication."
---

## Admin Guide


### Overview


UAC (User Agent Client) module provides some basic UAC
functionalities like FROM / TO header manipulation (anonymization)
or client authentication.


If the dialog module is loaded and a dialog can be created, 
then the auto mode can be done more efficiently.


Known limitations in this version:


- authentication does not support qop auth-int, just qop auth;
- CSeq not increased during authentication - the response 
may be rejected.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM - Transaction Module*.
- *RR - Record-Route Module*, but only if
restore mode for FROM URI is set to "auto".
- *UAC_AUTH - UAC Authentication Module*.
- *Dialog Module*, if "force_dialog"
module parameter is enabled, or a dialog is created from the
configuration script.


#### External Libraries or Applications


The following libraries or applications must be installed 
before running OpenSIPS with this module loaded:


- *None*


### Exported Parameters


#### restore_mode (string)


There are 3 mode of restoring the original headers (FROM/TO) URI:


- "none" - no information about original URI is 
stored; restoration is not possible.
- "manual" - all following replies will be restored,
except for the sequential requests - these must be manually 
updated based on original URI.
- "auto" - all sequential requests and replies will 
be automatically updated based on stored original URI.


*This parameter is optional, it's default value being 
"auto".*


```opensips title="Set restore_mode parameter"
...
modparam("uac","restore_mode","auto")
...
```


#### restore_passwd (string)


String password to be used to encrypt the RR storing parameter
(when replacing the TO/FROM headers). If empty, no encryption 
will be used.


*Default value of this parameter is empty.*


```opensips title="Set restore_passwd parameter"
...
modparam("uac","restore_passwd","my_secret_passwd")
...
```


#### rr_from_store_param (string)


Name of Record-Route header parameter that will be used to store 
(encoded) the original FROM URI.


*This parameter is optional, it's default value being 
"vsf".*


```opensips title="Set rr_from_store_param parameter"
...
modparam("uac","rr_from_store_param","my_Fparam")
...
```


#### rr_to_store_param (string)


Name of Record-Route header parameter that will be used to store 
(encoded) the original TO URI.


*This parameter is optional, it's default value being 
"vst".*


```opensips title="Set rr_to_store_param parameter"
...
modparam("uac","rr_to_store_param","my_Tparam")
...
```


#### force_dialog (int)


Force create dialog if it is not created from the configuration script.


Default value is no.


```opensips title="Set force_dialog parameter"
...
modparam("uac", "force_dialog", yes)
...
```


### Exported Functions


#### uac_replace_from(display,uri) uac_replace_to(display,uri)


Replace in FROM/TO header the *display* name and
the *URI* part.


*display* and *URI* 
parameters can include pseudo-variables.


> [!IMPORTANT]
> Calling the function more than once per branch will lead
> to inconsistent changes over the request.Be sure you do the change
> only ONCE per branch. Note that calling the function from REQUEST
> ROUTE affects all the branches!, so no other change will be 
> possible in the future. For per branch changes use BRANCH and 
> FAILURE route.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
FAILURE_ROUTE.


```opensips title="uac_replace_from/uac_replace_to usage"
...
# replace both display and uri
uac_replace_from("$avp(display)","$avp(uri)");
# replace only display and do not touch uri
uac_replace_from("batman","");
# remove display and replace uri
uac_replace_from("","sip:robin@gotham.org");
# remove display and do not touch uri
uac_replace_from("","");
...
				
```


#### uac_replace_from(uri) uac_replace_to(uri)


Replace in FROM/TO header the *URI* part
without altering the display name.


*URI* parameter can include pseudo-variables.


This function can be used from REQUEST_ROUTE.


```opensips title="uac_replace_from/uac_replace_to usage"
...
uac_replace_from("sip:batman@gotham.org");
...
				
```


#### uac_restore_from() uac_restore_to()


This function will check if the FROM/TO URI was modified and will
use the information stored in header parameter to restore
the original FROM/TO URI value.


> [!NOTE]
> This function should be used only if you configured MANUAL
> restoring of the headers (see restore_mode param). For AUTO 
> and NONE, there is no need to use this function.


This function can be used from REQUEST_ROUTE.


```opensips title="uac_restore_from/uac_restore_to usage"
...
uac_restore_from();
...
```


#### uac_auth()


This function can be called only from failure route and will 
build the authentication response header and insert it into the
request without sending anything.
Credentials for buiding the authentication response will be taken
from the list of credentials provided by the uac_auth module (static
or via AVPs).


This function can be used from FAILURE_ROUTE.


```opensips title="uac_auth usage"
...
uac_auth();
...
				
```


## Frequently Asked Questions


**Q: What happened with auth_username_avp, auth_realm_avp and auth_password_avp parameters**


Due some restructuring of the UAC auth modules, these parameters were moved into the "uac_auth" module.
This module is now responsible for handling all the credentials (static defined or dynamically defined 
via AVPs). The UAC module will still see the credentials defined via the AVPs.


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
users@lists.opensips.org and e-mails regarding development versions
should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
