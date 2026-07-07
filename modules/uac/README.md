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


#### uac_replace_from([display],uri) uac_replace_to([display],uri)


Replace in FROM/TO header the *display* name or/and
			the *URI* part.


Both parameters are string. The *display* is optional.
			If missing, only the URI will be changed in the message.


IMPORTANT: calling the function more than once per branch will lead
			to inconsistent changes over the request.Be sure you do the change
			only ONCE per branch. Note that calling the function from REQUEST
			ROUTE affects all the branches!, so no other change will be 
			possible in the future. For per branch changes use BRANCH and 
			FAILURE route.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
			FAILURE_ROUTE.


```opensips title="uac_replace_from/uac_replace_to usage"
...
# replace both display and uri
uac_replace_from($avp(display),$avp(uri));
# replace only display and do not touch uri
uac_replace_from("batman","");
# remove display and replace uri
uac_replace_from("","sip:robin@gotham.org");
# remove display and do not touch uri
uac_replace_from("","");
# replace the URI without touching the display
uac_replace_from( , "sip:batman@gotham.org");
...
				
```


#### uac_restore_from() uac_restore_to()


This function will check if the FROM/TO URI was modified and will
			use the information stored in header parameter to restore
			the original FROM/TO URI value.


NOTE - this function should be used only if you configured MANUAL
			restoring of the headers (see restore_mode param). For AUTO 
			and NONE, there is no need to use this function.


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


As optional parameter, the function may receive a list of auth
			algorithms to be considered / supported during authentication:


- MD5, MD5-sess
- SHA-256, SHA-256-sess (may be missing, depends on lib support)
- SHA-512-256, SHA-512-256-sess (may be missing, depends on lib support)


Note that the CSeq is automatically increased during authentication.


This function can be used from FAILURE_ROUTE.


*NOTE:* when used without dialog support, the
				*uac_auth()* function cannot be used for authenticating
				in-dialog requests, as there is no mechanism to store the CSeq changes that
				are required for ensuring the correctness of the dialog. The only exception are
				*BYE* messages, which are the last messages within a call,
				hence no further adjustments are needed. The function can still be used for
				authenticating the initial INVITE though.


```opensips title="uac_auth usage"
...
uac_auth();
...
failure_route[check_auth] {
    ...
    if ($T_reply_code==407) {
        if (uac_auth("MD5,MD5-sess")) {
            # auth is succesful, just relay
            t_relay();
            exit;
        }
        # auth failed (no credentials maybe)
        # so continue handling the 407 reply
    }
    ...
}
...
				
```


#### uac_inc_cseq()


This function can be called to increase the CSeq of an ongoing request.


It receives as the *cseq* parameter the value that
			the CSeq should be incremented with.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and  FAILURE_ROUTE.


```opensips title="uac_inc_cseq usage"
...
uac_inc_cseq(1);
...
				
```


## Frequently Asked Questions


**Q: What happened with auth_username_avp, auth_realm_avp and auth_password_avp parameters**


Due some restructuring of the UAC auth modules, these parameters were moved into the "uac_auth" module.
		This module is now responsible for handling all the credentials (static defined or dynamically defined 
		via AVPs). The UAC module will still see the credentials defined via the AVPs.


**Q: Where can I find more about OpenSIPS?**


Take a look at [https://opensips.org/](https://opensips.org/).


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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
