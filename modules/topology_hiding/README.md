---
title: "topology_hiding Module"
description: "This is a module which provides topology hiding capabilities. The module can work on top of the dialog module, or as a standalone module ( thus alowing topology hiding for all types of requests )"
---

## Admin Guide


### Overview


This is a module which provides topology hiding capabilities.
		The module can work on top of the dialog module, or as a standalone module ( thus alowing topology hiding for all
		types of requests )


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM - Transaction Module*.
- *Dialog Module*, if "force_dialog"
				module parameter is enabled, or a dialog is created from the
				configuration script.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*


### Exported Parameters


#### th_callid_passwd (string)


The string password that will be used for encoding/decoding the callid in case of topology_hiding with callid mangling.


*Default value is ""OpenSIPS""*


```opensips title="Set th_callid_passwd parameter"
...
modparam("topology_hiding", "th_callid_passwd", "my_topo_hiding_secret")
...
```


#### th_callid_prefix (string)


The prefix that will be used for detecting callids which have been encoded by the dialog topology hiding. Make sure to change this value in case your SIP path contains multiple OpenSIPS boxes with topology hiding.


*Default value is ""DLGCH_""*


```opensips title="Set th_callid_prefix parameter"
...
modparam("topology_hiding", "th_callid_prefix", "MYCALLIDPREFIX_")
...
```


#### th_passed_contact_uri_params (string)


List of semicolon-separated Contact URI parameters that will be passed from one side to the other for topology hiding calls. To be used when end-to-end functionality uses such Contact URI parameters.


*Default value is "empty" - do not pass any parameters*


```opensips title="Set th_passed_contact_uri_params parameter"
...
modparam("topology_hiding", "th_passed_contact_uri_params", "paramname1;myparam;custom_param")
...
```


#### th_passed_contact_params (string)


List of semicolon-separated Contact header parameters that will be passed from one side to the other for topology hiding calls. To be used when end-to-end functionality uses such Contact header parameters.


*Default value is "empty" - do not pass any parameters*


```opensips title="Set th_passed_contact_params parameter"
...
modparam("topology_hiding", "th_passed_contact_params", "paramname1;myparam;custom_param")
...
```


#### force_dialog (int)


If set to 1, the module will internally create the dialog ( if not already created ). This will only work for INVITE based dialogs, and the dialog module must be loaded.


*Default value is "0"*


```opensips title="Set force_dialog parameter"
...
modparam("topology_hiding", "force_dialog", 1)
...
```


#### th_contact_encode_passwd (string)


When not relying on the dialog module ( due to script writer preference or simply when doing topo hiding for non INVITE dialogs ), the module will store the needed information in a Contact URI param. The parameter configures the string password that will be used for encoding/decoding that specific param .


*Default value is ""ToPoCtPaSS""*


```opensips title="Set th_contact_encode_passwd parameter"
...
modparam("topology_hiding", "th_contact_encode_passwd", "my_topoh_passwd")
...
```


#### th_contact_encode_param (string)


When not relying on the dialog module ( due to script writer preference or simply when doing topo hiding for non INVITE dialogs ), the module will store the needed information in a Contact URI param. The parameter configures the respective parameter name.


*Default value is ""thinfo""*


```opensips title="Set th_contact_encode_param parameter"
...
modparam("topology_hiding", "th_contact_encode_param", "customparam")
...
```


#### th_contact_encode_scheme (string)


When not relying on the dialog module ( due to script writer preference or simply when doing topo hiding for non INVITE dialogs ), the module will store the needed information in a Contact URI param. This parameter configures the encoding scheme to be used for the data stored in
			the Contact URI param. Possible values are:


- *base64*
- *base32*


*Default value is ""base64""*


```opensips title="Set th_contact_encode_scheme parameter"
...
modparam("topology_hiding", "th_contact_encode_scheme", "base32")
...
```


#### th_contact_caller_username_var (string)


Variable used to store the value of the contact username advertised to the caller.


*Default value is "_th_contact_caller_username_var_"*


```opensips title="Set th_contact_caller_username_var parameter"
...
modparam("topology_hiding", "th_contact_caller_username_var", "__topo_hiding_username_var__")
...
```


#### th_contact_callee_username_var (string)


Variable used to store the value of the contact username advertised to the callee.


*Default value is "_th_contact_callee_username_var_"*


```opensips title="Set th_contact_callee_username_var parameter"
...
modparam("topology_hiding", "th_contact_callee_username_var", "__topo_hiding_username_var__")
...
```


#### th_callid_loop_protection (int)


Include the *from_tag* when encoding the
			topology-hiding Call-ID to ensure correct decoding in looping scenarios,
			(when the same call with a previously encoded Call-ID is being looped back).


Note that enabling this parameter will increase the generated Call-ID value,
			due to the additional from_tag information being embedded.


*Default value is "0" / disabled.*


```opensips title="Set th_callid_loop_protection parameter"
...
modparam("topology_hiding", "th_callid_loop_protection", 1)
...
```


### Exported Functions


#### topology_hiding()


By calling this function on an initial request, the modules will
			hide the topology, meaning that it will strip and restore all the Via,
			Record-Route and Route headers and it will replace the contact with the
			IP address of the interface where the request was received.


You must note however, that the detection of the future in-dialog requests(BYE, reInvite, etc.)
			for these dialogs on which topology hiding is applied, is not done automatically.
			Without topology hiding and only normal dialog, the detection was
			done when loose_route was called. But now, for this dialogs where topology
			hiding is applied, the in dialog requests reaching OpenSIPS won't have any Route headers
			and the RURI will point to OpenSIPS machine.
			So, to be able to match the in-dialog requests to the corresponding dialog, a script
			function must be called. It's name is *topology_hiding_match* and you can read
			it's description above.
			The in-dialog topology requests are requests with a to tag,
			RURI pointing to opensips and with a method specific to a
			Invite dialog. For this kind of requests you should call
			topology_hiding_match() function. If the request is successfully matched and fixed as according to the topology hiding logic,the function returns success.


Optionally,the function also receives a string parameter, which holds string flags.
			Current options for the string flags are :


- *U* - Propagate the Username in the Contact header URI
- *D* - Dialog ID (DID) is pushed into Contact username, rather than URI param. This option makes sense only when using topology hiding with dialog support.
- *a* - Preserve the advertised Contact header advertised to the caller throughout the entire dialog.
- *A* - Preserve the advertised Contact header advertised to the callee throughout the entire dialog.
- *D* - Dialog ID (DID) is pushed into Contact username, rather than URI param. This option makes sense only when using topology hiding with dialog support.
- *C* - Encode the callid header
There are many cases where propagating the callid towards the callee side is not a good idea, since sometimes the callid contains the IP of the actual caller side, thus revealing part of the network topology.
When using the "C" flag, the callid will be automatically encoded / decoded, transparent for the script writer - inside OpenSIPS (script,MI functions, etc ) all the variables related to the callid will represent the callid value for the caller side. If the callid for the callee side is needed, refer to the $TH_callee_callid pvar.
*Note:* Changing the callid of the call using the "C" flag is only
						available when doing topology_hiding with *dialog support*. Using this
						flag without dialog support will not change the callid at all!.


The second parameter can be used to advertise a particular
			*username* in the Contact header URI, either on the
			*caller*, either on the *callee*
			leg, separated by */*. The format of the parameter is 
			*caller_username|/[caller_contact_username][/callee_contact_username]*.
			If the separator is missing, the same contact username is advertised on
			both legs. If the separator is being used, you can control the username
			put in contact per leg.


```opensips title="topology_hiding usage"
...
if(!has_totag() && is_method("INVITE")) {
	topology_hiding();
}
...
...
if(!has_totag() && is_method("INVITE")) {
	topology_hiding("U");
}
...
# set "opensips" for both caller and the callee's Contact username
if(!has_totag() && is_method("INVITE")) {
	topology_hiding("U", "opensips");
}
...
# set "caller" in the caller's Contact username
if(!has_totag() && is_method("INVITE")) {
	topology_hiding("U", "/caller");
}
...
# set "callee" in the callee's Contact username
if(!has_totag() && is_method("INVITE")) {
	topology_hiding("U", "//callee");
}
...
# set "caller" in the caller's Contact username and
# "callee" in the callee's Contact username
if(!has_totag() && is_method("INVITE")) {
	topology_hiding("U", "/caller/callee");
}
...
```


```opensips title="Calling topology_hiding_match() function for topology hiding sequential requests"
...
if (has_totag())
        if(topology_hiding_match())
        {
                xlog("Found a request $rm belonging to an existing topology hiding dialog\n");
                route(relay);
                exit;
        }
}
...
```


#### topology_hiding_match([dlg_match_mode])


This function is to be used to match and fix a sequential request
		belong to an existing topology hiding dialog.


With regards to dialog matching (including the optional parameter),
		this function behaves identically to match_dialog(). Please see the
		dialog module documentation for further details regarding dialog
		matching options.


The function returns true if a topology hiding dialog exists for the request and the request has been successfully fixed.


This function can be used from REQUEST_ROUTE.


```opensips title="topology_hiding_match_dialog() usage"
...
    if (has_totag()) {
        if (!topology_hiding_match() ) {
            xlog(" cannot match request to a dialog \n");
	    send_reply(404,"Not found");
        } else
		route(RELAY);
    }
...
```


### Exported Pseudo-Variables


#### $TH_callee_callid


Read only variable that will contain the callid as it is propagated towards the callee side, in case topology_hiding("C") is called.


NULL will be returned if there is no topology hiding dialog for the request or if topology_hiding with callid encoding was not used for the current dialog.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
