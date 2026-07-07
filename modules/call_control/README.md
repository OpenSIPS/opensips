---
title: "Call Control Module"
description: "This module allows one to limit the duration of calls and automatically end them when they exceed the imposed limit. Its main use case is to implement a prepaid system, but it can also be used to impose a global limit on all calls processed by the proxy."
---

## Admin Guide


### Overview


This module allows one to limit the duration of calls and automatically
      end them when they exceed the imposed limit. Its main use case is to
      implement a prepaid system, but it can also be used to impose a global
      limit on all calls processed by the proxy.


### Description


Callcontrol consists of 3 components:


- The OpenSIPS call_control module
- An external application called callcontrol which keeps track of
            the calls that have a time limit and automatically ends them when
            they exceed it. This application receives requests from OpenSIPS
            and makes requests to a rating engine (see below) to find out if
            a call needs to be limited or not. When a call ends (or is ended)
            it will also instruct the rating engine to debit the balance for
            the caller with the consumed amount. The callcontrol application
            is available from http://callcontrol.ag-projects.com/
- A rating engine that is used to calculate the time limit based on
            the caller's credit and the destination price and to debit the
            caller's balance after a call ends. This is available as part of
            CDRTool from http://cdrtool.ag-projects.com/


The callcontrol application runs on the same machine as OpenSIPS and they
      communicate over a filesystem socket, while the rating engine can run on
      a different host and communicates with the callcontrol application using
      a TCP connection.


Callcontrol is invoked by calling the call_control() function for the
      initial INVITE of every call we want to apply a limit to. This will end
      up as a request to the callcontrol application, which will interrogate
      the rating engine for a time limit for the given caller and destination.
      The rating engine will determine if the destination has any associated
      cost and if the caller has any credit limit and if so will return the
      amount of time he is allowed to call that destination. Otherwise it will
      indicate that there is no limit associated with the call. If there is a
      limit, the callcontrol application will retain the session and attach
      a timer to it that will expire after the given time causing it to call
      back to OpenSIPS with a request to end the dialog. If the rating engine
      returns that there is no limit for the call, the session is discarded
      by the callcontrol application and it will allow it to go proceed any
      limit. An appropriate response is returned to the call_control module
      that is then returned by the call_control() function call and allows
      the script to make a decision based on the answer.


### Features


- Very simple API consisting of a single function that needs to be
            called once for the first INVITE of every call. The rest is done
            automatically in the background using dialog callbacks.
- Gracefully end dialogs when they exceed their time by triggering
            a dlg_end_dlg request into the dialog module, that will generate
            two BYE messages towards each endpoint, ending the call cleanly.
- Allow parallel sessions using one balance per subscriber
- Integrates with mediaproxy's ability to detect when a call does
            timeout sending media and is closed. In this case the dlg_end_dlg
            that is triggered by mediaproxy will end the callcontrol session
            before it reaches the limit and consumes all the credit for a call
            that died and didn't actually take place. For this mediaproxy has
            to be used and it has to be started by engage_media_proxy() to be
            able to keep track of the call's dialog and end it on timeout.
- Even when mediaproxy is unable to end the dialog because it was
            not started with engage_media_proxy(), the callcantrol application
            is still able to detect calls that did timeout sending media, by
            looking in the radius accounting records for entries recorded by
            mediaproxy for calls that did timeout. These calls will also be
            ended gracefully by the callcontrol application itself.
- If the prepaid_account_flag module parameter is defined, the
            external application compares the OpenSIPS's and the rating engine's
            views on whether the account calling is prepaid or not and takes
            appropriate action if they conflict. This provides protection
            against frauds in case the rating engine malfunctions or there is an
            inconsistency in the database.
- If the call_limit_avp is defined to a value greater than 0 it will be
            passed to the CallControl application, which will limit the number of concurrent
            calls the billing party (From user or diverter) is able to make. If the limit
            is reached the call_control function will return a specific error value.
- The call_token_avp may be used to detect calls with a duplicated CallID that could
            create potential problems in call rating engines.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *dialog* module


#### External Libraries or Applications


The following libraries or applications must be installed before
        running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### disable (int)


Boolean flag that specifies if callcontrol should be disabled. This
        is useful when you want to use the same OpenSIPS configuration in
        two different context, one using callcontrol, the other not. In the
        case callcontrol is disabled, calls to the call_control() function
        will return a code indicating that there is no limit associated with
        the call, allowing the use of the same configuration without changes.


*Default value is "0".*


```opensips title="Setting the disable parameter"
...
modparam("call_control", "disable", 1)
...
        
```


#### socket_name (string)


It is the path to the filesystem socket where the callcontrol
        application listens for commands from the module.


*Default value is 
            "/run/callcontrol/socket".*


```opensips title="Setting the socket_name parameter"
...
modparam("call_control", "socket_name", "/run/callcontrol/socket")
...
        
```


#### socket_timeout (int)


How much time (in milliseconds) to wait for an answer from the
        callcontrol application.


*Default value is "500" (ms).*


```opensips title="Setting the socket_timeout parameter"
...
modparam("call_control", "socket_timeout", 500)
...
        
```


#### signaling_ip_avp (string)


Specification of the AVP which holds the IP address from where
        the SIP signaling originated. If this AVP is set it will be used
        to get the signaling IP address, else the source IP address
        from where the SIP message was received will be used.
        This AVP is meant to be used in cases where there are more than
        one proxy in the call setup path and the proxy that actually
        starts callcontrol doesn't receive the SIP messages directly
        from the UA and it cannot determine the NAT IP address from
        where the signaling originated. In such a case attaching a
        SIP header at the first proxy and then copying that header's
        value into the signaling_ip_avp on the proxy that starts
        callcontrol will allow it to get the correct NAT IP address
        from where the SIP signaling originated.


This is used by the rating engine which finds the rates to apply to a
        call based on caller's SIP URI, caller's SIP domain or caller's IP
        address (whichever yields a rate first, in this order).


*Default value is "$avp(cc_signaling_ip)".*


```opensips title="Setting the signaling_ip_avp parameter"
...
modparam("call_control", "signaling_ip_avp", "$avp(cc_signaling_ip)")
...
        
```


#### canonical_uri_avp (string)


Specification of the AVP which holds an optional application defined
        canonical request URI. When this is set, it will be used as the
        destination when computing the call price, otherwise the request URI
        will be used. This is useful when the username of the ruri needs to
        have a different, canonical form in the rating engine computation
        than it has in the ruri.


*Default value is "$avp(cc_can_uri)".*


```opensips title="Setting the canonical_uri_avp parameter"
...
modparam("call_control", "canonical_uri_avp", "$avp(cc_can_uri)")
...
        
```


#### diverter_avp (string)


Specification of the AVP which holds an optional
        application defined diverter SIP URI. When this is set, it will be
        used by the rating engine as the billing party when finding the rates
        to apply to a given call, otherwise, the caller's URI taken from the
        From field will be used. When set, this AVP should contain a value in
        the form "user@domain" (no sip: prefix should be used).


This is useful when a destination diverts a call, thus becoming the
        new caller. In this case the billing party is the diverter and this
        AVP should be set to it, to allow the rating engine to pick the right
        rates for the call. For example, if A calls B and B diverts all its
        calls unconditionally to C, then the diverter AVP should the set to
        B's URI, because B is the billing party in the call not A after the
        call was diverted.


*Default value is "$avp(diverter)".*


```opensips title="Setting the diverter_avp parameter"
...
modparam("call_control", "diverter_avp", "$avp(diverter)")

route {
  ...
  # alice@example.com is paying for this call
  $avp(diverter) = "alice@example.com";
  ...
}
...
        
```


#### prepaid_account_flag (string)


The flag that is used to specify whether the account making the call is
        prepaid or postpaid. Setting this to a non-null value will determine
        the module to pass the flag's value to the external application. This
        will allow the external application to compare OpenSIPS's and the rating
        engine's views on whether the account calling is prepaid or not and take
        appropriate action if they conflict. The flag should be set from the
        OpenSIPS configuration for a prepaid account and reset for a postpaid
        one.


*Default value is NULL (undefined).*


```opensips title="Setting the prepaid_account_flag parameter"
...
modparam("call_control", "prepaid_account_flag", "PP_ACC_FLAG")
...
        
```


#### call_limit_avp (string)


Specification of the AVP which holds an optional application defined
        call limit. When this is set, it will be passed to the CallControl
        application and if the limit is reached the call_control function will
        return an error code of -4.


*Default value is "$avp(cc_call_limit)".*


```opensips title="Setting the call_limit_avp parameter"
...
modparam("call_control", "call_limit_avp", "$avp(cc_call_limit)")
...
        
```


#### call_token_avp (string)


Specification of the AVP which holds an optional application defined
        token. This token will be used to check if two calls with the same
        CallID actually refer to the same call. If call_control() is called
        multiple times for the same call (thus same CallID) the token needs
        to be the same or call_control will return -3 error, indicating that
        the CallID is duplicated.


*Default value is "$avp(cc_call_token)".*


```opensips title="Setting the call_token_avp parameter"
...
modparam("call_control", "call_token_avp", "$avp(cc_call_token)")
...
$avp(cc_call_token) := $RANDOM;
...
        
```


#### init (string)


This parameter is used to describe custom call control initialize messages. It represents a
      list of key value pairs and has the following format:


- "string1 = var1 [string2 = var2]*"


The left-hand side of the assignment can be any string.


The right-hand side of the assignment must be a script pseudo variable or
			a script AVP. For more information about them see [CookBooks - Scripting Variables](https://opensips.org/Resources/DocsCoreVar15).


If the parameter is not set, the default initialize message is sent.


*Default value is "NULL".*


```opensips title="Setting the init parameter"
	
...
modparam("call_control", "init", "call-id=$ci to=$tu from=$fu 
			authruri=$du another_field = $avp(10)")
...
        
```


#### start (string)


This parameter is used to describe custom call control start messages. It represents a
      list of key value pairs and has the following format:


- "string1 = var1 [string2 = var2]*"


The left-hand side of the assignment can be any string.


The right-hand side of the assignment must be a script pseudo variable or
			a script AVP. For more information about them see [CookBooks - Scripting Variables](https://opensips.org/Resources/DocsCoreVar15).


If the parameter is not set, the default start message is sent.


*Default value is "NULL".*


```opensips title="Setting the start parameter"
	
...
modparam("call_control", "start", "call-id=$ci to=$tu from=$fu 
			authruri=$du another_field = $avp(10)")
...
        
```


#### stop (string)


This parameter is used to describe custom call control stop messages. It represents a
      list of key value pairs and has the following format:


- "string1 = var1 [string2 = var2]*"


The left-hand side of the assignment can be any string.


The right-hand side of the assignment must be a script pseudo variable or
			a script AVP. For more information about them see [CookBooks - Scripting Variables](https://opensips.org/Resources/DocsCoreVar15).


If the parameter is not set, the default stop message is sent.


*Default value is "NULL".*


```opensips title="Setting the stop parameter"
	
...
modparam("call_control", "stop", "call-id=$ci to=$tu from=$fu 
			authruri=$du another_field = $avp(10)")
...
        
```


### Exported Functions


#### call_control()


Trigger the use of callcontrol for the dialog started by the INVITE
        for which this function is called (the function should only be called
        for the first INVITE of a call). Further in-dialog requests will be
        processed automatically using internal bindings into the dialog state
        machine, allowing callcontrol to update its internal state as the
        dialog progresses, without any other intervention from the script.


This function should be called right before the message is sent out
        using t_relay(), when all the request uri modifications are over and
        a final destination has been determined.


This function has the following return codes:


- +2 - call has no limit
- +1 - call has limit and is traced by callcontrol
- -1 - not enough credit to make the call
- -2 - call is locked by another call in progress
- -3 - duplicated callid
- -4 - call limit has been reached
- -5 - internal error (message parsing, communication, ...)


This function can be used from REQUEST_ROUTE.


```opensips title="Using the call_control function"
...
if ($avp(805) != NULL) {
    # the diverter AVP is set, use it as billing party
    $avp(billing_party_domain) = $(avp(805){uri.domain});
} else {
    $avp(billing_party_domain) = $fd;
}

if (is_method("INVITE") && !has_totag() &&
    is_domain_local($avp(billing_party_domain))) {
    call_control();
    switch ($retcode) {
    case 2:
        # Call with no limit
    case 1:
        # Call has limit and is under callcontrol management
        break;
    case -1:
        # Not enough credit (prepaid call)
        sl_send_reply(402, "Not enough credit");
        exit;
        break;
    case -2:
        # Locked by another call in progress (prepaid call)
        sl_send_reply(403, "Call locked by another call in progress");
        exit;
        break;
    case -3:
        # Duplicated callid
        sl_send_reply(400, "Duplicated callid");
        exit;
        break;
    case -4:
        # Call limit reached
        sl_send_reply(503, "Too many concurrent calls");
        exit;
        break;
    default:
        # Internal error (message parsing, communication, ...)
        if (PREPAID_ACCOUNT) {
            xlog("Call control: internal server error\n");
            sl_send_reply(500, "Internal server error");
            exit;
        } else {
            xlog("L_WARN", "Cannot set time limit for postpaid call\n");
        }
    }
}
t_relay();
...
        
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
