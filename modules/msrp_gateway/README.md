---
title: "MSRP Gateway Module"
description: "This module implements a Gateway for translating between Page Mode (SIP MESSAGE method) and Session Mode (MSRP) Instant Messaging."
---

## Admin Guide


### Overview


This module implements a Gateway for translating between Page Mode
		(SIP MESSAGE method) and Session Mode (MSRP) Instant Messaging.


The module makes use of the *msrp_ua* module's API for
    	the MSRP UAC/UAS functionalities.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tm*
- *msrp_ua*


#### External Libraries or Applications


The following libraries or applications must be installed 
			before running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### hash_size (int)


The size of the hash table that stores the gateway session
				information. It is the 2 logarithmic value of the real size.


*Default value is "10"*
			 (1024 records).


```opensips title="Set hash_size parameter"
...
modparam("msrp_gateway", "hash_size", 16)
...
		
```


#### cleanup_interval (int)


The interval between full iterations of the sessions table
			in order to clean up lingering sessions.


*Default value is "60". (seconds)*


```opensips title="Set cleanup_interval parameter"
...
modparam("msrp_gateway", "cleanup_interval", 60)
...
		
```


#### session_timeout (int)


Amount of time (in seconds) since last message has been received
			from either side, after which a session should be terminated.


*The default value is 12 * 3600 seconds (12 hours).*


```opensips title="Set session_timeout parameter"
...
modparam("msrp_gateway", "session_timeout", 7200)
...
		
```


#### message_timeout (int)


Amount of time (in seconds) since last MESSAGE has been received
			after which a session should be terminated.


*The default value is 2 * 3600 seconds (2 hours).*


```opensips title="Set message_timeout parameter"
...
modparam("msrp_gateway", "message_timeout", 3600)
...
		
```


### Exported Functions


#### msrp_gw_answer(key, content_types, from, to, ruri)


This functions initializes a new gateway session by answering an initial
			INVITE from the MSRP side SIP session. After running this function the
			call will be completely handled by the MSRP UA engine and MSRP SEND
			requests will be automatically translated to SIP MESSAGE requests.


The SIP From, To, and RURI coordinates for building MESSAGE requests
			are passed as parameters to the function.


Parameters:


- *key* (string) - gateway session key to be used
				to correlate the MESSAGE requests with the MSRP side SIP session.
				A simple example would be to build this key based on the From and To
				URIs from both sides(from the initial MSRP leg INVITE and SIP MESSAGE
				requests respectively).
- *content_types* (string) - content types
				adevertised in the SDP offer on the MSRP side SIP session.
- *from* (string) - From URI to be used for building
				SIP MESSAGE requests.
- *to* (string) - To URI to be used for building
				SIP MESSAGE requests.
- *ruri* (string) - Request-URI to be used for building
				SIP MESSAGE requests.


This function can be used only from a request route.


```opensips title="msrp_gw_answer() usage"
...
if (!has_totag() && is_method("INVITE")) {
	msrp_gw_answer($var(corr_key), "text/plain", $fu, $tu, $ru);
	exit;
}
...
```


#### msg_to_msrp(key, content_types)


This functions translates a SIP MESSAGE request into a MSRP SEND request.
			The function will initialize a new gateway session and establish the MSRP
			side SIP session if it is not done so already by a previous call.


The SIP From, To, and RURI coordinates for the new MSRP side session are
			taken from the MESSAGE request and mirrored back when translating a MSRP
			SEND to SIP MESSAGE with *msrp_gw_answer*.


Parameters:


- *key* (string) - gateway session key to be used
				to correlate the MESSAGE requests with the MSRP side SIP session.
				A simple example would be to build this key based on the From and To
				URIs from both sides(from the initial MSRP leg INVITE and SIP MESSAGE
				requests respectively).
- *content_types* (string) - content types
				adevertised in the SDP offer on the MSRP side SIP session.


This function can be used only from a request route.


```opensips title="msg_to_msrp() usage"
...
if (is_method("MESSAGE")) {
	msg_to_msrp($var(corr_key), "text/plain");
	exit;
}
...
```


### Exported MI Functions


#### msrp_gateway:list_sessions


Replaces obsolete MI command: *msrp_gw_list_sessions*.


Lists information about ongoing sessions.


Name: *msrp_gateway:list_sessions*


Parameters


- *None*.


MI FIFO Command Format:


```bash
opensips-cli -x mi msrp_gateway:list_sessions
		
```


#### msrp_gateway:end_session


Replaces obsolete MI command: *msrp_gw_end_session*.


Terminate an ongoing session.


Name: *msrp_gateway:end_session*


Parameters


- *key* (string) - session key


MI FIFO Command Format:


```bash
opensips-cli -x mi msrp_gateway:end_session alice@opensips.org-bob@opensips.org
		
```


### Exported Events


#### E_MSRP_GW_SETUP_FAILED


This event is triggered when the MSRP side SIP session fails to set up,
			when using the *msg_to_msrp()* function.


The event can be used to generate a message with the failure description,
			back on the MESSAGE side.


Parameters:


- *key* - The session key.
- *from_uri* - The URI in the SIP From header
				to use on the MESSAGE side.
- *to_uri* - The URI in the SIP To header
				to use on the MESSAGE side.
- *ruri* - The SIP Request URI to use on the
				MESSAGE side.
- *code* - The SIP error code in the negative reply
				received on the MSRP side. Might be NULL if the MSRP UA session expired
				before receiving a negative reply.
- *reason* - The SIP reason string in the negative reply
				received on the MSRP side. Might be NULL if the MSRP UA session expired
				before receiving a negative reply.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
