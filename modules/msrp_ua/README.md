---
title: "MSRP UA Module"
description: "This module implements an User Agent capable of establishing messaging sessions using the MSRP(RFC 4976) protocol."
---

## Admin Guide


### Overview


This module implements an User Agent capable of establishing messaging
		sessions using the MSRP(RFC 4976) protocol.


Through an internal API and exported script and MI functions, the module
		allows OpenSIPS to set up MSRP sessions via SIP and exchange messages as
		an MSRP endpoint.


The module makes use of the *proto_msrp* module for
    	the MSRP protocol stack and the *b2b_entities* module 
    	for the SIP UAC/UAS functionalities.


### Usage from Script and External API


In order to start a SIP call carying MSRP from OpenSIPS you can use the
	[mi start session](#mi_start_session) MI function. Alternatively, to
	answer a SIP session with MSRP you can use the
	[msrp ua answer](#func_msrp_ua_answer) script function.


When a UAC or UAS session is successfully established(ACK sent/received) the
	[E MSRP SESSION NEW](#event_e_msrp_session_new) event is triggered. After this point,
	you may receive MSRP messages or Reports, signaled by the
	[E MSRP MSG RECEIVED](#event_e_msrp_msg_received) and
	[E MSRP REPORT RECEIVED](#event_e_msrp_report_received) events.


Note that the *E_MSRP_REPORT_RECEIVED* event covers both actual MSRP
    REPORT requests as well as negative MSRP transaction responses and local send
    timeouts(which should be treated the same as a received timeout transaction
    response).


You can send MSRP messages to the peer with the
    [mi send message](#mi_send_message) MI function.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *proto_msrp*
- *b2b_entities*


#### External Libraries or Applications


The following libraries or applications must be installed 
			before running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### hash_size (int)


The size of the hash table that stores the MSRP session
				information. It is the 2 logarithmic value of the real size.


*Default value is "10"*
			 (1024 records).


```c title="Set hash_size parameter"
...
modparam("msrp_ua", "hash_size", 16)
...
		
```


#### cleanup_interval (int)


The interval between full iterations of the sessions table
			in order to clean up expired MSRP sessions.


*Default value is "60".*


```c title="Set cleanup_interval parameter"
...
modparam("msrp_ua", "cleanup_interval", 30)
...
		
```


#### max_duration (integer)


The maximum duration of a call. If set to 0, there will be no limitation.


The default value is 12 * 3600 seconds (12 hours).


```c title="max_duration parameter example"
...
modparam("msrp_ua", "max_duration", 7200)
...
```


#### my_uri (string)


The MSRP URI of the OpenSIPS endpoint. This URI will be advertised in the SDP
		offer provided to peers when setting up a session and should match one
		of the MSRP listeners defined in the script.


The *session-id* part of the URI should be ommited.


If the port is not set explicitly, the default value of 2855 wil
		be assumed


```c title="my_uri parameter usage"
...
modparam("msrp_ua", "my_uri", "msrp://opensips.org:2855;tcp")
...
```


#### advertised_contact (string)


Contact to be used in the generated SIP requests. For sessions answered
		by OpenSIPS, if it is not set, it is constructed dynamically from the
		socket where the initiating request was received.


This parameter is mandatory when using the
		[mi start session](#mi_start_session) MI function.


```c title="advertised_contact parameter usage"
...
modparam("msrp_ua", "advertised_contact", "sip:oss@opensips.org")
...
```


#### relay_uri (string)


URI of an MSRP relay to use for both accepted and initiated
		sessions.


Credentials for the MSRP client are provided via the
		*uac_auth* module by setting the
		*credential* module parameter.


If not set, no relay will be used.


```c title="relay_uri parameter usage"
...
modparam("msrp_ua", "relay_uri", "msrp://opensips.org:2856;tcp")
...
```


### Exported Functions


#### msrp_ua_answer(content_types)


This functions answers an initial INVITE offering a new MSRP
			messaging session. After this function is used to initialize the
			session, the call will be completely handled by the B2B engine.


Parameters:


- *content_types* (string) - content types
				adevertised in the *accept-types* SDP
				attribute. At least one of the content types in this list must
				match the types offered by the peer in its SDP offer.


This function can be used only from a request route.


```c title="msrp_ua_answer() usage"
...
if (!has_totag() && is_method("INVITE")) {
	msrp_ua_answer("text/plain");
	exit;
}
...
```


### Exported MI Functions


#### msrp_ua:send_message


Replaces obsolete MI command: *msrp_ua_send_message*.


Sends a new MSRP message to the peer.


Name: *msrp_ua:send_message*


Parameters


- *session_id* (string) - the MSRP session
				identifier ("session-id" part of the MSRP URI).
- *mime* (string, optional) - MIME content
				type of this message. If missing, an empty message will be sent.
- *body* (string, optional) - actual message
				body. If missing, an empty message will be sent.
- *success_report* (string, optional) - string
				indicating whether to request an MSRP Success Report. Possible
				values are *yes* or *no*.
				If the parameter is missing or is set to "no" the SEND request
				will not include a Success-Report header.
- *failure_report* (string, optional) - string
				indicating whether to request an MSRP Failure Report. Possible
				values are *yes*, *no* or
				*partial*, as specified in MSRP.
				If the parameter is missing or is set to "yes" the SEND request
				will not include a Failure-Report header. Note that if the header
				field is not present, the receving MSRP endpoint must treat it the
				same as a Failure-Report header with a value of "yes".


MI FIFO Command Format:


```c
opensips-cli -x mi msrp_ua:send_message \
	session_id=5addd9e7b74fa44fbace68a4fc562293 \
	mime=text/plain body=Hello success_report=yes
		
```


#### msrp_ua:start_session


Replaces obsolete MI command: *msrp_ua_start_session*.


Starts a MSRP session.


The [advertised contact](#param_advertised_contact) is mandatory if this
		function is used.


Name: *msrp_ua:start_session*


Parameters


- *content_types* (string) - content types
				adevertised in the *accept-types* SDP
				attribute.
- *from_uri* (string) - From URI to be used
				in the INVITE.
- *to_uri* (string) - To URI to be used
				in the INVITE.
- *ruri* (string) - Request URI and destination
				of the INVITE.


MI FIFO Command Format:


```c
opensips-cli -x mi msrp_ua:start_session \
	text/plain sip:oss@opensips.org \
	sip:alice@opensips.org sip:alice@opensips.org
		
```


#### msrp_ua:list_sessions


Replaces obsolete MI command: *msrp_ua_list_sessions*.


Lists information about ongoing MSRP sessions.


Name: *msrp_ua:list_sessions*


Parameters


- *None*.


MI FIFO Command Format:


```c
opensips-cli -x mi msrp_ua:list_sessions
		
```


#### msrp_ua:end_session


Replaces obsolete MI command: *msrp_ua_end_session*.


Terminate an ongoing MSRP session.


Name: *msrp_ua:end_session*


Parameters


- *session_id* (string) - the MSRP session
				identifier ("session-id" part of the MSRP URI).


MI FIFO Command Format:


```c
opensips-cli -x mi msrp_ua:end_session \
	5addd9e7b74fa44fbace68a4fc562293
		
```


### Exported Events


#### E_MSRP_SESSION_NEW


This event is triggered when a new MSRP session is successfully
			established(ACK sent/received).


Parameters:


- *from_uri* - The URI in the SIP From header
				of the answered INVITE.
- *to_uri* - The URI in the SIP To header
				of the answered INVITE.
- *ruri* - The SIP Request URI of the answered
				INVITE.
- *session_id* - The MSRP session identifier
				("session-id" part of the MSRP URI).
- *content_types* - The content types offered
				by the peer in the *accept-types* SDP attribute.


#### E_MSRP_SESSION_END


This event is triggered when an ongoing MSRP session is terminted (session
			expires or BYE is received; terminating a session via the
			*msrp_ua:end_session* MI function is not included).


Parameters:


- *session_id* - The MSRP session identifier
				("session-id" part of the MSRP URI).


#### E_MSRP_MSG_RECEIVED


This event is triggered when receiving a new, non-empty MSRP SEND
			request from the peer.


Parameters:


- *session_id* - The MSRP session identifier
				("session-id" part of the MSRP URI).
- *content_type* - The content type of this message.
- *body* - The actual message body.


#### E_MSRP_REPORT_RECEIVED


This event is triggered when:


- a MSRP REPORT request is received
- a failure transaction response is received
- a local timeout for a SEND request occured.


Parameters:


- *session_id* - The MSRP session identifier
				("session-id" part of the MSRP URI).
- *message_id* - The value of the Message-ID
				header field.
- *status* - The value of the Status header field.
- *byte_range* - The value of the Byte-Range header
				field.


## Developer Guide


### Overview


In order to answer a SIP session carying MSRP the [init uas](#dev_init_uas)
	function should be used. Conversely for starting a MSRP call as a UAC, one
	can use the [init uac](#dev_init_uac) function.


After initializing the session with either of the above functions, the SIP call
	will be further handled by the module and notifications regarding significant SIP
	level events and received MSRP requests and responses will be delivered via
	registering callback functions.


MSRP SEND requests can be sent with the [send message](#dev_send_message) function
    after the sessions is established, which will be signaled by the
    *msrp_ua_notify_cb_f* callback with the
    *MSRP_UA_SESS_ESTABLISHED* event.


Received MSRP requests, transaction responses and local send timeouts will be
    signaled via the *msrp_ua_req_cb_f* and
    *msrp_ua_rpl_cb_f* callbacks.


### Available Functions


#### init_uas(msg, accept_types, hdl)


This function will intialize a MSRP UA session based on a received SIP
        INVITE.


Meaning of the parameters is as follows:


- *struct sip_msg *msg* - the SIP message
- *str *accept_types* - the value of the
                "accept-types" attribute to include in the SDP offer.
- *struct msrp_ua_handler *hdl* - handler
                structure used to register the callbacks for SIP level and MSRP
                level notifications.


```c title="struct msrp_ua_handler structure"
struct msrp_ua_handler {
	/* name of this registration */
	str *name;
	/* parameter to be passed to msrp_req_cb and msrp_rpl_cb callbacks */
	void *param;
	/* callback for SIP level notifications */
	msrp_ua_notify_cb_f notify_cb;
	/* callback for receving MSRP requests */
	msrp_ua_req_cb_f msrp_req_cb;
	/* callback for receving MSRP responses */
	msrp_ua_rpl_cb_f msrp_rpl_cb;
};
```


```c title="msrp_ua_notify_cb_f prototype"
typedef int (*msrp_ua_notify_cb_f)(struct msrp_ua_notify_params *params,
	void *hdl_param);
```


```c title="struct msrp_ua_notify_params structure"
struct msrp_ua_notify_params {
	/* event type */
	enum msrp_ua_event_type event;
	/* SIP message */
	struct sip_msg *msg;
	/* SDP "accept-types" attribute in case of MSRP_UA_SESS_ESTABLISHED event */
	str *accept_types;
	/* MSRP UA session ID */
	str *session_id;
};
```


```c title="enum msrp_ua_event_type"
enum msrp_ua_event_type {
	/* session established (ACK sent/received) */
	MSRP_UA_SESS_ESTABLISHED = 1,
	/* failed to establish session (negative reply/timeout etc.) */
	MSRP_UA_SESS_FAILED,
	/* BYE received/sent(in case of session timeout) */
	MSRP_UA_SESS_TERMINATED
};
```


```c title="msrp_ua_req_cb_f prototype"
typedef int (*msrp_ua_req_cb_f)(struct msrp_msg *req, void *hdl_param);
```


```c title="msrp_ua_rpl_cb_f prototype"
/* an MSRP transaction timeout will be signaled by calling this callback
 * with a NULL rpl parameter */
typedef int (*msrp_ua_rpl_cb_f)(struct msrp_msg *rpl, void *hdl_param);
```


#### init_uac(accept_types, from_uri, to_uri, ruri, hdl)


This function will intialize a MSRP UA session by sending a SIP INVITE to
        a destination.


Meaning of the parameters is as follows:


- *str *accept_types* - the value of the
                "accept-types" attribute to include in the SDP offer.
- *str *from_uri* - URI to use in the From
                header of the INVITE.
- *str *to_uri* - URI to use in the To
                header of the INVITE.
- *str *ruri* - Request URI to use in the for
                the INVITE.
- *struct msrp_ua_handler *hdl* - handler
                structure used to register the callbacks for SIP level and MSRP
                level notifications.


#### end_session(session_id)


This function terminates an MSRP session.


Meaning of the parameters is as follows:


- *str *session_id* - MSRP UA session ID.


#### send_message(session_id, mime, body, failure_report, success_report)


This functions sends an MSRP SEND request to the peer.


Meaning of the parameters is as follows:


- *str *session_id* - MSRP UA session ID.
- *str *mime* - MIME content
				type of this message. If NULL, an empty message will be sent.
- *str *body* - actual message
				body. If NULL, an empty message will be sent.
- *enum msrp_failure_report_type failure_report* -
                MSRP Failure Report type - yes, no or partial.
- *int success_report* - indication whether to
                request an MSRP Failure Report or not.


```c title="enum msrp_failure_report_type"
enum msrp_failure_report_type {
	MSRP_FAILURE_REPORT_YES,
	MSRP_FAILURE_REPORT_PARTIAL,
	MSRP_FAILURE_REPORT_NO
};
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
