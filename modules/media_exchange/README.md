---
title: "Media Exchange Module"
description: "This module provides the means to exchange media SDP between different SIP proxied calls, and calls started or received from a Media Server. The module itself does not have any media capabilities, it simply exposes primitives to exchange the SDP body between two or more different calls."
---

## Admin Guide


### Overview


This module provides the means to exchange media SDP between different
		SIP proxied calls, and calls started or received from a Media Server.
		The module itself does not have any media capabilities, it simply
		exposes primitives to exchange the SDP body between two or more different
		calls.


The module can both originate calls, pushing an existing SDP to a
		media server, to playback, or simply record an existing RTP, as well
		as take the SDP of a new call and inject the SDP into an existing,
		proxied sip call. In order to manipulate the new calls, either generated,
		or terminated, the module behaves as a back-to-back user agent with the
		aim of the [OpenSIPS B2B entities module](../b2b_entities).


In terms of the SDP media exchanged, the module can have two different
		modes:


- *Two way Media* - in this mode, the media of a new
			call will be pushed towards one of the legs of an existing call. This
			will result in a party of the call talking with the Media Server. By
			default, the other participant of the call will be put on hold, but this
			behavior can be tuned when the new leg is originated.
- *Fork Media* - the new B2B call, either originated
			or terminated, will just have a copy of the RTP forked by the media
			proxy engine. In this mode, the proxied call should have had the RTP
			relay engaged path before the forked call starts. One can fork only one
			media leg, or both legs. *NOTE:* RTPProxy currently
			does not support stopping media streaming, therefore if the streaming
			call terminates, RTPProxy will continue streaming, even if there is no
			one listening on the other end.


This module can provide different functionalities and can be used in various
		use cases, such as:


- *Call Recording* - similar to the [OpenSIPS SIPREC](../siprec) module, it can be used to fork the
			RTP media to a new SIP destination, but without the SIPREC payload.
- *Call Listening* - one might want to call into
			OpenSIPS and start listening an existing call.
- *Call Announcements* - inject an announcement from a
			Media Server to the participants of an ongoing call.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM* - Transaction module.
- *Dialog* - Dialog module for keeping track of the proxied calls.
- *RTP Relay* - optional, when the initial
				call either uses RTP Relay, or when using the media forking mode.
- *B2B_ENTITIES* - Back-2-Back module used form
					manipulating calls with the Media Server.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Functions


#### media_fork_to_uri(URI[, leg][, headers][, medianum][, instance])


Behaves as a B2B user agent client to initiate a call to a SIP
				URI and then stream the media to the SDP received in the 200
				OK response.


Can be called multiple times, and will create a new call for
				each invocation. The generated calls can be identified using
				the *instance* parameter.


Parameters:


- *URI* (string) - destination where to push
						the current call's media
- *leg* (string, optional) - the leg that will
						be streamed. Possible values are *caller*,
						*callee* and *both*. If
						missing, the direction of the indialog request is used.
- *headers* (string, optional) - optional
						headers added to the generated request.
- *medianum* (integer, optional) - the media
						stream that will be forked within the call. First index is 0.
						If missing, all media streams of that leg(s) are streamed.
- *instance* (string, optional) - a unique name
					for identifying the forking instance. If missing, the
					*default* name is assumed.


This function can be used from any route.


```opensips title="Use media_fork_to_uri() function to fork media to a Media Server"
...
if (!has_totag() && is_method("INVITE"))
	media_fork_to_uri("sip:record@127.0.0.1:5080");
...
	
```


#### media_fork_from_call(callid[, leg][, medianum][, instance])


Starts streaming the media of an existing proxied call, identified
				by the *callid* parameter to the SDP in the
				request's body.


Can be called multiple times, and will accept a new call for
				each invocation. The calls can be identified using
				the *instance* parameter.


Parameters:


- *callid* (string) - the identifier of the callid
						to stream/fork media from
- *leg* (string, optional) - the leg that will
						be streamed. Possible values are *caller*,
						*callee* and *both*. If
						missing, both legs will be streamed.
- *medianum* (integer, optional) - the media
						stream that will be forked within the call. First index is 0.
						If missing, all media streams of that leg(s) are streamed,
						as long as the body has enough streams.
					*Note:* RTPProxy does not do any media mixing,
						therefore you need to make sure that the INVITE has enough SDP
						streams to handle all the media streams selected to fork.
- *instance* (string, optional) - a unique name
					for identifying the forking instance. If missing, the
					*default* name is assumed.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
				FAILURE_ROUTE and ONREPLY_ROUTE.


*NOTE:* the request of this call is completely
					handled by the B2B engine. Therefore, after running this function,
					please make sure you do not relay the message further, otherwise
					you will run into an unexpected behavior. Best thing to do is to
					exit the processing after running the function.


```opensips title="Use media_fork_from_call() function to fork all media streams of a call"
...
if (!has_totag() && is_method("INVITE") && $hdr(X-CallID) != NULL)
	media_fork_from_call($hdr(X-CallID));
...
	
```


```opensips title="Use media_fork_from_call() function to fork only the first caller's stream"
...
if (!has_totag() && is_method("INVITE") && $hdr(X-CallID) != NULL)
	media_fork_from_call($hdr(X-CallID), "caller", 0);
...
	
```


#### media_fork_pause([leg][, medianum][, instance])


Pauses an existing RTP media streaming session. This function does
				not terminate the forking call, but only stops sending the RTP.
				It also re-invites the Media Server to inform about the change.


Parameters:


- *leg* (string, optional) - the leg that will
						be paused. Possible values are *caller*,
						*callee* and *both*. If
						missing, all ongoing media sessions will be paused.
- *medianum* (integer, optional) - the media
						stream to be paused. First index is 0.
						If missing, all ongoing media streams associated to the
						selected leg will be paused.
- *instance* (string, optional) - the forking
					instance to be paused. If missing, all instances are paused.


This function can be used from any route.


```opensips title="Use media_fork_pause() function to temporarily stop the entire media stream of the call"
...
if (has_totag() && is_method("INVITE"))
	media_fork_pause();
...
	
```


#### media_fork_resume([leg][, medianum][, instance])


Resumes the RTP media stream of an existing session/call. This function
				relies on the fact that a media fork session has been previously started.


Parameters:


- *leg* (string, optional) - the leg that will
						be resumed. Possible values are *caller*,
						*callee* and *both*. If
						missing, all existing media legs that are stopped will be started.
- *medianum* (integer, optional) - the media
						stream to be paused. First index is 0.
						If missing, all ongoing media streams associated to the
						selected leg will be paused.
- *instance* (string, optional) - the forking
					instance to be resumed. If missing, all instances are resumed.


This function can be used from any route.


```opensips title="Use media_fork_resume() function to resume a forking previously stopped"
...
if (has_totag() && is_method("INVITE"))
	media_fork_resume();
...
	
```


#### media_exchange_from_uri(URI[, leg][, body][, headers][, nohold])


Originates a call to the specified URI. The SDP in the response is
				fetched and pushed towards one of the call's legs, resulting in two
				way audio between the participant of the ongoing call, and the new
				call. By default, the other participant leg is put on hold.


Can be called for an in-dialog request, such as a re-INVITE (for
				example when putting an entity on hold), or for an INFO request
				(triggered for example by a DTMF).


Parameters:


- *URI* (string) - destination used to
						originate the new call.
- *leg* (string, optional) - the leg where the
						new media SDP will be pushed. Possible values are
						*caller* and *callee*.
						If missing, the module considers it is an hold re-INVITE,
						and exchanges the media SDP of the other leg.
- *body* (string, optional) - custom body used
						for the generated INVITE. If missing, the body stored in the
						dialog associated with the involved leg will be used.
- *headers* (string, optional) - optional
						headers added to the generated request.
- *nohold* (integer, optional) - if set to true,
						the other participant will not be put on hold. This is useful
						when a new call will be generated for the other leg as well.


This function can be used from any route.


```opensips title="Use media_exchange_from_uri() function to fetch media from a Media Server's call"
...
if (has_totag() && is_method("INVITE") && is_audio_on_hold())
	media_exchange_from_uri("sip:moh@127.0.0.1:5080");
...
	
```


#### media_exchange_to_call(callid[, leg][, nohold])


Pushes the SDP of a new call received in an existing proxied
				call, resulting in two-way audio between a Media Server that
				originated the call, and the existing participant of the ongoing
				proxied call.


Parameters:


- *callid* (string) - the identifier of the callid
						to exchange media.
- *leg* (string) - the leg that will
						be streamed. Possible values are *caller*
							and *callee*.
- *nohold* (integer, optional) - if set to true,
						the other participant will not be put on hold. This is useful
						when a new call will be generated for the other leg as well.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
				FAILURE_ROUTE and ONREPLY_ROUTE.


*NOTE:* the request of this call is completely
					handled by the B2B engine. Therefore, after running this function,
					please make sure you do not relay the message further, otherwise
					you will run into an unexpected behavior. Best thing to do is to
					exit the processing after running the function.


```opensips title="Use media_exchange_to_call() function to make an announcement"
...
if (!has_totag() && is_method("INVITE") && $hdr(X-CallID) != NULL)
	media_exchange_to_call($hdr(X-CallID), "caller");
...
	
```


#### media_terminate([leg][, nohold][, instance])


Terminates an ongoing media session exchange, whether the media is
				only streamed, or two way audio is flowing. If the participant leg
				is involved in a different media exchange, the current leg is put on
				hold.


Parameters:


- *leg* (string, optional) - the leg to terminate
						the media exchange. Possible values are
						*caller* and *callee*.
						If missing, the direction of the indialog request is used.
- *nohold* (integer, optional) - if set to true,
						and the other participant is involved in a different media
						exchange, the current leg is no longer put on hold.
						*Note:* if the request that terminates
						the media exchange is a re-INVITE within the dialog, this
						function will not un-hold the other leg, as the re-INVITE
						itself should be relayed further to do that. This behavior
						can be changed by explicitly setting the
						*nohold* parameter
- *instance* (string, optional) - should only be
					used when terminating a forking instance, and represents the
					instance to terminate. It must be ommitted when terminating an
					streaming session. However, for fallback compatibility, if the
					parameter is missing, and no streaming session is found, the
					command terminates the *default* forking
					instance, if it exists.


This function can be used from any route.


```opensips title="Use media_terminate() function to terminate an announcement"
...
if (has_totag() && is_method("INVITE") && !is_audio_on_hold())
	media_terminate();
...
	
```


#### media_handle_indialog()


Searches for an existing media session started for any leg,
				and if there is ongoing session found, it performs additional
				logic for handling that request. For example, if media has been
				started in forking mode, and the INVITE is for activating on-hold,
				then the function will also pause the forked stream.


Depending on the return code of this function, one has to
				perform additional logic in the script. Possible return codes are:


- *1* - indicates that the message has been
					handled, but there's no additional tasks to be performed in
					the script.
- *-1* - indicates that there is no ongoing
					media exchange or fork happening for that call, or that there
					was no additional logic to do for that request.
- *-2* - indicates that all additional
					handling of the request was performed, and that the request
					should not be forwarded to the user agent, but instead it
					should be dropped.
- *-3* - signals an internal error.


This function can be used from REQUEST_ROUTE,
				BRANCH_ROUTE and ONREPLY_ROUTE.


```opensips title="Use media_terminate() function to terminate an announcement"
...
if (has_totag() && loose_route()) {
	# handling sequential
	media_handle_indialog();
	switch ($rc) {
	case -2:
		drop;
	case -1:
		xlog("no ongoing media session for $ci!\n");
	case 1:
		break;
}
...
	
```


### Exported MI Functions


#### media_exchange:fork_from_call_to_uri


Replaces obsolete MI command: *media_fork_from_call_to_uri*.


MI command that has the same behavior as
		[media fork to uri](#func_media_fork_to_uri), only that the triggering
		is not script driven, but exterior driven. Useful for starting
		listening a call.


Name: *media_exchange:fork_from_call_to_uri*


Parameters


- *callid* (string) - the callid of the
					dialog that will have its RTP streamed to the new call
					towards the Media Server
- *uri* (string) - the destination URI of
					the new call
- *leg* (string, optional) - indicates the
					participant leg that will have its RTP streamed in the
					new call. Possible values are "caller",
					"callee" or "both". If missing,
					both media streams are forked
- *headers* (string, optional) - extra
					headers to add to the outgoing request
- *medianum* (integer, optional) - the media
					stream that will be forked within the call. First index is 0.
					If missing, all media streams of that leg(s) are streamed.
- *instance* (string, optional) - the unique
				name of the forking instance. If missing, the
				*default* name is assumed.


MI FIFO Command Format:


```bash
# start streaming a callid to record media server
opensips-cli -x mi media_exchange:fork_from_call_to_uri \
	callid=c6fdb0f9-47dc-495d-8d38-0f37e836a531 \
	uri=sip:record@127.0.0.1:5080
		
```


#### media_exchange:from_call_to_uri


Replaces obsolete MI command: *media_exchange_from_call_to_uri*.


MI command that has the same behavior as
		[media exchange from uri](#func_media_exchange_from_uri), only that the triggering
		is not script driven, but exterior driven. Useful for injecting media
		announcements during a call.


Name: *media_exchange:from_call_to_uri*


Parameters


- *callid* (string) - the callid of the
					dialog that will have it's leg mixed with the new call
					to the Media Server
- *uri* (string) - the destination URI of
					the new call
- *leg* (string) - indicates the participant
					that will have its media pined into the new call. Possible
					values are "caller" and "callee".
- *headers* (string, optional) - extra headers
					to add to the outgoing request
- *nohold* (integer, optional) - if set to a
					non-zero value, the module avoids putting the other participant
					on hold when the media exchanging starts


MI FIFO Command Format:


```bash
# start playing back an annoucement to caller
opensips-cli -x mi media_exchange:from_call_to_uri \
	callid=c6fdb0f9-47dc-495d-8d38-0f37e836a531 \
	uri=sip:announcement@127.0.0.1:5080 \
	leg=caller
		
```


#### media_exchange:from_call_to_uri_body


Replaces obsolete MI command: *media_exchange_from_call_to_uri_body*.


MI command that does the same thing as the
		[mi from call to uri](#mi_from_call_to_uri) MI function, but
		also allows you to specify a custom body in the outgoing request.
		The body has to be specified in the mandatory *body*
		parameter, all the other parameters being the same as the ones of
		[mi from call to uri](#mi_from_call_to_uri).


#### media_exchange:terminate


Replaces obsolete MI command: *media_terminate*.


MI command to terminate an ongoing media exchange.


Name: *media_exchange:terminate*


Parameters


- *callid* (string) - the callid of the
					dialog that will have the media exchange terminated.
- *leg* (string, optional) - the leg for
					whom to terminate the media exchange. Accepted values are
					*caller*, *callee*
					and *both*. If missing, all media
					sessions are terminated.
- *nohold* (integer, optional) - if specified
					and has a non-zero value, the leg that is being terminated
					is not put on hold if the other participant still has an
					ongoing media session.
- *instance* (string, optional) - should only be
				used when terminating a forking instance, and represents the
				instance to terminate. It must be ommitted when terminating an
				streaming session. However, for fallback compatibility, if the
				parameter is missing, and no streaming session is found, the
				command terminates the *default* forking
				instance, if it exists.


MI FIFO Command Format:


```bash
# terminate a caller announcement
opensips-cli -x mi media_exchange:terminate \
	callid=c6fdb0f9-47dc-495d-8d38-0f37e836a531 \
	leg=caller
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
