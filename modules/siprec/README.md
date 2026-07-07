---
title: "SIPREC Module"
description: "This module provides the means to do calls recording using an external recorder - the entity that records the call is not in the media path between the caller and callee, but it is completely separate, thus it can not affect by any means the quality of the conversation. This is done in a ..."
---

## Admin Guide


### Overview


This module provides the means to do calls recording using an
		external recorder - the entity that records the call is not in
		the media path between the caller and callee, but it is completely
		separate, thus it can not affect by any means the quality of the
		conversation. This is done in a standardized manner, using
		the [SIPREC
			Protocol](https://tools.ietf.org/html/rfc7866), thus it can be used by any recorder that
		implements this protocol.


Since an external server is used to record calls, there are no
		constraints regarding the location of the recorder, thus it can be
		placed arbitrary. This offers huge flexibility to your architecture
		configuration and various means for scaling.


The work for this module has been sponsored by the [OrecX Company](http://www.orecx.com/). This module is
		fully integrated with the OrecX Call Recording products.


### How it works


The full architecture of a SIP Media Recording platform is
		documented in [RFC 7245](https://tools.ietf.org/html/rfc7245). According to this architecture, this OpenSIPS
		module implements a SRC (Session Recording Client) that instructs a SRS
		(Session Recording Server) when new calls are started, the
		participants of the calls and their profiles. Based on this data, the
		SRS can decide whether the call should be recorded or not.


From SIP signalling perspective, the module does not change the call
		flow between the caller and callee. The call is established just as
		any other calls that are not recorded. But for each call that has
		*SIPREC* engaged, a completely separate SIP session
		is started by the SRC (OpenSIPS) towards the SRS, using the [OpenSIPS Back-2-Back module](../b2b_entities). The
		*INVITE* message sent to the SRS contains a
		multi-part body consisting of two parts:


- *Recording SDP* - the SDP of the Media Server
			that will *fork* the RTP to the recorder.
- *Participants Metadata* - an XML-formatted
			document that contains information about the participants. The
			structure of the document is detailed in [RFC 7865](https://tools.ietf.org/html/rfc7865).


The SRS can respond with negative reply, indicating that the session
		does not need to be recorded, or with a positive reply (200 OK),
		indicating in the SDP body where the media RTP should be
		*sent/forked*. When the call ends, the SRC must
		send a *BYE* message to the SRS, indicating that
		the recording should be completed.


Full examples of call flows can be found in [RFC 8068](https://tools.ietf.org/html/rfc8068).


### Media Handling


Since OpenSIPS is a SIP Proxy, it does not have any Media Capabilities
		by itself. Thus we need to rely on a different Media Server to capture
		the RTP traffic and fork it to the SRS. The current implementation
		supports both the [RTPProxy](http://www.rtpproxy.org/)
		(through the [RTPProxy module](../rtpproxy)) and
		[RTPEngine](https://github.com/sipwise/rtpengine)
		(through the [RTEngine module](../rtpengine)) Media
		Servers.


### SRS Failover


The *siprec* module supports failover between
		multiple SRS servers - when calling the *[siprec start recording](#func_siprec_start_recording)* function, one
		can provision multiple SRS URIs, separated by comma. In this case, OpenSIPS
		will try to use them in the same order specified, one by one, until
		either one of them responds with a positive reply (200 OK), or the
		response code is one of the codes matched by the *[skip failover codes](#param_skip_failover_codes)* regular expression.
		In the latter case the call is not recorded at all.


### Limitations


This module only implements the SRC
	specifications of the [SIPREC RFC](https://tools.ietf.org/html/rfc7866). In
	order to have a full recording solution, you will also need a SRS solution
	such as [Oreka](http://oreka.sourceforge.net/) - an
	open-source project provided by [OrecX](http://www.orecx.com/).


Although this module provides all the necessary tools to do calls
		recording, it does not fully implement the entire
		*SIPREC* SRC specifications. This list contains
		some of the module's limitations:


- *There is no Recording Indicator played to the
				callee* - since OpenSIPS continues to act as a proxy,
			there is no way for us to postpone the media between the caller
			and callee to play a Recording Indicator message.
- *Cannot handle Recording Sessions initiated by
				SRS* - we do not support the scenario when an SRS
			suddenly decides to record a call in the middle of the dialog.
- *OpenSIPS cannot be "queried" for ongoing
				recording sessions* - this is scheduled to be
			implemented in further releases.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *TM* - Transaction module.
- *Dialog* - Dialog module for keeping track of the call.
- *RTP_Relay* - RTP Relay module used for controlling the
				Media Servers that will fork the media.
- *B2B_ENTITIES* - Back-2-Back module used for communicating with the SRS.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### skip_failover_codes (string)


A regular expression used to specify the codes that should prevent
			the module from failing over to a new SRS server.


*By default any negative reply generates a failover.*


```opensips title="Set skip_failover_codes parameter"
...
# do not failover on 408 reply codes
modparam("siprec", "skip_failover_codes", "408")

# do not failover on 408 or 487 reply codes
modparam("siprec", "skip_failover_codes", "408|487")

# do not failover on any 3xx or 4xx reply code
modparam("siprec", "skip_failover_codes", "[34][0-9][0-9]")
...
		
```


### Exported Events


#### E_SIPREC_START


This event is raised when a SIPREC call is established and a call
				starts to be recorded.


Parameters:


- *dlg_id* - dialog id ("did")
					of the call being recorded;
- *dlg_callid* - Call-Id of the call being
					recorded;
- *callid* - Call-Id (B2B id) of the
					SIPREC call;
- *session_id* - SIPREC UUID of the recording call;
- *server* - the SIPREC server handing this call;
- *instance* - the SIPREC instance this event is triggered for;


#### E_SIPREC_STOP


This event is raised when a SIPREC call is terminated.


This event exposes the same parameters as the
			[E SIPREC START](#event_e_siprec_start) event.


### Exported Functions


#### siprec_start_recording(srs[, instance])


Calling this function on an initial
				*INVITE* engages call recording to SRS(s) for
				that call. Note that it does not necessary mean that the call
				will be recorded - it just means that OpenSIPS will query
				instruct the SRS that a new call has started, but the SRS
				might decide that the recording is disabled for those
				participants.


*Note* that the call recording is not
				started right away, but only when the callee provides an
				SDP as well (usually in a 200 OK, or possibly a 183 Ringing).


*Note* if you only want to start recording
				when the call is established (200 OK is received), then you
				should call this function in the onreply route processing that
				200 OK.


Parameters:


- *srs* (string) - a comma-separated list of SRS
					URIs. These URIs are used in the order specified. See
					[siprec srs failover](#srs_failover) for more
					information.
- *instance* (string, optional) - used to
					start a particular SIPREC *instance*.
					When missing, the *default* instance
					is started.


The function returns false when an internal error is triggered
				and the call recording setup fails. Otherwise, if all the
				internal mechanisms are activated, it returns true.


This function can be used from REQUEST_ROUTE.


```opensips title="Use siprec_start_recording() function with a single SRS"
	...
	if (!has_totag() && is_method("INVITE")) {
		$var(srs) = "sip:127.0.0.1";
		xlog("Engage SIPREC call recording to $var(srs) for $ci\n");
		siprec_start_recording($var(srs));
	}
	...
	
```


```opensips title="Use siprec_start_recording() function with multiple SRS servers"
	...
	if (!has_totag() && is_method("INVITE")) {
		$var(srs) = "sip:127.0.0.1, sip:127.0.0.1;transport=TCP";
		xlog("Engage SIPREC call recording to servers $var(srs) for $ci in inbound group\n");
		siprec_start_recording($var(srs), "inbound");
	}
	...
	
```


```opensips title="Use siprec_start_recording() function with custom XML values for participants"
	...
	$xml(caller_xml) = "<nameID></nameID>";
	$xml(caller_xml/nameID.attr/aor) = "sip:6024151234@10.0.0.11:5090";
	$xml(caller_xml/nameID) = "<name>test</name>";
	$siprec(caller) = $xml(caller_xml/nameID);
	siprec_start_recording($var(srs));
	...
	
```


```opensips title="Use siprec_start_recording() function with custom headers"
	...
	$siprec(headers) = "X-MY-CUSTOM_HDR: 1\r\n";
	siprec_start_recording($var(srs));
	...
	
```


```opensips title="Use siprec_start_recording() function with custom group and session extensions"
	...
	$var(temp) = "
```


#### siprec_pause_recording([instance])


Pauses the recording for the ongoing call. Should be called after
				the dialog has matched.


Parameters:


- *instance* (string, optional) - used to
					pause a particular SIPREC *instance*.
					When missing, the *default* instance
					is paused.


This function can be used from any route.


```opensips title="Use siprec_pause_recording()"
	...
	if (has_totag() && is_method("INVITE")) {
		if (is_audio_on_hold())
			siprec_pause_recording();
	}
	...
	
```


#### siprec_resume_recording([instance])


Resumes the recording for the ongoing call. Should be called after
				the dialog has matched.


Parameters:


- *instance* (string, optional) - used to
					resume a particular SIPREC *instance*.
					When missing, the *default* instance
					is resumed.


This function can be used from any route.


```opensips title="Use siprec_resume_recording()"
	...
	if (has_totag() && is_method("INVITE")) {
		if (!is_audio_on_hold())
			siprec_resume_recording();
	}
	...
	
```


#### siprec_stop_recording([instance])


Stops the recording for the ongoing call. Should be called for SIPREC
				sessions that have been previously started.


Parameters:


- *instance* (string, optional) - used to
					stop a particular SIPREC *instance*.
					When missing, the *default* instance
					is stopped.


This function can be used from any route.


```opensips title="Use siprec_stop_recording()"
	...
	if (has_totag() && is_method("INVITE")) {
		if (is_audio_on_hold())
			siprec_stop_recording();
	}
	...
	
```


#### siprec_send_indialog([hdrs[, body]])


Sends an arbitrary in-dialog request to the SRS.


This function can be used from any route.


Parameters:


- *headers* (string, optional) - a set of headers
					that will be added to the generated request.
- *body* (string, optional) - the body that
					will be added to the generated request.
- *instance* (string, optional) - used to
					send a request within a particular SIPREC *instance*.
					When missing, the request is sent in to the *default*
					instance.


```opensips title="Use siprec_send_indialog()"
	...
	if (has_totag() && is_method("INFO")) {
		siprec_send_indialog("Content-Type: $hdr(Content-Type)\r\n", $rb);
	}
	...
	
```


### Exported Pseudo-Variables


#### $siprec


Used to modify/describe different siprec sessions
				parameters that should be taken into account by the
				[siprec start recording](#func_siprec_start_recording) function.


The variable can be indexed with the *instance*
				the user wants to tune the variable for. If missing, the
				the *default* instance is being altered.


The context of this variable is only limited to the current
				message processed - it is not available at the transaction
				or dialog level.


Any of this setting is optional.


Settings that can be provisioned:


- *group* - an opaque value that will be inserted
					in the SIPREC body and represents the name of the group that can be
					used to classify calls in certain profiles. If missing, no group is added.
- *caller* - an XML block containing information
					about the caller. If absent, the *From* header
					of the initial dialog is used to build the value.
- *callee* - an XML block containing information
					about the callee. If absent, the *To* header
					of the initial dialog is used to build the value.
- *media* - the IP that
					RTPProxy will be streaming media from. If absent
					*127.0.0.1* will be used.
					*NOTE:**media_ip* has been dropped.
- *headers* - extra headers
					that are to be added in the initial request towards the SRS.
					*NOTE:* headers must be separated by
					*\r\n* and must end with *\r\n*.
- *socket* - listening socket that the outgoing
					request towards SRS should be used.
- *from_uri* - the URI to appear in the
					*From* header of the dialog. Default value is the
					request URI. Note that this does not influence the
					*caller* information in the XML block,
					which is taken from the initial dialog.
- *to_uri* - the URI to appear in the
					*To* header of the dialog. Default value is the
					request URI. Note that this does not influence the
					*callee* information in the XML block,
					which is taken from the initial dialog.
- *group_custom_extension* - an optional XML block
					containing custom information to be added under the
					*group* tag.
					*NOTE:* if the *group* is absent this
					value will be ignored and not used anywhere.
- *session_custom_extension* - an optional XML block
					containing custom information to be added under the
					*session* tag.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
