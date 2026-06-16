---
title: "RTP Relay Module"
description: "The purpose of this module is to simplify the usage of different RTP Relays Servers (such as RTPProxy, RTPEngine, Media Proxy) in OpenSIPS scripting, as well as to provide various complex features that rely on the usage of RTP relays (such as media re-anchoring)."
---

## Admin Guide


### Overview


The purpose of this module is to simplify the usage of different
		RTP Relays Servers (such as RTPProxy, RTPEngine, Media Proxy)
		in OpenSIPS scripting, as well as to provide various complex
		features that rely on the usage of RTP relays (such as media re-anchoring).


The module provides the logic to engage a specific RTP relay in
		a call during initial INVITE, and then it will handle the entire
		communication with the RTP relay, until the call terminates.


Moreover, one can specify various flags that modify the way RTP
		engines use each user agent's SDP - these flags are persistent
		throughout the entire RTP session, and are being used for further
		in-dialog requests. These flags can be specified through the 
		[rtp relay](#pv_rtp_relay) and/or
		[rtp relay peer](#pv_rtp_relay_peer) variables at initial INVITE,
		or through the absolute
		[rtp relay caller](#pv_rtp_relay_caller) and
		[rtp relay callee](#pv_rtp_relay_callee) variables, and are then
		passed along with the RTP relay context until the end of the call.
		They can also be modified during sequential in-dialog requests.


This is not a stand-alone module that communicates directly with RTP relays,
		but rather a generic interface that is able to interact with the
		modules that interact with each specific RTP Relay
		(such as *rtpproxy* or *rtpengine*)
		and implement their specific communication protocol.


### Multiple Branches


The module is able to handle RTP relay for multiple branches, with
		different flags flavors. Each branch can have its flags tuned through
		the [rtp relay](#pv_rtp_relay) variable - if the variable
		is provisioned in the main route, then the flags are inherited
		by all further branches, unless specifically modified per branch.
		To modify a specific branch, one needs to specify the desired
		branch index as variable index
		(i.e. *$(rtp_relay[1]) = "cor"*).
		When provisioned in a branch route, the flags are only changed
		for that specific branch.


Starting with OpenSIPS 3.3, branches can be identified based
		on their participant's to_tag. This features becomes handy when
		using *rtp_relay* in B2B mode, where peers
		can no longer be identified simply by an index. However, this
		feature works in dialog secenatios as well.


The multiple branches behavior is handled differently by the
		back-end engine, depending on its capabilities. For example,
		*rtpengine* is able to natively support calls
		with multiple branches, whereas for *rtpproxy*,
		each branch is emulated in a different session with a different
		call-id.


When the call gets answered and a single branch remains active,
		all the other branches are destroyed and only the established
		branches remain active throughout the call.


### RTP Relay Engines


The module does not perform any SDP mangling itself, it is just an
		enabler of the different backends supported, such as RTPProxy
		or RTPEngine. These backends are called RTP Relay angines and they
		need to be specified when RTP Relay is being engaged.


Starting with OpenSIPS 3.6, the module has been enhanced with an
		internal RTP Engine, which can be used to perform
		*manual/custom* SDP mangling by running a set of
		routes when an RTP event (such as offer, answer, delete) happens.
		This can be enabled by engaging RTP Relay with the *route*
		engine. If the defined routes are not being defined, then the SDP does not
		change. For more information, please check the
		[route offer](#param_route_offer),
		[route answer](#param_route_answer) and
		[route delete](#param_route_delete) parameters.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Dialog* module - used to keep track of in-dialog requests.
- *RTP Relay* module(s) - such *rtpproxy*, or
				*rtpengine*, or any module that implements the
				*rtp_relay* interface.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### route_offer (string)


Route that is being run when an SDP offer happens (i.e.
			an INVITE with SDP is being processed).


When the route is executed, the following parameters are
			being populated:


- *callid* - the callid of the call being processed.
- *from_tag* - the from_tag of the call being processed.
- *to_tag* - the to_tag, if exists, of the call being processed.
- *branch* - the branch that RTP relay is being engaed
				on - if engaged in the main branch, *-1* is used.
- *body* - optional, if an explicit body is being used,
				otherwise the message's body should be considered.
- *set* - the rtp relay set being used for the call.
- *node* - optional, an node Engine idenfifier - this
				is a user populated value returned after running a
				*route_offer* route (see the return values section
				below).
- *ip* - optional, the IP being specified in the
				[rtp relay](#pv_rtp_relay) variable for the current peer.
- *type* - optional, the RTP type being specified in the
				[rtp relay](#pv_rtp_relay) variable for the current peer.
- *in-iface* - optional, the inbound interface
				that should be used for this peer.
- *out-iface* - optional, the outbound interface
				that should be used for this peer.
- *ctx-flags* - optional, global flags that are
				being specified in the [rtp relay ctx](#pv_rtp_relay_ctx) variable.
- *flags* - optional, flags specified for this peer.
- *peer* - optional, peer flags specified for
				the corresponding peer;


When running the route, the following values are expected to be returned:
			
			
			*body* - the newly created body to be offered. If
				not returned, the body is left unchanged.
			
			
			*node* - optional, a node to be identified for further
				routes/commands executed.
		*Default value is "rtp_relay_offer".*


```c title="Set route_offer parameter"
...
modparam("rtp_relay", "route_offer", "custom_rtp_offer")
...
```


```c title="route_offer route usage"
...
route[rtp_relay_offer] {
	# manually engaging RTPEngine, get the SDP, and replace it in the message
	return (1, $var(body));
}
...
```


#### route_answer (string)


Route that is being run when an SDP answer happens (i.e.
			a 183 or 200 OK reply with SDP is being processed).


When the route is executed, the following parameters are
			being populated:


- *callid* - the callid of the call being processed.
- *from_tag* - the from_tag of the call being processed.
- *to_tag* - the to_tag, if exists, of the call being processed.
- *branch* - the branch that RTP relay is being engaed
				on - if engaged in the main branch, *-1* is used.
- *body* - optional, if an explicit body is being used,
				otherwise the message's body should be considered.
- *set* - the rtp relay set being used for the call.
- *node* - optional, an node Engine idenfifier - this
				is a user populated value returned after running a
				*route_offer* route.
- *ip* - optional, the IP being specified in the
				[rtp relay](#pv_rtp_relay) variable for the current peer.
- *type* - optional, the RTP type being specified in the
				[rtp relay](#pv_rtp_relay) variable for the current peer.
- *in-iface* - optional, the inbound interface
				that should be used for this peer.
- *out-iface* - optional, the outbound interface
				that should be used for this peer.
- *ctx->flags* - optional, global flags that are
				being specified in the [rtp relay ctx](#pv_rtp_relay_ctx) variable.
- *flags* - optional, flags specified for this peer.
- *peer* - optional, peer flags specified for
				the corresponding peer;


When running the route, the following values are expected to be returned:
			
			
			*body* - the newly created body to be answered. If
				not returned, the body is left unchanged.
		*Default value is "rtp_relay_answer".*


```c title="Set route_answer parameter"
...
modparam("rtp_relay", "route_answer", "custom_rtp_answer")
...
```


```c title="route_answer route usage"
...
route[rtp_relay_answer] {
	# again, manually engaging RTPEngine
	rtpengine_answer(,, $var(body), $rb);
	return (1, $var(body));
}
...
```


#### route_delete (string)


Route that is being run when media should be disconnected
			(i.e. a CANCEL or BYE is received).


When the route is executed, the following parameters are
			being populated:


- *callid* - the callid of the call being processed.
- *from_tag* - the from_tag of the call being processed.
- *to_tag* - the to_tag, if exists, of the call being processed.
- *branch* - the branch that RTP relay is being engaed
				on - if engaged in the main branch, *-1* is used.
- *body* - optional, if an explicit body is being used,
				otherwise the message's body should be considered.
- *set* - the rtp relay set being used for the call.
- *node* - optional, an node Engine idenfifier - this
				is a user populated value returned after running a
				*route_offer* route (see the return values section
				below).
- *ctx->flags* - optional, global flags that are
				being specified in the [rtp relay ctx](#pv_rtp_relay_ctx) variable.
- *delete* - optional, delete flags specified in the
				[rtp relay ctx](#pv_rtp_relay_ctx) variable.


Return values are not needed.
		*Default value is "rtp_relay_delete".*


```c title="Set route_delete parameter"
...
modparam("rtp_relay", "route_delete", "custom_rtp_delete")
...
```


```c title="rtp_relay_delete route usage"
...
route[rtp_relay_delete] {
	# manually removing RTPEngine session
	rtpengine_delete();
}
...
```


#### route_copy_offer (string)


Route that is being executed when a new call's SDP is being copied.


When the route is executed, the following parameters are
			being populated:


- *callid* - the callid of the call being processed.
- *from_tag* - the from_tag of the call being processed.
- *to_tag* - the to_tag, if exists, of the call being processed.
- *branch* - the branch that RTP relay is being engaed
				on - if engaged in the main branch, *-1* is used.
- *set* - the rtp relay set being used for the call.
- *node* - optional, an node Engine idenfifier - this
				is a user populated value returned after running a
				*route_offer* route (see the return values section
				below).
- *flags* - optional, flags that are being specified
				by the module which is copying the SDP.
- *copy-ctx* - optional, an copy context identifier -
				this is a user populated value returned after running a
				*route_copy_offer* route (see the return values
				section below).


When running the route, the following values are expected to be returned:
			
			
			*copy-ctx* - optional, a copy context identifier
				that can be later used to identify the current copy session.
		*Default value is "rtp_relay_copy_offer".*


```c title="Set rtp_relay_copy_offer parameter"
...
modparam("rtp_relay", "route_copy_offer", "custom_rtp_copy_offer")
...
```


```c title="Set rtp_relay_copy_offer usage"
...
route[rtp_relay_copy_offer] {
	# instruct a media engine to fork media and assign an identifier
	# that shall be stored in the $var(handle) variable
	return (1, $var(handle));
}
...
```


#### route_copy_answer (string)


Route that is being run when an SDP for the copied stream is received.
			(i.e. a CANCEL or BYE is received).


When the route is executed, the following parameters are
			being populated:


- *callid* - the callid of the call being processed.
- *from_tag* - the from_tag of the call being processed.
- *to_tag* - the to_tag, if exists, of the call being processed.
- *branch* - the branch that RTP relay is being engaed
				on - if engaged in the main branch, *-1* is used.
- *body* - optional, if an explicit body is being used,
				otherwise the message's body should be considered.
- *set* - the rtp relay set being used for the call.
- *node* - optional, an node Engine idenfifier - this
				is a user populated value returned after running a
				*route_offer* route (see the return values section
				below).
- *flags* - optional, flags that are being specified
				by the module which is copying the SDP.
- *copy-ctx* - optional, an copy context identifier -
				this is a user populated value returned at the end of
				*route_copy_offer* execution.


*Default value is "rtp_relay_copy_answer".*


```c title="Set rtp_relay_copy_answer parameter"
...
modparam("rtp_relay", "route_copy_answer", "custom_rtp_copy_answer")
...
```


```c title="Set rtp_relay_copy_answer usage"
...
route[rtp_relay_copy_answer] {
	# feed the received $param(body) to the media engine that is forking the call
	# copy instance is identified by the $param(copy-ctx) variable
}
...
```


#### route_copy_delete (string)


Route that is being run when media fork should be removed.


When the route is executed, the following parameters are
			being populated:


- *callid* - the callid of the call being processed.
- *from_tag* - the from_tag of the call being processed.
- *to_tag* - the to_tag, if exists, of the call being processed.
- *branch* - the branch that RTP relay is being engaed
				on - if engaged in the main branch, *-1* is used.
- *body* - optional, if an explicit body is being used,
				otherwise the message's body should be considered.
- *set* - the rtp relay set being used for the call.
- *node* - optional, an node Engine idenfifier - this
				is a user populated value returned after running a
				*route_offer* route (see the return values section
				below).
- *flags* - optional, flags that are being specified
				by the module which is copying the SDP.
- *copy-ctx* - optional, an copy context identifier -
				this is a user populated value returned at the end of
				*route_copy_offer* execution.


Return values are not needed.


*Default value is "rtp_relay_copy_delete".*


```c title="Set rtp_relay_copy_delete parameter"
...
modparam("rtp_relay", "route_copy_delete", "custom_rtp_copy_delete")
...
```


```c title="Set rtp_relay_copy_delete usage"
...
route[rtp_relay_copy_delete] {
	# remove the copy instance is identified by the $param(copy-ctx) variable
}
...
```


### Exported Functions


#### rtp_relay_engage(engine, [set])


Engages the RTP Relay *engine* for the current initial
		INVITE. After calling this function, the entire RTP relay communication
		will be handled by the module itself, without having to intervene for any
		further in-dialog requests/replies (unless you specifically want to).


The function is not performing the media requests on the spot,
		but rather registers the hooks to automatically handle any
		further media requests.


The RTP session modifiers used are the ones provisioned through the
		[rtp relay](#pv_rtp_relay),
		[rtp relay peer](#pv_rtp_relay_peer),
		[rtp relay caller](#pv_rtp_relay_caller) and/or
		[rtp relay callee](#pv_rtp_relay_callee) variables.


The function can be called from the main request route - in this case
		the RTP relay will be engaged for any further branches created, or from
		the branch route - in this case the RTP relay will only be engaged for
		the branch where it was called, or that has an associated
		*rtp_relay* provisioned.


When using the scope-relative [rtp relay](#pv_rtp_relay)
		variable together with this function, note that its meaning depends
		on where it is used. In the main request route of the initial INVITE,
		[rtp relay](#pv_rtp_relay) refers to the caller and
		[rtp relay peer](#pv_rtp_relay_peer) refers to the callee. In a
		branch route, [rtp relay](#pv_rtp_relay) refers to the callee
		branch and [rtp relay peer](#pv_rtp_relay_peer) refers to the
		caller. To avoid depending on this route scope, use
		[rtp relay caller](#pv_rtp_relay_caller) and
		[rtp relay callee](#pv_rtp_relay_callee) instead.


Meaning of the parameters is as follows:


- *engine(string)* - the RTP relay engine
				to be used for the call (i.e. *rtpproxy*,
				*rtpengine* or *route*)
- *set(int, optional)* - the set used for this call.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE.


```c title="rtp_relay_engage usage"
...
if (is_method("INVITE") && !has_totag()) {
	xlog("SCRIPT: engaging RTPProxy relay for all branches\n");
	$rtp_relay = "co";
	$rtp_relay_peer = "co";
	rtp_relay_engage("rtpproxy");
}
...
		
```


### Exported MI Functions


#### rtp_relay:list


Replaces obsolete MI command: *rtp_relay_list*.


Lists all the RTP Relay sessions engaged.


Parameters:


- *engine* - (optional) the RTP
					relay engine (i.e. *rtpproxy*
					or *rtpengine*).
- *set* - (optional) the RTP
					relay set. When used, the *engine*
					parameter must also be specified.
- *node* - (optional) the RTP
					relay node. When used, the *engine*
					parameter must also be specified.


```c title="rtp_relay:list usage"
...
## list all sessions
$ opensips-cli -x mi rtp_relay:list

## list all sessions going through a specific RTP node
$ opensips-cli -x mi rtp_relay:list rtpproxy udp:127.0.0.1:2222
...
			
```


#### rtp_relay:update


Replaces obsolete MI command: *rtp_relay_update*.


Updates/Re-engages the RTP relays in all ongoing RTP relay sessions.


This function can be used to trigger dialog in-dialog
				updates for certain ongoing RTP sessions. For all matched
				sessions, it re-engages an RTP Relay offer/answer session,
				then sends re-INVITEs to call's participants to with
				the updated SDP.


*Note:*Running the command without a filter
				(such as *engine* or *set*)
				will cause all RTP relay sessions to be
				re-engaged.


*Note:*When enforcing a new node,
				it is not guaranteed to be used - if the node is not
				avaialble, but a different one is, the active one will
				be chosen.


*Note:*If the node is being changed,
				the module tries to unforce the previous RTP relay
				session, even though it might not work.


Parameters:


- *engine* - (optional) the RTP
					relay engine (i.e. *rtpproxy*
					or *rtpengine*) to be used
					as filter.
- *set* - (optional) the RTP
					relay set to be used as filter. If missing, the
					same set will be used as it was initially engaged
					for.
- *node* - (optional) the RTP
					relay node to be used as filter.
- *new_set* - (optional) a new RTP
					Relay set to be used for the call.
- *new_node* - (optional) a new RTP
					node to be used for the call. If
					*new_set* is missing, the
					same set will be used.


```c title="rtp_relay:update usage"
...
## update all sessions that are using rtpproxy
$ opensips-cli -x mi rtp_relay:update rtpproxy
...
			
```


#### rtp_relay:update_callid


Replaces obsolete MI command: *rtp_relay_update_callid*.


Updates/Re-engages the RTP relays in all ongoing RTP relay sessions.


The function basically works in the same manner as
				[mi update](#mi_update), but is to be
				used to update a specific callid. In addition, one can
				also update the *engine* and
				*flags* used for the particular
				session.


Parameters:


- *callid* - the callid used to
					match the dialog to be updated.
- *engine* - (optional) the new RTP
					relay engine (i.e. *rtpproxy*
					or *rtpengine*) to be used. If
					missing, the same initial engine is used.
- *set* - (optional) the new RTP
					relay set to be used. If missing, the default
					same set will be used as it was initially engaged
					for.
- *node* - (optional) the RTP
					relay node to be used. If not specified, the first
					available node is used.
- *flags* - (optional) a JSON
					contining the *caller* and/or
					*callee* nodes, which contain
					new flags that should be used for the session. Only
					explicitely specified flags will be overwritten.


```c title="rtp_relay:update_callid usage"
...
## update a call with a working RTPproxy node
$ opensips-cli -x mi rtp_relay:update_callid 1-3758963@127.0.0.1 rtpproxy

## update a call to use RTPEngine with a SRTP SDP for caller
$ opensips-cli -x mi rtp_relay:update_callid callid=1-3758963@127.0.0.1 \
	flags='{ "caller":{"type":"SRTP", "flags":"replace-origin"},
		"callee":{"type":"RTP", "flags"="replace-origin"}}'
...
			
```


### Exported Pseudo-Variables


#### $rtp_relay


Is used to provision the RTP back-end flags for the
				current peer. This variable is scope-relative: in the
				main request route of the initial INVITE it provisions
				the caller, while in the branch route or replies of the
				initial INVITE transaction it provisions the callee branch.


For a sequential request, the variable represents the
				flags used for the UAC that generated the request. When
				used in a reply, the other UAC's flags are provisioned.


Use [rtp relay caller](#pv_rtp_relay_caller) and
				[rtp relay callee](#pv_rtp_relay_callee) when the script
				needs to address the caller or callee side directly,
				independent of the route scope.


In an initial INVITE scope, the variable can be
				provisioned per branch, by using the variable's index.


For each UAC/peer, there are several flags that can be
				configured:


- *flags* (default, when
					variable is used without a name) - are the flags associated
					with the current UAC - they are passed along with the offer
					command
- *peer* - these flags are
					passed along in the offer command, but they are flags associated
					with the other UAC/peer
- *ip* - the IP that should be
					advertised in the resulted SDP.
- *type* - the RTP type used
					by the current UAC (currently only used by *rtpengine*)
- *iface* - the interface
					used for the traffic coming from this UAC.
- *body* - the body to be used
					for the UAC.
- *delete* - flags to be used
					when the media session is terminated/deleted.
- *disabled* - provisioned
					as an integer, it is used to disable RTP relay for this UAC.


#### $rtp_relay_peer


This variable has the same meaning and parameters as the
				[rtp relay](#pv_rtp_relay) variable, except that it
				is used to provision the other UAC's flags, except the
				current one. All other fields are similar.


#### $rtp_relay_caller


This variable has the same parameters as
				[rtp relay](#pv_rtp_relay), but always provisions
				the caller side of the RTP relay session, independent of
				the route where it is used.


In the main request route of the initial INVITE this is
				equivalent to [rtp relay](#pv_rtp_relay). In a branch
				route or in replies of the initial INVITE transaction this
				is equivalent to [rtp relay peer](#pv_rtp_relay_peer).
				After the dialog is established, it addresses the stored
				caller leg directly.


#### $rtp_relay_callee


This variable has the same parameters as
				[rtp relay](#pv_rtp_relay), but always provisions
				the callee side of the RTP relay session, independent of
				the route where it is used.


In the main request route of the initial INVITE this is
				equivalent to [rtp relay peer](#pv_rtp_relay_peer). In a
				branch route or in replies of the initial INVITE
				transaction this is equivalent to
				[rtp relay](#pv_rtp_relay). After the dialog is
				established, it addresses the stored callee leg directly.


#### $rtp_relay_ctx()


This variable can be used to provide information about the
				RTP context, information that is not associated with any of
				the involved peers.


The following settings can be used:


- *callid* - The callid
					to be used for all communication with the rtp server.
					If not specified, it is taken from the message/dialog.
- *from_tag* - The from-tag
					to be used for all communication with the rtp server.
					If not specified, it is taken from the message/dialog.
- *to_tag* - The to-tag
					to be used for all communication with the rtp server.
					If not specified, it is taken from the message/dialog.
- *flags* - Generic flags
					to be sent to all offer/answer requests.
- *delete* - flags sent
					when the relay session is terminated.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
