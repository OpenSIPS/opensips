---
title: "sngtc Module"
description: "The **Sangoma transcoding module** offers the possibility of performing voice transcoding with the [D-series transcoding cards manufactured by Sangoma](https://wiki.sangoma.com/display/MTC/Media+Transcoding). The module makes use of the Sangoma Transcoding API in order to manage transcoding..."
---

## Admin Guide


### Overview


The **Sangoma transcoding module** offers the
	possibility of performing voice transcoding with the
	[D-series
		transcoding cards manufactured by Sangoma](https://wiki.sangoma.com/display/MTC/Media+Transcoding). The module makes use
	of the Sangoma Transcoding API in order to
	manage transcoding sessions on the dedicated equipment. For the cards
	in the network to be detected, the Sangoma SOAP server must be up and
	running (*sngtc_server* daemon).


### How it works


The module performs several modifications in the SDP body of SIP INVITE,
	200 OK and ACK messages. In all transcoding scenarios, the UAC performs early
	SDP negotiation, while the UAS does late negotiation. This way, OpenSIPS
	becomes responsible for intersecting the codec offer and answer, together with
	the management of transcoding sessions on the Sangoma cards.


This scenario brings about a couple of
	**restrictions**:


- UACs MUST only perform early SDP negotiation
- UASs MUST support late SDP negotiation (rfc 3261 requirement)


Since the *sngtc_node* library performs several memory
	allocations with each newly created transcoding session, the module uses a
	dedicated process, responsible for the management of the above-mentioned sessions. The
	*sangoma_worker* process communicates with the OpenSIPS
	UDP receivers through a series of pipes.


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *dialog*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *sngtc_node library - [download from Sangoma](https://wiki.freepbx.org/display/MTC/Media+Transcoding+Download),
					unpack, make, make install (required in order to compile this module)*.
- *sngtc_server up and running (required in order for
					this module to properly work)*.


### Exported Functions


#### sngtc_offer()


The function strips off the SDP offer from a SIP INVITE, thus
		asking for another SDP offer from the opposite endpoint (late negotiation).
		
		The following **error codes** may be returned:


- *-1* - SDP parsing error
- *-3* - internal error / no more memory


The function can be used from REQUEST_ROUTE, ONREPLY_ROUTE.


```opensips title="sngtc_offer usage"
...
	if (is_method("INVITE")) {
		t_newtran();
		create_dialog();
		sngtc_offer();
	}
...
```


#### sngtc_callee_answer([listen_if_A], [listen_if_B])


Handles the SDP offer from 200 OK responses, intersects both offers with
		the capabilities of the transcoding card and creates a new transcoding
		session on the card **only if** necessary. It then rewrites the 200 OK SDP so that it 
		contains the information resulted from the codec intersection.


**Parameters** explained:


Since the D-series transcoding cards are connected through either a
		PCI slot or simply an Ethernet connector, they cannot be assigned
		global IPs. Consequently, the module will write the local, private IP of the
		card in the SDP answers sent to each of the endpoints. Since this will not
		work with non-local UAs, the optional parameters force the RTP listen
		interface for each UA. This way, the script writer can enforce a global IP
		for the incoming RTP (which can be port forwarded to a transcoding card).


- *listen_if_A* (string) - the interface where the UAC (the caller) will send RTP after the call is established (IP from the 'c=' SDP line(s))
- *listen_if_B* (string) - the interface where the UAS (the callee) will send RTP after the call is established (IP from the 'c=' SDP line(s))


The following **error codes** may be returned:


- *-1* - SDP parsing error
- *-2* - failed to create transcoding session
- *-3* - internal error / no more memory


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE.


```opensips title="sngtc_callee_answer usage"
...
onreply_route[1] {
	if ($rs == 200)
		sngtc_callee_answer("11.12.13.14", "11.12.13.14");
}
...
```


#### sngtc_caller_answer()


Attaches an SDP body to the caller's ACK request, so that it matches
		the late SDP negotiation done by the UAS.


The following **error codes** may be returned:


- *-3* - internal error / no more memory


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE.


```opensips title="sngtc_caller_answer usage"
...
	if (has_totag()) {
		if (loose_route()) {
			...
			if (is_method("ACK"))
				sngtc_caller_answer();
		}
		...
	}
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
