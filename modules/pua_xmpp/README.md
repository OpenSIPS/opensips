---
title: "Presence User Agent for XMPP (Presence gateway between SIP and XMPP)"
description: "This module is a gateway for presence between SIP and XMPP."
---

## Admin Guide


### Overview


This module is a gateway for presence between SIP and XMPP.


It translates one format into another and uses xmpp, pua and presence
		modules to manage the transmition of presence state information.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *presence*.
- *pua*.
- *xmpp*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libxml*.


### Exported Parameters


#### server_address(str)


The IP address of the server.


```c title="Set server_address parameter"
...
modparam("pua_xmpp", "server_address", "sip:sa@opensips.org:5060")
...
```


#### presence_server (str)


The the address of the presence server. If set, it will be
		used as outbound proxy when sending PUBLISH requests.


```c title="Set presence_server parameter"
...
modparam("pua_xmpp", "presence_server", "sip:pa@opensips.org:5075")
...
	
```


### Exported Functions


Functions exported to be used in configuration file.


#### pua_xmpp_notify()


Function that handles Notify messages addressed to a user from
		an xmpp domain. It requires filtering after method and domain in
		configuration file. If the function is successful, a 2xx reply must
		be sent.


This function can be used from REQUEST_ROUTE.


```c title="Notify2Xmpp usage"
...
	if( is_method("NOTIFY") && $ru=~"sip:.+@sip-xmpp.siphub.ro")
	{
		if(Notify2Xmpp())
			t_reply(200, "OK");
		exit;
	}
...
```


#### pua_xmpp_req_winfo(request_uri, expires)


Function called when a Subscribe addressed to a user from a
		xmpp domain is received. It calls sending a Subscribe for 
		winfo for the user, and the following Notify with dialog-info
		is translated into a subscription in xmpp. 
		It also requires filtering in configuration file, after method, 
		domain and event(only for presence).


Parameters:


- *request_uri* (string)
- *expires* (int) - value of Expires header field 
				in received Subscribe.


This function can be used from REQUEST_ROUTE.


```c title="xmpp_send_winfo usage"
...
	if( is_method("SUBSCRIBE"))
	{
		handle_subscribe();
		if($ru=~"sip:.+@sip-xmpp.siphub.ro" && $hdr(Event)== "presence")
		{
			pua_xmpp_req_winfo($ruri, $hdr(Expires));
		}
		t_release();
	}

...
		
```


### Filtering


Instead of "sip-xmpp.siphub.ro"  in the example you should use the value
	set for the xmpp module parameter named 'gateway_domain'.


## Developer Guide


The module provides no function to be used in other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
