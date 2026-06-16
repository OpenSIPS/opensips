---
title: "path Module"
description: "This module is designed to be used at intermediate sip proxies like loadbalancers in front of registrars and proxies. It provides functions for inserting a Path header including a parameter for passing forward the received-URI of a registration to the next hop. It also provides a mechanism ..."
---

## Admin Guide


### Overview


This module is designed to be used at intermediate sip proxies like loadbalancers in front of
		registrars and proxies. It provides functions for inserting a Path header including a parameter for
		passing forward the received-URI of a registration to the next hop. It also provides a mechanism
		for evaluating this parameter in subsequent requests and to set the destination URI according to it.


#### Path insertion for registrations


For registrations in a scenario like "[UAC] -> [P1] -> [REG]", 
			the "path" module can be used at the intermediate proxy P1 to insert a Path
			header into the message before forwarding it to the registrar REG. Two functions
			can be used to achieve this:


- *add_path(...)* adds a Path header in the form of
					"Path: <sip:1.2.3.4;lr>" to the message using the address
					of the outgoing interface. A port is only added if it's not the default
					port 5060.
If a username is passed to the function, it is also included in the Path
					URI, like "Path: <sip:username@1.2.3.4;lr>".
- *add_path_received(...)* also add a Path header in the
					same form as above, but also adds a parameter indicating the received-URI
					of the message, like 
					"Path: <sip:1.2.3.4;received=sip:2.3.4.5:1234;lr>". This
					is especially useful if the proxy does NAT detection and wants to pass
					the NAT'ed address to the registrar.
If the function is called with a username, it's included in the Path URI too.


#### Outbound routing to NAT'ed UACs


If the NAT'ed address of an UAC is passed to the registrar, the registrar routes back
			subsequent requests using the Path header of the registration as Route header of the
			current request. If the intermediate proxy had inserted a Path header including the
			"received" parameter during the registration, this parameter will show up
			in the Route header of the new request as well, allowing the intermediate proxy to route
			to this address instead of the one propagated in the Route URI for tunneling through NAT.
			This behaviour can be activated by setting the module parameter "use_received".


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- The "rr" module is needed for outbound routing according to the "received"
				parameter.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### use_received (int)


If set to 1, the "received" parameter of the first Route URI is evaluated and
		used as destination-URI if present.


*Default value is 0.*


```c title="Set use_received parameter"
...
modparam("path", "use_received", 1)
...
```


#### enable_double_path (integer)


There are some situations when the server needs to insert two 
		Path header fields instead of one. For example when using 
		two disconnected networks or doing cross-protocol forwarding from 
		UDP->TCP. This parameter enables inserting of 2
		Paths.


*Default value is 1 (yes).*


```c title="Set enable_double_path parameter"
...
modparam("path", "enable_double_path", 0)
...
```


### Exported Functions


#### add_path([user])


This function adds a Path header in the form 
		"Path: <sip:user@1.2.3.4;lr>".


Meaning of the parameters is as follows:


- *user* (string, optional) -
			The username to be inserted as user part.


This function can be used from REQUEST_ROUTE.


```c title="add_path(user) usage"
...
if (!add_path("loadbalancer")) {
	sl_send_reply(503, "Internal Path Error");
	...
};
...
```


#### add_path_received([user])


This function adds a Path header in the form 
		"Path: <sip:user@1.2.3.4;received=sip:2.3.4.5:1234;lr>", setting
		'user' as username part of address, it's own 
		outgoing address as domain-part, and the address the request has been received from as
		received-parameter.


Meaning of the parameters is as follows:


- *user* (string, optional) -
			The username to be inserted as user part.


This function can be used from REQUEST_ROUTE.


```c title="add_path_received(user) usage"
...
if (!add_path_received("inbound")) {
	sl_send_reply(503, "Internal Path Error");
	...
};
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
