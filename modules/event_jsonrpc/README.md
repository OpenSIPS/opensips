---
title: "event_jsonrpc Module"
description: "This module is an implementation of an JSON-RPC v2.0 client [http://www.jsonrpc.org/specification](http://www.jsonrpc.org/specification). that can send a RPC to a JSON-RPC server (when used in *sync_mode*), or send a notification (when *sync_mode* is disabled) whenever whenever OpenSIPS..."
---

## Admin Guide


### Overview


This module is an implementation of an JSON-RPC v2.0
client [http://www.jsonrpc.org/specification](http://www.jsonrpc.org/specification).
that can send a RPC to a JSON-RPC server (when used in
*sync_mode*), or send a notification
(when *sync_mode* is disabled) whenever
whenever OpenSIPS raises a notification through the Event
Interface. This module acts as a transport layer for the Event
Notification Interface.


This module sends the JSON-RPC directly over TCP, avoiding
the any application transport layer (such as HTTP). This
makes this module a very lightweight and reliable module
to deliver events to an application server.


In order to be notified, a JSON-RPC server has to subscribe for a
certain event provided by OpenSIPS. This can be done using the generic
MI Interface (*event_subscribe* function) or from
OpenSIPS script (*subscribe_event* core function).


### JSON-RPC socket syntax


*'jsonrpc:' host ':' port ['/' method]*


Meaning:


- *'jsonrpc:'* - specifies the
transport protocol used by the Event Interface
to send the command. the *jsonrpc*
token indicates that the subscriber's events should be
notified using the
*event_jsonrpc* module.
- *host* - host name of the JSON-RPC server.
- *port* - port of the JSON-RPC server.
- *method* - method called remotely by the
JSON-RPC client.
NOTE: this parameter is optional - if it is missing,
the method used is the actual event subscribed
to (i.e. if *localhost:8080*
subscribes to the *E_PIKE_BLOCKED*
event, the RPC call will use the
*E_PIKE_BLOCKED* method.


The JSON-RPC command is built as it follows:


- *id* - uniquly generated if
*sync_mode* is used, otherwise (for
notifications) *null*.
- *method* - if no method is specified in the
socket, the name of the event is set as method, otherwise
the token specified is used.
- *params* - if the event sent contains
named parameters, then this parameter contains a JSON object
with an object for each parameter. If the event sent only
contains values, the parameters will be sent as an array.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *none*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### sync_mode (integer)


This parameter controls the way the
*event_jsonrpc* module communicates
with the JSON-RPC server. If enabled, (set to
*yes*), each event is translated to
a JSON-RPC request. If disabled, each event will be sent
as a JSON-RPC notification - there will be no reply
expected by our client.


Note that if you need a reliable communication with
the JSON-RPC server, where each event sent needs to be
confirmed, you must set this parameter to
*1/yes*. Also, if you are using this
module in a failover setup (using the
*event_virtual* module), you should
also set this parameter to *1/yes*.


*Default value is "0 (disabled)".*


```opensips title="Set sync_mode parameter"
...
modparam("event_jsonrpc", "sync_mode", yes)
...
```


#### timeout (integer)


Specified the amount of milliseconds the module
waits for a command to complete. In
*sync_mode*, it specifies the time
module waits the request to be sent and a reply received.
In non-*sync_mode*, it represents
only the time opensips takes to send the JSON-RPC
notification.


NOTE that if the event is not using names for its parameters,
the event will be the first parameter in the JSON-RPC command.


*Default value is "1000 milliseconds = 1 second".*


```opensips title="Set timeout parameter"
...
# only wait for 200 milliseonds for a reply
modparam("event_jsonrpc", "timeout", 200)
...
```


#### event_param (string)


By default, the name of the event subscribed to is not
send in the JSON-RPC command. If one needs to send the
name of the event as well, you can use this parameter to
specify the name of JSON object within the params that
will contain the name of the event.


*Default value is "disabled" - event is not added.*


```opensips title="Set event_param parameter"
...
modparam("event_jsonrpc", "event_param", "opensips_event")
# json resulted will contain the "opensips_event": EVENT token
...
```


### Exported Functions


No function exported to be used from configuration file.


### Examples


```c title="JSON-RPC socket"
	# calls the 'block_ip' method
	jsonrpc:127.0.0.1:8080/block_ip

	# calls the 'E_PIKE_BLOCKED' method, if subscribed to the E_PIKE_BLOCKED event
	jsonrpc:127.0.0.1:8080
```


#### JSON-RPC notification


This is an example of an event raised when
*sync_mode* is disabled
by the pike module when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED JSON-RPC notification"
{
	"id": null,
	"jsonrpc": "2.0",
	"method": "E_PIKE_BLOCKED",
	"params": {
		"ip": "192.168.2.11"
	}
}
```


#### JSON-RPC Request


This is an example of an event raised in
*sync_mode* by the pike module
when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED JSON-RPC request (sync_mode)"
# request
{
	"id": 915243442,
	"jsonrpc": "2.0",
	"method": "E_PIKE_BLOCKED",
	"params": {
		"ip": "192.168.2.11"
	}
}

# reply
{
	"jsonrpc": "2.0",
	"result": 8,
	"id": 915243442
}
```


#### JSON-RPC Notification with Event's name


when having the *event_param* set to
*opensips_event*, the event raised by
the pike module will look like the following:


```c title="E_PIKE_BLOCKED notification with event name"
# module configuration
modparam("event_jsonrpc", "event_param", "opensips_event")

# JSON-RPC socket: jsonrpc:HOST:PORT/handle_cmd

# JSON-RPC command sent
{
	"id": null,
	"jsonrpc": "2.0",
	"method": "handle_cmd",
	"params": {
		"opensips_event": "E_PIKE_BLOCKED"
		"ip": "192.168.2.11"
	}
}
```


#### Custom JSON-RPC Notification from script


This example contains a snippet to send a custom
event from the script using the
*event_jsonrpc* module.


Note that we are only populating values for the
event, we are not assinging names to those values.
Therefore, the parameters will be sent as an array.


```c title="E_PIKE_BLOCKED event"
startup_route {
	subscribe_event("E_MY_EVENT", "jsonrpc:127.0.0.1:8080");
}

route {
	...
	$avp(attr-val) = 3;
	$avp(attr-val) = 5;
	raise_event("E_MY_EVENT", $avp(attr-val));
	...
}

# JSON-RPC command sent
{
	"id": null,
	"jsonrpc": "2.0",
	"method": "E_MY_EVENT",
	"params": [3, 5]
}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
