---
title: "event_stream Module"
description: "This module provides a TCP transport layer implementation for the Event Interface. The module can either send a JSON-RPC notification or a standard request and wait for the response (when used in *reliable_mode*)."
---

## Admin Guide


### Overview


This module provides a TCP transport layer implementation for the Event
		Interface. The module can either send a JSON-RPC notification or a
		standard request and wait for the response (when used in
		*reliable_mode*).


As the JSON-RPC is sent directly over TCP, avoiding any application
		transport layer (such as HTTP), this module offers a very lightweight
		and reliable way of delivering events to an application server.


In order to be notified, a JSON-RPC server has to subscribe for a
		certain event provided by OpenSIPS. This can be done using the generic
		MI Interface (*event_subscribe* function) or from
		OpenSIPS script (*subscribe_event* core function).


### Stream socket syntax


*'tcp:' host ':' port ['/' method]*


Meaning:


- *'tcp:'* - specifies the
					transport protocol used by the Event Interface
					to send the command. the *tcp*
					token indicates that the subscriber's events should be
					notified using the
					*event_strea,* module.
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
				*reliable_mode* is used, otherwise (for
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


#### reliable_mode (integer)


This parameter controls the way the
			*event_stream* module communicates
			with the JSON-RPC server. If enabled, (set to
			*1*), each event is translated to
			a JSON-RPC request. If disabled, each event will be sent
			as a JSON-RPC notification - there will be no reply
			expected by our client.


Note that if you need a reliable communication with
			the JSON-RPC server, where each event sent needs to be
			confirmed (by a JSON-RPC response), you must set this parameter
			to *1/yes*. If you are using this
			module in a failover setup (using the
			*event_virtual* module), it is recommended
			to set this parameter to *1/yes*.


*Default value is "0 (disabled)".*


```c title="Set reliable_mode parameter"
...
modparam("event_stream", "reliable_mode", yes)
...
```


#### timeout (integer)


Specified the amount of milliseconds the module
			waits for a command to complete. In
			*reliable_mode*, it specifies the time
			module waits the request to be sent and a reply received.
			In non-*reliable_mode*, it represents
			only the time opensips takes to send the JSON-RPC
			notification.


NOTE that if the event is not using names for its parameters,
			the event will be the first parameter in the JSON-RPC command.


*Default value is "1000 milliseconds = 1 second".*


```c title="Set timeout parameter"
...
# only wait for 200 milliseonds for a reply
modparam("event_stream", "timeout", 200)
...
```


#### event_param (string)


By default, the name of the event subscribed to is not
			send in the JSON-RPC command. If one needs to send the
			name of the event as well, you can use this parameter to
			specify the name of JSON object within the params that
			will contain the name of the event.


*Default value is "disabled" - event is not added.*


```c title="Set event_param parameter"
...
modparam("event_stream", "event_param", "opensips_event")
# json resulted will contain the "opensips_event": EVENT token
...
```


### Exported Functions


No function exported to be used from configuration file.


### Examples


```c title="Stream socket"
	# calls the 'block_ip' method
	tcp:127.0.0.1:8080/block_ip

	# calls the 'E_PIKE_BLOCKED' method, if subscribed to the E_PIKE_BLOCKED event
	tcp:127.0.0.1:8080
```


#### JSON-RPC notification


This is an example of an event raised when
			*reliable_mode* is disabled
			by the pike module when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED JSON-RPC notification"
{
	"jsonrpc": "2.0",
	"method": "E_PIKE_BLOCKED",
	"params": {
		"ip": "192.168.2.11"
	}
}
```


#### JSON-RPC Request


This is an example of an event raised in
			*reliable_mode* by the pike module
			when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED JSON-RPC request (reliable_mode)"
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
modparam("event_stream", "event_param", "opensips_event")

# Stream socket: tcp:HOST:PORT/handle_cmd

# JSON-RPC command sent
{
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
			*event_stream* module.


Note that we are only populating values for the
			event, we are not assinging names to those values.
			Therefore, the parameters will be sent as an array.


```c title="E_PIKE_BLOCKED event"
startup_route {
	subscribe_event("E_MY_EVENT", "tcp:127.0.0.1:8080");
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
	"jsonrpc": "2.0",
	"method": "E_MY_EVENT",
	"params": [3, 5]
}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
