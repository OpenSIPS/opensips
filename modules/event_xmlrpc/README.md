---
title: "event_xmlrpc Module"
description: "This module is an implementation of an XMLRPC client used to notify XMLRPC servers whenever certain notifications are raised by OpenSIPS. It acts as a transport layer for the Event Notification Interface."
---

## Admin Guide


### Overview


This module is an implementation of an XMLRPC client used to notify
		XMLRPC servers whenever certain notifications are raised by OpenSIPS. It
		acts as a transport layer for the Event Notification Interface.


Basicly, the module executes a remote procedure call when an event is
		raised from OpenSIPS's script, core or modules using the Event
		Interface.


In order to be notified, an XMLRPC server has to subscribe for a certain
		event provided by OpenSIPS. This can be done using the generic MI
		Interface (*event_subscribe* function) or from
		OpenSIPS script (*subscribe_event* core function).


### XMLRPC socket syntax


*'xmlrpc:' host ':' port ':' method*


Meanings:


- *'xmlrpc:'* - informs the Event Interface
					that the events sent to this subscriber should be handled
					by the *event_xmlrpc* module.
- *host* - host name of the XMLRPC server.
- *port* - port of the XMLRPC server.
- *method* - method called remotely by the
					XMLRPC client.
					NOTE: the client does not wait for a response from the
						XMLRPC server.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *none*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### use_struct_param (integer)


When raising an event, pack the name and value of the
			parameters in a XMLRPC structure. This provides an easier
			way for some XMLRPC server implementations to interpret
			the parameters.
			Set it to zero to disable or to non-zero to enable it.


*Default value is "0 (disabled)".*


```opensips title="Set use_struct_param parameter"
...
modparam("event_xmlrpc", "use_struct_param", 1)
...
```


### Exported Functions


No function exported to be used from configuration file.


### Example


This is an example of an event raised by the pike module
			when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED event"
POST /RPC2 HTTP/1.1.
Host: 127.0.0.1:8081.
Connection: close.
User-Agent: OpenSIPS XMLRPC Notifier.
Content-type: text/xml.
Content-length: 240.
		.
<?xml version="1.0"?>
<methodCall>
	<methodName>e_dummy_h</methodName>
	<params>
		<param>
			<value><string>E_MY_EVENT</string></value>
		</param>
		<param>
			<name>ip</name>
			<value><string>192.168.2.11</string></value>
		</param>
	</params>
</methodCall>
```


```c title="XMLRPC socket"
	# calls the 'block_ip' function
	xmlrpc:127.0.0.1:8080:block_ip
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
