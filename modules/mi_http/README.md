---
title: "mi_http Module"
description: "This module provides a HTTP transport layer implementation for OpenSIPS's Management Interface."
---

## Admin Guide


### Overview


This module provides a HTTP transport layer implementation
		for OpenSIPS's Management Interface.


### Dependencies


#### External Libraries or Applications


None


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *httpd* module.


### Exported Parameters


#### root(string)


Specifies the root path for HTTP requests:
		http://[opensips_IP]:[opensips_httpd_port]/[root]


*The default value is "mi".*


```opensips title="Set root parameter"
...
modparam("mi_http", "root", "opensips_mi")
...
```


#### trace_destination (string)


Trace destination as defined in the tracing module. Currently
		the only tracing module is **proto_hep**.
		This is where traced mi messages will go.


**WARNING:**A tracing module must be
			loaded in order for this parameter to work. (for example
			**proto_hep**).


*Default value is none(not defined).*


```opensips title="Set trace_destination parameter"
...
modparam("proto_hep", "trace_destination", "[hep_dest]10.0.0.2;transport=tcp;version=3")

modparam("mi_http", "trace_destination", "hep_dest")
...
```


#### trace_bwlist (string)


Filter traced mi commands based on a blacklist or a whitelist.
		**trace_destination** must be defined for
		this parameter to have any purpose. Whitelists can be defined using
		'w' or 'W', blacklists using 'b' or 'B'. The type is separate by the
		actual blacklist by ':'. The mi commands in the list must be separated
		by ','.


Defining a blacklists means all the commands that are not blacklisted
			will be traced. Defining a whitelist means all the commands that are
			not whitelisted will not be traced.
			**WARNING:** One can't define both
			a whitelist and a blacklist. Only one of them is allowed. Defining
			the parameter a second time will just overwrite the first one.


**WARNING:**A tracing module must be
			loaded in order for this parameter to work. (for example
			**proto_hep)**.


*Default value is none(not defined).*


```opensips title="Set trace_destination parameter"
...
## blacklist ps and which mi commands
## all the other commands shall be traced
modparam("mi_http", "trace_bwlist", "b: ps, which")
...
## allow only sip_trace mi command
## all the other commands will not be traced
modparam("mi_http", "trace_bwlist", "w: sip_trace")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Known Issues


Commands with large responses (like ul_dump) will fail if the
		configured size of the httpd buffer is to small (or if there
		isn't enough pkg memory configured).


Future realeases of the httpd module will address this issue.


### Examples


This is an example showing the JSON-RPC request and reply over HTTP
		for the "ps" MI command.


```c title="JSON-RPC request"
POST /mi HTTP/1.1
Accept: application/json
Content-Type: application/json
Host: example.net

{"jsonrpc":"2.0","method":"ps","id":10}

HTTP/1.1 200 OK
Content-Length: 317
Content-Type: application/json
Date: Fri, 01 Nov 2013 12:00:00 GMT

{"jsonrpc":"2.0","result":{"Processes":[{"ID":0,"PID":9467,"Type":"attendant"},{"ID":1,"PID":9468,"Type":"HTTPD127.0.0.1:8008"},{"ID":3,"PID":9470,"Type":"time_keeper"},{"ID":4,"PID":9471,"Type":"timer"},{"ID":5,"PID":9472,"Type":"SIPreceiverudp:127.0.0.1:5060"},{"ID":7,"PID":9483,"Type":"Timerhandler"},]},"id":10}
```


This is an example showing the JSON-RPC request with params and reply over HTTP
		for the "get_statistics" MI command.


```c title="JSON-RPC request with params"
POST /mi HTTP/1.1
Accept: application/json
Content-Type: application/json
Host: example.net

{"jsonrpc":"2.0","method":"get_statistics","params":[["dialog:","tm:"]],"id":10}

HTTP/1.1 200 OK
Content-Length: 317
Content-Type: application/json
Date: Fri, 01 Nov 2013 12:00:00 GMT

{"jsonrpc":"2.0","result":{"dialog:active_dialogs":0,"dialog:early_dialogs":0,"dialog:processed_dialogs":2,"dialog:expired_dialogs":0,"dialog:failed_dialogs":2,"dialog:create_sent":0,"dialog:update_sent":0,"dialog:delete_sent":0,"dialog:create_recv":0,"dialog:update_recv":0,"dialog:delete_recv":0,"tm:received_replies":49252,"tm:relayed_replies":49220,"tm:local_replies":370,"tm:UAS_transactions":49584,"tm:UAC_transactions":0,"tm:2xx_transactions":12004,"tm:3xx_transactions":0,"tm:4xx_transactions":37580,"tm:5xx_transactions":0,"tm:6xx_transactions":0,"tm:inuse_transactions":60},"id":10}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
