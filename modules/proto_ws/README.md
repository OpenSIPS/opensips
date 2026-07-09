---
title: "proto_ws Module"
description: "The WebSocket protocol ([RFC 6455](http://tools.ietf.org/html/rfc6455)) provides an end-to-end full-duplex communication channel between two web-based applications. This allows WebSocket enabled browsers to connect to a WebSocket server and exchange any type of data. [RFC 7118](http://tools...."
---

## Admin Guide


### Overview


The WebSocket protocol ([RFC 6455](http://tools.ietf.org/html/rfc6455))
 provides an end-to-end full-duplex communication channel between two web-based applications.
This allows WebSocket enabled browsers to connect to a WebSocket server
and exchange any type of data.
[RFC 7118](http://tools.ietf.org/html/rfc7118)
provides the specifications for transporting SIP messages over the WebSocket protocol.


The **proto_ws** module is transport module that provides
communication over the WebSocket protocol. This module is fully compliant with the
[RFC 7118](http://tools.ietf.org/html/rfc7118), thus allowing browsers
to act as SIP clients for the OpenSIPS proxy.


The current implementation can only act as a WebSocket server, meaning that it can only
accept connections from WebSocket clients and cannot initiate connections to another
WebSocket server. After the connection is established, messages can flow  in
both directions.


OpenSIPS supports the following WebSocket operations:


- text and binary - can both send and receive WebSocket messages that contain text or binary body
- close - messages used to safely close the WebSocket communication using a 2-messages handshake
- ping - responds with pong messages. There is no mechanism to trigger ping messages.
- pong - sent when a ping message is received. OpenSIPS, absorbes the pong messages received.


Once loaded, you will be able to define WebSocket listeners in your script. To
add a listener, you have to add its IP, and optionally the listening port,
*after* the `mpath` parameter, similar to this
example:
	```c

...
mpath=/path/to/modules
...
listen=ws:127.0.0.1		# change with the listening IP
listen=ws:127.0.0.1:5060	# change with the listening IP and port
...
```


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before
running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### ws_port (integer)


The default port to be used by all WebSocket listeners.


*Default value is 80.*


```c title="Set ws_port parameter"
...
modparam("proto_ws", "ws_port", 8080)
...
```


#### ws_send_timeout (integer)


Time in milliseconds after a WebSocket connection will be closed if it is
not available for blocking writing in this interval (and OpenSIPS wants
to send something on it).


*Default value is 100 ms.*


```opensips title="Set ws_send_timeout parameter"
...
modparam("proto_ws", "ws_send_timeout", 200)
...
```


#### ws_max_msg_chunks (integer)


The maximum number of chunks that a SIP message is expected to
arrive via WebSocket. If a packet is received more fragmented than this,
the connection is dropped (either the connection is very
overloaded and this leads to high fragmentation - or we are the
victim of an ongoing attack where the attacker is sending the
traffic very fragmented in order to decrease our performance).


*Default value is 4.*


```opensips title="Set ws_max_msg_chunks parameter"
...
modparam("proto_ws", "ws_max_msg_chunks", 8)
...
```


## Frequently Asked Questions


**Q: Can OpenSIPS act as a WebSocket client?**


No, currently OpenSIPS can only behave as a Websocket server.


**Q: Does OpenSIPS support WebSocket message fragmentation?**


No, WebSocket fragmentation mechanims is not supported.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
