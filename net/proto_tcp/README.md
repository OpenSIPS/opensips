---
title: "proto_tcp Module"
description: "This module is a built-in transport module which implements SIP TCP-based communication. It does not handle TCP connections management, but only offers higher-level primitives to read and write SIP messages over TCP."
---

## Admin Guide


### Overview


The **proto_tcp** module is a built-in
transport module which implements SIP TCP-based communication. It does
not handle TCP connections management, but only offers higher-level
primitives to read and write SIP messages over TCP.


Once loaded, you will be able to define TCP listeners in your script,
by adding its IP, and optionally the listening port, in your configuration
file, similar to this example:

```opensips
...
listen=tcp:127.0.0.1 		# change the listening IP
listen=tcp:127.0.0.1:5080	# change with the listening IP and port
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


#### tcp_port (integer)


The default port to be used for all TCP related operation. Be careful
as the default port impacts both the SIP listening part (if no port is
defined in the TCP listeners) and the SIP sending part (if the 
destination URI has no explicit port).


If you want to change only the listening port for TCP, use the port
option in the SIP listener defintion.


*Default value is 5060.*


```c title="Set tcp_port parameter"
...
modparam("proto_tcp", "tcp_port", 5065)
...
```


#### tcp_send_timeout (integer)


Time in milliseconds after a TCP connection will be closed if it is
not available for blocking writing in this interval (and OpenSIPS wants
to send something on it).


*Default value is 100 ms.*


```opensips title="Set tcp_send_timeout parameter"
...
modparam("proto_tcp", "tcp_send_timeout", 200)
...
```


#### tcp_max_msg_chunks (integer)


The maximum number of chunks that a SIP message is expected to
arrive via TCP. If a packet is received more fragmented than this,
the connection is dropped (either the connection is very
overloaded and this leads to high fragmentation - or we are the
victim of an ongoing attack where the attacker is sending the
traffic very fragmented in order to decrease our performance).


*Default value is 4.*


```opensips title="Set tcp_max_msg_chunks parameter"
...
modparam("proto_tcp", "tcp_max_msg_chunks", 8)
...
```


#### tcp_crlf_pingpong (integer)


Send CRLF pong (\r\n) to incoming CRLFCRLF ping messages over TCP.
By default it is enabled (1).


*Default value is 1 (enabled).*


```opensips title="Set tcp_crlf_pingpong parameter"
...
modparam("proto_tcp", "tcp_crlf_pingpong", 0)
...
```


#### tcp_crlf_drop (integer)


Drop CRLF (\r\n) ping messages. When this parameter is enabled,
the TCP layer drops packets that contains a single CRLF message.
If a CRLFCRLF message is received, it is handled according to the
*tcp_crlf_pingpong* parameter.


*Default value is 0 (disabled).*


```opensips title="Set tcp_crlf_drop parameter"
...
modparam("proto_tcp", "tcp_crlf_drop", 1)
...
```


#### tcp_async (integer)


If the TCP connect and write operations should be done in an
asynchronous mode (non-blocking connect and
write). If disabled, OpenSIPS will block and wait for TCP 
operations like connect and write.


*Default value is 1 (enabled).*


```opensips title="Set tcp_async parameter"
...
modparam("proto_tcp", "tcp_async", 0)
...
```


#### tcp_async_max_postponed_chunks (integer)


If *tcp_async* is enabled, this specifies the
maximum number of SIP messages that can be stashed for later/async
writing. If the connection pending writes exceed this number, the
connection will be marked as broken and dropped.


*Default value is 32.*


```opensips title="Set tcp_async_max_postponed_chunks parameter"
...
modparam("proto_tcp", "tcp_async_max_postponed_chunks", 16)
...
```


#### tcp_async_local_connect_timeout (integer)


If *tcp_async* is enabled, this specifies the
			number of milliseconds that a connect will be tried in blocking
			mode (optimization). If the connect operation lasts more than
			this, the connect will go to async mode and will be passed to TCP
			MAIN for polling.


*Default value is 100 ms.*


```opensips title="Set tcp_async_local_connect_timeout parameter"
...
modparam("proto_tcp", "tcp_async_local_connect_timeout", 200)
...
```


#### tcp_async_local_write_timeout (integer)


If *tcp_async* is enabled, this specifies the
number of milliseconds that a write op will be tried in blocking
mode (optimization). If the write operation lasts more than this,
the write will go to async mode and will be passed to TCP MAIN for
polling.


*Default value is 10 ms.*


```opensips title="Set tcp_async_local_write_timeout parameter"
...
modparam("proto_tcp", "tcp_async_local_write_timeout", 100)
...
```


## Frequently Asked Questions


**Q: After switching to OpenSIPS 2.1, I'm getting this error: "listeners found for protocol tcp, but no module can handle it"**


You need to load the "proto_tcp" module. In your script, make sure you do a **loadmodule "proto_tcp.so"** after setting the **[mpath](https://docs.opensips.org/manual/2-1/script-coreparameters#mpath)**.


**Q: I cannot locate "proto_tcp.so". Where is it?**


The "proto_udp" and "proto_tcp" modules are simply built into the opensips binary by default. They are not available as shared libraries, but look like modules for code consistency reasons.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
