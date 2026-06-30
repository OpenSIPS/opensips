---
title: "proto_tcp Module"
description: "The **proto_tcp** module is a built-in transport module which implements SIP TCP-based communication. It does not handle TCP connections management, but only offers higher-level primitives to read and write SIP messages over TCP."
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
	```c

...
socket=tcp:127.0.0.1 		# change the listening IP
socket=tcp:127.0.0.1:5080	# change with the listening IP and port
...
```


### Related Core TCP APIs


#### tcp_close_conn(ipport)


Force-close an existing TCP-based connection. The
			*ipport* argument may be either a TCP connection ID,
			as reported by the *tcp:list* MI command, or a remote
			endpoint in the form *ip:port* or
			*proto:ip:port*. If the protocol is omitted,
			OpenSIPS will search all TCP-based transports.


The function returns true if a matching connection was scheduled for
			closing, false if no connection matched and an error on invalid input
			or internal failure.


```c title="Force-close a TCP connection from script"
...
if (!tcp_close_conn("tcp:10.0.0.10:5060")) {
	xlog("No matching TCP connection was found\n");
}
...
```


#### tcp:close


Core MI command equivalent of [tcp close conn](#tcp_close_conn_ipport). It
			accepts a single *ipport* parameter using the same
			formats described above.


```c title="Force-close a TCP connection via MI"
$ opensips-cli -x mi tcp:close ipport=tcp:10.0.0.10:5060
OK
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


```c title="Set tcp_send_timeout parameter"
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


```c title="Set tcp_max_msg_chunks parameter"
...
modparam("proto_tcp", "tcp_max_msg_chunks", 8)
...
```


#### tcp_crlf_pingpong (integer)


Send CRLF pong (\r\n) to incoming CRLFCRLF ping messages over TCP.
			By default it is enabled (1).


*Default value is 1 (enabled).*


```c title="Set tcp_crlf_pingpong parameter"
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


```c title="Set tcp_crlf_drop parameter"
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


```c title="Set tcp_async parameter"
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


```c title="Set tcp_async_max_postponed_chunks parameter"
...
modparam("proto_tcp", "tcp_async_max_postponed_chunks", 16)
...
```


#### tcp_async_local_write_timeout (integer)


If *tcp_async* is enabled, this specifies the
			number of milliseconds that a write op will be tried in blocking
			mode (optimization). If the write operation lasts more than this,
			the write will go to async mode and will be passed to TCP MAIN for
			polling.


*Default value is 10 ms.*


```c title="Set tcp_async_local_write_timeout parameter"
...
modparam("proto_tcp", "tcp_async_local_write_timeout", 100)
...
```


#### trace_destination (string)


Trace destination as defined in the tracing module. Currently
		the only tracing module is **proto_hep**.
		Network events such as connect, accept and connection closed events
		shall be traced along with errors that could appear in the process.


**WARNING:**A tracing module must be
			loaded in order for this parameter to work. (for example
			**proto_hep**).


*Default value is none(not defined).*


```c title="Set trace_destination parameter"
...
modparam("proto_hep", "hep_id", "[hep_dest]10.0.0.2;transport=tcp;version=3")

modparam("proto_tcp", "trace_destination", "hep_dest")
...
```


#### trace_on (int)


This controls whether tracing for tcp is on or not. You still need to define
			[trace destination](#param_trace_destination)in order to work, but this value will be
			controlled using mi function [tcp trace](#mi_tcp_trace).


```c title="Set trace_on parameter"
...
modparam("proto_tcp", "trace_on", 1)
...
```


#### trace_filter_route (string)


Define the name of a route in which you can filter which connections will
			be trace and which connections won't be. In this route you will have
			information regarding source and destination ips and ports for the current
			connection. To disable tracing for a specific connection the last call in
			this route must be **drop**, any other exit
			mode resulting in tracing the current connection ( of course you still
			have to define a [trace destination](#param_trace_destination) and trace must be
			on at the time this connection is opened.


**IMPORTANT**
			Filtering on ip addresses and ports can be made using **$si** and **$sp** for matching
			either the entity that is connecting to OpenSIPS or the entity to which
			OpenSIPS is connecting. The name might be misleading (**$si** meaning the source ip if you read the docs) but in reality
			it is simply the socket other than the OpenSIPS socket. In order to match
			OpenSIPS interface (either the one that accepted the connection or the one
			that initiated a connection) **$socket_in(ip)** (ip) and
			**$socket_in(port)** (port) can be used.


**WARNING:** IF [trace on](#param_trace_on) is
			set to 0 or tracing is deactived via the mi command [tcp trace](#mi_tcp_trace)
			this route won't be called.


```c title="Set trace_filter_route parameter"
...
modparam("proto_tcp", "trace_filter_route", "tcp_filter")
...
/* all tcp connections will go through this route if tracing is activated
 * and a trace destination is defined */
route[tcp_filter] {
	...
	/* all connections opened from/by ip 1.1.1.1:8000 will be traced
	   on interface 1.1.1.10:5060(opensips listener)
	   all the other connections won't be */
	 if ( $si == "1.1.1.1" && $sp == 8000 &&
		$socket_in(ip) == "1.1.1.10"  && $socket_in(port) == 5060)
		exit;
	else
		drop;
}
...
```


### Exported MI Functions


#### tcp_trace


Name: *tcp_trace*


Parameters:


- trace_mode(optional): set tcp tracing on and off. This parameter
						can be missing and the command will show the current tracing
						status for this module( on or off );
						Possible values:
						
							on
							off


MI FIFO Command Format:


```c
			:tcp_trace:_reply_fifo_file_
			trace_mode
			_empty_line_
			
```


## Frequently Asked Questions


**Q: After switching to OpenSIPS 2.1, I'm getting this error:
				"listeners found for protocol tcp, but no module can handle it"**


You need to load the "proto_tcp" module. In your script, make sure
			you do a **loadmodule "proto_tcp.so"** after setting the **[mpath](https://docs.opensips.org/manual/2-1/script-coreparameters#mpath)**.


**Q: I cannot locate "proto_tcp.so". Where is it?**


The "proto_udp" and "proto_tcp" modules are simply built into
				the opensips binary by default. They are not available as shared
				libraries, but look like modules for code consistency reasons.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
