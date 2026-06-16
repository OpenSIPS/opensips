---
title: "proto_bins Module"
description: "This module implements a secure Binary communication protocol over TLS, to be used by the OpenSIPS clustering engine provided by the clusterer module."
---

## Admin Guide


### Overview


This module implements a secure Binary communication protocol
		over TLS, to be used by the OpenSIPS clustering engine provided
		by the clusterer module.


Once loaded, you will be able to define BINS listeners in your
		configuration file by adding their IP and, optionally, a
		listening port, similar to this example:
	```c

...
socket= bins:127.0.0.1 		# change the listening IP
socket= bins:127.0.0.1:5557	# change the listening IP and port
...
```


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_openssl* or *tls_wolfssl*,
				depending on the desired TLS library
- *tls_mgm*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### bins_port (integer)


The default port to be used by all BINS listeners.


*Default value is 5556.*


```c title="Set bins_port parameter"
...
modparam("proto_bins", "bins_port", 5557)
...
```


#### bins_handshake_timeout (integer)


Sets the timeout (in milliseconds) for the SSL/TLS handshake
		sequence to complete. It may be necessary to increase this
		value when using a CPU intensive cipher for the connection to
		allow time for keys to be generated and processed.


The timeout is invoked during acceptance of a new connection
		(inbound) and during the wait period when a new session is
		being initiated (outbound).


*Default value is 100.*


```c title="Set bins_handshake_timeout variable"
param("proto_tls", "bins_handshake_timeout", 200) # number of milliseconds

			
```


#### bins_send_timeout (integer)


Sets the timeout (in milliseconds) for blocking send operations
		to complete.


The send timeout is invoked for all TLS write operations,
		excluding the handshake process (see: bins_handshake_timeout)


*Default value is 100 ms.*


```c title="Set bins_send_timeout parameter"
...
modparam("proto_bins", "bins_send_timeout", 200)
...
```


#### bins_max_msg_chunks (integer)


The maximum number of chunks in which a BINS message is
			expected to arrive via TCP. If a received packet is more
			fragmented than this, the connection is dropped (either the
			connection is very overloaded and this leads to high
			fragmentation - or we are the victim of an ongoing attack where
			the attacker is sending very fragmented traffic in order to
			decrease server performance).


*Default value is 32.*


```c title="Set bins_max_msg_chunks parameter"
...
modparam("proto_bins", "bins_max_msg_chunks", 8)
...
```


#### bins_async (integer)


Specifies whether the TCP/TLS connect and write operations
			should be done in an asynchronous mode (non-blocking connect
			and write) or not. If disabled, OpenSIPS will block and wait
			for TCP/TLS operations like connect and write.


*Default value is 1 (enabled).*


```c title="Set bins_async parameter"
...
modparam("proto_bins", "bins_async", 0)
...
```


#### bins_async_max_postponed_chunks (integer)


If bins_async is enabled, this specifies the maximum number of
			BINS messages that can be stashed for later/async writing. If
			the connection pending writes exceed this number, the
			connection will be marked as broken and dropped.


*Default value is 32.*


```c title="Set bins_async_max_postponed_chunks parameter"
...
modparam("proto_bins", "bins_async_max_postponed_chunks", 16)
...
```


#### trace_destination (string)


Trace destination as defined in the tracing module. Currently
		the only tracing module is **proto_hep**.
		Network events such as connect, accept and connection closed events
		shall be traced along with errors that could appear in the process.
		For each connection that is created an event containing information
		about the client and server certificates, master key and network layer
		information shall be sent.


**WARNING:**A tracing module must be
			loaded in order for this parameter to work. (for example
			**proto_hep**).


*Default value is none(not defined).*


```c title="Set trace_destination parameter"
...
modparam("proto_hep", "hep_id", "[hep_dest]10.0.0.2;transport=tcp;version=3")

modparam("proto_bins", "trace_destination", "hep_dest")
...
```


#### trace_on (int)


This controls whether tracing for tls is on or not. You still need to define
			[trace destination](#param_trace_destination)in order to work, but this value will be
			controlled using mi function [mi trace](#mi_trace).


```c title="Set trace_on parameter"
...
modparam("proto_bins", "trace_on", 1)
...
```


### Exported MI Functions


#### bins:trace


Replaces obsolete MI command: *tls_trace*.


Name: *bins:trace*


Parameters:


- trace_mode(optional): set bins tracing on and off. This parameter
						can be missing and the command will show the current tracing
						status for this module( on or off );
						Possible values:
						
							on
							off


MI FIFO Command Format:


```c
			opensips-cli -x mi bins:trace on
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
