---
title: "proto_msrp Module"
description: "The **proto_msrp** module provides the MSRP protocol stack, meaning the network read/wite (plain and TLS), message parsing and assembling, transactional layer and the basic signalling operations."
---

## Admin Guide


### Overview


The **proto_msrp** module provides
		the MSRP protocol stack, meaning the network read/wite (plain and TLS),
		message parsing and assembling, transactional layer and the basic
		signalling operations.


Once loaded, you will be able to define MSRP listeners in your script,
		by adding its IP, and optionally the listening port,
		in your configuration file, similar to this example:
	```c

...
socket=msrp:127.0.0.1:65432
socket=msrps:127.0.0.1:65431
...
```


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* - you need to load this module
				if using MSRPS (secure) sockets. Via this module you will
				manage the SSL certificates


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### send_timeout (integer)


Time in milliseconds after a MSRP connection will be closed if it is
		not available for blocking writing in this interval (and OpenSIPS wants
		to send something on it).


*Default value is 100 ms.*


```c title="Set send_timeout parameter"
...
modparam("proto_msrp", "send_timeout", 200)
...
```


#### max_msg_chunks (integer)


The maximum number of chunks that a SIP message is expected to
			arrive via MSRP. If a packet is received more fragmented than this,
			the connection is dropped (either the connection is very
			overloaded and this leads to high fragmentation - or we are the
			victim of an ongoing attack where the attacker is sending the
			traffic very fragmented in order to decrease our performance).


*Default value is 4.*


```opensips title="Set max_msg_chunks parameter"
...
modparam("proto_msrp", "max_msg_chunks", 8)
...
```


#### tls_handshake_timeout (integer)


Sets the timeout (in milliseconds) for the SSL handshake sequence
			to complete. It may be necessary to increase this value when using
			a CPU intensive cipher 
			for the connection to allow time for keys to be generated and 
			processed.


The timeout is invoked during acceptance of a new connection 
			(inbound) and during the wait period when a new session is being
			initiated (outbound).


*Default value is 100.*


```opensips title="Set tls_handshake_timeout variable"
param("proto_msrp", "tls_handshake_timeout", 200) # number of milliseconds

			
```


#### cert_check_on_conn_reusage (integer)


This parameter turns on or off the extra checking/matching of the
		TLS domain (SSL certificate) when comes to reusing an existing TLS
		connection. Without this extra check, only IP and port of the
		connections will be check (in order to re-use an existing connection).
		With this extra check, the connection to be reused must have the same
		SSL certificate as the one set for the current signaling operation.


This checking is done only when comes to send SIP traffic via TLS and
		it is applied only against connections that were created / initiated 
		by OpenSIPS (as TLS client). Any accepte connection (as TLS server)
		will automatically match (the extra test will be skipped).


*Default value is 0 (disabled).*


```opensips title="Set cert_check_on_conn_reusage parameter"
...
modparam("proto_msrp", "cert_check_on_conn_reusage", 1)
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


```opensips title="Set trace_destination parameter"
...
modparam("proto_hep", "hep_id", "[hep_dest]10.0.0.2;transport=tcp;version=3")

modparam("proto_msrp", "trace_destination", "hep_dest")
...
```


#### trace_on (int)


This controls whether tracing for MSRP is on or not. You still need
		to define [trace destination](#param_trace_destination)in order to work, but
		this value will be controlled using MI function
		[msrp trace](#msrp-trace).


```opensips title="Set trace_on parameter"
...
modparam("proto_msrp", "trace_on", 1)
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
			set to 0 or tracing is deactived via the mi command [msrp trace](#msrp-trace)
			this route won't be called.


```opensips title="Set trace_filter_route parameter"
...
modparam("proto_msrp", "trace_filter_route", "msrp_filter")
...
/* all MSRP connections will go through this route if tracing is activated
 * and a trace destination is defined */
route[msrp_filter] {
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


#### msrp:trace


Replaces obsolete MI command: *msrp_trace*.


Name: *msrp:trace*


Parameters:


- trace_mode(optional): set MSRP tracing on and off.
				This parameter can be missing and the command will show the 
				current tracing status for this module( on or off );
				Possible values:
				
				on
				off


MI FIFO Command Format:


```bash
			:msrp:trace:_reply_fifo_file_
			trace_mode
			_empty_line_
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
