---
title: "proto_wss Module"
description: "The WSS (Secure WebSocket) module provides the ability to communicate with a WebSocket ([RFC 6455](http://tools.ietf.org/html/rfc6455)) client or server over a secure (TLS encrypted) channel. As part of the [WebRTC](https://webrtc.org/) specifications, this protocol can be used to provide se..."
---

## Admin Guide


### Overview


The WSS (Secure WebSocket) module provides the ability to communicate with
	a WebSocket ([RFC
		6455](http://tools.ietf.org/html/rfc6455)) client or server over a secure (TLS encrypted) channel.
	As part of the [WebRTC](https://webrtc.org/)
	specifications, this protocol can be used to provide secure VoIP calls to
	HTTPS enabled browsers.


This module behaves as any other transport protocol module: in order to
	use it, you must define one or more listeners that will handle the secure
	WebSocket traffic, *after* the `mpath`
	parameter:
	```c

...
mpath=/path/to/modules
...
listen=wss:10.0.0.1			# change with the listening IP
listen=wss:10.0.0.1:5060	# change with the listening IP and port
...
```
	Besides that, you need to define the TLS parameters for securing the connection. This is done through the *tls_mgm* module interface, similar to the *proto_tls* module:
	```c

modparam("tls_mgm", "certificate", "/certs/biloxy.com/cert.pem")
modparam("tls_mgm", "private_key", "/certs/biloxy.com/privkey.pem")
modparam("tls_mgm", "ca_list", "/certs/wellknownCAs")
modparam("tls_mgm", "tls_method", "tlsv1")
modparam("tls_mgm", "verify_cert", "1")
modparam("tls_mgm", "require_cert", "1")
```
	Check the *tls_mgm* module documentation for more info.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm*.


#### Dependencies of external libraries


OpenSIPS TLS v1.0 support requires the following packages:


- *openssl* or
					*libssl* >= 0.9.6
- *openssl-dev* or
					*libssl-dev*


OpenSIPS TLS v1.1/1.2 support requires the following packages:


- *openssl* or
					*libssl* >= 1.0.1e
- *openssl-dev* or
					*libssl-dev*


### Exported Parameters


All these parameters can be used from the opensips.cfg file,
		to configure the behavior of OpenSIPS-WSS.


#### listen=interface


This is a global parameter that specifies what interface/IP and
			port should handle WSS traffic.


```opensips title="Set listen variable"
...
listen = wss:1.2.3.4:44344
...
				
```


#### wss_port (integer)


The default port to be used for all WSS related operation. Be 
			careful as the default port impacts both the SIP listening part 
			(if no port is defined in the WSS listeners) and the SIP sending 
			part (if the destination WSS URI has no explicit port).


If you want to change only the listening port for WSS, use the port
			option in the SIP listener defintion.


*Default value is 443.*


```opensips title="Set wss_port variable"
...
modparam("proto_wss", "wss_port", 44344)
...
				
```


#### wss_max_msg_chunks (integer)


The maximum number of chunks in which a SIP message is expected to
			arrive via WSS. If a received packet is more fragmented than this,
			the connection is dropped (either the connection is very
			overloaded and this leads to high fragmentation - or we are the
			victim of an ongoing attack where the attacker is sending very
			fragmented traffic in order to decrease server performance).


*Default value is 4.*


```opensips title="Set wss_max_msg_chunks parameter"
...
modparam("proto_wss", "wss_max_msg_chunks", 8)
...
```


#### wss_resource (string)


The resource queried for when a WebSocket handshake is initiated.


*Default value is "/".*


```opensips title="Set wss_resource parameter"
...
modparam("proto_wss", "wss_resource", "/wss")
...
```


#### wss_handshake_timeout (integer)


This parameter specifies the time in milliseconds the proto_wss module
			waits for a WebSocket handshake reply from a WebSocket server.


*Default value is 100.*


```opensips title="Set wss_handshake_timeout parameter"
...
modparam("proto_wss", "wss_handshake_timeout", 300)
...
```


## Frequently Asked Questions


**Q: Does OpenSIPS support fragmented Secure WebSocket messages?**


No, the WebSocket fragmentation mechanism is not supported.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
