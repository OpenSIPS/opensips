---
title: "proto_hep Module"
description: "The **proto_hep** module is a transport module which implements hepV1 and hepV2 UDP-based communication and hepV3 TCP-based communication."
---

## Admin Guide


### Overview


The **proto_hep** module is a
transport module which implements hepV1 and hepV2 UDP-based communication
and hepV3 TCP-based communication. It also offers an API with which
you can register callbacks which are called after the HEP header is
parsed and also can pack sip messages to HEP messages.The unpacking
part is done internally.


Once loaded, you will be able to define HEP listeners in your
configuration file by adding their IP and, optionally, a listening port.
You can define both TCP and UDP listeners. On UDP you will be able to
receive HEP v1, v2 and v3 packets, on TCP and TLS only HEPv3.

```opensips
...
#HEPv3 listener
listen = hep_tcp:127.0.0.1:6061 		# change the listening IP
#HEPv1, v2, v3 listener
listen = hep_udp:127.0.0.1:6061 		# change the listening IP
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


#### hep_port (integer)


The default port to be used by all TCP/UDP listeners.


*Default value is 5656.*


```c title="Set hep_port parameter"
...
modparam("proto_hep", "hep_port", 6666)
...
```


#### hep_send_timeout (integer)


Time in milliseconds after a TCP connection will be closed if it is
not available for blocking writing in this interval (and OpenSIPS wants
to send something on it).


*Default value is 100 ms.*


```opensips title="Set hep_send_timeout parameter"
...
modparam("proto_hep", "hep_send_timeout", 200)
...
```


#### hep_max_msg_chunks (integer)


The maximum number of chunks in which a HEP message is expected to
arrive via TCP. If a received packet is more fragmented than this,
the connection is dropped (either the connection is very
overloaded and this leads to high fragmentation - or we are the
victim of an ongoing attack where the attacker is sending very
fragmented traffic in order to decrease server performance).


*Default value is 32.*


```opensips title="Set hep_max_msg_chunks parameter"
...
modparam("proto_hep", "hep_max_msg_chunks", 8)
...
```


#### hep_async (integer)


Specifies whether the TCP connect and write operations should be
done in an asynchronous mode (non-blocking connect and
write) or not. If disabled, OpenSIPS will block and wait for TCP
operations like connect and write.


*Default value is 1 (enabled).*


```opensips title="Set hep_async parameter"
...
modparam("proto_hep", "hep_async", 0)
...
```


#### hep_async_max_postponed_chunks (integer)


If *hep_async* is enabled, this specifies the
maximum number of HEP messages that can be stashed for later/async
writing. If the connection pending writes exceed this number, the
connection will be marked as broken and dropped.


*Default value is 32.*


```opensips title="Set hep_async_max_postponed_chunks parameter"
...
modparam("proto_hep", "hep_async_max_postponed_chunks", 16)
...
```


#### hep_capture_id (integer)


The parameter indicate the capture agent ID for HEPv2/v3 protocol.
Limitation: 16-bit integer.


*Default value is "1".*


```opensips title="Set hep_capture_id parameter"
...
modparam("proto_hep", "hep_capture_id", 234)
...
```


#### hep_async_local_connect_timeout (integer)


If *hep_async* is enabled, this specifies the
number of milliseconds that a connect will be tried in blocking
mode (optimization). If the connect operation lasts more than
this, the connect will go to async mode and will be passed to TCP
MAIN for polling.


*Default value is 100 ms.*


```opensips title="Set hep_async_local_connect_timeout parameter"
...
modparam("proto_hep", "hep_async_local_connect_timeout", 200)
...
```


#### hep_async_local_write_timeout (integer)


If *hep_async* is enabled, this specifies the
number of milliseconds that a write op will be tried in blocking
mode (optimization). If the write operation lasts more than this,
the write will go to async mode and will be passed to bin MAIN for
polling.


*Default value is 10 ms.*


```opensips title="Set hep_async_local_write_timeout parameter"
...
modparam("proto_hep", "tcp_async_local_write_timeout", 100)
...
```


## Developer Guide


### Available Functions


#### pack_hep(from, to, proto, payload, plen, retbuf, retlen)


The function packs connection details and sip message into HEP message. It's
your job to free both the old and the new buffer.


Meaning of the parameters is as follows:


- *sockaddr_union *from* - sockaddr_union describing
sending socket
- *sockaddr_union *to* - sockaddr_union describing
receiving socket
- *int proto* - protocol used in hep header;
- *char *payload* SIP payload buffer
- *int plen* SIP payload buffer length
- *char **retbuf* HEP message buffer
- *int *retlen* HEP message buffer length


#### register_hep_cb(cb)


The function register callbacks to be called whenever a HEP message
is received. The callbacks parameters are struct hep_desc*(see hep.h for
details) a structure that holds all details about the hep header and the
receive_info* structure. The callback can return HEP_SCRIPT_SKIP which
stops the HEP message from being passed thrrough scripts.


Meaning of the parameters is as follows:


- *hep_cb_t cb* HEP callback


#### hep_version


Current version of hep used.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
