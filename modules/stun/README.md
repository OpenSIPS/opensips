---
title: "Stun Module"
---

## Admin Guide


### Overview


#### The idea


A stun server working with the same port as SIP (5060) in order to
				gain accurate information.
				The benefit would be an exact external address in the case of NATs translating differently
				when given different destination ports.


#### Basic Operation


```c
				The stun server will use 4 sockets:
					socket1 = ip1 : port1
					socket2 = ip1 : port2
					socket3 = ip2 : port1
					socket4 = ip2 : port2
				
```


The sockets come from existing SIP sockets or are created.


socket1 will allways be the the SIP socket.


The server will create a separate process.
				This process will listen for data on created sockets.

				The server will register a callback function to SIP.
				This function is called when a specific (stun)header is found.


#### Supported STUN Attributes


This stun implements rfc 3489 (and XOR_MAPPED_ADDRESS from rfc 5389)


MAPPED_ADDRESS,
RESPONSE_ADDRESS,
CHANGE_REQUEST,
SOURCE_ADDRESS,
CHANGED_ADDRESS,
ERROR_CODE,
UNKNOWN_ATTRIBUTES,
REFLECTED_FROM,
XOR_MAPPED_ADDRESS


Not supported attributes:


USERNAME,
PASSWORD,
MESSAGE_INTEGRITY,
and associated ERROR_CODEs


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### primary_ip (str)


The ip of the interface SIP is working on.


```opensips title="Set primary_ip parameter"
...

modparam("stun","primary_ip","192.168.0.100")
...
                
```


#### primary_port (str)


The port SIP is working on.


```opensips title="Set primary_port parameter"
...

modparam("stun","primary_port","5060")
...
                
```


#### alternate_ip (str)


Another ip from another interface.


```opensips title="Set alternate_ip parameter"
...

modparam("stun","alternate_ip","11.22.33.44")
...
                
```


#### alternate_port (str)


Another port used by STUN.


```opensips title="Set alternate_port parameter"
...

modparam("stun","alternate_port","3479")
...
                
```


### Exported MI Functions
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
