---
title: "proto_ipsec Module"
description: "The **proto_ipsec** module provides IPSec sockets for establishing secure communication channels. It relies on RFC 3329 (Security Mechanism Agreement for the Session Initiation Protocol (SIP)) to establish the IPSec parameters necessary for creating dynamic Security Associations (SAs) for..."
---

## Admin Guide


### Overview


The **proto_ipsec** module provides
		IPSec sockets for establishing secure communication channels.
		It relies on RFC 3329 (Security Mechanism Agreement for the Session
		Initiation Protocol (SIP)) to establish the IPSec parameters necessary
		for creating dynamic Security Associations (SAs) for each connection.


This module has been developed to fully comply with the VoLTE
		specification (GSMA PRD IR.92) and implements the extensions defined
		in TS 33.203 (3G Security: Access Security for IP-based Services).


It allows creation of both UDP and TCP secure connections on the same
		IP:port pair, defined as sockets. Essentially, when defining a socket
		using the *proto_ipsec* protocol, two new
		internal/hidden sockets are created on the specified port.
		For example, defining the following socket:
	```c

...
socket=ipsec:127.0.0.1:5100
...
```
		Internally, two different sockets are created:
	```c

...
socket=udp:127.0.0.1:5100
socket=tcp:127.0.0.1:5100
...
```
		Communication through these sockets should be done over IPSec,
		thus appropriate security associations (SAs) should be made prior
		to using these listeners, as defined in RFC 3329.


*NOTE* that this means that you can no longer
		define these sockets in your config, otherwise they will overlap
		with the internally defined ones.


IPSec communication requires each participant to define at least two
		ports for each connection: one when the entity behaves as a client and
		another when it behaves as a server. Consequently, it's typically
		necessary to define at least two IPSec sockets for the module to
		function correctly.


The module implements the entire logic of keeping track of the
		registration status by hooking into the usrloc module and listening
		for contact changes updates. It also ensures the persistency of the
		tunnels by restoring them after a restart.


When a request is received over an IPSec tunnel, the module provides
		two variables, [ipsec](#pv_ipsec) and
		[ipsec ue](#pv_ipsec_ue) to inspect details about it.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tm* - used to keep track of IPSec
				SA context between requests and replies.
- *usrloc* - used to identify when
				a successful registration/de-registration happens.
- *proto_udp* - used for handling
				IPSec UDP connections operations.
- *proto_tcp* - used for handling
				IPSec TCP connections operations.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *libmnl* - Minimalistic Netlink Library
				used to create IPSec SA using the XFRM kernel interface.


### Exported Parameters


#### port (integer)


Default IPSec port used when no prot is being specified in the
			*socket* global parameter.


*Default value is 5062.*


```c title="Set port parameter"
...
modparam("proto_ipsec", "port", 5100)
...
```


#### min_spi (integer)


This parameter represents the minimum value for the Security
			Association's (SA) SPI parameter. In conjunction with the
			*max_spi* setting, it defines the SPI
			range *[min_spi, max_spi]* that must be
			unique within the system.


*Default value is 65536.*


```c title="Set min_spi parameter"
...
modparam("proto_ipsec", "min_spi", 10000)
...
```


#### max_spi (integer)


This parameter represents the maximum value for the Security
			Association's (SA) SPI parameter. In conjunction with the
			*min_spi* setting, it defines the SPI
			range *[min_spi, max_spi]* that must be
			unique within the system.


*Default value is 262144.*


```c title="Set max_spi parameter"
...
modparam("proto_ipsec", "max_spi", 20000)
...
```


#### temporary_timeout (integer)


Sets the timeout (in seconds) a temporary security association
			can be stored in memory until in is confirmed (or used) by the
			remote endpoint.


The timeout signifies the duration elapsed after sending the
			Security Association's (SA) parameters in the 401 reply and
			when the User Equipment (UE) transmits the initial message
			over the new secure channel.


*Default value is 30.*


```c title="Set temporary_timeout variable"
param("proto_ipsec", "temporary_timeout", 10) # number of seconds

			
```


#### default_client_port (integer)


Default port value to be used when we act as clients in the
			IPSec communication.


*Default value is not defined - a random socket is being used,
			but needs to be different from the server socket.*


```c title="Set default_client_port parameter"
...
modparam("proto_ipsec", "default_client_port", 5100)
...
```


#### default_server_port (integer)


Default port value to be used when we act as server in the
			IPSec communication.


*Default value is not defined - a random socket is being used,
			but needs to be different from the client socket.*


```c title="Set default_server_port parameter"
...
modparam("proto_ipsec", "default_server_port", 6100)
...
```


#### allowed_algorithms (string)


Whitelists the authentication and encryption algorithms
			that can be used for IPSec.


Its format is: *alg|ealg|alg=ealg*


Multiple algorithms pairs can be specified separated by comma.


Currently supported algorithms are:


- Authentication algorithms:
				
					hmac-md5-96 - deprecated by TS 33.203 V13
					hmac-sha-1-96 - not recommended by TS 33.203 V17
					aes-gmac
					null - must only be used with aes-gcm encryption
- Encryption algorithms:
				
					des-ede3-cbc - not recommended
					aes-cbc - not recommended by TS 33.203 V17
					aes-gcm
					null - no encryption


*Default value is none - this means that all algorithms can be used.*


```c title="Set allowed_algorithms parameter"
...
modparam("proto_ipsec", "allowed_algorithms", "null")
modparam("proto_ipsec", "allowed_algorithms", "hmac-sha-1-96=null")
modparam("proto_ipsec", "allowed_algorithms", "hmac-sha-1-96=null,aes-gmac=aes-gcm")
...
```


#### disable_deprecated_algorithms (integer)


Indicates whether we should ignore deprecated algorithms,
			as defined in TS 33.203 (3G Security: Access Security for
			IP-based Services). At the moment, this disables the
			following algorithms:


- *hmac-md5-96* and *hmac-sha-1-96* authentication algorithms
- *des-ede3-cbc* and *aes-cbc* encryption algorithms


*Default value is false - all algorithms can be used.*


```c title="Set disable_deprecated_algorithms parameter"
...
modparam("proto_ipsec", "disable_deprecated_algorithms", yes)
...
```


### Exported Functions


#### ipsec_create([port_server], [port_client], [algos])


Creates an IPSec SA/tunnel according to the
			*Security-Client* header and the AKA information
			received in the 401 reply.


This function should only be called on a 401 reply for a REGISTER message.


Upon successful creation of the IPSec tunnel, it builds the
			*Security-Server* header and appends it to the reply.


Meaning of the parameters is as follows:


- *port_server (integer, optional)* - the server
				port to be used in the IPSec communication. It should be an existing
				IPSec port and is advertised in the
				*Security-Server* header. If missing, the
				[default client port](#param_default_client_port) is considered.
- *port_client (integer, optional)* - the client
				port to be used in the IPSec communication. It should be an existing
				IPSec port and is advertised in the
				*Security-Server* header. If missing, the
				[default server port](#param_default_server_port) is considered.
- *algos (string, optional)* - a list of
				algorithms that should be used for creating this security association.
				It has the same format as [allowed algorithms](#param_allowed_algorithms)
				and overwrites its value when used. If missing, the
				[allowed algorithms](#param_allowed_algorithms) is considered.


This function can be used from REPLY_ROUTE.


```c title="ipsec_create() usage"
...
onreply_route[ipsec] {
	if ($T_reply_code == 401)
		if (ipsec_create())
}
...
```


### Exported Pseudo-Variables


#### $ipsec


Populated for a request that is being received over
				an IPSec tunnel, it contains information about the
				local IPSec endpoint.


The following fields can be retrieved:


- *ik* - integrity key
					being used by the IPSec tunnel.
- *ck* - confidentiality key
					being used by the IPSec tunnel.
- *alg* - authentication
					algorithm being used.
- *ealg* - encryption
					algorithm being used.
- *ip* - local IP bound
					for this tunnel.
- *spi-c* - local SPI
					chosen for receiving messages through the client channel.
- *spi-s* - local SPI
					chosen for receiving messages through the server channel.
- *port-c* - local port
					chosen for communicating through the client channel.
- *port-c* - local port
					chosen for communicating through the server channel.


```c title="$ipsec(field) usage"
...
xlog("Using $ipsec(ip):$ipsec(port-c) and $ipsec(ip):$ipsec(port-s) socket\n");
...
```


#### $ipsec_ue


Populated for a request that is being received over
				an IPSec tunnel, it contains information about the
				remote IPSec endpoint.


The following fields can be retrieved:


- *ik* - integrity key
					being used by the IPSec tunnel.
- *ck* - confidentiality key
					being used by the IPSec tunnel.
- *alg* - authentication
					algorithm being used.
- *ealg* - encryption
					algorithm being used.
- *ip* - remote IP of
					the UE that uses this tunnel.
- *spi-c* - remote SPI
					chosen for sending messages through the client channel.
- *spi-s* - remote SPI
					chosen for sending messages through the server channel.
- *port-c* - remote port
					chosen for communicating through the client channel.
- *port-c* - remote port
					chosen for communicating through the server channel.


```c title="$ipsec_ue(field) usage"
...
xlog("Using $ipsec_ue(ip):$ipsec_ue(port-c) and $ipsec_ue(ip):$ipsec_ue(port-s) socket\n");
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
