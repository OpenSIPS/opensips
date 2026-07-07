---
title: "Stun Module"
---

## Admin Guide


### Overview


#### The idea


A stun server working with the same port as SIP (5060) in order to
			gain accurate information. The benefit would be an exact external 
			address in the case of NATs translating differently when given 
			different destination ports. The server may also advertise different
			network addresses than the ones it is actually listening on.


#### Basic Operation


The stun server will use 4 sockets:


- socket1 = ip1 : port1
- socket2 = ip1 : port2
- socket3 = ip2 : port1
- socket4 = ip2 : port2


The sockets come from existing SIP sockets or are created.


Socket1 must allways be a SIP UDP listener from OpenSIPS.


The server will create a separate process.
				This process will listen for data on created sockets.
				The server will register a callback function to SIP.
				This function is called when a specific (stun)header is found.


#### Supported STUN Attributes


This stun implements RFC3489 (and XOR_MAPPED_ADDRESS from 
				RFC5389)


- MAPPED_ADDRESS
- RESPONSE_ADDRESS
- CHANGE_REQUEST
- SOURCE_ADDRESS
- CHANGED_ADDRESS
- ERROR_CODE
- UNKNOWN_ATTRIBUTES
- REFLECTED_FROM
- XOR_MAPPED_ADDRESS


Not supported attributes:


- USERNAME
- PASSWORD
- MESSAGE_INTEGRITY


and associated ERROR_CODEs


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


*None*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
			running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### primary_ip (str)


The IP of an interface which is configured as an UDP SIP listener
			in OpenSIPS. This is a mandatory parameter.


Syntax: "ip [/ advertised_ip]


By default, the *primary_ip* and the advertised
			*primary_ip* will be identical.
			This may be changed with an optional "/ xxx.xxx.xxx.xxx" string.


```opensips title="Set primary_ip parameter"
...
modparam("stun", "primary_ip", "192.168.0.100")

# Example of a STUN server within OpenSIPS which is behind NAT
modparam("stun", "primary_ip", "192.168.0.100 / 64.50.46.78")
...
				
```


#### primary_port (str)


The port configured (together with the *primary_ip*) as an UDP SIP
			listener in OpenSIPS. The default value is 5060.


Syntax: "port [/ advertised_port]


By default, the *primary_port* and the advertised
			*primary_port* will be identical.
			This may be changed with an optional "/ adv_port" string.


```opensips title="Set primary_port parameter"
...
modparam("stun", "primary_port", "5060")

# Listening on a primary port, but advertising a different one
modparam("stun", "primary_port", "5060 / 5062")
...
				
```


#### alternate_ip (str)


Another IP from another interface. This is a mandatory parameter.


Syntax: "ip [/ advertised_ip]


By default, the *alternate_ip* and the advertised
			*alternate_ip* will be identical.
			This may be changed with an optional "/ xxx.xxx.xxx.xxx" string.


```opensips title="Set alternate_ip parameter"
...
modparam("stun","alternate_ip","11.22.33.44")

# Example of a STUN server within OpenSIPS which is behind NAT
modparam("stun", "alternate_ip", "192.168.0.100 / 64.78.46.50")
...
				
```


#### alternate_port (str)


The port used by the STUN server for the second interface.
			The default value is 3478 (default STUN port).


Syntax: "port [/ advertised_port]


By default, the *alternate_port* and the advertised
			*alternate_port* will be identical.
			This may be changed with an optional "/ adv_port" string.


```opensips title="Set alternate_port parameter"
...
modparam("stun","alternate_port","3479")

# Listening on an alternate port, but advertising a different one
modparam("stun", "alternate_port", "5060 / 5062")
...
				
```


### Exported MI Functions


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
